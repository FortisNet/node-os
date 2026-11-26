#!/usr/bin/env python3
"""Host update state-machine contracts; a fake crun never starts real containers."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import platform
import unittest

# Releases are per processor architecture; the orchestrator under test accepts its own.
ARCHITECTURE = {'arm64': 'aarch64', 'amd64': 'x86_64'}.get(platform.machine(), platform.machine())

from acme_fixture import Authority
from store_fixture import Store
from tls_ca import create_certificates

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import publish_release  # noqa: E402
CRUN = r'''#!/usr/bin/env python3
# Stands in for the container runtime: "run" stays in the foreground like the
# real one, so the keeper observes a real child, real signals and real exits.
# It then answers HTTP on the sockets the keeper passed in, as the node would,
# so the controller's own client is what the tests exercise.
import json,os,pathlib,select,signal,socket,ssl,sys,time
p=pathlib.Path(os.environ['NATIVE_FIXTURE'])
a=sys.argv[3:]
with (p/'commands').open('a') as f:f.write(json.dumps(a)+'\n')
def load():return json.loads((p/'state.json').read_text())
def save(s):
 t=p/('state.%d.tmp'%os.getpid());t.write_text(json.dumps(s));os.replace(t,p/'state.json')
if a[0]=='delete':sys.exit(0)
if a[0]=='kill':
 pid=load().get('pids',{}).get(a[1])
 if not pid:sys.exit(1)
 with (p/'signals').open('a') as f:f.write(a[1]+' '+a[2]+'\n')
 try:os.kill(pid,signal.SIGHUP if a[2]=='SIGHUP' else signal.SIGKILL if a[2]=='SIGKILL' or (p/'force-kill').exists() else signal.SIGTERM)
 except ProcessLookupError:sys.exit(1)
 sys.exit(0)
if a[0]!='run':sys.exit(2)
name=a[-1];bundle=pathlib.Path(a[a.index('--bundle')+1]);preflight='-preflight-' in name;page=name.endswith('-page')
config=json.loads((bundle/'config.json').read_text())
count=int(a[a.index('--preserve-fds')+1]);listeners=[];sockets={}
for fd in range(3,3+count):
 sockets[fd]=socket.socket(fileno=os.dup(fd));host,port=sockets[fd].getsockname();listeners.append('%s:%d'%(host,port))
(p/('config-preflight.json' if preflight else 'config-page.json' if page else 'config-node.json')).write_text(json.dumps({'config':config,'listeners':listeners}))
s=load();root=None;selected=None;unhealthy=False
def mounted(target):return pathlib.Path(next(m['source'] for m in config['mounts'] if m['destination']==target))
if not preflight and not page:
 if (p/'start-fails').exists():sys.exit(1)
 if (p/'start-fails-once').exists():(p/'start-fails-once').unlink();sys.exit(1)
 app=pathlib.Path(next(m['source'] for m in config['mounts'] if m['destination']=='/app'))
 if not (app/'current').exists():sys.exit(1)
 selected=os.readlink(app/'current');root=app.parent
 if (p/'fail-target').exists() and (p/'fail-target').read_text()==selected:
  (p/'database/acknowledged').write_text('candidate acknowledged write must survive rollback')
  unhealthy=True
s.setdefault('pids',{})[name]=os.getpid();save(s)
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
pathlib.Path(a[a.index('--pid-file')+1]).write_text(str(os.getpid()))
if not preflight and (p/'crash-loop').exists():time.sleep(.2);sys.exit(1)
env=dict(v.split('=',1) for v in config['process']['env'])
inside={int(k):sockets[int(v)] for k,v in (e.split('=') for e in env['FORTIS_LISTEN_FDS'].split(','))}
tls=None
def load_certificates(*_):
 # Like the node: one certificate per configured name, from the selected
 # generation, loaded at start and again on the reload signal.
 global tls
 current=mounted('/certificates')/'current'
 def context(kind):
  c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(current/(kind+'.pem'),current/(kind+'.key'));return c
 address=context('ip')
 if 'FORTIS_HTTPS_DOMAIN' in env:
  name=context('domain')
  def choose(sock,server_name,_):
   if server_name==env['FORTIS_HTTPS_DOMAIN']:sock.context=name
  address.sni_callback=choose
 tls=address
 with (p/'certificate-loads').open('a') as f:f.write(os.readlink(current)+'\n')
if 'FORTIS_HTTPS_CERT_DIR' in env:
 try:load_certificates()
 except (OSError,ssl.SSLError,StopIteration):sys.exit(1)
 signal.signal(signal.SIGHUP,load_certificates)
def challenge(path):
 prefix='/.well-known/acme-challenge/'
 if not path.startswith(prefix):return 503 if page else 308,'setup'
 try:return 200,(mounted('/acme')/path[len(prefix):]).read_text()
 except (OSError,StopIteration):return 404,''
def answer(path):
 if unhealthy:return 503,'{}'
 if path=='/v1/networks':return 401,'{}'
 if preflight:return 200,'{"ok":true}'
 if path=='/errorsz':
  records=[]
  if selected=='releases/two' and (p/'incident-kind').exists():
   kind=(p/'incident-kind').read_text()
   records=[{'origin':kind,'service':'fixture','code':'failure','identifier':'','provider':'coingecko' if kind=='third_party' else '', 'httpStatus':429 if kind=='third_party' else None,'count':3,'firstSeenMs':1,'lastSeenMs':2}]
  if records:return 200,json.dumps({'operational':{'persisted':True,'writeFailed':False,'records':records}})
  return 200,'{"operational":{"persisted":'+('false' if (p/'storage-fails').exists() else 'true')+',"writeFailed":'+('true' if (p/'write-fails').exists() else 'false')+'}}'
 if path=='/releasesz':
  if (p/'wrong-metadata').exists():return 200,'{"schemaVersion":1,"managed":true,"current":null,"candidate":null,"sequence":0}'
  return 200,(root/'deployment/public/current.json').read_text()
 if path=='/statsz':
  n=0 if (p/'no-traffic').exists() else 100
  return 200,json.dumps({'groups':[{'service':'fixture','requests':n,'errors4xx':0,'errors5xx':0,'p95Ms':10}]})
 return 200,'{"ok":true}'
def serve(listener,secure,plain_http=False):
 try:
  connection,_=listener.accept();connection.setblocking(True);connection.settimeout(2)
  if secure:connection=tls.wrap_socket(connection,server_side=True)
  data=b''
  while b'\r\n\r\n' not in data:
   more=connection.recv(4096)
   if not more:return
   data+=more
  status,body=(challenge if plain_http else answer)(data.split(b' ',2)[1].decode());body=body.encode()
  connection.sendall(b'HTTP/1.1 %d Fixture\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'%(status,len(body))+body)
  connection.close()
 except (OSError,ssl.SSLError):pass
while True:
 for ready in select.select(list(inside.values()),[],[],.05)[0]:
  serve(ready,tls is not None and ready is inside.get(8080),ready is inside.get(8082))
'''


@unittest.skipUnless(os.uname().sysname == 'Linux', 'Linux host controller; runs in make verify')
class NativeUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='fortis-signing-fixture-')
        cls.key = Path(cls.keys.name) / 'private.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-out', str(cls.key)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fortis-native-update-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.database = self.path / 'database'
        self.database.mkdir()
        self.root = self.path / 'node'
        self.public = self.path / 'public.pem'
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.public)],
                       check=True, capture_output=True)
        self.env_file = self.path / 'runtime.env'
        self.env_file.write_text('NODE_ENV=development\n')
        self.env_file.chmod(0o600)
        self.config = self.path / 'node.conf'
        self.config.write_text(f'''FORTIS_NATIVE_ROOT={self.root}
FORTIS_NATIVE_DATA={self.database}
FORTIS_NATIVE_ENV={self.env_file}
FORTIS_NATIVE_PUBLIC_KEY={self.public}
FORTIS_NATIVE_RUNTIME_STATE={self.path / 'runtime-state'}
FORTIS_NATIVE_PORT={self.free_port()}
FORTIS_NATIVE_REQUIRE_MOUNT=0
FORTIS_NATIVE_HEALTH_ATTEMPTS=1
FORTIS_NATIVE_PREFLIGHT=0
FORTIS_NATIVE_VERIFY_PID=0
FORTIS_NATIVE_OBSERVE_SECONDS=0
FORTIS_NATIVE_MIN_REQUESTS=0
''')
        self.config.chmod(0o600)
        (self.path / 'state.json').write_text('{}')
        tools = self.path / 'tools'
        tools.mkdir()
        # The only program the controller runs is the container runtime. Every
        # other name it once ran as a command now fails loudly if it is used.
        (tools / 'crun').write_text(CRUN)
        for name in ('curl', 'openssl', 'sha256sum', 'cp', 'du', 'df', 'sync', 'chown', 'mountpoint', 'docker'):
            (tools / name).write_text(f'#!/bin/sh\ntouch "$NATIVE_FIXTURE/ran-{name}"\nexit 97\n')
        for file in tools.iterdir():
            file.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'],
                                NATIVE_FIXTURE=str(self.path))
        self.release = self.package('one')
        self.addCleanup(self.stop_keeper)

    @staticmethod
    def free_port():
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            return probe.getsockname()[1]

    @staticmethod
    def free_ports(count):
        """Ports that differ: asked for one after another, the same one can come back."""
        probes = [socket.socket() for _ in range(count)]
        try:
            for probe in probes:
                probe.bind(('127.0.0.1', 0))
            return [probe.getsockname()[1] for probe in probes]
        finally:
            for probe in probes:
                probe.close()

    def keeper(self, request):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(10)
            client.connect(str(self.root / 'keeper.sock'))
            client.sendall(request.encode() + b'\n')
            return client.makefile().readline().strip()

    def stop_keeper(self):
        try:
            self.keeper('shutdown')
        except OSError:
            return
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.keeper('ping')
            except OSError:
                return
            time.sleep(.05)
        self.fail('keeper did not shut down')

    def node_running(self):
        try:
            return ' running=1 ' in ' ' + self.keeper('state') + ' '
        except OSError:
            return False

    def launched(self, kind='node'):
        return json.loads((self.path / f'config-{kind}.json').read_text())

    def package(self, version, *, epoch=1, architecture=ARCHITECTURE, padding=0, machine=None):
        directory = self.path / ('upload-' + version)
        directory.mkdir()
        binary = bytearray(256)
        binary[:7] = b'\x7fELF\x02\x01\x01'
        # The ELF machine number of the architecture: 62 is x86_64, 183 aarch64.
        struct.pack_into('<H', binary, 18, machine or {'x86_64': 62, 'aarch64': 183}[ARCHITECTURE])
        struct.pack_into('<H', binary, 16, 3)
        struct.pack_into('<Q', binary, 32, 64)
        struct.pack_into('<HH', binary, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', binary, 64, 0x6474e551, 6, 0, 0, 0, 0, 2097152, 16)
        binary[128:] = (version.encode() * 128)[:128].ljust(128, b'.')
        binary += os.urandom(padding)
        (directory / 'fortis-node').write_bytes(binary)
        (directory / 'manifest').write_text(
            f'format=1\nversion={version}\narchitecture={architecture}\n'
            f'runtime=linux-musl-static-v1\nstorage_epoch={epoch}\n'
            f'sha256={hashlib.sha256(binary).hexdigest()}\nbytes={len(binary)}\n')
        self.sign(directory)
        return directory

    def sign(self, directory):
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key), '-out',
                        str(directory / 'manifest.sig'), str(directory / 'manifest')],
                       check=True, capture_output=True)

    def run_action(self, action, package=None, success=True):
        args = [str(ROOT / 'image/files/manage-native-node.sh'), str(self.config), action]
        if package:
            args.append(str(package))
        result = subprocess.run(args, env=self.environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def selected(self):
        return os.readlink(self.root / 'app/current')

    def test_first_install_start_update_and_repeated_release(self):
        self.run_action('update', self.release)
        self.assertEqual(self.selected(), 'releases/one')
        self.run_action('start')
        self.run_action('update', self.release)
        two = self.package('two')
        self.run_action('update', two)
        self.assertEqual(self.selected(), 'releases/two')
        self.assertEqual(os.readlink(self.root / 'app/previous'), 'releases/one')
        self.assertEqual(len(list((self.root / 'backups').iterdir())), 2)
        config = self.launched()['config']
        self.assertTrue(config['root']['readonly'])
        self.assertTrue(config['process']['noNewPrivileges'])
        self.assertEqual(config['process']['user'], {'uid': 10001, 'gid': 10001})
        self.assertTrue(all(value == [] for value in config['process']['capabilities'].values()))
        self.assertEqual(config['linux']['resources'], {'memory': {'limit': 536870912}, 'pids': {'limit': 512}})
        self.assertNotIn('network', [entry['type'] for entry in config['linux']['namespaces']])
        # The Droplet boot check runs a throwaway container with these same
        # isolation settings; it must not drift from what the node gets.
        check = json.loads((ROOT / 'image/bootcheck/crun-check.json').read_text())
        # The filter names the host's own architecture; the boot check image is x86_64.
        self.assertEqual(config['linux']['seccomp']['architectures'], ['SCMP_ARCH_' + ARCHITECTURE.upper()])
        self.assertEqual(check['linux']['seccomp']['architectures'], ['SCMP_ARCH_X86_64'])
        config['linux']['seccomp']['architectures'] = check['linux']['seccomp']['architectures']
        for field in ('seccomp', 'resources', 'namespaces', 'maskedPaths', 'readonlyPaths'):
            self.assertEqual(check['linux'][field], config['linux'][field], field)
        for field in ('user', 'capabilities', 'noNewPrivileges', 'rlimits'):
            self.assertEqual(check['process'][field], config['process'][field], field)
        self.assertTrue(any(value.startswith('FORTIS_LISTEN_FDS=8080=3') for value in config['process']['env']))
        self.assertEqual(list(self.path.glob('ran-*')), [])

    def test_failed_candidate_rolls_back_without_losing_acknowledged_writes(self):
        self.run_action('update', self.release)
        two = self.package('two')
        (self.path / 'fail-target').write_text('releases/two')
        self.run_action('update', two, success=False)
        self.assertEqual(self.selected(), 'releases/one')
        self.assertTrue((self.database / 'acknowledged').exists())
        self.assertFalse((self.root / 'pending').exists())

    def test_interrupted_update_recovers_previous_binary(self):
        self.run_action('update', self.release)
        two = self.package('two')
        self.run_action('update', two)
        (self.root / 'pending').write_text('releases/one\n')
        self.run_action('recover')
        self.assertEqual(self.selected(), 'releases/one')

    def test_failed_recovery_retains_journal(self):
        self.run_action('update', self.release)
        (self.root / 'pending').write_text('releases/one\n')
        (self.path / 'start-fails').touch()
        self.run_action('recover', success=False)
        self.assertTrue((self.root / 'pending').exists())

    def test_first_install_failure_stays_stopped_and_preserves_data(self):
        (self.path / 'fail-target').write_text('releases/one')
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())
        self.assertTrue((self.database / 'acknowledged').exists())

    def test_unsigned_or_corrupted_release_refused(self):
        (self.release / 'manifest.sig').unlink()
        self.run_action('update', self.release, success=False)
        self.sign(self.release)
        with (self.release / 'fortis-node').open('ab') as file:
            file.write(b'corruption')
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_version_content_collision_refused(self):
        self.run_action('update', self.release)
        text = (self.release / 'manifest').read_text().replace('bytes=256', 'bytes=0256')
        (self.release / 'manifest').write_text(text)
        self.sign(self.release)
        self.run_action('update', self.release, success=False)
        self.assertEqual(self.selected(), 'releases/one')

    def test_incompatible_epoch_and_architecture_refused(self):
        for package in [self.package('epoch', epoch=2), self.package('other', architecture='x86_64' if ARCHITECTURE == 'aarch64' else 'aarch64'),
                        # A program for the other architecture under a manifest naming this one.
                        self.package('mislabelled', machine=62 if ARCHITECTURE == 'aarch64' else 183)]:
            self.run_action('update', package, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_existing_database_requires_audited_adoption(self):
        (self.database / 'fortis.kv').write_bytes(b'existing-data')
        self.run_action('update', self.release, success=False)
        self.assertEqual((self.database / 'fortis.kv').read_bytes(), b'existing-data')

    def test_configuration_change_applies_at_next_start(self):
        # No container outlives its process, so nothing can drift from the
        # reviewed files: every start is built from them again.
        self.run_action('update', self.release)
        self.assertIn('NODE_ENV=development', self.launched()['config']['process']['env'])
        self.env_file.write_text('NODE_ENV=production\n')
        self.run_action('stop')
        self.run_action('start')
        self.assertIn('NODE_ENV=production', self.launched()['config']['process']['env'])

    def test_candidate_preflight_is_isolated_and_removed(self):
        self.config.write_text(self.config.read_text().replace('FORTIS_NATIVE_PREFLIGHT=0', 'FORTIS_NATIVE_PREFLIGHT=1'))
        self.run_action('update', self.release)
        preflight = self.launched('preflight')
        config = preflight['config']
        self.assertIn('network', [entry['type'] for entry in config['linux']['namespaces']])
        self.assertTrue(preflight['listeners'][0].startswith('127.0.0.1:'))
        self.assertEqual(config['process']['env'], ['NODE_ENV=development', 'FORTIS_KV_DIR=/data',
                                                    'FORTIS_CA_BUNDLE_PATH=/etc/ssl/certs/ca-certificates.crt',
                                                    'FORTIS_LISTEN_FDS=8080=3'])
        mounts = {mount['destination']: mount for mount in config['mounts']}
        self.assertEqual(mounts['/data']['type'], 'tmpfs')
        self.assertEqual(mounts['/app/current']['source'], str(self.root / 'app/releases/one'))
        self.assertNotIn('/deployment', mounts)
        commands = [json.loads(line) for line in (self.path / 'commands').read_text().splitlines()]
        self.assertIn(['kill', 'fortis-node-preflight-1', 'SIGTERM'], commands)
        self.assertFalse((self.root / 'run/fortis-node-preflight-1').exists())
        self.assertTrue(self.node_running())

    def test_keeper_holds_the_port_while_the_node_is_stopped(self):
        self.run_action('update', self.release)
        address = self.launched()['listeners'][0].split(':')
        self.run_action('stop')
        self.assertFalse(self.node_running())
        with socket.create_connection((address[0], int(address[1])), timeout=2):
            pass  # Queued by the keeper's socket, not refused.
        self.stop_keeper()
        with self.assertRaises(OSError):
            socket.create_connection((address[0], int(address[1])), timeout=2)

    def tree(self, directory):
        """Every file and link under a folder, without the node's lock and the manifest."""
        found = {}
        for path in sorted(Path(directory).rglob('*')):
            name = path.relative_to(directory).as_posix()
            if name in ('fortis.kv.lock', 'fortis-backup.manifest'):
                continue
            found[name] = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
        return found

    def seed_database(self):
        (self.database / 'nested').mkdir()
        (self.database / 'fortis.kv').write_bytes(os.urandom(70000))
        (self.database / 'nested/segment 1').write_bytes(b'second file')
        (self.database / 'pointer').symlink_to('nested/segment 1')

    def backup(self):
        output = self.run_action('backup').stdout
        return Path(output.split('Backup written: ')[1].strip())

    def test_backup_has_a_manifest_and_restarts_the_node(self):
        self.run_action('update', self.release)
        self.seed_database()
        before = self.keeper('state')
        folder = self.backup()
        self.assertTrue(self.node_running())
        self.assertNotEqual(self.keeper('state'), before)  # stopped for the copy, then started
        self.assertEqual(self.tree(folder), self.tree(self.database))
        manifest = (folder / 'fortis-backup.manifest').read_text()
        self.assertTrue(manifest.startswith('format=1\ncreated_ms='))
        self.assertIn('\nstorage_epoch=1\nrelease=one\nrelease_sha256=' +
                      hashlib.sha256((self.release / 'fortis-node').read_bytes()).hexdigest() + '\n', manifest)
        digest = hashlib.sha256((self.database / 'fortis.kv').read_bytes()).hexdigest()
        self.assertIn(f'f\t{digest}\t70000\tfortis.kv\n', manifest)
        self.assertIn('d\tnested\n', manifest)
        self.assertIn('l\tnested/segment 1\tpointer\n', manifest)
        self.assertEqual((folder / 'fortis-backup.manifest').stat().st_mode & 0o777, 0o600)

    def test_backup_before_an_update_is_restorable_too(self):
        self.run_action('update', self.release)
        self.seed_database()
        self.run_action('update', self.package('two'))
        folder = max((self.root / 'backups').iterdir(), key=lambda path: path.stat().st_mtime_ns)
        self.assertIn('release=one\n', (folder / 'fortis-backup.manifest').read_text())
        (self.database / 'fortis.kv').write_bytes(b'written by release two')
        self.run_action('restore', folder)
        self.assertEqual(len((self.database / 'fortis.kv').read_bytes()), 70000)

    def test_restore_round_trip_keeps_the_replaced_database(self):
        self.run_action('update', self.release)
        self.seed_database()
        original = self.tree(self.database)
        # As if copied in from another machine: the folder is moved elsewhere.
        folder = self.path / 'carried-backup'
        shutil.move(str(self.backup()), folder)
        (self.database / 'fortis.kv').write_bytes(b'later, unwanted state')
        (self.database / 'nested/segment 1').unlink()
        (self.database / 'added').write_bytes(b'x')
        changed = self.tree(self.database)
        result = self.run_action('restore', folder)
        self.assertEqual(self.tree(self.database), original)
        self.assertTrue(self.node_running())
        kept = Path(result.stdout.split('the previous database is kept in ')[1].strip())
        self.assertTrue(kept.name.endswith('-before-restore'))
        self.assertEqual(self.tree(kept), changed)
        # The database that was replaced is itself a restorable backup.
        self.run_action('restore', kept)
        self.assertEqual(self.tree(self.database), changed)

    def test_damaged_or_foreign_backups_are_refused_before_anything_is_touched(self):
        self.run_action('update', self.release)
        self.seed_database()
        good = self.backup()
        current, state = self.tree(self.database), self.keeper('state')

        def attempt(name, damage):
            folder = self.path / name
            shutil.copytree(good, folder, symlinks=True)
            damage(folder)
            with self.subTest(damage=name):
                self.run_action('restore', folder, success=False)
                self.assertEqual(self.tree(self.database), current)
                self.assertEqual(self.keeper('state'), state)  # never stopped

        def rewrite(change):
            def apply(folder):
                manifest = folder / 'fortis-backup.manifest'
                manifest.chmod(0o600)
                manifest.write_text(change(manifest.read_text()))
            return apply

        attempt('changed-file', lambda folder: (folder / 'fortis.kv').write_bytes(os.urandom(70000)))
        attempt('missing-file', lambda folder: (folder / 'nested/segment 1').unlink())
        attempt('extra-file', lambda folder: (folder / 'planted').write_bytes(b'x'))
        attempt('no-manifest', lambda folder: (folder / 'fortis-backup.manifest').unlink())
        attempt('special-file', lambda folder: os.mkfifo(folder / 'pipe'))
        attempt('truncated-manifest', rewrite(lambda text: text[:len(text) // 2]))
        attempt('other-format', rewrite(lambda text: text.replace('format=1', 'format=2', 1)))
        attempt('other-storage', rewrite(lambda text: text.replace('storage_epoch=1', 'storage_epoch=2', 1)))
        attempt('path-leaves-backup', rewrite(lambda text: text + 'd\t../outside\n'))
        attempt('absolute-path', rewrite(lambda text: text + 'd\t/etc\n'))
        attempt('listed-twice', rewrite(lambda text: text + 'd\tnested\n'))
        attempt('wrong-total', rewrite(lambda text: text.replace('\nbytes=', '\nbytes=9', 1)))

        def escaping_link(folder):
            (folder / 'pointer').unlink()
            (folder / 'pointer').symlink_to('/etc/passwd')
        attempt('link-leaves-backup', escaping_link)
        self.run_action('restore', self.path / 'does-not-exist', success=False)
        self.run_action('restore', self.database, success=False)
        self.assertEqual(self.tree(self.database), current)

    def test_restore_that_does_not_come_up_puts_the_previous_database_back(self):
        self.run_action('update', self.release)
        self.seed_database()
        folder = self.backup()
        (self.database / 'fortis.kv').write_bytes(b'state that must survive a failed restore')
        current = self.tree(self.database)
        (self.path / 'start-fails-once').touch()
        result = self.run_action('restore', folder, success=False)
        self.assertIn('the previous database was put back', result.stderr)
        self.assertEqual(self.tree(self.database), current)
        self.assertTrue(self.node_running())
        self.assertEqual([path.name for path in (self.root / 'backups').iterdir() if 'before-restore' in path.name], [])

    def test_backup_refused_before_anything_is_installed(self):
        self.run_action('backup', success=False)
        self.assertFalse(self.node_running())

    def release_store(self):
        """A store on loopback holding release 'one', and a host configured to read it."""
        self.path.chmod(0o755)  # the unprivileged fetch process must reach its own state
        self.store_folder = self.path / 'store'
        self.store_folder.mkdir()
        # A store holds one tree per processor architecture; a host reads its own.
        self.store_tree = self.store_folder / ARCHITECTURE
        publish_release.publish(self.store_folder, self.release, self.key)
        tls = self.path / 'store-tls'
        tls.mkdir()
        ca, certificate, key, _ = create_certificates(tls, 'IP:127.0.0.1')
        self.store = Store(self.store_folder, certificate, key)
        self.addCleanup(self.store.close)
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_TLS_CA={ca}\nFORTIS_NATIVE_RELEASE_STORE={self.store.url}\n'
                       f'FORTIS_NATIVE_RELEASE_STORE_LOOPBACK=1\nFORTIS_NATIVE_FETCH_STATE={self.path / "fetch-state"}\n')

    def staged(self):
        folder = self.root / 'staged'
        return sorted(path.name for path in folder.iterdir()) if folder.exists() else []

    def test_fetch_stages_and_update_installs_by_version(self):
        self.release_store()
        listing = self.run_action('releases').stdout
        self.assertIn('Release index 1, 1 release(s)', listing)
        self.assertIn('one', listing)
        self.assertIn('Staged release one', self.run_action('fetch', 'one').stdout)
        # Staged is not installed: nothing runs until the operator says so.
        self.assertEqual(self.staged(), ['one'])
        self.assertFalse((self.root / 'app/current').exists())
        self.assertFalse(self.node_running())
        self.assertEqual((self.root / 'staged/one').stat().st_mode & 0o777, 0o700)
        self.run_action('update', 'one')
        self.assertEqual(self.selected(), 'releases/one')
        publish_release.publish(self.store_folder, self.package('two'), self.key)
        listing = self.run_action('releases').stdout
        self.assertIn('Release index 2, 2 release(s)', listing)
        self.assertIn('one  (running)  (staged)', listing)
        self.run_action('fetch', 'two')
        self.run_action('update', 'two')
        self.assertEqual(self.selected(), 'releases/two')

    def test_large_release_is_fetched_in_ranges(self):
        self.release_store()
        large = self.package('large', padding=5 * 1024 * 1024 + 123)
        publish_release.publish(self.store_folder, large, self.key)
        self.run_action('fetch', 'large')
        self.assertEqual((self.root / 'staged/large/fortis-node').read_bytes(), (large / 'fortis-node').read_bytes())
        ranges = [header for path, header in self.store.requests if path == f'/{ARCHITECTURE}/releases/large/fortis-node']
        self.assertEqual(ranges, ['bytes=0-2097151', 'bytes=2097152-4194303', 'bytes=4194304-5243258'])

    def test_tampered_truncated_or_swapped_download_is_discarded(self):
        self.release_store()
        self.run_action('fetch', 'one')
        self.run_action('update', 'one')
        two = self.package('two')
        publish_release.publish(self.store_folder, two, self.key)
        published = self.store_tree / 'releases/two'

        def refused(reason):
            with self.subTest(reason=reason):
                self.run_action('fetch', 'two', success=False)
                self.assertEqual(self.staged(), ['one'])
                self.assertEqual(self.selected(), 'releases/one')
                self.assertTrue(self.node_running())

        binary = bytearray((published / 'fortis-node').read_bytes())
        binary[200] ^= 1
        (published / 'fortis-node').write_bytes(binary)
        refused('one bit changed in the executable')
        (published / 'fortis-node').write_bytes((two / 'fortis-node').read_bytes())
        self.store.truncate[f'/{ARCHITECTURE}/releases/two/fortis-node'] = 10
        refused('download cut short')
        self.store.truncate.clear()
        # Another release, correctly signed, served under this version's name.
        other = self.package('other')
        for name in ('fortis-node', 'manifest', 'manifest.sig'):
            shutil.copyfile(other / name, published / name)
        refused('a different signed release under this name')
        for name in ('fortis-node', 'manifest', 'manifest.sig'):
            shutil.copyfile(two / name, published / name)
        (published / 'manifest.sig').write_bytes(b'not a signature')
        refused('manifest signature replaced')
        shutil.copyfile(two / 'manifest.sig', published / 'manifest.sig')
        self.run_action('fetch', 'two')
        self.assertEqual(self.staged(), ['one', 'two'])
        self.run_action('fetch', 'never-published', success=False)

    def test_index_must_be_signed_and_never_go_backwards(self):
        self.release_store()
        first = [(self.store_tree / name).read_bytes() for name in ('index', 'index.sig')]
        publish_release.publish(self.store_folder, self.package('two'), self.key)
        self.assertIn('Release index 2', self.run_action('releases').stdout)
        second = [(self.store_tree / name).read_bytes() for name in ('index', 'index.sig')]

        def serve(index, signature):
            (self.store_tree / 'index').write_bytes(index)
            (self.store_tree / 'index.sig').write_bytes(signature)

        # An earlier, correctly signed index: hides release two.
        serve(*first)
        result = self.run_action('releases', success=False)
        self.assertIn('older index', result.stderr)
        self.run_action('fetch', 'one', success=False)
        # The same sequence with other content, correctly signed.
        forged = second[0].replace(b'published_ms=', b'published_ms=1')
        (self.path / 'forged').write_bytes(forged)
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key), '-out', str(self.path / 'forged.sig'),
                        str(self.path / 'forged')], check=True, capture_output=True)
        serve(forged, (self.path / 'forged.sig').read_bytes())
        self.assertIn('different index', self.run_action('releases', success=False).stderr)
        # Changed after signing, or signed by a stranger.
        serve(second[0] + b'release\tevil\t' + b'0' * 64 + b'\t100\n', second[1])
        self.assertIn('signature', self.run_action('releases', success=False).stderr)
        stranger = self.path / 'stranger.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(stranger)], check=True, capture_output=True)
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(stranger), '-out', str(self.path / 'stranger.sig'),
                        str(self.store_tree / 'index')], check=True, capture_output=True)
        serve(second[0], (self.path / 'stranger.sig').read_bytes())
        self.assertIn('signature', self.run_action('releases', success=False).stderr)
        # The honest index is accepted again, and nothing was staged meanwhile.
        serve(*second)
        self.assertIn('Release index 2', self.run_action('releases').stdout)
        self.assertEqual(self.staged(), [])

    def test_recovery_key_can_sign_when_installed(self):
        self.release_store()
        recovery = self.path / 'recovery.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(recovery)], check=True, capture_output=True)
        public = self.path / 'recovery-public.pem'
        subprocess.run(['openssl', 'pkey', '-in', str(recovery), '-pubout', '-out', str(public)],
                       check=True, capture_output=True)
        # The release key is lost: the next release and index are signed by the recovery key.
        two = self.package('two')
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(recovery), '-out', str(two / 'manifest.sig'),
                        str(two / 'manifest')], check=True, capture_output=True)
        publish_release.publish(self.store_folder, two, recovery)
        self.run_action('releases', success=False)   # this host does not know that key yet
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_RECOVERY_KEY={public}\n')
        self.assertIn('Release index 2', self.run_action('releases').stdout)
        self.run_action('fetch', 'two')
        self.run_action('update', 'two')
        self.assertEqual(self.selected(), 'releases/two')

    def test_unreachable_store_changes_nothing(self):
        self.release_store()
        self.run_action('fetch', 'one')
        self.run_action('update', 'one')
        state = self.keeper('state')
        self.store.close()
        result = self.run_action('releases', success=False)
        self.assertIn('release store unreachable', result.stderr)
        self.run_action('fetch', 'one', success=False)
        self.assertEqual(self.keeper('state'), state)
        self.assertEqual(self.staged(), ['one'])

    def test_no_store_configured_is_said_plainly(self):
        self.assertIn('no release store is configured', self.run_action('releases', success=False).stderr)

    def published(self, name):
        return (self.root / 'deployment/public' / name).read_text()

    def health(self):
        return json.loads(self.published('health.json'))

    def test_pages_say_what_the_host_is_doing(self):
        # Nothing installed yet: a supervisor tick still writes the pages.
        self.run_action('tick')
        report = self.health()
        self.assertEqual((report['schemaVersion'], report['status'], report['healthy']), (1, 503, False))
        self.assertIn(report['orchestrator']['runsIn'], ('machine', 'container'))
        self.assertEqual(report['node'], {'state': 'not-installed', 'checks': []})
        self.assertIn('This host is being set up', self.published('index.html'))
        self.assertIn('http-equiv="refresh"', self.published('index.html'))
        self.assertTrue(self.published('health.status').startswith('503 '))

        self.run_action('update', self.release)
        report = self.health()
        self.assertEqual((report['status'], report['healthy'], report['node']['state']), (200, True, 'serving'))
        self.assertEqual(report['node']['version'], 'one')
        self.assertEqual(report['node']['sha256'], hashlib.sha256((self.release / 'fortis-node').read_bytes()).hexdigest())
        self.assertEqual([check['name'] for check in report['orchestrator']['checks']], ['Orchestrator', 'Disk', 'Backups'])
        self.assertTrue(all(check['state'] == 'healthy' for check in report['orchestrator']['checks'] + report['node']['checks']))
        page = self.published('index.html')
        self.assertIn('The node is running', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn('href="https://blockchain.fortisnet.io/"', page)
        self.assertIn('<a href="/dashboard">', page)
        self.assertIn('This host is healthy', self.published('health.html'))
        written = int(self.published('health.status').split()[1])
        self.assertLess(abs(written - time.time() * 1000), 30000)
        # One self-contained file: no script, and nothing fetched from elsewhere.
        for forbidden in ('<script', 'src="/', 'src="http', "url('/", 'url(/'):
            self.assertNotIn(forbidden, page)
        self.assertLess(len(page), 512 * 1024)
        # `status` prints the same report for the operator.
        self.assertIn('"schemaVersion":1', self.run_action('status').stdout)

        self.run_action('stop')
        report = self.health()
        self.assertEqual((report['status'], report['node']['state']), (503, 'stopped'))
        self.assertEqual(report['node']['checks'][0]['state'], 'failing')
        page = self.published('index.html')
        self.assertIn('The node is stopped', page)
        self.assertIn('<li class="off">Dashboard</li>', page)
        self.assertNotIn('href="/dashboard"', page)

    def test_pages_contain_nothing_private(self):
        self.env_file.write_text('NODE_ENV=development\nPROVIDER_API_KEY=secret-provider-key-123\n')
        self.run_action('update', self.release)
        for name in ('index.html', 'health.html', 'health.json'):
            text = self.published(name)
            for private in ('secret-provider-key-123', str(self.path), str(self.root), 'fortis-native', 'PROVIDER_API_KEY',
                            'runtime.env'):
                self.assertNotIn(private, text, (name, private))

    def test_page_names_a_staged_update_and_how_to_install_it(self):
        self.release_store()
        self.run_action('fetch', 'one')
        self.run_action('update', 'one')
        self.assertIn('The installed release is the newest one published', self.published('index.html'))
        publish_release.publish(self.store_folder, self.package('two'), self.key)
        self.run_action('releases')
        self.run_action('tick')
        self.assertIn('<code>fortis fetch two</code>', self.published('index.html'))
        self.run_action('fetch', 'two')
        self.assertIn('<code>fortis update two</code>', self.published('index.html'))
        names = [check['name'] for check in self.health()['orchestrator']['checks']]
        self.assertIn('Releases', names)

    def test_in_a_container_the_runtime_avoids_what_docker_forbids(self):
        self.run_action('update', self.release)
        runs = [json.loads(line) for line in (self.path / 'commands').read_text().splitlines()]
        runs = [command for command in runs if command[0] == 'run']
        self.assertTrue(runs)
        # The gate runs in a container; a direct `make test` may not.
        contained = Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()
        for command in runs:
            for option in ('--no-new-keyring', '--no-pivot'):
                self.assertEqual(option in command, contained, command)

    def test_stopping_the_node_brings_up_the_page_server(self):
        self.direct_https(domain=None)
        self.run_action('update', self.release)
        commands = lambda: [json.loads(line) for line in (self.path / 'commands').read_text().splitlines()]
        before = len([c for c in commands() if c[0] == 'run' and c[-1] == 'fortis-node-page'])
        self.run_action('stop')
        self.assertEqual(len([c for c in commands() if c[0] == 'run' and c[-1] == 'fortis-node-page']), before + 1)
        page = self.launched('page')
        mounts = {mount['destination']: mount for mount in page['config']['mounts']}
        self.assertEqual(mounts['/pages']['source'], str(self.root / 'deployment/public'))
        self.assertIn('ro', mounts['/pages']['options'])
        self.assertEqual(page['config']['process']['args'][-1], '/pages')
        # Starting the node takes the port back.
        self.run_action('start')
        self.assertIn('fortis-node-page SIGTERM', (self.path / 'signals').read_text().split('fortis-node SIGTERM')[-1])
        self.assertTrue(self.node_running())

    def new_host(self, **settings):
        """An image's contents under a scratch folder, and the host configured from them."""
        self.path.chmod(0o755)
        host = self.path / 'host'
        share = host / 'usr/share/fortis'
        share.mkdir(parents=True)
        shutil.copyfile(self.public, share / 'release-public.pem')
        shutil.copytree(self.release, share / 'node-release')
        tls = self.path / 'tls'
        tls.mkdir()
        ca, certificate, key, _ = create_certificates(tls, 'IP:127.0.0.1')
        self.server_certificate, self.server_key = certificate, key
        ports = self.free_ports(3)
        self.authority = Authority(self.path / 'authority', ca, tls / 'ca.key', certificate, key, ports[1])
        self.addCleanup(self.authority.close)
        values = {'FORTIS_HTTPS_IP': '127.0.0.1', 'FORTIS_NATIVE_TLS_CA': str(ca),
                  'FORTIS_NATIVE_ACME_DIRECTORY': self.authority.url('/dir'), 'FORTIS_NATIVE_ACME_LOOPBACK': '1',
                  'FORTIS_NATIVE_PORT': ports[0], 'FORTIS_NATIVE_HTTP_PORT': ports[1],
                  'FORTIS_NATIVE_HEALTH_HOST_PORT': ports[2],
                  'FORTIS_NATIVE_RUNTIME_STATE': str(self.path / 'runtime-state'),
                  'FORTIS_NATIVE_REQUIRE_CLOCK': '0', 'FORTIS_NATIVE_PREFLIGHT': '0', 'FORTIS_NATIVE_VERIFY_PID': '0',
                  'FORTIS_NATIVE_HEALTH_ATTEMPTS': '1', 'FORTIS_NATIVE_OBSERVE_SECONDS': '0'}
        values.update(settings)
        (host / 'etc/fortis').mkdir(parents=True)
        (host / 'etc/fortis/first-boot.conf').write_text(
            ''.join(f'{key}={value}\n' for key, value in values.items() if value is not None))
        self.config = host / 'etc/fortis/orchestrator.conf'
        self.root = host / 'var/lib/fortis/state'
        self.database = host / 'var/lib/fortis/data/kv'
        self.certificates = host / 'var/lib/fortis/certificates'
        return host

    def first_boot(self, host):
        result = subprocess.run([str(ROOT / 'image/files/manage-native-node.sh'), str(self.config), 'first-boot',
                                 str(host)], env=self.environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_new_host_configures_itself_and_installs_the_baked_release(self):
        host = self.new_host()
        self.assertIn('Host configured', self.first_boot(host))
        settings = dict(line.split('=', 1) for line in self.config.read_text().splitlines())
        self.assertEqual(settings['FORTIS_NATIVE_ROOT'], str(self.root))
        self.assertEqual(settings['FORTIS_NATIVE_BAKED_RELEASE'], str(host / 'usr/share/fortis/node-release'))
        self.assertEqual((settings['FORTIS_NATIVE_HTTPS'], settings['FORTIS_NATIVE_REQUIRE_MOUNT']), ('1', '0'))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        node = dict(line.split('=', 1) for line in (host / 'etc/fortis/node.env').read_text().splitlines())
        self.assertEqual(node['FORTIS_HTTPS_IP'], '127.0.0.1')
        self.assertEqual((host / 'etc/fortis/node.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o700)
        # Nothing is installed by first boot itself; the supervisor does that.
        self.assertFalse((self.root / 'app/current').exists())
        self.assertEqual(self.authority.requests, 0)

        self.run_action('tick')
        self.assertEqual(self.selected(), 'releases/one')
        self.assertTrue(self.node_running())
        self.assertTrue((self.certificates / 'current/ip.pem').exists())
        report = self.health()
        self.assertEqual((report['status'], report['node']['state'], report['node']['version']), (200, 'serving', 'one'))
        self.assertNotIn('Setup', [check['name'] for check in report['orchestrator']['checks']])
        self.assertIn('The node is running', self.published('index.html'))

        # Running first boot again changes nothing.
        before = self.config.read_text()
        self.assertIn('Host already configured', self.first_boot(host))
        self.assertEqual(self.config.read_text(), before)
        self.run_action('tick')
        self.assertTrue(self.node_running())

    def test_new_host_waits_for_a_certificate_without_blaming_the_release(self):
        host = self.new_host()
        self.first_boot(host)
        self.authority.refuse_orders = True
        self.run_action('tick')
        self.assertFalse((self.root / 'app/current').exists())
        report = self.health()
        setup = next(check for check in report['orchestrator']['checks'] if check['name'] == 'Setup')
        self.assertEqual(setup['state'], 'waiting')
        self.assertIn('did not issue a certificate', setup['detail'])
        self.assertIn('did not issue a certificate', self.published('index.html'))
        self.assertIn('This host is being set up', self.published('index.html'))
        # The release was never tried, so it is not quarantined.
        quarantine = self.root / 'quarantine'
        self.assertEqual(list(quarantine.iterdir()) if quarantine.exists() else [], [])
        # It does not ask again straight away...
        orders = self.authority.requests
        self.run_action('tick')
        self.assertEqual(self.authority.requests, orders)
        self.assertIn('Waiting to ask for a certificate again', self.published('index.html'))
        # ...and installs by itself once the authority answers.
        self.authority.refuse_orders = False
        (self.root / 'certificates.next').unlink()
        self.run_action('tick')
        self.assertEqual(self.selected(), 'releases/one')
        self.assertTrue(self.node_running())
        self.assertNotIn('did not issue', self.published('index.html'))

    def test_new_host_without_a_public_address_says_so_and_asks_nobody(self):
        host = self.new_host(FORTIS_HTTPS_IP='10.1.2.3', FORTIS_NATIVE_ACME_LOOPBACK=None,
                             FORTIS_NATIVE_ADDRESS_LOOKUP='off')
        self.first_boot(host)
        self.run_action('tick')
        self.assertFalse((self.root / 'app/current').exists())
        self.assertIn('not a public one', self.published('index.html'))
        self.assertEqual(self.authority.requests, 0)

    def lookup_services(self, host, *answers):
        """Stand-in address services, one per answer, named in the host's first-boot settings."""
        folder = self.path / 'lookup'
        folder.mkdir()
        for index, answer in enumerate(answers):
            (folder / str(index)).write_text(answer)
        services = Store(folder, self.server_certificate, self.server_key)
        self.addCleanup(services.close)
        with (host / 'etc/fortis/first-boot.conf').open('a') as file:
            file.write('FORTIS_NATIVE_ADDRESS_LOOKUP=' +
                       ' '.join(f'{services.url}/{index}' for index in range(len(answers))) +
                       '\nFORTIS_NATIVE_RELEASE_STORE_LOOPBACK=1\n')
        return services

    def node_environment(self, host):
        return dict(line.split('=', 1) for line in (host / 'etc/fortis/node.env').read_text().splitlines())

    def test_host_behind_address_translation_finds_its_public_address(self):
        host = self.new_host(FORTIS_HTTPS_IP='10.1.2.3', FORTIS_NATIVE_ACME_LOOPBACK=None)
        services = self.lookup_services(host, '8.8.4.4\n', '8.8.4.4')
        self.first_boot(host)
        self.assertEqual(self.node_environment(host)['FORTIS_HTTPS_IP'], '10.1.2.3')
        self.run_action('tick')
        environment = self.node_environment(host)
        self.assertEqual(environment['FORTIS_HTTPS_IP'], '8.8.4.4')
        self.assertEqual(environment['FORTIS_HEALTH_PORT'], '8081')   # the rest is kept
        self.assertEqual((host / 'etc/fortis/node.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(services.requests), 2)
        self.assertIn('Found this host', self.published('index.html'))
        # Nothing was installed and nobody was asked for a certificate in that tick.
        self.assertFalse((self.root / 'app/current').exists())
        self.assertEqual(self.authority.requests, 0)

    def address_not_believed(self, *answers):
        host = self.new_host(FORTIS_HTTPS_IP='10.1.2.3', FORTIS_NATIVE_ACME_LOOPBACK=None)
        services = self.lookup_services(host, *answers)
        self.first_boot(host)
        self.run_action('tick')
        self.assertEqual(self.node_environment(host)['FORTIS_HTTPS_IP'], '10.1.2.3')
        self.assertIn('could not be found', self.published('index.html'))
        # It does not ask again straight away.
        asked = len(services.requests)
        self.assertGreater(asked, 0)
        self.run_action('tick')
        self.assertEqual(len(services.requests), asked)
        self.assertEqual(self.authority.requests, 0)

    def test_address_services_that_disagree_are_not_believed(self):
        self.address_not_believed('8.8.4.4', '8.8.8.8')

    def test_address_service_naming_a_private_address_is_not_believed(self):
        self.address_not_believed('192.168.1.5')

    def test_address_service_answering_with_a_page_is_not_believed(self):
        self.address_not_believed('<html>8.8.4.4</html>')

    def test_first_boot_needs_the_release_key_from_the_image(self):
        host = self.new_host()
        (host / 'usr/share/fortis/release-public.pem').unlink()
        result = subprocess.run([str(ROOT / 'image/files/manage-native-node.sh'), str(self.config), 'first-boot',
                                 str(host)], env=self.environment, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no release key', result.stderr)
        self.assertFalse(self.config.exists())

    def test_baked_release_that_fails_to_verify_is_not_installed(self):
        host = self.new_host()
        self.first_boot(host)
        with (host / 'usr/share/fortis/node-release/fortis-node').open('ab') as file:
            file.write(b'tampered')
        self.run_action('tick')
        self.assertFalse((self.root / 'app/current').exists())
        self.assertIn('cannot be used', self.published('index.html'))
        self.assertEqual(self.authority.requests, 0)

    def test_modified_installed_release_refused(self):
        self.run_action('update', self.release)
        binary = self.root / 'app/releases/one/fortis-node'
        binary.chmod(0o755)
        binary.write_bytes(b'changed')
        self.run_action('start', success=False)

    def test_forced_shutdown_refused(self):
        self.run_action('update', self.release)
        (self.path / 'force-kill').touch()
        self.run_action('update', self.package('two'), success=False)
        self.assertEqual(self.selected(), 'releases/one')

    def test_update_lock_refuses_concurrent_process(self):
        import fcntl
        self.root.mkdir()
        with (self.root / 'update.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_action('update', self.release, success=False)

    def test_symlinked_payload_refused(self):
        binary = self.release / 'fortis-node'
        other = self.path / 'external'
        binary.rename(other)
        binary.symlink_to(other)
        self.run_action('update', self.release, success=False)

    def test_bad_config_permissions_refused(self):
        self.config.chmod(0o644)
        self.run_action('update', self.release, success=False)

    def test_insufficient_backup_space_restores_previous_code(self):
        self.run_action('update', self.release)
        # A file with a huge declared length and no stored data: a full copy
        # would have to write all of it, so it cannot fit.
        with (self.database / 'sparse').open('wb') as file:
            file.truncate(8 * 1024 ** 4)
        self.run_action('update', self.package('two'), success=False)
        self.assertEqual(self.selected(), 'releases/one')
        self.assertEqual(len(list((self.root / 'backups').iterdir())), 1)

    def test_failed_backup_removes_partial_copy_and_restores_code(self):
        self.run_action('update', self.release)
        (self.database / 'kept').write_bytes(b'data')
        os.mkfifo(self.database / 'zz-not-a-file')
        result = self.run_action('update', self.package('two'), success=False)
        self.assertIn('partial copy removed', result.stderr)
        self.assertEqual(self.selected(), 'releases/one')
        self.assertEqual(len(list((self.root / 'backups').iterdir())), 1)

    def test_backup_keeps_contents_owner_mode_and_time(self):
        self.run_action('update', self.release)
        (self.database / 'nested').mkdir(mode=0o750)
        file = self.database / 'nested/fortis.kv'
        file.write_bytes(os.urandom(300000))
        file.chmod(0o640)
        os.utime(file, (1700000000, 1700000000))
        (self.database / 'link').symlink_to('nested/fortis.kv')
        self.run_action('update', self.package('two'))
        backup = max((self.root / 'backups').iterdir(), key=lambda path: path.stat().st_mtime_ns)
        copy = backup / 'nested/fortis.kv'
        self.assertEqual(copy.read_bytes(), file.read_bytes())
        self.assertEqual(copy.stat().st_mode & 0o7777, 0o640)
        self.assertEqual(int(copy.stat().st_mtime), 1700000000)
        self.assertEqual((backup / 'nested').stat().st_mode & 0o7777, 0o750)
        self.assertEqual(os.readlink(backup / 'link'), 'nested/fortis.kv')

    def test_active_database_writer_refused(self):
        import fcntl
        self.run_action('update', self.release)
        with (self.database / 'fortis.kv.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_action('update', self.package('two'), success=False)
        self.assertEqual(self.selected(), 'releases/one')

    def test_invalid_recovery_target_never_selected(self):
        self.run_action('update', self.release)
        (self.root / 'pending').write_text('../../escape\n')
        self.run_action('recover', success=False)
        self.assertEqual(self.selected(), 'releases/one')
        self.assertTrue((self.root / 'pending').exists())

    def test_host_service_bounds_repeated_crashes(self):
        self.run_action('update', self.release)
        (self.path / 'crash-loop').touch()
        # The running node dies, and every restart dies again shortly after.
        os.kill(json.loads((self.path / 'state.json').read_text())['pids']['fortis-node'], 9)
        result = subprocess.run([str(ROOT / 'image/files/run-native-service.sh'), str(self.config)],
                                env=self.environment, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Repeated native node crashes', result.stderr)

    def test_missing_mount_refused(self):
        self.config.write_text(self.config.read_text().replace('FORTIS_NATIVE_REQUIRE_MOUNT=0', 'FORTIS_NATIVE_REQUIRE_MOUNT=1'))
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_runtime_environment_permissions_refused(self):
        self.env_file.chmod(0o644)
        self.run_action('update', self.release, success=False)

    def test_duplicate_manifest_fields_refused(self):
        with (self.release / 'manifest').open('a') as file:
            file.write('storage_epoch=1\n')
        self.sign(self.release)
        self.run_action('update', self.release, success=False)

    def test_oversized_signature_refused(self):
        (self.release / 'manifest.sig').write_bytes(b'x' * 16385)
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_previous_persistence_does_not_hide_current_write_failure(self):
        (self.path / 'write-fails').touch()
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_signature_by_another_key_or_key_type_refused(self):
        other = self.path / 'other.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(other)], check=True, capture_output=True)
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(other), '-out',
                        str(self.release / 'manifest.sig'), str(self.release / 'manifest')],
                       check=True, capture_output=True)
        self.run_action('update', self.release, success=False)
        self.sign(self.release)
        signature = bytearray((self.release / 'manifest.sig').read_bytes())
        signature[-1] ^= 1
        (self.release / 'manifest.sig').write_bytes(signature)
        self.run_action('update', self.release, success=False)
        self.sign(self.release)
        self.public.write_text('-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n')
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_configured_ca_bundle_is_not_overridden(self):
        self.env_file.write_text('NODE_ENV=development\nFORTIS_CA_BUNDLE_PATH=/data/ca-bundle.pem\n')
        self.run_action('update', self.release)
        environment = self.launched()['config']['process']['env']
        self.assertEqual([value for value in environment if value.startswith('FORTIS_CA_BUNDLE_PATH=')],
                         ['FORTIS_CA_BUNDLE_PATH=/data/ca-bundle.pem'])

    def test_dedicated_health_port_is_inherited(self):
        health, port = self.free_ports(2)
        with self.env_file.open('a') as file:
            file.write('FORTIS_HEALTH_PORT=8081\n')
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_HEALTH_HOST_PORT={health}\nFORTIS_NATIVE_PORT={port}\n')
        self.run_action('update', self.release)
        launched = self.launched()
        self.assertEqual(launched['listeners'], [f'127.0.0.1:{port}', f'127.0.0.1:{health}'])
        self.assertIn('FORTIS_LISTEN_FDS=8080=3,8081=4', launched['config']['process']['env'])

    def direct_https(self, domain='node.example'):
        # The certificate process is a different, unprivileged user when the
        # tests run as an administrator: it must be able to reach its own
        # state, the challenge directory and the trust file, and nothing else.
        self.path.chmod(0o755)
        self.certificates = self.path / 'certificates'
        self.challenges = self.path / 'challenges'
        self.certificates.mkdir()
        self.challenges.mkdir()
        with self.env_file.open('a') as file:
            file.write('FORTIS_HEALTH_PORT=8081\nFORTIS_HTTPS_CERT_DIR=/certificates\n'
                       'FORTIS_ACME_CHALLENGE_DIR=/acme\nFORTIS_HTTP_REDIRECT_PORT=8082\n'
                       'FORTIS_HTTPS_IP=127.0.0.1\n' + (f'FORTIS_HTTPS_DOMAIN={domain}\n' if domain else ''))
        # A stand-in certificate authority: the controller asks it for the
        # node's certificates exactly as it would ask the public one.
        tls = self.path / 'tls'
        tls.mkdir()
        ca, certificate, key, _ = create_certificates(tls, 'IP:127.0.0.1')
        self.ports = self.free_ports(3)
        self.authority = Authority(self.path / 'authority', ca, tls / 'ca.key', certificate, key, self.ports[1])
        self.addCleanup(self.authority.close)
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_TLS_CA={ca}\n'
                       f'FORTIS_NATIVE_ACME_DIRECTORY={self.authority.url("/dir")}\n'
                       f'FORTIS_NATIVE_ACME_STATE={self.path / "acme-state"}\nFORTIS_NATIVE_ACME_LOOPBACK=1\n'
                       f'FORTIS_NATIVE_HTTPS=1\nFORTIS_NATIVE_PORT={self.ports[0]}\n'
                       f'FORTIS_NATIVE_HTTP_PORT={self.ports[1]}\n'
                       f'FORTIS_NATIVE_HEALTH_HOST_PORT={self.ports[2]}\n'
                       f'FORTIS_NATIVE_CERTIFICATES={self.certificates}\n'
                       f'FORTIS_NATIVE_ACME_CHALLENGES={self.challenges}\n')

    def generation(self):
        return os.readlink(self.certificates / 'current')

    def subject(self, kind):
        return subprocess.run(['openssl', 'x509', '-in', str(self.certificates / 'current' / (kind + '.pem')),
                               '-noout', '-ext', 'subjectAltName'], capture_output=True, text=True).stdout

    def test_first_install_obtains_address_and_name_certificates(self):
        self.direct_https()
        self.run_action('update', self.release)
        self.assertIn('IP Address:127.0.0.1', self.subject('ip'))
        self.assertIn('DNS:node.example', self.subject('domain'))
        # Asked for as FortisNet, through the unprivileged page server.
        self.assertEqual(self.authority.user_agents, {'FortisNet-Orchestrator/1'})
        self.assertEqual(sorted(self.authority.subjects),
                         ['subject=CN=node.example,OU=FortisNet Node,O=FortisNet',
                          'subject=OU=FortisNet Node,O=FortisNet'])
        self.assertEqual([order['profile'] for order in self.authority.orders], ['shortlived', None])
        page = self.launched('page')
        self.assertEqual(page['listeners'], [f'0.0.0.0:{self.ports[1]}'])
        self.assertEqual(page['config']['process']['user'], {'uid': 10003, 'gid': 10003})
        self.assertIn('network', [entry['type'] for entry in page['config']['linux']['namespaces']])
        self.assertEqual({mount['destination'] for mount in page['config']['mounts']},
                         {'/proc', '/dev', '/page/native-controller', '/acme', '/pages'})
        commands = (self.path / 'signals').read_text()
        self.assertIn('fortis-node-page SIGTERM', commands)
        # Nothing is left behind for the next challenge to trip over, and the
        # keys are readable by the node only.
        self.assertEqual(list(self.challenges.iterdir()), [])
        directory = self.certificates / self.generation()
        self.assertEqual(directory.stat().st_mode & 0o777, 0o500)
        self.assertEqual((directory / 'ip.key').stat().st_mode & 0o777, 0o400)
        self.assertIn('FORTIS_HTTPS_DOMAIN=node.example', self.launched()['config']['process']['env'])
        self.assertEqual((self.path / 'certificate-loads').read_text().splitlines(), [self.generation()])
        self.assertIn('Certificates are current', self.run_action('certificates').stdout)

    def test_page_server_serves_challenges_and_nothing_else(self):
        # The real program, given one listening socket the way the keeper
        # gives it: no configuration, no other file, no port of its own.
        challenges = self.path / 'page-challenges'
        challenges.mkdir()
        (challenges / 'token_A-1').write_text('token_A-1.thumbprint')
        (self.path / 'secret').write_text('not for the internet')
        (challenges / 'link').symlink_to(self.path / 'secret')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        pages = self.path / 'served-pages'
        pages.mkdir()
        first_page = '<!DOCTYPE html><title>first page</title>' + 'x' * 400000  # larger than a socket buffer
        (pages / 'index.html').write_text(first_page)
        (pages / 'health.html').write_text('<!DOCTYPE html><title>health</title>')
        (pages / 'health.json').write_text('{"status":200}\n')
        (pages / 'health.status').write_text(f'200 {int(time.time() * 1000)}\n')
        server = subprocess.Popen([str(ROOT / 'image/files/manage-native-node.sh'), str(challenges), 'page-server',
                                   str(pages)],
                                  env=dict(os.environ, FORTIS_LISTEN_FDS=f'8082={listener.fileno()}'),
                                  pass_fds=[listener.fileno()])
        self.addCleanup(server.wait, 5)
        self.addCleanup(server.terminate)

        def get(target, method='GET'):
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.sendall(f'{method} {target} HTTP/1.1\r\nHost: x\r\n\r\n'.encode())
                data = b''
                while chunk := client.recv(4096):
                    data += chunk
            head, _, body = data.partition(b'\r\n\r\n')
            return int(head.split()[1]), body.decode()

        self.assertEqual(get('/.well-known/acme-challenge/token_A-1'), (200, 'token_A-1.thumbprint'))
        self.assertEqual(get('/.well-known/acme-challenge/token_A-1', 'HEAD'), (200, ''))
        for target in ('/.well-known/acme-challenge/absent', '/.well-known/acme-challenge/link',
                       '/.well-known/acme-challenge/../secret', '/.well-known/acme-challenge/a/b',
                       '/.well-known/acme-challenge/'):
            self.assertEqual(get(target)[0], 404, target)
        # The orchestrator's pages, whole, with the status the report states.
        self.assertEqual(get('/'), (200, first_page))
        self.assertEqual(get('/?utm=x')[0], 200)
        self.assertEqual(get('/', 'HEAD'), (200, ''))
        self.assertEqual(get('/health'), (200, '<!DOCTYPE html><title>health</title>'))
        self.assertEqual(get('/health.json'), (200, '{"status":200}\n'))
        (pages / 'health.status').write_text(f'503 {int(time.time() * 1000)}\n')
        self.assertEqual(get('/health')[0], 503)
        self.assertEqual(get('/health.json'), (503, '{"status":200}\n'))
        # A healthy report that nobody refreshed for two minutes is not believed.
        (pages / 'health.status').write_text(f'200 {int(time.time() * 1000) - 120000}\n')
        self.assertEqual(get('/health')[0], 503)
        for broken in ('', 'garbage\n', '200\n', '200 soon\n', f'200 {int(time.time() * 1000) + 3600000}\n'):
            (pages / 'health.status').write_text(broken)
            self.assertEqual(get('/health.json')[0], 503, repr(broken))
        # Nothing but those addresses is served from the folder.
        (pages / 'secret.html').write_text('not linked')
        for target in ('/secret.html', '/index.html', '/health.status', '/dashboard', '/v1/networks', '//', '/../x'):
            status, body = get(target)
            self.assertEqual(status, 503, target)
            self.assertIn('https://blockchain.fortisnet.io', body)
        self.assertEqual(get('/', 'POST')[0], 405)
        (pages / 'index.html').unlink()
        self.assertEqual(get('/')[0], 503)
        # A client that connects and says nothing does not hold up the next.
        with socket.create_connection(('127.0.0.1', port), timeout=5):
            self.assertEqual(get('/.well-known/acme-challenge/token_A-1')[0], 200)
        with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
            client.sendall(b'GET /' + b'a' * 8192)
            self.assertEqual(get('/.well-known/acme-challenge/token_A-1')[0], 200)
        server.terminate()
        self.assertEqual(server.wait(5), 0)

    def test_address_only_node_needs_no_name(self):
        self.direct_https(domain=None)
        self.run_action('update', self.release)
        self.assertEqual(len(self.authority.orders), 1)
        self.assertFalse((self.certificates / 'current/domain.pem').exists())
        self.assertFalse(any(value.startswith('FORTIS_HTTPS_DOMAIN=')
                             for value in self.launched()['config']['process']['env']))

    def test_name_that_does_not_point_here_leaves_the_address_serving(self):
        self.direct_https()
        self.authority.fail_names = {'node.example'}
        result = self.run_action('update', self.release)
        self.assertIn('domain: certificate authority reports invalid', result.stderr)
        self.assertIn('the challenge file was not served', result.stderr)
        self.assertFalse((self.certificates / 'current/domain.pem').exists())
        self.assertFalse(any(value.startswith('FORTIS_HTTPS_DOMAIN=')
                             for value in self.launched()['config']['process']['env']))
        self.assertTrue(self.node_running())

    def test_renewal_reloads_the_running_node_without_restart(self):
        self.direct_https(domain=None)
        # Issued five days ago for six days: under a third of its life left.
        self.authority.valid_days = (5, 1)
        self.run_action('update', self.release)
        first, pid = self.generation(), self.keeper('state')
        self.authority.valid_days = (0, 6)
        self.assertIn('Certificates renewed', self.run_action('certificates').stdout)
        self.assertNotEqual(self.generation(), first)
        self.assertEqual(self.keeper('state'), pid)
        self.assertIn('fortis-node SIGHUP', (self.path / 'signals').read_text())
        self.assertEqual((self.path / 'certificate-loads').read_text().splitlines(), [first, self.generation()])
        # The serving node answered the challenge itself: the page server ran
        # for the first certificate only.
        runs = [json.loads(line) for line in (self.path / 'commands').read_text().splitlines()]
        self.assertEqual(len([run for run in runs if run[0] == 'run' and run[-1] == 'fortis-node-page']), 1)
        self.assertIn('Certificates are current', self.run_action('certificates').stdout)

    def test_stale_anti_replay_value_is_retried(self):
        self.direct_https(domain=None)
        self.authority.bad_nonce_once = True
        self.run_action('update', self.release)
        self.assertTrue((self.certificates / 'current/ip.pem').exists())

    def test_authority_refusal_is_reported_and_nothing_starts(self):
        self.direct_https(domain=None)
        self.authority.refuse_orders = True
        result = self.run_action('update', self.release, success=False)
        self.assertIn('urn:ietf:params:acme:error:rateLimited', result.stderr)
        self.assertFalse((self.certificates / 'current').exists())
        self.assertFalse(self.node_running())
        self.assertFalse((self.root / 'app/current').exists())

    def test_certificate_for_another_name_is_refused_by_the_administrator_side(self):
        self.direct_https(domain=None)
        self.authority.issue_for = '127.0.0.9'
        result = self.run_action('update', self.release, success=False)
        self.assertIn('not trusted for this name or address', result.stderr)
        self.assertFalse((self.certificates / 'current').exists())

    def test_direct_https_inherits_tls_and_acme_only(self):
        self.direct_https()
        self.run_action('update', self.release)
        launched = self.launched()
        self.assertEqual(launched['listeners'], [f'0.0.0.0:{self.ports[0]}', f'0.0.0.0:{self.ports[1]}',
                                                 f'127.0.0.1:{self.ports[2]}'])
        self.assertIn('FORTIS_LISTEN_FDS=8080=3,8082=4,8081=5', launched['config']['process']['env'])
        mounts = {mount['destination']: mount for mount in launched['config']['mounts']}
        for target in ('/certificates', '/acme'):
            self.assertIn('ro', mounts[target]['options'])
        self.assertTrue(launched['config']['root']['readonly'])

    def sandbox_control(self):
        directory = self.path / 'sandbox-control'
        directory.mkdir(mode=0o755)
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_SANDBOX_CONTROL={directory}\n')
        return directory

    def test_sandbox_control_is_readonly_and_unprivileged(self):
        directory = self.sandbox_control()
        self.run_action('update', self.release)
        mounts = {mount['destination']: mount for mount in self.launched()['config']['mounts']}
        self.assertEqual(mounts['/run/fortis-sandbox']['source'], str(directory))
        self.assertIn('ro', mounts['/run/fortis-sandbox']['options'])
        self.run_action('start')

    def test_sandbox_control_refuses_writable_and_symlink_directories(self):
        directory = self.sandbox_control()
        directory.chmod(0o777)
        self.run_action('update', self.release, success=False)
        directory.chmod(0o755)
        directory.rmdir()
        directory.symlink_to(self.database, target_is_directory=True)
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_direct_https_requires_consistent_environment(self):
        self.direct_https()
        self.env_file.write_text(self.env_file.read_text().replace('FORTIS_HTTPS_CERT_DIR=/certificates',
                                                                 'FORTIS_HTTPS_CERT_DIR=/data'))
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_tls_environment_cannot_silently_run_in_proxy_mode(self):
        with self.env_file.open('a') as file:
            file.write('FORTIS_HTTPS_CERT_DIR=/certificates\n')
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_invalid_or_unconfigured_health_forward_refused(self):
        original = self.config.read_text()
        for value in ['text', '999999', '8080', '8081']:
            self.config.write_text(original + f'FORTIS_NATIVE_HEALTH_HOST_PORT={value}\n')
            self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def test_storage_failure_is_not_readiness(self):
        (self.path / 'storage-fails').touch()
        self.run_action('update', self.release, success=False)
        self.assertFalse((self.root / 'app/current').exists())

    def public_state(self):
        return json.loads((self.root / 'deployment/public/current.json').read_text())

    def test_hash_history_and_serving_intervals(self):
        self.run_action('update', self.release)
        first = self.public_state()['current']
        self.assertEqual(first['sha256'], hashlib.sha256((self.release / 'fortis-node').read_bytes()).hexdigest())
        self.run_action('update', self.package('two'))
        current = self.public_state()['current']
        self.assertNotEqual(first['deploymentId'], current['deploymentId'])
        rows = json.loads((self.root / 'deployment/public/history-0.json').read_text())['records']
        prior = next(row for row in rows if row['deploymentId'] == first['deploymentId'])
        self.assertIsNotNone(prior['trafficDisabledAtMs'])
        self.assertIsNotNone(prior['drainedAtMs'])
        self.assertTrue(prior['timeUncertain'])
        self.assertEqual(current['phase'], 'stable')

    def test_signed_source_provenance(self):
        text = (self.release / 'manifest').read_text().replace('format=1', 'format=2')
        text += 'source_commit=' + 'a'*40 + '\nbuild_inputs_sha256=' + 'b'*64 + '\n'
        (self.release / 'manifest').write_text(text)
        self.sign(self.release)
        self.run_action('update', self.release)
        self.assertEqual(self.public_state()['current']['sourceCommit'], 'a'*40)

    def test_v2_restart_verifies_snapshot_before_publishing_serving_row(self):
        text = (self.release / 'manifest').read_text().replace('format=1', 'format=2')
        (self.release / 'manifest').write_text(text + 'source_commit=' + 'a'*40 + '\nbuild_inputs_sha256=' + 'b'*64 + '\n')
        self.sign(self.release)
        self.run_action('update', self.release)
        first = self.public_state()['current']
        self.run_action('stop')
        self.assertIsNone(self.public_state()['current'])
        self.run_action('start')
        current = self.public_state()['current']
        self.assertEqual(current['phase'], 'stable')
        self.assertEqual(current['sha256'], first['sha256'])
        self.assertGreater(current['instanceId'], first['instanceId'])
        self.assertIsNone(self.public_state()['candidate'])

    def test_v2_restart_rejects_managed_snapshot_from_wrong_mount(self):
        text = (self.release / 'manifest').read_text().replace('format=1', 'format=2')
        (self.release / 'manifest').write_text(text + 'source_commit=' + 'a'*40 + '\nbuild_inputs_sha256=' + 'b'*64 + '\n')
        self.sign(self.release)
        self.run_action('update', self.release)
        self.run_action('stop')
        (self.path / 'wrong-metadata').touch()
        result = self.run_action('start', success=False)
        self.assertIn('readiness failed', result.stderr)
        self.assertIsNone(self.public_state()['current'])

    def test_unverified_upload_is_recorded_without_claiming_signature(self):
        (self.release / 'manifest.sig').unlink()
        self.run_action('update', self.release, success=False)
        page = json.loads((self.root / 'deployment/public/history-0.json').read_text())
        self.assertFalse(page['records'][0]['signatureVerified'])
        self.assertIsNone(page['records'][0]['sha256'])
        self.assertIsNone(page['records'][0]['trafficEnabledAtMs'])

    def test_quarantine_requires_explicit_retry(self):
        self.run_action('update', self.release)
        two = self.package('two')
        (self.path / 'fail-target').write_text('releases/two')
        self.run_action('update', two, success=False)
        (self.path / 'fail-target').unlink()
        self.run_action('update', two, success=False)
        self.assertEqual(self.selected(), 'releases/one')
        self.run_action('retry', two)
        self.assertEqual(self.selected(), 'releases/two')

    def test_corrupt_ledger_refuses_promotion_without_stopping_worker(self):
        self.run_action('update', self.release)
        (self.root / 'deployment/head').write_text('corrupt')
        before = (self.path / 'commands').read_text()
        self.run_action('update', self.package('two'), success=False)
        self.assertEqual((self.path / 'commands').read_text(), before)
        self.assertTrue(self.node_running())

    def observation(self, *, timeout=8):
        self.run_action('update', self.release)
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_OBSERVE_SECONDS=1\nFORTIS_NATIVE_MIN_REQUESTS=10\nFORTIS_NATIVE_OBSERVE_TIMEOUT_SECONDS={timeout}\n')

    def test_node_regression_rolls_back_after_consecutive_observations(self):
        self.observation()
        (self.path / 'incident-kind').write_text('node')
        self.run_action('update', self.package('two'), success=False)
        self.assertEqual(self.selected(), 'releases/one')
        rows = json.loads((self.root / 'deployment/public/history-0.json').read_text())['records']
        failed = next(row for row in rows if row['version']=='two')
        self.assertEqual(failed['reason'], 'node-regression')

    def test_provider_failures_do_not_blame_the_release(self):
        self.observation()
        (self.path / 'incident-kind').write_text('third_party')
        self.run_action('update', self.package('two'))
        self.assertEqual(self.selected(), 'releases/two')
        self.assertEqual(self.public_state()['current']['providerEvents'], 3)

    def test_missing_traffic_does_not_establish_success(self):
        self.observation(timeout=3)
        (self.path / 'no-traffic').touch()
        self.run_action('update', self.package('two'), success=False)
        self.assertEqual(self.selected(), 'releases/one')
        rows = json.loads((self.root / 'deployment/public/history-0.json').read_text())['records']
        self.assertEqual(next(r for r in rows if r['version']=='two')['reason'], 'insufficient-evidence')

    def test_configuration_is_data_not_shell(self):
        marker = self.path / 'must-not-exist'
        with self.config.open('a') as file:
            file.write(f'FORTIS_NATIVE_ROOT=$(touch {marker})\n')
        self.run_action('update', self.release, success=False)
        self.assertFalse(marker.exists())

    def test_supervisor_shutdown_waits_for_active_update_recovery(self):
        import signal
        import time
        self.observation(timeout=4)
        (self.path / 'no-traffic').touch()
        two = self.package('two')
        update = subprocess.Popen([str(ROOT / 'image/files/manage-native-node.sh'), str(self.config), 'update', str(two)],
                                  env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        service = None
        try:
            deadline = time.monotonic()+12
            while time.monotonic()<deadline:
                state = self.public_state()
                if state['candidate'] and state['candidate']['phase']=='observing':
                    break
                if update.poll() is not None:
                    self.fail('update ended before its observation window')
                time.sleep(.05)
            else:
                self.fail('candidate did not reach observation')
            service = subprocess.Popen([str(ROOT / 'image/files/run-native-service.sh'), str(self.config)],
                                       env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(.2)
            service.send_signal(signal.SIGTERM)
            update.communicate(timeout=15)
            output, errors = service.communicate(timeout=15)
            self.assertNotEqual(update.returncode, 0)
            self.assertEqual(service.returncode, 0, errors.decode())
            self.assertEqual(self.selected(), 'releases/one')
            self.assertFalse(self.node_running())
            self.assertIsNone(self.public_state()['current'])
        finally:
            for process in (update, service):
                if process is not None and process.poll() is None:
                    process.kill(); process.communicate()


if __name__ == '__main__':
    unittest.main()
