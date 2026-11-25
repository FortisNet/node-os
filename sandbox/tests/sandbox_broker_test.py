#!/usr/bin/env python3
"""Real node (UID 10001) -> root local broker -> real gVisor. Disposable Linux only."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time


def main():
    assert os.environ.get('FORTIS_DISPOSABLE_SANDBOX_TEST') == '1'
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    assert Path('/proc/self/cgroup').read_text().strip() == '0::/'
    manager, node = map(lambda x: str(Path(x).resolve()), sys.argv[1:3])
    cg = Path('/sys/fs/cgroup'); (cg / 'test-control').mkdir()
    for pid in (cg / 'cgroup.procs').read_text().split():
        try: (cg / 'test-control/cgroup.procs').write_text(pid)
        except ProcessLookupError: pass
    (cg / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    for registry in ['/etc/subuid', '/etc/subgid']:
        Path(registry).write_text('fortis-sandbox:1048576:131072\n')
    root = Path('/opt/fortis-sandboxes/images/fixture/rootfs')
    for directory in ['', 'bin', 'proc', 'tmp', 'dev']: (root / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile('/sandbox-payload', root / 'bin/probe'); (root / 'bin/probe').chmod(0o555)
    policy = Path('/root/policy.json'); runtime = Path('/usr/local/bin/runsc')
    policy.write_text(json.dumps({'schemaVersion':1,'runtimeSha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
                                 'maxJobs':2,'cpuBudgetMillicores':2000,'memoryBudgetMiB':1024}))
    policy.chmod(0o600)
    endpoint = Path('/run/fortis-sandbox/node.sock'); endpoint.parent.mkdir(mode=0o755)
    jobs = Path('/var/lib/fortis-sandboxes/jobs')
    checks = []

    def admin(*args):
        r = subprocess.run([manager, str(policy), *args], capture_output=True, text=True, timeout=40)
        assert r.returncode == 0, r
        return r

    def command(*args, uid=10001, code=0, sock=endpoint):
        r = subprocess.run([node, 'sandbox', str(sock), *map(str,args)], user=uid, group=uid, extra_groups=[],
                           capture_output=True, text=True, timeout=8)
        assert r.returncode == code, (args,r)
        assert 'private-' not in r.stderr
        if r.stdout:
            body = json.loads(r.stdout)
            assert 'ownerUid' not in body and 'requestHash' not in body and 'args' not in body
            return body
        return None

    def spec(job, mode='cpu', **extra):
        p = Path('/tmp') / (job+'.json')
        p.write_text(json.dumps({'schemaVersion':1,'id':job,'image':'fixture','args':['/bin/probe',mode],
                                 'timeoutSeconds':30} | extra)); p.chmod(0o644)
        return p

    def record(job): return json.loads((jobs/job/'record').read_text().splitlines()[0])

    def wait(job, states):
        end = time.monotonic()+12
        while time.monotonic()<end:
            try:
                r=record(job)
                if r['state'] in states: return r
            except FileNotFoundError: pass
            time.sleep(.05)
        raise AssertionError((job,record(job)))

    def spawn_broker():
        p=subprocess.Popen([manager,str(policy),'broker',str(endpoint),'10001'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        end=time.monotonic()+5
        while time.monotonic()<end:
            if p.poll() is not None: raise AssertionError(p.communicate())
            if endpoint.exists():
                try:
                    command('status','absent',code=1)
                    return p
                except AssertionError: pass
            time.sleep(.03)
        raise AssertionError('broker did not start')

    def raw(packet, uid=10001, delay=False):
        script = '''import socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect(sys.argv[1]);s.sendall(bytes.fromhex(sys.argv[2]))
if sys.argv[3]=='1':time.sleep(2.5)
else:s.shutdown(socket.SHUT_WR)
b=b''
while True:
 try:x=s.recv(8192)
 except ConnectionResetError:break
 if not x:break
 b+=x
print(b.hex())'''
        r=subprocess.run([sys.executable,'-c',script,str(endpoint),packet.hex(),str(int(delay))],
                         user=uid,group=uid,extra_groups=[],capture_output=True,text=True,timeout=7)
        assert r.returncode==0,r
        data=bytes.fromhex(r.stdout.strip());assert data[:5]==b'FSB1\x01' and len(data)>=12,data
        return data[5],json.loads(data[12:])

    def frame(op,body): return b'FSB1\x00'+bytes([op,0,0])+struct.pack('!I',len(body))+body

    admin('init')
    supervisor=subprocess.Popen([manager,str(policy),'supervise'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    time.sleep(.3)
    broker=spawn_broker()
    try:
        # This invokes the actual production entry point, not a fake client.
        p=spec('owned')
        accepted=command('start',p);assert accepted['id']=='owned'
        wait('owned',{'running'})
        assert record('owned')['ownerUid']==10001
        again=command('start',p);assert again['createdAtMs']==accepted['createdAtMs']
        changed=spec('owned','fail');assert command('start',changed,code=1)['error']=='conflict'
        command('status','owned',uid=10002,code=2)
        # Even if DAC is accidentally widened, kernel peer authentication rejects another UID.
        endpoint.chmod(0o666)
        assert raw(frame(2,b'owned'),uid=10002)[0]==4
        endpoint.chmod(0o600)
        command('stop','owned');wait('owned',{'cancelled'});command('stop','owned')
        checks += ['actual-node-unprivileged-start-status-stop','durable-owner','idempotent-start','conflicting-id',
                   'unauthorized-uid-dac','unauthorized-uid-peercred','idempotent-stop','sanitized-replies']
        # Concurrent callers share one durable idempotent execution, never duplicate admission.
        same=spec('concurrent')
        with ThreadPoolExecutor(max_workers=6) as pool:
            replies=list(pool.map(lambda _: command('start',same),range(6)))
        assert len({reply['createdAtMs'] for reply in replies})==1
        wait('concurrent',{'running'})
        command('start',spec('capacity'));wait('capacity',{'running'})
        assert command('start',spec('over-capacity'),code=1)['error']=='busy'
        assert not (jobs/'over-capacity').exists()
        with ThreadPoolExecutor(max_workers=6) as pool:
            replies=list(pool.map(lambda _: command('stop','concurrent'),range(6)))
        wait('concurrent',{'cancelled'})
        command('stop','capacity');wait('capacity',{'cancelled'})
        # Terminal ids stay terminal; retry cannot restart a completed/cancelled job.
        assert command('start',same)['state']=='cancelled'
        fifo=Path('/tmp/not-a-spec');os.mkfifo(fifo,0o644)
        command('start',fifo,code=2);fifo.unlink()
        checks += ['concurrent-idempotent-start','concurrent-idempotent-stop','bounded-admission',
                   'terminal-id-not-reexecuted','nonregular-spec-refused-without-blocking']
        # Invalid frames and attempts to request host capabilities do not start jobs.
        for packet in [b'BAD1\0\x01\0\0'+struct.pack('!I',1)+b'x',frame(9,b'x'),
                       b'FSB1\0\x01\0\0'+struct.pack('!I',2**32-1),frame(2,b'../owned'),
                       frame(1,b'{"schemaVersion":1,"id":"private-bad","image":"fixture","args":["/bin/probe","cpu"],"mounts":[]}'),
                       frame(1,b'{}')+b'extra']:
            assert raw(packet)[0]==6,packet
        assert not (jobs/'private-bad').exists()
        assert raw(b'FSB1',delay=True)[0]==6
        checks += ['bad-version-opcode-length','path-traversal','unknown-capabilities','trailing-data','slow-client-deadline']
        # Root/admin jobs cannot be read or stopped by the node principal.
        legacy=spec('admin-job')
        root_manager=subprocess.Popen([manager,str(policy),'run',str(legacy)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        wait('admin-job',{'running'})
        assert command('status','admin-job',code=1)['error']=='not_found'
        assert command('stop','admin-job',code=1)['error']=='not_found'
        assert not (jobs/'admin-job/cancel').exists()
        admin('stop','admin-job');root_manager.communicate(timeout=30)
        checks.append('admin-jobs-not-authorized')
        # Broker death leaves bounded jobs monitorable by a fresh authenticated broker.
        p=spec('restart')
        command('start',p);wait('restart',{'running'})
        broker.kill();broker.communicate(timeout=10)
        broker=spawn_broker()
        assert command('status','restart')['id']=='restart'
        command('stop','restart');wait('restart',{'cancelled'})
        checks += ['broker-crash-restart','no-inherited-broker-lock','durable-reconnect-control']
        # Reject a fake non-root listener, without sending it request data.
        fake=endpoint.with_name('fake.sock')
        fake_script='''import socket,os,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600);os.setgroups([]);os.setgid(10001);os.setuid(10001);s.listen()
c,_=s.accept();print(len(c.recv(100)),flush=True)'''
        fake_server=subprocess.Popen([sys.executable,'-c',fake_script,str(fake)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        end=time.monotonic()+3
        while not fake.exists() and time.monotonic()<end: time.sleep(.02)
        os.chown(fake,10001,0)
        command('status','owned',sock=fake,code=2)
        out,err=fake_server.communicate(timeout=5);assert fake_server.returncode==0 and out.strip()=='0',(out,err)
        fake.unlink();checks.append('mutual-auth-fake-server-rejected-before-send')
        # The node has no authority to edit protected records or cgroup settings.
        denied=subprocess.run([sys.executable,'-c',"open('/var/lib/fortis-sandboxes/jobs/owned/record').read()"],
                              user=10001,group=10001,extra_groups=[],capture_output=True)
        assert denied.returncode!=0;checks.append('node-cannot-read-private-state')
        command('start',spec('shutdown'));wait('shutdown',{'running'})
        broker.terminate();out,err=broker.communicate(timeout=25);assert broker.returncode==0,(out,err)
        wait('shutdown',{'cancelled'});assert not endpoint.exists()
        checks.append('graceful-broker-shutdown')
    finally:
        if broker.poll() is None: broker.terminate();broker.communicate(timeout=30)
        supervisor.terminate();out,err=supervisor.communicate(timeout=40);assert supervisor.returncode==0,(out,err)
    print(json.dumps({'passed':True,'nodeUid':10001,'brokerUid':0,'checks':checks,'gvisor':subprocess.check_output([str(runtime),'--version'],text=True).splitlines()[0]},sort_keys=True))


if __name__=='__main__':main()
