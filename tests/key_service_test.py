#!/usr/bin/env python3
"""The key service end to end (docs/fortis-did.md, sections 9 to 13).

  key_service_test.py BUILD/fortis-keyd BUILD/key_client_tool

Starts fortis-keyd on fresh folders, connects to node.sock as the
orchestrator does, and hands the connection to key_client_tool, a stand-in
for the node, through FORTIS_KEYS_FD. Checks the first start, signing with
every algorithm, parallel channels, refusals of malformed requests, that the
identity survives a restart, and that a damaged or unsafe store is refused.
"""
import hashlib
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

KEYD, TOOL = sys.argv[1], sys.argv[2]
failures = []


def check(condition, what):
    if not condition:
        failures.append(what)
        print(f'FAILED: {what}', file=sys.stderr)


class Service:
    def __init__(self, root):
        self.store = root / 'store'
        self.sockets = root / 'run'
        self.log = root / 'keyd.log'
        self.process = None

    def start(self, wait=True):
        log = open(self.log, 'ab')
        self.process = subprocess.Popen([KEYD, str(self.store), str(self.sockets)], stdout=log, stderr=log)
        if not wait:
            return self.process.wait(timeout=120)
        deadline = time.monotonic() + 120  # the first start makes SQIsign keys
        while not self.answering():
            if self.process.poll() is not None:
                raise SystemExit(f'fortis-keyd stopped:\n{self.log.read_text()}')
            if time.monotonic() > deadline:
                raise SystemExit('fortis-keyd did not start')
            time.sleep(0.05)
        return None

    def answering(self):
        try:
            self.connect().close()
            return True
        except OSError:
            return False

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.sockets / 'node.sock'))
        return s

    def node(self, *arguments):
        """Run the node stand-in with one node channel, as the orchestrator will."""
        with self.connect() as channel:
            fd = channel.fileno()
            environment = dict(os.environ, FORTIS_KEYS_FD=str(fd))
            return subprocess.run([TOOL, *arguments], pass_fds=(fd,), env=environment, capture_output=True,
                                  text=True, timeout=300)


def info(service):
    result = service.node('info')
    check(result.returncode == 0, f'info answers: {result.stderr}')
    return dict(line.split('=', 1) for line in result.stdout.split())


def header(code, length, request_id=1, direction=0, magic=b'FKD1'):
    return magic + struct.pack('>BBHII', direction, code, 0, request_id, length)


def reply(s):
    data = b''
    while len(data) < 16:
        try:
            chunk = s.recv(16 - len(data))
        except ConnectionResetError:
            # Linux resets a connection closed with unread data in it: refused, as an end of stream is.
            return None
        if not chunk:
            return None
        data += chunk
    return data


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        service = Service(root)
        service.start()
        try:
            first = info(service)
            check(first.get('ready') == '1', 'ready')
            check(first.get('did', '').startswith('did:fortis:pq2:') and len(first['did']) == 15 + 128, 'a pq2 DID')
            check(len(first.get('machine', '')) == 32, 'a 32-character machine ID')
            check(first.get('algorithms') == '123', 'all three algorithms offered')
            check('created identity' in service.log.read_text(), 'the first start is logged as a creation')

            for name in ('identity.key', 'machine.key'):
                mode = stat.S_IMODE((service.store / name).stat().st_mode)
                check(mode == 0o600, f'{name} is mode 0600')
            check(stat.S_IMODE(service.store.stat().st_mode) == 0o700, 'store folder is mode 0700')
            check(stat.S_IMODE(service.sockets.stat().st_mode) == 0o700, 'socket folder is mode 0700')
            check(b'did:fortis' not in (service.store / 'identity.key').read_bytes(), 'the key file holds no text')
            # The public part, for the orchestrator's pages, and nothing else in that file.
            public = service.store / 'identity.public'
            check(public.read_text() == f"did={first.get('did')}\nmachine={first.get('machine')}\n",
                  'identity.public holds the DID and the machine ID')
            check(stat.S_IMODE(public.stat().st_mode) == 0o644, 'identity.public is mode 0644')

            result = service.node('roundtrip')
            check(result.returncode == 0, f'round trips: {result.stderr}')
            print(result.stdout, end='')
            result = service.node('audit')
            check(result.returncode == 0, f'a peer can check the signatures against the log: {result.stderr}')
            print(result.stdout, end='')
            audited_last = int(result.stdout.split('last=')[1].split()[0]) if 'last=' in result.stdout else 0
            mode = stat.S_IMODE((service.store / 'signing.log').stat().st_mode)
            check(mode == 0o600, 'signing.log is mode 0600')
            result = service.node('badlabel')
            check(result.returncode == 0 and 'refused' in result.stdout, 'invalid label refused')
            result = service.node('parallel', '4')
            check(result.returncode == 0, f'parallel channels: {result.stderr}')
            print(result.stdout, end='')

            # Malformed requests: the service answers BadRequest, or ends the stream.
            with service.connect() as s:
                s.sendall(header(2, 1) + b'\x09')  # PublicKey of an unknown algorithm
                answer = reply(s)
                check(answer is not None and answer[5] == 1, 'unknown algorithm: BadRequest')
                s.sendall(header(3, 3) + b'\x01\x05a')  # Sign with a label longer than the body
                answer = reply(s)
                check(answer is not None and answer[5] == 1, 'short Sign body: BadRequest')
                label = b'Bad label'  # refused by the service itself, not only by the client library
                body = bytes([3, len(label)]) + label + b'message'
                s.sendall(header(3, len(body)) + body)
                answer = reply(s)
                check(answer is not None and answer[5] == 1, 'invalid label sent to the service: BadRequest')
                s.sendall(header(1, 0, request_id=77))  # the stream still works after a refusal
                answer = reply(s)
                check(answer is not None and answer[5] == 0 and struct.unpack('>I', answer[8:12])[0] == 77,
                      'request IDs are copied into replies')
            for bad in (header(1, 0, magic=b'XKD1'), header(1, 0, direction=1), header(9, 0),
                        header(1, 5), header(3, (1 << 20) + 67)):
                with service.connect() as s:
                    s.sendall(bad)
                    check(reply(s) is None, f'malformed header ends the stream: {bad.hex()}')

            # At most 64 channels: the 65th connection is closed unanswered.
            time.sleep(0.5)  # the channels of the requests above end
            held = []
            for _ in range(64):
                s = service.connect()
                s.sendall(header(1, 0))
                held.append((s, reply(s)))
            check(all(answer is not None and answer[5] == 0 for _, answer in held), '64 channels are served')
            with service.connect() as s:
                s.sendall(header(1, 0))
                check(reply(s) is None, 'a 65th channel is refused')
            for s, _ in held:
                s.close()
            time.sleep(0.5)
            check(info(service).get('did') == first.get('did'), 'channels are served again once others close')

            # One key service per store.
            second_service = Service(root)
            second_service.sockets = root / 'run2'
            check(second_service.start(wait=False) == 1, 'a second key service on the same store stops')
            check('another key service' in second_service.log.read_text(), 'and says why')

            # The identity survives a restart; nothing is made again.
            service.stop()
            service.start()
            second = info(service)
            check(second.get('did') == first.get('did'), 'same DID after a restart')
            check(second.get('machine') == first.get('machine'), 'same machine ID after a restart')
            check('opened identity' in service.log.read_text(), 'a restart is logged as opening')
            # Sequence numbers continue after a restart: none is ever given twice.
            result = service.node('audit')
            first_after = int(result.stdout.split('first=')[1].split()[0]) if 'first=' in result.stdout else 0
            check(result.returncode == 0 and first_after > audited_last,
                  f'sequence numbers continue after a restart ({first_after} after {audited_last})')
            service.stop()

            # A damaged identity file is refused, and never replaced by a new identity.
            path = service.store / 'identity.key'
            data = bytearray(path.read_bytes())
            data[100] ^= 1
            path.write_bytes(bytes(data))
            check(service.start(wait=False) == 1, 'a damaged identity.key stops the service')
            check(bytes(data) == path.read_bytes(), 'a damaged identity.key is left as it was')
            data[100] ^= 1
            path.write_bytes(bytes(data))

            # A changed file with a recomputed checksum: the ML-DSA-87 root is no
            # longer the one the master derives, and the service refuses it.
            original = path.read_bytes()
            body = bytearray(original[:-64])
            body[4 + 4 + 32 + 1 + 4 + 10] ^= 1  # inside the ML-DSA-87 root's public key
            path.write_bytes(bytes(body) + hashlib.sha512(bytes(body)).digest())
            check(service.start(wait=False) == 1, 'a changed key with a valid checksum stops the service')
            check('not the one the master derives' in service.log.read_text(), 'because the derived key does not match')
            path.write_bytes(original)

            # A record cut short by a crash is removed; a damaged log stops the service.
            signing_log = service.store / 'signing.log'
            entries = signing_log.read_bytes()
            with open(signing_log, 'ab') as f:
                f.write(b'cut short')
            service.start()
            check(info(service).get('did') == first.get('did'), 'a record cut short does not stop the service')
            service.stop()
            check(signing_log.read_bytes() == entries, 'and it is removed')
            damaged = bytearray(entries)
            damaged[146 + 30] ^= 1  # inside the label of entry 2
            signing_log.write_bytes(bytes(damaged))
            check(service.start(wait=False) == 1, 'a damaged signing.log stops the service')
            check('signing.log is damaged at entry 2' in service.log.read_text(), 'and says which entry')
            signing_log.write_bytes(entries)

            # A missing identity is never replaced by a new one.
            os.rename(path, root / 'identity.key.saved')
            check(service.start(wait=False) == 1, 'a missing identity.key stops the service')
            check(not path.exists(), 'and no new identity is made')
            check('identity.key is missing' in service.log.read_text(), 'and the log says why')
            os.rename(root / 'identity.key.saved', path)

            # A store others can read is refused.
            os.chmod(path, 0o644)
            check(service.start(wait=False) == 1, 'a readable identity.key stops the service')
            os.chmod(path, 0o600)
            os.chmod(service.store, 0o755)
            check(service.start(wait=False) == 1, 'a readable store folder stops the service')
            os.chmod(service.store, 0o700)
            service.start()
            check(info(service).get('did') == first.get('did'), 'the repaired store opens again')
        finally:
            service.stop()
    if failures:
        print(f'key_service_test: {len(failures)} failed', file=sys.stderr)
        return 1
    print('key_service_test: all passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
