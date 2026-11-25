"""A small certificate authority speaking ACME (RFC 8555) for the host tests.

It checks what a real authority checks of a client: every request is signed
by the account key (ES256), carries a fresh anti-replay value and names the
address it was sent to; the HTTP challenge is fetched from the node's own
HTTP port; and the certificate is issued from the request's public key with
the ordered name or address only. Issuance uses the OpenSSL command line.
"""
import base64
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import threading
import time


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def der_integer(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 8) // 8 or 1, 'big')
    return b'\x02' + bytes([len(body)]) + body


class Authority:
    """Start with `Authority(directory, ca, ca_key, server_cert, server_key, http_port)`."""

    def __init__(self, work: Path, ca: Path, ca_key: Path, certificate: Path, key: Path, http_port: int):
        self.work, self.ca, self.ca_key, self.http_port = work, ca, ca_key, http_port
        work.mkdir()
        (work / 'issued').mkdir()
        (work / 'index.txt').touch()
        (work / 'serial').write_text('1000\n')
        (work / 'ca.cnf').write_text(
            f'[ca]\ndefault_ca=fixture\n[fixture]\ndatabase={work}/index.txt\nnew_certs_dir={work}/issued\n'
            f'serial={work}/serial\ndefault_md=sha256\npolicy=any\nunique_subject=no\ncopy_extensions=none\n'
            '[any]\ncommonName=optional\norganizationName=optional\norganizationalUnitName=optional\n')
        self.lock = threading.Lock()
        self.nonces, self.accounts, self.orders = set(), {}, []
        self.user_agents, self.subjects, self.requests = set(), [], 0
        # Behaviour switches for individual tests.
        self.bad_nonce_once = False
        self.refuse_orders = False
        self.fail_names = set()       # identifiers whose challenge is reported invalid
        self.issue_for = None         # issue for this name instead of the ordered one
        self.valid_days = (0, 6)      # days before now, days after now
        authority = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def reply(self, status, body, location=None, kind='application/json'):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', kind)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Replay-Nonce', authority.nonce())
                if location:
                    self.send_header('Location', location)
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                authority.user_agents.add(self.headers.get('User-Agent'))
                if self.path == '/dir':
                    self.reply(200, {'newNonce': authority.url('/nonce'), 'newAccount': authority.url('/acct'),
                                     'newOrder': authority.url('/order'),
                                     'meta': {'profiles': {'classic': 'default', 'shortlived': 'six days'}}})
                elif self.path == '/nonce':
                    self.reply(204, b'')
                else:
                    self.reply(405, authority.problem('malformed', 'signed requests only'))

            def do_POST(self):
                authority.user_agents.add(self.headers.get('User-Agent'))
                body = self.rfile.read(int(self.headers['Content-Length']))
                try:
                    with authority.lock:
                        status, answer, location, kind = authority.handle(self.path, self.headers, body)
                except Refusal as refusal:
                    status, answer, location, kind = refusal.status, authority.problem(refusal.kind, str(refusal)), None, \
                        'application/problem+json'
                self.reply(status, answer, location, kind)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def url(self, path):
        return f'https://127.0.0.1:{self.port}{path}'

    def nonce(self):
        value = secrets.token_urlsafe(16)
        self.nonces.add(value)
        return value

    @staticmethod
    def problem(kind, detail):
        return {'type': 'urn:ietf:params:acme:error:' + kind, 'detail': detail}

    def verify(self, jwk, signed: bytes, signature: bytes):
        if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256' or len(signature) != 64:
            raise Refusal('badPublicKey', 'P-256 keys only')
        point = b'\x04' + unb64(jwk['x']) + unb64(jwk['y'])
        public = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + point
        pair = der_integer(int.from_bytes(signature[:32], 'big')) + der_integer(int.from_bytes(signature[32:], 'big'))
        token = secrets.token_hex(8)
        files = [self.work / f'{token}.{name}' for name in ('pub', 'sig', 'msg')]
        for file, data in zip(files, (public, b'\x30' + bytes([len(pair)]) + pair, signed)):
            file.write_bytes(data)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(files[0]), '-keyform', 'DER',
                                 '-signature', str(files[1]), str(files[2])], capture_output=True)
        for file in files:
            file.unlink()
        if result.returncode != 0:
            raise Refusal('malformed', 'signature does not verify')

    def handle(self, path, headers, body):
        self.requests += 1
        if headers.get('Content-Type') != 'application/jose+json':
            raise Refusal('malformed', 'wrong content type', 415)
        envelope = json.loads(body)
        protected = json.loads(unb64(envelope['protected']))
        if self.bad_nonce_once:
            self.bad_nonce_once = False
            raise Refusal('badNonce', 'use the fresh value')
        if protected.get('alg') != 'ES256' or protected.get('url') != self.url(path):
            raise Refusal('malformed', 'wrong algorithm or address')
        if protected.get('nonce') not in self.nonces:
            raise Refusal('badNonce', 'unknown or reused value')
        self.nonces.discard(protected['nonce'])
        if path == '/acct':
            jwk = protected['jwk']
            canonical = json.dumps({k: jwk[k] for k in ('crv', 'kty', 'x', 'y')}, separators=(',', ':'), sort_keys=True)
            account = hashlib.sha256(canonical.encode()).digest()
            self.accounts.setdefault(b64(account), jwk)
            kid = b64(account)
        else:
            kid = protected.get('kid', '').rsplit('/', 1)[-1]
            if kid not in self.accounts or 'jwk' in protected:
                raise Refusal('accountDoesNotExist', 'unknown account')
        self.verify(self.accounts[kid], (envelope['protected'] + '.' + envelope['payload']).encode(),
                    unb64(envelope['signature']))
        payload = json.loads(unb64(envelope['payload'])) if envelope['payload'] else None
        if path == '/acct':
            if not payload.get('termsOfServiceAgreed'):
                raise Refusal('userActionRequired', 'terms not agreed')
            return 200, {'status': 'valid', 'contact': payload.get('contact', [])}, self.url('/acct/' + kid), None
        if path == '/order':
            if self.refuse_orders:
                raise Refusal('rateLimited', 'too many certificates already issued', 429)
            identifiers = payload['identifiers']
            if len(identifiers) != 1 or identifiers[0]['type'] not in ('ip', 'dns'):
                raise Refusal('rejectedIdentifier', 'one name or address')
            if identifiers[0]['type'] == 'ip' and payload.get('profile') != 'shortlived':
                raise Refusal('rejectedIdentifier', 'addresses need the short-lived profile')
            self.orders.append({'account': kid, 'identifier': identifiers[0], 'profile': payload.get('profile'),
                                'token': secrets.token_urlsafe(24), 'authorization': 'pending', 'status': 'pending',
                                'certificate': None, 'reason': None})
            return 201, self.order(len(self.orders) - 1), self.url(f'/order/{len(self.orders) - 1}'), None
        kind, _, number = path.strip('/').partition('/')
        order = self.orders[int(number)]
        if order['account'] != kid:
            raise Refusal('unauthorized', 'another account')
        if kind == 'order':
            return 200, self.order(int(number)), None, None
        if kind == 'authz':
            return 200, self.authorization(int(number)), None, None
        if kind == 'chall':
            if payload != {}:
                raise Refusal('malformed', 'a challenge is answered with an empty object')
            if order['authorization'] == 'pending':
                self.validate(order, kid)
            return 200, self.authorization(int(number))['challenges'][0], None, None
        if kind == 'finalize':
            if order['authorization'] != 'valid':
                raise Refusal('orderNotReady', 'not authorized yet', 403)
            order['certificate'] = self.issue(int(number), order, unb64(payload['csr']))
            order['status'] = 'valid'
            return 200, self.order(int(number)), None, None
        if kind == 'cert' and order['certificate']:
            return 200, order['certificate'], None, 'application/pem-certificate-chain'
        raise Refusal('malformed', 'unknown resource', 404)

    def order(self, number):
        order = self.orders[number]
        document = {'status': 'ready' if order['status'] == 'pending' and order['authorization'] == 'valid'
                    else order['status'], 'identifiers': [order['identifier']],
                    'authorizations': [self.url(f'/authz/{number}')], 'finalize': self.url(f'/finalize/{number}')}
        if order['certificate']:
            document['certificate'] = self.url(f'/cert/{number}')
        return document

    def authorization(self, number):
        order = self.orders[number]
        challenge = {'type': 'http-01', 'url': self.url(f'/chall/{number}'), 'token': order['token'],
                     'status': order['authorization']}
        if order['reason']:
            challenge['error'] = self.problem('unauthorized', order['reason'])
        return {'status': order['authorization'], 'identifier': order['identifier'],
                'challenges': [{'type': 'tls-alpn-01', 'url': self.url('/unused'), 'token': 'unused',
                                'status': 'pending'}, challenge][::-1]}

    def validate(self, order, kid):
        expected = order['token'] + '.' + kid
        observed = None
        if order['identifier']['value'] not in self.fail_names:
            try:
                connection = http.client.HTTPConnection('127.0.0.1', self.http_port, timeout=5)
                connection.request('GET', '/.well-known/acme-challenge/' + order['token'],
                                   headers={'Host': order['identifier']['value']})
                response = connection.getresponse()
                observed = response.read().decode() if response.status == 200 else f'status {response.status}'
                connection.close()
            except OSError as error:
                observed = f'connection failed: {error}'
        if observed == expected:
            order['authorization'] = 'valid'
        else:
            order['authorization'], order['status'] = 'invalid', 'invalid'
            order['reason'] = 'the challenge file was not served at this name or address'

    def issue(self, number, order, request: bytes):
        base = self.work / f'order-{number}'
        base.with_suffix('.csr').write_bytes(request)
        subject = subprocess.run(['openssl', 'req', '-inform', 'DER', '-in', str(base.with_suffix('.csr')), '-noout',
                                  '-verify', '-subject', '-nameopt', 'RFC2253'], capture_output=True, text=True)
        if subject.returncode != 0:
            raise Refusal('badCSR', 'request does not verify')
        # Some OpenSSL versions print the verification result on the same stream.
        self.subjects.append(next(line for line in subject.stdout.splitlines() if line.startswith('subject=')))
        identifier = order['identifier']
        # As the public authority does: an address is named in the alternative
        # names only.
        if identifier['type'] == 'ip' and 'CN=' in self.subjects[-1]:
            raise Refusal('badCSR', 'CSR contains IP address in Common Name')
        value = self.issue_for or identifier['value']
        name = ('IP:' if identifier['type'] == 'ip' else 'DNS:') + value
        base.with_suffix('.ext').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n'
                                            f'extendedKeyUsage=serverAuth\nsubjectAltName={name}\n')
        now = time.time()
        stamp = lambda offset: time.strftime('%Y%m%d%H%M%SZ', time.gmtime(now + offset * 86400))
        result = subprocess.run(['openssl', 'ca', '-batch', '-config', str(self.work / 'ca.cnf'), '-notext',
                                 '-cert', str(self.ca), '-keyfile', str(self.ca_key), '-inform', 'DER',
                                 '-in', str(base.with_suffix('.csr')), '-out', str(base.with_suffix('.pem')),
                                 '-startdate', stamp(-self.valid_days[0] - 1 / 1440), '-enddate',
                                 stamp(self.valid_days[1]), '-extfile', str(base.with_suffix('.ext'))],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise Refusal('serverInternal', result.stderr[-200:], 500)
        return base.with_suffix('.pem').read_bytes()


class Refusal(Exception):
    def __init__(self, kind, detail, status=400):
        super().__init__(detail)
        self.kind, self.status = kind, status
