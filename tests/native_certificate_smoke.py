#!/usr/bin/env python3
"""Opt-in certificate qualification under real crun, on an isolated test volume.

The real node, the real page server and the real certificate process run
against a stand-in certificate authority on loopback (tests/acme_fixture.py).
It shows what the unit tests cannot: the page server answering a challenge
from inside its container, the node starting on an address certificate with
no domain, and a renewal activated by a reload with no restart.

Run as root inside the privileged container scripts/test-native-runtime.sh
starts. No public authority, production endpoint or credential is used.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time

from acme_fixture import Authority
from tls_ca import create_certificates

ROOT = Path(__file__).resolve().parents[1]
TLS_PORT, HTTP_PORT, HEALTH_PORT = 53612, 53613, 53614


def run(args, *, success=True):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=300)
    if (result.returncode == 0) != success:
        raise RuntimeError(f'Command failed: {args[-1]}: {result.stderr[-2000:]} {result.stdout[-1000:]}')
    return result


def main():
    base = Path(os.environ['FORTIS_NATIVE_SMOKE_ROOT'] + '-certificates')
    base.mkdir(parents=True)
    base.chmod(0o755)
    data = base / 'database'
    data.mkdir(mode=0o700)
    os.chown(data, 10001, 10001)
    certificates, challenges = base / 'certificates', base / 'challenges'
    certificates.mkdir()
    challenges.mkdir()
    key, public = base / 'fixture-private.pem', base / 'fixture-public.pem'
    run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key])
    run(['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
    release = base / 'upload'
    shutil.copytree(Path(sys.argv[1]), release)
    version = (release / 'manifest').read_text().splitlines()[1]
    (release / 'manifest').write_text((release / 'manifest').read_text().replace(version, 'version=certificate-smoke'))
    run(['openssl', 'dgst', '-sha256', '-sign', key, '-out', release / 'manifest.sig', release / 'manifest'])
    fixtures = base / 'tls-fixtures'
    fixtures.mkdir()
    ca, authority_certificate, authority_key, _ = create_certificates(fixtures, 'IP:127.0.0.1')
    authority = Authority(base / 'authority', ca, fixtures / 'ca.key', authority_certificate, authority_key, HTTP_PORT)
    # The first certificate is already due for renewal: five of six days gone.
    authority.valid_days = (5, 1)
    env = base / 'runtime.env'
    env.write_text('NODE_ENV=development\nFORTIS_HEALTH_PORT=8081\nFORTIS_HTTPS_CERT_DIR=/certificates\n'
                   'FORTIS_ACME_CHALLENGE_DIR=/acme\nFORTIS_HTTP_REDIRECT_PORT=8082\nFORTIS_HTTPS_IP=127.0.0.1\n')
    env.chmod(0o600)
    # Container names become host names: 64 characters at most, suffix included.
    name = 'fortis-cert-' + str(os.getpid())
    emulated = os.environ.get('FORTIS_NATIVE_SMOKE_EMULATED', '0')
    config = base / 'node.conf'
    config.write_text(f'''FORTIS_NATIVE_ROOT={base / 'state'}
FORTIS_NATIVE_DATA={data}
FORTIS_NATIVE_ENV={env}
FORTIS_NATIVE_PUBLIC_KEY={public}
FORTIS_NATIVE_RUNTIME_STATE={Path('/run') / name}
FORTIS_NATIVE_NAME={name}
FORTIS_NATIVE_HTTPS=1
FORTIS_NATIVE_PORT={TLS_PORT}
FORTIS_NATIVE_HTTP_PORT={HTTP_PORT}
FORTIS_NATIVE_HEALTH_HOST_PORT={HEALTH_PORT}
FORTIS_NATIVE_CERTIFICATES={certificates}
FORTIS_NATIVE_ACME_CHALLENGES={challenges}
FORTIS_NATIVE_ACME_STATE={base / 'acme-state'}
FORTIS_NATIVE_ACME_DIRECTORY={authority.url('/dir')}
FORTIS_NATIVE_ACME_LOOPBACK=1
FORTIS_NATIVE_TLS_CA={ca}
FORTIS_NATIVE_REQUIRE_MOUNT=0
FORTIS_NATIVE_HEALTH_ATTEMPTS=5
FORTIS_NATIVE_EMULATED_FIXTURE={emulated}
FORTIS_NATIVE_OBSERVE_SECONDS=0
FORTIS_NATIVE_MIN_REQUESTS=0
''')
    config.chmod(0o600)
    command = [ROOT / 'image/files/manage-native-node.sh', config]
    os.environ['FORTIS_NATIVE_WAIT_LOCK'] = '1'
    result = {'passed': False}

    def keeper(request):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(240)
            client.connect(str(base / 'state/keeper.sock'))
            client.sendall(request.encode() + b'\n')
            return dict(field.split('=') for field in client.makefile().readline().split()[1:])

    def served():
        """The certificate the node presents for its address, verified against the test authority."""
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(('127.0.0.1', TLS_PORT), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname='127.0.0.1') as secure:
                secure.sendall(f'GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{TLS_PORT}\r\nConnection: close\r\n\r\n'.encode())
                answer = secure.recv(4096)
                return secure.getpeercert(binary_form=True), answer.split(b'\r\n', 1)[0].decode()

    def plain(target):
        connection = http.client.HTTPConnection('127.0.0.1', HTTP_PORT, timeout=10)
        connection.request('GET', target, headers={'Host': '127.0.0.1'})
        response = connection.getresponse()
        answer = response.status, response.getheader('Location'), response.read()
        connection.close()
        return answer

    try:
        # No certificate exists: the page server must answer the challenge
        # before the node can start at all.
        run([*command, 'update', release])
        page_log = base / 'state/log/page.log'
        result['page_server_ran_in_its_own_container'] = page_log.exists() and \
            any(order['authorization'] == 'valid' for order in authority.orders)
        result['authority_saw'] = {'user_agents': sorted(authority.user_agents), 'subjects': authority.subjects,
                                   'profiles': [order['profile'] for order in authority.orders]}
        if authority.user_agents != {'FortisNet-Orchestrator/1'} or \
                authority.subjects != ['subject=OU=FortisNet Node,O=FortisNet']:
            raise RuntimeError('the request was not identified as FortisNet')
        first, status = served()
        result['address_only_node_serves_trusted_tls'] = status
        if not status.startswith('HTTP/1.1 200'):
            raise RuntimeError('node did not answer over TLS: ' + status)
        state = keeper('state')
        result['node_http_port'] = {'challenge_absent': plain('/.well-known/acme-challenge/absent')[0],
                                    'redirect': plain('/x')[:2]}
        if result['node_http_port'] != {'challenge_absent': 404, 'redirect': (308, 'https://127.0.0.1/x')}:
            raise RuntimeError('unexpected HTTP port behaviour: ' + repr(result['node_http_port']))
        # Renewal: the running node answers the challenge itself and takes the
        # new certificate on a reload signal.
        authority.valid_days = (0, 6)
        renewal = run([*command, 'certificates']).stdout
        if 'Certificates renewed' not in renewal:
            raise RuntimeError('renewal did not happen: ' + renewal)
        deadline = time.monotonic() + 15
        second = first
        while second == first and time.monotonic() < deadline:
            time.sleep(.5)
            second, status = served()
        result['renewed_certificate_served'] = second != first
        result['node_not_restarted'] = keeper('state') == state
        if not (result['renewed_certificate_served'] and result['node_not_restarted']):
            raise RuntimeError('renewal was not activated by a reload')
        log = (base / 'state/log/node.log').read_text(errors='replace')
        result['node_reported_activation'] = 'Certificate generation activated' in log
        if 'Certificates are current' not in run([*command, 'certificates']).stdout:
            raise RuntimeError('a fresh certificate was renewed again')
        result['orders'] = len(authority.orders)
        result['challenge_directory_empty'] = list(challenges.iterdir()) == []
        result['passed'] = result['orders'] == 2 and result['challenge_directory_empty']
    finally:
        try:
            run([*command, 'stop'], success=True)
            keeper('shutdown')
        except (OSError, RuntimeError):
            pass
        authority.close()
        for log in ('node.log', 'page.log', 'preflight.log', 'keeper.log'):
            if (base / 'state/log' / log).exists():
                shutil.copyfile(base / 'state/log' / log, base / ('certificate-' + log))
        (base / 'certificate-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
