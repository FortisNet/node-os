#!/usr/bin/env python3
"""Known-answer tests of the copied ML-DSA-87 and SQIsign-V code.

  crypto_vectors_test.py BUILD/keys_test

The vectors in tests/vectors/ are unchanged upstream files, pinned by hash in
tests/vectors/MANIFEST.json:

- NIST's ACVP vectors for FIPS 204: every ML-DSA-87 key generation case, and
  every external, pure (no pre-hash) signing and verification case, which is
  the interface the key service uses;
- the SQIsign team's known-answer file for p664_17: every signature in it
  must verify, and a changed one must not. Signing itself is randomized, so
  its correctness is checked by the round trips in keys_test.

The cases are passed to keys_test on standard input (see its header).
"""
import hashlib
import json
import pathlib
import subprocess
import sys

VECTORS = pathlib.Path(__file__).resolve().parent / 'vectors'
SQISIGN_SIGNATURE = 406


def pinned():
    manifest = json.loads((VECTORS / 'MANIFEST.json').read_text())
    for component in manifest.values():
        for name, expected in component['files'].items():
            if hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() != expected:
                sys.exit(f'tests/vectors/{name} is not the pinned upstream file')


def h(value):
    return value.lower() if value else '-'


def groups(name):
    data = json.loads((VECTORS / name / 'internalProjection.json').read_text())
    for group in data['testGroups']:
        if group.get('parameterSet') == 'ML-DSA-87':
            yield group


def external_pure(group):
    return group.get('signatureInterface') == 'external' and group.get('preHash') == 'pure' \
        and not group.get('externalMu')


def mldsa_cases():
    for group in groups('ML-DSA-keyGen-FIPS204'):
        for test in group['tests']:
            yield f"K {h(test['seed'])} {h(test['pk'])} {h(test['sk'])}"
    for group in groups('ML-DSA-sigGen-FIPS204'):
        if not external_pure(group):
            continue
        for test in group['tests']:
            rnd = '00' * 32 if group['deterministic'] else test['rnd']
            yield f"S {h(rnd)} {h(test['sk'])} {h(test.get('context'))} {h(test['message'])} {h(test['signature'])}"
    for group in groups('ML-DSA-sigVer-FIPS204'):
        if not external_pure(group):
            continue
        for test in group['tests']:
            verdict = '1' if test['testPassed'] else '0'
            yield f"V {h(test['pk'])} {h(test.get('context'))} {h(test['message'])} {h(test['signature'])} {verdict}"


def sqisign_cases():
    entry = {}
    for line in (VECTORS / 'PQCsignKAT_549_SQIsign_p664_17.rsp').read_text().splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            entry[key] = value.strip()
        if 'sm' in entry:
            mlen = int(entry['mlen'])
            sm = entry['sm']
            signature, message = sm[:2 * SQISIGN_SIGNATURE], sm[2 * SQISIGN_SIGNATURE:]
            if mlen != len(message) // 2 or message.lower() != entry['msg'].lower():
                sys.exit('unexpected SQIsign KAT layout')
            yield f"Q {h(entry['pk'])} {h(entry['msg'])} {h(signature)} 1"
            # The same signature with one bit changed must not verify.
            changed = format(int(signature[:2], 16) ^ 1, '02x') + signature[2:]
            yield f"Q {h(entry['pk'])} {h(entry['msg'])} {changed.lower()} 0"
            entry = {}


def main(program):
    pinned()
    cases = list(mldsa_cases()) + list(sqisign_cases())
    kinds = {kind: sum(1 for c in cases if c[0] == kind) for kind in 'KSVQ'}
    # NIST: 25 key generation, 30 external pure signing, 15 verification cases
    # for ML-DSA-87; SQIsign: 100 signatures, each also changed.
    expected = {'K': 25, 'S': 30, 'V': 15, 'Q': 200}
    if kinds != expected:
        sys.exit(f'unexpected vector counts {kinds}, expected {expected}')
    result = subprocess.run([program, 'vectors'], input='\n'.join(cases) + '\n', text=True)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
