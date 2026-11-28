#!/usr/bin/env python3
"""Check the copied cryptographic code in third_party/crypto/.

Each file there is an unchanged copy of an upstream file, pinned in
MANIFEST.json by its upstream repository, commit and SHA-256 hash. This
fails when a copy has changed, when a pinned file is missing, or when a file
is present that the manifest does not list: nothing may be added or edited
there without updating the manifest in the same review.

Given a checkout of the upstream project (an argument NAME=PATH, for example
sqisign=../the-sqisign), it also checks each copy against that checkout.
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / 'third_party' / 'crypto'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(arguments):
    checkouts = dict(argument.split('=', 1) for argument in arguments)
    manifest = json.loads((ROOT / 'MANIFEST.json').read_text())
    failures = []
    listed = {ROOT / 'MANIFEST.json'}
    for name, component in sorted(manifest.items()):
        base = ROOT / name
        for relative, expected in sorted(component['files'].items()):
            path = base / relative
            listed.add(path)
            if not path.is_file():
                failures.append(f'{name}/{relative}: missing')
            elif sha256(path) != expected:
                failures.append(f'{name}/{relative}: changed since it was copied')
            if name in checkouts:
                upstream = pathlib.Path(checkouts[name]) / relative
                if not upstream.is_file() or sha256(upstream) != expected:
                    failures.append(f'{name}/{relative}: differs from {upstream}')
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and path not in listed:
            failures.append(f'{path.relative_to(ROOT)}: not in MANIFEST.json')
    for failure in failures:
        print(failure, file=sys.stderr)
    if not failures:
        count = sum(len(component['files']) for component in manifest.values())
        print(f'third_party/crypto: {count} files, all unchanged')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
