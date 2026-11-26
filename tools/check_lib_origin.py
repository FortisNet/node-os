#!/usr/bin/env python3
"""Keep the copied library files honest.

lib/ holds copies of source files from the FortisNet node (an HTTPS client, a
JSON reader and small support headers). They are copies on purpose: this
repository builds from its own files and Mbed TLS alone, so the part that
runs as administrator on a host can be reviewed and released by itself.

lib/ORIGIN.json records, for each copy, the node file it came from and that
file's hash at the time. A copy may differ from its origin; it may not fall
behind unnoticed.

  check_lib_origin.py                 every file in lib/ has an entry, and the reverse
  check_lib_origin.py NODE_CHECKOUT   also: no origin has changed since it was copied.
                                      NODE_CHECKOUT is a checkout of
                                      https://github.com/FortisNet/node
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('.cpp', '.h', '.c', '.inc')
# Files in lib/ that are this repository's own, not copies.
OWN = {'fortis_mbedtls_config.h'}


def main():
    errors = []
    origin = json.loads((ROOT / 'lib/ORIGIN.json').read_text())
    present = {p.name for p in (ROOT / 'lib').iterdir() if p.suffix in SOURCE} - OWN
    for name in sorted(present ^ set(origin)):
        errors.append(f'lib/{name}: the file and its ORIGIN.json entry must both exist')
    node = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
    for name, entry in sorted(origin.items()) if node else ():
        source = node / entry['from']
        if not source.is_file():
            errors.append(f'lib/{name}: origin {entry["from"]} no longer exists; update ORIGIN.json')
        elif hashlib.sha256(source.read_bytes()).hexdigest() != entry['sha256']:
            errors.append(f'{entry["from"]} changed since lib/{name} was taken from it: port the change or '
                          'decide it does not apply, then record the new hash in lib/ORIGIN.json')
    for error in errors:
        print('FAIL: ' + error)
    if errors:
        return 1
    print(f'lib: {len(origin)} copies ' + ('match their recorded origins' if node else 'have a recorded origin'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
