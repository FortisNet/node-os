#!/usr/bin/env python3
"""Add a signed node release to a release store folder and re-sign its index.

Run on the trusted signing machine, never on a node host:

    publish_release.py STORE_FOLDER RELEASE_FOLDER PRIVATE_KEY

RELEASE_FOLDER is a signed node release: `fortis-node`, `manifest` and
`manifest.sig`. STORE_FOLDER is a local copy of the store; afterwards upload
it as it is to the object store the hosts read (any static HTTPS file host
that honours range requests).

    STORE/ARCH/index                        format, sequence, date, one line per release
    STORE/ARCH/index.sig                    signature over the exact index bytes
    STORE/ARCH/releases/VERSION/manifest
    STORE/ARCH/releases/VERSION/manifest.sig
    STORE/ARCH/releases/VERSION/fortis-node

ARCH is the processor architecture the release was built for, taken from its
manifest: `x86_64` or `aarch64`. Each has its own index, and a host reads only
its own, so publish a version once per architecture.

The index sequence grows by one with every publication. Hosts refuse an
index with a lower sequence than one they have accepted, so never restore an
old copy of this folder and publish from it: the sequence would repeat.
"""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

FILES = ('fortis-node', 'manifest', 'manifest.sig')


def read_index(path: Path):
    if not path.is_file():
        return 0, []
    lines = path.read_text().splitlines()
    if len(lines) < 3 or lines[0] != 'format=1' or not lines[1].startswith('sequence='):
        raise SystemExit(f'{path} is not a release index this tool understands')
    return int(lines[1].split('=', 1)[1]), [line.split('\t') for line in lines[3:]]


def publish(store: Path, release: Path, key: Path, now_ms=None) -> int:
    """Publish `release` into `store`; returns the new index sequence."""
    for name in FILES:
        if not (release / name).is_file():
            raise SystemExit(f'{release} has no {name}: build and sign the release first')
    manifest = (release / 'manifest').read_bytes()
    fields = dict(line.split('=', 1) for line in manifest.decode().splitlines())
    version = fields['version']
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', version) or version in ('.', '..'):
        raise SystemExit('the manifest names an invalid version')
    if fields.get('architecture') not in ('x86_64', 'aarch64'):
        raise SystemExit('the manifest names no known processor architecture')
    store = store / fields['architecture']
    store.mkdir(parents=True, exist_ok=True)
    binary = (release / 'fortis-node').read_bytes()
    if hashlib.sha256(binary).hexdigest() != fields['sha256'] or len(binary) != int(fields['bytes']):
        raise SystemExit('the executable does not match its manifest')
    target = store / 'releases' / version
    if target.exists():
        if any((target / name).read_bytes() != (release / name).read_bytes() for name in FILES):
            raise SystemExit(f'{version} is already published with different content; a version is never replaced')
    else:
        target.mkdir(parents=True)
        for name in FILES:
            shutil.copyfile(release / name, target / name)
    sequence, entries = read_index(store / 'index')
    if not any(entry[1] == version for entry in entries):
        entries.append(['release', version, hashlib.sha256(manifest).hexdigest(), str(len(binary))])
    sequence += 1
    stamp = int(time.time() * 1000) if now_ms is None else now_ms
    text = f'format=1\nsequence={sequence}\npublished_ms={stamp}\n' + ''.join('\t'.join(entry) + '\n' for entry in entries)
    # The signature is replaced first and the index last: a host that reads
    # between the two sees a mismatch and tries again, never a wrong pairing
    # that verifies.
    pending = store / 'index.pending'
    pending.write_text(text)
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-out', str(store / 'index.sig'), str(pending)],
                   check=True)
    pending.replace(store / 'index')
    return sequence


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    store, release, key = map(Path, sys.argv[1:])
    store.mkdir(parents=True, exist_ok=True)
    sequence = publish(store, release, key)
    print(f'Published; index sequence {sequence}. Upload {store} to the release store as it is.')


if __name__ == '__main__':
    main()
