#!/usr/bin/env python3
"""Add a signed node release to a release store folder and re-sign its list.

Run on the trusted signing machine, never on a node host:

    publish_release.py [options] STORE_FOLDER RELEASE_FOLDER PRIVATE_KEY

RELEASE_FOLDER is a signed node release: `fortis-node`, `manifest` and
`manifest.sig`. STORE_FOLDER is a local copy of the store; afterwards upload
it as it is to wherever the hosts read it from.

With `--layout tree` (the default), for any static HTTPS file host that
honours range requests:

    STORE/ARCH/index                        the release list
    STORE/ARCH/index.sig                    signature over the exact list bytes
    STORE/ARCH/releases/VERSION/manifest
    STORE/ARCH/releases/VERSION/manifest.sig
    STORE/ARCH/releases/VERSION/fortis-node

With `--layout flat`, for GitHub releases, where each folder is one release
(named by its tag) and its files are that release's assets:

    STORE/node-channel-CHANNEL/index-ARCH
    STORE/node-channel-CHANNEL/index-ARCH.sig
    STORE/node-V/fortis-node-ARCH
    STORE/node-V/fortis-node-ARCH.manifest
    STORE/node-V/fortis-node-ARCH.manifest.sig

V is the version without a leading `node-`. ARCH is the processor
architecture the release was built for, taken from its manifest: `x86_64` or
`aarch64`. Each has its own list, and a host reads only its own, so publish
a version once per architecture.

The list is written in format 2: besides the releases it names its channel
(`--channel`, default `stable`), the day it stops being valid
(`--expires-days`, default 30) and, for every release, the host interface
the release needs, read from its manifest (`host_interface`, 1 when the
manifest has none). Publish again before a list expires, even when there is
no new release: hosts refuse an expired list. `--format 1` writes the older
list, which has none of the three.

The list's sequence grows by one with every publication. Hosts refuse a
list with a lower sequence than one they have accepted, so never restore an
old copy of this folder and publish from it: the sequence would repeat.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import time

FILES = ('fortis-node', 'manifest', 'manifest.sig')
# Having these two channels is provisional and expected to change.
CHANNELS = ('stable', 'edge')
DAY_MS = 24 * 3600 * 1000


def read_index(path: Path):
    """The sequence and the entries of an existing list, of either format."""
    if not path.is_file():
        return 0, []
    lines = path.read_text().splitlines()
    header = {'format=1': 3, 'format=2': 5}.get(lines[0] if lines else '')
    if header is None or len(lines) < header or not lines[1].startswith('sequence='):
        raise SystemExit(f'{path} is not a release list this tool understands')
    entries = [line.split('\t') for line in lines[header:]]
    # A format 1 list says nothing about host interfaces, which means 1.
    return int(lines[1].split('=', 1)[1]), [entry + ['1'] if len(entry) == 4 else entry for entry in entries]


def flat_name(version: str) -> str:
    """The folder of a version in the flat layout: `node-` and the version without that prefix."""
    return 'node-' + version.removeprefix('node-')


def publish(store: Path, release: Path, key: Path, now_ms=None, *, channel='stable', expires_days=30,
            layout='tree', index_format=2) -> int:
    """Publish `release` into `store`; returns the new list sequence."""
    if channel not in CHANNELS or layout not in ('tree', 'flat') or index_format not in (1, 2):
        raise SystemExit('unknown channel, layout or list format')
    if not 1 <= expires_days <= 366:
        raise SystemExit('a list must expire in 1 to 366 days')
    for name in FILES:
        if not (release / name).is_file():
            raise SystemExit(f'{release} has no {name}: build and sign the release first')
    manifest = (release / 'manifest').read_bytes()
    fields = dict(line.split('=', 1) for line in manifest.decode().splitlines())
    version = fields['version']
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', version) or version in ('.', '..'):
        raise SystemExit('the manifest names an invalid version')
    architecture = fields.get('architecture')
    if architecture not in ('x86_64', 'aarch64'):
        raise SystemExit('the manifest names no known processor architecture')
    host_interface = fields.get('host_interface', '1')
    if not re.fullmatch(r'[1-9][0-9]{0,3}', host_interface) or int(host_interface) > 1000:
        raise SystemExit('the manifest names an invalid host interface')
    if index_format == 1 and host_interface != '1':
        raise SystemExit('a format 1 list cannot hold a release that needs a host interface other than 1')
    binary = (release / 'fortis-node').read_bytes()
    if hashlib.sha256(binary).hexdigest() != fields['sha256'] or len(binary) != int(fields['bytes']):
        raise SystemExit('the executable does not match its manifest')
    if layout == 'tree':
        folder = store / architecture
        target, index = folder / 'releases' / version, folder / 'index'
        names = {name: name for name in FILES}
    else:
        folder = store / f'node-channel-{channel}'
        target, index = store / flat_name(version), folder / f'index-{architecture}'
        names = {'fortis-node': f'fortis-node-{architecture}', 'manifest': f'fortis-node-{architecture}.manifest',
                 'manifest.sig': f'fortis-node-{architecture}.manifest.sig'}
    folder.mkdir(parents=True, exist_ok=True)
    target.mkdir(parents=True, exist_ok=True)
    if all((target / names[name]).exists() for name in FILES):
        if any((target / names[name]).read_bytes() != (release / name).read_bytes() for name in FILES):
            raise SystemExit(f'{version} is already published with different content; a version is never replaced')
    else:
        for name in FILES:
            shutil.copyfile(release / name, target / names[name])
    sequence, entries = read_index(index)
    if not any(entry[1] == version for entry in entries):
        entries.append(['release', version, hashlib.sha256(manifest).hexdigest(), str(len(binary)), host_interface])
    sequence += 1
    stamp = int(time.time() * 1000) if now_ms is None else now_ms
    if index_format == 1:
        if any(entry[4] != '1' for entry in entries):
            raise SystemExit('a format 1 list cannot hold a release that needs a host interface other than 1')
        text = f'format=1\nsequence={sequence}\npublished_ms={stamp}\n' + ''.join(
            '\t'.join(entry[:4]) + '\n' for entry in entries)
    else:
        text = (f'format=2\nsequence={sequence}\npublished_ms={stamp}\nexpires_ms={stamp + expires_days * DAY_MS}\n'
                f'channel={channel}\n' + ''.join('\t'.join(entry) + '\n' for entry in entries))
    # The signature is replaced first and the list last: a host that reads
    # between the two sees a mismatch and tries again, never a wrong pairing
    # that verifies.
    pending = index.with_name(index.name + '.pending')
    pending.write_text(text)
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-out', str(index) + '.sig', str(pending)],
                   check=True)
    pending.replace(index)
    return sequence


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('store', type=Path, metavar='STORE_FOLDER')
    parser.add_argument('release', type=Path, metavar='RELEASE_FOLDER')
    parser.add_argument('key', type=Path, metavar='PRIVATE_KEY')
    parser.add_argument('--channel', choices=CHANNELS, default='stable',
                        help='the channel the list is for (default: stable)')
    parser.add_argument('--expires-days', type=int, default=30,
                        help='days until hosts refuse this list (default: 30)')
    parser.add_argument('--layout', choices=('tree', 'flat'), default='tree',
                        help='tree for a static file host, flat for GitHub releases (default: tree)')
    parser.add_argument('--format', type=int, choices=(1, 2), default=2, dest='index_format',
                        help='the list format to write (default: 2)')
    options = parser.parse_args()
    options.store.mkdir(parents=True, exist_ok=True)
    sequence = publish(options.store, options.release, options.key, channel=options.channel,
                       expires_days=options.expires_days, layout=options.layout, index_format=options.index_format)
    print(f'Published; list sequence {sequence}. Upload {options.store} to the release store as it is.')


if __name__ == '__main__':
    main()
