#!/usr/bin/env python3
"""Build a release-specific offline gVisor package, preserving its loaded ELF image.

Build tool only: no runtime downloads or privileged installation. SHA-512 pins the
complete upstream archive. The reduced profile removes unused optional programs
and non-loaded debug sections, never executable or allocated runtime contents.
"""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent  # sandbox
PROFILE = ROOT / 'gvisor_runtime.json'
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
MACHINES = {'x86_64': 62, 'aarch64': 183}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf_image(data, architecture):
    """Fingerprint every mapped byte and program header; allow only section metadata to move.

    ELF64 little-endian only. Section-table offsets/counts are non-execution
    metadata in the first load segment. No entry, flags, memory sizes, mapping,
    permissions, Go build IDs, runtime symbols or allocated bytes may change.
    """
    if len(data) < 64 or len(data) > MAX_BINARY or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected bounded little-endian ELF64')
    if struct.unpack_from('<H', data, 18)[0] != MACHINES[architecture]:
        raise ValueError('ELF architecture mismatch')
    header = bytearray(data[:64])
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from('<HHHHHH', data, 52)
    if ehsize != 64 or phsize != 56 or not phnum or phoff < 64 or phoff + phsize * phnum > len(data):
        raise ValueError('invalid ELF program headers')
    if shsize != 64 or not shnum or shstr >= shnum or shoff < 64 or shoff + shsize * shnum > len(data):
        raise ValueError('invalid ELF section headers')
    # These are the only changed bytes permitted inside any mapped segment.
    header[40:48] = bytes(8)
    header[58:64] = bytes(6)
    programs = data[phoff:phoff + phsize * phnum]
    loads = []
    for index in range(phnum):
        kind, flags, offset, address, physical, size, memory, align = struct.unpack_from('<IIQQQQQQ', programs, index * phsize)
        if offset > len(data) or size > len(data) - offset:
            raise ValueError('invalid ELF segment bounds')
        if kind == 1:
            if size > memory or not memory:
                raise ValueError('invalid ELF load segment')
            content = bytearray(data[offset:offset + size])
            for start, end in [(40, 48), (58, 64)]:
                low, high = max(offset, start), min(offset + size, end)
                if low < high:
                    content[low - offset:high - offset] = bytes(high - low)
            loads.append({'fileOffset': offset, 'address': address, 'flags': flags, 'fileBytes': size, 'memoryBytes': memory,
                          'sha256': digest(content)})
    if not loads:
        raise ValueError('missing ELF load segments')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * shsize) for index in range(shnum)]
    names = sections[shstr]
    if names[4] > len(data) or names[5] > len(data) - names[4]:
        raise ValueError('invalid ELF section names')
    strings = data[names[4]:names[4] + names[5]]
    allocated = {}
    allocated_ranges = []
    for name, kind, flags, address, offset, size, link, info, align, stride in sections:
        if not flags & 2:
            continue
        if name >= len(strings) or b'\0' not in strings[name:]:
            raise ValueError('invalid allocated section name')
        label = strings[name:strings.index(b'\0', name)].decode('ascii')
        if label in allocated or (kind != 8 and (offset > len(data) or size > len(data) - offset)):
            raise ValueError('invalid allocated ELF section')
        if kind != 8 and size:
            allocated_ranges.append([offset, offset + size])
        allocated[label] = {'type': kind, 'flags': flags, 'address': address, 'bytes': size, 'alignment': align,
                            'sha256': None if kind == 8 else digest(data[offset:offset + size])}
    return {'headerSha256': digest(header), 'programHeadersSha256': digest(programs),
            'loads': loads, 'allocatedSections': allocated, 'sectionHeaderRange': [shoff, shoff + shsize * shnum],
            'programHeaderRange': [phoff, phoff + phsize * phnum], 'allocatedFileRanges': allocated_ranges}


def verify_stripped(original, installed, architecture):
    """Allow ELF section-table metadata to move, never runtime mappings or sections.

    elfutils moves the section table out of Go's first load segment and clears
    its old table. ELF loaders use the unchanged program table. Exclusions must
    not overlap any allocated section, the program table, or the ELF header.
    GNU strip's changed PT_LOAD sizes are intentionally rejected.
    """
    before, after = elf_image(original, architecture), elf_image(installed, architecture)
    for key in ('headerSha256', 'programHeadersSha256', 'allocatedSections'):
        if before[key] != after[key]:
            raise ValueError('stripping changed execution headers, runtime sections or protections')
    metadata = [before['sectionHeaderRange'], after['sectionHeaderRange']]
    for low, high in metadata:
        for image in (before, after):
            protected = [[0, 64], image['programHeaderRange'], *image['allocatedFileRanges']]
            if any(low < end and start < high for start, end in protected):
                raise ValueError('section table overlaps execution data')
    loads = []
    for load in before['loads']:
        offset, size = load['fileOffset'], load['fileBytes']
        hashes = []
        for data in (original, installed):
            content = bytearray(data[offset:offset + size])
            if len(content) != size:
                raise ValueError('truncated mapped image')
            for start, end in [(40, 48), (58, 64), *metadata]:
                low, high = max(offset, start), min(offset + size, end)
                if low < high:
                    content[low - offset:high - offset] = bytes(high - low)
            hashes.append(digest(content))
        if hashes[0] != hashes[1]:
            raise ValueError('stripping changed mapped bytes outside section metadata')
        loads.append(dict(load, sha256=hashes[0]))
    return {'programHeadersSha256': before['programHeadersSha256'], 'loads': loads,
            'allocatedSections': before['allocatedSections'], 'excludedSectionTableRanges': metadata,
            'headerPolicy': 'only e_shoff, e_shentsize, e_shnum and e_shstrndx may change'}


def package(archive, output, architecture, profile='fortis-v1', strip_tool='eu-strip', config=None):
    config = json.loads(PROFILE.read_text()) if config is None else config
    if profile not in ('fortis-v1', 'full') or architecture not in MACHINES:
        raise ValueError('unsupported package profile or architecture')
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError('invalid bounded archive')
    sha = hashlib.sha512()
    with archive.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            sha.update(chunk)
        if sha.hexdigest() != config['archiveSha512'][architecture]:
            raise ValueError('upstream archive checksum mismatch')
        source.seek(0)
        with tarfile.open(fileobj=source, mode='r:bz2') as bundle:
            entries = {}
            expected = set(config['required']) | set(config['omitted'])
            for member in bundle.getmembers():
                if member.isdir() and member.name == 'gvisor-bin':
                    continue
                if member.name not in expected or member.name in entries or not member.isfile() or not 0 < member.size <= MAX_BINARY:
                    raise ValueError('unexpected or unsafe upstream archive member')
                entries[member.name] = member
            if set(entries) != expected:
                raise ValueError('upstream inventory changed; review package profile')
            if output.exists() or output.is_symlink() or not output.parent.is_dir():
                raise ValueError('output must be a new directory under an existing parent')
            with tempfile.TemporaryDirectory(prefix='.gvisor-package-', dir=output.parent) as temporary:
                staging = Path(temporary) / 'package'
                staging.mkdir()
                files = {}
                selected = config['required'] if profile == 'fortis-v1' else sorted(expected)
                for name in selected:
                    target = staging / name
                    target.parent.mkdir(exist_ok=True)
                    stream = bundle.extractfile(entries[name])
                    if stream is None:
                        raise ValueError('missing regular executable')
                    with stream:
                        original = stream.read(MAX_BINARY + 1)
                    if len(original) != entries[name].size:
                        raise ValueError('archive member size mismatch')
                    target.write_bytes(original)
                    if profile == 'fortis-v1':
                        subprocess.run([strip_tool, '--strip-debug', str(target)], check=True, capture_output=True, timeout=120)
                    installed = target.read_bytes()
                    proof = verify_stripped(original, installed, architecture)
                    target.chmod(0o555)
                    files[name] = {'upstreamBytes': len(original), 'bytes': len(installed),
                                   'upstreamSha256': digest(original), 'sha256': digest(installed),
                                   'loadImage': proof}
                total = sum(item['bytes'] for item in files.values())
                baseline = sum(entries[name].size for name in config['required'] + list(config['omitted'])
                               if name != 'containerd-shim-runsc-v1')
                manifest = {'schemaVersion': 1, 'profile': profile, 'release': config['release'],
                            'sourceCommit': config['sourceCommit'], 'architecture': architecture,
                            'archiveSha512': sha.hexdigest(), 'installedExecutableBytes': total,
                            'baselineExecutableBytesWithoutContainerd': baseline,
                            'files': files, 'omitted': config['omitted'] if profile == 'fortis-v1' else {},
                            'debugPolicy': 'strip-debug; program headers, all allocated sections and mapped bytes outside ELF section-table metadata unchanged' if profile == 'fortis-v1' else 'original upstream files'}
                notices = ROOT / 'third_party/gvisor-runtime'
                shutil.copytree(notices, staging / 'licenses')
                manifest['noticeSha256'] = {file.name: digest(file.read_bytes()) for file in sorted(notices.iterdir()) if file.is_file()}
                (staging / 'fortis-gvisor-package.json').write_text(json.dumps(manifest, indent=2) + '\n')
                os.rename(staging, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--architecture', required=True, choices=MACHINES)
    parser.add_argument('--profile', choices=['fortis-v1', 'full'], default='fortis-v1')
    parser.add_argument('--strip-tool', default='eu-strip')
    args = parser.parse_args()
    result = package(args.archive, args.output, args.architecture, args.profile, args.strip_tool)
    print(json.dumps({key: result[key] for key in ['profile', 'release', 'architecture', 'installedExecutableBytes', 'baselineExecutableBytesWithoutContainerd']}))


if __name__ == '__main__':
    main()
