#!/usr/bin/env python3
"""Fail-closed native compiler-profile and exact static-PIE ELF qualification.

Compiler flags are audited per actual C/C++/assembly invocation. They do not
prove that every function has a stack guard or every access has a bounds check.
Prebuilt CRT/libc/libstdc++ and handwritten assembly remain explicit limitations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def profile():
    return {kind: shlex.split(subprocess.check_output(
        ['make', '-s', '-f', str(ROOT / 'tools/hardening.mk'), kind], text=True))
            for kind in ('c', 'cxx', 'asm', 'link')}


def macro_value(arguments, name):
    value = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in ('-D', '-U') and index + 1 < len(arguments):
            index += 1
            token += arguments[index]
        if token == '-U' + name:
            value = None
        elif token == '-D' + name:
            value = '1'
        elif token.startswith('-D' + name + '='):
            value = token.split('=', 1)[1]
        index += 1
    return value


def validate_commands(records, expected_sources, output, dependency_roots=('/mbedtls-3.6.7/',)):
    required = profile()
    covered, assembly = set(), set()
    links = 0
    for record in records:
        if record['returncode'] != 0:
            raise ValueError('failed compiler invocation in release audit')
        args = record['arguments'][1:]
        if any(x.startswith('@') or (x.startswith('-Wp,') and ('FORTIFY_SOURCE' in x or 'GLIBCXX_ASSERTIONS' in x)) for x in args):
            raise ValueError('opaque protection override in compiler audit')
        for source in record['sources']:
            if '-c' not in args:
                continue
            path = Path(source)
            kind = 'asm' if path.suffix in ('.s', '.S') else 'cxx' if path.suffix == '.cpp' else 'c'
            if not all(flag in args for flag in required[kind]):
                raise ValueError('missing hardening flag: ' + source)
            # Reject later overrides, not just absent positive tokens.
            if kind != 'asm':
                stack = [x for x in args if x.startswith(('-fstack-protector', '-fno-stack-protector'))]
                clash = [x for x in args if x in ('-fstack-clash-protection', '-fno-stack-clash-protection')]
                pie = [x for x in args if x in ('-fPIE', '-fpie', '-fPIC', '-fpic', '-fno-PIE', '-fno-pie', '-fno-pic', '-fno-PIC')]
                if not stack or stack[-1] != '-fstack-protector-strong' or not clash or clash[-1] != '-fstack-clash-protection':
                    raise ValueError('compiler protection overridden: ' + source)
                if macro_value(args, '_FORTIFY_SOURCE') != '3' or not pie or pie[-1] != '-fPIE':
                    raise ValueError('fortify/PIE overridden: ' + source)
                if not any(x.startswith(('-O1', '-O2', '-O3', '-Os', '-Og', '-Ofast', '-Oz')) for x in args) or '-O0' in args:
                    raise ValueError('fortify requires optimization: ' + source)
                if kind == 'cxx':
                    if macro_value(args, '_GLIBCXX_ASSERTIONS') != '1':
                        raise ValueError('library assertions overridden: ' + source)
            (assembly if kind == 'asm' else covered).add(source)
        if '-c' not in args and '-o' in args and args[args.index('-o') + 1] == output:
            if not all(flag in args for flag in required['link'] + required['cxx']):
                raise ValueError('release link lacks hardening profile')
            links += 1
    if links != 1:
        raise ValueError('expected one audited production link')
    if not expected_sources or not expected_sources.issubset(covered):
        raise ValueError('production sources missing compiler audit: ' + str(sorted(expected_sources - covered)))
    if not all(any(root in p for p in covered) for root in dependency_roots):
        raise ValueError('dependency compilation missing from hardening audit')
    return {'compiled_c_cpp_sources': len(covered), 'assembly_sources': sorted(assembly),
            'production_sources': len(expected_sources), 'profile': required,
            'limits': ['SSP uses compiler eligibility heuristics, not every function.',
                       'Fortify checks only operations with available object-size information.',
                       'Handwritten assembly and prebuilt CRT/libc/libstdc++ are not rebuilt/instrumented by this profile.',
                       'CET, CFI and sanitizers are not release guarantees.']}


# ELF machine numbers of the architectures a release is built for.
MACHINES = {'x86_64': 62, 'aarch64': 183}


def validate_elf(data, architecture='x86_64'):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian ELF64')
    if struct.unpack_from('<HH', data, 16) != (3, MACHINES[architecture]):
        raise ValueError(f'expected {architecture} static PIE')
    entry, offset = struct.unpack_from('<QQ', data, 24)
    header_size, stride, count = struct.unpack_from('<HHH', data, 52)
    if header_size != 64 or stride != 56 or not count or offset < 64 or offset + stride * count > len(data):
        raise ValueError('invalid program header bounds')
    headers = [struct.unpack_from('<IIQQQQQQ', data, offset + i * stride) for i in range(count)]
    loads, relro, stacks, dynamic = [], [], [], []
    for kind, flags, start, address, _, size, memory, alignment in headers:
        if start > len(data) or size > len(data) - start or address + memory >= 1 << 64:
            raise ValueError('invalid segment bounds')
        if kind == 3:
            raise ValueError('external interpreter is forbidden')
        if kind == 1:
            if size > memory or flags & 3 == 3 or (alignment > 1 and (alignment & (alignment - 1) or (address - start) % alignment)):
                raise ValueError('invalid/W+X load segment')
            loads.append((address, address + memory, flags))
        elif kind == 0x6474e551:
            stacks.append((flags, memory))
        elif kind == 0x6474e552:
            relro.append((address, address + memory))
        elif kind == 2:
            if not size or size % 16:
                raise ValueError('invalid dynamic table')
            entries = []
            for p in range(start, start + size, 16):
                tag, value = struct.unpack_from('<qQ', data, p)
                if tag == 0:
                    break
                entries.append((tag, value))
            else:
                raise ValueError('unterminated dynamic table')
            dynamic.append(entries)
    if not loads or not any(lo <= entry < hi and flags & 1 for lo, hi, flags in loads):
        raise ValueError('entry outside executable load segment')
    if len(stacks) != 1 or stacks[0][0] & 1 or stacks[0][1] < 2 * 1024 * 1024:
        raise ValueError('requires NX stack with 2 MiB native thread budget')
    if len(relro) != 1 or relro[0][0] >= relro[0][1] or not any(lo <= relro[0][0] < relro[0][1] <= hi for lo, hi, _ in loads):
        raise ValueError('valid RELRO segment required')
    if len(dynamic) != 1:
        raise ValueError('one static-PIE dynamic table required')
    entries = dynamic[0]
    if any(tag in (1, 15, 29, 22) or (tag == 30 and value & 4) for tag, value in entries):
        raise ValueError('shared dependencies, search paths or text relocations forbidden')
    if not any(tag == 24 or (tag == 30 and value & 8) or (tag == 0x6ffffffb and value & 1) for tag, value in entries):
        raise ValueError('immediate binding required')
    return {'static_pie': True, 'nx_stack': True, 'relro': True, 'immediate_binding': True,
            'no_writable_executable_loads': True, 'no_text_relocations': True,
            'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release', type=Path)
    parser.add_argument('commands', type=Path)
    parser.add_argument('--binary', choices=['native-controller', 'fortis-sandbox'], required=True)
    parser.add_argument('--architecture', choices=sorted(MACHINES), default='x86_64')
    parser.add_argument('--build', default='build-release', help='the BUILD directory the release was made in')
    args = parser.parse_args()
    records = [json.loads(line) for line in args.commands.read_text().splitlines()]
    for record in records:
        for source, digest in record['sources'].items():
            if hashlib.sha256(Path(source).read_bytes()).hexdigest() != digest:
                raise ValueError('source changed after compilation: ' + source)
    # The Makefile owns which sources make up each program.
    listed = subprocess.check_output(['make', '-s', 'print-' + args.binary + '-sources'], text=True,
                                     cwd=ROOT).split()
    sources = {str((ROOT / name).resolve()) for name in listed}
    report = {'compiler': validate_commands(records, sources, args.build + '/' + args.binary),
              'elf': validate_elf((args.release / args.binary).read_bytes(), args.architecture)}
    def executable_bytes(data):
        offset = struct.unpack_from('<Q', data, 32)[0]
        stride, count = struct.unpack_from('<HH', data, 54)
        segments = [struct.unpack_from('<IIQQQQQQ', data, offset + i * stride) for i in range(count)]
        return [hashlib.sha256(data[start:start + size]).hexdigest()
                for kind, flags, start, _, _, size, _, _ in segments if kind == 1 and flags & 1]
    debug = (args.release / (args.binary + '.debug')).read_bytes()
    validate_elf(debug, args.architecture)
    if executable_bytes(debug) != executable_bytes((args.release / args.binary).read_bytes()):
        raise ValueError('debug symbols do not describe artifact executable segments')
    report['executable_segment_hashes'] = executable_bytes(debug)
    report['compiler_command_log_sha256'] = hashlib.sha256(args.commands.read_bytes()).hexdigest()
    installed = subprocess.check_output(['apk', 'info', '-v'], text=True).splitlines()
    packages = {}
    for name in ('musl', 'fortify-headers', 'libstdc++'):
        versions = [line[len(name) + 1:] for line in installed if line.startswith(name + '-')
                    and re.fullmatch(r'[0-9][^\s]*', line[len(name) + 1:])]
        if len(versions) != 1:
            raise ValueError('missing/ambiguous installed package version: ' + name)
        packages[name] = versions[0]
    report['toolchain'] = {'gcc': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
                           'packages': packages}
    disassembly = subprocess.check_output(['objdump', '-d', str(args.release / (args.binary + '.debug'))], text=True)
    references = len(re.findall(r'(?:call\S*|bl)\s+[^\n]*<__stack_chk_fail(?:_local)?>', disassembly))
    if not references:
        raise ValueError('artifact has no observed stack-guard failure calls')
    report['observed_stack_guard_calls'] = references
    (args.release / ({'native-controller': 'controller-hardening.json', 'fortis-sandbox': 'sandbox-hardening.json'}[args.binary])).write_text(json.dumps(report, indent=2) + '\n')
    print('Native compiler/ELF hardening passed:', report['elf']['sha256'])


if __name__ == '__main__':
    main()
