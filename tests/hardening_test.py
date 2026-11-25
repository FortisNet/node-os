#!/usr/bin/env python3
"""The release audit: missing or overridden compiler protections and malformed
executables must be refused."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hardening', ROOT / 'tools/hardening.py')
hardening = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardening)


def elf():
    data = bytearray(1024)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQ', data, 16, 3, 62, 1, 512, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 5)
    def header(i, kind, flags, offset, address, size, memory):
        struct.pack_into('<IIQQQQQQ', data, 64 + i * 56, kind, flags, offset, address, address, size, memory, 1)
    header(0, 1, 5, 0, 0, 600, 600)
    header(1, 1, 6, 600, 600, 424, 424)
    header(2, 0x6474e551, 6, 0, 0, 0, 2097152)
    header(3, 0x6474e552, 4, 600, 600, 100, 100)
    header(4, 2, 6, 720, 720, 32, 32)
    struct.pack_into('<qQqQ', data, 720, 30, 8, 0, 0)
    return data


class HardeningTest(unittest.TestCase):
    def test_exact_elf_properties(self):
        self.assertTrue(hardening.validate_elf(elf())['static_pie'])
        # The same file is an aarch64 one only when it says so, and the reverse.
        arm = elf(); struct.pack_into('<H', arm, 18, 183)
        self.assertTrue(hardening.validate_elf(arm, 'aarch64')['static_pie'])
        with self.assertRaises(ValueError):
            hardening.validate_elf(elf(), 'aarch64')
        mutations = [(16, '<H', 2), (18, '<H', 183), (32, '<Q', 1000),
                     (64 + 4, '<I', 7), (64 + 2 * 56 + 4, '<I', 7),
                     (64 + 3 * 56, '<I', 1), (720, '<q', 1), (728, '<Q', 4),
                     (64 + 4 * 56 + 32, '<Q', 33), (64 + 56 + 40, '<Q', (1 << 64) - 1)]
        for offset, fmt, value in mutations:
            data = elf(); struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                hardening.validate_elf(data)
        for length in (0, 63, 64, 200, 1023):
            with self.subTest(truncated=length), self.assertRaises(ValueError):
                hardening.validate_elf(elf()[:length])

    def records(self, sources, target):
        flags = hardening.profile()
        paths = [*sources, '/work/build-release/mbedtls-3.6.7/library/sha256.c']
        records = [{'returncode': 0, 'sources': {path: 'hash'},
                    'arguments': ['cc', '-O2', '-c', *flags['cxx' if path.endswith('.cpp') else 'c']]} for path in paths]
        records.append({'returncode': 0, 'sources': {},
                        'arguments': ['c++', *flags['cxx'], *flags['link'], '-o', target]})
        return records

    def test_every_source_and_the_link_must_carry_the_profile(self):
        sources = ['/work/orchestrator/native_update.cpp', '/work/lib/outbound_https.cpp']
        target = 'build-release/native-controller'
        records = self.records(sources, target)
        self.assertEqual(hardening.validate_commands(records, set(sources), target)['production_sources'], 2)
        for change in ['missing', 'override-stack', 'override-clash', 'override-fortify', 'split-override',
                       'response-file', 'override-pie', 'override-assertions', 'missing-source', 'missing-link',
                       'missing-dependency', 'failed', 'link-not-static']:
            bad = copy.deepcopy(records)
            if change == 'missing': bad[0]['arguments'].remove('-fstack-protector-strong')
            elif change == 'override-stack': bad[0]['arguments'].append('-fno-stack-protector')
            elif change == 'override-clash': bad[0]['arguments'].append('-fno-stack-clash-protection')
            elif change == 'override-fortify': bad[0]['arguments'].append('-U_FORTIFY_SOURCE')
            elif change == 'split-override': bad[0]['arguments'] += ['-U', '_FORTIFY_SOURCE']
            elif change == 'response-file': bad[0]['arguments'].append('@hidden-flags')
            elif change == 'override-pie': bad[0]['arguments'].append('-fno-PIE')
            elif change == 'override-assertions': bad[0]['arguments'].append('-U_GLIBCXX_ASSERTIONS')
            elif change == 'missing-source': bad.pop(1)
            elif change == 'missing-link': bad.pop()
            elif change == 'missing-dependency': bad.pop(2)
            elif change == 'failed': bad[0]['returncode'] = 1
            elif change == 'link-not-static': bad[-1]['arguments'].remove('-static-pie')
            with self.subTest(change=change), self.assertRaises(ValueError):
                hardening.validate_commands(bad, set(sources), target)

    def test_one_program_does_not_vouch_for_another(self):
        sources = ['/work/sandbox/sandbox_manager.cpp', '/work/sandbox/sandbox_spec.cpp']
        records = self.records(sources, 'build-release/fortis-sandbox')
        self.assertEqual(hardening.validate_commands(records, set(sources), 'build-release/fortis-sandbox')
                         ['production_sources'], 2)
        with self.assertRaises(ValueError):
            hardening.validate_commands(records, set(sources), 'build-release/native-controller')
        with self.assertRaises(ValueError):
            hardening.validate_commands(records, {'/work/orchestrator/native_update.cpp'},
                                        'build-release/fortis-sandbox')


if __name__ == '__main__':
    unittest.main()
