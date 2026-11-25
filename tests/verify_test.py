#!/usr/bin/env python3
"""The gate's own rules: what counts as a passing report."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify


class ReportTest(unittest.TestCase):
    def report(self, **changes):
        hashes = {'Makefile': 'a' * 64}
        report = {'complete': True, 'inputs_unchanged': True, 'input_sha256': dict(hashes),
                  'stages': {name: {'returncode': 0} for name in verify.STAGES}}
        report.update(changes)
        return report, hashes

    def test_complete_passing_matching_report_counts(self):
        self.assertTrue(verify.passing(*self.report()))

    def test_anything_less_does_not(self):
        for changes in ({'complete': False}, {'inputs_unchanged': False}, {'input_sha256': {'Makefile': 'b' * 64}},
                        {'input_sha256': {'Makefile': 'a' * 64, 'new.cpp': 'c' * 64}},
                        {'stages': {name: {'returncode': 0} for name in verify.STAGES[:-1]}},
                        {'stages': {name: {'returncode': int(name == 'lint')} for name in verify.STAGES}}):
            with self.subTest(changes=changes):
                self.assertFalse(verify.passing(*self.report(**changes)))

    def test_inputs_cover_sources_and_tooling_but_not_build_output(self):
        hashes = verify.input_hashes()
        for name in ('Makefile', 'verify.py', 'orchestrator/native_update.cpp', 'lib/ORIGIN.json',
                     'tools/Dockerfile.verify', 'image/packages.why', 'tests/native_update_test.py'):
            self.assertIn(name, hashes)
        self.assertFalse(any(name.startswith(('build/', 'build-verify/')) or '__pycache__' in name for name in hashes))


if __name__ == '__main__':
    unittest.main()
