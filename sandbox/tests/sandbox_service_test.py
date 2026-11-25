#!/usr/bin/env python3
"""Exercise OpenRC cold-start preparation without root or a host cgroup mount."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ServiceTests(unittest.TestCase):
    def test_cold_start_initializes_before_doctor_and_reuses_history(self):
        script = (ROOT / 'config/fortis-sandbox.openrc').read_text()
        body = script.split('start_pre() {', 1)[1].split('}', 1)[0]
        with tempfile.TemporaryDirectory(prefix='fortis-sandbox-service-') as temporary:
            root = Path(temporary)
            history = root / 'history'
            history.write_text('existing durable job history')
            helper = root / 'helper'
            helper.write_text("""#!/bin/sh
set -eu
printf '%s\n' "$2" >> "$FIXTURE_ROOT/calls"
case "$2" in
 init) mkdir -p "$FIXTURE_ROOT/ephemeral-cgroup" ;;
 doctor) test -d "$FIXTURE_ROOT/ephemeral-cgroup" ;;
 *) exit 2 ;;
esac
""")
            helper.chmod(0o755)
            env = dict(os.environ, FIXTURE_ROOT=str(root), command=str(helper))
            for _ in range(2):
                subprocess.run(['sh', '-eu', '-c', body], env=env, check=True, timeout=5)
            self.assertEqual((root / 'calls').read_text().splitlines(), ['init', 'doctor', 'init', 'doctor'])
            self.assertEqual(history.read_text(), 'existing durable job history')
            (root / 'ephemeral-cgroup').rmdir()
            subprocess.run(['sh', '-eu', '-c', body], env=env, check=True, timeout=5)
            self.assertTrue((root / 'ephemeral-cgroup').is_dir())
            self.assertEqual(history.read_text(), 'existing durable job history')

    def test_node_starts_after_optional_broker(self):
        script = (ROOT.parent / 'image/files/fortis-native.openrc').read_text()
        body = script.split('depend() {', 1)[1].split('}', 1)[0]
        with tempfile.TemporaryDirectory(prefix='fortis-service-order-') as temporary:
            marker = Path(temporary) / 'after-broker'
            shims = ('need() { :; }; after() { case " $* " in *" fortis-sandbox-broker "*) touch "$ORDER_MARKER";; '
                     'esac; }; ')
            subprocess.run(['sh', '-eu', '-c', shims + body],
                           env=dict(os.environ, ORDER_MARKER=str(marker)), check=True, timeout=5)
            self.assertTrue(marker.exists())


if __name__ == '__main__':
    unittest.main()
