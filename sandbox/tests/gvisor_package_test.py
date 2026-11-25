#!/usr/bin/env python3
"""Package integrity, archive validation and loaded-image equivalence contracts."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import struct
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_gvisor', ROOT / 'package_gvisor.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fortis-gvisor-package-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.arch = platform.machine()
        source = self.root / 'fixture.c'
        source.write_text('int main(void) { return 0; }\n')
        self.binary = self.root / 'fixture'
        subprocess.run(['gcc-13', '-g', '-fPIE', '-pie', '-Wl,-z,relro,-z,now,-z,noexecstack',
                        str(source), '-o', str(self.binary)], check=True)
        self.data = self.binary.read_bytes()
        self.config = {'release': 'test', 'sourceCommit': 'test', 'required': ['runsc'],
                       'omitted': {'optional': 'unused'}, 'archiveSha512': {}}

    def archive(self, entries):
        path = self.root / 'runtime.tar.bz2'
        with tarfile.open(path, 'w:bz2') as output:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name); info.size = len(data); info.type = kind
                output.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        self.config['archiveSha512'][self.arch] = hashlib.sha512(path.read_bytes()).hexdigest()
        return path

    def test_strip_preserves_mapped_bytes_and_protections(self):
        before = package.elf_image(self.data, self.arch)
        subprocess.run(['strip', '--strip-debug', str(self.binary)], check=True)
        self.assertEqual(package.elf_image(self.binary.read_bytes(), self.arch)['programHeadersSha256'], before['programHeadersSha256'])
        package.verify_stripped(self.data, self.binary.read_bytes(), self.arch)
        changed = bytearray(self.binary.read_bytes())
        # Mutate executable bytes, entry point and program permissions separately.
        phoff = struct.unpack_from('<Q', changed, 32)[0]
        offsets = [24, phoff + 4]
        for index in range(struct.unpack_from('<H', changed, 56)[0]):
            entry = struct.unpack_from('<IIQQQQQQ', changed, phoff + index * 56)
            if entry[0] == 1 and entry[1] & 1:
                offsets.append(entry[2] + 8)
        for offset in offsets:
            modified = bytearray(changed); modified[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertNotEqual(package.elf_image(modified, self.arch), before)
                with self.assertRaises(ValueError): package.verify_stripped(self.data, modified, self.arch)
        for data in (b'', self.data[:63], self.data[:100]):
            with self.assertRaises(ValueError): package.elf_image(data, self.arch)
        with self.assertRaises(ValueError): package.elf_image(self.data, 'aarch64' if self.arch == 'x86_64' else 'x86_64')

    def test_reduced_package_is_atomic_and_pinned(self):
        archive = self.archive([('runsc', self.data, tarfile.REGTYPE), ('optional', self.data, tarfile.REGTYPE)])
        output = self.root / 'result'
        result = package.package(archive, output, self.arch, strip_tool='strip', config=self.config)
        self.assertLess(result['installedExecutableBytes'], len(self.data))
        self.assertFalse((output / 'optional').exists())
        self.assertEqual((output / 'runsc').stat().st_mode & 0o777, 0o555)
        self.assertEqual(json.loads((output / 'fortis-gvisor-package.json').read_text()), result)
        with self.assertRaises(ValueError): package.package(archive, output, self.arch, strip_tool='strip', config=self.config)
        wrong = copy.deepcopy(self.config); wrong['archiveSha512'][self.arch] = '0' * 128
        with self.assertRaises(ValueError): package.package(archive, self.root / 'bad', self.arch, config=wrong)
        self.assertFalse((self.root / 'bad').exists())
        full = package.package(archive, self.root / 'full', self.arch, profile='full', strip_tool='strip', config=self.config)
        self.assertEqual(full['installedExecutableBytes'], 2 * len(self.data))
        self.assertEqual((self.root / 'full/runsc').read_bytes(), self.data)

    def test_archive_inventory_refuses_missing_extra_duplicate_and_links(self):
        for entries in [[], [('runsc', self.data, tarfile.REGTYPE)],
                        [('runsc', self.data, tarfile.REGTYPE), ('optional', self.data, tarfile.REGTYPE), ('../escape', self.data, tarfile.REGTYPE)],
                        [('runsc', self.data, tarfile.REGTYPE), ('runsc', self.data, tarfile.REGTYPE), ('optional', self.data, tarfile.REGTYPE)],
                        [('runsc', b'', tarfile.SYMTYPE), ('optional', self.data, tarfile.REGTYPE)]]:
            archive = self.archive(entries)
            with self.assertRaises(ValueError): package.package(archive, self.root / 'result', self.arch, strip_tool='strip', config=self.config)
            self.assertFalse((self.root / 'result').exists())

    def test_bad_strip_tool_cannot_publish_changed_execution_image(self):
        archive = self.archive([('runsc', self.data, tarfile.REGTYPE), ('optional', self.data, tarfile.REGTYPE)])
        tool = self.root / 'bad-strip'
        tool.write_text('#!/usr/bin/env python3\nimport sys\np=sys.argv[-1]\nb=bytearray(open(p,"rb").read()); b[24]^=1\nopen(p,"wb").write(b)\n')
        tool.chmod(0o755)
        with self.assertRaises(ValueError): package.package(archive, self.root / 'result', self.arch, strip_tool=str(tool), config=self.config)
        self.assertFalse((self.root / 'result').exists())


if __name__ == '__main__':
    unittest.main()
