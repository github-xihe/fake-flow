import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_release', ROOT / 'scripts/prepare_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'inputs'
        self.output = self.root / 'release'
        self.sha = 'a' * 40
        self.tag, core = release.package_version(ROOT / 'packaging/openwrt/Makefile')
        _, luci = release.package_version(ROOT / 'packaging/luci/Makefile')
        groups = {
            'openwrt24': [f'fakeflow_{self.tag}-r{core}_x86_64.ipk'],
            'luci24': [f'luci-app-fakeflow_{self.tag}-r{luci}_all.ipk'],
            'openwrt25': [f'fakeflow-{self.tag}-r{core}.apk', f'luci-app-fakeflow-{self.tag}-r{luci}.apk'],
        }
        for group, names in groups.items():
            folder = self.inputs / group
            folder.mkdir(parents=True)
            sdk = '25.12.5' if group == 'openwrt25' else '24.10.5'
            (folder / 'BUILD.txt').write_text(f'OpenWrt SDK: {sdk}\nSource: {self.sha}\n')
            manifest = ''
            for name in names:
                data = name.encode()
                (folder / name).write_bytes(data)
                manifest += f'{hashlib.sha256(data).hexdigest()}  {name}\n'
            (folder / 'SHA256SUMS').write_text(manifest)

    def collect(self):
        return release.collect(self.inputs, self.output, self.tag, self.sha)

    def rejected(self):
        with self.assertRaises(ValueError):
            self.collect()
        self.assertFalse(self.output.exists(), 'Invalid inputs must not be staged')

    def test_complete_release(self):
        self.collect()
        self.assertEqual(len(list(self.output.glob('*.ipk'))), 2)
        self.assertEqual(len(list(self.output.glob('*.apk'))), 2)
        for line in (self.output / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split()
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_wrong_commit(self):
        path = self.inputs / 'openwrt25/BUILD.txt'
        path.write_text(path.read_text().replace(self.sha, 'b' * 40))
        self.rejected()

    def test_release_documents_and_asset_set(self):
        subprocess.run([sys.executable, str(ROOT / 'scripts/prepare_release.py'),
                        '--tag', self.tag, '--source', self.sha,
                        '--run-url', 'https://github.com/lilu0826/fake-flow/actions/runs/123'],
                       cwd=self.root, check=True, capture_output=True)
        self.assertEqual(len(list(self.output.iterdir())), 8)
        text = (self.output / 'INSTALL-OpenWrt-25.12.md').read_text(encoding='utf-8')
        self.assertIn("grep '\\.apk$' SHA256SUMS | sha256sum -c -", text)
        notes = (self.root / 'release-notes.md').read_text(encoding='utf-8')
        self.assertIn(self.sha, notes)
        self.assertIn('actions/runs/123', notes)

    def test_corrupt_package(self):
        next((self.inputs / 'openwrt25').glob('*.apk')).write_bytes(b'corrupt')
        self.rejected()

    def test_missing_package(self):
        next((self.inputs / 'luci24').glob('*.ipk')).unlink()
        self.rejected()

    def test_extra_package(self):
        (self.inputs / 'openwrt24/old.ipk').write_bytes(b'old')
        self.rejected()

    def test_wrong_sdk(self):
        path = self.inputs / 'openwrt25/BUILD.txt'
        path.write_text(path.read_text().replace('25.12.5', '24.10.5'))
        self.rejected()

    def test_invalid_tag(self):
        for tag in ['v' + self.tag, '../escape', '9.9.9']:
            with self.assertRaises(ValueError):
                release.check_version(tag)


if __name__ == '__main__':
    unittest.main()
