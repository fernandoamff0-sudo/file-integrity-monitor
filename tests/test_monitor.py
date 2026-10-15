import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from monitor import MonitorError, compare, load_baseline, make_baseline, scan, validate_baseline, write_baseline

ROOT = Path(__file__).resolve().parent.parent


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'files'
        self.folder.mkdir()
        self.baseline = Path(self.temp.name) / 'baseline.json'

    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'monitor.py'), *map(str, args)], capture_output=True, text=True)

    def test_binary_and_empty_file_digests(self):
        for name, data in [('binary', b'\x00\xff\r\n'), ('empty', b'')]:
            (self.folder / name).write_bytes(data)
        result = scan(self.folder)
        self.assertEqual(result['binary']['sha256'], hashlib.sha256(b'\x00\xff\r\n').hexdigest())
        self.assertEqual(result['empty']['size'], 0)

    def test_add_modify_delete(self):
        (self.folder / 'modified').write_text('before')
        (self.folder / 'deleted').write_text('old')
        data = make_baseline(self.folder)
        (self.folder / 'modified').write_text('after!')
        (self.folder / 'deleted').unlink()
        (self.folder / 'added').write_text('new')
        report = compare(data, scan(self.folder))
        for category, name in [('added', 'added'), ('modified', 'modified'), ('deleted', 'deleted')]:
            self.assertEqual(report[category], [name])
        self.assertEqual(report['status'], 'changed')

    def test_multichunk_file_digest(self):
        contents = b'0123456789' * 250000
        (self.folder / 'large').write_bytes(contents)
        result = scan(self.folder)['large']
        self.assertEqual(result['sha256'], hashlib.sha256(contents).hexdigest())
        self.assertEqual(result['size'], len(contents))

    def test_file_changing_during_read_rejected(self):
        path = self.folder / 'changing'
        path.write_bytes(b'original')
        before = path.stat()
        after = SimpleNamespace(**{field: getattr(before, field) for field in
                                  ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')})
        after.st_size += 1
        with patch('monitor.os.fstat', side_effect=[before, after]):
            with self.assertRaisesRegex(MonitorError, 'changed during scan'):
                scan(self.folder)

    def test_same_size_edit_detected(self):
        path = self.folder / 'file'
        path.write_bytes(b'abcd')
        data = make_baseline(self.folder)
        path.write_bytes(b'efgh')
        self.assertEqual(compare(data, scan(self.folder))['modified'], ['file'])

    def test_timestamp_only_change_is_not_content_change(self):
        path = self.folder / 'file'
        path.write_text('data')
        data = make_baseline(self.folder)
        os.utime(path, (1, 1))
        self.assertEqual(compare(data, scan(self.folder))['status'], 'unchanged')

    def test_nested_paths_and_git_exclusion(self):
        (self.folder / 'nested').mkdir()
        (self.folder / 'nested/file').write_text('x')
        (self.folder / '.git').mkdir()
        (self.folder / '.git/config').write_text('ignored')
        self.assertEqual(list(scan(self.folder)), ['nested/file'])

    def test_empty_directory(self):
        data = make_baseline(self.folder)
        self.assertEqual(data['files'], {})
        self.assertEqual(compare(data, scan(self.folder))['status'], 'unchanged')

    def test_baseline_roundtrip_and_no_overwrite(self):
        data = make_baseline(self.folder)
        write_baseline(self.baseline, data)
        self.assertEqual(load_baseline(self.baseline), data)
        with self.assertRaises(MonitorError):
            write_baseline(self.baseline, {'bad': 'data'})
        self.assertEqual(load_baseline(self.baseline), data)

    def test_invalid_baselines(self):
        for value in [None, [], {}, {'version': True}, dict(make_baseline(self.folder), algorithm='md5'),
                      dict(make_baseline(self.folder), excluded_names=[])]:
            with self.subTest(value=value), self.assertRaises(MonitorError):
                validate_baseline(value)
        for name, item in [('../escape', {'sha256': 'a'*64, 'size': 1}),
                           ('/absolute', {'sha256': 'a'*64, 'size': 1}),
                           ('a//b', {'sha256': 'a'*64, 'size': 1}),
                           ('a', {'sha256': 'bad', 'size': 1}),
                           ('a', {'sha256': 'a'*64, 'size': True})]:
            data = make_baseline(self.folder)
            data['files'] = {name: item}
            with self.subTest(name=name), self.assertRaises(MonitorError):
                validate_baseline(data)

    def test_symlink_file_and_directory_rejected(self):
        target = Path(self.temp.name) / 'target'
        target.write_text('private')
        for destination in (target, Path(self.temp.name)):
            link = self.folder / 'link'
            link.symlink_to(destination)
            with self.assertRaises(MonitorError):
                scan(self.folder)
            link.unlink()

    def test_special_file_rejected(self):
        os.mkfifo(self.folder / 'pipe')
        with self.assertRaises(MonitorError):
            scan(self.folder)

    def test_io_failure_not_silently_skipped(self):
        (self.folder / 'file').write_text('data')
        with patch('monitor.hash_file', side_effect=PermissionError('denied')):
            with self.assertRaises(MonitorError):
                scan(self.folder)

    def test_cli_lifecycle(self):
        (self.folder / 'demo').write_text('original')
        result = self.cli('baseline', self.folder, self.baseline, '--format', 'json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['scanned_files'], 1)
        self.assertEqual(self.cli('check', self.folder, self.baseline).returncode, 0)
        (self.folder / 'demo').write_text('changed')
        result = self.cli('check', self.folder, self.baseline, '--format', 'json')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['modified'], ['demo'])
        self.assertEqual((self.folder / 'demo').read_text(), 'changed')

    def test_baseline_inside_root_is_rejected(self):
        result = self.cli('baseline', self.folder, self.folder / 'baseline.json')
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.folder / 'baseline.json').exists())

    def test_existing_baseline_unchanged(self):
        self.baseline.write_text('keep me')
        result = self.cli('baseline', self.folder, self.baseline)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.baseline.read_text(), 'keep me')

    def test_cli_invalid_inputs(self):
        for content in ('{', '{}', '[]', '{"version":1,"version":1}', '\ufffd'):
            self.baseline.write_text(content)
            result = self.cli('check', self.folder, self.baseline)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('Traceback', result.stderr)
        self.baseline.write_bytes(b'\xff')
        self.assertEqual(self.cli('check', self.folder, self.baseline).returncode, 2)
        self.assertEqual(self.cli('check', self.folder, Path(self.temp.name) / 'missing').returncode, 2)
        self.assertEqual(self.cli('baseline', self.folder / 'missing', self.baseline).returncode, 2)

    def test_symlink_root_and_baseline_rejected(self):
        link = Path(self.temp.name) / 'root-link'
        link.symlink_to(self.folder, target_is_directory=True)
        self.assertEqual(self.cli('baseline', link, self.baseline).returncode, 2)
        target = Path(self.temp.name) / 'target'
        target.write_text('{}')
        self.baseline.symlink_to(target)
        self.assertEqual(self.cli('check', self.folder, self.baseline).returncode, 2)

    def test_paths_with_spaces_unicode_and_control_characters(self):
        (self.folder / 'archivo ñ\n.txt').write_text('x')
        self.assertEqual(self.cli('baseline', self.folder, self.baseline).returncode, 0)
        (self.folder / 'archivo ñ\n.txt').write_text('y')
        result = self.cli('check', self.folder, self.baseline)
        self.assertEqual(result.returncode, 1)
        self.assertIn('\\n.txt', result.stdout)

    def test_demo(self):
        result = subprocess.run([sys.executable, str(ROOT / 'examples/demo.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"modified": [', result.stdout)
        self.assertIn('"new.txt"', result.stdout)

    def test_help_and_usage(self):
        self.assertEqual(self.cli('--help').returncode, 0)
        self.assertEqual(self.cli().returncode, 2)


if __name__ == '__main__':
    unittest.main()
