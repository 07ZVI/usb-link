#!/usr/bin/env python3
"""Exercise publication boundaries in disposable repositories with synthetic data."""
import json
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

AUDIT = Path(__file__).with_name('audit_distribution.py')


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usb-link-publication-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env.update(GIT_AUTHOR_NAME='Test', GIT_AUTHOR_EMAIL='test@example.invalid',
                        GIT_COMMITTER_NAME='Test', GIT_COMMITTER_EMAIL='test@example.invalid')
        self.git('init', '-q')
        self.git('config', 'core.hooksPath', '.no-hooks')
        (self.root / 'scripts').mkdir()
        shutil.copyfile(AUDIT, self.root / 'scripts/audit_distribution.py')
        (self.root / '.gitignore').write_text('/.local/\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Initial synthetic source')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, env=self.env,
                                       stderr=subprocess.STDOUT)

    def audit(self, *args):
        result = subprocess.run([sys.executable, 'scripts/audit_distribution.py', *args],
                                cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode, json.loads(result.stdout)

    def private_file(self):
        directory = self.root / '.local'
        directory.mkdir()
        path = directory / 'notes.txt'
        path.write_text('Synthetic private note\n')
        return path

    def test_ignored_private_files_are_not_scanned(self):
        self.private_file()
        self.assertEqual(self.audit('--source')[0], 0)

    def test_force_added_private_path_is_rejected(self):
        self.private_file()
        self.git('add', '-f', '.local/notes.txt')
        for mode in ('--source', '--staged'):
            code, result = self.audit(mode)
            self.assertEqual(code, 1)
            self.assertTrue(any('local-only path' in e for e in result['errors']))

    def test_index_secret_cannot_be_hidden_by_working_copy(self):
        path = self.root / 'settings.txt'
        path.write_text('ghp_' + 'A' * 36)
        self.git('add', 'settings.txt')
        path.write_text('clean working copy\n')
        self.assertEqual(self.audit('--source')[0], 0)
        self.assertEqual(self.audit('--staged')[0], 1)

    def test_deleted_private_history_is_still_rejected(self):
        self.private_file()
        self.git('add', '-f', '.local/notes.txt')
        self.git('commit', '-qm', 'Synthetic accidental addition')
        self.git('rm', '-q', '.local/notes.txt')
        self.git('commit', '-qm', 'Remove from current tree')
        self.assertEqual(self.audit('--source')[0], 0)
        self.assertEqual(self.audit('--history')[0], 1)

    def test_normal_zip_entries_are_inspected_once(self):
        package = self.root / 'package'
        package.mkdir()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w') as z:
            z.writestr('note.txt', 'Original synthetic fixture')
        with zipfile.ZipFile(package / 'bundle.zip', 'w', zipfile.ZIP_STORED) as z:
            z.writestr('inner.zip', inner.getvalue())
        code, result = self.audit('--package', str(package))
        self.assertEqual(code, 0, result)
        self.assertEqual(result['archives_inspected'], 2)

    def test_forbidden_nested_binary_remains_rejected(self):
        package = self.root / 'package'
        package.mkdir()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w') as z:
            z.writestr('wintun.dll', 'Synthetic forbidden binary')
        with zipfile.ZipFile(package / 'bundle.zip', 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('inner.zip', inner.getvalue())
        code, result = self.audit('--package', str(package))
        self.assertEqual(code, 1)
        self.assertTrue(any('external component' in e for e in result['errors']))


if __name__ == '__main__':
    unittest.main()
