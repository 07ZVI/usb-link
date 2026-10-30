import json
import pathlib
import tempfile
import unittest
import subprocess
import sys
import os
from unittest.mock import patch

import local_installer_retention as retention


class LocalRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'out').mkdir()

    def put(self, name, content='installer'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_keep_current_previous_and_selected_without_touching_evidence(self):
        selected = self.put('out/installer-retention.json', json.dumps({'previous': '0.8.139', 'previous_selection': 'selected'}))
        original_receipt = selected.read_bytes()
        for version in ('0.8.139', '0.10.10', '0.10.12', '0.10.13', '0.10.14'):
            self.put(f'out/USB-Link-{version}-windows-x64-local.exe')
            self.put(f'.local/deliverables/{version}/USB-Link-Setup-{version}.exe')
        self.put('out/USB-Link-0.10.10-windows-x64.exe')
        protected = [self.put('out/USB-Link-0.10.10-source.zip'),
                     self.put('.local/deliverables/0.10.10/repair-deleted-install.exe'),
                     self.put('.local/deliverables/0.10.10/USB-Link-Setup-0.10.10.manifest.json'),
                     self.put('.local/deliverables/USB-Link-reinstall-0.10.0/USB-Link-0.10.0-windows-x64.exe'),
                     self.put('.local/deliverables/0.10.10/USB-Link-Setup-0.10.9.exe')]
        result = retention.retain(self.root, '0.10.13')
        self.assertEqual(result['previous'], '0.10.12')
        self.assertEqual(len(result['files']), 3)
        self.assertTrue(all(row['removed'] and len(row['sha256']) == 64 for row in result['files']))
        self.assertTrue(all(path.exists() for path in protected))
        self.assertEqual(selected.read_bytes(), original_receipt)
        for version in ('0.8.139', '0.10.12', '0.10.13', '0.10.14'):
            self.assertTrue((self.root / f'out/USB-Link-{version}-windows-x64-local.exe').exists())

    def test_latest_public_build_counts_as_previous_and_explicit_choices_accumulate(self):
        self.put('out/installer-retention.json', '{"previous":"0.10.8","previous_selection":"selected"}')
        for version in ('0.10.8', '0.10.9', '0.10.10'):
            self.put(f'out/USB-Link-{version}-windows-x64-local.exe')
        self.put('out/USB-Link-0.10.12-windows-x64.exe')
        planned = retention.plan(self.root, '0.10.13', '0.10.9')
        self.assertEqual(planned['previous'], '0.10.12')
        self.assertEqual([p.name for p in planned['candidates']], ['USB-Link-0.10.10-windows-x64-local.exe'])

    def test_invalid_rollback_fails_without_deletion(self):
        old = self.put('out/USB-Link-0.10.10-windows-x64-local.exe')
        self.put('out/installer-retention.json', '{"previous":"../bad","previous_selection":"selected"}')
        with self.assertRaises(ValueError): retention.retain(self.root, '0.10.13')
        self.assertTrue(old.exists())

    def test_cleanup_removes_only_empty_obsolete_version_directories(self):
        for version in ('0.10.10', '0.10.12', '0.10.13'):
            self.put(f'.local/deliverables/{version}/USB-Link-Setup-{version}.exe')
        empty = self.root / '.local/deliverables/0.10.9'
        empty.mkdir()
        evidence = self.put('.local/deliverables/0.10.8/diagnostics.json')
        result = retention.retain(self.root, '0.10.13')
        self.assertFalse(empty.exists())
        self.assertFalse((self.root / '.local/deliverables/0.10.10').exists())
        self.assertTrue(evidence.exists())
        self.assertTrue((self.root / '.local/deliverables/0.10.12').exists())
        self.assertEqual(len(result['empty_directories_removed']), 2)

    @unittest.skipIf(os.name == 'nt', 'Creating symlinks may require Windows administrator rights')
    def test_redirected_roots_fail_without_deletion(self):
        old = self.put('out/USB-Link-0.10.10-windows-x64-local.exe')
        (self.root / '.local').symlink_to(self.root / 'out', target_is_directory=True)
        with self.assertRaises(ValueError): retention.retain(self.root, '0.10.13')
        self.assertTrue(old.exists())

    def test_build_audit_failure_prevents_cleanup(self):
        import project
        with patch.object(project, 'prepare', return_value='bridge'), patch.object(project, 'write_resource') as resource, \
             patch.object(project, 'go_build'), patch.object(project, 'verify_release_surface'), patch.object(project, 'verify_manifest'), patch.object(project, 'verify_icon'), \
             patch.object(project, 'retain_local_installers') as cleanup, patch.object(project, 'write_checksums'), \
             patch.object(project, 'run') as run:
            def audit_fails(args, *unused):
                if 'scripts/audit_distribution.py' in args: raise RuntimeError('audit failed')
            run.side_effect = audit_fails
            with self.assertRaisesRegex(RuntimeError, 'audit failed'): project.build('local')
            cleanup.assert_not_called()
            resource.return_value.unlink.assert_called_once()
            events = []
            run.side_effect = lambda args, *unused: events.append('audit') if '--artifact' in args else None
            cleanup.side_effect = lambda *args: events.append('cleanup')
            project.build('local')
            self.assertEqual(events, ['audit', 'cleanup'])
            cleanup.reset_mock()
            project.build('release')
            cleanup.assert_not_called()

    def test_single_artifact_audit_ignores_other_old_outputs_and_rejects_private_data(self):
        current = self.put('out/USB-Link-0.10.13-windows-x64-local.exe', 'current artifact')
        private_marker = '-----BEGIN ' + 'PRIVATE KEY-----'
        self.put('out/old.exe', private_marker)
        audit = pathlib.Path(__file__).with_name('audit_distribution.py')
        args = [sys.executable, str(audit), '--artifact', str(current)]
        good = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        current.write_text(private_marker)
        bad = subprocess.run(args, capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('private identity/credential', bad.stdout)


if __name__ == '__main__': unittest.main()
