#!/usr/bin/env python3
"""Check build isolation without generating installers or touching output."""
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import project


class BuildProfileTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(project, 'local_publisher_flags', return_value='')
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_final_binary_and_symbol_twin_use_identical_explicit_tags(self):
        for profile, expected in [('local', '-tags=usblink_local_remote'), ('release', '-tags=')]:
            with self.subTest(profile=profile), patch.object(project, 'run') as run, patch.object(
                    project.subprocess, 'check_output', return_value=''):
                project.go_build('./cmd/ipad-usb-easy', Path('unused.exe'), profile=profile)
                project.verify_release_surface('synthetic-bridge-hash', profile)
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(len(commands), 2)
                for command in commands:
                    self.assertEqual([arg for arg in command if str(arg).startswith('-tags=')], [expected])

    def test_local_allows_server_but_public_rejects_it(self):
        for symbol in ('remoteupdate.(*Server).ServeHTTP', 'connectioninstall.LaunchLocalRemoteElevation',
                       'connectioninstall.DispatchLocalRemoteInstall', 'connectioninstall.RunLocalRemoteInstall',
                       'launcher.handleLocalRemoteCommand', 'ipadncm.applyPhotoPolicy', 'ipadncm.(*localDirectRun).prepare', 'ipadncm.(*directNetworkTarget).mapping'):
            with self.subTest(symbol=symbol), patch.object(project, 'run'), patch.object(project.subprocess, 'check_output',
                    return_value='suhang/usbnet/internal/app/'+symbol):
                project.verify_release_surface('synthetic-bridge-hash', 'local')
                with self.assertRaisesRegex(RuntimeError, 'Forbidden release'):
                    project.verify_release_surface('synthetic-bridge-hash', 'release')

    def test_removed_handlers_and_old_worker_are_forbidden_in_both_profiles(self):
        for profile in ('local', 'release'):
            for symbol in ('connectioninstall.RunUpdateWorker', 'usbrecovery.Run',
                           'filedrop.Handler', 'webdav.(*Handler).ServeHTTP'):
                with self.subTest(profile=profile, symbol=symbol), patch.object(project, 'run'), patch.object(
                        project.subprocess, 'check_output', return_value=symbol):
                    with self.assertRaisesRegex(RuntimeError, 'Forbidden '+profile):
                        project.verify_release_surface('synthetic-bridge-hash', profile)

    def test_session_isolation_is_an_ordinary_network_feature(self):
        for profile in ('local', 'release'):
            for symbol in ('ipadncm.(*localPhotoNativeBackend).disable',
                           'ipadncm.(*localAMDSHoldNative).start'):
                with self.subTest(profile=profile, symbol=symbol), patch.object(project, 'run'), patch.object(
                        project.subprocess, 'check_output', return_value=symbol):
                    project.verify_release_surface('synthetic-bridge-hash', profile)

    def test_unknown_profile_fails_before_build(self):
        with patch.object(project, 'run') as run:
            with self.assertRaises(ValueError):
                project.go_build('./cmd/ipad-usb-easy', Path('unused.exe'), profile='typo')
            run.assert_not_called()

    def test_native_metadata_observers_are_local_only(self):
        symbols = ('deviceguard.SubscribeAppleChangeMetadata',
                   'deviceguard.(*ChangeMetadataStream).offer')
        for symbol in symbols:
            with self.subTest(symbol=symbol), patch.object(project, 'run'), patch.object(
                    project.subprocess, 'check_output', return_value=symbol):
                project.verify_release_surface('synthetic-bridge-hash', 'local')
                with self.assertRaisesRegex(RuntimeError, 'Forbidden release'):
                    project.verify_release_surface('synthetic-bridge-hash', 'release')

    def test_go_file_selection_ignores_inherited_tags_and_restricts_platform(self):
        go = shutil.which(project.GO)
        if not go:
            self.skipTest('Go unavailable; set USBLINK_GO to run real build-tag selection')
        for system, arch, profile, enabled in [
                ('windows', 'amd64', 'local', True),
                ('windows', 'amd64', 'release', False),
                ('windows', 'arm64', 'local', False),
                ('darwin', 'amd64', 'local', False)]:
            with self.subTest(system=system, arch=arch, profile=profile):
                env = {**project.ENV, 'GOOS': system, 'GOARCH': arch, 'CGO_ENABLED': '0',
                       'GOFLAGS': '-tags=usblink_local_remote'}
                selected = json.loads(subprocess.check_output(
                    [go, 'list', project.profile_tags(profile), '-json', './internal/buildinfo'],
                    cwd=project.ROOT, env=env, text=True))['GoFiles']
                self.assertEqual('local_remote_enabled.go' in selected, enabled)
                self.assertEqual('local_remote_disabled.go' in selected, not enabled)


if __name__ == '__main__':
    unittest.main()
