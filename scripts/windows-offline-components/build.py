#!/usr/bin/env python3
"""Build a private, flat offline bundle: one BAT and five original packages."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent
KIT = ROOT / 'offline-components'
EVIDENCE = ROOT / '.local/evidence/offline-components-flat-layout'
CATALOG = json.loads((ROOT / 'internal/dependencies/catalog.json').read_text())
VERSION = (ROOT / 'VERSION').read_text().strip()
BOOTSTRAP = "$text=[IO.File]::ReadAllText($env:KIT_SCRIPT); $parts=$text.Split([string[]]@(('::'+'USB-LINK-PS'),('::'+'USB-LINK-HELPER')),[StringSplitOptions]::None); if($parts.Length -ne 3){throw 'Incomplete install_all.bat'}; & ([ScriptBlock]::Create($parts[1]))"


def digest(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(folder):
    result = {}
    for p in sorted(folder.rglob('*')):
        if p.is_symlink():
            raise RuntimeError('Redirected bundle path: ' + str(p))
        if p.is_file():
            result[p.relative_to(folder).as_posix()] = {'bytes': p.stat().st_size, 'sha256': digest(p)}
    return result


def build():
    assert KIT.is_dir() and not KIT.is_symlink()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    before = inventory(KIT)
    assets = CATALOG['assets']
    inputs = {}
    for asset in assets:
        name = asset['url'].rsplit('/', 1)[1]
        p = KIT / name
        if not p.exists():
            p = KIT / 'packages' / name
        assert p.is_file() and not p.is_symlink() and p.stat().st_size <= asset['max_bytes'], name
        assert digest(p, asset['algorithm']) == asset['digest'], name
        inputs[name] = p
    assert len(inputs) == 5
    allowed = set(inputs) | {'install_all.bat', 'BUILD-RECEIPT.json', 'SHA256SUMS.txt', '.DS_Store', 'bootstrap.ps1', 'catalog.json', 'download.py', 'inspect-install.bat', 'inspect-install.ps1', 'install-mac-only.bat', 'install.bat', 'prepare-components.exe', 'verify-only.bat', '使用说明.md', 'src', 'packages'}
    assert all(p.name in allowed for p in KIT.iterdir()), 'Unknown files in kit; preserve them before reorganizing.'
    allowed_files = (allowed - {'src', 'packages'}) | {'src/main.go'} | {'packages/' + name for name in inputs}
    assert set(before) <= allowed_files, 'Unknown nested files in kit; nothing replaced.'
    assert all(p.relative_to(KIT).as_posix() in {'src', 'packages'} for p in KIT.rglob('*') if p.is_dir()), 'Unknown nested directory in kit.'
    if (KIT / 'prepare-components.exe').exists():
        old_receipt = json.loads((KIT / 'BUILD-RECEIPT.json').read_text())
        assert digest(KIT / 'prepare-components.exe') == old_receipt['helper_sha256'], 'Changed legacy helper must be preserved before rebuilding.'
    # Preserve the original editable support files outside the user-facing kit.
    for relative in before:
        p = KIT / relative
        if p.suffix == '.exe' or p.name == '.DS_Store' or p.name in inputs:
            continue
        target = EVIDENCE / 'previous-support-files' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, target)
    (EVIDENCE / 'before.json').write_text(json.dumps(before, ensure_ascii=False, indent=2) + '\n')
    env = os.environ.copy()
    env.update(GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOTOOLCHAIN='local')
    go = env.get('USBLINK_GO', str(ROOT / '.local/tooling/go-1.26.0/go/bin/go'))
    with tempfile.TemporaryDirectory(prefix='build-', dir=EVIDENCE) as temporary:
        stage = Path(temporary) / 'flat'
        stage.mkdir()
        helper = Path(temporary) / 'prepare-components.exe'
        subprocess.run([go, 'vet', '-tags=usblink_offline_components', './scripts/windows-offline-components', './internal/app/connectioninstall'], cwd=ROOT, env=env, check=True)
        subprocess.run([go, 'build', '-tags=usblink_offline_components', '-trimpath', '-buildvcs=false', '-ldflags', '-s -w -X main.bundleVersion=' + VERSION, '-o', str(helper), './scripts/windows-offline-components'], cwd=ROOT, env=env, check=True)
        helper_sha = digest(helper)
        powershell = (SOURCE / 'install.ps1.in').read_text().replace('@HELPER_SHA@', helper_sha.upper()).replace('@BOOTSTRAP_COMMAND@', BOOTSTRAP.replace("'", "''"))
        assert '@HELPER_SHA@' not in powershell and '@BOOTSTRAP_COMMAND@' not in powershell
        encoded = base64.b64encode(gzip.compress(helper.read_bytes(), compresslevel=9, mtime=0)).decode('ascii')
        encoded = '\n'.join(encoded[i:i + 120] for i in range(0, len(encoded), 120))
        header = '''@echo off
setlocal
chcp 65001 >nul
set "KIT_SCRIPT=%~f0"
set "KIT_POWERSHELL=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
if exist "%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" set "KIT_POWERSHELL=%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"
"%KIT_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -Command "@COMMAND@"
set "KIT_EXIT=%ERRORLEVEL%"
if /I not "%~1"=="--no-pause" pause
exit /b %KIT_EXIT%
::USB-LINK-PS
'''.replace('@COMMAND@', BOOTSTRAP)
        bat = (header + powershell + '\n::USB-LINK-HELPER\n' + encoded + '\n').replace('\n', '\r\n')
        (stage / 'install_all.bat').write_bytes(bat.encode('utf-8'))
        for name, path in inputs.items():
            shutil.copy2(path, stage / name)
        # Decode the final BAT exactly as the runtime does, and independently
        # verify its helper, package hashes and ZIP before publishing the folder.
        parts = bat.split('::USB-LINK-PS')
        assert len(parts) == 2 and 'exit /b %KIT_EXIT%' in parts[0]
        payload = parts[1].split('::USB-LINK-HELPER')
        assert len(payload) == 2
        assert hashlib.sha256(gzip.decompress(base64.b64decode(payload[1]))).hexdigest() == helper_sha
        for asset in assets:
            name = asset['url'].rsplit('/', 1)[1]
            assert digest(stage / name, asset['algorithm']) == asset['digest']
        after = inventory(stage)
        assert len(after) == 6
        archive = ROOT / 'USB-Link-offline-components-windows-x64.zip'
        pending_archive = Path(temporary) / archive.name
        with zipfile.ZipFile(pending_archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(stage.iterdir()):
                z.write(p, 'offline-components/' + p.name)
        with zipfile.ZipFile(pending_archive) as z:
            assert z.testzip() is None and len(z.namelist()) == 6
            for name, metadata in after.items():
                assert hashlib.sha256(z.read('offline-components/' + name)).hexdigest() == metadata['sha256']
        assert inventory(KIT) == before, 'Source folder changed during build; nothing replaced.'
        old = Path(temporary) / 'previous'
        KIT.rename(old)
        try:
            stage.rename(KIT)
        except BaseException:
            old.rename(KIT)
            raise
        assert inventory(old) == before
        pending_archive.replace(archive)
        receipt = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()), 'version': VERSION, 'target': 'windows/amd64', 'layout': 'one BAT and five original packages; no subfolders', 'helper_sha256': helper_sha, 'files': after, 'archive_sha256': digest(archive), 'zip_bytes': archive.stat().st_size, 'validation': 'Official package hashes, embedded-helper readback, Windows cross-build/vet and ZIP checked; Windows execution pending'}
        (EVIDENCE / 'BUILD-RECEIPT.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'folder': str(KIT), 'files': list(after), 'bat_bytes': after['install_all.bat']['bytes'], 'zip_bytes': archive.stat().st_size, 'helper_sha256': helper_sha}, ensure_ascii=False))


if __name__ == '__main__':
    build()
