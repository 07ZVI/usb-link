#!/usr/bin/env python3
"""Build the narrowly scoped private recovery tool; never patch public sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import shutil
import zipfile

root = Path(__file__).resolve().parents[2]
source = Path(__file__).resolve().parent
version = (root / 'VERSION').read_text().strip()
assert version.startswith('0.10.')
parser = argparse.ArgumentParser()
parser.add_argument('--installer-sha', required=True, help='SHA256 of the reviewed release installer')
parser.add_argument('--offline-components', action='store_true', help='Include pinned third-party packages for fully offline preparation; default is the small online kit')
args = parser.parse_args()
assert len(args.installer_sha) == 64 and all(c in '0123456789abcdef' for c in args.installer_sha)
destination = root / ('.local/deliverables/USB-Link-reinstall-' + version + ('' if args.offline_components else '-online'))
installer = root / ('out/USB-Link-' + version + '-windows-x64.exe')
digest = hashlib.sha256(installer.read_bytes()).hexdigest()
assert digest == args.installer_sha
if destination.exists() and any(destination.iterdir()):
    raise SystemExit('Refusing to mix an existing kit/logs with a new build; preserve or move the existing kit first.')
destination.mkdir(parents=True, exist_ok=True)
environment = os.environ.copy()
environment.update(GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOTOOLCHAIN='local')
go = environment.get('USBLINK_GO', str(root / '.local/tooling/go-1.26.0/go/bin/go'))
with tempfile.TemporaryDirectory(prefix='usb-link-deleted-repair-') as tmp:
    overlay = Path(tmp) / 'overlay.json'
    virtual = root / 'internal/app/connectioninstall/deleted_install_private_windows.go'
    assert not virtual.exists()
    overlay.write_text(json.dumps({'Replace': {str(virtual): str(source / 'connectioninstall_windows.go.txt')}}))
    subprocess.run([go, 'vet', '-tags=usblink_operator_repair', '-overlay', str(overlay), './scripts/windows-deleted-install-repair', './internal/app/connectioninstall'], cwd=root, env=environment, check=True)
    subprocess.run([go, 'build', '-tags=usblink_operator_repair', '-overlay', str(overlay), '-trimpath', '-buildvcs=false', '-ldflags', '-s -w -X main.installerSHA=' + digest + ' -X main.installerVersion=' + version, '-o', str(destination / 'repair-deleted-install.exe'), './scripts/windows-deleted-install-repair'], cwd=root, env=environment, check=True)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

shutil.copy2(installer, destination / installer.name)
pins = {'@VERSION@': version, '@REPAIR_SHA@': sha(destination / 'repair-deleted-install.exe'), '@INSTALLER_SHA@': digest}
if args.offline_components:
    shutil.copytree(root / 'offline-components', destination / 'offline-components', ignore=shutil.ignore_patterns('logs', '__pycache__', '.DS_Store'))
    pins['@COMPONENT_PIN@'] = "        'offline-components\\install_all.bat' = '" + sha(destination / 'offline-components/install_all.bat').upper() + "'"
    pins['@COMPONENT_PREPARE@'] = """    Write-Host 'Verifying local/offline components; existing verified components are reused.'
    Write-Host 'If official Apple setup opens, finish its wizard. No device is force-bound.'
    & (Join-Path $PSScriptRoot 'offline-components\\install_all.bat') --no-pause
    if ($LASTEXITCODE -eq 0) { & $repair --prepare-components }"""
else:
    pins['@COMPONENT_PIN@'] = ''
    pins['@COMPONENT_PREPARE@'] = """    Write-Host 'Reusing verified .NET/Wintun; missing components download from pinned official sources.'
    Write-Host 'Keep Windows online if a required component is missing. No third-party packages are bundled.'
    & $repair --prepare-components"""
script = (source / 'repair-and-install.ps1.in').read_text()
for placeholder, value in pins.items():
    script = script.replace(placeholder, value)
assert all(placeholder not in script for placeholder in pins)
(destination / 'repair-and-install.ps1').write_bytes(script.replace('\n', '\r\n').encode('utf-8-sig'))
batch = '''@echo off
setlocal
set "KIT_POWERSHELL=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
if exist "%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" set "KIT_POWERSHELL=%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"
"%KIT_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0repair-and-install.ps1"
set "KIT_EXIT=%ERRORLEVEL%"
echo.
if "%KIT_EXIT%"=="0" (echo Core installation verified. USB/SMB device acceptance is still required.) else (echo Not verified. Return the logs folder. Exit code: %KIT_EXIT%)
pause
exit /b %KIT_EXIT%
'''
(destination / 'repair-and-install.bat').write_bytes(batch.replace('\n', '\r\n').encode('ascii'))
component_instructions = ('已有效的组件会复用；缺少的组件使用离线包准备。若出现 Apple 官方安装向导，按向导完成。' if args.offline_components else '不附带第三方安装包。先复用通过校验的 .NET／Wintun，缺失时从固定的官方来源下载；缺组件时请保持 Windows 联网。Apple 通信组件按连接设备需要由主程序提示。')
(destination / '使用说明.txt').write_bytes('''USB Link @VERSION@ 删除安装目录后的专用修复包（@MODE@）

1. 完整解压并将整个文件夹复制到 Windows，或从 U 盘直接运行。
2. 双击 repair-and-install.bat，允许管理员提示。不要单独运行目录内的 EXE。
3. @COMPONENT_INSTRUCTIONS@
4. 工具只核对并处理已删除目录的 0.8.139 安装登记和停止的 0.9.3 服务，先保存备份。
5. 等待窗口的核验结果。程序打开不等于 USB 或共享已验收。
6. 保留这个文件夹及 logs。完成后接回 Mac/iPad 检查连接；失败时把 logs 文件夹带回 Mac。

不会由本工具删除已有账户、共享资料、驱动、网络规则或 Windows Temp 中的恢复记录。
如果目标状态已改变，工具会停止，不覆盖其他安装或运行中的服务。
原始残留备份：ProgramData/USB Link/DeletedInstallRecovery/。
这次手动删除的密码/权限凭据可能已丢失，因此不自动重置原 SMB 账户。
'''.replace('@VERSION@', version).replace('@MODE@', '离线完整包' if args.offline_components else '精简联网包').replace('@COMPONENT_INSTRUCTIONS@', component_instructions).replace('\n', '\r\n').encode('utf-8-sig'))
receipt = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()),
    'version': version, 'expected_registration': '0.8.139', 'expected_stopped_service': '0.9.3',
    'installer_sha256': digest, 'helper_sha256': pins['@REPAIR_SHA@'],
    'validation': 'Windows x64 cross-build and native vet passed; Windows execution and device acceptance pending',
    'private_build_tag': 'usblink_operator_repair',
    'component_mode': 'offline' if args.offline_components else 'online-reuse-or-download',
    'repair_sources': {p.name: sha(p) for p in sorted(source.iterdir()) if p.is_file()},
}
(destination / 'BUILD-RECEIPT.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n')
files = sorted(p for p in destination.rglob('*') if p.is_file() and 'logs' not in p.relative_to(destination).parts and p != destination / 'SHA256SUMS.txt')
(destination / 'SHA256SUMS.txt').write_text(''.join(sha(p) + '  ' + p.relative_to(destination).as_posix() + '\n' for p in files))
files.append(destination / 'SHA256SUMS.txt')
archive = destination.parent / (destination.name + '.zip')
temporary = archive.with_suffix('.zip.tmp')
with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for p in sorted(files):
        z.write(p, destination.name + '/' + p.relative_to(destination).as_posix())
with zipfile.ZipFile(temporary) as z:
    assert z.testzip() is None
    assert len(z.namelist()) == len(files)
    for p in files:
        assert hashlib.sha256(z.read(destination.name + '/' + p.relative_to(destination).as_posix())).hexdigest() == sha(p)
temporary.replace(archive)
print(json.dumps({'kit': str(destination), 'files_checked': len(files), 'zip_bytes': archive.stat().st_size, 'helper_sha256': pins['@REPAIR_SHA@']}))
