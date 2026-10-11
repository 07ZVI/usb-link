#!/usr/bin/env python3
"""Package a plain sequential BAT with five unmodified official downloads."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent
KIT = ROOT / 'offline-components'
EVIDENCE = ROOT / '.local/evidence/offline-components-simple'


def digest(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(folder):
    assert folder.is_dir() and not folder.is_symlink()
    assert all(p.is_file() and not p.is_symlink() for p in folder.iterdir())
    return {p.name: {'bytes': p.stat().st_size, 'sha256': digest(p)} for p in sorted(folder.iterdir())}


def build():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    before = inventory(KIT)
    assets = json.loads((SOURCE / 'packages.json').read_text())['assets']
    allowed = {'install_all.bat', '.DS_Store', 'dotnet-runtime-10.0.12-win-x64.zip'} | {a['url'].rsplit('/', 1)[1] for a in assets}
    assert set(before) <= allowed, 'Unknown files in bundle; nothing replaced.'
    with tempfile.TemporaryDirectory(prefix='build-', dir=EVIDENCE) as temp:
        stage = Path(temp) / 'flat'
        stage.mkdir()
        shutil.copy2(SOURCE / 'install_all.bat', stage / 'install_all.bat')
        assert (stage / 'install_all.bat').stat().st_size < 8192
        for a in assets:
            name = a['url'].rsplit('/', 1)[1]
            src = KIT / name
            if not src.exists():
                src = EVIDENCE / name
            assert src.is_file() and not src.is_symlink() and src.stat().st_size <= a['max_bytes'], name
            assert digest(src, a['algorithm']) == a['digest'], name
            shutil.copy2(src, stage / name)
        after = inventory(stage)
        assert len(after) == 6
        archive = ROOT / 'USB-Link-offline-components-windows-x64.zip'
        pending = Path(temp) / archive.name
        with zipfile.ZipFile(pending, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(stage.iterdir()):
                z.write(p, 'offline-components/' + p.name)
        with zipfile.ZipFile(pending) as z:
            assert z.testzip() is None and len(z.namelist()) == 6
            for name, info in after.items():
                assert hashlib.sha256(z.read('offline-components/' + name)).hexdigest() == info['sha256']
        assert inventory(KIT) == before, 'Bundle changed during packaging.'
        previous = Path(temp) / 'previous'
        KIT.rename(previous)
        try:
            stage.rename(KIT)
        except BaseException:
            previous.rename(KIT)
            raise
        assert inventory(previous) == before
        pending.replace(archive)
        receipt = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()), 'version': (ROOT / 'VERSION').read_text().strip(), 'layout': 'one plain BAT and five original packages', 'before': before, 'files': after, 'zip_bytes': archive.stat().st_size, 'archive_sha256': digest(archive), 'validation': 'All official hashes and ZIP checked; Windows installation execution pending'}
        (EVIDENCE / 'BUILD-RECEIPT.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'folder': str(KIT), 'files': list(after), 'bat_bytes': after['install_all.bat']['bytes'], 'zip_bytes': archive.stat().st_size}, ensure_ascii=False))


if __name__ == '__main__':
    build()
