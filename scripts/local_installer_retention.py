"""Retain local installer builds without touching public release retention."""
import hashlib
import json
import pathlib
import re

VERSION = re.compile(r'\d+\.\d+\.\d+')
OUTPUT = re.compile(r'USB-Link-(\d+\.\d+\.\d+)-windows-x64(-local)?\.exe')


def version_key(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Installer retention requires an exact numeric version')
    return tuple(map(int, version.split('.')))


def plan(root, current, rollback=None):
    root = pathlib.Path(root)
    current_key = version_key(current)
    out = root / 'out'
    deliveries = root / '.local' / 'deliverables'
    for directory in (out, root / '.local', deliveries):
        if directory.is_symlink():
            raise ValueError('Refusing redirected installer directory')
    selected = set()
    if rollback is not None:
        version_key(rollback)
        selected.add(rollback)
    receipt = out / 'installer-retention.json'
    if receipt.is_symlink():
        raise ValueError('Refusing redirected rollback receipt')
    if receipt.exists():
        saved = json.loads(receipt.read_text(encoding='utf-8'))
        if saved.get('previous_selection') == 'selected':
            version_key(saved.get('previous'))
            selected.add(saved['previous'])
    known = set()
    candidates = []
    if out.is_dir():
        for path in out.iterdir():
            match = OUTPUT.fullmatch(path.name)
            if match and path.is_file() and not path.is_symlink():
                known.add(match[1])
                candidates.append((match[1], path))
    if deliveries.is_dir():
        for directory in deliveries.iterdir():
            if not VERSION.fullmatch(directory.name) or directory.is_symlink() or not directory.is_dir():
                continue
            version = directory.name
            # Never recurse into repair kits, tools, or historical deliveries.
            names = {f'USB-Link-Setup-{version}{suffix}.exe' for suffix in ('', '-local')}
            names |= {f'USB-Link-{version}-windows-x64{suffix}.exe' for suffix in ('', '-local')}
            for path in directory.iterdir():
                if path.name in names and path.is_file() and not path.is_symlink():
                    known.add(version)
                    candidates.append((version, path))
    previous = max((v for v in known if version_key(v) < current_key), key=version_key, default=None)
    keep = selected | {current, previous}
    return {
        'current': current, 'previous': previous, 'selected_rollbacks': sorted(selected, key=version_key),
        'candidates': [path for version, path in sorted(candidates) if version not in keep and version_key(version) < current_key],
    }


def retain(root, current, rollback=None):
    root = pathlib.Path(root)
    planned = plan(root, current, rollback)
    receipt = root / 'out' / 'local-installer-retention.json'
    if receipt.is_symlink():
        raise ValueError('Refusing redirected local retention receipt')
    rows = []
    for path in planned.pop('candidates'):
        rows.append({'path': path.relative_to(root).as_posix(), 'bytes': path.stat().st_size,
                     'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'removed': False})
    result = {**planned, 'files': rows, 'empty_directories_removed': []}
    # Keep a receipt even if a later removal fails; never advance the selected rollback.
    def save():
        receipt.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    save()
    for row in rows:
        path = root / row['path']
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
            raise ValueError('Installer path redirected during cleanup')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('Installer changed during cleanup')
        path.unlink()
        row['removed'] = True
        save()
    deliveries = root / '.local' / 'deliverables'
    keep = {current, planned['previous'], *planned['selected_rollbacks']}
    if deliveries.is_dir() and not deliveries.is_symlink():
        for directory in sorted(deliveries.iterdir()):
            if (not VERSION.fullmatch(directory.name) or directory.name in keep
                    or version_key(directory.name) >= version_key(current)
                    or directory.is_symlink() or not directory.is_dir()):
                continue
            # rmdir only removes empty directories; preserve evidence and unknown files.
            if any(directory.iterdir()):
                continue
            directory.rmdir()
            result['empty_directories_removed'].append(directory.relative_to(root).as_posix())
            save()
    print(f'Local installer retention: current={current}, previous={planned["previous"]}; removed {len(rows)} installers.', flush=True)
    return result
