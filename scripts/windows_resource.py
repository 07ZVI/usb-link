#!/usr/bin/env python3
"""Deterministic amd64 COFF resource for the launcher, without external tooling."""
import pathlib, struct


def resource_object(items: dict) -> bytes:
    """Numeric type/name/language resource tree with one relocation per payload."""
    tree = {}
    for (kind, name, language), content in sorted(items.items()):
        tree.setdefault(kind, {}).setdefault(name, {})[language] = content
    resources = bytearray()
    leaves = []

    def directory(children):
        start = len(resources)
        resources.extend(struct.pack('<IIHHHH', 0, 0, 0, 0, 0, len(children)))
        resources.extend(bytes(8 * len(children)))
        for i, (identity, child) in enumerate(sorted(children.items())):
            if isinstance(child, dict):
                target = directory(child) | 0x80000000
            else:
                target = len(resources)
                resources.extend(bytes(16))
                leaves.append((target, child))
            struct.pack_into('<II', resources, start+16+i*8, identity, target)
        return start

    directory(tree)
    for entry, content in leaves:
        resources.extend(bytes((-len(resources)) % 4))
        struct.pack_into('<IIII', resources, entry, len(resources), len(content), 0, 0)
        resources.extend(content)
    resources.extend(bytes((-len(resources)) % 4))
    relocation_offset = 60 + len(resources)
    symbol_offset = relocation_offset + 10 * len(leaves)
    header = struct.pack('<HHIIIHH', 0x8664, 1, 0, symbol_offset, 2, 0, 0)
    section = struct.pack('<8sIIIIIIHHI', b'.rsrc\0\0\0', 0, 0, len(resources),
                          60, relocation_offset, 0, len(leaves), 0, 0x40000040)
    relocations = b''.join(struct.pack('<IIH', entry, 0, 3) for entry, _ in leaves)
    symbol = struct.pack('<8sIhHBB', b'.rsrc\0\0\0', 0, 1, 0, 3, 1)
    auxiliary = struct.pack('<IHHIhBBH', len(resources), len(leaves), 0, 0, 0, 0, 0, 0)
    return header + section + resources + relocations + symbol + auxiliary + struct.pack('<I', 4)


def icon_resources(icon: bytes) -> dict:
    if len(icon) < 6:
        raise ValueError('Truncated ICO header')
    reserved, kind, count = struct.unpack_from('<HHH', icon)
    if reserved != 0 or kind != 1 or not 1 <= count <= 64 or len(icon) < 6+16*count:
        raise ValueError('Invalid ICO directory')
    entries = []
    resources = {}
    for i in range(count):
        width, height, colors, reserved, planes, bits, length, offset = struct.unpack_from('<BBBBHHII', icon, 6+16*i)
        if reserved or not length or offset < 6+16*count or offset+length > len(icon):
            raise ValueError('Invalid ICO image extent')
        entries.append(struct.pack('<BBBBHHIH', width, height, colors, 0, planes, bits, length, i+1))
        resources[(3, i+1, 0)] = icon[offset:offset+length]  # RT_ICON
    resources[(14, 1, 0)] = struct.pack('<HHH', 0, 1, count) + b''.join(entries)  # RT_GROUP_ICON
    return resources


def manifest_object(manifest: bytes, icon=None) -> bytes:
    resources = {(24, 1, 0): manifest}
    if icon is not None:
        resources.update(icon_resources(icon))
    return resource_object(resources)


def write_resource(root: pathlib.Path) -> pathlib.Path:
    target = root / 'cmd/ipad-usb-easy/zz_setup_windows_amd64.syso'
    target.write_bytes(manifest_object((root / 'cmd/ipad-usb-easy/setup.manifest').read_bytes(), (root / 'desktop/Assets/usb-link.ico').read_bytes()))
    return target


def read_pe_resource(executable: pathlib.Path, resource_type: int, resource_id: int) -> bytes:
    """Follow the PE resource tree, rather than searching incidental byte copies."""
    data = executable.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('Not a PE executable')
    count, optional_size = struct.unpack_from('<H', data, pe+6)[0], struct.unpack_from('<H', data, pe+20)[0]
    optional = pe+24
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('Not an amd64 PE32+ launcher')
    rva, size = struct.unpack_from('<II', data, optional+112+2*8)
    sections = optional+optional_size

    def offset(address):
        for i in range(count):
            vsize, virtual, rawsize, raw = struct.unpack_from('<IIII', data, sections+i*40+8)
            if virtual <= address < virtual+max(vsize, rawsize):
                return raw+address-virtual
        raise ValueError('Unmapped resource RVA')

    base = offset(rva)
    def child(directory, identity):
        named, entries = struct.unpack_from('<HH', data, base+directory+12)
        for i in range(named+entries):
            name, target = struct.unpack_from('<II', data, base+directory+16+i*8)
            if name == identity:
                return target
        raise ValueError(f'Missing resource {resource_type}/{resource_id}/{identity}')

    type_dir = child(0, resource_type)
    name_dir = child(type_dir & 0x7fffffff, resource_id)
    leaf = child(name_dir & 0x7fffffff, 0)
    if not type_dir & 0x80000000 or not name_dir & 0x80000000 or leaf & 0x80000000:
        raise ValueError('Invalid manifest tree')
    content, length = struct.unpack_from('<II', data, base+leaf)
    if not size:
        raise ValueError('Empty PE resources')
    return data[offset(content):offset(content)+length]


def verify_manifest(executable: pathlib.Path, expected: bytes) -> None:
    if read_pe_resource(executable, 24, 1) != expected:
        raise ValueError('Embedded launcher manifest differs from reviewed source')


def verify_icon(executable: pathlib.Path, expected: bytes, group_id: int = 1) -> None:
    for (kind, identity, _), content in icon_resources(expected).items():
        if read_pe_resource(executable, kind, group_id if kind == 14 else identity) != content:
            raise ValueError('Embedded launcher icon differs from reviewed source')
