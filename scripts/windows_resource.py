#!/usr/bin/env python3
"""Deterministic amd64 COFF resource for the launcher, without external tooling."""
import pathlib, struct


def manifest_object(manifest: bytes) -> bytes:
    # RT_MANIFEST=24, CREATEPROCESS_MANIFEST_RESOURCE_ID=1, neutral language.
    directory = lambda: struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    resources = (directory() + struct.pack('<II', 24, 0x80000018)
                 + directory() + struct.pack('<II', 1, 0x80000030)
                 + directory() + struct.pack('<II', 0, 72)
                 + struct.pack('<IIII', 88, len(manifest), 65001, 0) + manifest)
    resources += bytes((-len(resources)) % 4)
    relocation_offset = 60 + len(resources)
    symbol_offset = relocation_offset + 10
    header = struct.pack('<HHIIIHH', 0x8664, 1, 0, symbol_offset, 2, 0, 0)
    section = struct.pack('<8sIIIIIIHHI', b'.rsrc\0\0\0', 0, 0, len(resources),
                          60, relocation_offset, 0, 1, 0, 0x40000040)
    relocation = struct.pack('<IIH', 72, 0, 3)  # IMAGE_REL_AMD64_ADDR32NB
    symbol = struct.pack('<8sIhHBB', b'.rsrc\0\0\0', 0, 1, 0, 3, 1)
    auxiliary = struct.pack('<IHHIhBBH', len(resources), 1, 0, 0, 0, 0, 0, 0)
    return header + section + resources + relocation + symbol + auxiliary + struct.pack('<I', 4)


def write_resource(root: pathlib.Path) -> pathlib.Path:
    target = root / 'cmd/ipad-usb-easy/zz_setup_windows_amd64.syso'
    target.write_bytes(manifest_object((root / 'cmd/ipad-usb-easy/setup.manifest').read_bytes()))
    return target


def verify_manifest(executable: pathlib.Path, expected: bytes) -> None:
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
        raise ValueError('Missing manifest resource')

    type_dir = child(0, 24)
    name_dir = child(type_dir & 0x7fffffff, 1)
    leaf = child(name_dir & 0x7fffffff, 0)
    if not type_dir & 0x80000000 or not name_dir & 0x80000000 or leaf & 0x80000000:
        raise ValueError('Invalid manifest tree')
    content, length = struct.unpack_from('<II', data, base+leaf)
    if not size or data[offset(content):offset(content)+length] != expected:
        raise ValueError('Embedded launcher manifest differs from reviewed source')
