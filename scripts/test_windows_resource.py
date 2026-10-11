#!/usr/bin/env python3
import pathlib
import struct
import unittest
import xml.etree.ElementTree as ET
from windows_resource import manifest_object

ROOT = pathlib.Path(__file__).resolve().parents[1]

class WindowsResourceTests(unittest.TestCase):
    def test_manifest_section_and_relocation(self):
        manifest = (ROOT/'cmd/ipad-usb-easy/setup.manifest').read_bytes()
        data = manifest_object(manifest)
        machine, sections, timestamp, symbols, symbol_count, optional, flags = struct.unpack_from('<HHIIIHH', data)
        self.assertEqual((machine,sections,timestamp,symbol_count,optional), (0x8664,1,0,2,0))
        section = struct.unpack_from('<8sIIIIIIHHI',data,20)
        self.assertEqual(section[0], b'.rsrc\0\0\0')
        self.assertEqual(data[section[4]+88:section[4]+88+len(manifest)],manifest)
        self.assertEqual(struct.unpack_from('<IIH',data,section[5]),(72,0,3))
        self.assertEqual(symbols, section[5]+10)
        self.assertEqual(data, manifest_object(manifest))

    def test_theme_manifest_keeps_elevation_explicit(self):
        tree=ET.fromstring((ROOT/'cmd/ipad-usb-easy/setup.manifest').read_bytes())
        identities=tree.findall('.//{urn:schemas-microsoft-com:asm.v1}assemblyIdentity')
        self.assertTrue(any(i.attrib.get('name')=='Microsoft.Windows.Common-Controls' and i.attrib.get('version')=='6.0.0.0' for i in identities))
        execution=tree.find('.//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')
        self.assertEqual(execution.attrib['level'],'asInvoker')

if __name__=='__main__': unittest.main()
