#!/usr/bin/env python3
import pathlib
import struct
import unittest
import xml.etree.ElementTree as ET
from windows_resource import manifest_object, icon_resources

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

    def test_launcher_icon_payloads_and_relocations(self):
        icon=(ROOT/'desktop/Assets/usb-link.ico').read_bytes()
        resources=icon_resources(icon)
        group=resources[(14,1,0)]
        count=struct.unpack_from('<H',group,4)[0]
        self.assertEqual(count,15)
        sizes=set()
        for i in range(count):
            width,height,_,_,planes,bits,length,identity=struct.unpack_from('<BBBBHHIH',group,6+i*14)
            sizes.add(width or 256)
            image=resources[(3,identity,0)]
            self.assertEqual(len(image),length)
            self.assertEqual(image[:8],b'\x89PNG\r\n\x1a\n')
            self.assertEqual(struct.unpack_from('>II',image,16),(width or 256,height or 256))
            self.assertEqual((planes,bits),(1,32))
        self.assertTrue({16,20,24,30,32,36,40,48,60,64,72,80,96,128,256} <= sizes)
        data=manifest_object(b'<manifest/>',icon)
        section=struct.unpack_from('<8sIIIIIIHHI',data,20)
        self.assertEqual(section[7],count+2)
        for i in range(section[7]):
            offset,symbol,kind=struct.unpack_from('<IIH',data,section[5]+10*i)
            self.assertEqual((symbol,kind),(0,3))
            address,length=struct.unpack_from('<II',data,section[4]+offset)
            self.assertLessEqual(address+length,section[3])
        with self.assertRaises(ValueError):icon_resources(icon[:30])

    def test_theme_manifest_keeps_elevation_explicit(self):
        tree=ET.fromstring((ROOT/'cmd/ipad-usb-easy/setup.manifest').read_bytes())
        identities=tree.findall('.//{urn:schemas-microsoft-com:asm.v1}assemblyIdentity')
        self.assertTrue(any(i.attrib.get('name')=='Microsoft.Windows.Common-Controls' and i.attrib.get('version')=='6.0.0.0' for i in identities))
        execution=tree.find('.//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')
        self.assertEqual(execution.attrib['level'],'asInvoker')

if __name__=='__main__': unittest.main()
