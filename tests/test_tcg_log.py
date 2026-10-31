"""Offline malformed measured-boot data and independent EFI hash ranges."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from tcg_log import parse,efi_measurement


def boot_log(*events):
    spec=b'Spec ID Event03\0'+struct.pack('<IBBBBIHHB',0,0,2,0,2,1,11,32,0)
    return struct.pack('<II20sI',0,3,bytes(20),len(spec))+spec+b''.join(events)


def event(payload=b'',pcr=4,kind=0x80000003):
    return struct.pack('<IIIH32sI',pcr,kind,1,11,bytes(32),len(payload))+payload


def efi():
    b=bytearray(1024);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    struct.pack_into('<HH',b,132,0x8664,1);struct.pack_into('<H',b,148,240)
    struct.pack_into('<H',b,152,0x20b);struct.pack_into('<I',b,212,512)
    struct.pack_into('<H',b,220,10);struct.pack_into('<I',b,260,16)
    struct.pack_into('<II',b,408,512,512);b[512:]=bytes(range(256))*2
    return b


class TcgTests(unittest.TestCase):
    def test_valid_image(self):
        path=b'\x7f\xff\x04\x00'
        r=parse(boot_log(event(struct.pack('<4Q',0x1234,100,0x140000000,len(path))+path)))
        self.assertTrue(r['complete']);self.assertEqual(r['events'][0]['image']['size'],100)

    def test_truncations(self):
        data=boot_log(event(struct.pack('<4Q',0,0,0,4)+b'\x7f\xff\x04\x00'))
        header=len(boot_log())
        for n in range(len(data)):
            if n==header:continue # a complete SpecID-only log has zero events
            with self.subTest(n=n),self.assertRaises(ValueError):parse(data[:n])

    def test_invalid_algorithm_and_event_geometry(self):
        d=bytearray(boot_log());struct.pack_into('<H',d,62,31)
        with self.assertRaises(ValueError):parse(d)
        for d in [boot_log(event(pcr=24)),boot_log(event(b'x')),
                  boot_log(event(struct.pack('<4Q',0,0,0,5)+b'\x7f\xff\x04\x00'))]:
            with self.subTest(d=d),self.assertRaises(ValueError):parse(d)

    def test_independent_authenticode_ranges(self):
        b=efi();expected=hashlib.sha256(b[:216]+b[220:296]+b[304:]).hexdigest()
        self.assertEqual(efi_measurement(b)['sha256'],expected)
        checksum=bytearray(b);checksum[216:220]=b'abcd'
        self.assertEqual(efi_measurement(checksum),efi_measurement(b))
        b[700]^=1;self.assertNotEqual(efi_measurement(b)['sha256'],expected)

    def test_unsupported_or_malformed_pe(self):
        for where,value,fmt in [(296,1,'I'),(408,511,'I'),(412,511,'I'),(132,0x14c,'H'),(220,3,'H'),(260,4,'I')]:
            b=efi();struct.pack_into('<'+fmt,b,where,value)
            with self.subTest(where=where),self.assertRaises(ValueError):efi_measurement(b)
        with self.assertRaises(ValueError):efi_measurement(efi()+b'x')
        with self.assertRaises(ValueError):efi_measurement(efi()[:-1])


if __name__=='__main__':unittest.main()
