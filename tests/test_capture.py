import struct
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from review_capture import records,pci_status,review,signature_fuses


class CaptureTests(unittest.TestCase):
    def test_sec2_fuse_is_not_the_gsp_ucode3_fuse(self):
        result,blockers=signature_fuses({0x8241c8:1,0x8241e0:1})
        self.assertFalse(result['booter_sec2_ucode3']['observed'])
        self.assertEqual(result['fwsec_gsp_ucode9']['version'],1)
        self.assertTrue(any('0x824148' in b for b in blockers))
        for raw,version in ((0,0),(1,1),(3,2)):
            result,blockers=signature_fuses({0x824148:raw,0x8241e0:1})
            self.assertEqual(result['booter_sec2_ucode3']['version'],version)
            self.assertEqual(bool(blockers),version>=2)
        for raw in (0xffffffff,0xbadf5040):
            result,blockers=signature_fuses({0x824148:raw,0x8241e0:1})
            self.assertFalse(result['booter_sec2_ucode3']['supported'])
            self.assertIsNone(result['booter_sec2_ucode3']['version'])
    def pci(self):
        b=bytearray(256);struct.pack_into('<I',b,0,0x270410de);struct.pack_into('<I',b,0x2c,0x15007377)
        struct.pack_into('<H',b,6,0x10);b[0x34]=0x40;b[0x40:0x42]=bytes([1,0x50]);b[0x50]=0x10
        struct.pack_into('<I',b,0x54,1<<28)
        return b

    def test_binary_records_and_truncation(self):
        raw=b'device_path=0x0000000000000004\r\ndata_le=0x000000000000ff7f\r\n'
        self.assertEqual(records(raw),[('device_path',b'\x7f\xff\0\0')])
        for bad in (b'data_le=0x0000000000000000\n',raw.splitlines()[0],b'foo=0x123'):
            with self.assertRaises(ValueError):records(bad)

    def test_capability_cycle_and_identity(self):
        b=self.pci();self.assertTrue(pci_status(b)['flr_capable']);self.assertTrue(pci_status(b)['power_d0'])
        b[0x51]=0x40
        with self.assertRaisesRegex(ValueError,'cyclic'):pci_status(b)
        b[0]=0
        with self.assertRaisesRegex(ValueError,'identity'):pci_status(b)

    def test_successful_capture_is_not_write_ready(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'RTX00001.LOG';p.with_suffix('.PCI').write_bytes(self.pci())
            fields={'probe_schema':1,'gpu_write_capability':0,'capture_status':0,'capture_complete':1,
                    'target_handle':1,'console_out_handle':2,'pci_command':0}
            p.write_text(''.join(f'{k}=0x{v:016x}\n' for k,v in fields.items()))
            result=review(p)
            self.assertFalse(result['write_ready']);self.assertFalse(result['mmio_capture_complete'])
            self.assertTrue(any('PROM' in x for x in result['remaining_conditions']))
            p.write_text(p.read_text()+'capture_complete=0x0000000000000001\n')
            with self.assertRaisesRegex(ValueError,'duplicate'):review(p)

    def test_schema_two_requires_successful_one_shot_claim(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'RTX00001.LOG';p.with_suffix('.PCI').write_bytes(self.pci())
            fields={'probe_schema':2,'gpu_write_capability':0,'capture_status':0,'capture_complete':1,
                    'target_handle':1,'console_out_handle':2,'pci_command':0}
            raw=''.join(f'{k}=0x{v:016x}\n' for k,v in fields.items())
            for claim in ('','one_shot_status=0x8000000000000014\n',
                          'one_shot_status=0x0000000000000000\none_shot_status=0x0000000000000000\n'):
                p.write_text(raw+claim)
                with self.assertRaisesRegex(ValueError,'one-shot'):review(p)
            p.write_text(raw+'one_shot_status=0x0000000000000000\n')
            self.assertFalse(review(p)['write_ready'])

    def test_rom_identity_must_be_supplied_independently(self):
        from unittest.mock import patch
        from review_capture import review_rom_views
        digest = 'a' * 64
        parsed = {'pci_chain': {'sha256': digest}, 'fwsec': {}}
        with patch('review_capture.analyze', return_value=parsed):
            _, blocked = review_rom_views({'.PRM': b'synthetic'})
            self.assertTrue(any('independently reviewed' in b for b in blocked))
            _, blocked = review_rom_views({'.PRM': b'synthetic'}, 'b' * 64)
            self.assertTrue(blocked)
            _, blocked = review_rom_views({'.PRM': b'synthetic'}, digest.upper())
            self.assertEqual(blocked, [])
        with self.assertRaises(ValueError):
            review_rom_views({}, 'invalid')
