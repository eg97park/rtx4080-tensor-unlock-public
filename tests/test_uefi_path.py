from pathlib import Path
import struct
import sys
import unittest
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from uefi_path import decode,match_esp,SIMPLE_FS

class UefiPathTests(unittest.TestCase):
    def setUp(self):
        self.guid='12345678-1234-5678-90ab-1234567890ab'
        self.hd=struct.pack('<BBHIQQ',4,1,42,1,2048,204800)+uuid.UUID(self.guid).bytes_le+bytes([2,2])
        self.end=bytes([0x7f,0xff,4,0]);self.path=self.hd+self.end
        self.node={'handle':'0x1','records':[['device_path',self.path.hex()],['protocol_guid',uuid.UUID(SIMPLE_FS).bytes_le.hex()]]}
        self.windows={'administrative_queries_complete':True,'boot_manager_candidates':[{
            'partition_guid':'{'+self.guid+'}','boot_manager_path':'\\EFI\\Microsoft\\Boot\\bootmgfw.efi','sha256':'a'*64}]}

    def test_gpt_little_endian_and_geometry(self):
        hd=decode(self.path)['hard_drives'][0]
        self.assertEqual(hd['gpt_guid'],self.guid);self.assertEqual(hd['start_lba'],2048);self.assertEqual(hd['size_lba'],204800)

    def test_bounds_termination_and_trailing_data(self):
        for raw in (b'',self.hd,self.path+b'\0',b'\4\1\3\0',bytes(4097),self.path[:30],bytes([0x7f,1,4,0])):
            with self.subTest(raw=raw[:4]),self.assertRaises(ValueError):decode(raw)

    def test_file_path_utf16(self):
        name='\\EFI\\Microsoft\\Boot\\bootmgfw.efi';payload=(name+'\0').encode('utf-16-le')
        file_node=struct.pack('<BBH',4,4,len(payload)+4)+payload
        self.assertEqual(decode(self.hd+file_node+self.end)['file_paths'],[name])
        with self.assertRaises(ValueError):decode(self.hd+file_node[:-2]+b'XX'+self.end)

    def test_unique_partition_is_not_boot_authorization(self):
        result=match_esp([self.node],self.windows)
        self.assertTrue(result['unique_partition_match']);self.assertFalse(result['boot_ready']);self.assertFalse(result['boot_file_verified_in_uefi'])

    def test_mbr_or_multi_instance_not_matched(self):
        mbr=bytearray(self.hd);mbr[40:42]=bytes([1,1])
        for path in (bytes(mbr)+self.end,self.hd+bytes([0x7f,1,4,0])+self.path):
            self.node['records'][0][1]=path.hex()
            self.assertFalse(match_esp([self.node],self.windows)['unique_partition_match'])

    def test_ambiguous_fs_or_absent_protocol(self):
        other={**self.node,'handle':'0x2'}
        self.assertFalse(match_esp([self.node,other],self.windows)['unique_partition_match'])
        self.node['records'].pop()
        self.assertFalse(match_esp([self.node],self.windows)['unique_partition_match'])

    def test_duplicate_handle_and_path_refused(self):
        with self.assertRaises(ValueError):match_esp([self.node,self.node],self.windows)
        self.node['records'].append(['device_path',self.path.hex()])
        with self.assertRaises(ValueError):match_esp([self.node],self.windows)

    def test_incomplete_windows_review_refused(self):
        self.windows['administrative_queries_complete']=False
        with self.assertRaises(ValueError):match_esp([self.node],self.windows)
