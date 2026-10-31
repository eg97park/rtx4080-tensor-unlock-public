"""Synthetic topologies, including EDK2 ConSplitter's physical -> virtual edge.

The fixtures are invented handles, not this machine's cold-boot observations.
"""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from uefi_graph import analyze_graph, PCI_IO, GOP, DRIVER_BINDING, LOADED_IMAGE, TEXT_OUT
from review_capture import review, records


def node(handle, protocols, metadata=()):
    result = [('handle', handle), *metadata]
    for guid, opens in protocols:
        result.append(('protocol_guid', uuid.UUID(guid).bytes_le))
        for entry in opens:
            result.extend(zip(('agent', 'controller', 'attributes', 'open_count'), entry))
    return result


def binding(handle, image):
    return node(handle, [(DRIVER_BINDING, [])], [('driver_image', image),
                ('driver_binding_handle', handle), ('driver_version', 1)])


def image(handle):
    return node(handle, [(LOADED_IMAGE, [])], [('image_base', 0x100000), ('image_size', 4096),
                ('image_device', 0), ('mapped_image_sha256', bytes(32))])


def fixture(shared_console=False, get_only=False, shared_image=False):
    nvidia_gop_opens = []
    if shared_console:
        nvidia_gop_opens = [(0x42, 0x11, 16, 1), (0x42, 0x30, 8, 1)]
    elif get_only:
        nvidia_gop_opens = [(0x42, 0x30, 2, 1)]
    blocks = [node(1, [(PCI_IO, [(0x40, 1, 16, 1), (0x40, 0x11, 8, 1)])]),
              node(2, [(PCI_IO, [(0x41, 2, 16, 1), (0x41, 0x12, 8, 1)])]),
              node(3, [(PCI_IO, [])]),
              node(0x11, [(GOP, []), (TEXT_OUT, nvidia_gop_opens)]),
              node(0x12, [(GOP, []), (TEXT_OUT, [(0x42, 0x12, 16, 1), (0x42, 0x30, 8, 1)])]),
              node(0x30, [(TEXT_OUT, [])]), binding(0x40, 0x50),
              binding(0x41, 0x50 if shared_image else 0x51), binding(0x42, 0x52),
              image(0x50), image(0x51), image(0x52)]
    return [('console_out_handle', 0x30), ('handle_count', len(blocks)),
            *(pair for block in blocks for pair in block),
            ('intel_pci_handle', 2), ('intel_pci_id', 0x7d678086),
            ('intel_pci_handle', 3), ('intel_pci_id', 0x12348086), ('target_handle', 1)]


def encode(pairs):
    lines = []
    for key, value in pairs:
        if isinstance(value, bytes):
            lines.append(f'{key}=0x{len(value):016x}')
            for off in range(0, len(value), 8):
                lines.append(f'data_le=0x{int.from_bytes(value[off:off+8], "little"):016x}')
        else:
            lines.append(f'{key}=0x{value:016x}')
    return ('\r\n'.join(lines) + '\r\n').encode('ascii')


class UefiGraphTests(unittest.TestCase):
    def test_separate_output_is_still_not_detach_permission(self):
        graph, report = analyze_graph(fixture())
        self.assertEqual(len(graph), 12)
        self.assertTrue(report['structural_observations_complete'], report['issues'])
        self.assertEqual(report['intel_display']['observed_path_to_console_out'], ['0x2', '0x12', '0x30'])
        self.assertEqual(report['target']['gop_handles'], ['0x11'])
        self.assertEqual(report['target']['observed_path_to_console_out'], [])
        self.assertFalse(report['detach_ready']); self.assertFalse(report['console_preservation_proven'])
        self.assertFalse(report['conflicts'])

    def test_virtual_console_shared_despite_distinct_gpu_handle(self):
        _, report = analyze_graph(fixture(shared_console=True))
        self.assertEqual(report['target']['observed_path_to_console_out'], ['0x1', '0x11', '0x30'])
        self.assertEqual(report['shared_handles'], ['0x30'])
        self.assertIn('0x52', report['shared_driver_images'])
        self.assertEqual(len(report['conflicts']), 3)
        self.assertFalse(report['detach_ready'])

    def test_get_protocol_is_reference_not_child_or_driver_ownership(self):
        _, report = analyze_graph(fixture(get_only=True))
        self.assertFalse(report['target']['observed_path_to_console_out'])
        self.assertEqual(report['target']['driver_agents'], ['0x40'])
        self.assertEqual(len(report['child_edges']), 3)

    def test_unresolved_get_address_is_not_promoted_to_owner(self):
        pairs=fixture(get_only=True)
        # All three synthetic image ranges overlap: preserve every candidate.
        index=next(i for i,pair in enumerate(pairs) if pair==('attributes',2))
        pairs[index-2]=('agent',0x100123)
        _,report=analyze_graph(pairs)
        entry=report['unresolved_open_agents'][0]
        self.assertTrue(entry['non_owning_reference'])
        self.assertEqual([c['offset'] for c in entry['address_in_loaded_images']],['0x123']*3)
        self.assertFalse(entry['valid_handle_proven'])
        self.assertFalse(report['structural_observations_complete'])
        self.assertFalse(report['detach_ready'])
        self.assertEqual(report['target']['driver_agents'],['0x40'])
        pairs[index-2]=('agent',0x101000)  # exact image end is excluded
        _,report=analyze_graph(pairs)
        self.assertEqual(report['unresolved_open_agents'][0]['address_in_loaded_images'],[])

    def test_shared_driver_image_detected_without_shared_console(self):
        _, report = analyze_graph(fixture(shared_image=True))
        self.assertEqual(report['shared_driver_images'], ['0x50'])
        self.assertFalse(report['shared_handles'])
        self.assertTrue(any('unloading' in s for s in report['conflicts']))

    def test_other_intel_device_and_pci_record_boundary(self):
        graph, report = analyze_graph(fixture())
        self.assertEqual(report['intel_other_pci_handles'], ['0x3'])
        self.assertNotIn('0x3', report['intel_display']['reachable_handles'])
        self.assertFalse(any(k.startswith('intel_') for n in graph for k, _ in n['records']))

    def test_no_graph_and_missing_count_remain_unproven(self):
        _, report = analyze_graph([('target_handle', 1), ('console_out_handle', 2)])
        self.assertFalse(report['structural_observations_complete'])
        self.assertTrue(any('no handle' in s for s in report['issues']))
        self.assertFalse(analyze_graph([p for p in fixture() if p[0] != 'handle_count'])[1]['structural_observations_complete'])

    def test_duplicate_handles_counts_protocols_and_incomplete_entries_rejected(self):
        pairs = fixture(); protocol_at = next(i for i, p in enumerate(pairs) if p[0] == 'protocol_guid')
        bad = [pairs + [('handle', 1)], pairs + [('handle_count', 12)],
               pairs[:protocol_at] + [pairs[protocol_at]] + pairs[protocol_at:],
               [p for i, p in enumerate(pairs) if i != protocol_at + 2],
               [('protocol_guid', uuid.UUID(GOP).bytes_le)] + pairs]
        for candidate in bad:
            with self.subTest(candidate=candidate[:3]), self.assertRaises(ValueError): analyze_graph(candidate)

    def test_invalid_modes_counts_and_integer_widths_rejected(self):
        for key, value in [('attributes', 0x18), ('attributes', 0), ('open_count', 0),
                           ('open_count', 1 << 32), ('agent', 0), ('controller', 0), ('agent', -1)]:
            pairs = fixture(); pos = next(i for i, p in enumerate(pairs) if p[0] == key)
            pairs[pos] = (key, value)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): analyze_graph(pairs)

    def test_exclusive_application_is_not_driver_and_duplicate_open_is_rejected(self):
        pairs = fixture(); pos = next(i for i, p in enumerate(pairs) if p[0] == 'agent')
        pairs[pos:pos+4] = [('agent', 0x50), ('controller', 0), ('attributes', 32), ('open_count', 1)]
        report = analyze_graph(pairs)[1]
        self.assertFalse(report['target']['driver_agents'])
        self.assertEqual(report['target']['exclusive_opens'][0]['agent'], '0x50')
        self.assertTrue(any('exclusive' in s for s in report['conflicts']))
        pairs[pos+4:pos+4] = [('agent', 0x50), ('controller', 0), ('attributes', 32), ('open_count', 2)]
        with self.assertRaisesRegex(ValueError, 'duplicate protocol open'): analyze_graph(pairs)

    def test_unresolved_child_and_missing_binding_are_explicit(self):
        pairs = fixture(); pos = next(i for i, p in enumerate(pairs) if p == ('controller', 0x11))
        pairs[pos] = ('controller', 0xdead)
        report = analyze_graph(pairs)[1]
        self.assertFalse(report['structural_observations_complete'])
        self.assertTrue(any('unresolved open controller' in s for s in report['issues']))
        pairs = [p for p in fixture() if p != ('driver_image', 0x50)]
        self.assertTrue(any('incomplete driver binding' in s for s in analyze_graph(pairs)[1]['issues']))

    def test_child_cycle_finishes_and_blocks_completeness(self):
        pairs = fixture(); pos = pairs.index(('handle', 0x12))
        pairs[pos:pos] = [('agent', 0x40), ('controller', 1), ('attributes', 8), ('open_count', 1)]
        report = analyze_graph(pairs)[1]
        self.assertTrue(report['cycle_detected']); self.assertFalse(report['structural_observations_complete'])

    def test_self_child_rejected_and_competing_driver_owners_flagged(self):
        pairs = fixture(); pos = pairs.index(('controller', 0x11)); pairs[pos] = ('controller', 1)
        with self.assertRaisesRegex(ValueError, 'parent'): analyze_graph(pairs)
        pairs = fixture(); pos = pairs.index(('handle', 2))
        pairs[pos:pos] = [('agent', 0x41), ('controller', 1), ('attributes', 16), ('open_count', 1)]
        report = analyze_graph(pairs)[1]
        self.assertFalse(report['structural_observations_complete'])
        self.assertTrue(any('contradictory' in s for s in report['issues']))

    def test_long_child_chain_is_iterative(self):
        count = 1100
        pairs = [('handle_count', count), ('console_out_handle', count)]
        for h in range(1, count + 1):
            pairs += node(h, [(PCI_IO, [(1, h + 1, 8, 1)] if h < count else [])])
        pairs.append(('target_handle', 1))
        report = analyze_graph(pairs)[1]
        self.assertEqual(len(report['target']['observed_path_to_console_out']), count)
        self.assertFalse(report['cycle_detected']); self.assertFalse(report['detach_ready'])

    def test_wrong_or_duplicate_intel_identity_rejected(self):
        for bad in (0x7d6710de, 1 << 32):
            pairs = fixture(); pos = pairs.index(('intel_pci_id', 0x7d678086)); pairs[pos] = ('intel_pci_id', bad)
            with self.assertRaises(ValueError): analyze_graph(pairs)
        pairs = fixture(); pairs[-1:-1] = [('intel_pci_handle', 2), ('intel_pci_id', 0x7d678086)]
        with self.assertRaises(ValueError): analyze_graph(pairs)

    def test_metadata_protocol_and_hash_inconsistency_are_not_accepted(self):
        pairs = fixture(); pos = pairs.index(('mapped_image_sha256', bytes(32)))
        pairs[pos] = ('mapped_image_sha256', bytes(31))
        with self.assertRaisesRegex(ValueError, 'hash'): analyze_graph(pairs)
        pairs = [p for p in fixture() if p != ('image_size', 4096)]
        self.assertTrue(any('incomplete loaded image' in s for s in analyze_graph(pairs)[1]['issues']))
        pairs = fixture(); pos = pairs.index(('driver_binding_handle', 0x40))
        pairs[pos] = ('driver_binding_handle', 0x41)
        self.assertTrue(any('binding handle mismatch' in s for s in analyze_graph(pairs)[1]['issues']))

    def test_by_driver_exclusive_and_handle_count_mismatch(self):
        pairs = fixture(); pos = pairs.index(('attributes', 16)); pairs[pos] = ('attributes', 48)
        report = analyze_graph(pairs)[1]
        self.assertEqual(report['target']['driver_agents'], ['0x40'])
        self.assertTrue(any('exclusive' in s for s in report['conflicts']))
        pairs[1] = ('handle_count', 13)
        self.assertFalse(analyze_graph(pairs)[1]['structural_observations_complete'])

    def test_raw_log_and_full_reviewer_integration(self):
        pairs = [('probe_schema', 2), ('gpu_write_capability', 0), ('one_shot_status', 0),
                 *fixture(shared_console=True), ('pci_command', 0), ('capture_status', 0), ('capture_complete', 1)]
        encoded = encode(pairs); self.assertEqual(records(encoded), pairs)
        pci = bytearray(256); struct.pack_into('<I', pci, 0, 0x270410de); struct.pack_into('<I', pci, 0x2c, 0x15007377)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'RTX00001.LOG'; path.write_bytes(encoded); path.with_suffix('.PCI').write_bytes(pci)
            result = review(path)
        self.assertFalse(result['write_ready'])
        self.assertTrue(result['ownership_review']['conflicts'])
        self.assertTrue(any('shared descendants' in s for s in result['remaining_conditions']))


if __name__ == '__main__': unittest.main()
