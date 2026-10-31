"""Windows/display evidence validation with synthetic data, no hardware."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from measurement_context import comparison_context, validate_run_context
from summarize_bench import validate_post_health


def fixture_run():
    context = {
        'schema_version': 1, 'captured_utc': '2026-10-30T15:00:01Z',
        'session': {'boot_utc': '2026-10-30T14:00:00Z', 'windows_directory': 'C:\\Windows',
                    'system_drive': 'C:', 'volume_serial': '11111111', 'os_version': 'fixture', 'os_build': 'fixture'},
        'display': {'adapter_path': '\\\\?\\PCI#VEN_8086&DEV_7D67&SYNTHETIC',
                    'monitor_path': '\\\\?\\DISPLAY#SAME069#SYNTHETIC', 'adapter_luid': [123, 0],
                    'source_id': 0, 'target_id': 1, 'path_flags': 9, 'technology': 5,
                    'rotation': 1, 'scaling': 1, 'scanline': 1, 'clone_group': 65535,
                    'width': 3840, 'height': 2160, 'refresh_numerator': 133275000, 'refresh_denominator': 925600,
                    'mode_words': [['0000000000000001'] * 6 for _ in range(3)]}}
    checks = []
    for index, stage in enumerate(('baseline', 'case-0-before', 'case-0-after', 'final'), 1):
        check = copy.deepcopy(context)
        check.update(stage=stage, captured_utc=f'2026-10-30T15:00:0{index}Z')
        checks.append(check)
    return {'schema_version': 2, 'start_utc': '2026-10-30T15:00:00Z', 'end_utc': '2026-10-30T15:00:05Z',
            'cases': [{}], 'context_checks': checks, 'control_after': 'fixture'}


class MeasurementContextTests(unittest.TestCase):
    def test_recorded_and_legacy_context(self):
        run = fixture_run()
        self.assertEqual(validate_run_context(run), run['context_checks'][0])
        self.assertIsNone(validate_run_context({'schema_version': 1}))
        legacy = comparison_context({'schema_version': 1}, run)
        self.assertFalse(legacy['before_recorded'])
        self.assertIsNone(legacy['same_display_conditions'])
        run['schema_version'] = 1
        with self.assertRaisesRegex(ValueError, 'require measurement schema 2'):
            validate_run_context(run)

    def test_changed_display_or_windows_stops_validation(self):
        for section, field, value in [('display', 'refresh_numerator', 60), ('display', 'adapter_luid', [124, 0]),
                                      ('session', 'volume_serial', '22222222'),
                                      ('session', 'boot_utc', '2026-10-30T14:59:00Z')]:
            run = fixture_run()
            run['context_checks'][2][section][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'changed'):
                validate_run_context(run)

    def test_missing_or_reordered_checkpoints_and_bad_times(self):
        for mutate in (lambda r: r.pop('context_checks'), lambda r: r['context_checks'].pop(),
                       lambda r: r['context_checks'].reverse(),
                       lambda r: r['context_checks'][1].update(stage='case-0-after'),
                       lambda r: r['context_checks'][2].update(captured_utc='2026-10-30T15:00:06Z'),
                       lambda r: r['context_checks'][0].update(captured_utc='2026-10-30T15:00:00')):
            run = fixture_run()
            mutate(run)
            with self.assertRaises(ValueError):
                validate_run_context(run)

    def test_missing_or_invalid_display_evidence(self):
        for field, value in [('mode_words', []), ('refresh_denominator', 0), ('rotation', None),
                             ('adapter_path', 'ROOT#BasicDisplay'), ('width', 1920)]:
            run = fixture_run()
            for check in run['context_checks']:
                check['display'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_run_context(run)

    def test_comparison_separates_boot_local_handles_and_refresh(self):
        before, after = fixture_run(), fixture_run()
        for check in after['context_checks']:
            check['session']['boot_utc'] = '2026-10-30T14:30:00Z'
            check['display']['adapter_luid'] = [456, 0]
        result = comparison_context(before, after)
        self.assertTrue(result['same_display_conditions'])
        self.assertTrue(result['same_windows_installation'])
        self.assertFalse(result['same_boot_session'])
        for check in after['context_checks']:
            check['display']['refresh_numerator'] = 60
            check['display']['refresh_denominator'] = 1
            check['session']['volume_serial'] = '22222222'
        result = comparison_context(before, after)
        self.assertFalse(result['same_display_conditions'])
        self.assertFalse(result['same_windows_installation'])

    def test_post_health_cannot_borrow_a_different_boot_or_display(self):
        with tempfile.TemporaryDirectory() as temp:
            run = fixture_run()
            run_file, health_file = Path(temp) / 'run.json', Path(temp) / 'post-health.json'
            run_file.write_text(json.dumps(run))
            context = copy.deepcopy(run['context_checks'][0])
            context.pop('stage')
            context['captured_utc'] = '2026-10-30T15:00:06Z'
            health = {'schema_version': 1, 'healthy': True, 'gpu_workload_started': False, 'errors': [], 'events': [],
                      'run_sha256': hashlib.sha256(run_file.read_bytes()).hexdigest(), 'control': 'fixture',
                      'event_start_utc': run['start_utc'], 'event_end_utc': '2026-10-30T15:00:06Z',
                      'context_verified': True, 'context': context, 'display': [
                          {'PNPDeviceID': 'PCI\\VEN_10DE&DEV_2704&SUBSYS_15007377', 'ConfigManagerErrorCode': 0},
                          {'PNPDeviceID': 'PCI\\VEN_8086&DEV_7D67', 'ConfigManagerErrorCode': 0}]}

            def validate(h):
                health_file.write_text(json.dumps(h))
                validate_post_health(health_file, run_file, run)

            validate(health)
            for mutate in (lambda h: h.pop('context'), lambda h: h.update(context_verified=False),
                           lambda h: h['context'].update(captured_utc='2026-10-30T15:00:01Z'),
                           lambda h: h['context']['session'].update(boot_utc='2026-10-30T15:00:00Z'),
                           lambda h: h['context']['display'].update(refresh_numerator=60)):
                h = copy.deepcopy(health)
                mutate(h)
                with self.assertRaises(ValueError):
                    validate(h)


if __name__ == '__main__':
    unittest.main()
