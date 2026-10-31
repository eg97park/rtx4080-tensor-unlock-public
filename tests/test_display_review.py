import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from review_display_isolation import review


class DisplayReviewTests(unittest.TestCase):
    def setUp(self):
        self.during = json.loads((Path(__file__).parent / 'fixtures/measurement-display.json').read_text())
        self.before = copy.deepcopy(self.during)
        basic = copy.deepcopy(self.before['Paths'][0])
        for name in ('SourceAdapterName', 'TargetAdapterName'):
            basic[name]['Name'] = '\\\\?\\ROOT#BasicDisplay#0000#SYNTHETIC'
        basic['Native']['Source']['Adapter']['Low'] = 999
        basic['Native']['Target']['Adapter']['Low'] = 999
        basic['SourceModeIndex'] = 4; basic['TargetModeIndex'] = 3
        basic['Native']['Source']['ModeIndex'] = (4 << 16) | 65535
        basic['Native']['Target']['ModeIndex'] = (3 << 16) | 5
        modes = copy.deepcopy(self.during['Modes'])
        for mode in modes:
            mode['Adapter']['Low'] = 999
        self.before['Paths'].append(basic)
        self.before['Modes'].extend(modes)
        self.after = copy.deepcopy(self.before)

    def test_transition_is_not_root_cause_proof(self):
        result = review(self.before, self.during, self.after)
        self.assertEqual(result['active_path_counts'], [2, 1, 2])
        self.assertFalse(result['root_cause_proven'])
        self.assertFalse(result['visual_symptoms_proven_by_ccd'])

    def test_reject_missing_or_duplicate_path(self):
        for broken in (self.before, {'QueryFlags': 82, 'Paths': [], 'Modes': []}):
            with self.assertRaises(ValueError):
                review(self.before, broken, self.after)

    def test_reject_mode_changes_and_incomplete_restore(self):
        for section in ('during', 'after'):
            changed = copy.deepcopy(getattr(self, section))
            changed['Modes'][0]['Raw0'] += 1
            with self.subTest(section=section), self.assertRaises(ValueError):
                review(self.before, changed if section == 'during' else self.during,
                       changed if section == 'after' else self.after)

    def test_reject_bad_association_and_query_failure(self):
        for mutate in (lambda p: p.update(SourceModeIndex=0),
                       lambda p: p['TargetName'].update(Status=5)):
            changed = copy.deepcopy(self.during)
            mutate(changed['Paths'][0])
            with self.assertRaises(ValueError):
                review(self.before, changed, self.after)

    def test_equivalent_mode_renumbering(self):
        changed = copy.deepcopy(self.during)
        changed['Modes'][0], changed['Modes'][1] = changed['Modes'][1], changed['Modes'][0]
        path = changed['Paths'][0]
        path.update(SourceModeIndex=0, TargetModeIndex=1)
        path['Native']['Source']['ModeIndex'] = 65535
        path['Native']['Target']['ModeIndex'] = 65538
        self.assertTrue(review(self.before, changed, self.after)['intel_mode_preserved'])
