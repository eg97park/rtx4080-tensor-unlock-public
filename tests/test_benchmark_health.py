"""Regression cases for reused/misbound post-run health evidence. No hardware."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from summarize_bench import validate_post_health


class HealthBindingTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.run_file=Path(temp.name)/'run.json';self.health_file=Path(temp.name)/'post-health.json'
        self.run={'schema_version':1,'control_after':'same settings','start_utc':'2026-10-30T15:00:00+00:00',
                  'end_utc':'2026-10-30T15:00:17+00:00'}
        self.run_file.write_text(json.dumps(self.run))
        self.health={'schema_version':1,'healthy':True,'gpu_workload_started':False,'errors':[],
                     'events':[],'run_sha256':hashlib.sha256(self.run_file.read_bytes()).hexdigest(),
                     'control':'same settings','event_start_utc':'2026-10-30T15:00:00Z',
                     'event_end_utc':'2026-10-30T15:00:30Z','display':[
                         {'PNPDeviceID':'PCI\\VEN_10DE&DEV_2704&SUBSYS_15007377','ConfigManagerErrorCode':0},
                         {'PNPDeviceID':'PCI\\VEN_8086&DEV_7D67','ConfigManagerErrorCode':0}]}

    def validate(self, health):
        self.health_file.write_text(json.dumps(health))
        validate_post_health(self.health_file,self.run_file,self.run)

    def test_matching_run_and_covering_window(self):
        self.validate(self.health)
        h=copy.deepcopy(self.health);h['event_start_utc']='2026-10-30T23:59:59+09:00'
        self.validate(h)

    def test_stale_report_hash_or_control(self):
        for key,value in [('run_sha256','0'*64),('control','changed settings')]:
            h=copy.deepcopy(self.health);h[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate(h)
        # Identical parsed data still needs the exact source-file hash.
        self.run_file.write_text(json.dumps(self.run,indent=2))
        with self.assertRaisesRegex(ValueError,'different run'):self.validate(self.health)

    def test_healthy_flag_does_not_override_faults_or_missing_observations(self):
        cases=[('healthy',False),('errors',['failure']),('events',[{'Id':4101}]),
               ('gpu_workload_started',True),('display',[]),('events',None)]
        for key,value in cases:
            h=copy.deepcopy(self.health);h[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate(h)

    def test_partial_or_ambiguous_event_window(self):
        for key,value in [('event_start_utc','2026-10-30T15:00:01Z'),
                          ('event_end_utc','2026-10-30T15:00:16Z'),
                          ('event_start_utc','2026-10-30T15:00:00'),('event_end_utc',None)]:
            h=copy.deepcopy(self.health);h[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.validate(h)

    def test_device_error_or_wrong_gpu(self):
        for update in [{'ConfigManagerErrorCode':43},{'PNPDeviceID':'PCI\\VEN_10DE&DEV_2702'}]:
            h=copy.deepcopy(self.health);h['display'][0].update(update)
            with self.subTest(update=update),self.assertRaises(ValueError):self.validate(h)
        h=copy.deepcopy(self.health);h['display'].append(h['display'][1])
        with self.assertRaises(ValueError):self.validate(h)


if __name__=='__main__':unittest.main()
