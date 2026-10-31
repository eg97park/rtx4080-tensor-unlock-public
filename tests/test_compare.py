import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from compare_bench import compare


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.a=Path(self.temp.name)/'a';self.b=Path(self.temp.name)/'b'
        self.data={'schema_version':1,'complete':True,'device':'fixture','pci_bus':'fixture','sm_count':76,
                   'cuda_driver':1,'cuda_runtime':1,'cublas':1,'reps':3,'results':[
            {'kind':'gemm','mode':'f16_f32','m':128,'n':128,'k':128,'seed':2704,'samples_ms':[1,1,1],
             'median_ms':1,'tflops':2*128**3/1e9,'accuracy_pass':True,'all_outputs_finite':True,
             'validation_runs':2,'checked_per_validation':128**2,'nrmse':0,'initial_nrmse':0}]}
        self.run={'schema_version':1,'complete':True,'event_review_required':False,'failures':[],
                  'control_before':'fixture','control_after':'fixture','suite':'smoke','exe_sha256':'fixture',
                  'cublas_dlls':{'fixture':'fixture'},'environment':{'override':None},'state':'stock'}

    def save(self,path,data=None,run=None):
        path.mkdir(exist_ok=True)
        text=json.dumps(data or self.data).encode();(path/'case-0.json').write_bytes(text)
        r=copy.deepcopy(run or self.run);r['cases']=[{'file':'case-0.json','sha256':hashlib.sha256(text).hexdigest()}]
        (path/'run.json').write_text(json.dumps(r))

    def test_valid_speedup_without_claiming_unlock(self):
        self.save(self.a);d=copy.deepcopy(self.data);v=d['results'][0]
        v.update(samples_ms=[0.5]*3,median_ms=0.5,tflops=v['tflops']*2)
        self.save(self.b,d)
        result=compare(self.a,self.b)
        self.assertEqual(result['rows'][0]['speedup'],2)
        self.assertFalse(result['hardware_unlock_proven_by_this_report'])

    def test_control_or_health_mismatch(self):
        self.save(self.a)
        for key,val in (('exe_sha256','other'),('control_after','other'),('event_review_required',True),('complete',False),('cublas_dlls',{})):
            r=copy.deepcopy(self.run);r[key]=val;self.save(self.b,run=r)
            with self.subTest(key=key),self.assertRaises(ValueError):compare(self.a,self.b)

    def test_corrupt_or_nonfinite_result(self):
        self.save(self.a)
        for key,val in (('samples_ms',[0,0,0]),('nrmse',float('nan')),('accuracy_pass',False),('median_ms',2),('tflops',99)):
            d=copy.deepcopy(self.data);d['results'][0][key]=val;self.save(self.b,d)
            with self.subTest(key=key),self.assertRaises(ValueError):compare(self.a,self.b)
        self.save(self.b);(self.b/'case-0.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):compare(self.a,self.b)

    def test_new_measurement_cannot_omit_context(self):
        self.save(self.a)
        run=copy.deepcopy(self.run);run['schema_version']=2
        self.save(self.b,run=run)
        with self.assertRaisesRegex(ValueError,'context checkpoints'):compare(self.a,self.b)
