import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).with_name('full_run.py')
spec = importlib.util.spec_from_file_location('full_run', path)
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class FullRunTests(unittest.TestCase):
    def test_plan_is_complete_and_unique(self):
        plan = list(run.jobs(pathlib.Path('/bin')))
        self.assertEqual(len(plan), 82)
        self.assertEqual(len({n for n, _, _, _ in plan}), len(plan))
        self.assertEqual(sum(k == 'paired' for _, k, _, _ in plan), 60)
        self.assertEqual(sum(k == 'tree' for _, k, _, _ in plan), 12)
        self.assertEqual(sum(k == 'packed' for _, k, _, _ in plan), 8)

    def test_paired_records_require_warmup_and_measured(self):
        warmup = dict(kind='sample', warmup=True, negative_guest_cases=30)
        sample = dict(kind='sample', warmup=False, aggregate_prove_us=1, execution_gas=61)
        run.validate([warmup, sample], 'paired')
        for rows in [[], [sample], [warmup], [warmup, sample, sample],
                     [dict(warmup, negative_guest_cases=0), sample]]:
            with self.assertRaises(AssertionError):
                run.validate(rows, 'paired')

    def test_packed_requires_all_repeats(self):
        with self.assertRaises(AssertionError):
            run.validate([dict(prove_us_all=[1, 2], negative_cases=3)], 'packed')

    def test_capacity_is_not_a_measurement(self):
        run.validate([dict(status='unsupported')], 'capacity')
        with self.assertRaises(AssertionError):
            run.validate([dict(status='passed')], 'capacity')

class SummaryTests(unittest.TestCase):
    def test_tables_use_only_measured_samples(self):
        import json
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            plan = [dict(name=n,kind=k) for n,k,_,_ in run.jobs(pathlib.Path('/bin'))]
            (out/'manifest.json').write_text(json.dumps(dict(jobs=plan)))
            (out/'complete.json').write_text(json.dumps(dict(validated_jobs=82,expected_jobs=82)))
            for job in plan:
                name,kind=job['name'],job['kind']
                (out/(name+'.result.json')).write_text(json.dumps(dict(status='passed',exit_code=0,minimum_available_gib=60,peak_rss_gib=4)))
                mode='pcs' if '-pcs-' in name else 'r1cs-vm'
                if kind=='paired':
                    row=dict(kind='sample',warmup=False,interface=mode,client_us=2e6,aggregate_prove_us=1e6 if mode=='pcs' else 1.1e6,
                             aggregate_verify_us=1e3,serial_warm_us=3e6,serial_cold_us=4e6,base_cycles=800000,
                             aggregate_transport_bytes=200000,execution_gas=10971 if mode=='pcs' else 61)
                    rows=[dict(row,warmup=True,negative_guest_cases=30,aggregate_prove_us=999e6),row]
                elif kind=='tree':
                    leaves,per_leaf=map(int,name.split('-')[0][4:].split('x'))
                    rows=[dict(kind='tree',interface=mode,leaves=leaves,per_leaf=per_leaf,negative_cases=6,
                               root_prove_us=1e6,root_base_cycles=260000,verify_us=1000,
                               leaf_runs=[dict(prove_us=2e6) for _ in range(leaves)])]
                elif kind=='packed':
                    rows=[dict(statement=name[7:],prove_us_all=[1e6,2e6,3e6],prove_us_median=2e6,
                               verify_us=1000,proof_bytes=100000,peak_rss_kib=2**20,negative_cases=3)]
                else:rows=[dict(status='unsupported')]
                (out/(name+'.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in rows))
            subprocess.run([sys.executable,str(path.with_name('summarize_full.py')),str(out)],check=True)
            summary=json.loads((out/'summary.json').read_text())
            self.assertEqual(summary['paired']['falcon512']['pcs']['aggregate_prove_us'],1e6)
            self.assertAlmostEqual(summary['paired']['falcon512']['median_paired_aggregate_ratio'],1.1)
            self.assertEqual(summary['trees']['4x4']['pcs']['leaf_prove_us'],8e6)
            self.assertIn('not a dedicated-machine',(out/'README.md').read_text())


if __name__ == '__main__':
    unittest.main()
