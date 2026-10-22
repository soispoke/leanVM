#!/usr/bin/env python3
"""Regression checks for the retained Flock evidence, not proof verification."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from summarize_flock import summarize


FIXTURE = Path(__file__).resolve().parent.parent / 'evidence/2026-10-22-flock-blake2s-baseline/flock-b2s-repeated-final'


class FlockRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['started.json', 'result.json', 'run-00']:
            source, target = FIXTURE / name, self.root / name
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)

    def rewrite(self, change):
        path = self.root / 'run-00/stdout.log'
        lines = path.read_text().splitlines()
        records = [json.loads(line) for line in lines if line.startswith('{')]
        records = change(records)
        path.write_text('\n'.join(line for line in lines if not line.startswith('{')) + '\n' +
                        '\n'.join(json.dumps(r) for r in records) + '\n')
        run_path = self.root / 'run-00/result.json'
        run = json.loads(run_path.read_text())
        run['stdout_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        run['json_event_count'] = len(records)
        run_path.write_text(json.dumps(run))
        receipt_path = self.root / 'result.json'
        receipt = json.loads(receipt_path.read_text())
        receipt['runs'] = [run]
        receipt_path.write_text(json.dumps(receipt))

    def mutate(self, kind, key, value):
        def change(records):
            row = next(r for r in records if r['record'] == kind)
            row[key] = value
            return records
        self.rewrite(change)

    def test_complete_evidence(self):
        result = summarize(self.root)
        self.assertEqual(result['status'], 'complete_record_set')
        self.assertEqual(len(result['trials']), 3)

    def test_missing_material_proof(self):
        self.rewrite(lambda rows: [r for r in rows if not (r['record'] == 'stage' and r['trial'] == 1 and r['ordinal'] == 0)])
        with self.assertRaisesRegex(ValueError, 'missing trial stages'):
            summarize(self.root)

    def test_duplicate_summary(self):
        self.rewrite(lambda rows: rows + [next(r for r in rows if r['record'] == 'summary')])
        with self.assertRaisesRegex(ValueError, 'missing trial stages'):
            summarize(self.root)

    def test_endpoint_recomputed(self):
        self.mutate('statement', 'h_end', [0] * 16)
        with self.assertRaisesRegex(ValueError, 'endpoint mismatch'):
            summarize(self.root)

    def test_wrong_workload(self):
        self.mutate('summary', 'blocks_per_leaf', 16)
        with self.assertRaisesRegex(ValueError, 'wrong workload'):
            summarize(self.root)

    def test_incomplete_mutation_checks(self):
        self.mutate('summary', 'mutation_rejections', 8)
        with self.assertRaisesRegex(ValueError, 'mutation coverage'):
            summarize(self.root)

    def test_unverified_root(self):
        self.mutate('summary', 'verified', False)
        with self.assertRaisesRegex(ValueError, 'verification'):
            summarize(self.root)

    def test_wrong_repeat_policy(self):
        self.mutate('shared_vk_setup', 'same_process', False)
        with self.assertRaisesRegex(ValueError, 'repeat policy'):
            summarize(self.root)

    def test_unmeasured_online_wall(self):
        self.mutate('stage', 'online_wall_ms', 0)
        with self.assertRaisesRegex(ValueError, 'empty stage'):
            summarize(self.root)


if __name__ == '__main__':
    unittest.main()
