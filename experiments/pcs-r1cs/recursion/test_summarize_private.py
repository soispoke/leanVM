#!/usr/bin/env python3
"""Coverage/accounting controls for the local private-tree summarizer."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from summarize_private import summarize


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.started = dict(command=['private_tree', '--depth', '1', '--chain', '16'],
                            source_commit='a' * 40, binary_sha256='b' * 64, budget_gib=64)
        self.result = dict(self.started, returncode=0, stop_reason=None, elapsed_s=1,
                           peak_rss_gib=1, min_available_gib=100)
        self.rows = []
        for level in range(2):
            self.rows.append(dict(kind='setup', level=level, rows=8192,
                                  native_shape=[2, 1, 2], compressions=1, official_score=False))
            for index in range(2 >> level):
                self.rows.append(dict(kind='proof', level=level, index=index,
                                      proving_s=.1, verification_ms=1, proof_bytes=128, verified=True))
        self.rows.append(dict(kind='complete', levels=1, chain=16, root=[0] * 32,
                              status='locally_verified', same_backend=True,
                              single_fixed_circuit=False, lean_certificate=False, official_score=False))

    def run_summary(self):
        (self.path / 'started.json').write_text(json.dumps(self.started))
        (self.path / 'result.json').write_text(json.dumps(self.result))
        (self.path / 'stdout.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in self.rows))
        return summarize(self.path)

    def first_proof(self):
        return next(r for r in self.rows if r['kind'] == 'proof')

    def test_complete(self):
        result = self.run_summary()
        self.assertEqual(result['status'], 'complete_record_set')
        self.assertEqual([r['proofs'] for r in result['levels']], [2, 1])

    def test_missing_sample(self):
        self.rows.remove(self.first_proof())
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_duplicated_sample(self):
        proofs = [r for r in self.rows if r['kind'] == 'proof']
        proofs[1]['index'] = proofs[0]['index']
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_extra_sample(self):
        self.rows.insert(0, copy.deepcopy(self.first_proof()))
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_wrong_workload(self):
        self.rows[-1]['chain'] = 15
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_provenance(self):
        self.result['source_commit'] = 'c' * 40
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_failed_process(self):
        self.result['returncode'] = 2
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_oversized_proof(self):
        self.first_proof()['proof_bytes'] = (1 << 20) + 1
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_failed_verification(self):
        self.first_proof()['verified'] = False
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_nan_timing(self):
        self.first_proof()['proving_s'] = float('nan')
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_unearned_certificate_claim(self):
        self.rows[-1]['lean_certificate'] = True
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_resource_limit(self):
        self.result['peak_rss_gib'] = 65
        with self.assertRaises(ValueError):
            self.run_summary()

    def test_incomplete_marker(self):
        self.rows.insert(0, dict(kind='capacity_limit'))
        with self.assertRaises(ValueError):
            self.run_summary()


if __name__ == '__main__':
    unittest.main()
