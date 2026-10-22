#!/usr/bin/env python3
"""Regression tests for complete and matched benchmark evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('compare', Path(__file__).with_name('compare.py'))
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        for n in compare.FAN_INS:
            for backend in ('native', 'vm'):
                d = self.root / f'{backend}-{n}'
                d.mkdir()
                result = dict(returncode=0, stop_reason=None, peak_rss_gib=1, min_available_gib=100,
                              binary_sha256='same', source_commit='same', hostname='same', kernel='same',
                              logical_cpus=64, affinity=[0])
                (d / 'result.json').write_text(json.dumps(result))
                rows = [dict(kind='setup', backend=backend, fan_in=n, oracle='blake2s', child_log_rows=12, setup_ms=1)]
                for sample in (0, 1):
                    rows.append(dict(kind='sample', backend=backend, fan_in=n, sample=sample,
                                     status='verified', warmup=sample == 0, negative_cases=8,
                                     prep_ms=1, prove_ms=2, verify_ms=3, total_certificate_bytes=4,
                                     public=[sample], child_proof_digests=[[sample]] * n))
                (d / 'stdout.jsonl').write_text('\n'.join(map(json.dumps, rows)) + '\n')

    def mutate_rows(self, name, fn):
        path = self.root / name / 'stdout.jsonl'
        rows = list(map(json.loads, path.read_text().splitlines()))
        fn(rows)
        path.write_text('\n'.join(map(json.dumps, rows)) + '\n')

    def test_complete_evidence_is_summarized(self):
        self.assertEqual(compare.summarize(self.root, 1)['status'], 'validated')
        self.assertTrue((self.root / 'TABLE.md').exists())

    def test_missing_and_duplicate_samples_are_rejected(self):
        self.mutate_rows('native-1', lambda rows: rows.pop())
        with self.assertRaises(ValueError): compare.summarize(self.root, 1)
        self.mutate_rows('native-1', lambda rows: rows.append(rows[1].copy()))
        with self.assertRaises(ValueError): compare.summarize(self.root, 1)

    def test_different_child_proof_bytes_are_rejected(self):
        self.mutate_rows('native-8', lambda rows: rows[2].update(child_proof_digests=[[99]] * 8))
        with self.assertRaises(ValueError): compare.summarize(self.root, 1)

    def test_failed_runner_is_rejected(self):
        path = self.root / 'vm-4' / 'result.json'
        result = json.loads(path.read_text()); result['returncode'] = 1
        path.write_text(json.dumps(result))
        with self.assertRaises(ValueError): compare.summarize(self.root, 1)


if __name__ == '__main__':
    unittest.main()
