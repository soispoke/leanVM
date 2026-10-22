"""Regression controls for complete tagged-tree benchmark accounting."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from summarize_trees import group, load, statements


class TreeRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.receipt = dict(command=['binary', '--depth', '1', '--chain', '1'], returncode=0,
                            stop_reason=None, harness_worktree_dirty=False, peak_rss_gib=1,
                            budget_gib=2, min_available_gib=50, source_commit='a', binary_sha256='b',
                            elapsed_s=2, hostname='host', kernel='kernel', cpu_model='cpu', affinity=[0],
                            worker_count='1', rust_toolchain='1.99.1', rustflags='native')
        expected = statements(1, 1)
        self.rows = []
        for level in range(2):
            self.rows.append(dict(kind='setup', level=level))
            for index, statement in enumerate(expected[level]):
                self.rows.append(dict(kind='proof', level=level, index=index, statement=list(statement),
                                      proof_bytes=100, proving_s=1, verification_ms=1, preparation_s=.1,
                                      verified=True, deferred_records=(1 << level) - 1))
        self.rows.append(dict(kind='complete', backend='vm', forwarded_deferred_claims=True,
                              chain=1, levels=1, root=list(expected[-1][0]), status='locally_verified',
                              single_fixed_circuit=False, lean_certificate=False, official_score=False))

    def save(self):
        (self.directory / 'started.json').write_text(json.dumps({'source_commit': self.receipt['source_commit']}))
        (self.directory / 'result.json').write_text(json.dumps(self.receipt))
        (self.directory / 'stdout.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in self.rows))

    def test_valid_group_and_preparation(self):
        self.save()
        result = group([self.directory, self.directory])
        self.assertEqual(result['trials'], 2)
        self.assertAlmostEqual(result['levels'][1]['preparation_plus_proving_s']['median'], 1.1)

    def test_rejects_bad_accounting_and_statements(self):
        reference_rows, reference_receipt = copy.deepcopy(self.rows), self.receipt.copy()
        changes = [
            lambda: self.rows.pop(1),
            lambda: self.rows.insert(1, self.rows[1].copy()),
            lambda: self.rows[1].update(index=8),
            lambda: self.rows[1].update(statement=[0] * 32),
            lambda: self.rows[-1].update(root=[0] * 32),
            lambda: self.rows[-1].update(official_score=True),
            lambda: self.rows[-2].update(deferred_records=0),
            lambda: self.rows[1].update(proof_bytes=(1 << 20) + 1),
            lambda: self.rows[1].update(proving_s=float('nan')),
            lambda: self.rows[1].update(preparation_s=-1),
            lambda: self.receipt.update(returncode=1),
            lambda: self.receipt.update(harness_worktree_dirty=True),
            lambda: self.receipt.update(peak_rss_gib=3),
            lambda: self.receipt.update(min_available_gib=39),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.rows, self.receipt = copy.deepcopy(reference_rows), reference_receipt.copy()
                change()
                self.save()
                with self.assertRaises(ValueError):
                    load(self.directory)

    def test_changed_receipt(self):
        self.save()
        (self.directory / 'started.json').write_text(json.dumps({'source_commit': 'changed'}))
        with self.assertRaises(ValueError):
            load(self.directory)


if __name__ == '__main__':
    unittest.main()
