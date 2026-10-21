"""Regression tests for incomplete or misleading benchmark records."""
import copy
import unittest
from run import validate


def records():
    rows = []
    for fan in (1, 2):
        for sample in (0, 1):
            for mode in ("pcs", "r1cs"):
                row = dict(process=0, fan_in=fan, sample=sample, interface=mode, warmup=sample == 0,
                           execution_gas=fan * (10971 if mode == "pcs" else 61))
                for key in ("client_us", "witness_us", "piop_prove_us", "opening_prove_us", "admission_piop_us",
                            "admission_openings_us", "hint_prep_us", "aggregate_prove_us", "aggregate_verify_us",
                            "evm_with_context_us", "coverage_us"):
                    row[key] = 1.0
                row["serial_warm_us"] = 8.0
                rows.append(row)
    return rows


class Validation(unittest.TestCase):
    def test_complete_matrix(self):
        validate(records(), 1, 1)

    def test_vm_transcript_has_its_own_clients(self):
        rows = [dict(r, interface="r1cs-vm", fan_in=4 * r["fan_in"], execution_gas=4 * r["fan_in"] * 61, client_us=3.0, serial_warm_us=10.0)
                for r in records() if r["interface"] == "r1cs"]
        validate(rows, 1, 1, fans=(4, 8), interfaces=("r1cs-vm",))
        with self.assertRaises(ValueError):
            validate(rows[1:], 1, 1, fans=(4, 8), interfaces=("r1cs-vm",))

    def test_missing_duplicate_and_mismatched_rows(self):
        good = records()
        bad = [good[:-1], good + [good[0]], []]
        for key, value in [("client_us", 2.0), ("warmup", False), ("execution_gas", 0),
                           ("aggregate_prove_us", float("nan")), ("serial_warm_us", 0)]:
            changed = copy.deepcopy(good)
            changed[0][key] = value
            bad.append(changed)
        for rows in bad:
            with self.assertRaises(ValueError):
                validate(rows, 1, 1)


if __name__ == "__main__":
    unittest.main()
