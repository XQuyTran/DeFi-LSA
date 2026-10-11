import unittest
from pathlib import Path

from defi_lsa.registry import build_contract_scope, load_event_candidates
from defi_lsa.quality import audit_unknown_flows


ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "raw" / "event_candidates.csv"


class RegistryTests(unittest.TestCase):
    def test_candidates_are_valid_and_unique(self) -> None:
        candidates = load_event_candidates(CSV_PATH)
        self.assertEqual(
            [candidate.event_id for candidate in candidates],
            ["euler_2023-03-13", "curve_vyper_2023-07-30", "kyberswap_elastic_2023-11-22"],
        )

    def test_contract_scope_is_deduplicated_and_normalized(self) -> None:
        candidate = load_event_candidates(CSV_PATH)[0]
        scope = build_contract_scope(candidate)
        self.assertEqual(scope.chain_id, 1)
        self.assertEqual(len(scope.addresses), len(set(scope.addresses)))
        self.assertTrue(all(address == address.lower() for address in scope.addresses))

    def test_curve_scope_contains_multiple_registered_addresses(self) -> None:
        candidate = load_event_candidates(CSV_PATH)[1]
        scope = build_contract_scope(candidate)
        self.assertGreaterEqual(len(scope.addresses), 5)

    def test_unknown_flow_gate_uses_value_share(self) -> None:
        audit = audit_unknown_flows(
            [
                {"amount": 95, "classification": "swap"},
                {"amount": 5, "classification": "unknown"},
            ]
        )
        self.assertTrue(audit.passed)
        self.assertEqual(audit.unknown_share, 0.05)

    def test_unknown_flow_gate_fails_above_threshold(self) -> None:
        audit = audit_unknown_flows(
            [
                {"amount": 94, "classification": "swap"},
                {"amount": 6, "classification": "unknown"},
            ]
        )
        self.assertFalse(audit.passed)


if __name__ == "__main__":
    unittest.main()
