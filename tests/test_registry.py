import json
import unittest
from dataclasses import replace
from pathlib import Path

from defi_lsa.registry import (
    IncidentLeg,
    build_contract_scope,
    load_event_candidates,
    load_incident_legs,
    load_public_source_registry,
    load_token_registry,
    validate_executable_candidates,
    validate_incident_legs,
)
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

    def test_event_model_preserves_optional_collection_fields(self) -> None:
        candidate = load_event_candidates(CSV_PATH)[0]
        self.assertEqual(candidate.collection_start_utc, "2023-03-13T08:56:35Z")
        self.assertEqual(candidate.collection_end_utc, "2023-03-13T08:56:35Z")
        self.assertEqual(candidate.start_block, 16818024)
        self.assertEqual(candidate.end_block, 16818024)

    def test_metadata_registries_are_valid(self) -> None:
        self.assertGreater(len(load_token_registry(ROOT / "configs" / "tokens.json")), 0)
        self.assertEqual(
            len(load_public_source_registry(ROOT / "configs" / "public_sources.json")),
            3,
        )

    def test_incident_leg_address_is_added_to_contract_scope(self) -> None:
        candidate = load_event_candidates(CSV_PATH)[0]
        leg = IncidentLeg(
            leg_id="euler-representative",
            event_id=candidate.event_id,
            chain_id=1,
            affected_address="0x27182842e098f60e3d576794a5bffb0777e025d3",
            asset_pair="WETH/DAI",
            transaction_hash="0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",
            block_number=16818024,
            actor_address="0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
            role="attacker",
            evidence_urls=("https://etherscan.io/tx/0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",),
        )
        scope = build_contract_scope(candidate, [leg])
        self.assertIn(leg.affected_address, scope.addresses)

    def test_incident_leg_loader_rejects_duplicate_transactions(self) -> None:
        leg = {
            "leg_id": "leg-a",
            "event_id": "euler_2023-03-13",
            "chain_id": 1,
            "affected_address": "0x27182842e098f60e3d576794a5bffb0777e025d3",
            "asset_pair": "WETH/DAI",
            "transaction_hash": "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",
            "block_number": 16818024,
            "actor_address": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
            "role": "attacker",
            "evidence_urls": ["https://etherscan.io/"],
        }
        path = ROOT / "tests" / "_temporary_incident_legs.json"
        try:
            path.write_text(json.dumps([leg, {**leg, "leg_id": "leg-b"}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "one incident leg"):
                load_incident_legs(path)
        finally:
            path.unlink(missing_ok=True)

    def test_executable_events_require_frozen_windows(self) -> None:
        candidate = replace(
            load_event_candidates(CSV_PATH)[0],
            collection_start_utc=None,
            collection_end_utc=None,
            start_block=None,
            end_block=None,
        )
        legs = load_incident_legs(ROOT / "configs" / "incident_legs.json")
        with self.assertRaisesRegex(ValueError, "frozen fields"):
            validate_executable_candidates([candidate], legs)

    def test_conditional_events_may_remain_unfrozen(self) -> None:
        candidate = load_event_candidates(CSV_PATH)[1]
        validate_executable_candidates([candidate])

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
