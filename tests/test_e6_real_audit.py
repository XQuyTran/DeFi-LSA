"""Tests for Epic 6: Real D2 Audit and Gate Integration.

Verifies that every audit function derives its measurements from actual
persisted artifacts, that the gate report correctly identifies corrective
actions, and that D3 is blocked on NO_GO.
"""

from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

from defi_lsa.audit import (
    audit_abi_coverage,
    audit_block_coverage,
    audit_duplicate_records,
    audit_log_range_coverage,
    audit_public_sources_coverage,
    audit_receipt_coverage,
    audit_registered_transaction_coverage,
    audit_registry_consistency,
    audit_source_manifest,
    audit_token_price_coverage,
    build_d2_gate_report,
    enforce_d2_gate,
    load_artifact_records,
    render_d2_gate_markdown,
)
from defi_lsa.checkpoints import Checkpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def _make_log_record(chain_id: int, tx_hash: str, log_index: int, block_number: int = 100) -> dict:
    return {
        "record_key": f"{chain_id}:{tx_hash}:{log_index}",
        "event_id": "test_event",
        "chain_id": chain_id,
        "tx_hash": tx_hash,
        "log_index": log_index,
        "block_number": block_number,
        "address": "0x" + "a" * 40,
        "topics": "[]",
        "data": "0x",
        "source": "rpc",
        "source_sha256": "a" * 64,
        "normalization_version": "1.0.0",
    }


def _make_tx_record(chain_id: int, tx_hash: str, block_number: int = 100) -> dict:
    return {
        "record_key": tx_hash,
        "event_id": "test_event",
        "chain_id": chain_id,
        "tx_hash": tx_hash,
        "block_number": block_number,
        "from_address": "0x" + "b" * 40,
        "to_address": "0x" + "c" * 40,
        "value_wei": 0,
        "gas": 21000,
        "gas_price": 10 ** 9,
        "nonce": 0,
        "inclusion_reasons": '["registry_anchor"]',
        "source": "rpc",
        "source_sha256": "b" * 64,
        "normalization_version": "1.0.0",
    }


def _make_checkpoint(
    start: int = 100,
    end: int = 110,
    completed: list[tuple[int, int]] | None = None,
    failed: list | None = None,
) -> Checkpoint:
    return Checkpoint(
        event_id="test_event",
        collector="logs",
        scope_hash="a" * 64,
        requested_start=start,
        requested_end=end,
        completed_ranges=completed or [],
        failed_ranges=failed or [],
        updated_at_utc="2026-01-01T00:00:00Z",
        adapter_version="test",
    )


# ---------------------------------------------------------------------------
# E6 – load_artifact_records (JSONL + Parquet)
# ---------------------------------------------------------------------------

class TestLoadArtifactRecords(unittest.TestCase):
    def test_load_jsonl(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "data.jsonl"
            _write_jsonl(p, [{"a": 1}, {"a": 2}])
            records = load_artifact_records(p)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["a"], 1)

    def test_missing_path_returns_empty(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            records = load_artifact_records(pathlib.Path(td) / "nonexistent.jsonl")
            self.assertEqual(records, [])

    def test_none_path_returns_empty(self):
        self.assertEqual(load_artifact_records(None), [])


# ---------------------------------------------------------------------------
# E6.4 – Registry consistency
# ---------------------------------------------------------------------------

class TestAuditRegistryConsistency(unittest.TestCase):
    def _base_event(self) -> dict:
        return {
            "event_id": "euler_2023-03-13",
            "protocol_or_vulnerable_contracts": ["0x27182842e098f60e3d576794a5bffb0777e025d3"],
            "attack_contracts": ["0x036cec1a199234fc02f72d29e596a09440825f1c"],
            "attacker_addresses": ["0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4"],
            "tokens_related": ["WETH", "DAI"],
        }

    def _base_scope(self) -> list[str]:
        return [
            "0x27182842e098f60e3d576794a5bffb0777e025d3",
            "0x036cec1a199234fc02f72d29e596a09440825f1c",
            "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
        ]

    def _token_registry(self) -> list[dict]:
        return [
            {"symbol": "WETH", "chain_id": 1, "address": "0x" + "c" * 40,
             "decimals": 18, "coingecko_id": "weth", "fallback_price_source": "chainlink", "status": "verified"},
            {"symbol": "DAI", "chain_id": 1, "address": "0x" + "d" * 40,
             "decimals": 18, "coingecko_id": "dai", "fallback_price_source": "chainlink", "status": "verified"},
        ]

    def _incident_legs(self) -> list[dict]:
        return [{
            "leg_id": "euler-leg-1",
            "event_id": "euler_2023-03-13",
            "transaction_hash": "0x" + "a" * 64,
        }]

    def _public_sources(self) -> list[dict]:
        return [{
            "event_id": "euler_2023-03-13",
            "official_urls": ["https://euler.finance/blog"],
            "search_queries": ["Euler Finance exploit"],
            "gdelt_aliases": ["Euler Finance"],
            "topic_ids": [],
        }]

    def test_all_pass(self):
        result = audit_registry_consistency(
            event=self._base_event(),
            scope_addresses=self._base_scope(),
            token_registry=self._token_registry(),
            incident_legs=self._incident_legs(),
            public_source_registry=self._public_sources(),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["contracts_not_in_scope"], [])
        self.assertEqual(result["tokens_missing_from_registry"], [])
        self.assertEqual(result["incident_legs_with_invalid_tx_hash"], [])
        self.assertEqual(result["public_source_config_issues"], [])

    def test_contract_not_in_scope(self):
        event = self._base_event()
        # Scope missing attack contract
        scope = ["0x27182842e098f60e3d576794a5bffb0777e025d3", "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4"]
        result = audit_registry_consistency(
            event=event,
            scope_addresses=scope,
            token_registry=self._token_registry(),
            incident_legs=self._incident_legs(),
            public_source_registry=self._public_sources(),
        )
        self.assertFalse(result["passed"])
        self.assertIn("0x036cec1a199234fc02f72d29e596a09440825f1c", result["contracts_not_in_scope"])

    def test_token_missing_from_registry(self):
        event = self._base_event()
        event["tokens_related"] = ["WETH", "UNKNOWN_TOKEN"]
        result = audit_registry_consistency(
            event=event,
            scope_addresses=self._base_scope(),
            token_registry=self._token_registry(),
            incident_legs=self._incident_legs(),
            public_source_registry=self._public_sources(),
        )
        self.assertFalse(result["passed"])
        self.assertIn("UNKNOWN_TOKEN", result["tokens_missing_from_registry"])

    def test_token_incomplete_fields(self):
        event = self._base_event()
        # DAI missing decimals
        registry = [
            {"symbol": "WETH", "chain_id": 1, "address": "0x" + "c" * 40,
             "decimals": 18, "coingecko_id": "weth", "fallback_price_source": "chainlink", "status": "verified"},
            {"symbol": "DAI", "chain_id": 1, "address": None,
             "decimals": None, "coingecko_id": "dai", "fallback_price_source": "chainlink", "status": "verified"},
        ]
        result = audit_registry_consistency(
            event=event,
            scope_addresses=self._base_scope(),
            token_registry=registry,
            incident_legs=self._incident_legs(),
            public_source_registry=self._public_sources(),
        )
        self.assertFalse(result["passed"])
        self.assertIn("DAI", result["tokens_incomplete_fields"])

    def test_incident_leg_invalid_tx_hash(self):
        legs = [{"leg_id": "bad-leg", "event_id": "euler_2023-03-13",
                 "transaction_hash": "not-a-hash"}]
        result = audit_registry_consistency(
            event=self._base_event(),
            scope_addresses=self._base_scope(),
            token_registry=self._token_registry(),
            incident_legs=legs,
            public_source_registry=self._public_sources(),
        )
        self.assertFalse(result["passed"])
        self.assertIn("bad-leg", result["incident_legs_with_invalid_tx_hash"])

    def test_no_public_source_entry(self):
        result = audit_registry_consistency(
            event=self._base_event(),
            scope_addresses=self._base_scope(),
            token_registry=self._token_registry(),
            incident_legs=self._incident_legs(),
            public_source_registry=[],  # empty
        )
        self.assertFalse(result["passed"])
        self.assertIn("no_entry_for_event", result["public_source_config_issues"])

    def test_public_source_entry_with_no_targets(self):
        ps = [{"event_id": "euler_2023-03-13", "official_urls": [], "search_queries": [],
               "gdelt_aliases": [], "topic_ids": []}]
        result = audit_registry_consistency(
            event=self._base_event(),
            scope_addresses=self._base_scope(),
            token_registry=self._token_registry(),
            incident_legs=self._incident_legs(),
            public_source_registry=ps,
        )
        self.assertFalse(result["passed"])
        self.assertIn("entry_has_no_targets", result["public_source_config_issues"])


# ---------------------------------------------------------------------------
# E6.3 – Block and log-range coverage
# ---------------------------------------------------------------------------

class TestAuditBlockCoverage(unittest.TestCase):
    def test_full_coverage(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "logs.jsonl"
            _write_jsonl(p, [
                {"block_number": 100, "record_key": "100"},
                {"block_number": 101, "record_key": "101"},
            ])
            result = audit_block_coverage(100, 101, p)
            self.assertEqual(result["missing_block_count"], 0)
            self.assertEqual(result["collected_block_count"], 2)

    def test_partial_coverage(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "logs.jsonl"
            _write_jsonl(p, [{"block_number": 100, "record_key": "100"}])
            result = audit_block_coverage(100, 102, p)
            self.assertEqual(result["missing_block_count"], 2)

    def test_no_artifact(self):
        result = audit_block_coverage(100, 100, None)
        self.assertEqual(result["missing_block_count"], 1)


class TestAuditLogRangeCoverage(unittest.TestCase):
    def test_no_checkpoint(self):
        result = audit_log_range_coverage(None)
        self.assertFalse(result["checkpoint_present"])
        self.assertEqual(result["pending_log_ranges"], [])

    def test_full_checkpoint(self):
        cp = _make_checkpoint(100, 110, completed=[(100, 110)])
        result = audit_log_range_coverage(cp)
        self.assertTrue(result["checkpoint_present"])
        self.assertEqual(result["completed_range_percentage"], 100.0)
        self.assertEqual(result["pending_log_ranges"], [])
        self.assertEqual(result["failed_log_ranges"], [])

    def test_partial_checkpoint_reports_pending(self):
        cp = _make_checkpoint(100, 110, completed=[(100, 105)])
        result = audit_log_range_coverage(cp)
        self.assertEqual(result["pending_log_ranges"], [[106, 110]])

    def test_failed_ranges_reported(self):
        cp = _make_checkpoint(100, 110, completed=[(100, 110)],
                              failed=[{"start": 103, "end": 104}])
        result = audit_log_range_coverage(cp)
        self.assertEqual(result["failed_log_ranges"], [[103, 104]])


# ---------------------------------------------------------------------------
# E6.2 – Transaction and receipt coverage
# ---------------------------------------------------------------------------

class TestAuditTransactionCoverage(unittest.TestCase):
    TX = "0x" + "a" * 64

    def test_exploit_tx_present(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "tx.jsonl"
            _write_jsonl(p, [_make_tx_record(1, self.TX)])
            result = audit_registered_transaction_coverage([self.TX], p)
            self.assertEqual(result["missing_exploit_tx_count"], 0)

    def test_exploit_tx_missing(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "tx.jsonl"
            _write_jsonl(p, [])
            result = audit_registered_transaction_coverage([self.TX], p)
            self.assertEqual(result["missing_exploit_tx_count"], 1)
            self.assertIn(self.TX.lower(), result["missing_exploit_tx_hashes"])

    def test_case_insensitive_match(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "tx.jsonl"
            _write_jsonl(p, [_make_tx_record(1, self.TX.upper())])
            result = audit_registered_transaction_coverage([self.TX.lower()], p)
            self.assertEqual(result["missing_exploit_tx_count"], 0)


class TestAuditReceiptCoverage(unittest.TestCase):
    TX = "0x" + "b" * 64

    def test_receipt_present(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "receipts.jsonl"
            _write_jsonl(p, [{"tx_hash": self.TX, "record_key": self.TX}])
            result = audit_receipt_coverage([self.TX], p)
            self.assertEqual(result["missing_receipt_count"], 0)

    def test_receipt_missing(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "receipts.jsonl"
            _write_jsonl(p, [])
            result = audit_receipt_coverage([self.TX], p)
            self.assertEqual(result["missing_receipt_count"], 1)


# ---------------------------------------------------------------------------
# E6.4 – Duplicate record detection with canonical keys
# ---------------------------------------------------------------------------

class TestAuditDuplicateRecords(unittest.TestCase):
    def test_no_duplicates(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "logs.jsonl"
            _write_jsonl(p, [
                _make_log_record(1, "0x" + "a" * 64, 0),
                _make_log_record(1, "0x" + "a" * 64, 1),
            ])
            result = audit_duplicate_records(p, "logs")
            self.assertEqual(result["duplicate_count"], 0)

    def test_duplicate_log_by_chain_tx_logindex(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "logs.jsonl"
            same = _make_log_record(1, "0x" + "a" * 64, 0)
            _write_jsonl(p, [same, same])
            result = audit_duplicate_records(p, "logs")
            self.assertEqual(result["duplicate_count"], 1)
            # Sample should contain the (chain_id, tx_hash, log_index) tuple
            self.assertEqual(len(result["duplicate_key_samples"]), 1)
            sample = result["duplicate_key_samples"][0]
            self.assertEqual(sample[0], "1")          # chain_id
            self.assertIn("a" * 64, sample[1])        # tx_hash
            self.assertEqual(sample[2], "0")          # log_index

    def test_duplicate_transactions(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "tx.jsonl"
            tx = _make_tx_record(1, "0x" + "b" * 64)
            _write_jsonl(p, [tx, tx])
            result = audit_duplicate_records(p, "transactions")
            self.assertEqual(result["duplicate_count"], 1)

    def test_missing_path_returns_zero(self):
        result = audit_duplicate_records(None, "logs")
        self.assertEqual(result["total_records"], 0)
        self.assertEqual(result["duplicate_count"], 0)


# ---------------------------------------------------------------------------
# E6.4 – Source manifest integrity
# ---------------------------------------------------------------------------

class TestAuditSourceManifest(unittest.TestCase):
    def _write_manifest(self, tmp_path: Path, records: list[dict]) -> Path:
        manifest = {
            "manifest_version": "1.0",
            "generated_at_utc": "2026-01-01T00:00:00+00:00",
            "records": records,
        }
        p = tmp_path / "source_manifest.json"
        p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return p

    def test_no_manifest(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            result = audit_source_manifest(pathlib.Path(td) / "nonexistent.json")
            self.assertFalse(result["manifest_present"])

    def test_valid_manifest(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            artifact = td_path / "response.json"
            artifact.write_text("{}", encoding="utf-8")
            sha = hashlib.sha256(b"{}").hexdigest()
            manifest_path = self._write_manifest(td_path, [{
                "artifact_path": str(artifact),
                "artifact_sha256": sha,
                "request_url": "https://api.example.com/data",
                "source_name": "rpc",
                "response_sha256": sha,
            }])
            result = audit_source_manifest(manifest_path)
            self.assertTrue(result["manifest_present"])
            self.assertEqual(result["checksum_failures"], [])
            self.assertEqual(result["missing_artifacts"], [])
            self.assertFalse(result["credential_leak_detected"])

    def test_checksum_failure(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            artifact = td_path / "response.json"
            artifact.write_text("{}", encoding="utf-8")
            wrong_sha = "b" * 64
            manifest_path = self._write_manifest(td_path, [{
                "artifact_path": str(artifact),
                "artifact_sha256": wrong_sha,
                "request_url": "https://api.example.com/data",
            }])
            result = audit_source_manifest(manifest_path)
            self.assertEqual(len(result["checksum_failures"]), 1)

    def test_missing_artifact_detected(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            manifest_path = self._write_manifest(td_path, [{
                "artifact_path": str(td_path / "missing.json"),
                "artifact_sha256": "a" * 64,
                "request_url": "https://api.example.com/data",
            }])
            result = audit_source_manifest(manifest_path)
            self.assertEqual(len(result["missing_artifacts"]), 1)

    def test_credential_leak_detected(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            artifact = td_path / "response.json"
            artifact.write_text("{}", encoding="utf-8")
            sha = hashlib.sha256(b"{}").hexdigest()
            # URL with embedded API key — redact_credentials should catch this
            leak_url = "https://api.etherscan.io/v2/api?apikey=SECRETKEY123&module=contract"
            manifest_path = self._write_manifest(td_path, [{
                "artifact_path": str(artifact),
                "artifact_sha256": sha,
                "request_url": leak_url,
            }])
            result = audit_source_manifest(manifest_path)
            self.assertTrue(result["credential_leak_detected"])


# ---------------------------------------------------------------------------
# E6.5 – Token price coverage
# ---------------------------------------------------------------------------

class TestAuditTokenPriceCoverage(unittest.TestCase):
    def _base_event(self) -> dict:
        return {
            "event_id": "euler_2023-03-13",
            "tokens_related": ["WETH"],
            "collection_start_utc": "2023-03-13T08:00:00Z",
            "collection_end_utc": "2023-03-13T10:00:00Z",
        }

    def _token_registry(self) -> list[dict]:
        return [{
            "symbol": "WETH",
            "chain_id": 1,
            "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "decimals": 18,
            "coingecko_id": "weth",
            "fallback_price_source": "chainlink",
            "status": "verified",
        }]

    def test_no_records_gives_zero_coverage(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            p = td_path / "prices.jsonl"
            _write_jsonl(p, [])
            result = audit_token_price_coverage(
                event=self._base_event(),
                token_registry=self._token_registry(),
                prices_path=p,
                price_coverage_reports_dir=None,
            )
            self.assertEqual(result["status"], "failed")
            self.assertIn("WETH", result["tokens_below_threshold"])

    def test_precomputed_report_loaded(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            reports_dir = td_path / "reports"
            reports_dir.mkdir()
            (reports_dir / "price_coverage_weth.json").write_text(
                json.dumps({"coin_id": "weth", "coverage_percentage": 100.0,
                             "missing_hours": [], "max_consecutive_gap_hours": 0}),
                encoding="utf-8",
            )
            result = audit_token_price_coverage(
                event=self._base_event(),
                token_registry=self._token_registry(),
                prices_path=None,
                price_coverage_reports_dir=reports_dir,
            )
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["per_token_coverage"]["WETH"]["coverage_percentage"], 100.0)

    def test_token_missing_from_registry(self):
        event = self._base_event()
        event["tokens_related"] = ["UNKNOWN"]
        result = audit_token_price_coverage(
            event=event,
            token_registry=self._token_registry(),
            prices_path=None,
            price_coverage_reports_dir=None,
        )
        self.assertIn("UNKNOWN", result["tokens_missing"])

    def test_pending_token_not_failed(self):
        token_registry = [{
            "symbol": "WETH",
            "chain_id": 1,
            "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "decimals": 18,
            "coingecko_id": "weth",
            "fallback_price_source": "chainlink",
            "status": "pending",  # pending — not verified
        }]
        result = audit_token_price_coverage(
            event=self._base_event(),
            token_registry=token_registry,
            prices_path=None,
            price_coverage_reports_dir=None,
        )
        self.assertNotIn("WETH", result.get("tokens_missing", []))
        pct = result["per_token_coverage"]["WETH"].get("coverage_percentage")
        self.assertIsNone(pct)


# ---------------------------------------------------------------------------
# E6.5 – Public source query-level coverage
# ---------------------------------------------------------------------------

class TestAuditPublicSourcesCoverage(unittest.TestCase):
    def _base_event(self) -> dict:
        return {"event_id": "euler_2023-03-13"}

    def _public_sources(self) -> list[dict]:
        return [{
            "event_id": "euler_2023-03-13",
            "official_urls": ["https://euler.finance/blog/exploit"],
            "topic_ids": [],
            "search_queries": ["Euler Finance exploit"],
            "gdelt_aliases": ["Euler Finance"],
        }]

    def test_all_covered(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            normalized = td_path / "normalized"
            # Protocol records covering the official URL
            _write_jsonl(normalized / "protocol" / "euler_2023-03-13.jsonl", [
                {"url": "https://euler.finance/blog/exploit", "title": "Exploit blog", "record_key": "k1",
                 "event_id": "euler_2023-03-13", "canonical_url": "https://euler.finance/blog/exploit",
                 "published_at_utc": "2023-03-13T12:00:00Z", "source": "protocol",
                 "source_sha256": "a" * 64, "normalization_version": "1.0.0"},
            ])
            # GDELT records covering query and alias
            _write_jsonl(normalized / "gdelt" / "euler_2023-03-13.jsonl", [
                {"url": "https://news.example.com/euler", "title": "Euler Finance exploit news",
                 "record_key": "k2", "event_id": "euler_2023-03-13",
                 "canonical_url": "https://news.example.com/euler",
                 "published_at_utc": "2023-03-13T14:00:00Z", "source": "gdelt",
                 "source_sha256": "b" * 64, "normalization_version": "1.0.0"},
            ])
            result = audit_public_sources_coverage(
                event=self._base_event(),
                public_source_registry=self._public_sources(),
                normalized_base=normalized,
            )
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["uncovered_targets"], [])

    def test_uncovered_official_url(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            normalized = td_path / "normalized"
            # Empty records — nothing covered
            result = audit_public_sources_coverage(
                event=self._base_event(),
                public_source_registry=self._public_sources(),
                normalized_base=normalized,
            )
            self.assertEqual(result["status"], "conditional")
            self.assertTrue(len(result["uncovered_targets"]) > 0)

    def test_no_public_source_entry(self):
        result = audit_public_sources_coverage(
            event=self._base_event(),
            public_source_registry=[],
            normalized_base=None,
        )
        self.assertEqual(result["status"], "failed")

    def test_copyright_violation_detected(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            normalized = td_path / "normalized"
            # GDELT record with full body
            _write_jsonl(normalized / "gdelt" / "euler_2023-03-13.jsonl", [
                {"title": "Euler Finance story", "full_body": "This is the full article body...",
                 "url": "https://news.example.com", "record_key": "k1",
                 "event_id": "euler_2023-03-13", "canonical_url": "https://news.example.com",
                 "published_at_utc": "2023-03-13T14:00:00Z", "source": "gdelt",
                 "source_sha256": "c" * 64, "normalization_version": "1.0.0"},
            ])
            result = audit_public_sources_coverage(
                event=self._base_event(),
                public_source_registry=self._public_sources(),
                normalized_base=normalized,
            )
            self.assertTrue(result["copyright_violation_detected"])


# ---------------------------------------------------------------------------
# E6.6 – Gate report JSON + Markdown
# ---------------------------------------------------------------------------

class TestBuildD2GateReport(unittest.TestCase):
    def _all_pass_inputs(self) -> dict:
        return {
            "block": {"missing_block_count": 0},
            "transactions": {"missing_exploit_tx_count": 0},
            "receipts": {"missing_receipt_count": 0},
            "logs": {
                "checkpoint_present": True,
                "pending_log_ranges": [],
                "failed_log_ranges": [],
            },
            "abi": {"abi_coverage_percentage": 100.0},
            "prices": {"status": "ok"},
            "public_sources": {"status": "ok"},
        }

    def test_go_status_all_pass(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            report = build_d2_gate_report(p, **self._all_pass_inputs())
            self.assertEqual(report["status"], "GO")
            self.assertEqual(report["corrective_actions"], [])
            self.assertTrue(p.exists())

    def test_no_go_when_all_fail(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            report = build_d2_gate_report(
                p,
                block={"missing_block_count": 10},
                transactions={"missing_exploit_tx_count": 1},
                receipts={"missing_receipt_count": 1},
                logs={"checkpoint_present": False, "pending_log_ranges": [], "failed_log_ranges": []},
                abi={"abi_coverage_percentage": 0.0},
                prices={"status": "failed"},
                public_sources={"status": "failed"},
            )
            self.assertEqual(report["status"], "NO_GO")

    def test_conditional_go_with_conditional_sources(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            inputs = self._all_pass_inputs()
            inputs["prices"] = {"status": "conditional"}
            report = build_d2_gate_report(p, **inputs)
            self.assertEqual(report["status"], "CONDITIONAL_GO")

    def test_copyright_violation_blocks_unqualified_go(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            inputs = self._all_pass_inputs()
            inputs["public_sources"]["copyright_violation_detected"] = True
            report = build_d2_gate_report(p, **inputs)
            self.assertEqual(report["status"], "CONDITIONAL_GO")
            self.assertFalse(report["checks"]["public_source_copyright_compliance"])
            self.assertIn("public_source_copyright_compliance", report["corrective_actions"])

    def test_registry_consistency_check_included(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            inputs = self._all_pass_inputs()
            registry_consistency = {"passed": False, "contracts_not_in_scope": ["0x123"]}
            report = build_d2_gate_report(p, **inputs, registry_consistency=registry_consistency)
            self.assertIn("registry_consistency", report["checks"])
            self.assertFalse(report["checks"]["registry_consistency"])
            self.assertIn("registry_consistency", report["corrective_actions"])

    def test_duplicate_check_included(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            inputs = self._all_pass_inputs()
            report = build_d2_gate_report(p, **inputs,
                                          duplicates={"total_duplicate_count": 2, "by_schema": {}})
            self.assertIn("no_duplicate_records", report["checks"])
            self.assertFalse(report["checks"]["no_duplicate_records"])

    def test_source_manifest_check_included(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "audit.json"
            inputs = self._all_pass_inputs()
            report = build_d2_gate_report(p, **inputs, source_manifest={
                "manifest_present": True,
                "checksum_failures": [],
                "missing_artifacts": [],
                "credential_leak_detected": False,
            })
            self.assertIn("source_manifest_valid", report["checks"])
            self.assertTrue(report["checks"]["source_manifest_valid"])


class TestRenderD2GateMarkdown(unittest.TestCase):
    def test_markdown_written(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            json_path = td_path / "audit.json"
            md_path = td_path / "audit.md"
            report = build_d2_gate_report(
                json_path,
                block={"missing_block_count": 0},
                transactions={"missing_exploit_tx_count": 0},
                receipts={"missing_receipt_count": 0},
                logs={"checkpoint_present": True, "pending_log_ranges": [], "failed_log_ranges": []},
                abi={"abi_coverage_percentage": 100.0},
                prices={"status": "ok"},
                public_sources={"status": "ok"},
            )
            render_d2_gate_markdown(report, md_path)
            self.assertTrue(md_path.exists())
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("GO", content)
            self.assertIn("| Check |", content)

    def test_markdown_contains_no_go_badge(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            td_path = pathlib.Path(td)
            report = {
                "status": "NO_GO",
                "checks": {"missing_blocks": False},
                "corrective_actions": ["missing_blocks"],
                "block": {"missing_block_count": 5},
                "prices": {},
                "public_sources": {},
            }
            md_path = td_path / "audit.md"
            render_d2_gate_markdown(report, md_path)
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("NO_GO", content)
            self.assertIn("missing_block_count: 5", content)

    def test_markdown_maps_transaction_action_to_transactions_section(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            report = {
                "status": "NO_GO",
                "checks": {"missing_registered_transactions": False},
                "corrective_actions": ["missing_registered_transactions"],
                "transactions": {"missing_exploit_tx_hashes": ["0xmissing"]},
            }
            md_path = pathlib.Path(td) / "audit.md"
            render_d2_gate_markdown(report, md_path)
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("missing_exploit_tx_hashes: ['0xmissing']", content)


# ---------------------------------------------------------------------------
# E6.7 – enforce_d2_gate
# ---------------------------------------------------------------------------

class TestEnforceD2Gate(unittest.TestCase):
    def test_go_does_not_raise(self):
        enforce_d2_gate({"status": "GO"})  # must not raise

    def test_conditional_go_does_not_raise(self):
        enforce_d2_gate({"status": "CONDITIONAL_GO"})  # must not raise

    def test_no_go_raises_runtime_error(self):
        report = {"status": "NO_GO", "corrective_actions": ["missing_blocks"]}
        with self.assertRaises(RuntimeError) as ctx:
            enforce_d2_gate(report)
        self.assertIn("NO_GO", str(ctx.exception))
        self.assertIn("missing_blocks", str(ctx.exception))


# ---------------------------------------------------------------------------
# CLI – end-to-end audit command without real collection
# ---------------------------------------------------------------------------

class TestAuditCLI(unittest.TestCase):
    def test_audit_command_produces_json_and_markdown(self, tmp_path=None):
        """defi_lsa audit runs without collection and produces both report files."""
        import tempfile, pathlib, subprocess, sys
        with tempfile.TemporaryDirectory() as td:
            output_dir = pathlib.Path(td)
            result = subprocess.run(
                [sys.executable, "-m", "defi_lsa", "audit",
                 "--event", "euler_2023-03-13",
                 "--output", str(output_dir)],
                capture_output=True, text=True,
            )
            # Must produce output (NO_GO expected without real artifacts)
            status_line = result.stdout.strip()
            self.assertIn(status_line, ("NO_GO", "CONDITIONAL_GO", "GO"))
            self.assertEqual(status_line, "NO_GO")
            self.assertEqual(result.returncode, 2)
            # JSON report must be written
            json_path = output_dir / "euler_2023-03-13" / "d2_collection_audit.json"
            self.assertTrue(json_path.exists(), f"JSON report not found: {json_path}")
            # Markdown report must be written
            md_path = output_dir / "euler_2023-03-13" / "d2_collection_audit.md"
            self.assertTrue(md_path.exists(), f"MD report not found: {md_path}")
            # Corrective actions populated
            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIn("status", parsed)
            self.assertIn("corrective_actions", parsed)

    def test_audit_no_go_returns_exit_code_2(self, tmp_path=None):
        """NO_GO status must translate to exit code 2."""
        import tempfile, pathlib, subprocess, sys
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [sys.executable, "-m", "defi_lsa", "audit",
                 "--event", "euler_2023-03-13",
                 "--output", pathlib.Path(td)],
                capture_output=True, text=True,
            )
            # Empty output root → NO_GO → exit code 2
            if result.stdout.strip() == "NO_GO":
                self.assertEqual(result.returncode, 2)

    def test_audit_accepts_kyber_event_alias(self, tmp_path=None):
        """The audit command resolves the same Kyber alias as collection."""
        import pathlib, subprocess, sys, tempfile

        with tempfile.TemporaryDirectory() as td:
            output_dir = pathlib.Path(td)
            result = subprocess.run(
                [sys.executable, "-m", "defi_lsa", "audit",
                 "--event", "kyber",
                 "--output", str(output_dir)],
                capture_output=True, text=True,
            )

            self.assertNotIn("No event matched", result.stderr)
            self.assertTrue(
                (output_dir / "kyberswap_elastic_2023-11-22" / "d2_collection_audit.json").exists()
            )

    def test_audit_strict_flag_fails_conditional(self, tmp_path=None):
        """--strict causes CONDITIONAL_GO to exit with code 2."""
        import tempfile, pathlib, subprocess, sys
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [sys.executable, "-m", "defi_lsa", "audit",
                 "--event", "euler_2023-03-13",
                 "--output", pathlib.Path(td),
                 "--strict"],
                capture_output=True, text=True,
            )
            status = result.stdout.strip()
            if status in ("NO_GO", "CONDITIONAL_GO"):
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
