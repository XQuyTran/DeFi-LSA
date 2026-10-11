import json

from defi_lsa.audit import build_d2_gate_report
from defi_lsa.aws import filter_aws_records_by_scope, reconcile_source_records
from defi_lsa.config import SourceConfig
from defi_lsa.observability import CollectionMetrics
from defi_lsa.provenance import SourceRecord, generate_source_manifest


def test_pending_epic_contracts_are_deterministic(tmp_path):
    config = SourceConfig()
    config.validate()
    assert filter_aws_records_by_scope(
        [{"from": "0xA", "to": "0xB"}, {"from": "0xC", "to": "0xD"}], ["0xa"]
    ) == [{"from": "0xA", "to": "0xB"}]
    assert reconcile_source_records([{"tx_hash": "0x1"}], [{"tx_hash": "0x1"}], "tx_hash")["status"] == "match"


def test_audit_gate_reports_corrective_actions(tmp_path):
    report = build_d2_gate_report(
        tmp_path / "audit.json",
        block={"missing_block_count": 1},
        transactions={"missing_exploit_tx_count": 0},
        receipts={"missing_receipt_count": 0},
        logs={"failed_log_ranges": []},
        abi={"abi_coverage_percentage": 100.0},
        prices={"status": "conditional"},
        public_sources={"status": "conditional"},
    )
    assert report["status"] == "CONDITIONAL_GO"
    assert "missing_blocks" in report["corrective_actions"]


def test_manifest_uses_explicit_retrieval_fields(tmp_path):
    artifact = tmp_path / "response.json"
    artifact.write_text("{}", encoding="utf-8")
    output = tmp_path / "manifest.json"
    generate_source_manifest(
        output,
        [SourceRecord("rpc", "http://localhost", "2026-01-01T00:00:00+00:00", "0" * 64, str(artifact), "test")],
    )
    record = json.loads(output.read_text(encoding="utf-8"))["records"][0]
    assert record["requested_at_utc"]
    assert record["artifact_sha256"]


def test_observability_writes_final_summary(tmp_path):
    metrics = CollectionMetrics(event_id="fixture", collector="logs")
    metrics.write_summary(tmp_path / "run.json")
    assert json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))["status"] == "completed"
