import json

from defi_lsa.audit import audit_log_range_coverage, build_d2_gate_report
from defi_lsa.checkpoints import Checkpoint
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


def test_audit_gate_persists_effective_collection_range(tmp_path):
    report = build_d2_gate_report(
        tmp_path / "audit.json",
        block={"missing_block_count": 0},
        transactions={"missing_exploit_tx_count": 0},
        receipts={"missing_receipt_count": 0},
        logs={"checkpoint_present": True, "pending_log_ranges": [], "failed_log_ranges": []},
        abi={"abi_coverage_percentage": 100.0},
        prices={"status": "conditional"},
        public_sources={"status": "conditional"},
        effective_range={
            "start_block": 10,
            "end_block": 10,
            "registry_start_block": 1,
            "registry_end_block": 100,
            "overridden": True,
        },
    )

    assert report["effective_range"]["start_block"] == 10
    assert json.loads((tmp_path / "audit.json").read_text())["effective_range"]["overridden"] is True


def test_audit_gate_rejects_missing_log_checkpoint(tmp_path):
    report = build_d2_gate_report(
        tmp_path / "audit.json",
        block={},
        transactions={},
        receipts={},
        logs=audit_log_range_coverage(None),
        abi={"abi_coverage_percentage": 100.0},
        prices={"status": "conditional"},
        public_sources={"status": "conditional"},
    )

    assert report["checks"]["failed_log_ranges"] is False
    assert report["status"] == "CONDITIONAL_GO"


def test_audit_gate_rejects_partial_log_checkpoint(tmp_path):
    checkpoint = Checkpoint(
        event_id="test",
        collector="logs",
        scope_hash="a" * 64,
        requested_start=1,
        requested_end=10,
        completed_ranges=[(1, 5)],
        failed_ranges=[],
        updated_at_utc="2026-01-01T00:00:00Z",
        adapter_version="test",
    )

    logs = audit_log_range_coverage(checkpoint)
    report = build_d2_gate_report(
        tmp_path / "audit.json",
        block={},
        transactions={},
        receipts={},
        logs=logs,
        abi={"abi_coverage_percentage": 100.0},
        prices={"status": "conditional"},
        public_sources={"status": "conditional"},
    )

    assert logs["pending_log_ranges"] == [[6, 10]]
    assert report["checks"]["failed_log_ranges"] is False


def test_audit_gate_preserves_conditional_source_status(tmp_path):
    report = build_d2_gate_report(
        tmp_path / "audit.json",
        block={"missing_block_count": 0},
        transactions={"missing_exploit_tx_count": 0},
        receipts={"missing_receipt_count": 0},
        logs={
            "checkpoint_present": True,
            "pending_log_ranges": [],
            "failed_log_ranges": [],
        },
        abi={"abi_coverage_percentage": 100.0},
        prices={"status": "conditional"},
        public_sources={"status": "conditional"},
    )

    assert all(report["checks"].values())
    assert report["status"] == "CONDITIONAL_GO"


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
