import json
from pathlib import Path

import pytest
from eth_abi import encode

from defi_lsa.d3_decoding import event_topic0, function_selector
from defi_lsa.d3_pipeline import run_d3


def test_d3_requires_d2_gate(tmp_path: Path):
    events = tmp_path / "events.json"
    legs = tmp_path / "legs.json"
    events.write_text(json.dumps([{"event_id": "evt", "exploit_tx_hash": "0xtx"}]))
    legs.write_text("[]")

    with pytest.raises(FileNotFoundError, match="D2 gate report"):
        run_d3("evt", output_root=tmp_path, events_path=events, incident_legs_path=legs)


def test_d3_accepts_legacy_audit_output_root_layout(tmp_path: Path):
    events = tmp_path / "events.json"
    legs = tmp_path / "legs.json"
    report_dir = tmp_path / "evt"
    report_dir.mkdir(parents=True)
    (report_dir / "d2_collection_audit.json").write_text(
        json.dumps({"status": "NO_GO", "corrective_actions": []})
    )
    events.write_text(json.dumps([{"event_id": "evt", "exploit_tx_hash": "0xtx"}]))
    legs.write_text("[]")

    with pytest.raises(RuntimeError, match="D2 gate is NO_GO"):
        run_d3("evt", output_root=tmp_path, events_path=events, incident_legs_path=legs)


def test_d3_does_not_run_on_d2_no_go(tmp_path: Path):
    events = tmp_path / "events.json"
    legs = tmp_path / "legs.json"
    report_dir = tmp_path / "reports" / "evt"
    report_dir.mkdir(parents=True)
    (report_dir / "d2_collection_audit.json").write_text(
        json.dumps({"status": "NO_GO", "corrective_actions": ["collect logs"]})
    )
    events.write_text(json.dumps([{"event_id": "evt", "exploit_tx_hash": "0xtx"}]))
    legs.write_text("[]")

    with pytest.raises(RuntimeError, match="D2 gate is NO_GO"):
        run_d3("evt", output_root=tmp_path, events_path=events, incident_legs_path=legs)


def test_d3_publishes_canonical_artifacts_from_synthetic_d2_records(tmp_path: Path):
    event_id = "evt"
    contract = "0x" + "aa" * 20
    sender = "0x" + "11" * 20
    recipient = "0x" + "22" * 20
    tx_hash = "0x" + "bb" * 32
    transfer_event = {
        "type": "event",
        "name": "Transfer",
        "inputs": [
            {"name": "from", "type": "address", "indexed": True},
            {"name": "to", "type": "address", "indexed": True},
            {"name": "value", "type": "uint256", "indexed": False},
        ],
    }
    deposit_function = {
        "type": "function",
        "name": "deposit",
        "inputs": [{"name": "amount", "type": "uint256"}],
    }
    abi_dir = tmp_path / "data" / "raw" / "source" / "abi" / event_id
    abi_dir.mkdir(parents=True)
    (abi_dir / f"{contract}.json").write_text(
        json.dumps([transfer_event, deposit_function]), encoding="utf-8"
    )

    normalized = tmp_path / "data" / "raw" / "normalized"
    for category in ("logs", "transactions", "token_transfers"):
        (normalized / category).mkdir(parents=True)
    (normalized / "logs" / f"{event_id}.jsonl").write_text(
        json.dumps(
            {
                "event_id": event_id,
                "chain_id": 1,
                "tx_hash": tx_hash,
                "log_index": 0,
                "block_number": 1,
                "address": contract,
                "topics": [
                    event_topic0(transfer_event),
                    "0x" + ("00" * 12) + sender[2:],
                    "0x" + ("00" * 12) + recipient[2:],
                ],
                "data": "0x" + encode(["uint256"], [10]).hex(),
                "source_sha256": "sha",
                "normalization_version": "1.0.0",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    input_data = function_selector(deposit_function) + encode(["uint256"], [10]).hex()
    (normalized / "transactions" / f"{event_id}.jsonl").write_text(
        json.dumps(
            {
                "event_id": event_id,
                "chain_id": 1,
                "tx_hash": tx_hash,
                "block_number": 1,
                "from_address": sender,
                "to_address": contract,
                "input_data": input_data,
                "source_sha256": "sha",
                "normalization_version": "1.0.0",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (normalized / "token_transfers" / f"{event_id}.jsonl").write_text(
        json.dumps(
            {
                "event_id": event_id,
                "chain_id": 1,
                "tx_hash": tx_hash,
                "block_number": 1,
                "log_index": 0,
                "token_address": contract,
                "from_address": sender,
                "to_address": recipient,
                "value_wei": 10,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    report_dir = tmp_path / "reports" / event_id
    report_dir.mkdir(parents=True)
    (report_dir / "d2_collection_audit.json").write_text(
        json.dumps({"status": "GO"}), encoding="utf-8"
    )
    events = tmp_path / "events.json"
    events.write_text(json.dumps([{"event_id": event_id}]), encoding="utf-8")
    legs = tmp_path / "legs.json"
    legs.write_text("[]", encoding="utf-8")

    report = run_d3(
        event_id,
        output_root=tmp_path,
        events_path=events,
        incident_legs_path=legs,
    )

    assert report["status"] == "GO"
    assert (tmp_path / "data" / "decoded" / "decoded_events.parquet").exists()
    assert (tmp_path / "data" / "decoded" / "decoded_calls.parquet").exists()
    assert (report_dir / "unknown_event_report.json").exists()
    assert (report_dir / "d3_gate_report.json").exists()