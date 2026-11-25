"""D3 artifact pipeline over normalized D2 records."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .abi import LocalABIFallback
from .audit import enforce_d2_gate, load_artifact_records
from .d3_decoding import (
    aggregate_unknown_records,
    decode_input_data,
    decode_log,
    unknown_record,
)
from .d3_flow import (
    audit_flow_volume_by_token,
    build_balance_inputs,
    build_flow_legs,
    classify_addresses,
    classify_transaction,
    validate_incident_leg_ownership,
)
from .d3_schemas import D3_SCHEMA_VERSION
from .parquet import jsonl_to_parquet
from .registry import load_incident_legs
from .storage import normalized_path


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_parquet(rows: list[dict[str, Any]], schema_name: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    jsonl = output.with_suffix(".jsonl")
    with jsonl.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    jsonl_to_parquet(jsonl, schema_name, output)
    jsonl.unlink()


def _load_abi(address: str, abi_fallback: LocalABIFallback) -> tuple[list[dict[str, Any]], str]:
    metadata = abi_fallback.find_abi(address)
    if metadata is None:
        return [], ""
    return metadata.abi, metadata.checksum


def _decode_event_records(
    event_id: str,
    logs: list[dict[str, Any]],
    abi_fallback: LocalABIFallback,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    decoded: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    abi_cache: dict[str, tuple[list[dict[str, Any]], str]] = {}
    for log in logs:
        address = str(log.get("address", "")).lower()
        abi_cache.setdefault(address, _load_abi(address, abi_fallback))
        abi, _ = abi_cache[address]
        topics = [str(topic).lower() for topic in log.get("topics", [])]
        result = decode_log(log, abi) if abi else None
        if result is None:
            unknown.append(
                unknown_record(
                    event_id=event_id,
                    contract=address,
                    tx_hash=str(log.get("tx_hash", "")),
                    topic0=topics[0] if topics else "",
                    log_index=log.get("log_index"),
                    reason="missing ABI or unknown event topic",
                )
            )
            continue
        decoded.append(
            {
                "schema_version": D3_SCHEMA_VERSION,
                "event_id": event_id,
                "chain_id": log.get("chain_id", 0),
                "tx_hash": log.get("tx_hash", ""),
                "log_index": log.get("log_index", 0),
                "block_number": log.get("block_number", 0),
                "contract_address": address,
                "event_name": result["event_name"],
                "signature": result["signature"],
                "topic0": result["topic0"],
                "arguments_json": json.dumps(result["arguments"], sort_keys=True),
                "raw_topics": json.dumps(topics),
                "raw_data": str(log.get("data", "0x")),
                "source_sha256": log.get("source_sha256", ""),
                "normalization_version": log.get("normalization_version", ""),
            }
        )
    return decoded, aggregate_unknown_records(unknown)


def _decode_call_records(
    event_id: str,
    transactions: list[dict[str, Any]],
    abi_fallback: LocalABIFallback,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    decoded: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for transaction in transactions:
        address = str(transaction.get("to_address", "")).lower()
        abi, _ = _load_abi(address, abi_fallback)
        input_data = str(
            transaction.get("input_data", transaction.get("input", transaction.get("data", "0x")))
        )
        if input_data in {"", "0x"}:
            continue
        result = decode_input_data(input_data, abi) if abi else None
        if result is None:
            selector = input_data[:10].lower() if len(input_data) >= 10 else ""
            unknown.append(
                unknown_record(
                    event_id=event_id,
                    contract=address,
                    tx_hash=str(transaction.get("tx_hash", "")),
                    function_selector_value=selector,
                    reason="missing ABI or unknown function selector",
                )
            )
            continue
        decoded.append(
            {
                "schema_version": D3_SCHEMA_VERSION,
                "event_id": event_id,
                "chain_id": transaction.get("chain_id", 0),
                "tx_hash": transaction.get("tx_hash", ""),
                "block_number": transaction.get("block_number", 0),
                "contract_address": address,
                "function_name": result["function_name"],
                "signature": result["signature"],
                "selector": result["selector"],
                "arguments_json": json.dumps(result["arguments"], sort_keys=True),
                "raw_input": input_data,
                "source_sha256": transaction.get("source_sha256", ""),
                "normalization_version": transaction.get("normalization_version", ""),
            }
        )
    return decoded, aggregate_unknown_records(unknown)


def _publish_staged(staging: Path, output_root: Path, event_id: str) -> None:
    decoded_dir = output_root / "data" / "decoded"
    reports_dir = output_root / "reports" / event_id
    decoded_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    for source in staging.iterdir():
        destination = decoded_dir / source.name if source.suffix == ".parquet" else reports_dir / source.name
        os.replace(source, destination)


def _find_d2_report(output_root: Path, event_id: str) -> Path:
    """Find the persisted D2 report in supported CLI output layouts."""
    candidates = [
        output_root / "reports" / event_id / "d2_collection_audit.json",
        output_root / event_id / "d2_collection_audit.json",
    ]
    candidates.extend(
        sorted(
            path
            for path in output_root.rglob("d2_collection_audit.json")
            if path.parent.name == event_id
        )
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"D2 gate report not found for {event_id} below {output_root}"
    )


def run_d3(
    event_id: str,
    *,
    output_root: Path,
    events_path: Path,
    incident_legs_path: Path,
) -> dict[str, Any]:
    """Run D3 for one event and publish a complete artifact set."""
    d2_report_path = _find_d2_report(output_root, event_id)
    d2_report = _read_json(d2_report_path)
    enforce_d2_gate(d2_report)

    events = _read_json(events_path)
    event = next((item for item in events if item.get("event_id") == event_id), None)
    if event is None:
        raise ValueError(f"event not found: {event_id}")
    incident_legs = [
        leg for leg in load_incident_legs(incident_legs_path) if leg.event_id == event_id
    ]
    logs = load_artifact_records(normalized_path("logs", event_id, output_root))
    transactions = load_artifact_records(normalized_path("transactions", event_id, output_root))
    transfers = load_artifact_records(normalized_path("token_transfers", event_id, output_root))
    abi_fallback = LocalABIFallback(output_root / "data" / "raw" / "source" / "abi" / event_id)
    decoded_events, unknown_events = _decode_event_records(event_id, logs, abi_fallback)
    decoded_calls, unknown_calls = _decode_call_records(event_id, transactions, abi_fallback)
    unknown_records = aggregate_unknown_records(unknown_events + unknown_calls)

    decoded_events_by_tx: dict[str, list[dict[str, Any]]] = {}
    for row in decoded_events:
        decoded_events_by_tx.setdefault(str(row["tx_hash"]).lower(), []).append(row)
    decoded_calls_by_tx: dict[str, list[dict[str, Any]]] = {}
    for row in decoded_calls:
        decoded_calls_by_tx.setdefault(str(row["tx_hash"]).lower(), []).append(row)

    exploit_hashes = {
        value
        for value in {str(event.get("exploit_tx_hash", "")).lower()}
        if value
    }
    exploit_hashes.update(str(leg.transaction_hash).lower() for leg in incident_legs)
    role_by_address = {
        str(leg.actor_address).lower(): leg.role for leg in incident_legs
    }
    recovery_hashes = {
        str(leg.transaction_hash).lower()
        for leg in incident_legs
        if str(leg.role).strip().lower() in {"recovery", "protocol_recovery"}
    }
    flow_legs = build_flow_legs(
        transfers,
        decoded_events_by_tx=decoded_events_by_tx,
        decoded_calls_by_tx=decoded_calls_by_tx,
        exploit_hashes=exploit_hashes,
        recovery_hashes=recovery_hashes,
        core_addresses=(leg.affected_address for leg in incident_legs),
        role_by_address=role_by_address,
    )
    classifications: list[dict[str, Any]] = []
    classification_by_tx: dict[str, dict[str, Any]] = {}
    for transaction in transactions:
        tx_hash = str(transaction.get("tx_hash", ""))
        result = classify_transaction(
            transaction,
            decoded_events=[row for row in decoded_events if row["tx_hash"] == tx_hash],
            decoded_calls=[row for row in decoded_calls if row["tx_hash"] == tx_hash],
            exploit_hashes=exploit_hashes,
        )
        row = {
            "schema_version": D3_SCHEMA_VERSION,
            "event_id": event_id,
            "chain_id": transaction.get("chain_id", 0),
            "tx_hash": tx_hash,
            "block_number": transaction.get("block_number", 0),
            "primary_label": result["primary_label"],
            "matched_rules": json.dumps(result["matched_rules"]),
            "from_address": transaction.get("from_address", ""),
            "to_address": transaction.get("to_address", ""),
            "evidence": json.dumps(result["evidence"], sort_keys=True),
            "source_sha256": transaction.get("source_sha256", ""),
        }
        classifications.append(row)
        classification_by_tx[tx_hash.lower()] = result

    actor_rows: list[dict[str, Any]] = []
    for transaction in transactions:
        addresses = [transaction.get("from_address"), transaction.get("to_address")]
        addresses.extend(
            leg.actor_address for leg in incident_legs
            if leg.transaction_hash.lower() == str(transaction.get("tx_hash", "")).lower()
        )
        actor_rows.extend(
            classify_addresses(
                event_id=event_id,
                tx_hash=str(transaction.get("tx_hash", "")),
                addresses=addresses,
                role_by_address=role_by_address,
                chain_id=int(transaction.get("chain_id", 0)),
            )
        )

    resolved_legs = [
        {
            "schema_version": D3_SCHEMA_VERSION,
            "event_id": leg.event_id,
            "chain_id": leg.chain_id,
            "leg_id": leg.leg_id,
            "affected_address": leg.affected_address,
            "transaction_hash": leg.transaction_hash,
            "actor_address": leg.actor_address,
            "actor_role": leg.role,
            "asset_pair": leg.asset_pair,
            "pool_address": leg.affected_address,
            "token_address": "",
            "relationship_valid": "true",
            "evidence": json.dumps(list(leg.evidence_urls)),
        }
        for leg in incident_legs
    ]
    ownership = validate_incident_leg_ownership(
        exploit_hashes,
        resolved_legs,
        event_id=event_id,
    )
    if not ownership["passed"]:
        raise RuntimeError(f"incident-leg validation failed: {ownership}")
    leg_by_tx = {str(leg["transaction_hash"]).lower(): str(leg["leg_id"]) for leg in resolved_legs}
    actor_by_address = {row["address"]: row["actor_role"] for row in actor_rows}
    balance_rows = build_balance_inputs(
        transfers,
        classification_by_tx=classification_by_tx,
        actor_by_address=actor_by_address,
        leg_by_tx=leg_by_tx,
    )

    report = {
        "status": "GO",
        "event_id": event_id,
        "d2_gate_status": d2_report.get("status"),
        "decoded_event_count": len(decoded_events),
        "decoded_call_count": len(decoded_calls),
        "unknown_event_count": len(unknown_records),
        "flow_leg_count": len(flow_legs),
        "flow_label_counts": {
            label: sum(row["flow_label"] == label for row in flow_legs)
            for label in sorted({row["flow_label"] for row in flow_legs})
        },
        "flow_volume_audit_by_token": audit_flow_volume_by_token(flow_legs),
        "exploit_transaction_count": len(exploit_hashes - {""}),
        "attribution_row_count": len(actor_rows),
        "incident_leg_validation": ownership,
        "schema_version": D3_SCHEMA_VERSION,
    }

    with tempfile.TemporaryDirectory(dir=output_root, prefix=f".d3-{event_id}-") as temp:
        staging = Path(temp)
        _write_parquet(decoded_events, "decoded_events", staging / "decoded_events.parquet")
        _write_parquet(decoded_calls, "decoded_calls", staging / "decoded_calls.parquet")
        _write_parquet(flow_legs, "flow_legs", staging / "flow_legs.parquet")
        _write_parquet(classifications, "classified_transactions", staging / "classified_transactions.parquet")
        _write_parquet(actor_rows, "actor_roles", staging / "actor_roles.parquet")
        _write_parquet(resolved_legs, "incident_legs_resolved", staging / "incident_legs_resolved.parquet")
        _write_parquet(balance_rows, "balance_inputs", staging / "balance_inputs.parquet")
        _write_json(staging / "unknown_event_report.json", unknown_records)
        _write_json(staging / "d3_gate_report.json", report)
        _publish_staged(staging, output_root, event_id)
    return report
