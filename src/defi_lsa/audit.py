"""D2 coverage audits and readiness gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .checkpoints import Checkpoint, compute_pending_ranges
from .storage import read_jsonl_records


def _records(path: Path | None) -> list[dict[str, Any]]:
    return list(read_jsonl_records(path)) if path and path.exists() else []


def audit_block_coverage(requested_start: int, requested_end: int, path: Path | None) -> dict[str, int]:
    rows = _records(path)
    collected = {int(row.get("block_number", row.get("record_key", -1))) for row in rows}
    expected = set(range(requested_start, requested_end + 1))
    return {
        "requested_block_count": len(expected),
        "collected_block_count": len(collected & expected),
        "missing_block_count": len(expected - collected),
    }


def audit_registered_transaction_coverage(
    registered_hashes: Iterable[str], path: Path | None
) -> dict[str, Any]:
    expected = {value.lower() for value in registered_hashes}
    actual = {str(row.get("tx_hash", row.get("record_key", ""))).lower() for row in _records(path)}
    missing = sorted(expected - actual)
    return {
        "registered_exploit_tx_count": len(expected),
        "missing_exploit_tx_count": len(missing),
        "missing_exploit_tx_hashes": missing,
    }


def audit_receipt_coverage(tx_hashes: Iterable[str], path: Path | None) -> dict[str, Any]:
    expected = {value.lower() for value in tx_hashes}
    actual = {str(row.get("tx_hash", row.get("record_key", ""))).lower() for row in _records(path)}
    missing = sorted(expected - actual)
    return {"missing_receipt_count": len(missing), "missing_receipt_hashes": missing}


def audit_log_range_coverage(checkpoint: Checkpoint | None) -> dict[str, Any]:
    if checkpoint is None:
        return {
            "checkpoint_present": False,
            "failed_log_ranges": [],
            "pending_log_ranges": [],
        }
    completed = checkpoint.completed_ranges
    covered = sum(end - start + 1 for start, end in completed)
    requested = checkpoint.requested_end - checkpoint.requested_start + 1
    return {
        "checkpoint_present": True,
        "completed_block_count": covered,
        "completed_range_percentage": round(100 * covered / requested, 2),
        "pending_log_ranges": [
            list(item)
            for item in compute_pending_ranges(
                checkpoint.requested_start,
                checkpoint.requested_end,
                completed,
            )
        ],
        "failed_log_ranges": [
            [item.get("start"), item.get("end")] if isinstance(item, dict) else item
            for item in checkpoint.failed_ranges
        ],
    }


def audit_abi_coverage(addresses: Iterable[str], abi_dir: Path | None) -> dict[str, Any]:
    expected = {address.lower() for address in addresses}
    actual = {path.stem.lower() for path in abi_dir.glob("*.json")} if abi_dir and abi_dir.exists() else set()
    return {
        "abi_coverage_percentage": round(100 * len(expected & actual) / len(expected), 2) if expected else 100.0,
        "missing_abi_addresses": sorted(expected - actual),
    }


def audit_price_coverage(reports: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    reports = list(reports)
    return {
        "price_coverage_percentage_by_token": {
            str(report.get("coin_id", "")): report.get("coverage_percentage", 0.0)
            for report in reports
        },
        "maximum_consecutive_price_gap": max(
            (int(report.get("max_consecutive_gap_hours", 0)) for report in reports),
            default=0,
        ),
    }


def build_d2_gate_report(
    output_path: Path,
    *,
    block: Mapping[str, Any],
    transactions: Mapping[str, Any],
    receipts: Mapping[str, Any],
    logs: Mapping[str, Any],
    abi: Mapping[str, Any],
    prices: Mapping[str, Any],
    public_sources: Mapping[str, Any],
) -> dict[str, Any]:
    checks = {
        "missing_blocks": block.get("missing_block_count", 0) == 0,
        "missing_registered_transactions": transactions.get("missing_exploit_tx_count", 0) == 0,
        "missing_receipts": receipts.get("missing_receipt_count", 0) == 0,
        "failed_log_ranges": (
            logs.get("checkpoint_present", False)
            and not logs.get("pending_log_ranges")
            and not logs.get("failed_log_ranges")
        ),
        "abi_coverage": abi.get("abi_coverage_percentage", 0) == 100.0,
        "price_status": prices.get("status", "conditional") != "failed",
        "public_source_status": public_sources.get("status", "conditional") != "failed",
    }
    has_conditional_sources = any(
        source.get("status", "conditional") == "conditional"
        for source in (prices, public_sources)
    )
    status = (
        "GO"
        if all(checks.values()) and not has_conditional_sources
        else "CONDITIONAL_GO"
        if any(checks.values()) or has_conditional_sources
        else "NO_GO"
    )
    report = {
        "status": status,
        "checks": checks,
        "corrective_actions": [name for name, passed in checks.items() if not passed],
        "block": dict(block),
        "transactions": dict(transactions),
        "receipts": dict(receipts),
        "logs": dict(logs),
        "abi": dict(abi),
        "prices": dict(prices),
        "public_sources": dict(public_sources),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
