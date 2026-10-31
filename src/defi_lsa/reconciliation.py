"""Cross-source reconciliation reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .aws import reconcile_source_records


def reconcile_samples(
    output_path: Path,
    *,
    rpc_transactions: Iterable[Mapping[str, Any]],
    etherscan_transactions: Iterable[Mapping[str, Any]],
    aws_transactions: Iterable[Mapping[str, Any]],
    rpc_logs: Iterable[Mapping[str, Any]] = (),
    etherscan_logs: Iterable[Mapping[str, Any]] = (),
    aws_logs: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    rpc_transactions = list(rpc_transactions)
    rpc_logs = list(rpc_logs)
    report = {
        "transactions": {
            "rpc_vs_etherscan": reconcile_source_records(rpc_transactions, etherscan_transactions, "tx_hash"),
            "rpc_vs_aws": reconcile_source_records(rpc_transactions, aws_transactions, "tx_hash"),
        },
        "logs": {
            "rpc_vs_etherscan": reconcile_source_records(rpc_logs, etherscan_logs, "record_key"),
            "rpc_vs_aws": reconcile_source_records(rpc_logs, aws_logs, "record_key"),
        },
    }
    report["status"] = "match" if all(
        value["status"] == "match"
        for section in report.values() if isinstance(section, dict)
        for value in section.values()
    ) else "mismatch"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
