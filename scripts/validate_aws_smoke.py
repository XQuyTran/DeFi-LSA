"""Validate the known Euler AWS log identities against an RPC receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from defi_lsa.aws import (  # noqa: E402
    AwsPublicBlockchainAdapter,
    normalize_aws_log_record,
    reconcile_source_records,
)
from defi_lsa.collectors import json_rpc_client  # noqa: E402
from defi_lsa.schemas import normalize_log_record  # noqa: E402


EULER_TX_HASH = "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f"
EULER_EVENT_DATE = "2023-03-13"
EULER_BLOCK = 16818024


def _sha256_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_smoke(rpc_url: str, *, output_path: Path | None = None) -> dict[str, object]:
    adapter = AwsPublicBlockchainAdapter()
    aws_rows = adapter.fetch_table(
        "logs",
        start_date=EULER_EVENT_DATE,
        end_date=EULER_EVENT_DATE,
        start_block=EULER_BLOCK,
        end_block=EULER_BLOCK,
        transaction_hashes=[EULER_TX_HASH],
    )
    aws_records = [
        normalize_aws_log_record(row, "euler_2023-03-13", _sha256_json(aws_rows))
        for row in aws_rows
    ]

    rpc = json_rpc_client(rpc_url)
    receipt = rpc("eth_getTransactionReceipt", [EULER_TX_HASH])
    if not receipt:
        raise RuntimeError(f"RPC returned no receipt for {EULER_TX_HASH}")

    rpc_logs = []
    receipt_sha = _sha256_json(receipt)
    for raw_log in receipt.get("logs", []):
        rpc_log = dict(raw_log)
        rpc_log.setdefault("transactionHash", EULER_TX_HASH)
        rpc_log.setdefault("chainId", 1)
        rpc_log["source"] = "rpc"
        rpc_logs.append(normalize_log_record(rpc_log, "euler_2023-03-13", receipt_sha).__dict__)

    report = reconcile_source_records(aws_records, rpc_logs, "record_key")
    result: dict[str, object] = {
        "event_id": "euler_2023-03-13",
        "transaction_hash": EULER_TX_HASH,
        "block_number": EULER_BLOCK,
        "aws_log_count": len(aws_records),
        "rpc_log_count": len(rpc_logs),
        "aws_record_keys": sorted(record["record_key"] for record in aws_records),
        "rpc_record_keys": sorted(record["record_key"] for record in rpc_logs),
        "reconciliation": report,
        "status": "GO" if report["status"] == "match" else "NO_GO",
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", default=os.environ.get("ETH_RPC_URL"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.rpc_url:
        parser.error("--rpc-url or ETH_RPC_URL is required")

    result = validate_smoke(args.rpc_url, output_path=args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
