"""Validate AWS table evidence against RPC or an explicit evidence-only policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from defi_lsa.aws import (  # noqa: E402
    AwsPublicBlockchainAdapter,
    normalize_aws_block_record,
    normalize_aws_contract_record,
    normalize_aws_log_record,
    normalize_aws_token_transfer_record,
    normalize_aws_transaction_record,
    normalize_aws_trace_record,
    reconcile_source_records,
)
from defi_lsa.collectors import json_rpc_client  # noqa: E402
from defi_lsa.schemas import (  # noqa: E402
    normalize_block_record,
    normalize_log_record,
    normalize_transaction_record,
)


EULER_TX_HASH = "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f"
EULER_EVENT_DATE = "2023-03-13"
EULER_BLOCK = 16818024
EVENT_DEFAULTS = {
    "euler": ("euler_2023-03-13", EULER_EVENT_DATE, EULER_BLOCK, EULER_TX_HASH),
    "kyber": (
        "kyberswap_elastic_2023-11-22",
        "2023-11-22",
        18630392,
        "0x485e08dc2b6a4b3aeadcb89c3d18a37666dc7d9424961a2091d6b3696792f0f3",
    ),
}


def _sha256_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_smoke(
    rpc_url: str,
    *,
    event: str = "euler",
    table: str = "logs",
    event_date: str | None = None,
    block_number: int | None = None,
    transaction_hash: str | None = None,
    output_path: Path | None = None,
) -> dict[str, object]:
    if event not in EVENT_DEFAULTS:
        raise ValueError(f"unsupported event {event!r}; expected one of {sorted(EVENT_DEFAULTS)}")
    if table not in {"blocks", "transactions", "logs", "token_transfers", "traces", "contracts"}:
        raise ValueError(f"unsupported AWS smoke table {table!r}")
    event_id, default_date, default_block, default_tx = EVENT_DEFAULTS[event]
    event_date = event_date or default_date
    block_number = default_block if block_number is None else block_number
    transaction_hash = transaction_hash or default_tx
    adapter = AwsPublicBlockchainAdapter()
    aws_rows = adapter.fetch_table(
        table,
        start_date=event_date,
        end_date=event_date,
        start_block=block_number,
        end_block=block_number,
        transaction_hashes=[transaction_hash],
    )
    source_sha = _sha256_json(aws_rows)
    normalizers = {
        "blocks": normalize_aws_block_record,
        "transactions": normalize_aws_transaction_record,
        "logs": normalize_aws_log_record,
        "token_transfers": normalize_aws_token_transfer_record,
        "traces": normalize_aws_trace_record,
        "contracts": normalize_aws_contract_record,
    }
    aws_records = [normalizers[table](row, event_id, source_sha) for row in aws_rows]

    rpc = json_rpc_client(rpc_url)
    rpc_records = []
    verification_mode = "evidence_only"
    if table == "logs":
        receipt = rpc("eth_getTransactionReceipt", [transaction_hash])
        if not receipt:
            raise RuntimeError(f"RPC returned no receipt for {transaction_hash}")
        receipt_sha = _sha256_json(receipt)
        for raw_log in receipt.get("logs", []):
            rpc_log = dict(raw_log)
            rpc_log.setdefault("transactionHash", transaction_hash)
            rpc_log.setdefault("chainId", 1)
            rpc_log["source"] = "rpc"
            rpc_records.append(asdict(normalize_log_record(rpc_log, event_id, receipt_sha)))
        verification_mode = "rpc_equivalent"
    elif table == "transactions":
        raw_transaction = rpc("eth_getTransactionByHash", [transaction_hash])
        if not raw_transaction:
            raise RuntimeError(f"RPC returned no transaction for {transaction_hash}")
        raw_transaction = dict(raw_transaction)
        raw_transaction.setdefault("hash", transaction_hash)
        raw_transaction.setdefault("chainId", 1)
        raw_transaction["source"] = "rpc"
        rpc_records.append(
            asdict(
                normalize_transaction_record(
                    raw_transaction, event_id, _sha256_json(raw_transaction)
                )
            )
        )
        verification_mode = "rpc_equivalent"
    elif table == "blocks":
        raw_block = rpc("eth_getBlockByNumber", [hex(block_number), False])
        if not raw_block:
            raise RuntimeError(f"RPC returned no block for {block_number}")
        raw_block = dict(raw_block)
        raw_block.setdefault("chainId", 1)
        raw_block["source"] = "rpc"
        rpc_records.append(
            asdict(normalize_block_record(raw_block, event_id, _sha256_json(raw_block)))
        )
        verification_mode = "rpc_equivalent"

    report = (
        reconcile_source_records(aws_records, rpc_records, "record_key")
        if verification_mode == "rpc_equivalent"
        else {"status": "evidence_only", "primary_count": len(aws_records), "conflicts": []}
    )
    result: dict[str, object] = {
        "event_id": event_id,
        "event": event,
        "table": table,
        "event_date": event_date,
        "transaction_hash": transaction_hash,
        "block_number": block_number,
        "aws_record_count": len(aws_records),
        "rpc_record_count": len(rpc_records),
        "aws_record_keys": sorted(record["record_key"] for record in aws_records),
        "rpc_record_keys": sorted(record["record_key"] for record in rpc_records),
        "verification_mode": verification_mode,
        "reconciliation": report,
        "status": "GO" if report["status"] in {"match", "evidence_only"} and aws_records else "NO_GO",
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", default=os.environ.get("ETH_RPC_URL"))
    parser.add_argument("--event", choices=sorted(EVENT_DEFAULTS), default="euler")
    parser.add_argument(
        "--table",
        choices=("blocks", "transactions", "logs", "token_transfers", "traces", "contracts"),
        default="logs",
    )
    parser.add_argument("--date", dest="event_date")
    parser.add_argument("--block", dest="block_number", type=int)
    parser.add_argument("--tx-hash", dest="transaction_hash")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.rpc_url:
        parser.error("--rpc-url or ETH_RPC_URL is required")

    result = validate_smoke(
        args.rpc_url,
        event=args.event,
        table=args.table,
        event_date=args.event_date,
        block_number=args.block_number,
        transaction_hash=args.transaction_hash,
        output_path=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
