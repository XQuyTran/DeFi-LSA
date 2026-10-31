"""AWS Public Blockchain Data normalization adapter."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


class AwsPublicBlockchainAdapter:
    """Small client-independent adapter; ``query`` is injected for offline tests."""

    def __init__(self, query: Any, *, database: str = "ethereum"):
        self.query = query
        self.database = database

    def list_aws_partitions(self, start_date: str, end_date: str) -> list[dict[str, Any]]:
        return list(self.query("partitions", {"database": self.database, "start_date": start_date, "end_date": end_date}))

    def fetch_aws_blocks(self, start_block: int, end_block: int) -> list[dict[str, Any]]:
        return list(self.query("blocks", {"start_block": start_block, "end_block": end_block}))

    def fetch_aws_transactions(self, start_block: int, end_block: int) -> list[dict[str, Any]]:
        return list(self.query("transactions", {"start_block": start_block, "end_block": end_block}))

    def fetch_aws_logs(self, start_block: int, end_block: int, addresses: Iterable[str] = ()) -> list[dict[str, Any]]:
        scope_addresses = list(addresses)
        rows = self.query(
            "logs",
            {"start_block": start_block, "end_block": end_block, "addresses": scope_addresses},
        )
        return filter_aws_records_by_scope(rows, scope_addresses) if scope_addresses else list(rows)


def filter_aws_records_by_scope(records: Iterable[Mapping[str, Any]], addresses: Iterable[str]) -> list[dict[str, Any]]:
    scope = {address.lower() for address in addresses}
    selected = []
    for record in records:
        sender = str(record.get("from", "")).lower()
        recipient = str(record.get("to", "")).lower()
        emitter = str(record.get("address", "")).lower()
        if sender in scope or recipient in scope or emitter in scope:
            selected.append(dict(record))
    return selected


def normalize_aws_block(record: Mapping[str, Any], event_id: str) -> dict[str, Any]:
    return {
        "record_key": str(record["block_number"]),
        "event_id": event_id,
        "chain_id": int(record.get("chain_id", 1)),
        "block_number": int(record["block_number"]),
        "block_timestamp": int(record["timestamp"]),
        "gas_used": int(record.get("gas_used", 0)),
        "block_hash": str(record["hash"]).lower(),
        "source": "aws",
    }


def reconcile_source_records(primary: Iterable[Mapping[str, Any]], secondary: Iterable[Mapping[str, Any]], key: str) -> dict[str, Any]:
    provenance_fields = {"source", "source_sha256", "normalization_version", "retrieved_at_utc"}

    def canonical(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            field: value
            for field, value in row.items()
            if field not in provenance_fields
        }

    left = {str(row[key]).lower(): row for row in primary}
    right = {str(row[key]).lower(): row for row in secondary}
    conflicts = [
        {
            "key": item,
            "primary": left[item],
            "secondary": right[item],
            "primary_canonical": canonical(left[item]),
            "secondary_canonical": canonical(right[item]),
        }
        for item in sorted(left.keys() & right.keys())
        if canonical(left[item]) != canonical(right[item])
    ]
    return {
        "primary_count": len(left),
        "secondary_count": len(right),
        "missing_from_secondary": sorted(left.keys() - right.keys()),
        "missing_from_primary": sorted(right.keys() - left.keys()),
        "conflicts": conflicts,
        "status": "match" if not conflicts and left.keys() == right.keys() else "mismatch",
    }
