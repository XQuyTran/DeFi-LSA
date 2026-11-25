"""Reader and normalization helpers for the AWS public blockchain dataset."""

import ast
import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from numbers import Integral, Real
from typing import Any, Iterable, Mapping

from .schemas import (
    normalize_block_record,
    normalize_contract_record,
    normalize_log_record,
    normalize_token_transfer_record,
    normalize_transaction_record,
    normalize_trace_record,
)


class AwsSchemaError(ValueError):
    """Raised when an AWS Parquet table cannot satisfy its required contract."""


@dataclass(frozen=True)
class AwsTableContract:
    """Minimal contract used to validate and scan one AWS table."""

    name: str
    required_columns: tuple[str, ...]
    identity_columns: tuple[str, ...]
    address_columns: tuple[str, ...] = ()
    block_column: str = "block_number"
    transaction_column: str = "transaction_hash"


AWS_TABLE_CONTRACTS: dict[str, AwsTableContract] = {
    "blocks": AwsTableContract(
        "blocks", ("number", "timestamp", "gas_used", "hash"), ("number",), block_column="number"
    ),
    "transactions": AwsTableContract(
        "transactions",
        ("hash", "block_number", "from_address", "to_address", "value", "gas", "gas_price", "nonce"),
        ("hash",),
        ("from_address", "to_address"),
        transaction_column="hash",
    ),
    "logs": AwsTableContract(
        "logs",
        ("transaction_hash", "log_index", "block_number", "address", "topics", "data"),
        ("transaction_hash", "log_index"),
        ("address",),
    ),
    "token_transfers": AwsTableContract(
        "token_transfers",
        ("transaction_hash", "log_index", "block_number", "token_address", "from_address", "to_address", "value"),
        ("transaction_hash", "log_index"),
        ("token_address", "from_address", "to_address"),
    ),
    "traces": AwsTableContract(
        "traces",
        ("transaction_hash", "trace_address", "block_number", "from_address", "to_address", "value"),
        ("transaction_hash", "trace_address"),
        ("from_address", "to_address"),
    ),
    "contracts": AwsTableContract(
        "contracts", ("address", "block_number"), ("address",), ("address",)
    ),
}


def estimate_block_date(block_number: int) -> date:
    """Estimate the UTC calendar date for an Ethereum mainnet block number."""
    if block_number >= 15537393:
        # Post-merge (block 15537393 on 2022-09-15 06:42:42 UTC, timestamp 1663224162)
        # Average slot time is 12.06s in practice due to occasional missed slots
        ts = 1663224162 + int((block_number - 15537393) * 12.06)
    else:
        # Pre-merge average block time was ~13.3 seconds
        ts = 1438269988 + int((block_number / 15537393) * (1663224162 - 1438269988))
    return datetime.fromtimestamp(ts, tz=timezone.utc).date()


class AwsPublicBlockchainAdapter:
    """Read AWS Ethereum Parquet data with an injectable offline query seam."""

    def __init__(
        self,
        query: Any | None = None,
        *,
        database: str = "ethereum",
        root: str = "s3://aws-public-blockchain/v1.0/eth/",
        region: str = "us-east-2",
        filesystem: Any | None = None,
    ):
        self.query = query
        self.database = database
        self.root = root.rstrip("/") + "/"
        self.region = region
        self.filesystem = filesystem

    def list_aws_partitions(self, start_date: str, end_date: str) -> list[dict[str, Any]]:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
        if end < start:
            raise ValueError("end_date must not precede start_date")
        return [
            {"date": (start + timedelta(days=offset)).isoformat()}
            for offset in range((end - start).days + 1)
        ]

    def fetch_aws_blocks(self, start_block: int, end_block: int) -> list[dict[str, Any]]:
        return self.fetch_table("blocks", start_block=start_block, end_block=end_block)

    def fetch_aws_transactions(self, start_block: int, end_block: int) -> list[dict[str, Any]]:
        return self.fetch_table("transactions", start_block=start_block, end_block=end_block)

    def fetch_aws_logs(self, start_block: int, end_block: int, addresses: Iterable[str] = ()) -> list[dict[str, Any]]:
        scope_addresses = list(addresses)
        rows = self.fetch_table(
            "logs", start_block=start_block, end_block=end_block, addresses=scope_addresses
        )
        return filter_aws_records_by_scope(rows, scope_addresses) if scope_addresses else list(rows)

    def fetch_table(
        self,
        table: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        start_block: int | None = None,
        end_block: int | None = None,
        transaction_hashes: Iterable[str] = (),
        addresses: Iterable[str] = (),
    ) -> list[dict[str, Any]]:
        """Read a table and apply supported filters before returning records."""
        return [
            row
            for batch in self.iter_table_batches(
                table,
                start_date=start_date,
                end_date=end_date,
                start_block=start_block,
                end_block=end_block,
                transaction_hashes=transaction_hashes,
                addresses=addresses,
            )
            for row in batch
        ]

    def iter_table_batches(
        self,
        table: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        start_block: int | None = None,
        end_block: int | None = None,
        transaction_hashes: Iterable[str] = (),
        addresses: Iterable[str] = (),
    ) -> Iterable[list[dict[str, Any]]]:
        """Yield filtered table rows in bounded batches."""
        yield from self._fetch(
            table,
            start_date=start_date,
            end_date=end_date,
            start_block=start_block,
            end_block=end_block,
            transaction_hashes=list(transaction_hashes),
            addresses=list(addresses),
        )

    def _fetch(self, table: str, **filters: Any) -> Iterable[list[dict[str, Any]]]:
        if table not in AWS_TABLE_CONTRACTS:
            raise ValueError(f"unsupported AWS table {table!r}")
        if self.query is not None:
            query_filters = {key: value for key, value in filters.items() if value is not None}
            rows = list(self.query(table, query_filters))
            if rows:
                yield rows
            return
        if self.filesystem is None:
            self.filesystem = _anonymous_filesystem(self.region)
        contract = AWS_TABLE_CONTRACTS[table]
        start_date = filters.get("start_date")
        end_date = filters.get("end_date")
        if start_date is None and end_date is None:
            start_block = filters.get("start_block")
            end_block = filters.get("end_block")
            if start_block is not None or end_block is not None:
                sb = start_block if start_block is not None else end_block
                eb = end_block if end_block is not None else start_block
                start_date = (estimate_block_date(sb) - timedelta(days=1)).isoformat()
                end_date = (estimate_block_date(eb) + timedelta(days=1)).isoformat()
        paths = self._partition_paths(table, start_date, end_date)
        if not paths:
            return []
        try:
            import pyarrow.dataset as ds
        except ImportError as exc:
            raise RuntimeError("AWS Parquet collection requires the 'parquet' optional dependency") from exc

        dataset_paths = []
        for path in paths:
            filesystem_path = path.removeprefix("s3://") if path.startswith("s3://") else path
            if path.startswith("s3://") and hasattr(self.filesystem, "glob"):
                matched = self.filesystem.glob(f"{filesystem_path}/*.parquet")
                if not matched and "/date=" not in path:
                    matched = self.filesystem.glob(f"{filesystem_path}/date=*/*.parquet")
                dataset_paths.extend(matched)
            else:
                dataset_paths.append(filesystem_path)
        if not dataset_paths:
            raise FileNotFoundError(f"no Parquet files found for AWS partitions: {paths}")
        dataset = ds.dataset(dataset_paths, filesystem=self.filesystem, format="parquet")
        self._validate_columns(dataset.schema.names, contract)
        expression = _build_filter_expression(ds, contract, filters, dataset.schema)
        scanner = dataset.scanner(filter=expression, batch_size=8192)
        for record_batch in scanner.to_batches():
            rows = _post_filter_rows(record_batch.to_pylist(), contract, filters)
            if rows:
                yield rows

    def _partition_paths(self, table: str, start_date: str | None, end_date: str | None) -> list[str]:
        if start_date is None and end_date is None:
            return [self._table_path(table)]
        if not start_date or not end_date:
            raise ValueError("start_date and end_date must be supplied together")
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
        if end < start:
            raise ValueError("end_date must not precede start_date")
        return [self._table_path(table, (start + timedelta(days=offset)).isoformat()) for offset in range((end - start).days + 1)]

    def _table_path(self, table: str, partition_date: str | None = None) -> str:
        suffix = table
        if partition_date is not None:
            suffix += f"/date={partition_date}"
        return f"{self.root}{suffix}"

    @staticmethod
    def _validate_columns(columns: Iterable[str], contract: AwsTableContract) -> None:
        available = set(columns)
        missing = sorted(set(contract.required_columns) - available)
        if missing:
            raise AwsSchemaError(
                f"AWS table {contract.name!r} is missing required columns: {', '.join(missing)}"
            )


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


def _anonymous_filesystem(region: str) -> Any:
    try:
        import s3fs
    except ImportError as exc:
        raise RuntimeError("AWS collection requires the 'aws' optional dependency") from exc
    return s3fs.S3FileSystem(anon=True, client_kwargs={"region_name": region})


def _aws_address(value: Any) -> Any:
    """Convert ABI-padded 32-byte addresses to canonical Ethereum addresses."""
    if isinstance(value, str) and value.startswith("0x") and len(value) == 66:
        try:
            int(value[2:], 16)
        except ValueError:
            return value
        return "0x" + value[-40:]
    return value


def _aws_trace_address(value: Any) -> Any:
    """Convert serialized AWS trace paths into the canonical list shape."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="strict")
    if isinstance(value, Integral):
        return [int(value)]
    if isinstance(value, Real) and value.is_integer():
        return [int(value)]
    tolist = getattr(value, "tolist", None)
    if callable(tolist):
        parsed = tolist()
        if isinstance(parsed, (list, tuple)):
            return parsed
        if isinstance(parsed, Integral):
            return [int(parsed)]
        if isinstance(parsed, Real) and parsed.is_integer():
            return [int(parsed)]
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return []
    if text.lower() in {"root", "none", "null"}:
        return []
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
        except (ValueError, SyntaxError, json.JSONDecodeError):
            continue
        if isinstance(parsed, (list, tuple)):
            return parsed
        if isinstance(parsed, Integral):
            return [int(parsed)]
        if isinstance(parsed, Real) and parsed.is_integer():
            return [int(parsed)]
    match = re.fullmatch(r"[\[\(\{]?\s*(\d+(?:\s*[,.;/]\s*\d+)*)\s*[\]\)\}]?", text)
    if match:
        return [int(part) for part in re.split(r"\s*[,.;/]\s*", match.group(1))]
    return value


def _build_filter_expression(
    dataset_module: Any,
    contract: AwsTableContract,
    filters: Mapping[str, Any],
    schema: Any | None = None,
) -> Any:
    expression = None
    if filters.get("start_block") is not None:
        expression = dataset_module.field(contract.block_column) >= filters["start_block"]
    if filters.get("end_block") is not None:
        condition = dataset_module.field(contract.block_column) <= filters["end_block"]
        expression = condition if expression is None else expression & condition
    transaction_hashes = [str(value).lower() for value in filters.get("transaction_hashes", ())]
    if transaction_hashes and contract.transaction_column in contract.required_columns:
        condition = dataset_module.field(contract.transaction_column).isin(transaction_hashes)
        expression = condition if expression is None else expression & condition
    addresses = [str(value).lower() for value in filters.get("addresses", ())]
    address_columns = contract.address_columns
    if schema is not None:
        address_columns = tuple(
            column
            for column in address_columns
            if column in schema.names and str(schema.field(column).type) != "null"
        )
    address_expression = None
    for column in address_columns if addresses else ():
        condition = dataset_module.field(column).isin(addresses)
        address_expression = condition if address_expression is None else address_expression | condition
    if address_expression is not None:
        expression = address_expression if expression is None else expression & address_expression
    return expression


def _post_filter_rows(rows: Iterable[Mapping[str, Any]], contract: AwsTableContract, filters: Mapping[str, Any]) -> list[dict[str, Any]]:
    start_block = filters.get("start_block")
    end_block = filters.get("end_block")
    hashes = {str(value).lower() for value in filters.get("transaction_hashes", ())}
    addresses = {str(value).lower() for value in filters.get("addresses", ())}
    selected = []
    for row in rows:
        block_number = row.get(contract.block_column)
        if start_block is not None and (block_number is None or int(block_number) < start_block):
            continue
        if end_block is not None and (block_number is None or int(block_number) > end_block):
            continue
        if (
            hashes
            and contract.transaction_column in contract.required_columns
            and str(row.get(contract.transaction_column, "")).lower() not in hashes
        ):
            continue
        if addresses and not any(str(row.get(column, "")).lower() in addresses for column in contract.address_columns):
            continue
        selected.append(dict(row))
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


def normalize_aws_block_record(
    record: Mapping[str, Any], event_id: str, source_sha256: str
) -> dict[str, Any]:
    """Normalize an AWS block row using the repository's canonical block schema."""
    raw = {
        "number": record.get("number", record.get("block_number")),
        "timestamp": _aws_timestamp(record.get("timestamp")),
        "gasUsed": record.get("gas_used"),
        "hash": record.get("hash"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_block_record(raw, event_id, source_sha256))


def normalize_aws_transaction_record(
    record: Mapping[str, Any],
    event_id: str,
    source_sha256: str,
    *,
    inclusion_reasons: tuple[str, ...] = ("direct_call",),
) -> dict[str, Any]:
    """Normalize an AWS transaction row using the repository's canonical schema."""
    raw = {
        "hash": record.get("hash"),
        "blockNumber": record.get("block_number"),
        "from": _aws_address(record.get("from_address", record.get("from"))),
        "to": _aws_address(record.get("to_address", record.get("to"))),
        "value": _aws_quantity(record.get("value"), "value"),
        "gas": record.get("gas"),
        "gasPrice": _aws_quantity(record.get("gas_price"), "gas_price"),
        "nonce": record.get("nonce"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(
        normalize_transaction_record(
            raw,
            event_id,
            source_sha256,
            inclusion_reasons=inclusion_reasons,
        )
    )


def normalize_aws_log_record(
    record: Mapping[str, Any], event_id: str, source_sha256: str
) -> dict[str, Any]:
    """Normalize an AWS log row using the repository's canonical schema."""
    raw = {
        "transactionHash": record.get("transaction_hash"),
        "logIndex": record.get("log_index"),
        "blockNumber": record.get("block_number"),
        "address": _aws_address(record.get("address")),
        "topics": record.get("topics"),
        "data": record.get("data"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_log_record(raw, event_id, source_sha256))


def normalize_aws_token_transfer_record(
    record: Mapping[str, Any], event_id: str, source_sha256: str
) -> dict[str, Any]:
    """Normalize an AWS token-transfer row into the canonical schema."""
    raw = {
        "transactionHash": record.get("transaction_hash"),
        "logIndex": record.get("log_index"),
        "blockNumber": record.get("block_number"),
        "tokenAddress": _aws_address(record.get("token_address")),
        "from": _aws_address(record.get("from_address", record.get("from"))),
        "to": _aws_address(record.get("to_address", record.get("to"))),
        "value": _aws_quantity(record.get("value"), "value"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_token_transfer_record(raw, event_id, source_sha256))


def normalize_aws_trace_record(
    record: Mapping[str, Any], event_id: str, source_sha256: str
) -> dict[str, Any]:
    """Normalize an AWS execution-trace row into the canonical schema."""
    raw = {
        "transactionHash": record.get("transaction_hash"),
        "traceAddress": _aws_trace_address(record.get("trace_address")),
        "blockNumber": record.get("block_number"),
        "from": _aws_address(record.get("from_address", record.get("from"))),
        "to": _aws_address(record.get("to_address", record.get("to"))),
        "value": _aws_quantity(record.get("value"), "value"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_trace_record(raw, event_id, source_sha256))


def normalize_aws_contract_record(
    record: Mapping[str, Any], event_id: str, source_sha256: str
) -> dict[str, Any]:
    """Normalize an AWS contract row into the canonical schema."""
    raw = {
        "address": _aws_address(record.get("address")),
        "blockNumber": record.get("block_number"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_contract_record(raw, event_id, source_sha256))


def _aws_quantity(value: Any, field_name: str) -> int:
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"AWS {field_name} must be an integer-valued quantity")
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ValueError(f"AWS {field_name} must be an integer-valued quantity")


def _aws_timestamp(value: Any) -> int:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    return _aws_quantity(value, "timestamp")


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
