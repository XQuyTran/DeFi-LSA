"""Reader and normalization helpers for the AWS public blockchain dataset."""

from dataclasses import asdict, dataclass
from datetime import date, timedelta
from typing import Any, Iterable, Mapping

from .schemas import (
    normalize_block_record,
    normalize_log_record,
    normalize_transaction_record,
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
        "blocks", ("block_number", "timestamp", "gas_used", "hash"), ("block_number",)
    ),
    "transactions": AwsTableContract(
        "transactions",
        ("hash", "block_number", "from", "to", "value", "gas", "gas_price", "nonce"),
        ("hash",),
        ("from", "to"),
    ),
    "logs": AwsTableContract(
        "logs",
        ("transaction_hash", "log_index", "block_number", "address", "topics", "data"),
        ("transaction_hash", "log_index"),
        ("address",),
    ),
    "token_transfers": AwsTableContract(
        "token_transfers",
        ("transaction_hash", "log_index", "block_number", "token_address", "from", "to", "value"),
        ("transaction_hash", "log_index"),
        ("token_address", "from", "to"),
    ),
    "traces": AwsTableContract(
        "traces",
        ("transaction_hash", "trace_address", "block_number", "from", "to", "value"),
        ("transaction_hash", "trace_address"),
        ("from", "to"),
    ),
    "contracts": AwsTableContract(
        "contracts", ("address", "block_number"), ("address",), ("address",)
    ),
}


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
        return self._fetch("blocks", start_block=start_block, end_block=end_block)

    def fetch_aws_transactions(self, start_block: int, end_block: int) -> list[dict[str, Any]]:
        return self._fetch("transactions", start_block=start_block, end_block=end_block)

    def fetch_aws_logs(self, start_block: int, end_block: int, addresses: Iterable[str] = ()) -> list[dict[str, Any]]:
        scope_addresses = list(addresses)
        rows = self._fetch("logs", start_block=start_block, end_block=end_block, addresses=scope_addresses)
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
        return self._fetch(
            table,
            start_date=start_date,
            end_date=end_date,
            start_block=start_block,
            end_block=end_block,
            transaction_hashes=list(transaction_hashes),
            addresses=list(addresses),
        )

    def _fetch(self, table: str, **filters: Any) -> list[dict[str, Any]]:
        if table not in AWS_TABLE_CONTRACTS:
            raise ValueError(f"unsupported AWS table {table!r}")
        if self.query is not None:
            query_filters = {key: value for key, value in filters.items() if value is not None}
            return list(self.query(table, query_filters))
        if self.filesystem is None:
            self.filesystem = _anonymous_filesystem(self.region)
        contract = AWS_TABLE_CONTRACTS[table]
        paths = self._partition_paths(table, filters.get("start_date"), filters.get("end_date"))
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
                dataset_paths.extend(self.filesystem.glob(f"{filesystem_path}/*.parquet"))
            else:
                dataset_paths.append(filesystem_path)
        if not dataset_paths:
            raise FileNotFoundError(f"no Parquet files found for AWS partitions: {paths}")
        dataset = ds.dataset(dataset_paths, filesystem=self.filesystem, format="parquet")
        self._validate_columns(dataset.schema.names, contract)
        expression = _build_filter_expression(ds, contract, filters)
        table_data = dataset.to_table(filter=expression)
        rows = table_data.to_pylist()
        return _post_filter_rows(rows, contract, filters)

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


def _build_filter_expression(dataset_module: Any, contract: AwsTableContract, filters: Mapping[str, Any]) -> Any:
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
    if addresses:
        address_expression = None
        for condition in (dataset_module.field(column).isin(addresses) for column in contract.address_columns):
            address_expression = condition if address_expression is None else address_expression | condition
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
        if hashes and str(row.get(contract.transaction_column, "")).lower() not in hashes:
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
        "number": record.get("block_number"),
        "timestamp": record.get("timestamp"),
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
        "from": record.get("from"),
        "to": record.get("to"),
        "value": record.get("value"),
        "gas": record.get("gas"),
        "gasPrice": record.get("gas_price"),
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
        "address": record.get("address"),
        "topics": record.get("topics"),
        "data": record.get("data"),
        "chainId": record.get("chain_id", 1),
        "source": "aws",
    }
    return asdict(normalize_log_record(raw, event_id, source_sha256))


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
