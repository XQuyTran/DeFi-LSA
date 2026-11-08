"""Parquet conversion utilities for normalized JSONL records (A16).

Convert normalized JSONL files produced by the DeFi-LSA pipeline into
Parquet format using PyArrow. Integer quantities are preserved exactly;
``value_wei`` is stored as fixed-size 32-byte binary and other integer
quantities are stored as ``int64``.

Optional dependency: ``pyarrow``
  Install with:  pip install pyarrow>=14.0
  This module intentionally omits pyarrow from pyproject.toml; it is an
  optional dependency that collectors and analysts install as needed.

Usage example::

    from pathlib import Path
    from defi_lsa.parquet import jsonl_to_parquet

    rows = jsonl_to_parquet(
        Path("blocks.jsonl"),
        schema_name="blocks",
        output_path=Path("blocks.parquet"),
        partition_by=["event_id"],
        verify_row_count=True,
    )
    print(f"Wrote {rows} rows")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# PyArrow type mapping per schema
# ---------------------------------------------------------------------------

# Each entry maps field_name -> pyarrow DataType factory string.
# Fields absent from a schema's map default to pa.string().
# We use string names so the import stays deferred until the function is called.

_INT64_FIELDS: frozenset[str] = frozenset(
    {
        # BlockRecord
        "chain_id",
        "block_number",
        "block_timestamp",
        "gas_used",
        # TransactionRecord / ReceiptRecord
        "gas",
        "gas_price",
        "nonce",
        "block_number",
        "status",
        "log_count",
        # LogRecord
        "log_index",
        # PriceRecord
        "source_timestamp",
    }
)

_FLOAT64_FIELDS: frozenset[str] = frozenset({"usd_price"})
_UINT256_BINARY_FIELDS: frozenset[str] = frozenset({"value_wei"})

# Fields that are stored as JSON arrays (topics, inclusion_reasons) — they
# are serialised as JSON strings in JSONL and decoded back to lists for Arrow.
_JSON_LIST_FIELDS: frozenset[str] = frozenset({"topics", "inclusion_reasons"})
_JSON_INT_LIST_FIELDS: frozenset[str] = frozenset({"trace_address"})

# ---------------------------------------------------------------------------
# Supported schema names
# ---------------------------------------------------------------------------

_SUPPORTED_SCHEMAS: frozenset[str] = frozenset(
    {
        "blocks",
        "transactions",
        "receipts",
        "logs",
        "prices",
        "public_info",
        "token_transfers",
        "traces",
        "contracts",
    }
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def jsonl_to_parquet(
    jsonl_path: Path,
    schema_name: str,
    output_path: Path,
    *,
    partition_by: list[str] | None = None,
    verify_row_count: bool = True,
) -> int:
    """Convert a normalized JSONL file to Parquet.

    Each line of *jsonl_path* must be a JSON object produced by one of the
    ``normalize_*_record`` functions in :mod:`defi_lsa.schemas`.  Tuple fields
    (``topics``, ``inclusion_reasons``) must be serialised as JSON arrays.

    Args:
        jsonl_path: Path to the input JSONL file.
        schema_name: Which normalized schema this file contains.  Must be one
            of ``"blocks"``, ``"transactions"``, ``"receipts"``, ``"logs"``,
            ``"prices"``, ``"public_info"``, ``"token_transfers"``,
            ``"traces"``, or ``"contracts"``.
        output_path: Destination ``.parquet`` file (or directory when
            *partition_by* is set).
        partition_by: Optional list of column names to Hive-partition the
            output by (e.g. ``["event_id", "source"]``).
        verify_row_count: When ``True`` (default) the function reads back the
            written Parquet metadata and asserts that the number of rows
            matches the number of records in *jsonl_path*.

    Returns:
        The number of rows written.

    Raises:
        ImportError: If ``pyarrow`` is not installed.
        ValueError: For an unknown *schema_name* or a row-count mismatch when
            *verify_row_count* is ``True``.
        FileNotFoundError: If *jsonl_path* does not exist.
    """
    # Deferred import so the module can be imported without pyarrow installed.
    try:
        import pyarrow as pa  # noqa: F401
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ImportError(
            "pyarrow is required for Parquet conversion but is not installed. "
            "Install it with:  pip install 'pyarrow>=14.0'"
        ) from exc

    if schema_name not in _SUPPORTED_SCHEMAS:
        raise ValueError(
            f"unknown schema_name {schema_name!r}: "
            f"expected one of {sorted(_SUPPORTED_SCHEMAS)}"
        )

    jsonl_path = Path(jsonl_path)
    output_path = Path(output_path)

    if not jsonl_path.exists():
        raise FileNotFoundError(f"JSONL file not found: {jsonl_path}")

    # ------------------------------------------------------------------ #
    # 1. Read all records                                                  #
    # ------------------------------------------------------------------ #
    records: list[dict[str, Any]] = []
    with jsonl_path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"malformed JSON on line {lineno} of {jsonl_path}: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ValueError(
                    f"line {lineno} of {jsonl_path} is not a JSON object"
                )
            records.append(obj)

    input_count = len(records)

    if input_count == 0:
        # Write an empty Parquet file with zero rows.
        table = pa.table({})
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(table, output_path)
        return 0

    # ------------------------------------------------------------------ #
    # 2. Build columnar data with correct types                            #
    # ------------------------------------------------------------------ #
    # Collect all field names from the first record; assume consistent shape.
    field_names: list[str] = list(records[0].keys())

    columns: dict[str, pa.Array] = {}
    def _encode_uint256(value: Any) -> bytes | None:
        if value is None or value == "":
            return None
        integer = int(value)
        if integer < 0:
            raise ValueError("uint256 fields must be non-negative")
        return integer.to_bytes(32, byteorder="big", signed=False)

    for field in field_names:
        raw_values: list[Any] = [rec.get(field) for rec in records]

        if field in _UINT256_BINARY_FIELDS:
            columns[field] = pa.array(
                [_encode_uint256(value) for value in raw_values],
                type=pa.binary(32),
            )
        elif field in _INT64_FIELDS:
            columns[field] = pa.array(raw_values, type=pa.int64())
        elif field in _FLOAT64_FIELDS:
            columns[field] = pa.array(raw_values, type=pa.float64())
        elif field in _JSON_LIST_FIELDS:
            # topics / inclusion_reasons — stored as list<string> in Arrow
            list_values = [
                json.loads(v) if isinstance(v, str) else (v or [])
                for v in raw_values
            ]
            columns[field] = pa.array(
                list_values, type=pa.list_(pa.string())
            )
        elif field in _JSON_INT_LIST_FIELDS:
            list_values = [
                [int(item) for item in (json.loads(value) if isinstance(value, str) else (value or []))]
                for value in raw_values
            ]
            columns[field] = pa.array(list_values, type=pa.list_(pa.int64()))
        else:
            # Default: string
            str_values = [str(v) if v is not None else "" for v in raw_values]
            columns[field] = pa.array(str_values, type=pa.string())

    table = pa.table(columns)

    # ------------------------------------------------------------------ #
    # 3. Write Parquet                                                     #
    # ------------------------------------------------------------------ #
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if partition_by:
        # Hive-partitioned dataset — output_path is treated as a directory.
        import pyarrow.dataset as ds  # noqa: F401 – guarded by outer import

        pq.write_to_dataset(
            table,
            root_path=str(output_path),
            partition_cols=partition_by,
            use_legacy_dataset=False,
        )
    else:
        pq.write_table(table, output_path)

    # ------------------------------------------------------------------ #
    # 4. Optional row-count verification                                   #
    # ------------------------------------------------------------------ #
    if verify_row_count:
        if partition_by:
            # Sum row counts across all part files.
            import pyarrow.dataset as ds

            dataset = ds.dataset(str(output_path), format="parquet")
            written_count = dataset.count_rows()
        else:
            written_count = pq.read_metadata(output_path).num_rows

        if written_count != input_count:
            raise ValueError(
                f"row count mismatch: wrote {written_count} rows "
                f"but input had {input_count} records "
                f"(schema={schema_name!r}, path={output_path})"
            )

    return input_count
