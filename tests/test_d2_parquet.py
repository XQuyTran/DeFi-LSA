import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from defi_lsa.parquet import jsonl_to_parquet


def _write_jsonl(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")


def test_extended_aws_schemas_preserve_typed_columns(tmp_path):
    cases = {
        "token_transfers": {
            "record_key": "1:0x" + "a" * 64 + ":0",
            "value_wei": 2**255 + 1,
            "block_number": 12,
        },
        "traces": {
            "record_key": "1:0x" + "a" * 64 + ":0.1",
            "trace_address": [0, 1],
            "value_wei": 7,
            "block_number": 12,
        },
        "contracts": {
            "record_key": "1:0x" + "b" * 40,
            "block_number": 12,
        },
    }

    for schema_name, record in cases.items():
        input_path = tmp_path / f"{schema_name}.jsonl"
        output_path = tmp_path / f"{schema_name}.parquet"
        _write_jsonl(input_path, record)

        assert jsonl_to_parquet(input_path, schema_name, output_path) == 1
        table = pq.read_table(output_path)
        assert table.num_rows == 1
        if schema_name != "contracts":
            assert table.schema.field("value_wei").type.byte_width == 32
        if schema_name == "traces":
            assert table.schema.field("trace_address").type == pa.list_(pa.int64())
