import json
from pathlib import Path

import pyarrow.parquet as pq

from defi_lsa.d3_schemas import D3_SCHEMA_FIELDS, D3_SCHEMA_VERSION
from defi_lsa.orchestration import CollectionContext
from defi_lsa.parquet import jsonl_to_parquet


def _record(schema_name: str) -> dict[str, object]:
    return {
        field: (
            D3_SCHEMA_VERSION
            if field == "schema_version"
            else 1
            if field in {"chain_id", "block_number", "log_index"}
            else "[]"
            if field in {"matched_rules", "raw_topics"}
            else "0xabc"
        )
        for field in D3_SCHEMA_FIELDS[schema_name]
    }


def test_d3_parquet_columns_are_versioned_and_deterministic(tmp_path: Path):
    input_path = tmp_path / "records.jsonl"
    output_path = tmp_path / "data" / "decoded.parquet"
    input_path.write_text(
        json.dumps(_record("decoded_events"), sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert jsonl_to_parquet(input_path, "decoded_events", output_path) == 1
    table = pq.read_table(output_path)

    assert table.schema.names == list(D3_SCHEMA_FIELDS["decoded_events"])
    assert table.column("schema_version")[0].as_py() == D3_SCHEMA_VERSION


def test_collection_context_exposes_one_canonical_d3_location(tmp_path: Path):
    from tests.test_d2_orchestration import _make_context

    context: CollectionContext = _make_context(tmp_path)
    decoded_paths = {
        context.decoded_events_path,
        context.decoded_calls_path,
        context.classified_transactions_path,
        context.actor_roles_path,
        context.incident_legs_resolved_path,
        context.balance_inputs_path,
    }
    report_paths = {
        context.unknown_event_report_path,
        context.d3_gate_report_path,
    }

    assert len(decoded_paths | report_paths) == 8
    assert all(path.parent == context.decoded_dir for path in decoded_paths)
    assert context.unknown_event_report_path.parent == context.reports_dir
    assert context.d3_gate_report_path.parent == context.reports_dir