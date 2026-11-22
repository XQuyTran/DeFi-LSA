"""Versioned schema contracts for D3 decoded and classified artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


D3_SCHEMA_VERSION = "1.0.0"

D3_SCHEMA_FIELDS: dict[str, tuple[str, ...]] = {
    "decoded_events": (
        "schema_version",
        "event_id",
        "chain_id",
        "tx_hash",
        "log_index",
        "block_number",
        "contract_address",
        "event_name",
        "signature",
        "topic0",
        "arguments_json",
        "raw_topics",
        "raw_data",
        "source_sha256",
        "normalization_version",
    ),
    "decoded_calls": (
        "schema_version",
        "event_id",
        "chain_id",
        "tx_hash",
        "block_number",
        "contract_address",
        "function_name",
        "signature",
        "selector",
        "arguments_json",
        "raw_input",
        "source_sha256",
        "normalization_version",
    ),
    "classified_transactions": (
        "schema_version",
        "event_id",
        "chain_id",
        "tx_hash",
        "block_number",
        "primary_label",
        "matched_rules",
        "from_address",
        "to_address",
        "evidence",
        "source_sha256",
    ),
    "actor_roles": (
        "schema_version",
        "event_id",
        "chain_id",
        "tx_hash",
        "address",
        "actor_role",
        "confidence",
        "evidence",
        "source_role",
    ),
    "incident_legs_resolved": (
        "schema_version",
        "event_id",
        "chain_id",
        "leg_id",
        "affected_address",
        "transaction_hash",
        "actor_address",
        "actor_role",
        "asset_pair",
        "pool_address",
        "token_address",
        "relationship_valid",
        "evidence",
    ),
    "balance_inputs": (
        "schema_version",
        "event_id",
        "chain_id",
        "tx_hash",
        "block_number",
        "log_index",
        "token_address",
        "address",
        "actor_role",
        "primary_label",
        "incident_leg_id",
        "balance_delta",
        "from_address",
        "to_address",
        "evidence",
    ),
}


def d3_fields(schema_name: str) -> tuple[str, ...]:
    """Return the frozen column order for a D3 schema."""
    try:
        return D3_SCHEMA_FIELDS[schema_name]
    except KeyError as exc:
        raise ValueError(f"unknown D3 schema: {schema_name!r}") from exc


def validate_d3_record(schema_name: str, record: Mapping[str, Any]) -> None:
    """Validate required D3 fields and schema version."""
    fields = d3_fields(schema_name)
    missing = [field for field in fields if field not in record]
    if missing:
        raise ValueError(
            f"{schema_name} record is missing required fields: {', '.join(missing)}"
        )
    if record["schema_version"] != D3_SCHEMA_VERSION:
        raise ValueError(
            f"{schema_name} has unsupported schema_version "
            f"{record['schema_version']!r}; expected {D3_SCHEMA_VERSION!r}"
        )
