"""Versioned schema contracts for D3 decoded and classified artifacts."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


D3_SCHEMA_VERSION = "1.0.0"

FLOW_LEG_LABELS = (
    "attacker_drain",
    "recovery_flow",
    "user_net_flow",
    "swap_mev",
    "flash_loan",
    "internal_transfer",
    "unknown",
)

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
    "flow_legs": (
        "schema_version",
        "event_id",
        "chain_id",
        "flow_leg_id",
        "tx_hash",
        "block_number",
        "log_index",
        "token_address",
        "from_address",
        "to_address",
        "value_wei",
        "flow_label",
        "matched_rules",
        "evidence",
        "source_sha256",
    ),
    "hourly_panel": (
        "schema_version",
        "event_id",
        "hour_start_utc",
        "token_symbol",
        "token_address",
        "token_decimals",
        "missing_blocks",
        "missing_receipts",
        "data_status",
        "price_status",
        "usd_price_anchor",
        "anchor_price_source",
        "anchor_price_observed_timestamp_utc",
        "anchor_price_confidence",
        "attacker_drain_token",
        "recovery_flow_token",
        "user_net_flow_token",
        "swap_mev_token",
        "flash_loan_token",
        "internal_transfer_token",
        "unknown_token",
        "attacker_drain_usd",
        "recovery_flow_usd",
        "user_net_flow_usd",
        "swap_mev_usd",
        "flash_loan_usd",
        "internal_transfer_usd",
        "unknown_usd",
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
    if schema_name == "flow_legs":
        if record["flow_label"] not in FLOW_LEG_LABELS:
            raise ValueError(f"unsupported flow-leg label: {record['flow_label']!r}")
        try:
            value_wei = int(record["value_wei"])
        except (TypeError, ValueError) as exc:
            raise ValueError("flow-leg value_wei must be an integer") from exc
        if value_wei < 0:
            raise ValueError("flow-leg value_wei must be non-negative")
    if schema_name == "hourly_panel":
        status = record["data_status"]
        price_status = record["price_status"]
        if status not in {"COMPLETE", "MISSING_CHAIN_DATA"}:
            raise ValueError(f"unsupported hourly data_status: {status!r}")
        if price_status not in {"AVAILABLE", "MISSING_PRICE"}:
            raise ValueError(f"unsupported hourly price_status: {price_status!r}")
        if status == "COMPLETE" and (
            record["missing_blocks"] != 0 or record["missing_receipts"] != 0
        ):
            raise ValueError("complete hourly rows require zero missing blocks and receipts")
        metric_fields = tuple(
            field for field in fields if field.endswith("_token") or field.endswith("_usd")
        )
        if status == "MISSING_CHAIN_DATA" and any(
            not _is_nan(record[field]) for field in metric_fields
        ):
            raise ValueError("missing-chain hourly metrics must be NaN")
        price = record["usd_price_anchor"]
        if price_status == "AVAILABLE" and (
            not _is_finite_number(price) or float(price) <= 0
        ):
            raise ValueError("available anchor prices must be finite and positive")
        if price_status == "MISSING_PRICE" and not _is_nan(price):
            raise ValueError("missing anchor prices must be NaN")
        if price_status == "MISSING_PRICE" and any(
            not _is_nan(record[field]) for field in fields if field.endswith("_usd")
        ):
            raise ValueError("USD hourly metrics must be NaN when the anchor price is missing")


def _is_nan(value: Any) -> bool:
    return isinstance(value, float) and math.isnan(value)


def _is_finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
