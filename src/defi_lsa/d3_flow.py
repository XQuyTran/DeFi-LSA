"""Pure transaction, actor, incident-leg, and balance-input logic for D3."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .d3_schemas import D3_SCHEMA_VERSION, FLOW_LEG_LABELS


CLASSIFICATION_PRIORITY = (
    "exploit",
    "recovery",
    "liquidation",
    "flash_loan",
    "withdrawal",
    "deposit",
    "borrow",
    "repay",
    "swap",
    "unknown",
)

ROLE_MAP = {
    "attacker": "attacker",
    "primary_exploiter": "attacker",
    "white_hat": "whitehat",
    "white-hat": "whitehat",
    "whitehat": "whitehat",
    "protocol": "protocol",
    "protocol_treasury": "protocol",
    "user": "user",
    "victim": "user",
    "recovery": "protocol",
    "front_runner": "user",
    "mev": "user",
}

_FLOW_ROLE_ALIASES = {
    "attacker": "attacker",
    "primary_exploiter": "attacker",
    "white_hat": "whitehat",
    "white-hat": "whitehat",
    "whitehat": "whitehat",
    "protocol": "protocol",
    "protocol_treasury": "protocol",
    "user": "user",
    "victim": "user",
    "front_runner": "mev",
    "mev": "mev",
}


def normalize_actor_role(source_role: str | None) -> str:
    """Normalize registry role vocabulary to the D3 role contract."""
    role = str(source_role or "unknown").strip().lower().replace(" ", "_")
    return ROLE_MAP.get(role, "unknown")


def classify_transaction(
    transaction: Mapping[str, Any],
    *,
    decoded_events: Sequence[Mapping[str, Any]] = (),
    decoded_calls: Sequence[Mapping[str, Any]] = (),
    exploit_hashes: Iterable[str] = (),
    recovery_hashes: Iterable[str] = (),
) -> dict[str, Any]:
    """Assign one primary label while preserving all matched rule evidence."""
    tx_hash = str(transaction.get("tx_hash", "")).lower()
    exploit_set = {str(value).lower() for value in exploit_hashes}
    recovery_set = {str(value).lower() for value in recovery_hashes}
    event_names = {
        str(item.get("event_name", "")).lower() for item in decoded_events
    }
    function_names = {
        str(item.get("function_name", "")).lower() for item in decoded_calls
    }
    matched: list[str] = []
    if tx_hash in exploit_set:
        matched.append("exploit")
    if tx_hash in recovery_set or "recovery" in event_names:
        matched.append("recovery")
    if "liquidation" in event_names or "liquidate" in function_names:
        matched.append("liquidation")
    if "flashloan" in function_names or "flash_loan" in event_names:
        matched.append("flash_loan")
    if event_names & {"withdraw", "withdrawal", "redeem"} or function_names & {
        "withdraw",
        "redeem",
    }:
        matched.append("withdrawal")
    if event_names & {"deposit", "supply"} or function_names & {
        "deposit",
        "supply",
    }:
        matched.append("deposit")
    if event_names & {"borrow", "requestborrow"} or function_names & {
        "borrow",
        "requestborrow",
    }:
        matched.append("borrow")
    if event_names & {"repay", "requestrepay"} or function_names & {
        "repay",
        "requestrepay",
    }:
        matched.append("repay")
    if "swap" in event_names or "swap" in function_names:
        matched.append("swap")
    matched = [label for label in CLASSIFICATION_PRIORITY if label in matched]
    primary = matched[0] if matched else "unknown"
    return {
        "tx_hash": transaction.get("tx_hash", ""),
        "primary_label": primary,
        "matched_rules": matched,
        "evidence": {
            "event_names": sorted(event_names),
            "function_names": sorted(function_names),
            "registry_exploit": tx_hash in exploit_set,
            "registry_recovery": tx_hash in recovery_set,
        },
    }


def classify_addresses(
    *,
    event_id: str,
    tx_hash: str,
    addresses: Iterable[str],
    role_by_address: Mapping[str, str],
    chain_id: int,
) -> list[dict[str, Any]]:
    """Create one auditable role row per address in a transaction."""
    rows = []
    for address in sorted({str(value).lower() for value in addresses if value}):
        source_role = role_by_address.get(address, "unknown")
        canonical_role = normalize_actor_role(source_role)
        rows.append(
            {
                "schema_version": "1.0.0",
                "event_id": event_id,
                "chain_id": chain_id,
                "tx_hash": tx_hash,
                "address": address,
                "actor_role": canonical_role,
                "confidence": "high" if canonical_role != "unknown" else "low",
                "evidence": "registry" if canonical_role != "unknown" else "unmatched",
                "source_role": source_role,
            }
        )
    return rows


def validate_incident_leg_ownership(
    registered_transactions: Iterable[str],
    resolved_legs: Sequence[Mapping[str, Any]],
    *,
    event_id: str,
) -> dict[str, Any]:
    """Validate one-leg ownership and event scope for registered transactions."""
    registered = {str(value).lower() for value in registered_transactions}
    ownership: dict[str, list[str]] = {}
    wrong_scope: list[str] = []
    for leg in resolved_legs:
        tx_hash = str(leg.get("transaction_hash", "")).lower()
        ownership.setdefault(tx_hash, []).append(str(leg.get("leg_id", "")))
        if str(leg.get("event_id", "")) != event_id and tx_hash in registered:
            wrong_scope.append(tx_hash)
    orphan = sorted(registered - set(ownership))
    multiply_owned = sorted(
        tx_hash for tx_hash, leg_ids in ownership.items() if len(leg_ids) != 1
    )
    return {
        "passed": not orphan and not multiply_owned and not wrong_scope,
        "registered_count": len(registered),
        "orphan_transactions": orphan,
        "multiply_owned_transactions": multiply_owned,
        "wrong_scope_transactions": sorted(set(wrong_scope)),
    }


def build_balance_inputs(
    transfers: Sequence[Mapping[str, Any]],
    *,
    classification_by_tx: Mapping[str, Mapping[str, Any]],
    actor_by_address: Mapping[str, str],
    leg_by_tx: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Convert token transfers into D4-ready balance movement rows."""
    rows: list[dict[str, Any]] = []
    for transfer in transfers:
        tx_hash = str(transfer.get("tx_hash", ""))
        from_address = str(transfer.get("from_address", "")).lower()
        to_address = str(transfer.get("to_address", "")).lower()
        classification = classification_by_tx.get(tx_hash.lower(), {})
        rows.append(
            {
                "schema_version": "1.0.0",
                "event_id": transfer.get("event_id", ""),
                "chain_id": transfer.get("chain_id", 0),
                "tx_hash": tx_hash,
                "block_number": transfer.get("block_number", 0),
                "log_index": transfer.get("log_index", 0),
                "token_address": transfer.get("token_address", ""),
                "address": to_address,
                "actor_role": normalize_actor_role(actor_by_address.get(to_address)),
                "primary_label": classification.get("primary_label", "unknown"),
                "incident_leg_id": leg_by_tx.get(tx_hash.lower(), ""),
                "balance_delta": str(transfer.get("value_wei", "0")),
                "from_address": from_address,
                "to_address": to_address,
                "evidence": "token_transfer",
            }
        )
    return rows


def classify_flow_leg(
    transfer: Mapping[str, Any],
    *,
    decoded_events: Sequence[Mapping[str, Any]] = (),
    decoded_calls: Sequence[Mapping[str, Any]] = (),
    exploit_hashes: Iterable[str] = (),
    recovery_hashes: Iterable[str] = (),
    core_addresses: Iterable[str] = (),
    role_by_address: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Classify one token transfer using explicit registry and ABI evidence."""
    tx_hash = str(transfer.get("tx_hash", "")).lower()
    from_address = str(transfer.get("from_address", "")).lower()
    to_address = str(transfer.get("to_address", "")).lower()
    core = {str(address).lower() for address in core_addresses}
    roles = {
        str(address).lower(): _FLOW_ROLE_ALIASES.get(
            str(role).strip().lower().replace(" ", "_"), "unknown"
        )
        for address, role in (role_by_address or {}).items()
    }
    exploit_set = {str(value).lower() for value in exploit_hashes}
    recovery_set = {str(value).lower() for value in recovery_hashes}
    event_names = {str(item.get("event_name", "")).strip().lower() for item in decoded_events}
    function_names = {str(item.get("function_name", "")).strip().lower() for item in decoded_calls}
    endpoint_roles = {roles.get(from_address, "unknown"), roles.get(to_address, "unknown")}
    activity_addresses = {
        str(item.get("contract_address", "")).lower()
        for item in (*decoded_events, *decoded_calls)
        if item.get("contract_address")
    }

    matched: list[str] = []
    if from_address in core and roles.get(to_address) == "attacker":
        matched.append("core_to_attacker")
    if tx_hash in exploit_set and roles.get(to_address) == "attacker":
        matched.append("registered_exploit_to_attacker")
    if tx_hash in recovery_set:
        matched.append("registered_recovery_transaction")
    if from_address in core and to_address in core:
        matched.append("core_to_core_transfer")
    if event_names & {"flashloan", "flash_loan"} or function_names & {
        "flashloan",
        "flash_loan",
    }:
        matched.append("flash_loan_activity")
    if event_names & {"swap", "swapped"} or "swap" in function_names:
        matched.append("swap_activity")
    if "mev" in endpoint_roles:
        matched.append("mev_actor_endpoint")
    if (
        event_names
        & {
            "deposit",
            "supply",
            "withdraw",
            "withdrawal",
            "redeem",
            "borrow",
            "repay",
            "requestborrow",
            "requestrepay",
        }
        or function_names
        & {"deposit", "supply", "withdraw", "redeem", "borrow", "repay"}
    ) and (
        "user" in endpoint_roles
        or bool(({from_address, to_address} | activity_addresses) & core)
    ):
        matched.append("user_liquidity_activity")

    if "core_to_attacker" in matched or "registered_exploit_to_attacker" in matched:
        label = "attacker_drain"
    elif "registered_recovery_transaction" in matched:
        label = "recovery_flow"
    elif "core_to_core_transfer" in matched:
        label = "internal_transfer"
    elif "flash_loan_activity" in matched:
        label = "flash_loan"
    elif "swap_activity" in matched or "mev_actor_endpoint" in matched:
        label = "swap_mev"
    elif "user_liquidity_activity" in matched:
        label = "user_net_flow"
    else:
        label = "unknown"

    return {
        "flow_label": label,
        "matched_rules": matched,
        "evidence": {
            "event_names": sorted(event_names),
            "function_names": sorted(function_names),
            "from_role": roles.get(from_address, "unknown"),
            "to_role": roles.get(to_address, "unknown"),
            "registered_exploit": tx_hash in exploit_set,
            "registered_recovery": tx_hash in recovery_set,
        },
    }


def build_flow_legs(
    transfers: Sequence[Mapping[str, Any]],
    *,
    decoded_events_by_tx: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    decoded_calls_by_tx: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    exploit_hashes: Iterable[str] = (),
    recovery_hashes: Iterable[str] = (),
    core_addresses: Iterable[str] = (),
    role_by_address: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Return deterministic, schema-versioned flow-leg rows for transfers."""
    event_map = decoded_events_by_tx or {}
    call_map = decoded_calls_by_tx or {}
    rows: list[dict[str, Any]] = []
    for transfer in transfers:
        tx_hash = str(transfer.get("tx_hash", ""))
        tx_key = tx_hash.lower()
        token_address = str(transfer.get("token_address", "")).lower()
        log_index = int(transfer.get("log_index", 0))
        value_wei = int(transfer.get("value_wei", 0))
        if value_wei < 0:
            raise ValueError("flow-leg value_wei must be non-negative")
        result = classify_flow_leg(
            transfer,
            decoded_events=event_map.get(tx_key, ()),
            decoded_calls=call_map.get(tx_key, ()),
            exploit_hashes=exploit_hashes,
            recovery_hashes=recovery_hashes,
            core_addresses=core_addresses,
            role_by_address=role_by_address,
        )
        if result["flow_label"] not in FLOW_LEG_LABELS:
            raise ValueError(f"unsupported flow-leg label: {result['flow_label']}")
        rows.append(
            {
                "schema_version": D3_SCHEMA_VERSION,
                "event_id": transfer.get("event_id", ""),
                "chain_id": transfer.get("chain_id", 0),
                "flow_leg_id": f"{tx_key}:{log_index}:{token_address}",
                "tx_hash": tx_hash,
                "block_number": transfer.get("block_number", 0),
                "log_index": log_index,
                "token_address": token_address,
                "from_address": str(transfer.get("from_address", "")).lower(),
                "to_address": str(transfer.get("to_address", "")).lower(),
                "value_wei": str(value_wei),
                "flow_label": result["flow_label"],
                "matched_rules": json.dumps(result["matched_rules"]),
                "evidence": json.dumps(result["evidence"], sort_keys=True),
                "source_sha256": transfer.get("source_sha256", ""),
            }
        )
    return rows


def audit_flow_volume_by_token(
    flow_legs: Sequence[Mapping[str, Any]], *, unknown_threshold: float = 0.05
) -> list[dict[str, Any]]:
    """Measure unknown flow share per token without mixing incompatible units."""
    if not 0 <= unknown_threshold <= 1:
        raise ValueError("unknown_threshold must be between zero and one")
    totals: dict[str, int] = {}
    unknown: dict[str, int] = {}
    for leg in flow_legs:
        token = str(leg.get("token_address", "")).lower()
        value = int(leg.get("value_wei", 0))
        if value < 0:
            raise ValueError("flow-leg value_wei must be non-negative")
        totals[token] = totals.get(token, 0) + value
        if leg.get("flow_label") == "unknown":
            unknown[token] = unknown.get(token, 0) + value
    result: list[dict[str, Any]] = []
    for token in sorted(totals):
        total = totals[token]
        share = unknown.get(token, 0) / total if total else None
        result.append(
            {
                "token_address": token,
                "total_value_wei": str(total),
                "unknown_value_wei": str(unknown.get(token, 0)),
                "unknown_flow_share": share,
                "passed": share is not None and share <= unknown_threshold,
                "threshold": unknown_threshold,
            }
        )
    return result
