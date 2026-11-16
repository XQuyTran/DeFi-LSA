"""Pure transaction, actor, incident-leg, and balance-input logic for D3."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any


CLASSIFICATION_PRIORITY = (
    "exploit",
    "recovery",
    "liquidation",
    "flash_loan",
    "withdrawal",
    "deposit",
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
