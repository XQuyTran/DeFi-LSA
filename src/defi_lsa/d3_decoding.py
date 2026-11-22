"""Pure ABI event and transaction-input decoding for D3."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Mapping, Sequence

from eth_abi import decode as abi_decode
from eth_utils import keccak


def _canonical_type(item: Mapping[str, Any]) -> str:
    """Return the canonical ABI type, including tuple components."""
    item_type = str(item["type"])
    if not item_type.startswith("tuple"):
        return item_type
    suffix = item_type[len("tuple") :]
    components = ",".join(_canonical_type(component) for component in item.get("components", []))
    return f"({components}){suffix}"


def _signature(item: Mapping[str, Any]) -> str:
    name = str(item.get("name", ""))
    types = ",".join(_canonical_type(argument) for argument in item.get("inputs", []))
    return f"{name}({types})"


def event_topic0(event: Mapping[str, Any]) -> str:
    """Return the 0x-prefixed Keccak topic for an ABI event."""
    return "0x" + keccak(text=_signature(event)).hex()


def function_selector(function: Mapping[str, Any]) -> str:
    """Return the 4-byte selector for an ABI function."""
    return "0x" + keccak(text=_signature(function))[:4].hex()


def _hex_bytes(value: str) -> bytes:
    value = str(value)
    if value.startswith("0x"):
        value = value[2:]
    if len(value) % 2:
        raise ValueError("hex data must contain an even number of characters")
    return bytes.fromhex(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _decode_values(types: Sequence[str], payload: bytes) -> list[Any]:
    if not types:
        return []
    return [_json_value(value) for value in abi_decode(list(types), payload)]


def _find_abi_item(
    abi: Sequence[Mapping[str, Any]], item_type: str, identifier: str
) -> Mapping[str, Any] | None:
    identifier = identifier.lower()
    for item in abi:
        if item.get("type") != item_type:
            continue
        candidate = (
            event_topic0(item) if item_type == "event" else function_selector(item)
        )
        if candidate.lower() == identifier:
            return item
    return None


def decode_log(
    log: Mapping[str, Any],
    abi: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Decode one log, returning ``None`` when its topic is not in the ABI."""
    topics = [str(topic).lower() for topic in log.get("topics", [])]
    if not topics:
        return None
    event = _find_abi_item(abi, "event", topics[0])
    if event is None:
        return None

    inputs = list(event.get("inputs", []))
    indexed = [item for item in inputs if item.get("indexed")]
    non_indexed = [item for item in inputs if not item.get("indexed")]
    indexed_values: list[Any] = []
    for item, topic in zip(indexed, topics[1:]):
        item_type = _canonical_type(item)
        if item_type in {"string", "bytes"} or item_type.endswith("]"):
            indexed_values.append(topic)
        else:
            indexed_values.extend(_decode_values([item_type], _hex_bytes(topic)))

    data_values = _decode_values(
        [_canonical_type(item) for item in non_indexed],
        _hex_bytes(str(log.get("data", "0x"))),
    )
    decoded: dict[str, Any] = {}
    for item, value in zip(indexed, indexed_values):
        decoded[str(item.get("name", ""))] = value
    for item, value in zip(non_indexed, data_values):
        decoded[str(item.get("name", ""))] = value
    return {
        "event_name": str(event.get("name", "")),
        "signature": _signature(event),
        "topic0": topics[0],
        "arguments": decoded,
    }


def decode_input_data(
    input_data: str,
    abi: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Decode transaction calldata, returning ``None`` for unknown selectors."""
    raw = _hex_bytes(input_data)
    if len(raw) < 4:
        raise ValueError("transaction input must contain a four-byte selector")
    selector = "0x" + raw[:4].hex()
    function = _find_abi_item(abi, "function", selector)
    if function is None:
        return None
    inputs = list(function.get("inputs", []))
    values = _decode_values(
        [_canonical_type(item) for item in inputs], raw[4:]
    )
    arguments = {
        str(item.get("name", "")): value for item, value in zip(inputs, values)
    }
    return {
        "function_name": str(function.get("name", "")),
        "signature": _signature(function),
        "selector": selector,
        "arguments": arguments,
    }


def unknown_record(
    *,
    event_id: str,
    contract: str,
    tx_hash: str,
    signature: str = "",
    topic0: str = "",
    function_selector_value: str = "",
    log_index: int | None = None,
    reason: str = "not present in ABI",
    occurrence_count: int = 1,
) -> dict[str, Any]:
    """Build the stable shape used by ``unknown_event_report.json``."""
    return {
        "event_id": event_id,
        "contract": contract,
        "tx_hash": tx_hash,
        "signature": signature,
        "topic0": topic0,
        "function_selector": function_selector_value,
        "log_index": log_index,
        "occurrence_count": occurrence_count,
        "reason": reason,
    }


def aggregate_unknown_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate unknown records deterministically by signature and contract."""
    counts = Counter(
        (
            str(record.get("event_id", "")),
            str(record.get("contract", "")),
            str(record.get("topic0", "")),
            str(record.get("function_selector", "")),
        )
        for record in records
    )
    result: list[dict[str, Any]] = []
    for record in records:
        key = (
            str(record.get("event_id", "")),
            str(record.get("contract", "")),
            str(record.get("topic0", "")),
            str(record.get("function_selector", "")),
        )
        if record not in result:
            item = dict(record)
            item["occurrence_count"] = counts[key]
            result.append(item)
    return sorted(
        result,
        key=lambda item: (
            str(item.get("event_id", "")),
            str(item.get("contract", "")),
            str(item.get("tx_hash", "")),
            int(item.get("log_index") or -1),
        ),
    )
