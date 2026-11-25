"""Hourly panel construction and immutable E3 dataset freezing."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from .d3_schemas import D3_SCHEMA_VERSION, FLOW_LEG_LABELS, d3_fields, validate_d3_record
from .parquet import jsonl_to_parquet


CORE_TOKEN_SYMBOLS = ("WETH", "USDC", "DAI", "WBTC", "wstETH")
_FLOW_TYPES = tuple(label for label in FLOW_LEG_LABELS if label != "unknown")
_PANEL_COLUMNS = d3_fields("hourly_panel")


def _utc_hour(value: str | datetime) -> datetime:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("hour timestamps must be timezone-aware UTC")
    if (parsed.minute, parsed.second, parsed.microsecond) != (0, 0, 0):
        raise ValueError("hour timestamps must be aligned to the hour")
    return parsed.astimezone(timezone.utc)


def _hour_key(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _finite_positive(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number > 0 else None


def build_hourly_panel(
    event_id: str,
    *,
    start_utc: str | datetime,
    hours: int,
    tokens: list[dict[str, Any]],
    hourly_coverage: dict[str, dict[str, Any]],
    flow_legs: list[dict[str, Any]],
    block_timestamps: dict[int, int],
    anchor_prices: dict[str, Any],
) -> list[dict[str, Any]]:
    """Aggregate classified flow legs onto a token-by-hour panel.

    Coverage must explicitly report zero missing blocks and receipts before an
    empty hour is represented as zero. Missing coverage remains null evidence.
    Anchor prices are keyed by token address or symbol and must be positive.
    """
    if hours <= 0:
        raise ValueError("hours must be positive")
    start = _utc_hour(start_utc)
    token_by_address: dict[str, dict[str, Any]] = {}
    for token in tokens:
        address = str(token.get("address", "")).lower()
        symbol = str(token.get("symbol", ""))
        decimals = int(token.get("decimals", -1))
        if not address or not symbol or not 0 <= decimals <= 255:
            raise ValueError("each token requires address, symbol, and valid decimals")
        if address in token_by_address or any(
            item["symbol"] == symbol for item in token_by_address.values()
        ):
            raise ValueError("token addresses and symbols must be unique")
        token_by_address[address] = {"address": address, "symbol": symbol, "decimals": decimals}

    expected_hours = [start + timedelta(hours=index) for index in range(hours)]
    hour_index = {_hour_key(hour): hour for hour in expected_hours}
    amounts: dict[tuple[str, str], dict[str, Decimal]] = {}
    for leg in flow_legs:
        token_address = str(leg.get("token_address", "")).lower()
        token = token_by_address.get(token_address)
        if token is None:
            continue
        block_number = int(leg.get("block_number", -1))
        if block_number not in block_timestamps:
            raise ValueError(f"missing timestamp for flow-leg block {block_number}")
        timestamp = datetime.fromtimestamp(int(block_timestamps[block_number]), tz=timezone.utc)
        hour = timestamp.replace(minute=0, second=0, microsecond=0)
        key = _hour_key(hour)
        if key not in hour_index:
            continue
        label = str(leg.get("flow_label", "unknown"))
        if label not in FLOW_LEG_LABELS:
            raise ValueError(f"unsupported flow-leg label: {label}")
        value_wei = int(leg.get("value_wei", 0))
        if value_wei < 0:
            raise ValueError("flow-leg value_wei must be non-negative")
        bucket = amounts.setdefault((token_address, key), {})
        bucket[label] = bucket.get(label, Decimal(0)) + Decimal(value_wei) / (
            Decimal(10) ** token["decimals"]
        )

    rows: list[dict[str, Any]] = []
    for hour in expected_hours:
        key = _hour_key(hour)
        coverage = hourly_coverage.get(key)
        if coverage is not None:
            for field in ("missing_blocks", "missing_receipts"):
                value = coverage.get(field)
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                ):
                    raise ValueError(f"{field} must be a non-negative integer or null")
        complete = (
            coverage is not None
            and coverage.get("missing_blocks") == 0
            and coverage.get("missing_receipts") == 0
        )
        for token in token_by_address.values():
            price = _finite_positive(
                anchor_prices.get(token["address"], anchor_prices.get(token["symbol"]))
            )
            amounts_for_hour = amounts.get((token["address"], key), {})
            row: dict[str, Any] = {
                "schema_version": D3_SCHEMA_VERSION,
                "event_id": event_id,
                "hour_start_utc": key,
                "token_symbol": token["symbol"],
                "token_address": token["address"],
                "token_decimals": token["decimals"],
                "missing_blocks": coverage.get("missing_blocks") if coverage else None,
                "missing_receipts": coverage.get("missing_receipts") if coverage else None,
                "data_status": "COMPLETE" if complete else "MISSING_CHAIN_DATA",
                "price_status": "AVAILABLE" if price is not None else "MISSING_PRICE",
                "usd_price_anchor": price if price is not None else math.nan,
            }
            for label in _FLOW_TYPES + ("unknown",):
                amount = float(amounts_for_hour.get(label, Decimal(0))) if complete else math.nan
                row[f"{label}_token"] = amount
                row[f"{label}_usd"] = amount * price if complete and price is not None else math.nan
            validate_d3_record("hourly_panel", row)
            rows.append(row)
    return rows


def _validate_freeze_rows(
    rows: list[dict[str, Any]], *, required_hours: int, required_tokens: set[str]
) -> list[str]:
    if required_hours <= 0 or not required_tokens:
        raise ValueError("freeze requirements must include positive hours and tokens")
    expected_count = required_hours * len(required_tokens)
    if len(rows) != expected_count:
        raise ValueError(f"expected {expected_count} hourly rows, received {len(rows)}")
    event_ids = {str(row.get("event_id", "")) for row in rows}
    if len(event_ids) != 1 or "" in event_ids:
        raise ValueError("frozen rows must contain exactly one non-empty event_id")
    hours = sorted({str(row["hour_start_utc"]) for row in rows})
    if len(hours) != required_hours:
        raise ValueError("hourly panel contains duplicate or missing hours")
    parsed_hours = [_utc_hour(value) for value in hours]
    if any(right - left != timedelta(hours=1) for left, right in zip(parsed_hours, parsed_hours[1:])):
        raise ValueError("hourly panel hours must be contiguous")
    if {str(row["token_symbol"]) for row in rows} != required_tokens:
        raise ValueError("hourly panel token set does not match freeze requirements")
    keys: set[tuple[str, str]] = set()
    for row in rows:
        validate_d3_record("hourly_panel", row)
        key = (str(row["hour_start_utc"]), str(row["token_symbol"]))
        if key in keys:
            raise ValueError(f"duplicate hourly panel row: {key}")
        keys.add(key)
    return hours


def freeze_hourly_dataset(
    rows: list[dict[str, Any]],
    output_dir: Path,
    *,
    required_hours: int = 240,
    required_tokens: set[str] | None = None,
) -> dict[str, Any]:
    """Write validated CSV/Parquet outputs and a checksummed freeze manifest."""
    token_set = required_tokens or set(CORE_TOKEN_SYMBOLS)
    hours = _validate_freeze_rows(
        rows, required_hours=required_hours, required_tokens=token_set
    )
    rows = sorted(rows, key=lambda row: (row["hour_start_utc"], row["token_symbol"]))
    event_id = str(rows[0]["event_id"])
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_name = f"dataset_{event_id}_v1.csv"
    parquet_name = f"dataset_{event_id}_v1.parquet"
    manifest_name = "dataset_manifest.json"
    existing = [output_dir / name for name in (csv_name, parquet_name, manifest_name)]
    if any(path.exists() for path in existing):
        raise FileExistsError("hourly dataset v1 already exists; refusing to overwrite a freeze")

    with tempfile.TemporaryDirectory(dir=output_dir, prefix=".hourly-freeze-") as temp_dir:
        staging = Path(temp_dir)
        csv_path = staging / csv_name
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_PANEL_COLUMNS, extrasaction="raise")
            writer.writeheader()
            writer.writerows(rows)

        jsonl_path = staging / "hourly_panel.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, allow_nan=True) + "\n")
        parquet_path = staging / parquet_name
        jsonl_to_parquet(jsonl_path, "hourly_panel", parquet_path)
        jsonl_path.unlink()

        hashes = {
            csv_name: hashlib.sha256(csv_path.read_bytes()).hexdigest(),
            parquet_name: hashlib.sha256(parquet_path.read_bytes()).hexdigest(),
        }
        manifest = {
            "schema_version": D3_SCHEMA_VERSION,
            "event_id": event_id,
            "row_count": len(rows),
            "hour_count": len(hours),
            "hour_start_utc": hours[0],
            "hour_end_utc_exclusive": _hour_key(_utc_hour(hours[-1]) + timedelta(hours=1)),
            "token_symbols": sorted(token_set),
            "artifacts": hashes,
        }
        manifest_path = staging / manifest_name
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for name in (csv_name, parquet_name, manifest_name):
            os.replace(staging / name, output_dir / name)
    return manifest