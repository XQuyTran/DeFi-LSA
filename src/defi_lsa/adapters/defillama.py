"""DefiLlama historical price adapter for fixed incident-time anchors."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from defi_lsa.retry import RateLimiter, RetryPolicy, classify_source_error, execute_with_retry
from defi_lsa.storage import source_path, write_source_artifact


DEFAULT_API_BASE_URL = "https://coins.llama.fi/prices"
_BACKTRACK_SECONDS = 300


def _parse_utc(value: str | datetime) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("anchor_timestamp must be timezone-aware UTC")
    return parsed.astimezone(timezone.utc)


def _iso_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DefiLlamaAdapter:
    """Fetch one as-of-UTC price per token, rejecting post-anchor observations."""

    def __init__(
        self,
        *,
        api_base_url: str = DEFAULT_API_BASE_URL,
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        opener: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        max_age_seconds: int = 3600,
    ) -> None:
        if not api_base_url.startswith(("http://", "https://")):
            raise ValueError("api_base_url must be an HTTP(S) URL")
        if max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative")
        self.api_base_url = api_base_url.rstrip("/")
        self.retry_policy = retry_policy or RetryPolicy()
        self.rate_limiter = rate_limiter or RateLimiter(requests_per_second=2.0)
        self.opener = opener or urlopen
        self.sleep_fn = sleep_fn
        self.max_age_seconds = max_age_seconds

    def _fetch_json(self, url: str) -> bytes:
        def request() -> bytes:
            self.rate_limiter.acquire()
            req = Request(url, headers={"Accept": "application/json", "User-Agent": "defi-lsa/0.1"})
            try:
                response = self.opener(req, timeout=30)
                with response:
                    return response.read()
            except HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                raise classify_source_error(
                    status_code=exc.code,
                    response_body=body,
                    source="defillama",
                ) from exc
            except URLError as exc:
                raise classify_source_error(exc, source="defillama") from exc

        return execute_with_retry(request, self.retry_policy, sleep_fn=self.sleep_fn)

    def _load_or_fetch(
        self,
        *,
        event_id: str,
        symbol: str,
        coin: str,
        query_timestamp: int,
        output_root: Path,
    ) -> tuple[dict[str, Any], str]:
        safe_symbol = "".join(char.lower() if char.isalnum() else "_" for char in symbol)
        filename = f"historical_{query_timestamp}_{safe_symbol}.json"
        path = source_path("defillama", event_id, filename, output_root)
        if path.exists():
            raw_bytes = path.read_bytes()
        else:
            url = (
                f"{self.api_base_url}/historical/{query_timestamp}/"
                    f"{quote(coin, safe=':')}"
            )
            raw_bytes = self._fetch_json(url)
            write_source_artifact(path, raw_bytes)
        try:
            payload = json.loads(raw_bytes)
        except json.JSONDecodeError as exc:
            raise ValueError(f"DefiLlama returned malformed JSON for {symbol}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"DefiLlama response for {symbol} must be a JSON object")
        return payload, hashlib.sha256(raw_bytes).hexdigest()

    def fetch_anchor_prices(
        self,
        *,
        event_id: str,
        tokens: list[Mapping[str, Any]],
        anchor_timestamp: str | datetime,
        output_root: Path,
        report_path: Path,
        fixed_fallback_prices: Mapping[str, float] | None = None,
    ) -> dict[str, Any]:
        """Fetch pre-anchor token prices and report any required manual fallback.

        Tokens require ``symbol`` and Ethereum ``address``. If DefiLlama's
        nearest observation is after T0, the request is repeated five minutes
        earlier. A quote is accepted only when its observation is no later than
        T0 and is within ``max_age_seconds``.
        """
        anchor = _parse_utc(anchor_timestamp)
        anchor_unix = int(anchor.timestamp())
        anchor_iso = anchor.strftime("%Y-%m-%dT%H:%M:%SZ")
        fixed_fallback_prices = fixed_fallback_prices or {}
        records: list[dict[str, Any]] = []
        missing: list[dict[str, str]] = []

        for token in tokens:
            symbol = str(token.get("symbol", "")).strip()
            address = str(token.get("address", "")).strip().lower()
            if not symbol or not address.startswith("0x"):
                raise ValueError("each token requires a symbol and Ethereum contract address")
            coin = f"ethereum:{address}"
            candidates = (anchor_unix, anchor_unix - _BACKTRACK_SECONDS)
            observation: dict[str, Any] | None = None
            reason = "price_unavailable"

            for query_timestamp in candidates:
                try:
                    payload, digest = self._load_or_fetch(
                        event_id=event_id,
                        symbol=symbol,
                        coin=coin,
                        query_timestamp=query_timestamp,
                        output_root=Path(output_root),
                    )
                except Exception as exc:
                    reason = f"source_error:{type(exc).__name__}"
                    continue
                coin_payload = payload.get("coins", {}).get(coin)
                if not isinstance(coin_payload, dict):
                    reason = "no_price_returned"
                    continue
                try:
                    price = float(coin_payload["price"])
                    observed_at = int(coin_payload["timestamp"])
                    confidence = float(coin_payload.get("confidence", math.nan))
                except (KeyError, TypeError, ValueError):
                    reason = "malformed_price_record"
                    continue
                if not math.isfinite(price) or price <= 0:
                    reason = "invalid_price"
                    continue
                if observed_at > anchor_unix:
                    reason = "post_anchor_observation"
                    continue
                if anchor_unix - observed_at > self.max_age_seconds:
                    reason = "stale_observation"
                    continue
                observation = {
                    "symbol": symbol,
                    "token_address": address,
                    "usd_price": price,
                    "anchor_timestamp_utc": anchor_iso,
                    "observed_timestamp_utc": _iso_utc(observed_at),
                    "confidence": confidence if math.isfinite(confidence) else None,
                    "source": "defillama",
                    "source_sha256": digest,
                }
                break

            if observation is None:
                fallback = fixed_fallback_prices.get(symbol)
                try:
                    fallback_price = float(fallback) if fallback is not None else math.nan
                except (TypeError, ValueError):
                    fallback_price = math.nan
                if math.isfinite(fallback_price) and fallback_price > 0:
                    observation = {
                        "symbol": symbol,
                        "token_address": address,
                        "usd_price": fallback_price,
                        "anchor_timestamp_utc": anchor_iso,
                        "observed_timestamp_utc": anchor_iso,
                        "confidence": None,
                        "source": "fixed_price_anchor",
                        "source_sha256": "",
                    }
                else:
                    missing.append({"symbol": symbol, "reason": reason})
                    continue
            records.append(observation)

        prices = {record["symbol"]: record["usd_price"] for record in records}
        price_metadata = {
            record["symbol"]: {
                "source": record["source"],
                "observed_timestamp_utc": record["observed_timestamp_utc"],
                "confidence": record["confidence"],
            }
            for record in records
        }
        report = {
            "event_id": event_id,
            "anchor_timestamp_utc": anchor_iso,
            "anchor_semantics": "latest accepted observation at or before T0",
            "records": records,
            "prices": prices,
            "missing_tokens": missing,
            "fallback_required": [item["symbol"] for item in missing],
            "fallback_price_timestamp_utc": anchor_iso if missing else None,
        }
        report_path = Path(report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(dir=report_path.parent, prefix=".price-anchor-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True, allow_nan=True)
                handle.write("\n")
            os.replace(temporary_name, report_path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return {**report, "prices": prices, "anchor_price_metadata": price_metadata}