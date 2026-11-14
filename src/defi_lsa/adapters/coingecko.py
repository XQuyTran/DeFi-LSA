"""CoinGecko price adapter for historical token valuation (A05).

Fetches historical market charts from CoinGecko, persists immutable raw source
artifacts, normalizes price observations to hourly UTC boundaries, appends to
crash-safe JSONL storage, and audits window coverage without price fabrication.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from defi_lsa.errors import AuthenticationError, SourceError
from defi_lsa.identifiers import normalize_address, normalize_utc_timestamp
from defi_lsa.retry import (
    RateLimiter,
    RetryPolicy,
    classify_source_error,
    execute_with_retry,
)
from defi_lsa.schemas import PriceRecord, normalize_price_record
from defi_lsa.storage import (
    append_normalized_records,
    normalized_path,
    source_path,
    write_source_artifact,
)


@dataclass(frozen=True)
class PriceCoverageReport:
    """Coverage metrics for token prices across a requested research window.

    Attributes:
        coin_id: CoinGecko coin slug.
        token_address: Normalized Ethereum token contract address.
        start_hour_utc: Start hour boundary in UTC ISO 8601.
        end_hour_utc: End hour boundary in UTC ISO 8601.
        expected_hours: Total number of hourly boundaries expected.
        collected_hours: Total number of distinct hourly boundaries collected.
        missing_hours: Sorted tuple of missing hour timestamps.
        max_consecutive_gap_hours: Longest contiguous run of missing hours.
        coverage_percentage: Percentage of expected hours collected (0.0 - 100.0).
    """

    coin_id: str
    token_address: str
    start_hour_utc: str
    end_hour_utc: str
    expected_hours: int
    collected_hours: int
    missing_hours: tuple[str, ...]
    max_consecutive_gap_hours: int
    coverage_percentage: float

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary format."""
        return asdict(self)


def calculate_price_coverage(
    records: Iterable[PriceRecord],
    start_dt: str | datetime,
    end_dt: str | datetime,
    *,
    coin_id: str = "",
    token_address: str = "",
) -> PriceCoverageReport:
    """Compute hourly coverage metrics between start_dt and end_dt.

    Args:
        records: Iterable of :class:`PriceRecord` instances.
        start_dt: Beginning of research window (ISO string or datetime).
        end_dt: End of research window (ISO string or datetime).
        coin_id: CoinGecko coin identifier slug.
        token_address: Token contract address.

    Returns:
        A :class:`PriceCoverageReport` detailing missing hours, max gap,
        and coverage percentage.

    Raises:
        ValueError: If dates are invalid or end_dt is earlier than start_dt.
    """
    start_iso = normalize_utc_timestamp(start_dt)
    end_iso = normalize_utc_timestamp(end_dt)

    start_dt_utc = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    end_dt_utc = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))

    start_hour_dt = start_dt_utc.replace(minute=0, second=0, microsecond=0)
    end_hour_dt = end_dt_utc.replace(minute=0, second=0, microsecond=0)

    if end_hour_dt < start_hour_dt:
        raise ValueError(
            f"end_dt ({end_iso}) must be greater than or equal to start_dt ({start_iso})"
        )

    # Build all expected hourly boundary timestamps
    expected_hours_list: list[str] = []
    current_dt = start_hour_dt
    while current_dt <= end_hour_dt:
        expected_hours_list.append(current_dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
        current_dt += timedelta(hours=1)

    collected_set = {
        r.hour_utc
        for r in records
        if start_hour_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        <= r.hour_utc
        <= end_hour_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    missing_list: list[str] = []
    max_gap = 0
    current_gap = 0

    for slot in expected_hours_list:
        if slot not in collected_set:
            missing_list.append(slot)
            current_gap += 1
            if current_gap > max_gap:
                max_gap = current_gap
        else:
            current_gap = 0

    expected_count = len(expected_hours_list)
    collected_count = len(collected_set)
    coverage_pct = (
        round((collected_count / expected_count) * 100.0, 2)
        if expected_count > 0
        else 100.0
    )

    return PriceCoverageReport(
        coin_id=coin_id,
        token_address=token_address,
        start_hour_utc=start_hour_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_hour_utc=end_hour_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expected_hours=expected_count,
        collected_hours=collected_count,
        missing_hours=tuple(missing_list),
        max_consecutive_gap_hours=max_gap,
        coverage_percentage=coverage_pct,
    )


class CoinGeckoAdapter:
    """CoinGecko API adapter for token price series collection (A05).

    Retrieves market chart data, caches immutable source JSON responses,
    normalizes observations into :class:`PriceRecord` entries, and reports
    coverage metrics without fabricating stablecoin values.
    """

    def __init__(
        self,
        api_key: str | None = None,
        api_base_url: str = "https://api.coingecko.com/api/v3",
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        opener: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize the CoinGecko adapter.

        Args:
            api_key: Optional CoinGecko demo or pro API key.
            api_base_url: Base URL for CoinGecko API endpoints.
            retry_policy: Resilient retry policy for network requests.
            rate_limiter: Optional token-bucket rate limiter.
            opener: Optional URL opener callable (defaults to urllib.request.urlopen).
            sleep_fn: Sleep function for retry backoffs (defaults to time.sleep).
        """
        self.api_key = api_key
        self.api_base_url = api_base_url.rstrip("/")
        self.retry_policy = retry_policy or RetryPolicy()
        self.rate_limiter = rate_limiter
        self.opener = opener or urlopen
        self.sleep_fn = sleep_fn
        self.last_coverage_report: PriceCoverageReport | None = None

    def _request_json(self, url: str) -> dict[str, Any]:
        """Execute HTTP request with authentication, rate limiting, and retries."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "defi-lsa/0.1.0",
        }
        if self.api_key:
            host = (urlparse(self.api_base_url).hostname or "").lower()
            if host == "pro-api.coingecko.com":
                headers["x-cg-pro-api-key"] = self.api_key
            else:
                headers["x-cg-demo-api-key"] = self.api_key

        req = Request(url, headers=headers, method="GET")

        def _execute() -> dict[str, Any]:
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()
            try:
                with self.opener(req, timeout=30) as resp:
                    data = resp.read()
                    return json.loads(data.decode("utf-8"))
            except HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    body = None
                if exc.code == 401 and not self.api_key:
                    raise AuthenticationError(
                        "keyless request rejected; set COINGECKO_API_KEY for CoinGecko Demo access",
                        source="coingecko",
                        details={"status_code": exc.code},
                    ) from exc
                classified = classify_source_error(
                    exc,
                    status_code=exc.code,
                    response_body=body,
                    headers=dict(exc.headers) if exc.headers else None,
                    source="coingecko",
                )
                raise classified from exc
            except Exception as exc:
                raise classify_source_error(exc, source="coingecko") from exc

        return execute_with_retry(
            _execute,
            policy=self.retry_policy,
            sleep_fn=self.sleep_fn,
        )

    def fetch_market_chart_range(
        self,
        coin_id: str,
        vs_currency: str = "usd",
        from_timestamp: int = 0,
        to_timestamp: int = 0,
        *,
        event_id: str | None = None,
        raw_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Fetch historical market chart data within a UNIX timestamp range.

        Calls ``/coins/{id}/market_chart/range?vs_currency=...&from=...&to=...``.
        If *event_id* is provided, persists the raw response as a source artifact
        under ``data/raw/source/coingecko/{event_id}/{coin_id}_{from}_{to}.json``.

        Args:
            coin_id: CoinGecko asset slug (e.g. ``"usd-coin"``, ``"ethereum"``).
            vs_currency: Target quote currency (default ``"usd"``).
            from_timestamp: Start timestamp in UNIX seconds.
            to_timestamp: End timestamp in UNIX seconds.
            event_id: Optional incident event identifier for artifact storage.
            raw_dir: Optional root path for source storage.

        Returns:
            Raw response dictionary parsed from JSON.

        Raises:
            ValueError: If coin_id is blank or timestamp range is invalid.
            SourceError: On network or API failures.
        """
        if not coin_id or not coin_id.strip():
            raise ValueError("coin_id must be a non-empty string")
        if to_timestamp < from_timestamp:
            raise ValueError(
                f"to_timestamp ({to_timestamp}) must be >= from_timestamp ({from_timestamp})"
            )

        params = {
            "vs_currency": vs_currency.lower().strip(),
            "from": str(from_timestamp),
            "to": str(to_timestamp),
        }
        url = f"{self.api_base_url}/coins/{coin_id.strip()}/market_chart/range?{urlencode(params)}"
        if event_id:
            root = raw_dir or Path.cwd()
            filename = f"{coin_id.strip()}_{from_timestamp}_{to_timestamp}.json"
            dest_path = source_path("coingecko", event_id, filename, root=root)
            if dest_path.exists():
                data = json.loads(dest_path.read_text(encoding="utf-8"))
                sha256 = hashlib.sha256(dest_path.read_bytes()).hexdigest()
            else:
                data = self._request_json(url)
                content_bytes = (
                    json.dumps(data, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                sha256 = write_source_artifact(dest_path, content_bytes)
            data["_source_sha256"] = sha256
        else:
            data = self._request_json(url)

        return data

    def collect_hourly_prices(
        self,
        token_address: str,
        coin_id: str,
        event_id: str,
        start_dt: str | datetime,
        end_dt: str | datetime,
        output_dir: Path | None = None,
        raw_dir: Path | None = None,
        coverage_report_path: Path | None = None,
    ) -> list[PriceRecord]:
        """Collect and normalize hourly prices for a token in the research window.

        Retrieves market chart points from CoinGecko, normalizes each point into a
        :class:`PriceRecord` with exact hour UTC boundaries, appends to the
        normalized JSONL storage at
        ``data/raw/normalized/prices/coingecko/{event_id}.jsonl``, and calculates
        coverage audit metrics.

        Market prices for stablecoins are never forced to 1.0 USD; raw market
        observations are preserved exactly as reported.

        Args:
            token_address: Ethereum contract address of the token.
            coin_id: CoinGecko coin slug.
            event_id: Incident / collection event identifier.
            start_dt: Window start (ISO string or timezone-aware datetime).
            end_dt: Window end (ISO string or timezone-aware datetime).
            output_dir: Optional root path for normalized JSONL storage.
            raw_dir: Optional root path for raw source artifact storage.

        Returns:
            List of normalized :class:`PriceRecord` instances for the window.

        Raises:
            ValueError: On invalid address, invalid timestamp, or range error.
            SourceError: On network or provider errors.
        """
        norm_address = normalize_address(token_address)
        clean_coin_id = coin_id.strip()
        if not clean_coin_id:
            raise ValueError("coin_id must be a non-empty string")
        if not event_id or not event_id.strip():
            raise ValueError("event_id must be a non-empty string")

        start_iso = normalize_utc_timestamp(start_dt)
        end_iso = normalize_utc_timestamp(end_dt)
        start_datetime = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_datetime = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))

        if end_datetime < start_datetime:
            raise ValueError(
                f"end_dt ({end_iso}) must be greater than or equal to start_dt ({start_iso})"
            )

        from_ts = int(start_datetime.timestamp())
        to_ts = int(end_datetime.timestamp())

        # Retrieve raw chart range data and save raw source artifact
        chart_data = self.fetch_market_chart_range(
            coin_id=clean_coin_id,
            vs_currency="usd",
            from_timestamp=from_ts,
            to_timestamp=to_ts,
            event_id=event_id,
            raw_dir=raw_dir,
        )

        source_sha = chart_data.get("_source_sha256")
        if not source_sha:
            source_bytes = (
                json.dumps(chart_data, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            source_sha = hashlib.sha256(source_bytes).hexdigest()

        raw_prices = chart_data.get("prices", [])
        if not isinstance(raw_prices, list):
            raw_prices = []

        # Deduplicate multiple observations within the same hour boundary.
        # For each hour boundary, choose the observation closest to the hour mark.
        hourly_candidates: dict[str, tuple[int, float, int]] = {}
        for entry in raw_prices:
            if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                continue
            ts_ms, price = entry[0], entry[1]
            if not isinstance(ts_ms, (int, float)) or not isinstance(
                price, (int, float)
            ):
                continue
            unix_sec = int(ts_ms / 1000)
            dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
            hour_boundary_dt = dt_utc.replace(minute=0, second=0, microsecond=0)
            hour_iso = hour_boundary_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            target_sec = int(hour_boundary_dt.timestamp())
            distance = abs(unix_sec - target_sec)

            if hour_iso not in hourly_candidates or distance < hourly_candidates[hour_iso][2]:
                hourly_candidates[hour_iso] = (unix_sec, float(price), distance)

        # Build normalized PriceRecords sorted by hour
        retrieved_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        records: list[PriceRecord] = []
        for hour_iso in sorted(hourly_candidates.keys()):
            unix_sec, price, _ = hourly_candidates[hour_iso]
            record = normalize_price_record(
                {
                    "token_address": norm_address,
                    "coingecko_id": clean_coin_id,
                    "source_timestamp": unix_sec,
                    "usd_price": price,
                    "source": "coingecko",
                    "retrieved_at_utc": retrieved_at_utc,
                },
                event_id=event_id,
                source_sha256=source_sha,
            )
            records.append(record)

        # Append to crash-safe normalized storage
        root = output_dir or Path.cwd()
        dest_path = normalized_path("prices/coingecko", event_id, root=root)
        record_dicts = [asdict(r) for r in records]
        append_normalized_records(dest_path, record_dicts, key_field="record_key")

        # Compute and record coverage report
        self.last_coverage_report = calculate_price_coverage(
            records,
            start_iso,
            end_iso,
            coin_id=clean_coin_id,
            token_address=norm_address,
        )
        if coverage_report_path is not None:
            coverage_report_path.parent.mkdir(parents=True, exist_ok=True)
            coverage_report_path.write_text(
                json.dumps(self.last_coverage_report.to_dict(), indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )

        return records
