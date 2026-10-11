"""GDELT media adapter for news discovery and sentiment analysis (A06).

Queries the GDELT DOC 2.0 API, persists immutable raw source metadata artifacts
under ``data/raw/source/gdelt/{event_id}/...``, and normalizes articles into
:class:`PublicInfoRecord`.

Crucial Invariant:
    Full copyrighted article text is NEVER fetched, scraped, or stored. Only
    article metadata (URL, canonical URL, title, seendate, domain, language) is
    retained.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from defi_lsa.errors import SourceError
from defi_lsa.identifiers import normalize_utc_timestamp
from defi_lsa.retry import (
    RateLimiter,
    RetryPolicy,
    classify_source_error,
    execute_with_retry,
)
from defi_lsa.schemas import PublicInfoRecord, normalize_public_info_record
from defi_lsa.storage import (
    append_normalized_records,
    normalized_path,
    source_path,
    write_source_artifact,
)

# Permitted metadata keys in raw stored artifacts
_ALLOWED_METADATA_KEYS = frozenset(
    {
        "url",
        "url_mobile",
        "title",
        "seendate",
        "socialimage",
        "domain",
        "language",
        "sourcecountry",
    }
)

# Forbidden article content keys to guarantee copyright compliance
_FORBIDDEN_BODY_KEYS = frozenset(
    {
        "body",
        "text",
        "article_text",
        "content",
        "full_text",
        "article_body",
        "raw_content",
        "html",
    }
)


def _format_to_gdelt_datetime(value: str | datetime, is_end: bool = False) -> str:
    """Format an input timestamp into GDELT 14-digit YYYYMMDDHHMMSS format.

    Args:
        value: Input timestamp as ISO string or datetime.
        is_end: If True and date-only is provided, defaults to end of day 23:59:59.

    Returns:
        14-digit string suitable for GDELT startdatetime / enddatetime.

    Raises:
        ValueError: On naive datetimes or unparseable inputs.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError(
                f"naive datetime rejected: {value!r}. Provide timezone-aware datetime."
            )
        return value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S")

    cleaned = str(value).strip()

    # Already 14-digit format: YYYYMMDDHHMMSS
    if re.fullmatch(r"\d{14}", cleaned):
        return cleaned

    # 8-digit format: YYYYMMDD
    if re.fullmatch(r"\d{8}", cleaned):
        return cleaned + ("235959" if is_end else "000000")

    # Date-only ISO format: YYYY-MM-DD
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", cleaned):
        suffix = "T23:59:59Z" if is_end else "T00:00:00Z"
        cleaned = f"{cleaned}{suffix}"

    iso_str = normalize_utc_timestamp(cleaned)
    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return dt.strftime("%Y%m%d%H%M%S")


def _format_gdelt_seendate_to_utc(seendate: str) -> str:
    """Convert GDELT seendate representation to UTC ISO 8601 (YYYY-MM-DDTHH:MM:SSZ).

    Args:
        seendate: GDELT date string (e.g. ``"20230313T120000Z"`` or ``"20230313120000"``).

    Returns:
        Canonical UTC ISO 8601 string ending in ``Z``.
    """
    s = str(seendate).strip()
    if re.fullmatch(r"\d{8}T\d{6}Z", s):
        # Format: 20230313T120000Z
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[9:11]}:{s[11:13]}:{s[13:15]}Z"
    if re.fullmatch(r"\d{14}", s):
        # Format: 20230313120000
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}Z"
    if re.fullmatch(r"\d{8}", s):
        # Format: 20230313
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T00:00:00Z"

    return normalize_utc_timestamp(s)


def _sanitize_article_metadata(article: dict[str, Any]) -> dict[str, Any]:
    """Extract strictly non-copyrighted metadata; strips any body text.

    Ensures the plan requirement that full copyrighted article text is never stored.
    """
    sanitized: dict[str, Any] = {}
    for k, v in article.items():
        if k in _FORBIDDEN_BODY_KEYS:
            continue
        if k in _ALLOWED_METADATA_KEYS:
            sanitized[k] = v
    return sanitized


class GDELTAdapter:
    """GDELT DOC 2.0 API adapter for public news and media metadata (A06).

    Queries article metadata, stores raw metadata responses, and produces
    normalized :class:`PublicInfoRecord` instances.

    Invariant:
        Full article body text is NEVER queried, scraped, or persisted.
    """

    API_BASE_URL: str = "https://api.gdeltproject.org/api/v2/doc/doc"

    def __init__(
        self,
        *,
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        opener: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize the GDELT adapter.

        Args:
            retry_policy: Optional retry policy for transient errors.
            rate_limiter: Optional token-bucket rate limiter.
            opener: Optional URL opener callable (defaults to urllib.request.urlopen).
            sleep_fn: Sleep function for retry backoffs (defaults to time.sleep).
        """
        self.retry_policy = retry_policy or RetryPolicy()
        self.rate_limiter = rate_limiter
        self.opener = opener or urlopen
        self.sleep_fn = sleep_fn

    def _request_json(self, url: str) -> dict[str, Any]:
        """Request JSON from GDELT with retries and error classification."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "defi-lsa/0.1.0",
        }
        req = Request(url, headers=headers, method="GET")

        def _execute() -> dict[str, Any]:
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()
            try:
                with self.opener(req, timeout=30) as resp:
                    raw_data = resp.read()
                    text = raw_data.decode("utf-8", errors="replace").strip()
                    if not text:
                        return {"articles": []}
                    return json.loads(text)
            except HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    body = None
                classified = classify_source_error(
                    exc,
                    status_code=exc.code,
                    response_body=body,
                    headers=dict(exc.headers) if exc.headers else None,
                    source="gdelt",
                )
                raise classified from exc
            except Exception as exc:
                raise classify_source_error(exc, source="gdelt") from exc

        return execute_with_retry(
            _execute,
            policy=self.retry_policy,
            sleep_fn=self.sleep_fn,
        )

    def query_articles(
        self,
        query: str,
        start_date: str | datetime,
        end_date: str | datetime,
        event_id: str,
        max_records: int = 100,
        raw_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> list[PublicInfoRecord]:
        """Query GDELT DOC 2.0 API for news articles matching query and time range.

        Retrieves article metadata, saves sanitized raw source JSON under
        ``data/raw/source/gdelt/{event_id}/...``, and returns normalized
        :class:`PublicInfoRecord` items.

        Full article body text is strictly excluded and never stored.

        Args:
            query: Keyword or phrase query string.
            start_date: Start timestamp (ISO string or datetime).
            end_date: End timestamp (ISO string or datetime).
            event_id: Incident / collection event identifier.
            max_records: Maximum number of records to return (1 - 250).
            raw_dir: Optional root path for source storage.
            output_dir: Optional root path for normalized JSONL storage.

        Returns:
            List of normalized :class:`PublicInfoRecord` instances.

        Raises:
            ValueError: On invalid dates, empty query, or empty event_id.
            SourceError: On API or network errors.
        """
        clean_query = query.strip()
        if not clean_query:
            raise ValueError("query must be a non-empty string")
        if not event_id or not event_id.strip():
            raise ValueError("event_id must be a non-empty string")

        start_gdelt = _format_to_gdelt_datetime(start_date, is_end=False)
        end_gdelt = _format_to_gdelt_datetime(end_date, is_end=True)

        if end_gdelt < start_gdelt:
            raise ValueError(
                f"end_date ({end_gdelt}) must be greater than or equal to start_date ({start_gdelt})"
            )

        bounded_max = min(max(1, max_records), 250)
        params = {
            "query": clean_query,
            "mode": "artlist",
            "format": "json",
            "maxrecords": str(bounded_max),
            "startdatetime": start_gdelt,
            "enddatetime": end_gdelt,
        }
        url = f"{self.API_BASE_URL}?{urlencode(params)}"

        data = self._request_json(url)

        # Sanitize response articles so no copyright-protected text is stored
        raw_articles = data.get("articles", [])
        if not isinstance(raw_articles, list):
            raw_articles = []

        sanitized_articles = [
            _sanitize_article_metadata(a)
            for a in raw_articles
            if isinstance(a, dict)
        ]

        # Save immutable source artifact with metadata only
        source_payload = {
            "query": clean_query,
            "startdatetime": start_gdelt,
            "enddatetime": end_gdelt,
            "articles": sanitized_articles,
        }
        content_bytes = (
            json.dumps(source_payload, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        root = raw_dir or Path.cwd()
        query_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", clean_query)[:32].strip("_")
        if not query_slug:
            query_slug = "query"
        filename = f"gdelt_{query_slug}_{start_gdelt}_{end_gdelt}.json"
        dest_path = source_path("gdelt", event_id, filename, root=root)

        if dest_path.exists():
            sha256 = hashlib.sha256(dest_path.read_bytes()).hexdigest()
        else:
            sha256 = write_source_artifact(dest_path, content_bytes)

        # Normalize into PublicInfoRecords
        records: list[PublicInfoRecord] = []
        for article in sanitized_articles:
            raw_url = str(article.get("url", "")).strip()
            if not raw_url:
                continue
            raw_title = str(article.get("title", "")).strip()
            raw_seendate = str(article.get("seendate", "")).strip()
            if not raw_seendate:
                continue

            published_at_utc = _format_gdelt_seendate_to_utc(raw_seendate)

            record = normalize_public_info_record(
                {
                    "url": raw_url,
                    "canonical_url": raw_url,
                    "title": raw_title,
                    "published_at_utc": published_at_utc,
                    "source": "gdelt",
                },
                event_id=event_id,
                source_sha256=sha256,
            )
            records.append(record)

        if output_dir and records:
            dest_jsonl = normalized_path("gdelt", event_id, root=output_dir)
            record_dicts = [asdict(r) for r in records]
            append_normalized_records(dest_jsonl, record_dicts, key_field="record_key")

        return records

    def query_gdelt_articles(
        self,
        query: str,
        start_date: str | datetime,
        end_date: str | datetime,
        event_id: str,
        *,
        max_records: int = 100,
        raw_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> list[PublicInfoRecord]:
        """Named backlog-compatible alias for metadata-only article collection."""
        return self.query_articles(
            query,
            start_date,
            end_date,
            event_id,
            max_records=max_records,
            raw_dir=raw_dir,
            output_dir=output_dir,
        )
