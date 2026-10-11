"""Metadata-only protocol announcement adapter (A06)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

from defi_lsa.identifiers import normalize_utc_timestamp
from defi_lsa.schemas import PublicInfoRecord, normalize_public_info_record
from defi_lsa.storage import append_normalized_records, normalized_path, source_path, write_source_artifact


class ProtocolAnnouncementAdapter:
    """Collect official announcement metadata without scraping article bodies."""

    def __init__(self, opener: Callable[..., Any] | None = None) -> None:
        self.opener = opener or urlopen

    def _request(self, url: str) -> Any:
        request = Request(
            url,
            headers={"Accept": "application/json, application/rss+xml", "User-Agent": "defi-lsa/0.1.0"},
            method="GET",
        )
        with self.opener(request, timeout=30) as response:
            return response.read()

    def fetch_protocol_feed(
        self,
        feed_url: str,
        event_id: str,
        *,
        raw_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> list[PublicInfoRecord]:
        """Fetch a JSON feed containing announcement metadata."""
        if not feed_url.strip() or not event_id.strip():
            raise ValueError("feed_url and event_id must be non-empty")
        content = self._request(feed_url)
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("protocol feed must be valid JSON") from exc
        items = payload.get("items", payload.get("articles", []))
        if not isinstance(items, list):
            raise ValueError("protocol feed items must be a list")
        root = raw_dir or Path.cwd()
        filename = f"feed_{hashlib.sha256(feed_url.encode()).hexdigest()[:16]}.json"
        safe_payload = {
            "items": [
                {
                    key: item.get(key)
                    for key in ("title", "url", "link", "published_at", "published", "date")
                    if key in item
                }
                for item in items
                if isinstance(item, dict)
            ]
        }
        safe_content = (json.dumps(safe_payload, indent=2, sort_keys=True) + "\n").encode()
        destination = source_path("protocol", event_id, filename, root=root)
        source_sha = (
            hashlib.sha256(destination.read_bytes()).hexdigest()
            if destination.exists()
            else write_source_artifact(destination, safe_content)
        )
        records = [self.normalize_announcement_metadata(item, event_id, source_sha) for item in items]
        records = [record for record in records if record is not None]
        if output_dir and records:
            append_normalized_records(
                normalized_path("protocol", event_id, root=output_dir),
                [asdict(record) for record in records],
                key_field="record_key",
            )
        return records

    def normalize_announcement_metadata(
        self,
        item: dict[str, Any],
        event_id: str,
        source_sha256: str,
    ) -> PublicInfoRecord | None:
        url = str(item.get("url") or item.get("link") or "").strip()
        published = item.get("published_at") or item.get("published") or item.get("date")
        if not url or not published:
            return None
        return normalize_public_info_record(
            {
                "url": url,
                "canonical_url": url,
                "title": str(item.get("title", "")).strip(),
                "published_at_utc": normalize_utc_timestamp(str(published)),
                "source": "protocol",
            },
            event_id=event_id,
            source_sha256=source_sha256,
        )
