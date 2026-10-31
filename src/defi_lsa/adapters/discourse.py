"""Discourse forum adapter for incident announcements and discussions (A06).

Retrieves public topic and post metadata from Discourse JSON endpoints, stores
immutable raw artifacts under ``data/raw/source/discourse/{event_id}/topic_{topic_id}.json``,
normalizes into :class:`PublicInfoRecord`, and fails explicitly on inaccessible,
unauthorized, or missing content without storing unauthorized data.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
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


class DiscourseAdapter:
    """Public information adapter for Discourse forums (A06).

    Fetches topic and post metadata from public Discourse JSON endpoints.
    Never stores unauthorized or private content (fails explicitly on 401/403/404).
    """

    def __init__(
        self,
        *,
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        opener: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize the Discourse adapter.

        Args:
            retry_policy: Optional retry policy for transient HTTP errors.
            rate_limiter: Optional token-bucket rate limiter.
            opener: Optional URL opener callable (defaults to urllib.request.urlopen).
            sleep_fn: Sleep function for retry backoffs (defaults to time.sleep).
        """
        self.retry_policy = retry_policy or RetryPolicy()
        self.rate_limiter = rate_limiter
        self.opener = opener or urlopen
        self.sleep_fn = sleep_fn

    def _request_json(self, url: str) -> dict[str, Any]:
        """Request JSON from a public Discourse endpoint with retry and classification."""
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
                    data = resp.read()
                    return json.loads(data.decode("utf-8"))
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
                    source="discourse",
                )
                # 401, 403, and 404 classify as PermanentSourceError subclasses
                raise classified from exc
            except Exception as exc:
                raise classify_source_error(exc, source="discourse") from exc

        return execute_with_retry(
            _execute,
            policy=self.retry_policy,
            sleep_fn=self.sleep_fn,
        )

    def fetch_topic(
        self,
        base_url: str,
        topic_id: int | str,
        event_id: str,
        raw_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> list[PublicInfoRecord]:
        """Fetch a public Discourse topic and extract normalized PublicInfoRecords.

        Retrieves topic JSON via ``{base_url}/t/{topic_id}.json`` and saves
        raw response under ``data/raw/source/discourse/{event_id}/topic_{topic_id}.json``.
        Extracts each post with canonical URL ``{base_url}/t/{slug}/{topic_id}/{post_number}``.

        On 401/403 (unauthorized/forbidden) or 404 (not found), raises the
        classified exception and persists no data.

        Args:
            base_url: Base URL of the forum (e.g. ``"https://governance.aave.com"``).
            topic_id: Numeric topic ID or slug.
            event_id: Incident / collection event identifier.
            raw_dir: Optional root path for source storage.
            output_dir: Optional root path for normalized JSONL storage.

        Returns:
            List of normalized :class:`PublicInfoRecord` instances.

        Raises:
            ValueError: If base_url or event_id is blank.
            AuthenticationError: On HTTP 401 or 403.
            InvalidRequestError: On HTTP 404.
            SourceError: On transient network failure exhaustion.
        """
        if not base_url or not str(base_url).strip():
            raise ValueError("base_url must be a non-empty string")
        if topic_id is None or str(topic_id).strip() == "":
            raise ValueError("topic_id must be provided")
        if not event_id or not event_id.strip():
            raise ValueError("event_id must be a non-empty string")

        clean_base = str(base_url).strip().rstrip("/")
        clean_topic_id = str(topic_id).strip()
        root = raw_dir or Path.cwd()
        filename = f"topic_{clean_topic_id}.json"
        dest_path = source_path("discourse", event_id, filename, root=root)
        if dest_path.exists():
            data = json.loads(dest_path.read_text(encoding="utf-8"))
            sha256 = hashlib.sha256(dest_path.read_bytes()).hexdigest()
        else:
            topic_url = f"{clean_base}/t/{clean_topic_id}.json"
            data = self._request_json(topic_url)
            content_bytes = (
                json.dumps(data, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            sha256 = write_source_artifact(dest_path, content_bytes)

        topic_title = str(data.get("title", "")).strip()
        slug = str(data.get("slug", f"topic-{clean_topic_id}")).strip()
        post_stream = data.get("post_stream", {})
        raw_posts = post_stream.get("posts", [])
        if not isinstance(raw_posts, list):
            raw_posts = []

        records: list[PublicInfoRecord] = []
        for post in raw_posts:
            if not isinstance(post, dict):
                continue
            post_number = post.get("post_number", 1)
            canonical_url = f"{clean_base}/t/{slug}/{clean_topic_id}/{post_number}"
            created_at = post.get("created_at") or data.get("created_at")
            if not created_at:
                continue
            published_at_utc = normalize_utc_timestamp(str(created_at))

            post_title = (
                topic_title
                if post_number == 1
                else f"{topic_title} (Post #{post_number})"
            )

            record = normalize_public_info_record(
                {
                    "url": canonical_url,
                    "canonical_url": canonical_url,
                    "title": post_title,
                    "published_at_utc": published_at_utc,
                    "source": "discourse",
                },
                event_id=event_id,
                source_sha256=sha256,
            )
            records.append(record)

        if output_dir and records:
            dest_jsonl = normalized_path("discourse", event_id, root=output_dir)
            record_dicts = [asdict(r) for r in records]
            append_normalized_records(dest_jsonl, record_dicts, key_field="record_key")

        return records

    def fetch_topic_page(
        self,
        base_url: str,
        topic_id: int | str,
        event_id: str,
        *,
        page: int = 1,
        raw_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> list[PublicInfoRecord]:
        """Fetch one paginated topic page using Discourse's JSON endpoint."""
        if page < 1:
            raise ValueError("page must be >= 1")
        clean_base = str(base_url).strip().rstrip("/")
        if not clean_base or not event_id.strip():
            raise ValueError("base_url and event_id must be non-empty")
        root = raw_dir or Path.cwd()
        filename = f"topic_{str(topic_id).strip()}_page_{page}.json"
        destination = source_path("discourse", event_id, filename, root=root)
        if destination.exists():
            data = json.loads(destination.read_text(encoding="utf-8"))
            source_sha = hashlib.sha256(destination.read_bytes()).hexdigest()
        else:
            data = self._request_json(f"{clean_base}/t/{str(topic_id).strip()}.json?page={page}")
            content = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
            source_sha = write_source_artifact(destination, content)
        slug = str(data.get("slug", f"topic-{topic_id}")).strip()
        title = str(data.get("title", "")).strip()
        records: list[PublicInfoRecord] = []
        for post in data.get("post_stream", {}).get("posts", []):
            if not isinstance(post, dict) or not post.get("created_at"):
                continue
            post_number = post.get("post_number", 1)
            url = f"{clean_base}/t/{slug}/{topic_id}/{post_number}"
            records.append(
                normalize_public_info_record(
                    {
                        "url": url,
                        "canonical_url": url,
                        "title": title,
                        "published_at_utc": normalize_utc_timestamp(post["created_at"]),
                        "source": "discourse",
                    },
                    event_id=event_id,
                    source_sha256=source_sha,
                )
            )
        if output_dir and records:
            append_normalized_records(
                normalized_path("discourse", event_id, root=output_dir),
                [asdict(record) for record in records],
                key_field="record_key",
            )
        return records

    def search_topics(
        self,
        base_url: str,
        query: str,
        event_id: str,
        *,
        page: int = 1,
    ) -> list[dict[str, Any]]:
        """Search public topic metadata without storing private content."""
        if not query.strip() or page < 1:
            raise ValueError("query must be non-empty and page must be >= 1")
        clean_base = str(base_url).strip().rstrip("/")
        from urllib.parse import quote

        data = self._request_json(
            f"{clean_base}/search.json?q={quote(query.strip())}&page={page}"
        )
        return [
            {
                "event_id": event_id,
                "topic_id": item.get("topic_id"),
                "title": item.get("title", ""),
                "url": item.get("url", ""),
            }
            for item in data.get("topics", [])
            if isinstance(item, dict)
        ]
