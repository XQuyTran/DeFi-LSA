"""Structured collection metrics and run summaries."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class CollectionMetrics:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    event_id: str = ""
    collector: str = ""
    requests_total: int = 0
    requests_failed: int = 0
    rate_limit_events: int = 0
    records_received: int = 0
    records_written: int = 0
    records_skipped: int = 0
    current_block: int | None = None
    completed_range_percentage: float = 0.0
    bytes_written: int = 0
    retry_count: int = 0
    status: str = "running"
    errors: list[dict[str, Any]] = field(default_factory=list)

    def record_error(self, error: Exception, **context: Any) -> None:
        self.requests_failed += 1
        self.errors.append({
            "type": type(error).__name__,
            "message": str(error),
            **context,
        })

    def write_summary(self, path: Path) -> None:
        self.status = "failed" if self.errors else "completed"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        payload["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
