"""Persistent checkpoint store and range tracking (A02).

Manages per-collector checkpoints for reproducible and crash-resilient
data collection. Checkpoints track requested boundaries, coalesced completed
ranges, and failed ranges with structured failure details.

Storage Layout
--------------
``data/checkpoints/{event_id}/{collector}.json``
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from defi_lsa.identifiers import normalize_utc_timestamp
from defi_lsa.registry import ContractScope

# ---------------------------------------------------------------------------
# Base path constant
# ---------------------------------------------------------------------------

DEFAULT_CHECKPOINT_DIR = Path("data/checkpoints")


# ---------------------------------------------------------------------------
# Range coalescing and difference helpers
# ---------------------------------------------------------------------------


def coalesce_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Coalesce overlapping or adjacent inclusive integer ranges into minimal sorted ranges.

    Adjacent ranges like ``(1, 5)`` and ``(6, 10)`` merge into ``(1, 10)``.
    Overlapping ranges like ``(1, 5)`` and ``(3, 8)`` merge into ``(1, 8)``.
    Contained ranges like ``(1, 10)`` and ``(3, 7)`` merge into ``(1, 10)``.

    Args:
        ranges: Iterable of ``(start, end)`` tuples, where ``start <= end``.

    Returns:
        Sorted, non-overlapping, non-adjacent list of ``(start, end)`` tuples.

    Raises:
        ValueError: If any range has ``start > end``.
    """
    normalized: list[tuple[int, int]] = []
    for s, e in ranges:
        start, end = int(s), int(e)
        if start > end:
            raise ValueError(f"Invalid range: start ({start}) > end ({end})")
        normalized.append((start, end))

    if not normalized:
        return []

    normalized.sort(key=lambda r: (r[0], r[1]))
    merged: list[tuple[int, int]] = [normalized[0]]

    for current_start, current_end in normalized[1:]:
        prev_start, prev_end = merged[-1]
        # In discrete integer space, [1, 5] and [6, 10] are adjacent (5 + 1 == 6)
        if current_start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, current_end))
        else:
            merged.append((current_start, current_end))

    return merged


def compute_pending_ranges(
    requested_start: int,
    requested_end: int,
    excluded_ranges: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Compute remaining pending ranges within [requested_start, requested_end] after subtracting excluded_ranges.

    All ranges are inclusive integer intervals.

    Args:
        requested_start: Inclusive start of requested window.
        requested_end: Inclusive end of requested window.
        excluded_ranges: Iterable of inclusive ranges to exclude.

    Returns:
        List of sorted, non-overlapping pending inclusive ranges.

    Raises:
        ValueError: If ``requested_start > requested_end``.
    """
    req_start, req_end = int(requested_start), int(requested_end)
    if req_start > req_end:
        raise ValueError(
            f"requested_start ({req_start}) must be <= requested_end ({req_end})"
        )

    coalesced = coalesce_ranges(excluded_ranges)
    pending: list[tuple[int, int]] = []
    curr = req_start

    for excl_start, excl_end in coalesced:
        if excl_end < curr:
            continue
        if excl_start > req_end:
            break
        if excl_start > curr:
            pending.append((curr, min(excl_start - 1, req_end)))
        curr = max(curr, excl_end + 1)
        if curr > req_end:
            break

    if curr <= req_end:
        pending.append((curr, req_end))

    return pending


def _remove_completed_from_failed(
    failed_ranges: list[dict[str, Any]],
    comp_start: int,
    comp_end: int,
) -> list[dict[str, Any]]:
    """Remove or trim failed ranges that overlap with a newly completed range [comp_start, comp_end]."""
    updated: list[dict[str, Any]] = []
    for entry in failed_ranges:
        f_start = int(entry["start"])
        f_end = int(entry["end"])

        # No overlap
        if comp_end < f_start or comp_start > f_end:
            updated.append(dict(entry))
            continue

        # Completely covered by newly completed range
        if comp_start <= f_start and comp_end >= f_end:
            continue

        # Partially covered on right
        if f_start < comp_start and f_end <= comp_end:
            trimmed = dict(entry)
            trimmed["end"] = comp_start - 1
            updated.append(trimmed)
        # Partially covered on left
        elif comp_start <= f_start and f_end > comp_end:
            trimmed = dict(entry)
            trimmed["start"] = comp_end + 1
            updated.append(trimmed)
        # Completed range is strictly inside the failed range (splits failed range)
        elif f_start < comp_start and f_end > comp_end:
            left_trimmed = dict(entry)
            left_trimmed["end"] = comp_start - 1
            right_trimmed = dict(entry)
            right_trimmed["start"] = comp_end + 1
            updated.extend([left_trimmed, right_trimmed])

    return updated


# ---------------------------------------------------------------------------
# Scope hashing
# ---------------------------------------------------------------------------


def compute_scope_hash(scope: ContractScope) -> str:
    """Calculate deterministic SHA-256 hex digest over chain_id and sorted lowercase addresses.

    Addresses are trimmed, lowercased, and deduplicated before hashing.

    Args:
        scope: ContractScope containing chain_id and addresses.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    sorted_addresses = sorted({addr.strip().lower() for addr in scope.addresses})
    payload = json.dumps(
        {
            "addresses": sorted_addresses,
            "chain_id": int(scope.chain_id),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Checkpoint dataclass
# ---------------------------------------------------------------------------


@dataclass
class Checkpoint:
    """Persistent progress tracking for a single collector and incident event.

    Attributes:
        event_id: Incident / event identifier (e.g. ``"euler_2023-03-13"``).
        collector: Collector stage name (e.g. ``"blocks"``, ``"transactions"``, ``"receipts"``, ``"logs"``).
        scope_hash: SHA-256 digest of the ContractScope addresses and chain_id.
        requested_start: Starting block/unit of the overall requested collection range.
        requested_end: Ending block/unit of the overall requested collection range.
        completed_ranges: List of inclusive ``[start, end]`` ranges that have been successfully retrieved.
        failed_ranges: List of failure dicts containing start, end, error_type, message, retries, and timestamp_utc.
        updated_at_utc: UTC ISO 8601 timestamp string with Z suffix marking the last update.
        adapter_version: Version of the collector adapter that produced this checkpoint.
        metadata: Arbitrary extra key-value pairs for collector-specific bookkeeping.
    """

    event_id: str
    collector: str
    scope_hash: str
    requested_start: int
    requested_end: int
    completed_ranges: list[tuple[int, int]]
    failed_ranges: list[dict[str, Any]]
    updated_at_utc: str
    adapter_version: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id must not be empty")
        if not self.collector:
            raise ValueError("collector must not be empty")
        if not self.scope_hash:
            raise ValueError("scope_hash must not be empty")
        if self.requested_start < 0:
            raise ValueError(f"requested_start must be >= 0, got {self.requested_start}")
        if self.requested_end < self.requested_start:
            raise ValueError(
                f"requested_end ({self.requested_end}) must be >= requested_start ({self.requested_start})"
            )
        # Always coalesce completed_ranges into canonical form
        self.completed_ranges = coalesce_ranges(self.completed_ranges)
        # Ensure updated_at_utc is valid UTC ISO 8601
        self.updated_at_utc = normalize_utc_timestamp(self.updated_at_utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert checkpoint to a JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "collector": self.collector,
            "scope_hash": self.scope_hash,
            "requested_start": self.requested_start,
            "requested_end": self.requested_end,
            "completed_ranges": [[s, e] for s, e in self.completed_ranges],
            "failed_ranges": self.failed_ranges,
            "updated_at_utc": self.updated_at_utc,
            "adapter_version": self.adapter_version,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Checkpoint:
        """Construct a Checkpoint instance from a dictionary."""
        required = {
            "event_id",
            "collector",
            "scope_hash",
            "requested_start",
            "requested_end",
            "completed_ranges",
            "failed_ranges",
            "updated_at_utc",
            "adapter_version",
        }
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required checkpoint fields: {sorted(missing)}")

        raw_completed = data["completed_ranges"]
        completed_ranges = [(int(item[0]), int(item[1])) for item in raw_completed]

        raw_failed = data["failed_ranges"]
        failed_ranges = [dict(item) for item in raw_failed]

        return cls(
            event_id=str(data["event_id"]),
            collector=str(data["collector"]),
            scope_hash=str(data["scope_hash"]),
            requested_start=int(data["requested_start"]),
            requested_end=int(data["requested_end"]),
            completed_ranges=completed_ranges,
            failed_ranges=failed_ranges,
            updated_at_utc=normalize_utc_timestamp(str(data["updated_at_utc"])),
            adapter_version=str(data["adapter_version"]),
            metadata=dict(data.get("metadata", {})),
        )


# ---------------------------------------------------------------------------
# Scope validation & pending ranges functions
# ---------------------------------------------------------------------------


def validate_checkpoint_scope(
    checkpoint: Checkpoint,
    scope: ContractScope,
    requested_start: int,
    requested_end: int,
    *,
    strict: bool = False,
) -> bool:
    """Validate that a checkpoint matches the given ContractScope and requested range.

    Args:
        checkpoint: Checkpoint to validate.
        scope: Target ContractScope.
        requested_start: Expected requested_start boundary.
        requested_end: Expected requested_end boundary.
        strict: If True, raise ValueError on validation failure; otherwise return False.

    Returns:
        True if valid; False if invalid and strict is False.

    Raises:
        ValueError: If validation fails and strict is True.
    """
    errors: list[str] = []

    if checkpoint.event_id != scope.event_id:
        errors.append(
            f"event_id mismatch: checkpoint has {checkpoint.event_id!r}, "
            f"scope has {scope.event_id!r}"
        )

    expected_scope_hash = compute_scope_hash(scope)
    if checkpoint.scope_hash != expected_scope_hash:
        errors.append(
            f"scope_hash mismatch: checkpoint has {checkpoint.scope_hash!r}, "
            f"expected {expected_scope_hash!r}"
        )

    if checkpoint.requested_start != requested_start:
        errors.append(
            f"requested_start mismatch: checkpoint has {checkpoint.requested_start}, "
            f"expected {requested_start}"
        )

    if checkpoint.requested_end != requested_end:
        errors.append(
            f"requested_end mismatch: checkpoint has {checkpoint.requested_end}, "
            f"expected {requested_end}"
        )

    if errors:
        if strict:
            raise ValueError(f"Checkpoint invalidated: {'; '.join(errors)}")
        return False

    return True


def get_pending_ranges(
    checkpoint: Checkpoint,
    *,
    retry_failed: bool = False,
    include_failed: bool = False,
) -> list[tuple[int, int]]:
    """Compute the remaining pending [start, end] ranges to fetch for a checkpoint.

    Given the checkpoint's requested [start, end] boundaries and completed_ranges,
    calculates which intervals remain. Failed ranges are excluded from pending ranges
    (i.e. not retried) unless retry_failed (or include_failed) is explicitly True.

    Args:
        checkpoint: The Checkpoint to analyze.
        retry_failed: If True, include failed ranges in pending so they can be retried.
        include_failed: Alias for retry_failed.

    Returns:
        List of sorted, non-overlapping inclusive [start, end] intervals to fetch.
    """
    excluded: list[tuple[int, int]] = list(checkpoint.completed_ranges)

    should_retry = retry_failed or include_failed
    if not should_retry:
        for entry in checkpoint.failed_ranges:
            excluded.append((int(entry["start"]), int(entry["end"])))

    return compute_pending_ranges(
        checkpoint.requested_start,
        checkpoint.requested_end,
        excluded,
    )


def checkpoint_path(
    event_id: str,
    collector: str,
    base_dir: Path | str | None = None,
) -> Path:
    """Return the canonical file path for an event and collector checkpoint."""
    base = Path(base_dir) if base_dir is not None else DEFAULT_CHECKPOINT_DIR
    return base / event_id / f"{collector}.json"


# ---------------------------------------------------------------------------
# CheckpointStore
# ---------------------------------------------------------------------------


class CheckpointStore:
    """Manages reading, writing, and updating persistent collection checkpoints.

    Default storage path convention:
        ``{base_dir}/{event_id}/{collector}.json``
    """

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else DEFAULT_CHECKPOINT_DIR

    def checkpoint_path(self, event_id: str, collector: str) -> Path:
        """Return the canonical file path for an event and collector checkpoint."""
        return checkpoint_path(event_id, collector, self.base_dir)

    def load_checkpoint(self, event_id: str, collector: str) -> Checkpoint | None:
        """Load and deserialize a Checkpoint from disk, or return None if not found.

        Raises:
            ValueError: If the file exists but contains corrupted or invalid JSON.
        """
        path = self.checkpoint_path(event_id, collector)
        if not path.exists():
            return None
        try:
            raw_text = path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            return Checkpoint.from_dict(data)
        except Exception as exc:
            raise ValueError(f"Corrupted or invalid checkpoint file at {path}: {exc}") from exc

    def save_checkpoint_atomic(self, checkpoint: Checkpoint) -> None:
        """Atomically persist a Checkpoint to disk via temp-file + fsync + replace.

        The checkpoint is written to a temporary file in the destination directory,
        flushed, fsynced to disk, and atomically replaced into the final target path.
        """
        path = self.checkpoint_path(checkpoint.event_id, checkpoint.collector)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw_bytes = (
            json.dumps(checkpoint.to_dict(), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        # Write to a sibling temp file then replace atomically
        tmp_fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_cp_")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(tmp_fd, "wb") as handle:
                handle.write(raw_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def validate_checkpoint_scope(
        self,
        checkpoint: Checkpoint,
        scope: ContractScope,
        requested_start: int,
        requested_end: int,
        *,
        strict: bool = False,
    ) -> bool:
        """Validate that a checkpoint matches the given scope and range."""
        return validate_checkpoint_scope(
            checkpoint=checkpoint,
            scope=scope,
            requested_start=requested_start,
            requested_end=requested_end,
            strict=strict,
        )

    def mark_range_completed(
        self,
        event_id: str,
        collector: str,
        start: int,
        end: int,
        *,
        scope_hash: str | None = None,
        requested_start: int | None = None,
        requested_end: int | None = None,
        adapter_version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Checkpoint:
        """Mark [start, end] as completed in the checkpoint, coalesce ranges, and save.

        If the checkpoint does not yet exist on disk, a new one is initialized.
        If any previously failed range overlaps with [start, end], the failed range
        is removed or trimmed accordingly.

        Args:
            event_id: Incident / event identifier.
            collector: Collector stage name.
            start: Inclusive start of completed range.
            end: Inclusive end of completed range.
            scope_hash: Scope hash if creating a new checkpoint.
            requested_start: Requested start boundary if creating or updating.
            requested_end: Requested end boundary if creating or updating.
            adapter_version: Adapter version string.
            metadata: Additional metadata dictionary.

        Returns:
            The updated Checkpoint instance.
        """
        start, end = int(start), int(end)
        if start > end:
            raise ValueError(f"Invalid range: start ({start}) > end ({end})")

        now_utc = normalize_utc_timestamp(datetime.now(timezone.utc))
        existing = self.load_checkpoint(event_id, collector)

        if existing is None:
            r_start = requested_start if requested_start is not None else start
            r_end = requested_end if requested_end is not None else end
            checkpoint = Checkpoint(
                event_id=event_id,
                collector=collector,
                scope_hash=scope_hash or "unspecified",
                requested_start=r_start,
                requested_end=r_end,
                completed_ranges=[(start, end)],
                failed_ranges=[],
                updated_at_utc=now_utc,
                adapter_version=adapter_version or "1.0.0",
                metadata=dict(metadata or {}),
            )
        else:
            merged_completed = coalesce_ranges(existing.completed_ranges + [(start, end)])
            updated_failed = _remove_completed_from_failed(
                existing.failed_ranges,
                start,
                end,
            )
            checkpoint = Checkpoint(
                event_id=existing.event_id,
                collector=existing.collector,
                scope_hash=scope_hash if scope_hash is not None else existing.scope_hash,
                requested_start=(
                    requested_start if requested_start is not None else existing.requested_start
                ),
                requested_end=(
                    requested_end if requested_end is not None else existing.requested_end
                ),
                completed_ranges=merged_completed,
                failed_ranges=updated_failed,
                updated_at_utc=now_utc,
                adapter_version=(
                    adapter_version if adapter_version is not None else existing.adapter_version
                ),
                metadata={**existing.metadata, **(metadata or {})},
            )

        self.save_checkpoint_atomic(checkpoint)
        return checkpoint

    def mark_range_failed(
        self,
        event_id: str,
        collector: str,
        start: int,
        end: int,
        error: Exception | str,
        retries: int = 0,
        *,
        error_type: str | None = None,
        scope_hash: str | None = None,
        requested_start: int | None = None,
        requested_end: int | None = None,
        adapter_version: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Checkpoint:
        """Record a failure for [start, end], update updated_at_utc, and save atomically.

        Args:
            event_id: Incident / event identifier.
            collector: Collector stage name.
            start: Inclusive start of failed range.
            end: Inclusive end of failed range.
            error: Exception or error message string.
            retries: Number of retries already attempted.
            error_type: Explicit error classification name (defaults to error class name or 'Error').
            scope_hash: Scope hash if creating a new checkpoint.
            requested_start: Requested start boundary if creating.
            requested_end: Requested end boundary if creating.
            adapter_version: Adapter version string.
            metadata: Additional metadata dictionary.

        Returns:
            The updated Checkpoint instance.
        """
        start, end = int(start), int(end)
        if start > end:
            raise ValueError(f"Invalid range: start ({start}) > end ({end})")

        now_utc = normalize_utc_timestamp(datetime.now(timezone.utc))
        resolved_error_type = (
            error_type
            if error_type is not None
            else (type(error).__name__ if isinstance(error, Exception) else "Error")
        )
        fail_entry: dict[str, Any] = {
            "start": start,
            "end": end,
            "error_type": resolved_error_type,
            "message": str(error),
            "retries": int(retries),
            "timestamp_utc": now_utc,
        }

        existing = self.load_checkpoint(event_id, collector)
        if existing is None:
            r_start = requested_start if requested_start is not None else start
            r_end = requested_end if requested_end is not None else end
            checkpoint = Checkpoint(
                event_id=event_id,
                collector=collector,
                scope_hash=scope_hash or "unspecified",
                requested_start=r_start,
                requested_end=r_end,
                completed_ranges=[],
                failed_ranges=[fail_entry],
                updated_at_utc=now_utc,
                adapter_version=adapter_version or "1.0.0",
                metadata=dict(metadata or {}),
            )
        else:
            # If an exact match for (start, end) already exists, replace it; otherwise append
            new_failed: list[dict[str, Any]] = []
            replaced = False
            for entry in existing.failed_ranges:
                if entry["start"] == start and entry["end"] == end:
                    new_failed.append(fail_entry)
                    replaced = True
                else:
                    new_failed.append(entry)
            if not replaced:
                new_failed.append(fail_entry)

            checkpoint = Checkpoint(
                event_id=existing.event_id,
                collector=existing.collector,
                scope_hash=scope_hash if scope_hash is not None else existing.scope_hash,
                requested_start=(
                    requested_start if requested_start is not None else existing.requested_start
                ),
                requested_end=(
                    requested_end if requested_end is not None else existing.requested_end
                ),
                completed_ranges=existing.completed_ranges,
                failed_ranges=new_failed,
                updated_at_utc=now_utc,
                adapter_version=(
                    adapter_version if adapter_version is not None else existing.adapter_version
                ),
                metadata={**existing.metadata, **(metadata or {})},
            )

        self.save_checkpoint_atomic(checkpoint)
        return checkpoint

    def get_pending_ranges(
        self,
        checkpoint: Checkpoint,
        *,
        retry_failed: bool = False,
        include_failed: bool = False,
    ) -> list[tuple[int, int]]:
        """Compute the pending ranges for a checkpoint."""
        return get_pending_ranges(
            checkpoint,
            retry_failed=retry_failed,
            include_failed=include_failed,
        )


__all__ = [
    "Checkpoint",
    "CheckpointStore",
    "DEFAULT_CHECKPOINT_DIR",
    "checkpoint_path",
    "coalesce_ranges",
    "compute_pending_ranges",
    "compute_scope_hash",
    "get_pending_ranges",
    "validate_checkpoint_scope",
]
