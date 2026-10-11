"""Crash-safe raw and normalised storage layer (A09 + A12).

Layout
------
``data/raw/source/{category}/{event_id}/{filename}``
    Immutable source-shaped responses (one file per API call).

``data/raw/normalized/{category}/{event_id}.jsonl``
    Normalised JSONL records appended crash-safely.

All writes use a temp-file + atomic rename or fsync-before-append strategy so
that partial failures never corrupt existing data.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# Base path constants (relative to a caller-supplied root)
# ---------------------------------------------------------------------------

SOURCE_BASE = Path("data/raw/source")
NORMALIZED_BASE = Path("data/raw/normalized")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedSha256Ref:
    """Provenance reference attached to each normalised record.

    Attributes:
        source_sha256: SHA-256 hex digest of the source artifact this record
            was derived from.
        normalization_version: Semver string for the normalisation logic that
            produced this record (e.g. ``"1.0.0"``).
    """

    source_sha256: str
    normalization_version: str


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def source_path(category: str, event_id: str, filename: str, root: Path) -> Path:
    """Return the canonical path for a raw source artifact.

    The path follows the convention::

        <root>/data/raw/source/<category>/<event_id>/<filename>

    Args:
        category: Data category (e.g. ``"blocks"``, ``"logs"``).
        event_id: Event identifier from the registry.
        filename: Filename of the artifact (e.g. ``"response.json"``).
        root: Repository or workspace root that anchors the path.

    Returns:
        Absolute-style :class:`~pathlib.Path` (relative to *root* if *root*
        is relative).
    """
    return root / SOURCE_BASE / category / event_id / filename


def normalized_path(category: str, event_id: str, root: Path) -> Path:
    """Return the canonical path for a normalised JSONL artifact.

    The path follows the convention::

        <root>/data/raw/normalized/<category>/<event_id>.jsonl

    Args:
        category: Data category (e.g. ``"blocks"``, ``"logs"``).
        event_id: Event identifier from the registry.
        root: Repository or workspace root that anchors the path.

    Returns:
        Absolute-style :class:`~pathlib.Path` (relative to *root* if *root*
        is relative).
    """
    return root / NORMALIZED_BASE / category / f"{event_id}.jsonl"


# ---------------------------------------------------------------------------
# Source artifact writer
# ---------------------------------------------------------------------------


def write_source_artifact(path: Path, content: bytes | str) -> str:
    """Write an immutable source artifact and return its SHA-256 hex digest.

    The write is performed via a temporary file and an atomic rename so that
    a crash mid-write never produces a partial file at *path*.

    Args:
        path: Destination path.  Must **not** already exist (immutability
            invariant).
        content: Raw bytes or a UTF-8 string to persist.

    Returns:
        SHA-256 hex digest of the written content.

    Raises:
        FileExistsError: if *path* already exists.
    """
    if path.exists():
        raise FileExistsError(
            f"source artifact already exists (immutable): {path}"
        )
    raw: bytes = content if isinstance(content, bytes) else content.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a sibling temp file then rename atomically.
    tmp_fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # On Windows, os.rename raises if the destination already exists, so
        # we perform the existence check above.  On POSIX this is atomic.
        tmp_path.rename(path)
    except Exception:
        # Best-effort cleanup of the temp file on failure.
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return digest


# ---------------------------------------------------------------------------
# JSONL reader with quarantine
# ---------------------------------------------------------------------------


def read_jsonl_records(path: Path) -> list[dict]:
    """Read a JSONL file, quarantine trailing corrupt bytes, return valid records.

    Each non-blank line is parsed as JSON.  If a line fails to parse and it is
    the *last* non-blank content in the file (i.e. trailing corruption), the
    corrupt bytes are written to a ``.quarantine`` sidecar and the main file is
    truncated to the last good record boundary.

    Mid-file corruption (a bad line followed by good lines) is **not**
    quarantined — it raises :class:`json.JSONDecodeError` so the caller can
    decide how to handle it.

    Args:
        path: Path to the JSONL file.  Returns an empty list if the file does
            not exist.

    Returns:
        List of parsed record dicts (only valid records).
    """
    if not path.exists():
        return []

    raw_bytes = path.read_bytes()
    lines = raw_bytes.splitlines(keepends=True)

    records: list[dict] = []
    last_good_byte_offset = 0
    cumulative_offset = 0

    for line in lines:
        line_text = line.decode("utf-8", errors="replace")
        cumulative_offset += len(line)
        if not line_text.strip():
            last_good_byte_offset = cumulative_offset
            continue
        try:
            records.append(json.loads(line_text))
            last_good_byte_offset = cumulative_offset
        except json.JSONDecodeError:
            # This is the first bad line — check whether everything after is
            # also blank (trailing corruption) or whether there is more valid
            # content (mid-file corruption).
            remaining_bytes = raw_bytes[cumulative_offset:]
            remaining_non_blank = [
                ln for ln in remaining_bytes.splitlines()
                if ln.strip()
            ]
            if not remaining_non_blank:
                # Trailing corruption — quarantine and truncate.
                corrupt_bytes = raw_bytes[last_good_byte_offset:]
                quarantine_path = path.with_suffix(".quarantine")
                quarantine_path.write_bytes(corrupt_bytes)
                # Truncate the main file to last_good_byte_offset.
                with path.open("r+b") as handle:
                    handle.truncate(last_good_byte_offset)
                return records
            # Mid-file corruption — propagate.
            raise

    return records


# ---------------------------------------------------------------------------
# Crash-safe normalised record appender
# ---------------------------------------------------------------------------


def append_normalized_records(
    path: Path,
    records: Iterable[Mapping[str, Any]],
    *,
    key_field: str = "record_key",
) -> tuple[int, int]:
    """Crash-safe append of normalised JSONL records with duplicate skipping.

    Strategy
    --------
    1. Load existing ``key_field`` values from *path* (tolerates missing file).
    2. Serialise new (non-duplicate) records to a temp file.
    3. ``fsync`` the temp file.
    4. Read the temp file and append its bytes to *path* in a single
       ``write`` call (the OS guarantees atomicity of individual small writes
       on local filesystems; for large batches this is best-effort crash-safe).
    5. Return ``(written, skipped)``.

    Args:
        path: Destination JSONL file.
        records: Iterable of record dicts.  Each must contain *key_field*.
        key_field: Name of the deduplication key in each record.

    Returns:
        A ``(written, skipped)`` tuple of :class:`int`.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Load existing keys (use read_jsonl_records for quarantine safety).
    existing_keys: set[str] = set()
    if path.exists():
        for rec in read_jsonl_records(path):
            existing_keys.add(str(rec[key_field]))

    # 2. Serialise new records to a sibling temp file.
    written = skipped = 0
    tmp_fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_append_")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            for record in records:
                key = str(record[key_field])
                if key in existing_keys:
                    skipped += 1
                    continue
                line = (
                    json.dumps(dict(record), sort_keys=True, separators=(",", ":"))
                    + "\n"
                )
                handle.write(line.encode("utf-8"))
                existing_keys.add(key)
                written += 1
            # 3. fsync before reading back.
            handle.flush()
            os.fsync(handle.fileno())

        if written > 0:
            # 4. Append temp file content to the main file.
            batch = tmp_path.read_bytes()
            with path.open("ab") as dest:
                dest.write(batch)
                dest.flush()
                os.fsync(dest.fileno())
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    return written, skipped

