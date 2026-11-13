"""D2 coverage audits and readiness gate (E6).

This module evaluates collected D2 artifacts against registry expectations and
produces JSON + Markdown gate reports.  Every measurement comes from real
persisted artifacts; no placeholder values are accepted.

Public API
----------
audit_registry_consistency       -- E6.4  registry cross-checks
load_artifact_records            -- shared loader (JSONL + Parquet)
audit_block_coverage             -- E6.3  block-range completeness
audit_registered_transaction_coverage -- E6.2 exploit-tx presence
audit_receipt_coverage           -- E6.2  receipt presence
audit_log_range_coverage         -- E6.3  checkpoint-derived range status
audit_abi_coverage               -- E6.1  ABI directory scan
audit_price_coverage             -- legacy thin wrapper (kept for backward compat)
audit_token_price_coverage       -- E6.5  per-token hourly price completeness
audit_public_sources_coverage    -- E6.5  per-query / per-URL public source coverage
audit_duplicate_records          -- E6.4  duplicate-identity detection
audit_source_manifest            -- E6.4  manifest integrity + credential check
build_d2_gate_report             -- E6.6  compile JSON report + derive gate status
render_d2_gate_markdown          -- E6.6  human-readable Markdown summary
enforce_d2_gate                  -- E6.7  raise on NO_GO (block D3)
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .checkpoints import Checkpoint, compute_pending_ranges
from .registry import HASH_RE, sha256_file
from .retry import redact_credentials
from .storage import read_jsonl_records

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fields used as dedup keys per schema.  The ``record_key`` field stores the
# canonical serialised form; we validate it against the individual fields to
# catch cross-source collisions.
_SCHEMA_DEDUP_KEYS: dict[str, tuple[str, ...]] = {
    "logs": ("chain_id", "tx_hash", "log_index"),
    "transactions": ("chain_id", "tx_hash"),
    "receipts": ("chain_id", "tx_hash"),
    "blocks": ("chain_id", "block_number"),
    "prices": ("coingecko_id", "source_timestamp"),
}

_TOKEN_REQUIRED_FIELDS = frozenset(
    {"symbol", "chain_id", "address", "decimals", "coingecko_id", "fallback_price_source", "status"}
)

# ---------------------------------------------------------------------------
# Shared artifact loader
# ---------------------------------------------------------------------------


def load_artifact_records(path: Path | None) -> list[dict[str, Any]]:
    """Load normalized records from a JSONL or Parquet artifact.

    Tries ``path`` as given.  If the path does not exist and no extension is
    set, also tries ``.parquet`` and ``.jsonl`` variants so callers can pass a
    stem.  Returns an empty list when no artifact is found.

    Args:
        path: Destination path (may omit extension for automatic discovery).

    Returns:
        List of record dicts.
    """
    if path is None:
        return []

    candidates = [path]
    if path.suffix not in (".jsonl", ".parquet"):
        candidates = [path.with_suffix(".jsonl"), path.with_suffix(".parquet"), path]

    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.suffix == ".parquet":
            try:
                import pyarrow.parquet as pq  # type: ignore[import]
                table = pq.read_table(str(candidate))
                return table.to_pylist()
            except ImportError:
                pass  # fall through to JSONL
        if candidate.suffix in (".jsonl", ""):
            return list(read_jsonl_records(candidate))

    return []


def _records(path: Path | None) -> list[dict[str, Any]]:
    """Thin wrapper kept for backward compatibility."""
    return load_artifact_records(path)


# ---------------------------------------------------------------------------
# E6.4 – Registry consistency
# ---------------------------------------------------------------------------


def audit_registry_consistency(
    event: Mapping[str, Any],
    scope_addresses: Iterable[str],
    token_registry: Iterable[Mapping[str, Any]],
    incident_legs: Iterable[Mapping[str, Any]],
    public_source_registry: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Cross-check registry declarations against each other.

    Checks:
    1. All protocol/attack/attacker contract addresses exist in ``scope_addresses``.
    2. All tokens in ``event.tokens_related`` exist in ``token_registry`` with
       required attributes.
    3. All incident legs for this event have valid 66-char hex ``transaction_hash``.
    4. At least one ``public_sources.json`` entry exists for this event with a
       non-empty ``official_urls`` or ``search_queries`` or ``gdelt_aliases``.

    Returns a dict with ``passed`` (bool) and per-check details.
    """
    event_id = str(event.get("event_id", ""))
    scope_set = {str(a).lower() for a in scope_addresses}

    # --- 1. Contracts in scope -----------------------------------------------
    all_declared = (
        list(event.get("protocol_or_vulnerable_contracts", []))
        + list(event.get("attack_contracts", []))
        + list(event.get("attacker_addresses", []))
    )
    contracts_not_in_scope = sorted(
        {str(a).lower() for a in all_declared if a}
        - scope_set
    )

    # --- 2. Tokens in registry -----------------------------------------------
    token_map = {
        str(t.get("symbol", "")).upper(): dict(t)
        for t in token_registry
    }
    tokens_related = list(event.get("tokens_related", []))
    # Normalise compound entries like "WETH/DAI" or "WETH and DAI"
    normalised_symbols: list[str] = []
    for sym in tokens_related:
        sym = str(sym).strip()
        if "/" in sym:
            normalised_symbols.extend(s.strip().upper() for s in sym.split("/") if s.strip())
        elif " and " in sym.lower():
            normalised_symbols.extend(s.strip().upper() for s in sym.lower().split(" and ") if s.strip())
        else:
            if sym:
                normalised_symbols.append(sym.upper())

    tokens_missing_from_registry: list[str] = []
    tokens_incomplete: dict[str, list[str]] = {}
    for sym in normalised_symbols:
        if sym not in token_map:
            tokens_missing_from_registry.append(sym)
        else:
            token_entry = token_map[sym]
            missing_fields = [
                f for f in _TOKEN_REQUIRED_FIELDS
                if token_entry.get(f) is None
            ]
            if missing_fields:
                tokens_incomplete[sym] = sorted(missing_fields)

    # --- 3. Incident legs have valid tx hashes --------------------------------
    event_legs = [
        dict(leg) for leg in incident_legs
        if str(leg.get("event_id", "")) == event_id
    ]
    legs_invalid_tx: list[str] = []
    for leg in event_legs:
        leg_id = str(leg.get("leg_id", ""))
        tx = str(leg.get("transaction_hash", ""))
        if not HASH_RE.match(tx):
            legs_invalid_tx.append(leg_id)

    # --- 4. Public sources entry exists and is non-empty ---------------------
    event_public_sources = [
        dict(ps) for ps in public_source_registry
        if str(ps.get("event_id", "")) == event_id
    ]
    public_source_issues: list[str] = []
    if not event_public_sources:
        public_source_issues.append("no_entry_for_event")
    else:
        for ps in event_public_sources:
            has_target = (
                bool(ps.get("official_urls"))
                or bool(ps.get("search_queries"))
                or bool(ps.get("gdelt_aliases"))
                or bool(ps.get("topic_ids"))
            )
            if not has_target:
                public_source_issues.append("entry_has_no_targets")

    passed = (
        not contracts_not_in_scope
        and not tokens_missing_from_registry
        and not tokens_incomplete
        and not legs_invalid_tx
        and not public_source_issues
    )
    return {
        "passed": passed,
        "contracts_not_in_scope": contracts_not_in_scope,
        "tokens_missing_from_registry": tokens_missing_from_registry,
        "tokens_incomplete_fields": tokens_incomplete,
        "incident_legs_with_invalid_tx_hash": legs_invalid_tx,
        "public_source_config_issues": public_source_issues,
    }


# ---------------------------------------------------------------------------
# E6.3 – Block and log-range coverage
# ---------------------------------------------------------------------------


def audit_block_coverage(requested_start: int, requested_end: int, path: Path | None) -> dict[str, int]:
    """Check block-number coverage from a normalized artifact.

    Args:
        requested_start: First expected block (inclusive).
        requested_end:   Last expected block (inclusive).
        path:            Path to a normalized blocks or logs JSONL / Parquet.

    Returns:
        Dict with ``requested_block_count``, ``collected_block_count``,
        ``missing_block_count``.
    """
    rows = load_artifact_records(path)
    collected = {int(row.get("block_number", row.get("record_key", -1))) for row in rows}
    expected = set(range(requested_start, requested_end + 1))
    return {
        "requested_block_count": len(expected),
        "collected_block_count": len(collected & expected),
        "missing_block_count": len(expected - collected),
    }


def audit_log_range_coverage(checkpoint: Checkpoint | None) -> dict[str, Any]:
    """Evaluate log-collection progress from a checkpoint.

    Returns a dict describing whether a checkpoint is present, what percentage
    of blocks are covered, any pending ranges, and any failed ranges.
    """
    if checkpoint is None:
        return {
            "checkpoint_present": False,
            "failed_log_ranges": [],
            "pending_log_ranges": [],
        }
    completed = checkpoint.completed_ranges
    covered = sum(end - start + 1 for start, end in completed)
    requested = checkpoint.requested_end - checkpoint.requested_start + 1
    return {
        "checkpoint_present": True,
        "completed_block_count": covered,
        "completed_range_percentage": round(100 * covered / requested, 2),
        "pending_log_ranges": [
            list(item)
            for item in compute_pending_ranges(
                checkpoint.requested_start,
                checkpoint.requested_end,
                completed,
            )
        ],
        "failed_log_ranges": [
            [item.get("start"), item.get("end")] if isinstance(item, dict) else item
            for item in checkpoint.failed_ranges
        ],
    }


# ---------------------------------------------------------------------------
# E6.2 – Transaction and receipt coverage
# ---------------------------------------------------------------------------


def audit_registered_transaction_coverage(
    registered_hashes: Iterable[str], path: Path | None
) -> dict[str, Any]:
    """Check that all registered exploit tx hashes appear in the transactions artifact.

    Args:
        registered_hashes: All exploit/leg transaction hashes from the registry.
        path: Path to normalized transactions JSONL/Parquet.

    Returns:
        Dict with counts and missing hash lists.
    """
    expected = {value.lower() for value in registered_hashes}
    actual = {
        str(row.get("tx_hash", row.get("record_key", ""))).lower()
        for row in load_artifact_records(path)
    }
    missing = sorted(expected - actual)
    return {
        "registered_exploit_tx_count": len(expected),
        "missing_exploit_tx_count": len(missing),
        "missing_exploit_tx_hashes": missing,
    }


def audit_receipt_coverage(tx_hashes: Iterable[str], path: Path | None) -> dict[str, Any]:
    """Check that all supplied tx hashes have receipts in the receipts artifact.

    Args:
        tx_hashes: All tx hashes expected to have receipts.
        path: Path to normalized receipts JSONL/Parquet.

    Returns:
        Dict with missing receipt count and hash list.
    """
    expected = {value.lower() for value in tx_hashes}
    actual = {
        str(row.get("tx_hash", row.get("record_key", ""))).lower()
        for row in load_artifact_records(path)
    }
    missing = sorted(expected - actual)
    return {"missing_receipt_count": len(missing), "missing_receipt_hashes": missing}


# ---------------------------------------------------------------------------
# E6.1 – ABI coverage
# ---------------------------------------------------------------------------


def audit_abi_coverage(addresses: Iterable[str], abi_dir: Path | None) -> dict[str, Any]:
    """Check ABI file presence for all required contract addresses.

    Uses ``abi_dir/<address>.json`` glob; delegates to
    :func:`~defi_lsa.abi.compute_abi_coverage_report` when meta files are
    present, otherwise performs a simple file-existence check.

    Args:
        addresses: Contract addresses that must have ABIs.
        abi_dir: Directory containing ``<address>.json`` files.

    Returns:
        Dict with coverage percentage and list of missing addresses.
    """
    expected = {address.lower() for address in addresses}
    if abi_dir and abi_dir.exists():
        # Exclude meta sidecars from the coverage set
        actual = {
            path.stem.lower()
            for path in abi_dir.glob("*.json")
            if not path.stem.endswith(".meta")
        }
    else:
        actual = set()
    missing = sorted(expected - actual)
    return {
        "abi_coverage_percentage": round(100 * len(expected & actual) / len(expected), 2) if expected else 100.0,
        "missing_abi_addresses": missing,
    }


# ---------------------------------------------------------------------------
# E6.4 – Duplicate-identity detection
# ---------------------------------------------------------------------------


def audit_duplicate_records(
    path: Path | None,
    schema: str,
) -> dict[str, Any]:
    """Detect duplicate records by their canonical dedup key tuple.

    Canonical keys by schema:
    * ``logs``         → ``(chain_id, tx_hash, log_index)``
    * ``transactions`` → ``(chain_id, tx_hash)``
    * ``receipts``     → ``(chain_id, tx_hash)``
    * ``blocks``       → ``(chain_id, block_number)``
    * ``prices``       → ``(coingecko_id, source_timestamp)``

    Falls back to ``record_key`` for unknown schemas.

    Args:
        path: Path to the normalized artifact (JSONL or Parquet).
        schema: Schema name, one of the keys in ``_SCHEMA_DEDUP_KEYS``.

    Returns:
        Dict with ``total_records``, ``duplicate_count``,
        ``duplicate_key_samples`` (up to 10).
    """
    rows = load_artifact_records(path)
    key_fields = _SCHEMA_DEDUP_KEYS.get(schema)
    seen: dict[tuple[Any, ...], int] = {}
    for row in rows:
        if key_fields:
            key = tuple(str(row.get(f, "")).lower() for f in key_fields)
        else:
            key = (str(row.get("record_key", "")),)
        seen[key] = seen.get(key, 0) + 1

    duplicate_keys = [k for k, count in seen.items() if count > 1]
    return {
        "total_records": len(rows),
        "duplicate_count": len(duplicate_keys),
        "duplicate_key_samples": [list(k) for k in duplicate_keys[:10]],
    }


# ---------------------------------------------------------------------------
# E6.4 – Source manifest integrity
# ---------------------------------------------------------------------------


def audit_source_manifest(manifest_path: Path | None) -> dict[str, Any]:
    """Validate a source manifest: file presence, artifact checksums, credential leaks.

    Args:
        manifest_path: Path to ``source_manifest.json``.

    Returns:
        Dict with ``manifest_present``, ``total_records``,
        ``checksum_failures`` (list of artifact paths),
        ``missing_artifacts`` (list of artifact paths),
        ``credential_leak_detected`` (bool).
    """
    if manifest_path is None or not manifest_path.exists():
        return {
            "manifest_present": False,
            "total_records": 0,
            "checksum_failures": [],
            "missing_artifacts": [],
            "credential_leak_detected": False,
        }

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "manifest_present": True,
            "total_records": 0,
            "checksum_failures": [],
            "missing_artifacts": [],
            "credential_leak_detected": False,
            "parse_error": True,
        }

    records = payload.get("records", [])
    checksum_failures: list[str] = []
    missing_artifacts: list[str] = []
    credential_leak = False

    for rec in records:
        artifact_path = Path(rec.get("artifact_path", ""))
        expected_sha = str(rec.get("artifact_sha256", ""))
        request_url = str(rec.get("request_url", ""))

        # Credential leak: redacted URL should equal original
        redacted = redact_credentials(request_url)
        if redacted != request_url:
            credential_leak = True

        if not artifact_path.name:
            continue
        if not artifact_path.exists():
            missing_artifacts.append(str(artifact_path))
            continue
        if expected_sha and len(expected_sha) == 64:
            actual_sha = sha256_file(artifact_path)
            if actual_sha != expected_sha:
                checksum_failures.append(str(artifact_path))

    return {
        "manifest_present": True,
        "total_records": len(records),
        "checksum_failures": checksum_failures,
        "missing_artifacts": missing_artifacts,
        "credential_leak_detected": credential_leak,
    }


# ---------------------------------------------------------------------------
# E6.5 – Token price coverage
# ---------------------------------------------------------------------------


def audit_token_price_coverage(
    event: Mapping[str, Any],
    token_registry: Iterable[Mapping[str, Any]],
    prices_path: Path | None,
    price_coverage_reports_dir: Path | None,
) -> dict[str, Any]:
    """Evaluate per-token hourly price completeness.

    For each verified token related to the event:
    1. First tries to load a pre-computed ``price_coverage_<symbol>.json``
       report from *price_coverage_reports_dir*.
    2. Falls back to computing coverage from the normalized prices JSONL/Parquet
       if the report is absent, using the event's collection window.

    Args:
        event: Event dict from ``configs/events.json``.
        token_registry: Loaded token registry entries.
        prices_path: Path to the normalized prices JSONL/Parquet.
        price_coverage_reports_dir: Directory holding per-token JSON coverage reports.

    Returns:
        Dict with ``per_token_coverage``, ``tokens_missing``,
        ``tokens_below_threshold`` (< 90 % coverage), ``overall_status``.
    """
    start_utc = str(event.get("collection_start_utc") or "")
    end_utc = str(event.get("collection_end_utc") or "")
    event_id = str(event.get("event_id", ""))

    # Build lookup of tokens related to this event
    tokens_related: list[str] = []
    for sym in event.get("tokens_related", []):
        sym = str(sym).strip()
        if "/" in sym:
            tokens_related.extend(s.strip().upper() for s in sym.split("/") if s.strip())
        elif " and " in sym.lower():
            tokens_related.extend(s.strip().upper() for s in sym.lower().split(" and ") if s.strip())
        elif sym:
            tokens_related.append(sym.upper())

    token_map = {
        str(t.get("symbol", "")).upper(): dict(t)
        for t in token_registry
    }

    # Pre-load normalized price records (lazy)
    _price_rows: list[dict[str, Any]] | None = None

    def _get_price_rows() -> list[dict[str, Any]]:
        nonlocal _price_rows
        if _price_rows is None:
            _price_rows = load_artifact_records(prices_path)
        return _price_rows

    per_token: dict[str, dict[str, Any]] = {}
    tokens_missing: list[str] = []
    tokens_below_threshold: list[str] = []

    for sym in tokens_related:
        token = token_map.get(sym)
        if not token:
            tokens_missing.append(sym)
            continue
        if token.get("status") != "verified":
            per_token[sym] = {"status": "pending", "coverage_percentage": None}
            continue

        coin_id = str(token.get("coingecko_id", ""))

        # 1. Try pre-computed coverage report
        report_dict: dict[str, Any] | None = None
        if price_coverage_reports_dir:
            report_path = price_coverage_reports_dir / f"price_coverage_{sym.lower()}.json"
            if report_path.exists():
                try:
                    report_dict = json.loads(report_path.read_text(encoding="utf-8"))
                except Exception:
                    report_dict = None

        if report_dict is not None:
            per_token[sym] = {
                "coin_id": coin_id,
                "coverage_percentage": report_dict.get("coverage_percentage"),
                "missing_hours": report_dict.get("missing_hours", []),
                "max_consecutive_gap_hours": report_dict.get("max_consecutive_gap_hours", 0),
                "source": "precomputed_report",
            }
        else:
            # 2. Compute from normalized price records filtered by coin_id
            rows = [r for r in _get_price_rows() if str(r.get("coingecko_id", "")) == coin_id]
            if not rows:
                per_token[sym] = {
                    "coin_id": coin_id,
                    "coverage_percentage": 0.0,
                    "missing_hours": [],
                    "max_consecutive_gap_hours": 0,
                    "source": "normalized_records",
                    "note": "no_records_found",
                }
            elif start_utc and end_utc:
                try:
                    from .adapters.coingecko import PriceCoverageReport, calculate_price_coverage
                    from .schemas import PriceRecord

                    price_records = [
                        PriceRecord(
                            record_key=r.get("record_key", ""),
                            event_id=r.get("event_id", event_id),
                            token_address=r.get("token_address", ""),
                            coingecko_id=r.get("coingecko_id", ""),
                            source_timestamp=int(r.get("source_timestamp", 0)),
                            hour_utc=r.get("hour_utc", ""),
                            usd_price=float(r.get("usd_price", 0.0)),
                            source=r.get("source", ""),
                            retrieved_at_utc=r.get("retrieved_at_utc", ""),
                            source_sha256=r.get("source_sha256", ""),
                            normalization_version=r.get("normalization_version", ""),
                        )
                        for r in rows
                    ]
                    cov = calculate_price_coverage(
                        price_records, start_utc, end_utc,
                        coin_id=coin_id,
                        token_address=str(token.get("address", "")),
                    )
                    per_token[sym] = {
                        "coin_id": coin_id,
                        "coverage_percentage": cov.coverage_percentage,
                        "missing_hours": list(cov.missing_hours),
                        "max_consecutive_gap_hours": cov.max_consecutive_gap_hours,
                        "source": "normalized_records",
                    }
                except Exception as exc:
                    per_token[sym] = {
                        "coin_id": coin_id,
                        "coverage_percentage": None,
                        "source": "normalized_records",
                        "error": str(exc),
                    }
            else:
                # Window not set; just count rows
                per_token[sym] = {
                    "coin_id": coin_id,
                    "coverage_percentage": None,
                    "record_count": len(rows),
                    "source": "normalized_records",
                    "note": "collection_window_not_set",
                }

        pct = per_token[sym].get("coverage_percentage")
        if pct is not None and float(pct) < 90.0:
            tokens_below_threshold.append(sym)

    # Overall status
    if tokens_missing or tokens_below_threshold:
        overall_status = "failed"
    elif any(v.get("coverage_percentage") is None for v in per_token.values()):
        overall_status = "conditional"
    else:
        overall_status = "ok"

    return {
        "status": overall_status,
        "per_token_coverage": per_token,
        "tokens_missing": tokens_missing,
        "tokens_below_threshold": tokens_below_threshold,
    }


# ---------------------------------------------------------------------------
# E6.5 – Public source query coverage
# ---------------------------------------------------------------------------


def audit_public_sources_coverage(
    event: Mapping[str, Any],
    public_source_registry: Iterable[Mapping[str, Any]],
    normalized_base: Path | None,
) -> dict[str, Any]:
    """Evaluate per-query / per-URL coverage of public source records.

    For each entry in ``public_sources.json`` matching the event:
    * Checks whether normalized discourse, gdelt, and protocol JSONL files
      contain records referencing the configured URLs / queries.
    * Reports coverage per individual query target, not just file presence.
    * Verifies GDELT records do not carry raw article bodies (copyright compliance).

    Args:
        event: Event dict.
        public_source_registry: Loaded public sources registry entries.
        normalized_base: Root of ``data/raw/normalized/`` for this run.

    Returns:
        Dict with ``status``, ``coverage_by_source``, ``uncovered_targets``,
        ``copyright_violation_detected``.
    """
    event_id = str(event.get("event_id", ""))
    event_entries = [
        dict(ps) for ps in public_source_registry
        if str(ps.get("event_id", "")) == event_id
    ]

    if not event_entries:
        return {
            "status": "failed",
            "coverage_by_source": {},
            "uncovered_targets": ["no_public_source_entry"],
            "copyright_violation_detected": False,
        }

    # Pre-load normalized records per source channel
    def _load_channel(channel: str) -> list[dict[str, Any]]:
        if normalized_base is None:
            return []
        p = normalized_base / channel / event_id
        return load_artifact_records(p)

    discourse_rows = _load_channel("discourse")
    gdelt_rows = _load_channel("gdelt")
    protocol_rows = _load_channel("protocol")

    all_urls_in_discourse = {str(r.get("url", "")).lower() for r in discourse_rows}
    all_urls_in_protocol = {str(r.get("url", "")).lower() for r in protocol_rows}
    all_queries_in_gdelt = {str(r.get("title", "")).lower() for r in gdelt_rows}

    coverage_by_source: dict[str, dict[str, Any]] = {}
    uncovered_targets: list[str] = []
    copyright_violation = False

    # Check GDELT for full-body fields (copyright compliance)
    for row in gdelt_rows:
        if row.get("full_body") or row.get("body") or row.get("content"):
            copyright_violation = True
            break

    for entry in event_entries:
        # Official URLs → expect records in discourse or protocol
        for url in (entry.get("official_urls") or []):
            url_lower = str(url).lower()
            covered = url_lower in all_urls_in_discourse or url_lower in all_urls_in_protocol
            target_key = f"official_url:{url}"
            coverage_by_source[target_key] = {
                "type": "official_url",
                "target": url,
                "covered": covered,
                "channels_checked": ["discourse", "protocol"],
            }
            if not covered:
                uncovered_targets.append(target_key)

        # Topic IDs → expect discourse records
        for topic_id in (entry.get("topic_ids") or []):
            topic_url_fragment = f"/t/{topic_id}"
            covered = any(topic_url_fragment in u for u in all_urls_in_discourse)
            target_key = f"discourse_topic:{topic_id}"
            coverage_by_source[target_key] = {
                "type": "discourse_topic_id",
                "target": str(topic_id),
                "covered": covered,
                "channels_checked": ["discourse"],
            }
            if not covered:
                uncovered_targets.append(target_key)

        # Search queries → expect at least one gdelt or protocol record whose
        # title contains a keyword from the query
        for query in (entry.get("search_queries") or []):
            query_words = {w.lower() for w in re.split(r"\W+", str(query)) if len(w) > 3}
            covered = any(
                any(word in title for word in query_words)
                for title in all_queries_in_gdelt
            )
            target_key = f"search_query:{query}"
            coverage_by_source[target_key] = {
                "type": "search_query",
                "target": query,
                "covered": covered,
                "channels_checked": ["gdelt"],
            }
            if not covered:
                uncovered_targets.append(target_key)

        # GDELT aliases
        for alias in (entry.get("gdelt_aliases") or []):
            alias_lower = str(alias).lower()
            covered = any(alias_lower in title for title in all_queries_in_gdelt)
            target_key = f"gdelt_alias:{alias}"
            coverage_by_source[target_key] = {
                "type": "gdelt_alias",
                "target": alias,
                "covered": covered,
                "channels_checked": ["gdelt"],
            }
            if not covered:
                uncovered_targets.append(target_key)

    if not coverage_by_source:
        overall_status = "failed"
    elif uncovered_targets:
        overall_status = "conditional"
    else:
        overall_status = "ok"

    return {
        "status": overall_status,
        "coverage_by_source": coverage_by_source,
        "uncovered_targets": uncovered_targets,
        "copyright_violation_detected": copyright_violation,
    }


# ---------------------------------------------------------------------------
# Legacy thin wrapper (backward compat)
# ---------------------------------------------------------------------------


def audit_price_coverage(reports: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Legacy wrapper — summarises pre-computed price coverage reports."""
    reports = list(reports)
    return {
        "price_coverage_percentage_by_token": {
            str(report.get("coin_id", "")): report.get("coverage_percentage", 0.0)
            for report in reports
        },
        "maximum_consecutive_price_gap": max(
            (int(report.get("max_consecutive_gap_hours", 0)) for report in reports),
            default=0,
        ),
    }


# ---------------------------------------------------------------------------
# E6.6 – Report generation
# ---------------------------------------------------------------------------


def build_d2_gate_report(
    output_path: Path,
    *,
    block: Mapping[str, Any],
    transactions: Mapping[str, Any],
    receipts: Mapping[str, Any],
    logs: Mapping[str, Any],
    abi: Mapping[str, Any],
    prices: Mapping[str, Any],
    public_sources: Mapping[str, Any],
    registry_consistency: Mapping[str, Any] | None = None,
    duplicates: Mapping[str, Any] | None = None,
    source_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile measurements into a gate report JSON file and return the report dict.

    Gate logic
    ----------
    * ``GO``             — all checks pass and no source is ``conditional``.
    * ``CONDITIONAL_GO`` — at least one check passes; conditional sources present.
    * ``NO_GO``          — no substantive collection check passes.

    Args:
        output_path: Destination for the JSON report.
        block: From :func:`audit_block_coverage`.
        transactions: From :func:`audit_registered_transaction_coverage`.
        receipts: From :func:`audit_receipt_coverage`.
        logs: From :func:`audit_log_range_coverage`.
        abi: From :func:`audit_abi_coverage`.
        prices: From :func:`audit_token_price_coverage` or status dict.
        public_sources: From :func:`audit_public_sources_coverage` or status dict.
        registry_consistency: Optional; from :func:`audit_registry_consistency`.
        duplicates: Optional; aggregated duplicate-check results.
        source_manifest: Optional; from :func:`audit_source_manifest`.

    Returns:
        The full report dict (also written to *output_path*).
    """
    checks: dict[str, bool] = {
        "missing_blocks": block.get("missing_block_count", 0) == 0,
        "missing_registered_transactions": transactions.get("missing_exploit_tx_count", 0) == 0,
        "missing_receipts": receipts.get("missing_receipt_count", 0) == 0,
        "failed_log_ranges": (
            bool(logs.get("checkpoint_present", False))
            and not logs.get("pending_log_ranges")
            and not logs.get("failed_log_ranges")
        ),
        "abi_coverage": abi.get("abi_coverage_percentage", 0.0) == 100.0,
        "price_status": prices.get("status", "failed") not in ("failed",),
        "public_source_status": public_sources.get("status", "failed") not in ("failed",),
    }
    if registry_consistency is not None:
        checks["registry_consistency"] = bool(registry_consistency.get("passed", False))
    if duplicates is not None:
        checks["no_duplicate_records"] = int(duplicates.get("total_duplicate_count", 0)) == 0
    if source_manifest is not None:
        checks["source_manifest_valid"] = (
            bool(source_manifest.get("manifest_present", False))
            and not source_manifest.get("checksum_failures")
            and not source_manifest.get("missing_artifacts")
            and not source_manifest.get("credential_leak_detected")
        )
    if "copyright_violation_detected" in public_sources:
        checks["public_source_copyright_compliance"] = not bool(
            public_sources.get("copyright_violation_detected")
        )

    has_conditional_sources = any(
        source.get("status") == "conditional"
        for source in (prices, public_sources)
    )
    conditional_source_evidence = any(
        bool(item.get("covered"))
        for item in (public_sources.get("coverage_by_source", {}) or {}).values()
        if isinstance(item, dict)
    ) or any(
        float(item.get("coverage_percentage", 0.0) or 0.0) > 0.0
        or int(item.get("record_count", 0) or 0) > 0
        for item in (prices.get("per_token_coverage", {}) or {}).values()
        if isinstance(item, dict)
    )
    substantive_checks = tuple(
        checks[name]
        for name in (
            "missing_blocks",
            "missing_registered_transactions",
            "missing_receipts",
            "failed_log_ranges",
            "abi_coverage",
            "price_status",
            "public_source_status",
        )
    )
    substantive_checks = substantive_checks[:-1] + (
        checks["public_source_status"] and (
            public_sources.get("status") != "conditional"
            or conditional_source_evidence
        ),
    )
    status: str
    if all(checks.values()) and not has_conditional_sources:
        status = "GO"
    elif any(substantive_checks):
        status = "CONDITIONAL_GO"
    else:
        status = "NO_GO"

    corrective_actions = [name for name, passed in checks.items() if not passed]

    report: dict[str, Any] = {
        "status": status,
        "checks": checks,
        "corrective_actions": corrective_actions,
        "block": dict(block),
        "transactions": dict(transactions),
        "receipts": dict(receipts),
        "logs": dict(logs),
        "abi": dict(abi),
        "prices": dict(prices),
        "public_sources": dict(public_sources),
    }
    if registry_consistency is not None:
        report["registry_consistency"] = dict(registry_consistency)
    if duplicates is not None:
        report["duplicates"] = dict(duplicates)
    if source_manifest is not None:
        report["source_manifest"] = dict(source_manifest)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def render_d2_gate_markdown(report: Mapping[str, Any], output_path: Path) -> None:
    """Write a human-readable Markdown gate report.

    Args:
        report: Dict returned by :func:`build_d2_gate_report`.
        output_path: Destination ``.md`` file.
    """
    status = str(report.get("status", "UNKNOWN"))
    badge = {"GO": "✅ GO", "CONDITIONAL_GO": "⚠️ CONDITIONAL_GO", "NO_GO": "❌ NO_GO"}.get(status, status)

    lines: list[str] = [
        "# D2 Collection Audit Gate Report",
        "",
        f"**Status: {badge}**",
        "",
        "## Checks",
        "",
        "| Check | Result |",
        "|-------|--------|",
    ]
    for check_name, passed in report.get("checks", {}).items():
        icon = "✅" if passed else "❌"
        lines.append(f"| `{check_name}` | {icon} |")

    corrective = report.get("corrective_actions", [])
    if corrective:
        lines += [
            "",
            "## Corrective Actions Required",
            "",
        ]
        for action in corrective:
            lines.append(f"- **{action}**")
            # Provide detail from the relevant section
            action_sections = {
                "missing_blocks": "block",
                "missing_registered_transactions": "transactions",
                "missing_receipts": "receipts",
                "failed_log_ranges": "logs",
                "abi_coverage": "abi",
                "price_status": "prices",
                "public_source_status": "public_sources",
                "public_source_copyright_compliance": "public_sources",
                "registry_consistency": "registry_consistency",
                "no_duplicate_records": "duplicates",
                "source_manifest_valid": "source_manifest",
            }
            section = report.get(action_sections.get(action, action), {})
            if isinstance(section, dict):
                for k, v in section.items():
                    if isinstance(v, list) and v:
                        lines.append(f"  - {k}: {v[:5]}{'...' if len(v) > 5 else ''}")
                    elif v and not isinstance(v, (dict, list)):
                        lines.append(f"  - {k}: {v}")

    # Registry consistency section
    reg = report.get("registry_consistency")
    if reg:
        lines += ["", "## Registry Consistency", ""]
        for field, val in reg.items():
            if field == "passed":
                continue
            if val:
                lines.append(f"- ⚠️ **{field}**: {val}")

    # Price coverage section
    prices = report.get("prices", {})
    per_token = prices.get("per_token_coverage", {})
    if per_token:
        lines += ["", "## Price Coverage by Token", "", "| Token | Coverage % | Status |", "|-------|------------|--------|"]
        for sym, info in per_token.items():
            pct = info.get("coverage_percentage")
            token_status = info.get("status", "")
            pct_str = f"{pct:.1f}%" if pct is not None else "N/A"
            icon = "✅" if pct is not None and float(pct) >= 90 else "⚠️" if token_status == "pending" else "❌"
            lines.append(f"| `{sym}` | {pct_str} | {icon} |")

    # Public sources section
    ps = report.get("public_sources", {})
    uncovered = ps.get("uncovered_targets", [])
    if uncovered:
        lines += ["", "## Uncovered Public Source Targets", ""]
        for t in uncovered:
            lines.append(f"- {t}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# E6.7 – D3 gate enforcement
# ---------------------------------------------------------------------------


def enforce_d2_gate(report: Mapping[str, Any]) -> None:
    """Block D3 pipeline execution when D2 gate is ``NO_GO``.

    Args:
        report: Dict returned by :func:`build_d2_gate_report`.

    Raises:
        RuntimeError: When ``report["status"]`` is ``"NO_GO"``.
    """
    if report.get("status") == "NO_GO":
        actions = report.get("corrective_actions", [])
        raise RuntimeError(
            f"D2 gate is NO_GO — D3 pipeline execution is blocked. "
            f"Corrective actions required: {actions}"
        )
