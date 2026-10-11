"""Registry loading, validation, and contract-scope derivation."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .identifiers import normalize_address

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
REQUIRED_COLUMNS = {
    "event_id",
    "protocol",
    "chain_id",
    "event_date_utc",
    "block_number",
    "exploit_tx_hash",
    "pipeline_onchain_source",
    "pipeline_abi_source",
    "pipeline_price_source",
    "pipeline_public_info_source",
}


@dataclass(frozen=True)
class EventCandidate:
    event_id: str
    protocol: str
    chain_id: int
    event_date_utc: str
    block_number: int | None
    exploit_tx_hash: str | None
    tx_scope: str
    protocol_or_vulnerable_contracts: tuple[str, ...]
    attack_contracts: tuple[str, ...]
    attacker_addresses: tuple[str, ...]
    tokens_related: tuple[str, ...]
    feasibility_status: str
    required_next_action: str


@dataclass(frozen=True)
class ContractScope:
    event_id: str
    chain_id: int
    addresses: tuple[str, ...]
    rationale: str


def _split_addresses(value: str) -> tuple[str, ...]:
    """Extract and normalise Ethereum addresses from a delimited string.

    Uses :func:`~defi_lsa.identifiers.normalize_address` so all address
    normalisation is routed through the canonical validation path.
    """
    raw_matches = re.findall(r"0x[0-9a-fA-F]{40}", value)
    seen: dict[str, None] = {}
    for raw in raw_matches:
        normalised = normalize_address(raw)
        seen[normalised] = None
    return tuple(seen.keys())


def _parse_optional_int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value else None


def _parse_optional_hash(value: str) -> str | None:
    value = value.strip().lower()
    return value or None


def _parse_date(value: str) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return parsed.date().isoformat()


def load_event_candidates(path: Path) -> list[EventCandidate]:
    """Load and validate the candidate CSV without mutating source data."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or ())
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"Missing required candidate columns: {sorted(missing)}")

        candidates = [
            EventCandidate(
                event_id=row["event_id"].strip(),
                protocol=row["protocol"].strip(),
                chain_id=int(row["chain_id"]),
                event_date_utc=_parse_date(row["event_date_utc"]),
                block_number=_parse_optional_int(row["block_number"]),
                exploit_tx_hash=_parse_optional_hash(row["exploit_tx_hash"]),
                tx_scope=row["tx_scope"].strip(),
                protocol_or_vulnerable_contracts=_split_addresses(
                    row["protocol_or_vulnerable_contracts"]
                ),
                attack_contracts=_split_addresses(row["attack_contracts"]),
                attacker_addresses=_split_addresses(row["attacker_addresses"]),
                tokens_related=tuple(
                    item.strip()
                    for item in row["tokens_related"].split(";")
                    if item.strip()
                ),
                feasibility_status=row["feasibility_status"].strip(),
                required_next_action=row["required_next_action"].strip(),
            )
            for row in reader
        ]
    validate_candidates(candidates)
    return candidates


def validate_candidates(candidates: Iterable[EventCandidate]) -> None:
    """Enforce registry invariants and report every invalid candidate."""
    candidates = list(candidates)
    errors: list[str] = []
    ids = [candidate.event_id for candidate in candidates]
    duplicates = sorted({event_id for event_id in ids if ids.count(event_id) > 1})
    if duplicates:
        errors.append(f"duplicate event IDs: {duplicates}")

    for candidate in candidates:
        if not candidate.event_id:
            errors.append("event_id must not be empty")
        if candidate.chain_id <= 0:
            errors.append(f"{candidate.event_id}: chain_id must be positive")
        for field_name, addresses in (
            ("protocol contracts", candidate.protocol_or_vulnerable_contracts),
            ("attack contracts", candidate.attack_contracts),
            ("attacker addresses", candidate.attacker_addresses),
        ):
            invalid = [address for address in addresses if not ADDRESS_RE.fullmatch(address)]
            if invalid:
                errors.append(f"{candidate.event_id}: invalid {field_name}: {invalid}")
        if candidate.exploit_tx_hash and not HASH_RE.fullmatch(candidate.exploit_tx_hash):
            errors.append(f"{candidate.event_id}: invalid exploit transaction hash")

    if errors:
        raise ValueError("; ".join(errors))


def build_contract_scope(candidate: EventCandidate) -> ContractScope:
    """Build the contract-centric D2 collection boundary for one event."""
    addresses = tuple(
        sorted(
            set(candidate.protocol_or_vulnerable_contracts)
            | set(candidate.attack_contracts)
            | set(candidate.attacker_addresses)
        )
    )
    if not addresses:
        raise ValueError(f"{candidate.event_id}: contract scope is empty")
    return ContractScope(
        event_id=candidate.event_id,
        chain_id=candidate.chain_id,
        addresses=addresses,
        rationale=(
            "Registry protocol/vulnerable contracts plus configured attack "
            "contracts and attacker addresses; supporting addresses require "
            "an explicit registry update."
        ),
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return completed.stdout.strip()


def write_registry_manifest(
    output_path: Path,
    input_paths: Iterable[Path],
    registry_version: str = "1.0",
) -> None:
    """Write a deterministic manifest for registry inputs."""
    inputs = {
        str(path): sha256_file(path)
        for path in sorted(input_paths, key=lambda item: str(item))
    }
    manifest = {
        "registry_version": registry_version,
        "git_commit": current_git_commit(),
        "inputs": inputs,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def candidates_as_dicts(candidates: Iterable[EventCandidate]) -> list[dict[str, object]]:
    return [asdict(candidate) for candidate in candidates]
