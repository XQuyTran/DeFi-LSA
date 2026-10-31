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
from typing import Any, Iterable, Mapping

from .identifiers import normalize_address, normalize_utc_timestamp

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
EXECUTABLE_STATUSES = frozenset({"GO", "GO_WITH_ETHEREUM_SCOPE"})
TOKEN_REQUIRED_FIELDS = frozenset({"symbol", "chain_id", "address", "decimals", "coingecko_id", "fallback_price_source", "status"})
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
    collection_start_utc: str | None
    collection_end_utc: str | None
    start_block: int | None
    end_block: int | None
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
class IncidentLeg:
    """One verified pool/transaction/actor leg in an incident registry."""

    leg_id: str
    event_id: str
    chain_id: int
    affected_address: str
    asset_pair: str
    transaction_hash: str
    block_number: int
    actor_address: str
    role: str
    evidence_urls: tuple[str, ...]


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
    raw_matches = re.findall(r"0x[0-9a-fA-F]+", value)
    seen: dict[str, None] = {}
    for raw in raw_matches:
        normalised = normalize_address(raw)
        seen[normalised] = None
    return tuple(seen.keys())


def _parse_optional_int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value else None


def _parse_optional_timestamp(value: str) -> str | None:
    value = value.strip()
    return normalize_utc_timestamp(value) if value else None


def _parse_optional_hash(value: str) -> str | None:
    value = value.strip().lower()
    return value or None


def _parse_date(value: str) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return parsed.date().isoformat()


def load_event_candidates(path: Path) -> list[EventCandidate]:
    """Load and validate the candidate CSV without mutating source data."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        fieldnames = next(reader, [])
        columns = set(fieldnames)
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"Missing required candidate columns: {sorted(missing)}")

        candidates: list[EventCandidate] = []
        for values in reader:
            if len(values) == len(fieldnames) - 4:
                values = values[:5] + ["", "", "", ""] + values[5:]
            if len(values) != len(fieldnames):
                raise ValueError(
                    f"candidate row has {len(values)} fields; expected {len(fieldnames)}"
                )
            row = dict(zip(fieldnames, values))
            candidates.append(EventCandidate(
                event_id=row["event_id"].strip(),
                protocol=row["protocol"].strip(),
                chain_id=int(row["chain_id"]),
                event_date_utc=_parse_date(row["event_date_utc"]),
                collection_start_utc=_parse_optional_timestamp(
                    row.get("collection_start_utc", "")
                ),
                collection_end_utc=_parse_optional_timestamp(
                    row.get("collection_end_utc", "")
                ),
                start_block=_parse_optional_int(row.get("start_block", "")),
                end_block=_parse_optional_int(row.get("end_block", "")),
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
            ))
    validate_candidates(candidates)
    return candidates


def load_incident_legs(path: Path) -> list[IncidentLeg]:
    """Load structured incident legs without silently accepting partial rows."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("incident-leg registry must be a JSON array")

    legs: list[IncidentLeg] = []
    for item in payload:
        if not isinstance(item, Mapping):
            raise ValueError("each incident leg must be a JSON object")
        evidence = item.get("evidence_urls", [])
        if not isinstance(evidence, list) or not all(
            isinstance(value, str) and value.strip() for value in evidence
        ):
            raise ValueError("incident-leg evidence_urls must be a list of URLs")
        legs.append(
            IncidentLeg(
                leg_id=str(item.get("leg_id", "")).strip(),
                event_id=str(item.get("event_id", "")).strip(),
                chain_id=int(item.get("chain_id", 0)),
                affected_address=normalize_address(
                    str(item.get("affected_address", ""))
                ),
                asset_pair=str(item.get("asset_pair", "")).strip(),
                transaction_hash=str(item.get("transaction_hash", "")).strip().lower(),
                block_number=int(item.get("block_number", -1)),
                actor_address=normalize_address(str(item.get("actor_address", ""))),
                role=str(item.get("role", "")).strip().lower(),
                evidence_urls=tuple(value.strip() for value in evidence),
            )
        )
    validate_incident_legs(legs)
    return legs


def load_token_registry(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("token registry must be a JSON array")
    validate_token_registry(payload)
    return payload


def validate_token_registry(tokens: Iterable[Mapping[str, Any]]) -> None:
    errors: list[str] = []
    symbols: set[str] = set()
    for token in tokens:
        missing = TOKEN_REQUIRED_FIELDS - set(token)
        symbol = str(token.get("symbol", "")).strip()
        if missing:
            errors.append(f"{symbol or '<unknown>'}: missing token fields {sorted(missing)}")
            continue
        if symbol in symbols:
            errors.append(f"duplicate token symbol: {symbol}")
        symbols.add(symbol)
        if int(token["chain_id"]) != 1:
            errors.append(f"{symbol}: only Ethereum chain ID 1 is supported")
        if token["status"] == "verified":
            if not isinstance(token["address"], str) or not ADDRESS_RE.fullmatch(token["address"]):
                errors.append(f"{symbol}: verified token requires an Ethereum address")
            if not isinstance(token["decimals"], int) or not 0 <= token["decimals"] <= 36:
                errors.append(f"{symbol}: invalid decimals")
        elif token["status"] != "pending":
            errors.append(f"{symbol}: status must be verified or pending")
    if errors:
        raise ValueError("; ".join(errors))


def load_public_source_registry(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("public-source registry must be a JSON array")
    validate_public_source_registry(payload)
    return payload


def validate_public_source_registry(sources: Iterable[Mapping[str, Any]]) -> None:
    errors: list[str] = []
    for source in sources:
        event_id = str(source.get("event_id", "")).strip()
        if not event_id or not source.get("allowed_domains") or not source.get("collection_window"):
            errors.append(f"{event_id or '<unknown>'}: source requires event_id, allowed_domains, and collection_window")
        window = source.get("collection_window", {})
        if isinstance(window, Mapping):
            start = window.get("start_utc")
            end = window.get("end_utc")
            if (start is None) != (end is None) or (start and end and str(end) < str(start)):
                errors.append(f"{event_id}: invalid public-source collection window")
    if errors:
        raise ValueError("; ".join(errors))


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
        if (candidate.collection_start_utc is None) != (
            candidate.collection_end_utc is None
        ):
            errors.append(
                f"{candidate.event_id}: collection_start_utc and collection_end_utc "
                "must be provided together"
            )
        if candidate.collection_start_utc and candidate.collection_end_utc:
            if candidate.collection_end_utc < candidate.collection_start_utc:
                errors.append(
                    f"{candidate.event_id}: collection_end_utc must not precede "
                    "collection_start_utc"
                )
        if (candidate.start_block is None) != (candidate.end_block is None):
            errors.append(
                f"{candidate.event_id}: start_block and end_block must be provided together"
            )
        if candidate.start_block is not None and candidate.end_block is not None:
            if candidate.start_block < 0 or candidate.end_block < candidate.start_block:
                errors.append(f"{candidate.event_id}: invalid collection block window")
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


def validate_incident_legs(legs: Iterable[IncidentLeg]) -> None:
    """Validate one-to-one ownership of registered incident transactions."""
    legs = list(legs)
    errors: list[str] = []
    leg_ids = [leg.leg_id for leg in legs]
    transaction_hashes = [leg.transaction_hash for leg in legs]
    if any(not value for value in leg_ids):
        errors.append("incident leg IDs must not be empty")
    if len(set(leg_ids)) != len(leg_ids):
        errors.append("incident leg IDs must be unique")
    if len(set(transaction_hashes)) != len(transaction_hashes):
        errors.append("each registered transaction must belong to one incident leg")

    allowed_roles = {"attacker", "front_runner", "mev", "white_hat", "recovery", "victim"}
    for leg in legs:
        if leg.chain_id != 1:
            errors.append(f"{leg.leg_id}: only Ethereum chain ID 1 is supported")
        if not ADDRESS_RE.fullmatch(leg.affected_address):
            errors.append(f"{leg.leg_id}: invalid affected address")
        if not HASH_RE.fullmatch(leg.transaction_hash):
            errors.append(f"{leg.leg_id}: invalid transaction hash")
        if leg.block_number < 0:
            errors.append(f"{leg.leg_id}: block_number must be non-negative")
        if not ADDRESS_RE.fullmatch(leg.actor_address):
            errors.append(f"{leg.leg_id}: invalid actor address")
        if leg.role not in allowed_roles:
            errors.append(f"{leg.leg_id}: unsupported actor role {leg.role!r}")
        if not leg.asset_pair:
            errors.append(f"{leg.leg_id}: asset_pair must not be empty")
        if not leg.evidence_urls:
            errors.append(f"{leg.leg_id}: at least one evidence URL is required")

    if errors:
        raise ValueError("; ".join(errors))


def validate_executable_candidates(
    candidates: Iterable[EventCandidate],
    incident_legs: Iterable[IncidentLeg] = (),
) -> None:
    """Prevent executable events from being materialized without frozen inputs."""
    candidates = list(candidates)
    legs_by_event: dict[str, list[IncidentLeg]] = {}
    for leg in incident_legs:
        legs_by_event.setdefault(leg.event_id, []).append(leg)

    errors: list[str] = []
    for candidate in candidates:
        if candidate.feasibility_status not in EXECUTABLE_STATUSES:
            continue
        missing = [
            name
            for name, value in (
                ("collection_start_utc", candidate.collection_start_utc),
                ("collection_end_utc", candidate.collection_end_utc),
                ("start_block", candidate.start_block),
                ("end_block", candidate.end_block),
            )
            if value is None
        ]
        if missing:
            errors.append(
                f"{candidate.event_id}: executable status requires frozen fields "
                f"{sorted(missing)}"
            )
        if not legs_by_event.get(candidate.event_id):
            errors.append(f"{candidate.event_id}: executable status requires incident legs")

    if errors:
        raise ValueError("; ".join(errors))


def build_contract_scope(
    candidate: EventCandidate,
    incident_legs: Iterable[IncidentLeg] = (),
) -> ContractScope:
    """Build the contract-centric D2 collection boundary for one event."""
    addresses = tuple(
        sorted(
            set(candidate.protocol_or_vulnerable_contracts)
            | set(candidate.attack_contracts)
            | set(candidate.attacker_addresses)
            | {
                leg.affected_address
                for leg in incident_legs
                if leg.event_id == candidate.event_id
            }
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
