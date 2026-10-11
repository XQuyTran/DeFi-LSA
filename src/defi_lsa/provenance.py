"""Source and artifact provenance records."""



import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .registry import sha256_file


@dataclass(frozen=True)
class SourceRecord:
    source_name: str
    request_url: str
    retrieved_at_utc: str
    response_sha256: str
    artifact_path: str
    adapter_version: str
    limitations: str = ""
    request_method: str = "GET"
    request_parameters_hash: str = ""
    requested_at_utc: str = ""
    completed_at_utc: str = ""
    http_status: int | None = None
    record_count: int = 0
    block_range: list[int] | None = None
    event_id: str = ""
    scope_hash: str = ""
    artifact_sha256: str = ""


def generate_source_manifest(
    output_path: Path,
    records: Iterable[SourceRecord],
    *,
    manifest_version: str = "1.0",
) -> None:
    """Write a stable source manifest; callers must provide retrieval evidence."""
    normalized = sorted(
        (asdict(record) for record in records),
        key=lambda record: (
            record["source_name"],
            record["request_url"],
            record["artifact_path"],
        ),
    )
    for record in normalized:
        if not record["requested_at_utc"]:
            record["requested_at_utc"] = record["retrieved_at_utc"]
        if not record["completed_at_utc"]:
            record["completed_at_utc"] = record["retrieved_at_utc"]
        if not record["artifact_sha256"]:
            artifact = Path(record["artifact_path"])
            if artifact.is_file():
                record["artifact_sha256"] = sha256_file(artifact)
        datetime.fromisoformat(
            record["retrieved_at_utc"].replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        if len(record["response_sha256"]) != 64:
            raise ValueError(
                f"Invalid response checksum for {record['request_url']}"
            )
    manifest = {
        "manifest_version": manifest_version,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "records": normalized,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def artifact_record(
    source_name: str,
    request_url: str,
    artifact_path: Path,
    adapter_version: str,
    *,
    limitations: str = "",
) -> SourceRecord:
    """Create a record from a persisted response artifact."""
    if not artifact_path.is_file():
        raise FileNotFoundError(artifact_path)
    return SourceRecord(
        source_name=source_name,
        request_url=request_url,
        retrieved_at_utc=datetime.now(timezone.utc).isoformat(),
        response_sha256=sha256_file(artifact_path),
        artifact_path=str(artifact_path),
        adapter_version=adapter_version,
        limitations=limitations,
        requested_at_utc=datetime.now(timezone.utc).isoformat(),
        completed_at_utc=datetime.now(timezone.utc).isoformat(),
        artifact_sha256=sha256_file(artifact_path),
    )
