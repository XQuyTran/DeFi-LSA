"""Collection context and stage dispatch for executable D2 runs."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .checkpoints import CheckpointStore
from .collectors import CollectionResult, fetch_logs_chunked, json_rpc_client
from .config import SourceConfig
from .identifiers import normalize_address
from .registry import ContractScope
from .retry import RateLimiter, RetryPolicy, execute_with_retry
from .storage import normalized_path


@dataclass(frozen=True)
class CollectionContext:
    """Resolved inputs and canonical paths for one event collection run."""

    event: dict[str, Any]
    scope: ContractScope
    source_config: SourceConfig
    output_root: Path
    run_id: str
    resume: bool = False
    dry_run: bool = False

    @property
    def event_id(self) -> str:
        return str(self.event["event_id"])

    @property
    def start_block(self) -> int:
        return self._required_block("start_block")

    @property
    def end_block(self) -> int:
        return self._required_block("end_block")

    @property
    def logs_path(self) -> Path:
        return normalized_path("logs", self.event_id, self.output_root)

    @property
    def checkpoints(self) -> CheckpointStore:
        return CheckpointStore(self.output_root / "checkpoints")

    def _required_block(self, name: str) -> int:
        value = self.event.get(name)
        if value is None:
            raise ValueError(
                f"{self.event_id}: registry field {name} is required before collection"
            )
        return int(value)

    @classmethod
    def from_files(
        cls,
        event_id: str,
        *,
        events_path: Path,
        source_config: SourceConfig,
        output_root: Path,
        resume: bool = False,
        dry_run: bool = False,
    ) -> "CollectionContext":
        payload = json.loads(events_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("materialized events registry must be a JSON array")
        selector = str(event_id).strip()
        selector_aliases = {"kyber": "kyberswap"}
        selector = selector_aliases.get(selector, selector)
        matches = [
            item
            for item in payload
            if item.get("event_id") == selector
            or str(item.get("event_id", "")).startswith(f"{selector}_")
        ]
        if not matches:
            raise ValueError(f"No event matched: {event_id}")
        if len(matches) > 1:
            raise ValueError(f"Event prefix is ambiguous: {event_id}")
        event = matches[0]
        event_id = str(event["event_id"])

        addresses = {
            normalize_address(address)
            for field_name in (
                "protocol_or_vulnerable_contracts",
                "attack_contracts",
                "attacker_addresses",
            )
            for address in event.get(field_name, [])
        }
        if not addresses:
            raise ValueError(f"{event_id}: contract scope is empty")
        scope = ContractScope(
            event_id=event_id,
            chain_id=int(event.get("chain_id", 1)),
            addresses=tuple(sorted(addresses)),
            rationale="Materialized registry event scope",
        )
        return cls(
            event=event,
            scope=scope,
            source_config=source_config,
            output_root=output_root,
            run_id=uuid.uuid4().hex,
            resume=resume,
            dry_run=dry_run,
        )

    def collect_logs(self) -> CollectionResult:
        """Collect adaptive RPC logs for the frozen event block window."""
        if "logs" in self.source_config.source_priority:
            selected_source = self.source_config.select_source("logs", {"ethereum_rpc"})
            if selected_source != "ethereum_rpc":
                raise ValueError(
                    f"logs source {selected_source!r} is not implemented by the logs stage"
                )
        if not self.source_config.ethereum_rpc_url:
            raise ValueError("ETH_RPC_URL is required for RPC log collection")
        self.logs_path.parent.mkdir(parents=True, exist_ok=True)
        policy = RetryPolicy(max_attempts=self.source_config.maximum_attempts)
        rate_limiter = RateLimiter(requests_per_second=self.source_config.requests_per_second)
        rpc = json_rpc_client(
            self.source_config.ethereum_rpc_url,
            timeout=self.source_config.request_timeout_seconds,
        )

        def limited_rpc(method: str, params: list[Any]) -> Any:
            rate_limiter.acquire()
            return execute_with_retry(
                lambda: rpc(method, params),
                policy=policy,
            )

        return fetch_logs_chunked(
            limited_rpc,
            self.start_block,
            self.end_block,
            self.scope,
            self.logs_path,
            checkpoint_store=self.checkpoints,
            initial_chunk_size=self.source_config.initial_log_chunk_size,
            min_chunk_size=self.source_config.minimum_log_chunk_size,
            max_chunk_size=self.source_config.maximum_log_chunk_size,
            retry_policy=policy,
            retry_failed_ranges=self.resume,
            raw_source_dir=self.output_root,
            report_path=self.output_root / "reports" / self.event_id / "logs.json",
        )
