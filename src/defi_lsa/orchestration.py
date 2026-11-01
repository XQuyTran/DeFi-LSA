"""Collection context and stage dispatch for executable D2 runs."""

import json
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .checkpoints import Checkpoint, CheckpointStore, compute_scope_hash
from .collectors import (
    CollectionResult,
    DiscoveredTransactions,
    discover_scoped_transaction_hashes,
    fetch_abi,
    fetch_logs_chunked,
    fetch_receipts_by_hash,
    fetch_transactions_by_hash,
    json_rpc_client,
)
from .config import SourceConfig
from .identifiers import normalize_address, normalize_tx_hash, normalize_utc_timestamp
from .registry import (
    ContractScope,
    IncidentLeg,
    load_incident_legs,
    load_public_source_registry,
    load_token_registry,
)
from .retry import RateLimiter, RetryPolicy, execute_with_retry
from .storage import (
    append_normalized_records,
    normalized_path,
    read_jsonl_records,
    source_path,
)
from .adapters.coingecko import CoinGeckoAdapter
from .adapters.discourse import DiscourseAdapter
from .adapters.gdelt import GDELTAdapter
from .adapters.protocol import ProtocolAnnouncementAdapter


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2]


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
    force: bool = False
    version: str = "v1"
    incident_legs: tuple[IncidentLeg, ...] = field(default_factory=tuple)
    rpc: Callable[[str, list[Any]], Any] | None = None
    opener: Callable[..., Any] | None = None

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
    def transactions_path(self) -> Path:
        return normalized_path("transactions", self.event_id, self.output_root)

    @property
    def receipts_path(self) -> Path:
        return normalized_path("receipts", self.event_id, self.output_root)

    @property
    def transaction_index_path(self) -> Path:
        return normalized_path("transaction_index", self.event_id, self.output_root)

    @property
    def abi_dir(self) -> Path:
        return self.output_root / "data" / "raw" / "source" / "abi" / self.event_id

    @property
    def prices_path(self) -> Path:
        return (
            self.output_root
            / "data"
            / "raw"
            / "normalized"
            / "prices"
            / "coingecko"
            / f"{self.event_id}.jsonl"
        )

    @property
    def prices_raw_dir(self) -> Path:
        return self.output_root / "data" / "raw" / "source" / "coingecko" / self.event_id

    @property
    def discourse_path(self) -> Path:
        return normalized_path("discourse", self.event_id, self.output_root)

    @property
    def gdelt_path(self) -> Path:
        return normalized_path("gdelt", self.event_id, self.output_root)

    @property
    def protocol_path(self) -> Path:
        return normalized_path("protocol", self.event_id, self.output_root)

    @property
    def raw_source_dir(self) -> Path:
        return self.output_root / "data" / "raw" / "source"

    @property
    def reports_dir(self) -> Path:
        return self.output_root / "reports" / self.event_id

    @property
    def checkpoints(self) -> CheckpointStore:
        return CheckpointStore(self.output_root / "checkpoints")

    @property
    def registered_tx_hashes(self) -> tuple[str, ...]:
        hashes = set()
        exploit = self.event.get("exploit_tx_hash")
        if exploit:
            hashes.add(normalize_tx_hash(str(exploit)))
        for leg in self.incident_legs:
            if leg.event_id == self.event_id and leg.transaction_hash:
                hashes.add(normalize_tx_hash(leg.transaction_hash))
        return tuple(sorted(hashes))

    @property
    def tokens_related(self) -> tuple[str, ...]:
        raw_tokens = self.event.get("tokens_related", [])
        clean_tokens = []
        for item in raw_tokens:
            sym = str(item).strip()
            if "/" in sym:
                clean_tokens.extend(s.strip() for s in sym.split("/") if s.strip())
            elif " and " in sym:
                clean_tokens.extend(s.strip() for s in sym.split(" and ") if s.strip())
            elif sym:
                clean_tokens.append(sym)
        return tuple(sorted(set(clean_tokens)))

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
        force: bool = False,
        incident_legs_path: Path | None = None,
        rpc: Callable[[str, list[Any]], Any] | None = None,
        opener: Callable[..., Any] | None = None,
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

        legs: list[IncidentLeg] = []
        legs_file = incident_legs_path or (_default_root() / "configs" / "incident_legs.json")
        if legs_file.exists():
            legs = [leg for leg in load_incident_legs(legs_file) if leg.event_id == event_id]

        addresses = {
            normalize_address(address)
            for field_name in (
                "protocol_or_vulnerable_contracts",
                "attack_contracts",
                "attacker_addresses",
            )
            for address in event.get(field_name, [])
        }
        for leg in legs:
            addresses.add(normalize_address(leg.affected_address))

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
            force=force,
            incident_legs=tuple(legs),
            rpc=rpc,
            opener=opener,
        )

    def _handle_force(self, stage: str, paths: Iterable[Path]) -> None:
        """Create versioned archive of previous outputs and reset checkpoint for force runs."""
        if not self.force:
            return
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_dir = self.output_root / "data" / "raw" / "archive" / f"{self.event_id}_{stage}_{timestamp}"
        archived_any = False
        for path in paths:
            if path.exists():
                archive_dir.mkdir(parents=True, exist_ok=True)
                if path.is_file():
                    shutil.move(str(path), str(archive_dir / path.name))
                    archived_any = True
                elif path.is_dir() and any(path.iterdir()):
                    shutil.move(str(path), str(archive_dir / path.name))
                    archived_any = True

        # Reset checkpoint for this stage
        cp_path = self.checkpoints.checkpoint_path(self.event_id, stage)
        if cp_path.exists():
            archive_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(cp_path), str(archive_dir / f"{stage}_checkpoint.json"))

    def dry_run_plan(self) -> dict[str, Any]:
        """Produce a structured execution plan without network queries or writes."""
        return {
            "run_id": self.run_id,
            "event_id": self.event_id,
            "dry_run": True,
            "resume": self.resume,
            "force": self.force,
            "start_block": self.event.get("start_block"),
            "end_block": self.event.get("end_block"),
            "scope_addresses": list(self.scope.addresses),
            "registered_tx_hashes": list(self.registered_tx_hashes),
            "tokens_related": list(self.tokens_related),
            "paths": {
                "logs": str(self.logs_path),
                "transactions": str(self.transactions_path),
                "receipts": str(self.receipts_path),
                "transaction_index": str(self.transaction_index_path),
                "abi": str(self.abi_dir),
                "prices": str(self.prices_path),
                "discourse": str(self.discourse_path),
                "gdelt": str(self.gdelt_path),
                "protocol": str(self.protocol_path),
            },
        }

    def _rpc_caller(self) -> tuple[Callable[[str, list[Any]], Any], RetryPolicy]:
        policy = RetryPolicy(max_attempts=self.source_config.maximum_attempts)
        if self.rpc is not None:
            return self.rpc, policy
        if not self.source_config.ethereum_rpc_url:
            raise ValueError("ETH_RPC_URL is required for RPC collection")
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

        return limited_rpc, policy

    def collect_logs(self, source: str = "rpc") -> CollectionResult:
        """Collect adaptive RPC logs for the frozen event block window."""
        if source == "auto" and "logs" in self.source_config.source_priority:
            source = self.source_config.select_source("logs", {"ethereum_rpc"})
        if source not in ("rpc", "ethereum_rpc", "auto"):
            raise ValueError(f"logs source {source!r} is not implemented by the logs stage")

        self._handle_force("logs", [self.logs_path])
        self.logs_path.parent.mkdir(parents=True, exist_ok=True)
        limited_rpc, policy = self._rpc_caller()

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

    def discover_transactions(self) -> DiscoveredTransactions:
        """Discover scoped transaction hashes from logs and registered anchors."""
        self.transaction_index_path.parent.mkdir(parents=True, exist_ok=True)
        return discover_scoped_transaction_hashes(
            logs_path=self.logs_path if self.logs_path.exists() else None,
            registered_tx_hashes=self.registered_tx_hashes,
            scope=self.scope,
            output_path=self.transaction_index_path,
        )

    def collect_transactions(self, source: str = "rpc") -> CollectionResult:
        """Retrieve and normalize full transactions discovered from logs and registry anchors."""
        if source == "auto" and "transactions" in self.source_config.source_priority:
            source = self.source_config.select_source("transactions", {"ethereum_rpc"})
        if source not in ("rpc", "ethereum_rpc", "auto"):
            raise ValueError(f"transactions source {source!r} is not implemented")

        self._handle_force("transactions", [self.transactions_path, self.transaction_index_path])
        discovered = self.discover_transactions()
        if not discovered:
            return CollectionResult(self.transactions_path, 0, 0)

        limited_rpc, policy = self._rpc_caller()
        raw_dir = self.raw_source_dir / "transactions" / self.event_id
        return fetch_transactions_by_hash(
            limited_rpc,
            discovered,
            self.scope,
            self.transactions_path,
            raw_source_dir=raw_dir,
            retry_policy=policy,
        )

    def collect_receipts(self, source: str = "rpc") -> CollectionResult:
        """Retrieve and normalize transaction receipts for discovered scoped transactions."""
        if source == "auto" and "receipts" in self.source_config.source_priority:
            source = self.source_config.select_source("receipts", {"ethereum_rpc"})
        if source not in ("rpc", "ethereum_rpc", "auto"):
            raise ValueError(f"receipts source {source!r} is not implemented")

        self._handle_force("receipts", [self.receipts_path])
        discovered = self.discover_transactions()
        if not discovered:
            return CollectionResult(self.receipts_path, 0, 0)

        limited_rpc, policy = self._rpc_caller()
        raw_dir = self.raw_source_dir / "receipts" / self.event_id
        return fetch_receipts_by_hash(
            limited_rpc,
            discovered,
            self.scope,
            self.receipts_path,
            raw_source_dir=raw_dir,
            retry_policy=policy,
        )

    def collect_abi(self, source: str = "etherscan") -> CollectionResult:
        """Acquire verified contract ABIs for scoped addresses with local cache support."""
        if source == "auto" and "abi" in self.source_config.source_priority:
            source = self.source_config.select_source("abi", {"etherscan", "local_cache"})

        self._handle_force("abi", [self.abi_dir])
        self.abi_dir.mkdir(parents=True, exist_ok=True)

        cached_count = 0
        missing_addresses = []
        for address in self.scope.addresses:
            target_path = self.abi_dir / f"{address.lower()}.json"
            if target_path.exists() and not self.force:
                try:
                    json.loads(target_path.read_text(encoding="utf-8"))
                    cached_count += 1
                    continue
                except Exception:
                    pass
            missing_addresses.append(address)

        if not missing_addresses:
            return CollectionResult(self.abi_dir, 0, cached_count)

        if not self.source_config.etherscan_api_key:
            raise ValueError("ETHERSCAN_API_KEY is required for ABI collection")

        http_get = (lambda url: self.opener(url).read()) if self.opener is not None else None
        written_paths = fetch_abi(
            missing_addresses,
            self.source_config.etherscan_api_url,
            self.source_config.etherscan_api_key,
            self.abi_dir,
            http_get=http_get,
        )
        return CollectionResult(self.abi_dir, len(written_paths), cached_count)

    def collect_prices(self, source: str = "coingecko") -> CollectionResult:
        """Collect and normalize hourly token prices from CoinGecko for registered tokens."""
        if source == "auto" and "prices" in self.source_config.source_priority:
            source = self.source_config.select_source("prices", {"coingecko"})

        self._handle_force("prices", [self.prices_path])
        tokens_file = _default_root() / "configs" / "tokens.json"
        if not tokens_file.exists():
            return CollectionResult(self.prices_path, 0, 0)

        tokens = load_token_registry(tokens_file)
        start_dt = (
            self.event.get("collection_start_utc")
            or f"{self.event.get('event_date_utc', '2023-01-01')}T00:00:00Z"
        )
        end_dt = (
            self.event.get("collection_end_utc")
            or f"{self.event.get('event_date_utc', '2023-01-01')}T23:59:59Z"
        )

        policy = RetryPolicy(max_attempts=self.source_config.maximum_attempts)
        limiter = RateLimiter(requests_per_second=self.source_config.requests_per_second)
        adapter = CoinGeckoAdapter(
            api_key=self.source_config.coingecko_api_key,
            api_base_url=self.source_config.coingecko_api_url,
            retry_policy=policy,
            rate_limiter=limiter,
            opener=self.opener,
        )

        total_written = 0
        total_skipped = 0
        target_symbols = set(self.tokens_related)

        for token in tokens:
            symbol = token.get("symbol", "")
            if target_symbols and symbol not in target_symbols:
                continue
            if token.get("status") != "verified" or not token.get("address"):
                continue

            address = token["address"]
            coin_id = token.get("coingecko_id")
            if not coin_id:
                continue

            report_file = self.reports_dir / f"price_coverage_{symbol.lower()}.json"
            records = adapter.collect_hourly_prices(
                token_address=address,
                coin_id=coin_id,
                event_id=self.event_id,
                start_dt=start_dt,
                end_dt=end_dt,
                output_dir=self.output_root,
                raw_dir=self.output_root,
                coverage_report_path=report_file,
            )
            total_written += len(records)

        return CollectionResult(self.prices_path, total_written, total_skipped)

    def collect_public_sources(self, source: str = "auto") -> dict[str, CollectionResult]:
        """Collect forum announcements, protocol feeds, and GDELT metadata."""
        self._handle_force("public", [self.discourse_path, self.gdelt_path, self.protocol_path])
        results: dict[str, CollectionResult] = {}
        sources_file = _default_root() / "configs" / "public_sources.json"
        if not sources_file.exists():
            return results

        public_sources = load_public_source_registry(sources_file)
        matching = [s for s in public_sources if s.get("event_id") == self.event_id]
        if not matching:
            return results
        spec = matching[0]

        policy = RetryPolicy(max_attempts=self.source_config.maximum_attempts)
        limiter = RateLimiter(requests_per_second=self.source_config.requests_per_second)

        # 1. Discourse
        discourse_written = 0
        if self.source_config.forums and self.source_config.source_enabled("discourse"):
            adapter_discourse = DiscourseAdapter(
                retry_policy=policy, rate_limiter=limiter, opener=self.opener
            )
            for url in spec.get("official_urls", []):
                if "forum" in url or "gov" in url:
                    for topic_id in spec.get("topic_ids", []):
                        try:
                            recs = adapter_discourse.fetch_topic(
                                base_url=url.rstrip("/"),
                                topic_id=str(topic_id),
                                event_id=self.event_id,
                                output_dir=self.output_root,
                                raw_dir=self.output_root,
                            )
                            discourse_written += len(recs)
                        except Exception:
                            pass
        results["discourse"] = CollectionResult(self.discourse_path, discourse_written, 0)

        # 2. Protocol Announcement Feed
        protocol_written = 0
        if self.source_config.source_enabled("official_protocol"):
            proto_adapter = ProtocolAnnouncementAdapter(opener=self.opener)
            for url in spec.get("official_urls", []):
                if url.endswith(".json") or "feed" in url or "blog" in url:
                    try:
                        recs = proto_adapter.fetch_protocol_feed(
                            feed_url=url,
                            event_id=self.event_id,
                            raw_dir=self.output_root,
                            output_dir=self.output_root,
                        )
                        protocol_written += len(recs)
                    except Exception:
                        pass
        results["protocol"] = CollectionResult(self.protocol_path, protocol_written, 0)

        # 3. GDELT
        gdelt_written = 0
        if self.source_config.gdelt_enabled and self.source_config.source_enabled("gdelt"):
            gdelt_adapter = GDELTAdapter(
                retry_policy=policy, rate_limiter=limiter, opener=self.opener
            )
            window = spec.get("collection_window", {})
            start_date = window.get("start_utc") or self.event.get("collection_start_utc") or "2023-01-01T00:00:00Z"
            end_date = window.get("end_utc") or self.event.get("collection_end_utc") or "2023-01-01T23:59:59Z"
            for query in spec.get("search_queries", []) + spec.get("gdelt_aliases", []):
                try:
                    recs = gdelt_adapter.query_articles(
                        query=query,
                        start_date=start_date,
                        end_date=end_date,
                        event_id=self.event_id,
                        raw_dir=self.output_root,
                        output_dir=self.output_root,
                    )
                    gdelt_written += len(recs)
                except Exception:
                    pass
        results["gdelt"] = CollectionResult(self.gdelt_path, gdelt_written, 0)

        return results

    def collect_all(self, source: str = "auto") -> dict[str, Any]:
        """Execute all collection stages in strict dependency order.

        Order: abi -> logs -> transactions -> receipts -> prices -> public_sources.
        """
        results: dict[str, Any] = {}
        # 1. ABI
        results["abi"] = self.collect_abi(source="auto" if source == "auto" else source)
        # 2. Logs
        results["logs"] = self.collect_logs(source="auto" if source == "auto" else source)
        # 3. Transactions
        results["transactions"] = self.collect_transactions(source="auto" if source == "auto" else source)
        # 4. Receipts
        results["receipts"] = self.collect_receipts(source="auto" if source == "auto" else source)
        # 5. Prices
        results["prices"] = self.collect_prices(source="auto" if source == "auto" else source)
        # 6. Public Sources
        results["public_sources"] = self.collect_public_sources(source="auto" if source == "auto" else source)
        return results
