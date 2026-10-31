"""Validated, credential-free D2 source configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping


_PRIORITY_SOURCE_NAMES = {
    "aws_public_blockchain",
    "ethereum_rpc",
    "etherscan",
    "local_cache",
    "protocol_repository",
    "chainlink",
    "onchain_pool",
    "coingecko",
    "official_protocol",
    "discourse",
    "gdelt",
}


@dataclass(frozen=True)
class SourceConfig:
    ethereum_rpc_url: str = ""
    etherscan_api_url: str = "https://api.etherscan.io/v2/api"
    etherscan_api_key: str = field(default="", repr=False, compare=False)
    etherscan_chain_id: int = 1
    coingecko_api_url: str = "https://api.coingecko.com/api/v3"
    coingecko_api_key: str = field(default="", repr=False, compare=False)
    coingecko_api_key_header: str = "x-cg-demo-api-key"
    gdelt_doc_api_url: str = "https://api.gdeltproject.org/api/v2/doc/doc"
    forums: Mapping[str, Any] = field(default_factory=dict)
    aws_public_blockchain: Mapping[str, Any] = field(default_factory=dict)
    enabled_sources: Mapping[str, bool] = field(default_factory=dict)
    source_priority: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    output_root: str = ""
    gdelt_enabled: bool = True
    request_timeout_seconds: float = 30.0
    maximum_attempts: int = 5
    requests_per_second: float = 3.0
    initial_log_chunk_size: int = 2000
    minimum_log_chunk_size: int = 10
    maximum_log_chunk_size: int = 20000

    def validate(self, require_rpc: bool = False) -> None:
        if require_rpc and not self.ethereum_rpc_url:
            raise ValueError("ETH_RPC_URL is required for RPC collection")
        for field_name, value in (
            ("forums", self.forums),
            ("aws_public_blockchain", self.aws_public_blockchain),
            ("enabled_sources", self.enabled_sources),
            ("source_priority", self.source_priority),
        ):
            if not isinstance(value, Mapping):
                raise ValueError(f"{field_name} must be a mapping")
        if self.etherscan_chain_id != 1:
            raise ValueError("only Ethereum mainnet (chain ID 1) is supported")
        if self.request_timeout_seconds <= 0 or self.maximum_attempts < 1:
            raise ValueError("timeout must be positive and attempts must be >= 1")
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        if not (
            1 <= self.minimum_log_chunk_size
            <= self.initial_log_chunk_size
            <= self.maximum_log_chunk_size
        ):
            raise ValueError("log chunk sizes must be min <= initial <= max")
        for source_name, source_order in self.source_priority.items():
            if not source_name.strip():
                raise ValueError("source priority artifact names must not be blank")
            if not isinstance(source_order, (tuple, list)):
                raise ValueError(f"source priority for {source_name} must be a sequence")
            if not source_order or any(not source.strip() for source in source_order):
                raise ValueError(f"source priority for {source_name} must not be blank")
            if len(set(source_order)) != len(source_order):
                raise ValueError(f"source priority for {source_name} contains duplicates")
            unknown = set(source_order) - _PRIORITY_SOURCE_NAMES
            if unknown:
                raise ValueError(
                    f"source priority for {source_name} contains unknown sources: "
                    + ", ".join(sorted(unknown))
                )
        if self.etherscan_api_url and not self.etherscan_api_url.startswith(("http://", "https://")):
            raise ValueError("etherscan_api_url must be an HTTP(S) URL")
        if self.coingecko_api_url and not self.coingecko_api_url.startswith(("http://", "https://")):
            raise ValueError("coingecko_api_url must be an HTTP(S) URL")
        if self.gdelt_enabled and not self.gdelt_doc_api_url.startswith(("http://", "https://")):
            raise ValueError("gdelt_doc_api_url must be an HTTP(S) URL")
        self._validate_nested_sources()

        if any(not isinstance(value, bool) for value in self.enabled_sources.values()):
            raise ValueError("enabled_sources values must be boolean")

    def _validate_nested_sources(self) -> None:
        aws = self.aws_public_blockchain
        if aws:
            if not isinstance(aws.get("enabled", True), bool):
                raise ValueError("aws_public_blockchain.enabled must be boolean")
            for key in ("bucket", "region"):
                if not isinstance(aws.get(key), str) or not aws[key].strip():
                    raise ValueError(f"aws_public_blockchain.{key} is required")
            tables = aws.get("tables", {})
            if not isinstance(tables, Mapping) or not tables:
                raise ValueError("aws_public_blockchain.tables must be a non-empty mapping")
        forums = self.forums
        if forums:
            for key in ("discourse_topic_template", "discourse_search_template"):
                if key in forums and not isinstance(forums[key], str):
                    raise ValueError(f"forums.{key} must be a string")
            for key in ("probe_url", "base_url"):
                if key in forums and forums[key] and not str(forums[key]).startswith(("http://", "https://")):
                    raise ValueError(f"forums.{key} must be an HTTP(S) URL")

    def priority_for(
        self,
        artifact_type: str,
        available_sources: set[str] | None = None,
    ) -> tuple[str, ...]:
        """Return configured source order, optionally filtered by availability."""
        if not artifact_type.strip():
            raise ValueError("artifact_type must not be blank")
        configured = self.source_priority.get(artifact_type, ())
        if available_sources is None:
            return tuple(configured)
        return tuple(source for source in configured if source in available_sources)

    def source_enabled(self, source: str) -> bool:
        """Return configured enablement, defaulting to enabled for overrides."""
        return self.enabled_sources.get(source, True)

    def select_source(self, artifact_type: str, available_sources: set[str]) -> str:
        """Select the highest-priority available source for an artifact."""
        selected = self.priority_for(artifact_type, available_sources)
        if not selected:
            raise ValueError(
                f"no configured source is available for artifact type {artifact_type!r}"
            )
        return selected[0]

    def public_dict(self) -> dict[str, Any]:
        """Return serializable configuration without environment credentials."""
        return {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if not item.name.endswith("_api_key") and item.name != "ethereum_rpc_url"
        }


def load_source_config(path: Path | None = None) -> SourceConfig:
    values: dict[str, Any] = {}
    config_path = path
    if config_path is None:
        config_path = Path(__file__).resolve().parents[2] / "configs" / "sources.json"
    if config_path.exists():
        values = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("source configuration must be a JSON object")

    ethereum = values.get("ethereum", {})
    for section_name in (
        "ethereum",
        "etherscan",
        "coingecko",
        "gdelt",
        "forums",
        "aws_public_blockchain",
        "source_priority",
        "collection",
    ):
        section = values.get(section_name, {})
        if not isinstance(section, Mapping):
            raise ValueError(f"source configuration section {section_name!r} must be an object")
    ethereum_rpc = ethereum.get("rpc", {}) if isinstance(ethereum, Mapping) else {}
    if not isinstance(ethereum_rpc, Mapping):
        raise ValueError("source configuration section 'ethereum.rpc' must be an object")
    etherscan = values.get("etherscan", {})
    coingecko = values.get("coingecko", {})
    gdelt = values.get("gdelt", {})
    collection = values.get("collection", {})

    flattened = dict(values)
    flattened["ethereum_rpc_url"] = os.getenv(
        str(ethereum_rpc.get("url_env", "ETH_RPC_URL")),
        values.get("ethereum_rpc_url", ""),
    )
    flattened["etherscan_api_url"] = etherscan.get(
        "base_url", values.get("etherscan_api_url", SourceConfig.etherscan_api_url)
    )
    flattened["etherscan_api_key"] = os.getenv(
        str(etherscan.get("api_key_env", "ETHERSCAN_API_KEY")), ""
    )
    flattened["etherscan_chain_id"] = int(etherscan.get("chain_id", 1))
    flattened["coingecko_api_url"] = coingecko.get(
        "base_url", values.get("coingecko_api_url", SourceConfig.coingecko_api_url)
    )
    flattened["coingecko_api_key"] = os.getenv(
        str(coingecko.get("api_key_env", "COINGECKO_API_KEY")), ""
    )
    flattened["coingecko_api_key_header"] = coingecko.get(
        "api_key_header", "x-cg-demo-api-key"
    )
    flattened["gdelt_doc_api_url"] = gdelt.get(
        "doc_api_url", SourceConfig.gdelt_doc_api_url
    )
    flattened["gdelt_enabled"] = gdelt.get("enabled", values.get("gdelt_enabled", True))
    flattened["output_root"] = collection.get("output_root", values.get("output_root", ""))
    flattened.update(
        {
            "forums": values.get("forums", {}),
            "aws_public_blockchain": values.get("aws_public_blockchain", {}),
            "enabled_sources": {
                "ethereum_rpc": bool(ethereum.get("enabled", True)),
                "etherscan": bool(etherscan.get("enabled", True)),
                "coingecko": bool(coingecko.get("enabled", True)),
                "gdelt": bool(gdelt.get("enabled", True)),
                "aws_public_blockchain": bool(
                    values.get("aws_public_blockchain", {}).get("enabled", True)
                ),
                "forums": bool(values.get("forums", {}).get("enabled", True)),
            },
            "source_priority": {},
        }
    )
    for key, value in values.get("source_priority", {}).items():
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"source priority for {key} must be an array")
        flattened["source_priority"][key] = tuple(value)
    for key in (
        "request_timeout_seconds",
        "maximum_attempts",
        "requests_per_second",
    ):
        if key in ethereum_rpc:
            flattened[key] = ethereum_rpc[key]

    for key in (
        "request_timeout_seconds",
        "maximum_attempts",
        "requests_per_second",
        "initial_log_chunk_size",
        "minimum_log_chunk_size",
        "maximum_log_chunk_size",
    ):
        if key in collection:
            flattened[key] = collection[key]

    allowed = {item.name for item in fields(SourceConfig)}
    config = SourceConfig(**{key: value for key, value in flattened.items() if key in allowed})
    config.validate()
    return config


def save_source_config(path: Path, config: SourceConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.public_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
