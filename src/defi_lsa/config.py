"""Validated, credential-free D2 source configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping


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

    def public_dict(self) -> dict[str, Any]:
        """Return serializable configuration without environment credentials."""
        return {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if not item.name.endswith("_api_key")
        }


def load_source_config(path: Path | None = None) -> SourceConfig:
    values: dict[str, Any] = {}
    if path and path.exists():
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("source configuration must be a JSON object")

    ethereum = values.get("ethereum", {})
    etherscan = values.get("etherscan", {})
    coingecko = values.get("coingecko", {})
    gdelt = values.get("gdelt", {})
    collection = values.get("collection", {})

    flattened = dict(values)
    flattened["ethereum_rpc_url"] = os.getenv(
        str(ethereum.get("rpc", {}).get("url_env", "ETH_RPC_URL")),
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
            "source_priority": {
                key: tuple(value)
                for key, value in values.get("source_priority", {}).items()
            },
        }
    )
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
