"""Validated, credential-free D2 source configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceConfig:
    ethereum_rpc_url: str = ""
    etherscan_api_url: str = "https://api.etherscan.io/v2/api"
    coingecko_api_url: str = "https://api.coingecko.com/api/v3"
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


def load_source_config(path: Path | None = None) -> SourceConfig:
    values: dict[str, Any] = {}
    if path and path.exists():
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("source configuration must be a JSON object")
    values["ethereum_rpc_url"] = os.getenv("ETH_RPC_URL", values.get("ethereum_rpc_url", ""))
    values["etherscan_api_url"] = values.get("etherscan_api_url", SourceConfig.etherscan_api_url)
    values["coingecko_api_url"] = values.get("coingecko_api_url", SourceConfig.coingecko_api_url)
    config = SourceConfig(**{key: value for key, value in values.items() if key in SourceConfig.__dataclass_fields__})
    config.validate()
    return config


def save_source_config(path: Path, config: SourceConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2, sort_keys=True) + "\n", encoding="utf-8")
