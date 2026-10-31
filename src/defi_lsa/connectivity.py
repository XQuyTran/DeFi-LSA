"""Connectivity probes for configured external data sources."""

import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import SourceConfig
from .errors import (
    AuthenticationError,
    InvalidRequestError,
    RateLimitError,
    SourceError,
)
from .retry import redact_credentials, classify_source_error


@dataclass(frozen=True)
class ProbeResult:
    source: str
    status: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "details": self.details,
        }


def _status_for_error(error: Exception) -> str:
    if isinstance(error, AuthenticationError):
        return "authentication_error"
    if isinstance(error, RateLimitError):
        return "rate_limited"
    if isinstance(error, InvalidRequestError):
        return "invalid_request"
    if isinstance(error, ValueError):
        return "invalid_configuration"
    if isinstance(error, SourceError):
        return "unreachable"
    return "unreachable"


def _error_result(source: str, error: Exception) -> ProbeResult:
    classified = error if isinstance(error, SourceError) else classify_source_error(error, source=source)
    details: dict[str, Any] = {
        "error_type": type(classified).__name__,
        "message": redact_credentials(str(classified)),
    }
    if classified.details:
        details["classified"] = {
            key: value for key, value in classified.details.items() if key != "response_body"
        }
    return ProbeResult(source, _status_for_error(classified), details)


def _read_http(
    source: str,
    url: str,
    *,
    opener: Callable[..., Any],
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float,
) -> bytes:
    request = Request(
        url,
        data=data,
        headers=headers or {"Accept": "application/json"},
        method=method,
    )
    try:
        with opener(request, timeout=timeout) as response:
            return response.read()
    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = None
        raise classify_source_error(
            exc,
            status_code=exc.code,
            response_body=body,
            headers=dict(exc.headers) if exc.headers else None,
            source=source,
        ) from exc
    except Exception as exc:
        raise classify_source_error(exc, source=source) from exc


def _json_body(source: str, payload: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError("source returned invalid JSON", source=source) from exc
    if not isinstance(parsed, dict):
        raise InvalidRequestError("source returned a non-object JSON payload", source=source)
    return parsed


def _probe_rpc(config: SourceConfig, opener: Callable[..., Any]) -> None:
    if not config.ethereum_rpc_url:
        raise ValueError("ETH_RPC_URL is required for RPC connectivity")
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    ).encode("utf-8")
    body = _read_http(
        "ethereum_rpc",
        config.ethereum_rpc_url,
        opener=opener,
        method="POST",
        data=payload,
        headers={"Content-Type": "application/json"},
        timeout=config.request_timeout_seconds,
    )
    parsed = _json_body("ethereum_rpc", body)
    if parsed.get("error"):
        raise classify_source_error(response_body=body.decode("utf-8", errors="replace"), source="ethereum_rpc")
    if parsed.get("result") != "0x1":
        raise InvalidRequestError("RPC endpoint is not serving Ethereum mainnet", source="ethereum_rpc")


def _probe_etherscan(config: SourceConfig, opener: Callable[..., Any]) -> None:
    query = urlencode(
        {
            "module": "contract",
            "action": "getabi",
            "address": "0x0000000000000000000000000000000000000000",
            "chainid": config.etherscan_chain_id,
            "apikey": config.etherscan_api_key,
        }
    )
    body = _read_http(
        "etherscan",
        f"{config.etherscan_api_url}?{query}",
        opener=opener,
        timeout=config.request_timeout_seconds,
    )
    parsed = _json_body("etherscan", body)
    if str(parsed.get("status")) != "1":
        raise classify_source_error(
            response_body=body.decode("utf-8", errors="replace"), source="etherscan"
        )


def _probe_coingecko(config: SourceConfig, opener: Callable[..., Any]) -> None:
    headers = {"Accept": "application/json"}
    if config.coingecko_api_key:
        headers[config.coingecko_api_key_header] = config.coingecko_api_key
    body = _read_http(
        "coingecko",
        f"{config.coingecko_api_url.rstrip('/')}/ping",
        opener=opener,
        headers=headers,
        timeout=config.request_timeout_seconds,
    )
    _json_body("coingecko", body)


def _probe_gdelt(config: SourceConfig, opener: Callable[..., Any]) -> None:
    url = f"{config.gdelt_doc_api_url}?{urlencode({'query': 'ethereum', 'mode': 'artlist', 'format': 'json', 'maxrecords': 1})}"
    body = _read_http("gdelt", url, opener=opener, timeout=config.request_timeout_seconds)
    _json_body("gdelt", body)


def _probe_aws(config: SourceConfig, opener: Callable[..., Any]) -> None:
    aws = config.aws_public_blockchain
    bucket = aws.get("bucket", "aws-public-blockchain")
    region = aws.get("region", "us-east-2")
    url = f"https://{bucket}.s3.{region}.amazonaws.com/?{urlencode({'list-type': 2, 'prefix': 'v1.0/eth/', 'max-keys': 1})}"
    body = _read_http("aws_public_blockchain", url, opener=opener, timeout=config.request_timeout_seconds)
    if not body:
        raise InvalidRequestError("AWS returned an empty listing", source="aws_public_blockchain")


def _probe_forums(config: SourceConfig, opener: Callable[..., Any]) -> None:
    forums = config.forums
    url = forums.get("probe_url") or forums.get("base_url")
    if not url:
        raise ValueError("forums.probe_url or forums.base_url is required")
    body = _read_http("forums", str(url), opener=opener, timeout=config.request_timeout_seconds)
    _json_body("forums", body)


_PROBES: dict[str, Callable[[SourceConfig, Callable[..., Any]], None]] = {
    "rpc": _probe_rpc,
    "etherscan": _probe_etherscan,
    "coingecko": _probe_coingecko,
    "gdelt": _probe_gdelt,
    "aws": _probe_aws,
    "forums": _probe_forums,
}


def probe_source(
    config: SourceConfig,
    source: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> ProbeResult:
    """Run one configured source probe and return a stable result."""
    if source not in _PROBES:
        raise ValueError(f"unknown connectivity source: {source}")
    try:
        _PROBES[source](config, opener)
    except Exception as exc:
        return _error_result(source, exc)
    return ProbeResult(source, "reachable", {})


def probe_sources(
    config: SourceConfig,
    source: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, ProbeResult]:
    names = tuple(_PROBES) if source == "auto" else (source,)
    return {name: probe_source(config, name, opener=opener) for name in names}
