"""Normalized record schemas and RPC-to-record conversion utilities (A16).

Every public ``normalize_*_record`` function converts a raw RPC-shaped dict
into a deterministic, frozen dataclass.  All functions raise :exc:`ValueError`
explicitly on missing or malformed fields — there are no silent fallbacks.

Usage example::

    from defi_lsa.schemas import normalize_block_record, NORMALIZATION_VERSION

    record = normalize_block_record(raw_rpc_block, event_id="evt-001", source_sha256="abc...")
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from defi_lsa.identifiers import (
    normalize_address,
    normalize_tx_hash,
    parse_rpc_quantity,
)

# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

#: Bump this string whenever the normalization logic changes in a
#: backward-incompatible way so downstream consumers can detect schema drift.
NORMALIZATION_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Normalized record dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BlockRecord:
    """A single Ethereum block normalized from an RPC or AWS source.

    Attributes:
        record_key: Canonical dedup key — ``str(block_number)``.
        event_id: Incident / collection event identifier.
        chain_id: EIP-155 chain identifier.
        block_number: Absolute block height.
        block_timestamp: Unix seconds (exact, from block header).
        gas_used: Total gas consumed in the block.
        block_hash: Lowercase 0x-prefixed 32-byte block hash.
        source: Origin of the raw data, one of ``"rpc"`` or ``"aws"``.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    chain_id: int
    block_number: int
    block_timestamp: int
    gas_used: int
    block_hash: str
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class TransactionRecord:
    """A single Ethereum transaction normalized from an RPC source.

    Attributes:
        record_key: Canonical dedup key — ``tx_hash``.
        event_id: Incident / collection event identifier.
        chain_id: EIP-155 chain identifier.
        tx_hash: Lowercase 0x-prefixed 32-byte transaction hash.
        block_number: Block in which the transaction was included.
        from_address: Sender address (lowercase, 0x-prefixed).
        to_address: Recipient address, or empty string for contract creation.
        value_wei: Native-token transfer value in wei (exact integer).
        gas: Gas limit declared by the sender.
        gas_price: Gas price in wei (exact integer).
        nonce: Sender's transaction count at time of submission.
        inclusion_reasons: Why this tx is in the dataset — a tuple of one or
            more of ``"direct_call"``, ``"scoped_log"``, ``"registry_anchor"``.
        source: Origin of the raw data.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    chain_id: int
    tx_hash: str
    block_number: int
    from_address: str
    to_address: str
    value_wei: int
    gas: int
    gas_price: int
    nonce: int
    inclusion_reasons: tuple[str, ...]
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class ReceiptRecord:
    """A single Ethereum transaction receipt normalized from an RPC source.

    Attributes:
        record_key: Canonical dedup key — ``tx_hash``.
        event_id: Incident / collection event identifier.
        chain_id: EIP-155 chain identifier.
        tx_hash: Lowercase 0x-prefixed 32-byte transaction hash.
        block_number: Block in which the receipt was produced.
        status: ``1`` for success, ``0`` for reverted (EIP-658).
        gas_used: Actual gas consumed by the transaction.
        log_count: Number of logs emitted.
        source: Origin of the raw data.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    chain_id: int
    tx_hash: str
    block_number: int
    status: int
    gas_used: int
    log_count: int
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class LogRecord:
    """A single EVM event log normalized from an RPC source.

    Attributes:
        record_key: Canonical dedup key — ``"{chain_id}:{tx_hash}:{log_index}"``.
        event_id: Incident / collection event identifier.
        chain_id: EIP-155 chain identifier.
        tx_hash: Lowercase 0x-prefixed 32-byte transaction hash.
        log_index: Position of the log within the transaction receipt.
        block_number: Block containing the log.
        address: Emitting contract address (lowercase, 0x-prefixed).
        topics: Tuple of hex-encoded 32-byte topic strings.
        data: ABI-encoded data field as a hex string.
        source: Origin of the raw data.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    chain_id: int
    tx_hash: str
    log_index: int
    block_number: int
    address: str
    topics: tuple[str, ...]
    data: str
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class TokenTransferRecord:
    """An ERC-20 transfer row normalized from the AWS dataset."""

    record_key: str
    event_id: str
    chain_id: int
    tx_hash: str
    log_index: int
    block_number: int
    token_address: str
    from_address: str
    to_address: str
    value_wei: int
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class TraceRecord:
    """An EVM execution trace row normalized from the AWS dataset."""

    record_key: str
    event_id: str
    chain_id: int
    tx_hash: str
    trace_address: tuple[int, ...]
    block_number: int
    from_address: str
    to_address: str
    value_wei: int
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class ContractRecord:
    """A deployed contract row normalized from the AWS dataset."""

    record_key: str
    event_id: str
    chain_id: int
    address: str
    block_number: int
    source: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class PriceRecord:
    """A single token price observation normalized from an external price source.

    Attributes:
        record_key: Canonical dedup key — ``"{token_address}:{hour_utc}"``.
        event_id: Incident / collection event identifier.
        token_address: ERC-20 contract address (lowercase, 0x-prefixed).
        coingecko_id: CoinGecko asset identifier slug.
        source_timestamp: Unix seconds from the upstream source.
        hour_utc: ISO 8601 timestamp truncated to the UTC hour boundary,
            e.g. ``"2023-03-13T12:00:00Z"``.
        usd_price: USD price at the hour boundary (float).
        source: Data provider, e.g. ``"coingecko"``.
        retrieved_at_utc: ISO 8601 UTC string for when the record was fetched.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    token_address: str
    coingecko_id: str
    source_timestamp: int
    hour_utc: str
    usd_price: float
    source: str
    retrieved_at_utc: str
    source_sha256: str
    normalization_version: str


@dataclass(frozen=True)
class PublicInfoRecord:
    """A single public-information article normalized from a web/media source.

    Attributes:
        record_key: Canonical dedup key — ``"{source}:{url}"``.
        event_id: Incident / collection event identifier.
        url: Original URL of the article.
        canonical_url: Cleaned / canonical URL (may equal *url*).
        title: Article or post title.
        published_at_utc: ISO 8601 UTC publication timestamp.
        source: Publisher category — ``"discourse"``, ``"protocol"``,
            or ``"gdelt"``.
        source_sha256: SHA-256 of the source artifact bytes.
        normalization_version: Version string of the normalization logic.
    """

    record_key: str
    event_id: str
    url: str
    canonical_url: str
    title: str
    published_at_utc: str
    source: str
    source_sha256: str
    normalization_version: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_VALID_SOURCES_BLOCK = frozenset({"rpc", "aws"})
_VALID_INCLUSION_REASONS = frozenset(
    {"direct_call", "scoped_log", "registry_anchor"}
)
_VALID_SOURCES_PUBLIC_INFO = frozenset({"discourse", "protocol", "gdelt"})
_VALID_SOURCES_AWS = frozenset({"aws"})


def _require(raw: dict[str, Any], key: str) -> Any:
    """Return ``raw[key]`` or raise :exc:`ValueError` if the key is absent."""
    if key not in raw:
        raise ValueError(f"missing required field {key!r} in raw record")
    return raw[key]


def _sha256_str(data: str) -> str:
    """Return the lower-hex SHA-256 digest of *data* encoded as UTF-8."""
    return hashlib.sha256(data.encode()).hexdigest()


def _truncate_to_hour_utc(unix_seconds: int) -> str:
    """Convert *unix_seconds* to a UTC ISO 8601 string truncated to the hour.

    Example::

        >>> _truncate_to_hour_utc(1678708823)
        '2023-03-13T12:00:00Z'
    """
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    truncated = dt.replace(minute=0, second=0, microsecond=0)
    return truncated.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_topic(value: str) -> str:
    """Validate and lowercase a 32-byte EVM topic hex string.

    Raises:
        ValueError: If *value* is not a 0x-prefixed 64-hex-char string.
    """
    if not isinstance(value, str):
        raise ValueError(f"topic must be a str, got {type(value).__name__!r}")
    lowered = value.strip().lower()
    if not (lowered.startswith("0x") and len(lowered) == 66 and
            all(c in "0123456789abcdef" for c in lowered[2:])):
        raise ValueError(
            f"invalid topic {value!r}: expected 0x-prefixed 64 hex characters"
        )
    return lowered


def _normalize_hex_data(value: str) -> str:
    """Validate and lowercase a 0x-prefixed hex data field (arbitrary length).

    Raises:
        ValueError: If *value* is not a 0x-prefixed hex string.
    """
    if not isinstance(value, str):
        raise ValueError(f"data must be a str, got {type(value).__name__!r}")
    lowered = value.strip().lower()
    if not lowered.startswith("0x"):
        raise ValueError(
            f"invalid hex data {value!r}: must be 0x-prefixed"
        )
    hex_part = lowered[2:]
    if hex_part and not all(c in "0123456789abcdef" for c in hex_part):
        raise ValueError(
            f"invalid hex data {value!r}: non-hex characters after 0x prefix"
        )
    return lowered


# ---------------------------------------------------------------------------
# Public normalization functions
# ---------------------------------------------------------------------------


def normalize_block_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
) -> BlockRecord:
    """Convert a raw RPC ``eth_getBlockByNumber`` response dict to a :class:`BlockRecord`.

    Expected raw keys (standard Ethereum JSON-RPC field names):
        - ``number`` — hex block number
        - ``timestamp`` — hex Unix seconds
        - ``gasUsed`` — hex gas used
        - ``hash`` — block hash hex string
        - ``chainId`` — int or hex chain id (may also be supplied as a top-level
          wrapper field; callers should inject it)
        - ``source`` — ``"rpc"`` or ``"aws"``

    Args:
        raw: Raw block dict from an RPC response (or equivalent).
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.

    Returns:
        A frozen :class:`BlockRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")

    block_number = parse_rpc_quantity(_require(raw, "number"))
    block_timestamp = parse_rpc_quantity(_require(raw, "timestamp"))
    gas_used = parse_rpc_quantity(_require(raw, "gasUsed"))
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))

    raw_hash = _require(raw, "hash")
    if not isinstance(raw_hash, str):
        raise ValueError(f"block hash must be a str, got {type(raw_hash).__name__!r}")
    block_hash = raw_hash.strip().lower()
    # Block hash is 32 bytes = 66 chars with 0x prefix
    if not (block_hash.startswith("0x") and len(block_hash) == 66):
        raise ValueError(
            f"invalid block hash {raw_hash!r}: expected 0x-prefixed 64 hex characters"
        )

    source = _require(raw, "source")
    if source not in _VALID_SOURCES_BLOCK:
        raise ValueError(
            f"invalid source {source!r}: expected one of {sorted(_VALID_SOURCES_BLOCK)}"
        )

    return BlockRecord(
        record_key=str(block_number),
        event_id=event_id,
        chain_id=chain_id,
        block_number=block_number,
        block_timestamp=block_timestamp,
        gas_used=gas_used,
        block_hash=block_hash,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_transaction_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
    *,
    inclusion_reasons: tuple[str, ...] = ("direct_call",),
) -> TransactionRecord:
    """Convert a raw RPC ``eth_getTransactionByHash`` response dict to a :class:`TransactionRecord`.

    Expected raw keys:
        - ``hash`` — tx hash hex
        - ``blockNumber`` — hex block number
        - ``from`` — sender address
        - ``to`` — recipient address or ``None`` / absent for contract creation
        - ``value`` — hex wei value
        - ``gas`` — hex gas limit
        - ``gasPrice`` — hex gas price
        - ``nonce`` — hex nonce
        - ``chainId`` — int or hex chain id
        - ``source`` — data origin string

    Args:
        raw: Raw transaction dict from an RPC response (or equivalent).
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.
        inclusion_reasons: Why this transaction is in scope.  Each element must
            be one of ``"direct_call"``, ``"scoped_log"``,
            ``"registry_anchor"``.

    Returns:
        A frozen :class:`TransactionRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")
    if not inclusion_reasons:
        raise ValueError("inclusion_reasons must contain at least one entry")
    for reason in inclusion_reasons:
        if reason not in _VALID_INCLUSION_REASONS:
            raise ValueError(
                f"invalid inclusion_reason {reason!r}: "
                f"expected one of {sorted(_VALID_INCLUSION_REASONS)}"
            )

    tx_hash = normalize_tx_hash(_require(raw, "hash"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    from_address = normalize_address(_require(raw, "from"))
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    value_wei = parse_rpc_quantity(_require(raw, "value"))
    gas = parse_rpc_quantity(_require(raw, "gas"))
    gas_price = parse_rpc_quantity(_require(raw, "gasPrice"))
    nonce = parse_rpc_quantity(_require(raw, "nonce"))

    # ``to`` is None / null for contract creation transactions
    raw_to = raw.get("to")
    if raw_to is None or (isinstance(raw_to, str) and raw_to.strip() == ""):
        to_address = ""
    else:
        to_address = normalize_address(raw_to)

    source = _require(raw, "source")

    return TransactionRecord(
        record_key=tx_hash,
        event_id=event_id,
        chain_id=chain_id,
        tx_hash=tx_hash,
        block_number=block_number,
        from_address=from_address,
        to_address=to_address,
        value_wei=value_wei,
        gas=gas,
        gas_price=gas_price,
        nonce=nonce,
        inclusion_reasons=tuple(inclusion_reasons),
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_receipt_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
) -> ReceiptRecord:
    """Convert a raw RPC ``eth_getTransactionReceipt`` response dict to a :class:`ReceiptRecord`.

    Expected raw keys:
        - ``transactionHash`` — tx hash hex
        - ``blockNumber`` — hex block number
        - ``status`` — hex ``"0x1"`` or ``"0x0"``
        - ``gasUsed`` — hex gas used
        - ``logs`` — list of log objects (only length is used here)
        - ``chainId`` — int or hex chain id
        - ``source`` — data origin string

    Args:
        raw: Raw receipt dict from an RPC response (or equivalent).
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.

    Returns:
        A frozen :class:`ReceiptRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")

    tx_hash = normalize_tx_hash(_require(raw, "transactionHash"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    gas_used = parse_rpc_quantity(_require(raw, "gasUsed"))

    raw_status = _require(raw, "status")
    status = parse_rpc_quantity(raw_status)
    if status not in (0, 1):
        raise ValueError(
            f"invalid receipt status {raw_status!r}: expected 0x0 or 0x1"
        )

    raw_logs = _require(raw, "logs")
    if not isinstance(raw_logs, list):
        raise ValueError(
            f"receipt 'logs' must be a list, got {type(raw_logs).__name__!r}"
        )
    log_count = len(raw_logs)

    source = _require(raw, "source")

    return ReceiptRecord(
        record_key=tx_hash,
        event_id=event_id,
        chain_id=chain_id,
        tx_hash=tx_hash,
        block_number=block_number,
        status=status,
        gas_used=gas_used,
        log_count=log_count,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_log_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
) -> LogRecord:
    """Convert a raw RPC log object to a :class:`LogRecord`.

    Expected raw keys:
        - ``transactionHash`` — tx hash hex
        - ``logIndex`` — hex log index
        - ``blockNumber`` — hex block number
        - ``address`` — emitting contract address
        - ``topics`` — list of 32-byte hex topic strings
        - ``data`` — ABI-encoded data hex string
        - ``chainId`` — int or hex chain id
        - ``source`` — data origin string

    Args:
        raw: Raw log dict from an RPC receipt or ``eth_getLogs`` response.
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.

    Returns:
        A frozen :class:`LogRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")

    tx_hash = normalize_tx_hash(_require(raw, "transactionHash"))
    log_index = parse_rpc_quantity(_require(raw, "logIndex"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    address = normalize_address(_require(raw, "address"))
    data = _normalize_hex_data(_require(raw, "data"))
    source = _require(raw, "source")

    raw_topics = _require(raw, "topics")
    if not isinstance(raw_topics, list):
        raise ValueError(
            f"log 'topics' must be a list, got {type(raw_topics).__name__!r}"
        )
    topics = tuple(_normalize_topic(t) for t in raw_topics)

    record_key = f"{chain_id}:{tx_hash}:{log_index}"

    return LogRecord(
        record_key=record_key,
        event_id=event_id,
        chain_id=chain_id,
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        address=address,
        topics=topics,
        data=data,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def _validate_aws_context(event_id: str, source_sha256: str) -> None:
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")


def _validate_aws_source(raw: dict[str, Any]) -> str:
    source = _require(raw, "source")
    if source not in _VALID_SOURCES_AWS:
        raise ValueError(
            f"invalid AWS source {source!r}: expected one of {sorted(_VALID_SOURCES_AWS)}"
        )
    return source


def _normalize_trace_address(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("trace_address must be a list or tuple")
    normalized = []
    for item in value:
        parsed = parse_rpc_quantity(item)
        if parsed < 0:
            raise ValueError("trace_address values must be non-negative")
        normalized.append(parsed)
    return tuple(normalized)


def normalize_token_transfer_record(
    raw: dict[str, Any], event_id: str, source_sha256: str
) -> TokenTransferRecord:
    """Normalize an AWS token-transfer row with an exact uint256 amount."""
    _validate_aws_context(event_id, source_sha256)
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    tx_hash = normalize_tx_hash(_require(raw, "transactionHash"))
    log_index = parse_rpc_quantity(_require(raw, "logIndex"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    token_address = normalize_address(_require(raw, "tokenAddress"))
    from_address = normalize_address(_require(raw, "from"))
    to_address = normalize_address(_require(raw, "to"))
    value_wei = parse_rpc_quantity(_require(raw, "value"))
    source = _validate_aws_source(raw)
    return TokenTransferRecord(
        record_key=f"{chain_id}:{tx_hash}:{log_index}",
        event_id=event_id,
        chain_id=chain_id,
        tx_hash=tx_hash,
        log_index=log_index,
        block_number=block_number,
        token_address=token_address,
        from_address=from_address,
        to_address=to_address,
        value_wei=value_wei,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_trace_record(
    raw: dict[str, Any], event_id: str, source_sha256: str
) -> TraceRecord:
    """Normalize an AWS execution-trace row with a deterministic call path."""
    _validate_aws_context(event_id, source_sha256)
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    tx_hash = normalize_tx_hash(_require(raw, "transactionHash"))
    trace_address = _normalize_trace_address(_require(raw, "traceAddress"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    from_address = normalize_address(_require(raw, "from"))
    raw_to = _require(raw, "to")
    to_address = "" if raw_to is None or raw_to == "" else normalize_address(raw_to)
    value_wei = parse_rpc_quantity(_require(raw, "value"))
    source = _validate_aws_source(raw)
    path = ".".join(str(item) for item in trace_address) or "root"
    return TraceRecord(
        record_key=f"{chain_id}:{tx_hash}:{path}",
        event_id=event_id,
        chain_id=chain_id,
        tx_hash=tx_hash,
        trace_address=trace_address,
        block_number=block_number,
        from_address=from_address,
        to_address=to_address,
        value_wei=value_wei,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_contract_record(
    raw: dict[str, Any], event_id: str, source_sha256: str
) -> ContractRecord:
    """Normalize an AWS deployed-contract row."""
    _validate_aws_context(event_id, source_sha256)
    chain_id = parse_rpc_quantity(_require(raw, "chainId"))
    address = normalize_address(_require(raw, "address"))
    block_number = parse_rpc_quantity(_require(raw, "blockNumber"))
    source = _validate_aws_source(raw)
    return ContractRecord(
        record_key=f"{chain_id}:{address}",
        event_id=event_id,
        chain_id=chain_id,
        address=address,
        block_number=block_number,
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_price_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
) -> PriceRecord:
    """Convert a raw price dict (e.g. from CoinGecko) to a :class:`PriceRecord`.

    Expected raw keys:
        - ``token_address`` — ERC-20 contract address
        - ``coingecko_id`` — CoinGecko slug
        - ``source_timestamp`` — Unix seconds (int or float; truncated to int)
        - ``usd_price`` — float or int USD price
        - ``source`` — data provider string (e.g. ``"coingecko"``)
        - ``retrieved_at_utc`` — ISO 8601 UTC string

    Args:
        raw: Raw price dict.
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.

    Returns:
        A frozen :class:`PriceRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")

    token_address = normalize_address(_require(raw, "token_address"))
    coingecko_id = _require(raw, "coingecko_id")
    if not isinstance(coingecko_id, str) or not coingecko_id.strip():
        raise ValueError("coingecko_id must be a non-empty string")

    raw_ts = _require(raw, "source_timestamp")
    if not isinstance(raw_ts, (int, float)):
        raise ValueError(
            f"source_timestamp must be numeric, got {type(raw_ts).__name__!r}"
        )
    source_timestamp = int(raw_ts)

    raw_price = _require(raw, "usd_price")
    if not isinstance(raw_price, (int, float)):
        raise ValueError(
            f"usd_price must be numeric, got {type(raw_price).__name__!r}"
        )
    usd_price = float(raw_price)

    source = _require(raw, "source")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")

    retrieved_at_utc = _require(raw, "retrieved_at_utc")
    if not isinstance(retrieved_at_utc, str) or not retrieved_at_utc.strip():
        raise ValueError("retrieved_at_utc must be a non-empty string")

    hour_utc = _truncate_to_hour_utc(source_timestamp)
    record_key = f"{token_address}:{hour_utc}"

    return PriceRecord(
        record_key=record_key,
        event_id=event_id,
        token_address=token_address,
        coingecko_id=coingecko_id.strip(),
        source_timestamp=source_timestamp,
        hour_utc=hour_utc,
        usd_price=usd_price,
        source=source.strip(),
        retrieved_at_utc=retrieved_at_utc.strip(),
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def normalize_public_info_record(
    raw: dict[str, Any],
    event_id: str,
    source_sha256: str,
) -> PublicInfoRecord:
    """Convert a raw public-information dict to a :class:`PublicInfoRecord`.

    Expected raw keys:
        - ``url`` — original article URL
        - ``canonical_url`` — canonical / cleaned URL
        - ``title`` — article title
        - ``published_at_utc`` — ISO 8601 UTC publication timestamp
        - ``source`` — publisher category: ``"discourse"``, ``"protocol"``,
          or ``"gdelt"``

    Args:
        raw: Raw public information dict.
        event_id: Incident / collection event identifier.
        source_sha256: SHA-256 of the source artifact.

    Returns:
        A frozen :class:`PublicInfoRecord`.

    Raises:
        ValueError: On any missing or malformed field.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")

    url = _require(raw, "url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url must be a non-empty string")

    canonical_url = _require(raw, "canonical_url")
    if not isinstance(canonical_url, str):
        raise ValueError("canonical_url must be a string")

    title = _require(raw, "title")
    if not isinstance(title, str):
        raise ValueError("title must be a string")

    published_at_utc = _require(raw, "published_at_utc")
    if not isinstance(published_at_utc, str) or not published_at_utc.strip():
        raise ValueError("published_at_utc must be a non-empty string")

    source = _require(raw, "source")
    if source not in _VALID_SOURCES_PUBLIC_INFO:
        raise ValueError(
            f"invalid source {source!r}: "
            f"expected one of {sorted(_VALID_SOURCES_PUBLIC_INFO)}"
        )

    record_key = f"{source}:{url}"

    return PublicInfoRecord(
        record_key=record_key,
        event_id=event_id,
        url=url.strip(),
        canonical_url=canonical_url.strip(),
        title=title.strip(),
        published_at_utc=published_at_utc.strip(),
        source=source,
        source_sha256=source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )
