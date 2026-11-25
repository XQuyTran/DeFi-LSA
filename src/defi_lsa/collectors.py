"""Contract-scoped D2 raw collectors.

Collectors persist source-shaped JSONL records. They intentionally do not decode,
classify, or transform blockchain activity; downstream D3 owns those operations.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .abi import (
    EtherscanABIClient,
    LocalABIFallback,
    validate_abi_cache,
    _write_abi_metadata,
    _write_abi_file,
    ABIMetadata,
)
from .checkpoints import (
    Checkpoint,
    CheckpointStore,
    compute_scope_hash,
    get_pending_ranges,
    validate_checkpoint_scope,
)
from .errors import PermanentSourceError, SourceError, TransientSourceError
from .identifiers import (
    normalize_address,
    normalize_tx_hash,
    parse_rpc_quantity,
)
from .provenance import SourceRecord, generate_source_manifest
from .registry import ContractScope, sha256_file
from .retry import RateLimiter, RetryPolicy, classify_source_error, execute_with_retry
from .schemas import (
    NORMALIZATION_VERSION,
    LogRecord,
    ReceiptRecord,
    TransactionRecord,
    normalize_log_record,
    normalize_receipt_record,
    normalize_transaction_record,
)
from .storage import (
    append_normalized_records,
    normalized_path,
    read_jsonl_records,
    source_path,
    write_source_artifact,
)

ADAPTER_VERSION = "d2-0.1.0"
JsonRpc = Callable[[str, list[Any]], Any]


@dataclass(frozen=True)
class CollectionResult:
    """Result of a single collection run.

    Attributes:
        artifact_path: Path to the JSONL file that was written.
        records_written: Number of new records appended.
        records_skipped: Number of duplicate records that were skipped.
        source_sha256: Optional SHA-256 hex digest of the source artifact this
            collection was derived from.  ``None`` when not applicable.
        normalization_version: Optional semver string for the normalisation
            logic version.  ``None`` when not applicable.
    """

    artifact_path: Path
    records_written: int
    records_skipped: int
    source_sha256: str | None = None
    normalization_version: str | None = None


def json_rpc_client(
    endpoint: str,
    *,
    timeout: float = 30,
    opener: Callable[..., Any] = urlopen,
) -> JsonRpc:
    """Create a minimal Ethereum JSON-RPC client with explicit error handling."""

    def call(method: str, params: list[Any]) -> Any:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with opener(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code in (400, 413, 422):
                raw_err = ""
                try:
                    raw_err = exc.read().decode("utf-8", errors="replace")
                    err_body = json.loads(raw_err)
                except Exception:
                    err_body = None
                if isinstance(err_body, dict) and err_body.get("error"):
                    raise RuntimeError(f"{method} failed (HTTP {exc.code}): {err_body['error']}") from exc
                if raw_err:
                    raise RuntimeError(f"{method} failed (HTTP {exc.code}): {raw_err}") from exc
            raise
        if body.get("error"):
            raise RuntimeError(f"{method} failed: {body['error']}")
        if "result" not in body:
            raise RuntimeError(f"{method} returned no result")
        return body["result"]

    return call


def _hex_block(number: int) -> str:
    if number < 0:
        raise ValueError("block number must not be negative")
    return hex(number)


def _normalize_hash(value: str) -> str:
    """Normalise a transaction hash via the canonical identifiers module."""
    return normalize_tx_hash(value)


def _read_keys(path: Path) -> set[str]:
    if not path.exists():
        return set()
    keys: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                keys.add(str(json.loads(line)["record_key"]))
    return keys


def _append_records(
    path: Path,
    records: Iterable[Mapping[str, Any]],
) -> tuple[int, int]:
    """Persist JSONL records, skipping duplicates.

    Delegates to :func:`~defi_lsa.storage.append_normalized_records` so all
    crash-safe write logic lives in one place.
    """
    return append_normalized_records(path, records, key_field="record_key")


def fetch_blocks(
    rpc: JsonRpc,
    start_block: int,
    end_block: int,
    output_path: Path,
) -> CollectionResult:
    """Persist block headers and gas usage for an inclusive block range."""
    if end_block < start_block:
        raise ValueError("end_block must be >= start_block")

    def records() -> Iterable[Mapping[str, Any]]:
        for number in range(start_block, end_block + 1):
            block = rpc("eth_getBlockByNumber", [_hex_block(number), False])
            if not block:
                raise RuntimeError(f"Missing block {number}")
            yield {
                "record_key": str(number),
                "block_number": number,
                "timestamp": int(block["timestamp"], 16),
                "gas_used": int(block["gasUsed"], 16),
                "hash": _normalize_hash(block["hash"]),
            }

    written, skipped = _append_records(output_path, records())
    return CollectionResult(output_path, written, skipped)


def fetch_transactions(
    rpc: JsonRpc,
    block_numbers: Iterable[int],
    scope: ContractScope,
    output_path: Path,
) -> CollectionResult:
    """Persist only transactions touching a registry-scoped address."""
    addresses = set(scope.addresses)

    def records() -> Iterable[Mapping[str, Any]]:
        for block_number in block_numbers:
            block = rpc("eth_getBlockByNumber", [_hex_block(block_number), True])
            if not block:
                raise RuntimeError(f"Missing block {block_number}")
            for tx in block.get("transactions", []):
                sender = str(tx.get("from", "")).lower()
                recipient = str(tx.get("to") or "").lower()
                if sender not in addresses and recipient not in addresses:
                    continue
                yield {
                    "record_key": _normalize_hash(tx["hash"]),
                    "chain_id": scope.chain_id,
                    "event_id": scope.event_id,
                    "block_number": block_number,
                    "transaction": tx,
                }

    written, skipped = _append_records(output_path, records())
    return CollectionResult(output_path, written, skipped)


def fetch_receipts(
    rpc: JsonRpc,
    transaction_hashes: Iterable[str],
    scope: ContractScope,
    output_path: Path,
) -> CollectionResult:
    """Persist receipts for scoped transactions, including all receipt logs."""
    def records() -> Iterable[Mapping[str, Any]]:
        for tx_hash in transaction_hashes:
            normalized = _normalize_hash(tx_hash)
            receipt = rpc("eth_getTransactionReceipt", [normalized])
            if not receipt:
                raise RuntimeError(f"Missing receipt {normalized}")
            yield {
                "record_key": normalized,
                "chain_id": scope.chain_id,
                "event_id": scope.event_id,
                "receipt": receipt,
            }

    written, skipped = _append_records(output_path, records())
    return CollectionResult(output_path, written, skipped)


def fetch_logs(
    rpc: JsonRpc,
    start_block: int,
    end_block: int,
    scope: ContractScope,
    output_path: Path,
) -> CollectionResult:
    """Persist logs emitted by scoped contracts, keyed by tx and log index."""
    if end_block < start_block:
        raise ValueError("end_block must be >= start_block")
    params = [
        {
            "fromBlock": _hex_block(start_block),
            "toBlock": _hex_block(end_block),
            "address": list(scope.addresses),
        }
    ]
    logs = rpc("eth_getLogs", params)
    records = (
        {
            "record_key": f"{_normalize_hash(log['transactionHash'])}:{int(log['logIndex'], 16)}",
            "chain_id": scope.chain_id,
            "event_id": scope.event_id,
            "log": log,
        }
        for log in logs
    )
    written, skipped = _append_records(output_path, records)
    return CollectionResult(output_path, written, skipped)


def fetch_abi(
    addresses: Iterable[str],
    api_url: str,
    api_key: str,
    output_dir: Path,
    *,
    chain_id: int = 1,
    raw_source_dir: Path | None = None,
    retry_policy: RetryPolicy | None = None,
    rate_limiter: RateLimiter | None = None,
    resolve_proxies: bool = True,
    local_fallback_dir: Path | None = None,
    opener: Callable[..., Any] | None = None,
    http_get: Callable[[str], bytes] | None = None,
) -> list[Path]:
    """Persist verified ABIs using Etherscan V2 API with proxy resolution and local fallback.

    For each *address*:
    1. Checks the local cache via :func:`~defi_lsa.abi.validate_abi_cache`.
    2. If invalid or absent, fetches from Etherscan V2 (``chainid=<chain_id>``) with
       shared retry, throttle, credential redaction, and immutable raw-response
       persistence.
    3. Optionally resolves proxy implementation addresses and fetches their ABIs.
    4. Falls back to :class:`~defi_lsa.abi.LocalABIFallback` when Etherscan cannot serve.
    5. Records per-address provenance in ``<address>.meta.json`` sidecars.

    The ``http_get`` parameter is accepted for backward compatibility but is
    superseded by ``opener`` when both are provided.

    Args:
        addresses: Iterable of contract addresses.
        api_url: Etherscan V2 base URL (e.g. ``https://api.etherscan.io/v2/api``).
        api_key: Etherscan API key; never logged or written to metadata.
        output_dir: Directory for normalised ``<address>.json`` ABI files.
        chain_id: EVM chain ID (default ``1`` = Ethereum mainnet).
        raw_source_dir: Optional directory for immutable raw Etherscan response files.
        retry_policy: Optional retry configuration.
        rate_limiter: Optional token-bucket rate limiter.
        resolve_proxies: When ``True``, attempt to detect and resolve proxy contracts.
        local_fallback_dir: Optional directory containing pre-downloaded ABI files
            used when Etherscan cannot serve an address.
        opener: Optional HTTP opener callable (replaces ``http_get``).
        http_get: Deprecated HTTP getter; superseded by ``opener``.

    Returns:
        List of :class:`~pathlib.Path` objects for every written ABI file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    effective_raw_dir = raw_source_dir or output_dir / "raw"

    # Resolve opener: prefer explicit opener, then wrap http_get for compat
    effective_opener: Callable[..., Any] | None = opener
    legacy_http_get = effective_opener is None and http_get is not None
    if effective_opener is None and http_get is not None:
        _getter = http_get

        def _compat_opener(req: Any, timeout: float = 30.0) -> Any:
            url_str = req.full_url if hasattr(req, "full_url") else str(req)
            raw = _getter(url_str)

            class _Resp:
                def read(self) -> bytes:
                    return raw

            return _Resp()

        effective_opener = _compat_opener

    client = EtherscanABIClient(
        api_base_url=api_url,
        api_key=api_key,
        chain_id=chain_id,
        retry_policy=retry_policy,
        rate_limiter=rate_limiter,
        opener=effective_opener,
    )
    fallback = LocalABIFallback(local_fallback_dir) if local_fallback_dir else None

    paths: list[Path] = []
    sorted_addresses = sorted(set(a.lower() for a in addresses))

    for address in sorted_addresses:
        abi_path = output_dir / f"{address}.json"
        meta_path = output_dir / f"{address}.meta.json"

        # 1. Validate existing cache
        if abi_path.exists():
            valid, _ = validate_abi_cache(abi_path, meta_path if meta_path.exists() else None)
            if valid:
                paths.append(abi_path)
                continue

        # 2. Fetch from Etherscan V2 when credentials are available
        fetched = False
        if api_key:
            try:
                client.fetch_abi(
                    address,
                    output_dir,
                    effective_raw_dir,
                    resolve_proxy=resolve_proxies and not legacy_http_get,
                )
                paths.append(abi_path)
                fetched = True
            except Exception:
                pass  # Fall through to local fallback

        if fetched:
            continue

        # 3. Local protocol-repository fallback
        if fallback is not None:
            meta = fallback.find_abi(address)
            if meta is not None:
                abi_path.parent.mkdir(parents=True, exist_ok=True)
                normalized_checksum = _write_abi_file(meta.abi, abi_path)
                meta = replace(meta, checksum=normalized_checksum)
                _write_abi_metadata(meta, output_dir)
                paths.append(abi_path)
                continue

        # 4. Address is unresolvable — raise so caller can decide gate status
        raise RuntimeError(
            f"ABI unavailable for {address}: Etherscan failed and no local fallback found"
        )

    return paths


def collect_source_manifest(
    output_path: Path,
    source_artifacts: Iterable[tuple[str, str, Path, str]],
) -> None:
    """Create D2 provenance records for persisted raw artifacts."""
    records = [
        SourceRecord(
            source_name=source,
            request_url=url,
            retrieved_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)),
            response_sha256=sha256_file(path),
            artifact_path=str(path),
            adapter_version=version,
        )
        for source, url, path, version in source_artifacts
        if path.is_file()
    ]
    generate_source_manifest(output_path, records)


def connectivity_audit(
    endpoints: Mapping[str, str],
    *,
    http_get: Callable[[str], bytes] | None = None,
) -> dict[str, str]:
    """Probe configured public endpoints and return explicit status per source."""
    getter = http_get or (lambda url: urlopen(url, timeout=15).read())
    statuses: dict[str, str] = {}
    for source, url in endpoints.items():
        try:
            getter(url)
        except Exception as exc:
            statuses[source] = f"unreachable: {type(exc).__name__}: {exc}"
        else:
            statuses[source] = "reachable"
    return statuses


def fetch_hourly_prices(
    rows: Iterable[Mapping[str, Any]],
    output_path: Path,
) -> CollectionResult:
    """Persist already retrieved hourly price responses without interpolation."""
    required = {"timestamp_utc", "token_id", "price"}

    def records() -> Iterable[Mapping[str, Any]]:
        for row in rows:
            missing = required - set(row)
            if missing:
                raise ValueError(f"Price row missing fields: {sorted(missing)}")
            yield {
                "record_key": f"{row['token_id']}:{row['timestamp_utc']}",
                "timestamp_utc": row["timestamp_utc"],
                "token_id": row["token_id"],
                "price": row["price"],
                "source": row.get("source", ""),
            }

    written, skipped = _append_records(output_path, records())
    return CollectionResult(output_path, written, skipped)


def fetch_public_information(
    rows: Iterable[Mapping[str, Any]],
    output_path: Path,
) -> CollectionResult:
    """Persist registry-filtered forum/news records with canonical identity."""
    required = {"published_at_utc", "url", "title", "source"}

    def records() -> Iterable[Mapping[str, Any]]:
        for row in rows:
            missing = required - set(row)
            if missing:
                raise ValueError(f"Public-information row missing fields: {sorted(missing)}")
            yield {
                "record_key": f"{row['source']}:{row['url']}",
                "published_at_utc": row["published_at_utc"],
                "url": row["url"],
                "title": row["title"],
                "source": row["source"],
                "event_id": row.get("event_id", ""),
            }

    written, skipped = _append_records(output_path, records())
    return CollectionResult(output_path, written, skipped)


# ---------------------------------------------------------------------------
# Scope-aware transaction discovery & collection (A03)
# ---------------------------------------------------------------------------


class DiscoveredTransactions(set):
    """Set of discovered (tx_hash, inclusion_reasons) tuples with mapping conveniences.

    Inherits from :class:`set` so set operations and iteration over ``(tx_hash, reasons)``
    pairs behave naturally, while also providing dictionary-like lookup and conversion.
    """

    def __getitem__(self, tx_hash: str) -> tuple[str, ...]:
        normalized = normalize_tx_hash(tx_hash)
        for h, reasons in self:
            if h == normalized:
                return reasons
        raise KeyError(tx_hash)

    def get(self, tx_hash: str, default: Any = None) -> Any:
        try:
            return self[tx_hash]
        except (KeyError, ValueError):
            return default

    def __contains__(self, key: Any) -> bool:
        if isinstance(key, str):
            try:
                norm = normalize_tx_hash(key)
                return any(h == norm for h, _ in self)
            except ValueError:
                return False
        return super().__contains__(key)

    def keys(self) -> list[str]:
        return [h for h, _ in self]

    def values(self) -> list[tuple[str, ...]]:
        return [reasons for _, reasons in self]

    def items(self) -> list[tuple[str, tuple[str, ...]]]:
        return list(self)

    def to_dict(self) -> dict[str, tuple[str, ...]]:
        return {h: reasons for h, reasons in self}


def discover_scoped_transaction_hashes(
    logs_path: Path | str | None = None,
    registered_tx_hashes: Iterable[str] = (),
    direct_calls: Iterable[str] | Iterable[Mapping[str, Any]] = (),
    *,
    scope: ContractScope | None = None,
    output_path: Path | str | None = None,
) -> DiscoveredTransactions:
    """Discover transaction hashes relevant to an incident scope with inclusion reasons.

    Inclusion reasons:
        - ``"scoped_log"``: Emitted an event log from a contract within scope.
        - ``"registry_anchor"``: Explicit exploit or root-cause transaction from registry.
        - ``"direct_call"``: Directly called a contract within scope.

    Args:
        logs_path: Optional path to normalized logs JSONL file.
        registered_tx_hashes: Iterable of transaction hashes from incident registry.
        direct_calls: Iterable of transaction hashes or raw transaction objects touching scoped contracts.
        output_path: Optional path to write normalized transaction index JSONL.

    Returns:
        :class:`DiscoveredTransactions` set of ``(tx_hash, inclusion_reasons)`` tuples.
    """
    discovered: dict[str, set[str]] = {}

    # 1. From logs
    if logs_path is not None:
        p = Path(logs_path)
        if p.exists():
            for rec in read_jsonl_records(p):
                raw_hash = (
                    rec.get("tx_hash")
                    or rec.get("transactionHash")
                    or (rec.get("log", {}).get("transactionHash") if isinstance(rec.get("log"), dict) else None)
                )
                if raw_hash:
                    h = normalize_tx_hash(raw_hash)
                    discovered.setdefault(h, set()).add("scoped_log")

    # 2. From registered anchors
    for raw_anchor in registered_tx_hashes:
        if raw_anchor:
            h = normalize_tx_hash(raw_anchor)
            discovered.setdefault(h, set()).add("registry_anchor")

    # 3. From direct calls
    for item in direct_calls:
        if isinstance(item, str):
            if item:
                h = normalize_tx_hash(item)
                discovered.setdefault(h, set()).add("direct_call")
        elif isinstance(item, Mapping):
            if scope is not None:
                recipient = item.get("to")
                if recipient is not None:
                    try:
                        if normalize_address(recipient) not in set(scope.addresses):
                            continue
                    except ValueError:
                        continue
            raw_hash = item.get("hash") or item.get("transactionHash") or item.get("tx_hash")
            if raw_hash:
                h = normalize_tx_hash(raw_hash)
                discovered.setdefault(h, set()).add("direct_call")

    result_set = DiscoveredTransactions(
        (h, tuple(sorted(reasons)))
        for h, reasons in sorted(discovered.items())
    )

    if output_path is not None:
        out_p = Path(output_path)
        index_records = [
            {
                "record_key": h,
                "tx_hash": h,
                "inclusion_reasons": list(reasons),
            }
            for h, reasons in sorted(result_set)
        ]
        append_normalized_records(out_p, index_records, key_field="record_key")

    return result_set


def fetch_transactions_by_hash(
    rpc: JsonRpc,
    tx_hashes: Iterable[str] | Iterable[tuple[str, tuple[str, ...]]] | Mapping[str, tuple[str, ...]],
    scope: ContractScope,
    output_path: Path | str,
    *,
    raw_source_dir: Path | str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> CollectionResult:
    """Fetch and normalize full transactions by hash for an incident scope.

    Args:
        rpc: JSON-RPC client callable.
        tx_hashes: Collection of transaction hashes, (hash, reasons) pairs, or hash->reasons mapping.
        scope: Target contract scope.
        output_path: Path to write normalized transaction JSONL.
        raw_source_dir: Optional directory for raw immutable source artifacts.
        retry_policy: Optional retry policy.

    Returns:
        :class:`CollectionResult` with counts of records written and skipped.
    """
    hash_to_reasons: dict[str, tuple[str, ...]] = {}
    if isinstance(tx_hashes, Mapping):
        for k, v in tx_hashes.items():
            h = normalize_tx_hash(k)
            reasons = tuple(v) if isinstance(v, (tuple, list)) else ("direct_call",)
            hash_to_reasons[h] = reasons
    else:
        for item in tx_hashes:
            if isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[1], (tuple, list)):
                h = normalize_tx_hash(item[0])
                hash_to_reasons[h] = tuple(item[1])
            elif isinstance(item, str):
                h = normalize_tx_hash(item)
                hash_to_reasons[h] = ("direct_call",)
            else:
                raise ValueError(f"Invalid transaction hash item: {item!r}")

    out_path = Path(output_path)
    policy = retry_policy or RetryPolicy()
    records_to_append: list[dict[str, Any]] = []
    last_source_sha256: str | None = None

    for tx_h, reasons in sorted(hash_to_reasons.items()):
        def _do_rpc() -> Any:
            return rpc("eth_getTransactionByHash", [tx_h])

        tx_raw = execute_with_retry(_do_rpc, policy=policy)
        if not tx_raw:
            raise RuntimeError(f"Missing transaction {tx_h}")

        raw_tx_dict = dict(tx_raw)
        raw_tx_dict.setdefault("hash", tx_h)
        raw_tx_dict.setdefault("chainId", scope.chain_id)
        raw_tx_dict.setdefault("source", "rpc")

        if raw_source_dir is not None:
            raw_dir = Path(raw_source_dir)
            raw_dir.mkdir(parents=True, exist_ok=True)
            art_file = raw_dir / f"tx_{scope.event_id}_{tx_h}.json"
            content = json.dumps(tx_raw, indent=2, sort_keys=True)
            if art_file.exists():
                source_sha = hashlib.sha256(art_file.read_bytes()).hexdigest()
            else:
                source_sha = write_source_artifact(art_file, content)
        else:
            source_sha = hashlib.sha256(json.dumps(tx_raw, sort_keys=True).encode("utf-8")).hexdigest()

        last_source_sha256 = source_sha

        normalized_rec = normalize_transaction_record(
            raw_tx_dict,
            event_id=scope.event_id,
            source_sha256=source_sha,
            inclusion_reasons=reasons or ("direct_call",),
        )
        records_to_append.append(asdict(normalized_rec))

    written, skipped = append_normalized_records(out_path, records_to_append, key_field="record_key")
    return CollectionResult(
        artifact_path=out_path,
        records_written=written,
        records_skipped=skipped,
        source_sha256=last_source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def fetch_receipts_by_hash(
    rpc: JsonRpc,
    tx_hashes: Iterable[str] | Iterable[tuple[str, tuple[str, ...]]] | Mapping[str, tuple[str, ...]],
    scope: ContractScope,
    output_path: Path | str,
    *,
    raw_source_dir: Path | str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> CollectionResult:
    """Fetch and normalize transaction receipts by hash for an incident scope.

    Args:
        rpc: JSON-RPC client callable.
        tx_hashes: Collection of transaction hashes.
        scope: Target contract scope.
        output_path: Path to write normalized receipt JSONL.
        raw_source_dir: Optional directory for raw immutable source artifacts.
        retry_policy: Optional retry policy.

    Returns:
        :class:`CollectionResult` with counts of records written and skipped.
    """
    hashes: list[str] = []
    if isinstance(tx_hashes, Mapping):
        hashes = [normalize_tx_hash(k) for k in tx_hashes]
    else:
        for item in tx_hashes:
            if isinstance(item, (tuple, list)):
                hashes.append(normalize_tx_hash(item[0]))
            elif isinstance(item, str):
                hashes.append(normalize_tx_hash(item))
            else:
                raise ValueError(f"Invalid transaction hash item: {item!r}")

    out_path = Path(output_path)
    policy = retry_policy or RetryPolicy()
    unique_hashes = sorted(set(hashes))
    records_to_append: list[dict[str, Any]] = []
    last_source_sha256: str | None = None

    for tx_h in unique_hashes:
        def _do_rpc() -> Any:
            return rpc("eth_getTransactionReceipt", [tx_h])

        receipt_raw = execute_with_retry(_do_rpc, policy=policy)
        if not receipt_raw:
            raise RuntimeError(f"Missing receipt {tx_h}")

        raw_rec_dict = dict(receipt_raw)
        raw_rec_dict.setdefault("transactionHash", tx_h)
        raw_rec_dict.setdefault("chainId", scope.chain_id)
        raw_rec_dict.setdefault("source", "rpc")

        if raw_source_dir is not None:
            raw_dir = Path(raw_source_dir)
            raw_dir.mkdir(parents=True, exist_ok=True)
            art_file = raw_dir / f"receipt_{scope.event_id}_{tx_h}.json"
            content = json.dumps(receipt_raw, indent=2, sort_keys=True)
            if art_file.exists():
                source_sha = hashlib.sha256(art_file.read_bytes()).hexdigest()
            else:
                source_sha = write_source_artifact(art_file, content)
        else:
            source_sha = hashlib.sha256(json.dumps(receipt_raw, sort_keys=True).encode("utf-8")).hexdigest()

        last_source_sha256 = source_sha

        normalized_rec = normalize_receipt_record(
            raw_rec_dict,
            event_id=scope.event_id,
            source_sha256=source_sha,
        )
        records_to_append.append(asdict(normalized_rec))

    written, skipped = append_normalized_records(out_path, records_to_append, key_field="record_key")
    return CollectionResult(
        artifact_path=out_path,
        records_written=written,
        records_skipped=skipped,
        source_sha256=last_source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def collect_scoped_transactions(
    rpc: JsonRpc,
    scope: ContractScope,
    output_dir: Path | str | None = None,
    *,
    logs_path: Path | str | None = None,
    registered_tx_hashes: Iterable[str] = (),
    direct_calls: Iterable[str] | Iterable[Mapping[str, Any]] = (),
    transactions_output_path: Path | str | None = None,
    receipts_output_path: Path | str | None = None,
    index_output_path: Path | str | None = None,
    raw_source_dir: Path | str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> tuple[CollectionResult, CollectionResult]:
    """Discover scoped transaction hashes and collect their full transactions and receipts.

    Orchestrates:
    1. Discovery of scoped transaction hashes via :func:`discover_scoped_transaction_hashes`.
    2. Retrieval and normalization of transactions via :func:`fetch_transactions_by_hash`.
    3. Retrieval and normalization of receipts via :func:`fetch_receipts_by_hash`.

    Args:
        rpc: JSON-RPC client callable.
        scope: Target contract scope.
        output_dir: Base directory for output JSONL files (defaults to current dir if paths not set).
        logs_path: Path to normalized logs JSONL file.
        registered_tx_hashes: Explicit exploit/recovery hashes from registry.
        direct_calls: Top-level block transactions touching scoped addresses.
        transactions_output_path: Explicit override destination for transactions JSONL.
        receipts_output_path: Explicit override destination for receipts JSONL.
        index_output_path: Explicit override destination for transaction index JSONL.
        raw_source_dir: Optional directory for raw immutable source artifacts.
        retry_policy: Optional retry policy.

    Returns:
        Tuple of ``(transactions_result, receipts_result)``.
    """
    base = Path(output_dir) if output_dir is not None else Path(".")
    tx_out = Path(transactions_output_path) if transactions_output_path is not None else base / "transactions" / f"{scope.event_id}.jsonl"
    rc_out = Path(receipts_output_path) if receipts_output_path is not None else base / "receipts" / f"{scope.event_id}.jsonl"
    idx_out = Path(index_output_path) if index_output_path is not None else base / "transaction_index" / f"{scope.event_id}.jsonl"

    discovered = discover_scoped_transaction_hashes(
        logs_path=logs_path,
        registered_tx_hashes=registered_tx_hashes,
        direct_calls=direct_calls,
        output_path=idx_out,
    )

    tx_res = fetch_transactions_by_hash(
        rpc,
        discovered,
        scope,
        tx_out,
        raw_source_dir=raw_source_dir,
        retry_policy=retry_policy,
    )

    rc_res = fetch_receipts_by_hash(
        rpc,
        discovered,
        scope,
        rc_out,
        raw_source_dir=raw_source_dir,
        retry_policy=retry_policy,
    )

    return tx_res, rc_res


# ---------------------------------------------------------------------------
# Adaptive chunked log collection (A01)
# ---------------------------------------------------------------------------

_RANGE_OR_TRANSIENT_KEYWORDS = (
    "10000",
    "10,000",
    "more than",
    "block range",
    "too wide",
    "too large",
    "exceed",
    "limit exceeded",
    "response size",
    "payload too large",
    "size exceeded",
    "filter",
    "timeout",
    "timed out",
    "server busy",
    "unavailable",
    "busy",
)


def _is_range_or_transient_error(classified: SourceError, exc: Exception) -> bool:
    """Return True if an error is a block-range limit or transient failure that chunk shrinking might mitigate."""
    if isinstance(classified, TransientSourceError):
        return True
    msg = f"{classified.message} {str(exc)}".lower()
    return any(kw in msg for kw in _RANGE_OR_TRANSIENT_KEYWORDS)


def fetch_logs_chunked(
    rpc: JsonRpc,
    start_block: int,
    end_block: int,
    scope: ContractScope,
    output_path: Path | str,
    checkpoint_store: CheckpointStore | None = None,
    *,
    initial_chunk_size: int = 1000,
    min_chunk_size: int = 10,
    max_chunk_size: int = 10000,
    minimum_chunk_size: int | None = None,
    maximum_chunk_size: int | None = None,
    checkpoint_path: Path | str | None = None,
    retry_policy: RetryPolicy | None = None,
    raw_source_dir: Path | str | None = None,
    report_path: Path | str | None = None,
    retry_failed_ranges: bool = False,
    strict: bool = True,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> CollectionResult:
    """Retrieve contract event logs with adaptive chunk sizing, crash-safe persistence, and checkpoints (A01).

    Loops over pending ranges, dynamically shrinking chunk sizes upon provider range/size limits
    or timeouts, and growing chunk sizes on successful low-volume responses.

    Args:
        rpc: JSON-RPC client callable.
        start_block: Inclusive starting block number.
        end_block: Inclusive ending block number.
        scope: Target contract scope.
        output_path: Destination path for normalized JSONL logs.
        checkpoint_store: Optional CheckpointStore for progress tracking and resumption.
        initial_chunk_size: Initial block range query width.
        min_chunk_size: Lower bound on block range query width.
        max_chunk_size: Upper bound on block range query width.
        retry_policy: RetryPolicy for transient failures.
        raw_source_dir: Optional directory for raw immutable source artifacts.
        report_path: Optional path to persist JSON range report summary.
        retry_failed_ranges: When True, failed checkpoint ranges are retried.
        strict: When True, unrecoverable failures raise; when False, failed ranges are recorded.
        sleep_fn: Sleep function for retry backoff (defaults to time.sleep).

    Returns:
        :class:`CollectionResult` with counts of records written and skipped.
    """
    if minimum_chunk_size is not None:
        min_chunk_size = minimum_chunk_size
    if maximum_chunk_size is not None:
        max_chunk_size = maximum_chunk_size
    if checkpoint_path is not None:
        if checkpoint_store is not None:
            raise ValueError("provide checkpoint_store or checkpoint_path, not both")
        checkpoint_path = Path(checkpoint_path)
        checkpoint_store = CheckpointStore(checkpoint_path.parent.parent.parent)

    start_block = int(start_block)
    end_block = int(end_block)
    if start_block < 0:
        raise ValueError(f"start_block must be >= 0, got {start_block}")
    if end_block < start_block:
        raise ValueError(f"end_block ({end_block}) must be >= start_block ({start_block})")
    if initial_chunk_size < 1:
        raise ValueError(f"initial_chunk_size must be >= 1, got {initial_chunk_size}")
    if min_chunk_size < 1:
        raise ValueError(f"min_chunk_size must be >= 1, got {min_chunk_size}")
    if max_chunk_size < min_chunk_size:
        raise ValueError(
            f"max_chunk_size ({max_chunk_size}) must be >= min_chunk_size ({min_chunk_size})"
        )

    out_path = Path(output_path)
    policy = retry_policy or RetryPolicy()
    scope_hash = compute_scope_hash(scope)
    normalized_addresses = [normalize_address(a) for a in scope.addresses]

    # Checkpoint evaluation
    if checkpoint_store is not None:
        cp = checkpoint_store.load_checkpoint(scope.event_id, "logs")
        if cp is not None:
            if checkpoint_store.validate_checkpoint_scope(cp, scope, start_block, end_block, strict=False):
                pending_ranges = get_pending_ranges(cp, retry_failed=retry_failed_ranges)
            else:
                if strict:
                    checkpoint_store.validate_checkpoint_scope(cp, scope, start_block, end_block, strict=True)
                pending_ranges = [(start_block, end_block)]
        else:
            pending_ranges = [(start_block, end_block)]
    else:
        pending_ranges = [(start_block, end_block)]

    total_written = 0
    total_skipped = 0
    current_chunk_size = min(max(initial_chunk_size, min_chunk_size), max_chunk_size)
    last_source_sha256: str | None = None

    chunks_report: list[dict[str, Any]] = []
    failed_ranges_report: list[dict[str, Any]] = []

    for p_start, p_end in pending_ranges:
        curr = p_start
        failures_at_min = 0

        while curr <= p_end:
            chunk_len = min(current_chunk_size, p_end - curr + 1)
            chunk_end = curr + chunk_len - 1

            query_params: dict[str, Any] = {
                "fromBlock": _hex_block(curr),
                "toBlock": _hex_block(chunk_end),
            }
            if normalized_addresses:
                query_params["address"] = normalized_addresses

            try:
                raw_logs = rpc("eth_getLogs", [query_params])
            except Exception as exc:
                classified = (
                    exc if isinstance(exc, SourceError) else classify_source_error(exc, source="rpc")
                )

                if _is_range_or_transient_error(classified, exc):
                    if current_chunk_size > min_chunk_size:
                        # Shrink chunk
                        current_chunk_size = max(min_chunk_size, current_chunk_size // 2)
                        chunks_report.append({
                            "action": "shrink",
                            "start": curr,
                            "attempted_end": chunk_end,
                            "new_chunk_size": current_chunk_size,
                            "error": str(classified.message),
                        })
                        continue

                    # At min_chunk_size
                    failures_at_min += 1
                    if failures_at_min < policy.max_attempts:
                        delay = policy.compute_delay(failures_at_min)
                        if delay > 0:
                            sleep_fn(delay)
                        continue

                    # Exhausted retries at min_chunk_size
                    if checkpoint_store is not None:
                        checkpoint_store.mark_range_failed(
                            event_id=scope.event_id,
                            collector="logs",
                            start=curr,
                            end=chunk_end,
                            error=classified,
                            retries=failures_at_min,
                            error_type=type(classified).__name__,
                            scope_hash=scope_hash,
                            requested_start=start_block,
                            requested_end=end_block,
                        )
                    failed_ranges_report.append({
                        "start": curr,
                        "end": chunk_end,
                        "error": str(classified.message),
                        "error_type": type(classified).__name__,
                    })

                    if strict:
                        raise classified from exc

                    # Non-strict mode: advance past failing chunk
                    curr = chunk_end + 1
                    failures_at_min = 0
                    continue

                else:
                    # Permanent error not mitigated by chunk shrinking
                    if checkpoint_store is not None:
                        checkpoint_store.mark_range_failed(
                            event_id=scope.event_id,
                            collector="logs",
                            start=curr,
                            end=chunk_end,
                            error=classified,
                            retries=failures_at_min,
                            error_type=type(classified).__name__,
                            scope_hash=scope_hash,
                            requested_start=start_block,
                            requested_end=end_block,
                        )
                    raise classified from exc

            # Successful response
            failures_at_min = 0
            if not isinstance(raw_logs, list):
                raise RuntimeError(f"eth_getLogs expected list of logs, got {type(raw_logs).__name__}")

            # 1. Source artifact persistence
            if raw_source_dir is not None:
                raw_dir = Path(raw_source_dir)
                raw_dir.mkdir(parents=True, exist_ok=True)
                art_file = raw_dir / f"logs_{scope.event_id}_{curr}_{chunk_end}.json"
                content = json.dumps(raw_logs, indent=2, sort_keys=True)
                if art_file.exists():
                    source_sha = hashlib.sha256(art_file.read_bytes()).hexdigest()
                else:
                    source_sha = write_source_artifact(art_file, content)
            else:
                source_sha = hashlib.sha256(json.dumps(raw_logs, sort_keys=True).encode("utf-8")).hexdigest()

            last_source_sha256 = source_sha

            # 2. Record normalization
            records_to_append = []
            for item in raw_logs:
                raw_log_dict = dict(item)
                raw_log_dict.setdefault("chainId", scope.chain_id)
                raw_log_dict.setdefault("source", "rpc")
                raw_log_dict.setdefault("blockNumber", hex(curr))
                raw_log_dict.setdefault("address", normalized_addresses[0] if normalized_addresses else "0x" + "0" * 40)
                raw_log_dict.setdefault("data", "0x")
                raw_log_dict.setdefault("topics", [])

                rec = normalize_log_record(raw_log_dict, event_id=scope.event_id, source_sha256=source_sha)
                records_to_append.append(asdict(rec))

            written, skipped = append_normalized_records(out_path, records_to_append, key_field="record_key")
            total_written += written
            total_skipped += skipped

            # 3. Checkpoint update
            if checkpoint_store is not None:
                checkpoint_store.mark_range_completed(
                    event_id=scope.event_id,
                    collector="logs",
                    start=curr,
                    end=chunk_end,
                    scope_hash=scope_hash,
                    requested_start=start_block,
                    requested_end=end_block,
                )

            chunks_report.append({
                "action": "fetch",
                "start": curr,
                "end": chunk_end,
                "log_count": len(raw_logs),
                "written": written,
                "skipped": skipped,
            })

            # 4. Adaptive growth
            if len(raw_logs) < 1000 and current_chunk_size < max_chunk_size:
                current_chunk_size = min(max_chunk_size, max(current_chunk_size + 1, int(current_chunk_size * 1.5)))

            curr = chunk_end + 1

    if report_path is not None:
        r_path = Path(report_path)
        r_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "event_id": scope.event_id,
            "collector": "logs",
            "requested_start": start_block,
            "requested_end": end_block,
            "total_written": total_written,
            "total_skipped": total_skipped,
            "failed_ranges": failed_ranges_report,
            "chunks": chunks_report,
        }
        r_path.write_text(json.dumps(report_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if checkpoint_store is not None and strict:
        final_checkpoint = checkpoint_store.load_checkpoint(scope.event_id, "logs")
        if final_checkpoint is not None and final_checkpoint.failed_ranges:
            raise RuntimeError("log collection incomplete: failed ranges remain in checkpoint")

    return CollectionResult(
        artifact_path=out_path,
        records_written=total_written,
        records_skipped=total_skipped,
        source_sha256=last_source_sha256,
        normalization_version=NORMALIZATION_VERSION,
    )


def generate_log_range_report(
    scope: ContractScope,
    start_block: int,
    end_block: int,
    checkpoint: Checkpoint | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Generate a structured summary report for log collection coverage.

    Args:
        scope: Target contract scope.
        start_block: Starting block of requested window.
        end_block: Ending block of requested window.
        checkpoint: Optional Checkpoint instance to summarize.
        output_path: Optional destination to write JSON report.

    Returns:
        Structured report dictionary.
    """
    completed = checkpoint.completed_ranges if checkpoint else []
    failed = checkpoint.failed_ranges if checkpoint else []
    pending = get_pending_ranges(checkpoint) if checkpoint else [(start_block, end_block)]

    report = {
        "event_id": scope.event_id,
        "collector": "logs",
        "requested_start": start_block,
        "requested_end": end_block,
        "completed_ranges": [[s, e] for s, e in completed],
        "failed_ranges": failed,
        "pending_ranges": [[s, e] for s, e in pending],
        "is_complete": len(pending) == 0 and len(failed) == 0,
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return report
