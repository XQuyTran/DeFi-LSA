"""ABI acquisition, proxy resolution, cache validation, and local fallback (E5).

All Etherscan requests use V2 API with ``chainid=1``, shared retry and throttle
policies from :mod:`defi_lsa.retry`, immutable raw-response persistence, and
credential redaction so no API key appears in logs, errors, or manifests.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .errors import AuthenticationError, PermanentSourceError
from .retry import (
    RateLimiter,
    RetryPolicy,
    classify_source_error,
    execute_with_retry,
    redact_credentials,
)
from .storage import write_source_artifact

ETHERSCAN_ADAPTER_VERSION = "e5-0.1.0"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ABIMetadata:
    """Resolved ABI with provenance and proxy information.

    Attributes:
        address: Lowercased Ethereum address this ABI belongs to.
        abi: Parsed ABI array (list of function/event descriptors).
        source: Where the ABI came from: ``"etherscan"``, ``"local_cache"``,
            or ``"protocol_repository"``.
        raw_artifact_path: Absolute path to the immutable raw Etherscan response.
        source_url: Redacted request URL used to obtain the ABI.
        checksum: SHA-256 hex digest of the normalised ABI JSON file on disk.
        is_proxy: True if Etherscan identified the contract as a proxy.
        implementation_address: Implementation address resolved for proxy contracts.
        implementation_checksum: SHA-256 of the implementation ABI file.
        retrieved_at_utc: ISO-8601 UTC timestamp of the retrieval.
        coverage_status: One of ``"verified"``, ``"fallback"``, or ``"missing"``.
    """

    address: str
    abi: list[dict[str, Any]]
    source: str
    raw_artifact_path: str
    source_url: str
    checksum: str
    is_proxy: bool = False
    implementation_address: str = ""
    implementation_checksum: str = ""
    retrieved_at_utc: str = ""
    coverage_status: str = "verified"

    def to_meta_dict(self) -> dict[str, Any]:
        """Serialisable dictionary for the ``.meta.json`` sidecar file."""
        return {
            "address": self.address,
            "source": self.source,
            "raw_artifact_path": self.raw_artifact_path,
            "source_url": self.source_url,
            "checksum": self.checksum,
            "is_proxy": self.is_proxy,
            "implementation_address": self.implementation_address,
            "implementation_checksum": self.implementation_checksum,
            "retrieved_at_utc": self.retrieved_at_utc,
            "coverage_status": self.coverage_status,
            "adapter_version": ETHERSCAN_ADAPTER_VERSION,
        }


# ---------------------------------------------------------------------------
# URL construction
# ---------------------------------------------------------------------------


def build_etherscan_v2_url(
    base_url: str,
    module: str,
    action: str,
    address: str,
    api_key: str,
    *,
    chain_id: int = 1,
    extra: dict[str, str] | None = None,
) -> str:
    """Construct an Etherscan V2 API URL with the mandatory ``chainid`` parameter.

    Args:
        base_url: Etherscan V2 base URL, e.g. ``https://api.etherscan.io/v2/api``.
        module: Etherscan module, e.g. ``"contract"``.
        action: Etherscan action, e.g. ``"getabi"``.
        address: Ethereum address (checksummed or lowercase).
        api_key: Etherscan API key; included in the URL but **must be redacted
            before logging**.
        chain_id: EVM chain ID; defaults to ``1`` (Ethereum mainnet).
        extra: Optional additional query parameters.

    Returns:
        Fully-formed URL string.
    """
    params: dict[str, str] = {
        "chainid": str(chain_id),
        "module": module,
        "action": action,
        "address": address,
        "apikey": api_key,
    }
    if extra:
        params.update(extra)
    return f"{base_url.rstrip('/')}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _default_opener(url: str, timeout: float) -> bytes:
    req = Request(url, headers={"User-Agent": "defi-lsa/" + ETHERSCAN_ADAPTER_VERSION})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_raw_etherscan_response(
    url: str,
    *,
    timeout: float = 30.0,
    opener: Callable[..., Any] | None = None,
) -> tuple[bytes, str]:
    """Fetch a raw Etherscan response and return ``(raw_bytes, redacted_url)``.

    Args:
        url: Full Etherscan API URL (may contain API key).
        timeout: HTTP request timeout in seconds.
        opener: Optional custom HTTP opener (used for testing / Kaggle proxies).

    Returns:
        A ``(raw_bytes, redacted_url)`` tuple where *redacted_url* has the
        ``apikey`` query parameter replaced with ``[REDACTED]``.

    Raises:
        AuthenticationError: If Etherscan reports an authentication failure.
        PermanentSourceError: On any other unrecoverable error.
    """
    redacted = redact_credentials(url)
    try:
        if opener is not None:
            # Support both (url, timeout) and (Request, timeout) opener shapes
            req = Request(url, headers={"User-Agent": "defi-lsa/" + ETHERSCAN_ADAPTER_VERSION})
            resp_obj = opener(req, timeout=timeout)
            raw = resp_obj.read() if hasattr(resp_obj, "read") else resp_obj
        else:
            raw = _default_opener(url, timeout)
    except Exception as exc:
        classified = classify_source_error(exc, source="etherscan")
        classified.message = redact_credentials(classified.message)
        raise classified from exc

    # Parse Etherscan envelope
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise PermanentSourceError(
            message=f"Etherscan returned non-JSON response for {redacted}",
            source="etherscan",
        ) from exc

    if isinstance(body, dict) and body.get("status") == "0":
        result_msg = str(body.get("result", "") or body.get("message", "")).lower()
        if any(kw in result_msg for kw in ("invalid api key", "api key", "unauthorized", "max rate")):
            raise AuthenticationError(
                message=f"Etherscan authentication error for {redacted}: {redact_credentials(result_msg)}",
                source="etherscan",
            )
        raise PermanentSourceError(
            message=f"Etherscan error for {redacted}: {redact_credentials(result_msg)}",
            source="etherscan",
        )

    return raw, redacted


# ---------------------------------------------------------------------------
# File persistence helpers
# ---------------------------------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _persist_raw_response(
    raw: bytes,
    raw_source_dir: Path,
    filename: str,
) -> Path:
    """Write an immutable raw Etherscan response; skips write if already present.

    Args:
        raw: Raw response bytes.
        raw_source_dir: Directory in which to write the artifact.
        filename: Target file name (e.g. ``<address>_abi.json``).

    Returns:
        Path to the persisted artifact.
    """
    raw_source_dir.mkdir(parents=True, exist_ok=True)
    art_path = raw_source_dir / filename
    if art_path.exists():
        return art_path
    write_source_artifact(art_path, raw.decode("utf-8", errors="replace"))
    return art_path


def _write_abi_file(abi: list[dict[str, Any]], abi_path: Path) -> str:
    """Write normalised ABI JSON and return its SHA-256 checksum."""
    abi_path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(abi, indent=2, sort_keys=True) + "\n"
    abi_path.write_text(content, encoding="utf-8")
    return _sha256_bytes(content.encode("utf-8"))


def _write_abi_metadata(metadata: ABIMetadata, abi_dir: Path) -> None:
    """Write the ``.meta.json`` sidecar alongside the ABI file."""
    abi_path = abi_dir / f"{metadata.address}.json"
    if abi_path.exists():
        metadata.checksum = _sha256_file(abi_path)
    meta_path = abi_dir / f"{metadata.address}.meta.json"
    meta_path.write_text(
        json.dumps(metadata.to_meta_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# ABI cache validation
# ---------------------------------------------------------------------------


def validate_abi_cache(
    abi_path: Path,
    metadata_path: Path | None = None,
) -> tuple[bool, str]:
    """Validate a cached ABI file against its stored checksum.

    Args:
        abi_path: Path to the ``<address>.json`` ABI file.
        metadata_path: Optional path to the ``<address>.meta.json`` sidecar.
            When ``None``, the sidecar is inferred from *abi_path*.

    Returns:
        ``(valid, reason)`` — ``valid`` is ``True`` when the file is present
        and its checksum matches the stored value; ``reason`` explains any
        failure.
    """
    if not abi_path.exists():
        return False, f"ABI file missing: {abi_path}"

    meta_path = metadata_path or abi_path.with_suffix("").with_suffix(".meta.json")
    # Handle <address>.json → <address>.meta.json
    if metadata_path is None:
        stem = abi_path.stem  # e.g. "0xdeadbeef..."
        meta_path = abi_path.parent / f"{stem}.meta.json"

    if not meta_path.exists():
        return False, f"ABI metadata sidecar missing: {meta_path}"

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return False, f"ABI metadata sidecar is not valid JSON: {meta_path}"

    stored_checksum = meta.get("checksum", "")
    if not stored_checksum:
        return False, "ABI metadata missing checksum"

    actual_checksum = _sha256_file(abi_path)
    if actual_checksum != stored_checksum:
        return False, (
            f"ABI checksum mismatch for {abi_path.name}: "
            f"stored={stored_checksum[:12]}… actual={actual_checksum[:12]}…"
        )

    # Ensure file is valid JSON
    try:
        json.loads(abi_path.read_text(encoding="utf-8"))
    except Exception:
        return False, f"ABI file is not valid JSON: {abi_path}"

    return True, "ok"


# ---------------------------------------------------------------------------
# Proxy resolution
# ---------------------------------------------------------------------------


def resolve_proxy_implementation(
    address: str,
    api_base_url: str,
    api_key: str,
    chain_id: int = 1,
    *,
    retry_policy: RetryPolicy | None = None,
    rate_limiter: RateLimiter | None = None,
    opener: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> str | None:
    """Resolve a proxy contract's implementation address via ``getsourcecode``.

    Checks the ``Implementation`` field in the Etherscan ``getsourcecode``
    response, which is populated for EIP-1967 and transparent-proxy patterns.

    Args:
        address: Proxy contract address.
        api_base_url: Etherscan V2 base URL.
        api_key: Etherscan API key.
        chain_id: EVM chain ID.
        retry_policy: Optional retry configuration.
        rate_limiter: Optional token-bucket rate limiter.
        opener: Optional HTTP opener (used for testing).
        timeout: HTTP request timeout.

    Returns:
        Lowercase implementation address string, or ``None`` if not a proxy.
    """
    policy = retry_policy or RetryPolicy()
    url = build_etherscan_v2_url(
        api_base_url, "contract", "getsourcecode", address, api_key, chain_id=chain_id
    )

    def _do_fetch() -> bytes:
        if rate_limiter is not None:
            rate_limiter.acquire()
        raw, _ = fetch_raw_etherscan_response(url, timeout=timeout, opener=opener)
        return raw

    try:
        raw = execute_with_retry(_do_fetch, policy=policy)
    except Exception:
        return None

    try:
        body = json.loads(raw.decode("utf-8"))
        results = body.get("result", [])
        if isinstance(results, list) and results:
            impl = str(results[0].get("Implementation", "")).strip()
            if impl and impl not in ("", "0x0000000000000000000000000000000000000000"):
                return impl.lower()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Etherscan ABI client
# ---------------------------------------------------------------------------


class EtherscanABIClient:
    """Fetches, validates, and caches ABIs from the Etherscan V2 API.

    Each call to :meth:`fetch_abi` persists:
    - An immutable raw Etherscan response JSON under *raw_source_dir*.
    - A normalised ``<address>.json`` ABI file under *abi_dir*.
    - A ``<address>.meta.json`` sidecar with checksum, source URL, and
      proxy information.

    All request URLs are redacted before appearing in logs or exceptions.
    """

    def __init__(
        self,
        api_base_url: str,
        api_key: str,
        chain_id: int = 1,
        *,
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimiter | None = None,
        opener: Callable[..., Any] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = api_base_url.rstrip("/")
        self._api_key = api_key
        self._chain_id = chain_id
        self._policy = retry_policy or RetryPolicy()
        self._limiter = rate_limiter
        self._opener = opener
        self._timeout = timeout

    def _throttle(self) -> None:
        if self._limiter is not None:
            self._limiter.acquire()

    def fetch_abi(
        self,
        address: str,
        abi_dir: Path,
        raw_source_dir: Path,
        *,
        resolve_proxy: bool = True,
    ) -> ABIMetadata:
        """Fetch, persist, and return ABI metadata for *address*.

        Args:
            address: Contract address (case-insensitive).
            abi_dir: Directory for normalised ``<address>.json`` ABI files.
            raw_source_dir: Directory for immutable raw Etherscan response files.
            resolve_proxy: When ``True``, attempt to resolve implementation ABIs
                for proxy contracts.

        Returns:
            :class:`ABIMetadata` with full provenance.

        Raises:
            AuthenticationError: On Etherscan authentication failure.
            PermanentSourceError: On any unrecoverable Etherscan error.
        """
        addr = address.lower()
        abi_dir.mkdir(parents=True, exist_ok=True)
        raw_source_dir.mkdir(parents=True, exist_ok=True)
        retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        url = build_etherscan_v2_url(
            self._base_url, "contract", "getabi", addr, self._api_key,
            chain_id=self._chain_id,
        )
        redacted_url = redact_credentials(url)

        def _do_fetch() -> bytes:
            self._throttle()
            raw, _ = fetch_raw_etherscan_response(
                url, timeout=self._timeout, opener=self._opener
            )
            return raw

        raw = execute_with_retry(_do_fetch, policy=self._policy)

        # Persist immutable raw response
        raw_artifact = _persist_raw_response(
            raw, raw_source_dir, f"{addr}_abi.json"
        )

        # Parse ABI from response
        body = json.loads(raw.decode("utf-8"))
        abi_json_str = body.get("result", "[]")
        try:
            abi: list[dict[str, Any]] = json.loads(abi_json_str)
            if not isinstance(abi, list):
                raise ValueError("ABI result is not a JSON array")
        except Exception as exc:
            raise PermanentSourceError(
                message=f"Invalid ABI from Etherscan for {addr}: {redact_credentials(str(exc))}",
                source="etherscan",
            ) from exc

        # Write normalised ABI file
        abi_path = abi_dir / f"{addr}.json"
        checksum = _write_abi_file(abi, abi_path)

        # Proxy resolution
        is_proxy = False
        impl_address = ""
        impl_checksum = ""

        if resolve_proxy:
            impl = resolve_proxy_implementation(
                addr,
                self._base_url,
                self._api_key,
                self._chain_id,
                retry_policy=self._policy,
                rate_limiter=self._limiter,
                opener=self._opener,
                timeout=self._timeout,
            )
            if impl:
                is_proxy = True
                impl_address = impl
                # Fetch implementation ABI if not already cached
                impl_abi_path = abi_dir / f"{impl}.json"
                if not impl_abi_path.exists():
                    try:
                        impl_meta = self.fetch_abi(impl, abi_dir, raw_source_dir, resolve_proxy=False)
                        impl_checksum = impl_meta.checksum
                    except Exception:
                        impl_checksum = ""
                else:
                    impl_checksum = _sha256_file(impl_abi_path)

        coverage_status = "fallback" if is_proxy and not impl_checksum else "verified"
        meta = ABIMetadata(
            address=addr,
            abi=abi,
            source="etherscan",
            raw_artifact_path=str(raw_artifact),
            source_url=redacted_url,
            checksum=checksum,
            is_proxy=is_proxy,
            implementation_address=impl_address,
            implementation_checksum=impl_checksum,
            retrieved_at_utc=retrieved_at,
            coverage_status=coverage_status,
        )
        _write_abi_metadata(meta, abi_dir)
        return meta


# ---------------------------------------------------------------------------
# Local protocol-repository ABI fallback
# ---------------------------------------------------------------------------


class LocalABIFallback:
    """Reads pre-downloaded ABIs from a local protocol-repository directory.

    Expected layout::

        <repo_dir>/
            <address>.json          # ABI array
            <address>.meta.json     # Optional provenance sidecar

    When a sidecar is absent, a minimal one is synthesised with
    ``source="protocol_repository"`` and ``coverage_status="fallback"``.

    Args:
        repo_dir: Root directory containing local ABI files.
    """

    def __init__(self, repo_dir: Path) -> None:
        self._dir = repo_dir

    def find_abi(self, address: str) -> ABIMetadata | None:
        """Find an ABI by address; returns ``None`` if not found.

        Args:
            address: Contract address (case-insensitive).

        Returns:
            :class:`ABIMetadata` with ``source="protocol_repository"`` and
            ``coverage_status="fallback"``, or ``None`` if absent.
        """
        if not self._dir.exists():
            return None
        addr = address.lower()
        abi_path = self._dir / f"{addr}.json"
        if not abi_path.exists():
            return None
        try:
            abi: list[dict[str, Any]] = json.loads(abi_path.read_text(encoding="utf-8"))
            if not isinstance(abi, list):
                return None
        except Exception:
            return None

        checksum = _sha256_file(abi_path)
        meta_path = self._dir / f"{addr}.meta.json"
        source_url = ""
        retrieved_at = ""
        if meta_path.exists():
            try:
                meta_raw = json.loads(meta_path.read_text(encoding="utf-8"))
                source_url = meta_raw.get("source_url", "")
                retrieved_at = meta_raw.get("retrieved_at_utc", "")
            except Exception:
                pass
        if not source_url:
            source_url = f"local://protocol_repository/{addr}.json"

        return ABIMetadata(
            address=addr,
            abi=abi,
            source="protocol_repository",
            raw_artifact_path=str(abi_path),
            source_url=source_url,
            checksum=checksum,
            retrieved_at_utc=retrieved_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            coverage_status="fallback",
        )


# ---------------------------------------------------------------------------
# ABI coverage reporting
# ---------------------------------------------------------------------------


def compute_abi_coverage_report(
    addresses: Iterable[str],
    abi_dir: Path,
    *,
    event_id: str = "",
) -> dict[str, Any]:
    """Compute an ABI coverage report from persisted ``<address>.meta.json`` files.

    Args:
        addresses: All contract addresses that must have ABIs.
        abi_dir: Directory containing ``<address>.json`` and ``<address>.meta.json`` files.
        event_id: Optional event identifier for the report.

    Returns:
        Structured report dictionary with ``status``, ``abi_coverage_percentage``,
        per-address detail, and proxy information.
    """
    address_list = [a.lower() for a in addresses]
    verified = []
    fallback = []
    missing = []
    proxy_addresses = []

    for addr in address_list:
        meta_path = abi_dir / f"{addr}.meta.json"
        abi_path = abi_dir / f"{addr}.json"

        if not abi_path.exists():
            missing.append(addr)
            continue

        cache_valid, _ = validate_abi_cache(abi_path, meta_path if meta_path.exists() else None)
        if not cache_valid:
            missing.append(addr)
            continue

        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                status = meta.get("coverage_status", "verified")
                incomplete_proxy = bool(meta.get("is_proxy")) and not meta.get(
                    "implementation_checksum"
                )
                if status == "fallback" or incomplete_proxy:
                    fallback.append(addr)
                else:
                    verified.append(addr)
                if meta.get("is_proxy"):
                    proxy_addresses.append(addr)
                continue
            except Exception:
                pass

        # No meta sidecar — treat as verified if JSON is valid
        try:
            json.loads(abi_path.read_text(encoding="utf-8"))
            verified.append(addr)
        except Exception:
            missing.append(addr)

    total = len(address_list)
    covered = len(verified) + len(fallback)
    pct = (covered / total * 100.0) if total > 0 else 100.0

    if missing:
        overall_status = "NO_GO"
    elif fallback:
        overall_status = "CONDITIONAL_GO"
    else:
        overall_status = "GO"

    return {
        "event_id": event_id,
        "total_addresses": total,
        "verified_count": len(verified),
        "fallback_count": len(fallback),
        "missing_count": len(missing),
        "abi_coverage_percentage": round(pct, 2),
        "proxy_addresses": proxy_addresses,
        "verified_addresses": verified,
        "fallback_addresses": fallback,
        "missing_addresses": missing,
        "status": overall_status,
        "adapter_version": ETHERSCAN_ADAPTER_VERSION,
    }

