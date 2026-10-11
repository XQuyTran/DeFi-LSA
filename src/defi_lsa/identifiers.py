"""Identifier validation and normalisation utilities (A11).

All public functions raise ``ValueError`` for malformed input.  There are no
silent fallbacks — callers must handle the error explicitly.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_QUANTITY_RE = re.compile(r"^0x[0-9a-fA-F]+$")


# ---------------------------------------------------------------------------
# Ethereum address
# ---------------------------------------------------------------------------


def normalize_address(value: str) -> str:
    """Return a lowercase, 0x-prefixed 40-hex-char Ethereum address.

    Accepts mixed-case input (e.g. EIP-55 checksummed addresses) and strips
    surrounding whitespace before validation.

    Raises:
        ValueError: if *value* is not a valid Ethereum address.
    """
    if not isinstance(value, str):
        raise ValueError(f"address must be a str, got {type(value).__name__!r}")
    normalised = value.strip().lower()
    if not _ADDRESS_RE.fullmatch(normalised):
        raise ValueError(
            f"invalid Ethereum address {value!r}: "
            "expected 0x-prefixed 40 hex characters"
        )
    return normalised


def validate_address(value: str) -> str:
    """Alias for :func:`normalize_address` for explicit validation call sites.

    Raises:
        ValueError: if *value* is not a valid Ethereum address.
    """
    return normalize_address(value)


# ---------------------------------------------------------------------------
# Transaction hash
# ---------------------------------------------------------------------------


def normalize_tx_hash(value: str) -> str:
    """Return a lowercase, 0x-prefixed 64-hex-char transaction hash.

    Accepts mixed-case input and strips surrounding whitespace before
    validation.

    Raises:
        ValueError: if *value* is not a valid transaction hash.
    """
    if not isinstance(value, str):
        raise ValueError(f"tx hash must be a str, got {type(value).__name__!r}")
    normalised = value.strip().lower()
    if not _TX_HASH_RE.fullmatch(normalised):
        raise ValueError(
            f"invalid transaction hash {value!r}: "
            "expected 0x-prefixed 64 hex characters"
        )
    return normalised


def validate_tx_hash(value: str) -> str:
    """Alias for :func:`normalize_tx_hash` for explicit validation call sites.

    Raises:
        ValueError: if *value* is not a valid transaction hash.
    """
    return normalize_tx_hash(value)


# ---------------------------------------------------------------------------
# JSON-RPC quantity
# ---------------------------------------------------------------------------


def parse_rpc_quantity(value: str | int) -> int:
    """Convert a JSON-RPC *quantity* to a Python :class:`int`.

    Accepts:
    - A plain Python ``int`` (returned unchanged).
    - A 0x-prefixed hexadecimal string (e.g. ``"0x1a"``).

    Raises:
        ValueError: for any other type or malformed hex string.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        if not _HEX_QUANTITY_RE.fullmatch(value):
            raise ValueError(
                f"invalid RPC quantity {value!r}: "
                "expected a plain int or 0x-prefixed hex string"
            )
        return int(value, 16)
    raise ValueError(
        f"invalid RPC quantity {value!r}: "
        f"expected str or int, got {type(value).__name__!r}"
    )


# ---------------------------------------------------------------------------
# UTC timestamp
# ---------------------------------------------------------------------------


def normalize_utc_timestamp(value: str | datetime) -> str:
    """Return a UTC ISO 8601 string with a ``Z`` suffix.

    Accepts:
    - A :class:`datetime` that is timezone-aware (any timezone is accepted and
      converted to UTC).
    - An ISO 8601 string with an explicit UTC offset (``Z`` or ``+00:00`` etc.).

    Raises:
        ValueError: for naive :class:`datetime` objects or unparseable strings.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError(
                "naive datetime rejected: supply a timezone-aware datetime "
                "(e.g. datetime(..., tzinfo=timezone.utc))"
            )
        utc_dt = value.astimezone(timezone.utc)
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(value, str):
        # fromisoformat handles the common "Z" suffix only in Python 3.11+.
        # Replace "Z" with "+00:00" for portability.
        normalised_str = value.strip()
        if normalised_str.endswith("Z"):
            normalised_str = normalised_str[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalised_str)
        except ValueError as exc:
            raise ValueError(
                f"unparseable timestamp {value!r}: {exc}"
            ) from exc
        if parsed.tzinfo is None:
            raise ValueError(
                f"naive timestamp string rejected {value!r}: "
                "include an explicit UTC offset (e.g. Z or +00:00)"
            )
        utc_dt = parsed.astimezone(timezone.utc)
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    raise ValueError(
        f"invalid timestamp {value!r}: "
        f"expected str or datetime, got {type(value).__name__!r}"
    )

