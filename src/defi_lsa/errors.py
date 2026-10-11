"""Shared error taxonomy for external data source requests (A04).

Defines base and specialised exceptions distinguishing transient (retryable)
from permanent (fatal) errors across JSON-RPC, REST, scraper, and archive sources.
"""

from __future__ import annotations

from typing import Any


class SourceError(Exception):
    """Base error for all data source request failures.

    Attributes:
        message: Human-readable error description (with secrets redacted).
        source: Identifier of the source that produced the error
            (e.g., ``"rpc"``, ``"etherscan"``, ``"coingecko"``).
        details: Additional structured context (status code, RPC payload, etc.).
    """

    def __init__(
        self,
        message: str = "",
        source: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = str(message) if message else ""
        self.source = str(source) if source else ""
        self.details = dict(details) if details is not None else {}
        prefix = f"[{self.source}] " if self.source else ""
        super().__init__(f"{prefix}{self.message}" if self.message else prefix.rstrip())

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"source={self.source!r}, "
            f"details={self.details!r})"
        )


class TransientSourceError(SourceError):
    """Temporary error that may succeed on retry.

    Covers network timeouts, transient 5xx server errors, connection resets,
    and temporary provider unavailability.
    """


class RateLimitError(TransientSourceError):
    """Rate limit exceeded (e.g. HTTP 429 or provider quota limit).

    Attributes:
        retry_after: Recommended backoff duration in seconds, if supplied
            by the upstream provider.
    """

    def __init__(
        self,
        message: str = "",
        source: str = "",
        details: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message=message, source=source, details=details)
        self.retry_after = float(retry_after) if retry_after is not None else None

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"source={self.source!r}, "
            f"details={self.details!r}, "
            f"retry_after={self.retry_after!r})"
        )


class IncompleteResponseError(TransientSourceError):
    """Response truncated, incomplete payload, or unexpected EOF."""


class PermanentSourceError(SourceError):
    """Unrecoverable error that should not be retried automatically."""


class AuthenticationError(PermanentSourceError):
    """Authentication or authorization failure (e.g. HTTP 401, 403, invalid API key)."""


class InvalidRequestError(PermanentSourceError):
    """Malformed request, invalid parameters, or client error (e.g. HTTP 400, 404, 422)."""


__all__ = [
    "AuthenticationError",
    "IncompleteResponseError",
    "InvalidRequestError",
    "PermanentSourceError",
    "RateLimitError",
    "SourceError",
    "TransientSourceError",
]

