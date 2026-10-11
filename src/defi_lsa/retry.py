"""Request retry policies, credential redaction, and error classification (A04).

Provides resilient HTTP/JSON-RPC execution with bounded exponential backoff,
jitter, upstream Retry-After adherence, token-bucket rate limiting, and leak-free
credential redaction.
"""

from __future__ import annotations

import functools
import json
import random
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, TypeVar

from .errors import (
    AuthenticationError,
    IncompleteResponseError,
    InvalidRequestError,
    PermanentSourceError,
    RateLimitError,
    SourceError,
    TransientSourceError,
)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Credential redaction patterns
# ---------------------------------------------------------------------------

_REDACTED = "[REDACTED]"

# Matches query params or key=value pairs like ?apikey=..., &key=..., apikey=...
_PARAM_RE = re.compile(
    r"(?i)([\?&;]|\b)(api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|secret[_-]?key|secret|password|pwd)=((?!\[REDACTED\])[^&\s\"'#;]+)"
)

# Matches JSON key-value patterns: "apikey": "..." or 'token': '...'
_JSON_KV_RE = re.compile(
    r"""(?i)(["'](?:api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|secret[_-]?key|secret|password|pwd|x-api-key)["']\s*:\s*["'])((?!\[REDACTED\])[^"'\r\n]+)(["'])"""
)

# Matches Bearer or Basic authorization headers
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(bearer|basic)\s+((?!\[REDACTED\])[a-zA-Z0-9_\-\.~+/]+=*)"
)

# Matches known provider RPC endpoints with secret tokens in path
_PROVIDER_PATH_RE = re.compile(
    r"(https?://(?:[a-zA-Z0-9_\-\.]*infura\.io/v3/|[a-zA-Z0-9_\-\.]*alchemy\.com/v2/))((?!\[REDACTED\])[a-zA-Z0-9_\-]+)"
)

# Matches basic auth embedded in URLs: https://user:pass@host
_URL_BASIC_AUTH_RE = re.compile(r"(https?://[^:]+:)([^@\s/]+)(@)")


def redact_credentials(text: str, secrets: Iterable[str] = ()) -> str:
    """Redact API keys, secret tokens, and credentials from text.

    Redacts query parameters matching ``apikey=...``, ``key=...``, ``token=...``,
    authorization headers, known provider paths, and exact matches of provided *secrets*.

    Args:
        text: String to sanitize (URL, log line, exception message, etc.).
        secrets: Optional iterable of sensitive strings to redact unconditionally.

    Returns:
        Sanitized string with sensitive tokens replaced by ``[REDACTED]``.
    """
    if not isinstance(text, str):
        text = str(text)

    # 1. Exact string matches from user-provided secrets (longest first)
    for secret in sorted((s for s in secrets if s and s != _REDACTED), key=len, reverse=True):
        text = text.replace(secret, _REDACTED)

    # 2. URL embedded basic auth
    text = _URL_BASIC_AUTH_RE.sub(r"\g<1>[REDACTED]\g<3>", text)

    # 3. Known provider URL paths (Infura / Alchemy project IDs)
    text = _PROVIDER_PATH_RE.sub(r"\g<1>[REDACTED]", text)

    # 4. URL query parameters and standalone key=value parameters
    text = _PARAM_RE.sub(r"\g<1>\g<2>=[REDACTED]", text)

    # 5. JSON key-value pairs
    text = _JSON_KV_RE.sub(r"\g<1>[REDACTED]\g<3>", text)

    # 6. Authorization headers (Bearer / Basic)
    text = _AUTH_HEADER_RE.sub(r"\g<1> [REDACTED]", text)

    return text


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

_RATE_LIMIT_KEYWORDS = (
    "rate limit",
    "too many requests",
    "request rate exceeded",
    "daily request count exceeded",
    "compute units per second",
    "cu limit",
    "throttled",
    "max rate limit reached",
)

_AUTH_KEYWORDS = (
    "unauthorized",
    "forbidden",
    "invalid api key",
    "invalid project id",
    "api key required",
    "access denied",
)

_INVALID_REQUEST_KEYWORDS = (
    "invalid params",
    "parse error",
    "method not found",
    "invalid request",
    "invalid argument",
    "execution reverted",
)

_TRANSIENT_KEYWORDS = (
    "internal error",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "service unavailable",
    "gateway timeout",
    "bad gateway",
    "connection reset",
    "connection refused",
    "failed to respond",
)

_INCOMPLETE_KEYWORDS = (
    "incomplete response",
    "unexpected eof",
    "response truncated",
    "incomplete read",
    "chunked stream ended prematurely",
)


def _extract_retry_after(
    headers: Mapping[str, str] | None,
    response_body: str | None,
) -> float | None:
    """Extract Retry-After duration in seconds from headers or response body."""
    if headers:
        for k, v in headers.items():
            if k.lower() == "retry-after":
                try:
                    return max(0.0, float(v))
                except (ValueError, TypeError):
                    pass

    if response_body:
        try:
            parsed = json.loads(response_body)
            if isinstance(parsed, dict):
                candidates = [
                    parsed.get("retry_after"),
                    parsed.get("retryAfter"),
                    parsed.get("retry_in"),
                ]
                if isinstance(parsed.get("error"), dict):
                    candidates.append(parsed["error"].get("retry_after"))
                    candidates.append(parsed["error"].get("retryAfter"))
                for c in candidates:
                    if c is not None:
                        try:
                            return max(0.0, float(c))
                        except (ValueError, TypeError):
                            pass
        except Exception:
            pass

        # Regex search in body text
        match = re.search(r"(?i)retry[-_ ]after[:\s]+(\d+(?:\.\d+)?)", response_body)
        if match:
            try:
                return max(0.0, float(match.group(1)))
            except (ValueError, TypeError):
                pass

    return None


def classify_source_error(
    exc: Exception | None = None,
    *,
    status_code: int | None = None,
    response_body: str | None = None,
    source: str = "",
    headers: Mapping[str, str] | None = None,
) -> SourceError:
    """Classify an exception, HTTP status code, or response body into SourceError.

    Distinguishes transient (retryable) from permanent (fatal) failures,
    handling HTTP status codes, standard JSON-RPC 2.0 error codes, and common
    provider-specific error bodies.

    Args:
        exc: Optional underlying exception that occurred.
        status_code: Optional HTTP status code.
        response_body: Optional response payload text.
        source: Optional identifier of the source service.
        headers: Optional response HTTP headers.

    Returns:
        An instance of an appropriate :class:`SourceError` subclass with
        sanitized message and structured details.
    """
    # Inherit status code / response body from exception if not explicitly passed
    if status_code is None and exc is not None:
        status_code = getattr(exc, "status_code", None)
        if status_code is None:
            status_code = getattr(exc, "code", None)
        if status_code is None:
            resp = getattr(exc, "response", None)
            if resp is not None:
                status_code = getattr(resp, "status_code", None)

    if response_body is None and exc is not None:
        resp = getattr(exc, "response", None)
        if resp is not None:
            response_body = getattr(resp, "text", None)
            if response_body is None:
                body_bytes = getattr(resp, "content", None)
                if isinstance(body_bytes, bytes):
                    response_body = body_bytes.decode("utf-8", errors="replace")

    if headers is None and exc is not None:
        headers = getattr(exc, "headers", None)
        if headers is None:
            resp = getattr(exc, "response", None)
            if resp is not None:
                headers = getattr(resp, "headers", None)

    # Base error message
    raw_message = ""
    if exc is not None:
        raw_message = str(exc)
    elif response_body:
        raw_message = response_body[:200]
    elif status_code is not None:
        raw_message = f"HTTP {status_code}"
    else:
        raw_message = "Unknown source error"

    sanitized_message = redact_credentials(raw_message)

    # Details context
    details: dict[str, Any] = {}
    if status_code is not None:
        details["status_code"] = status_code
    if exc is not None:
        details["original_error"] = type(exc).__name__
    if response_body:
        details["response_body"] = redact_credentials(response_body[:500])

    # Extract retry_after if available
    retry_after = _extract_retry_after(headers, response_body)
    if retry_after is None and exc is not None:
        exc_ra = getattr(exc, "retry_after", None)
        if exc_ra is not None:
            try:
                retry_after = max(0.0, float(exc_ra))
            except (ValueError, TypeError):
                pass
    if retry_after is not None:
        details["retry_after"] = retry_after

    # If exc is already a classified SourceError and no override given, return it
    if isinstance(exc, SourceError) and status_code is None and response_body is None:
        if source and not exc.source:
            exc.source = source
        return exc

    # 1. Parse JSON-RPC or provider-specific body
    rpc_code: int | None = None
    rpc_message: str = ""
    if response_body:
        try:
            parsed = json.loads(response_body)
            if isinstance(parsed, dict):
                # Standard JSON-RPC: {"jsonrpc": "2.0", "error": {"code": -32600, "message": "..."}}
                if "error" in parsed:
                    err = parsed["error"]
                    if isinstance(err, dict):
                        rpc_code = err.get("code")
                        rpc_message = str(err.get("message", ""))
                        details["rpc_error"] = err
                    elif isinstance(err, str):
                        rpc_message = err
                        details["rpc_error"] = err
                # Etherscan format: {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"}
                elif parsed.get("status") == "0" and "result" in parsed:
                    rpc_message = str(parsed["result"])
                    details["etherscan_error"] = parsed
        except Exception:
            pass

    body_or_rpc_lower = f"{rpc_message} {response_body or ''}".lower()

    # Check RPC codes & body keywords
    if rpc_code is not None or rpc_message:
        # Rate limit
        if rpc_code in (-32005, 429, -32029) or any(
            kw in body_or_rpc_lower for kw in _RATE_LIMIT_KEYWORDS
        ):
            return RateLimitError(
                message=sanitized_message,
                source=source,
                details=details,
                retry_after=retry_after,
            )
        # Authentication
        if rpc_code in (401, 403, -32001, -32002) or any(
            kw in body_or_rpc_lower for kw in _AUTH_KEYWORDS
        ):
            return AuthenticationError(
                message=sanitized_message, source=source, details=details
            )
        # Invalid request / client error
        if rpc_code in (-32700, -32600, -32601, -32602, -32004) or any(
            kw in body_or_rpc_lower for kw in _INVALID_REQUEST_KEYWORDS
        ):
            return InvalidRequestError(
                message=sanitized_message, source=source, details=details
            )
        # Server / transient error
        if rpc_code in (-32603, -32000) or any(
            kw in body_or_rpc_lower for kw in _TRANSIENT_KEYWORDS
        ):
            return TransientSourceError(
                message=sanitized_message, source=source, details=details
            )

    # 2. HTTP status code classification
    if status_code is not None:
        if status_code in (401, 403):
            return AuthenticationError(
                message=sanitized_message, source=source, details=details
            )
        if status_code == 429:
            return RateLimitError(
                message=sanitized_message,
                source=source,
                details=details,
                retry_after=retry_after,
            )
        if status_code in (400, 404, 422):
            return InvalidRequestError(
                message=sanitized_message, source=source, details=details
            )
        if status_code in (500, 502, 503, 504) or (500 <= status_code < 600):
            return TransientSourceError(
                message=sanitized_message, source=source, details=details
            )
        if status_code == 408:  # Request Timeout
            return TransientSourceError(
                message=sanitized_message, source=source, details=details
            )
        if 400 <= status_code < 500:
            return InvalidRequestError(
                message=sanitized_message, source=source, details=details
            )

    # 3. Exception type classification
    if exc is not None:
        exc_type_name = type(exc).__name__

        # Incomplete response
        if "IncompleteRead" in exc_type_name or any(
            kw in sanitized_message.lower() for kw in _INCOMPLETE_KEYWORDS
        ):
            return IncompleteResponseError(
                message=sanitized_message, source=source, details=details
            )

        # Timeouts and network connection errors
        if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
            return TransientSourceError(
                message=sanitized_message, source=source, details=details
            )

        if any(
            kw in exc_type_name.lower()
            for kw in ("timeout", "connect", "connection", "socket")
        ):
            return TransientSourceError(
                message=sanitized_message, source=source, details=details
            )

        # Standard client parameter errors
        if isinstance(exc, (ValueError, TypeError, KeyError)):
            return InvalidRequestError(
                message=sanitized_message, source=source, details=details
            )

    # 4. Keyword heuristics on message
    msg_lower = sanitized_message.lower()
    if any(kw in msg_lower for kw in _RATE_LIMIT_KEYWORDS):
        return RateLimitError(
            message=sanitized_message,
            source=source,
            details=details,
            retry_after=retry_after,
        )
    if any(kw in msg_lower for kw in _AUTH_KEYWORDS):
        return AuthenticationError(
            message=sanitized_message, source=source, details=details
        )
    if any(kw in msg_lower for kw in _INCOMPLETE_KEYWORDS):
        return IncompleteResponseError(
            message=sanitized_message, source=source, details=details
        )
    if any(kw in msg_lower for kw in _TRANSIENT_KEYWORDS):
        return TransientSourceError(
            message=sanitized_message, source=source, details=details
        )

    # Default fallback: PermanentSourceError (safe non-infinite retry default)
    return PermanentSourceError(
        message=sanitized_message, source=source, details=details
    )


# ---------------------------------------------------------------------------
# Retry policy and execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """Configurable retry policy with bounded exponential backoff and jitter.

    Attributes:
        max_attempts: Maximum total attempts (initial attempt + retries).
        initial_delay: Base delay in seconds before the first retry.
        max_delay: Upper cap on retry delay in seconds.
        backoff_factor: Multiplier applied per subsequent retry attempt.
        jitter: When True, applies full random jitter ``[0, delay]`` to prevent
            thundering herds.
        retryable_errors: Tuple of exception types that should be retried.
        raise_permanent_on_exhaustion: When True, raises :class:`PermanentSourceError`
            upon exhaustion; when False, raises the underlying classified error.
    """

    max_attempts: int = 5
    initial_delay: float = 0.5
    max_delay: float = 30.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retryable_errors: tuple[type[Exception], ...] = (TransientSourceError,)
    raise_permanent_on_exhaustion: bool = False

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {self.max_attempts}")
        if self.initial_delay < 0:
            raise ValueError(f"initial_delay must be >= 0, got {self.initial_delay}")
        if self.max_delay < self.initial_delay:
            raise ValueError(
                f"max_delay ({self.max_delay}) must be >= initial_delay ({self.initial_delay})"
            )
        if self.backoff_factor < 1.0:
            raise ValueError(
                f"backoff_factor must be >= 1.0, got {self.backoff_factor}"
            )

    def compute_delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Compute sleep duration before the next retry attempt.

        Args:
            attempt: The 1-based attempt number that just failed.
            retry_after: Optional upstream provider recommended backoff.

        Returns:
            Delay in seconds, bounded by :attr:`max_delay`.
        """
        if retry_after is not None and retry_after > 0:
            return min(self.max_delay, float(retry_after))

        exp = max(0, attempt - 1)
        nominal = min(self.max_delay, self.initial_delay * (self.backoff_factor ** exp))

        if not self.jitter:
            return nominal

        return random.uniform(0.0, nominal)


def execute_with_retry(
    call_or_policy: Any = None,
    policy_or_call: Any = None,
    *,
    policy: RetryPolicy | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_retry: Callable[[Exception, int, float], None] | None = None,
) -> Any:
    """Execute a callable with retry according to a RetryPolicy.

    Catches retryable errors and performs bounded exponential backoff.
    Never retries permanent errors (:class:`AuthenticationError`,
    :class:`InvalidRequestError`, etc.).

    Args:
        call_or_policy: Either the callable to execute or a :class:`RetryPolicy`.
        policy_or_call: Either the :class:`RetryPolicy` or the callable.
        policy: Optional :class:`RetryPolicy` passed as keyword argument.
        sleep_fn: Sleep implementation (defaults to ``time.sleep``, replaceable
            for testing).
        on_retry: Optional callback ``(exception, attempt_number, delay)`` invoked
            prior to sleeping before each retry.

    Returns:
        The result of calling the target callable.

    Raises:
        PermanentSourceError: If a non-retryable error occurs or retries are
            exhausted with ``raise_permanent_on_exhaustion=True``.
        SourceError: The underlying error if retries are exhausted.
    """
    target_call: Callable[..., Any] | None = None
    target_policy: RetryPolicy | None = policy

    if isinstance(call_or_policy, RetryPolicy):
        target_policy = call_or_policy
        if callable(policy_or_call):
            target_call = policy_or_call
    elif callable(call_or_policy):
        target_call = call_or_policy
        if isinstance(policy_or_call, RetryPolicy):
            target_policy = policy_or_call

    if target_policy is None:
        if isinstance(policy_or_call, RetryPolicy):
            target_policy = policy_or_call
        else:
            target_policy = RetryPolicy()

    if target_call is None and callable(policy_or_call):
        target_call = policy_or_call

    if not callable(target_call):
        raise TypeError(
            f"target must be callable, got {type(target_call).__name__}"
        )

    attempt = 0
    while True:
        attempt += 1
        try:
            return target_call()
        except Exception as exc:
            classified: SourceError
            if isinstance(exc, SourceError):
                classified = exc
            else:
                classified = classify_source_error(exc)

            # Never retry permanent errors
            if isinstance(classified, PermanentSourceError) or not isinstance(
                classified, target_policy.retryable_errors
            ):
                raise classified from exc

            # Retries exhausted
            if attempt >= target_policy.max_attempts:
                details = dict(classified.details)
                details["attempts"] = attempt
                details["exhausted"] = True
                if target_policy.raise_permanent_on_exhaustion:
                    redacted_msg = redact_credentials(
                        f"Retries exhausted ({attempt}/{target_policy.max_attempts}): {classified.message}"
                    )
                    raise PermanentSourceError(
                        message=redacted_msg,
                        source=classified.source,
                        details=details,
                    ) from exc
                classified.details.update(details)
                raise classified from exc

            # Compute delay and sleep
            retry_after = getattr(classified, "retry_after", None)
            delay = target_policy.compute_delay(attempt, retry_after=retry_after)

            if on_retry is not None:
                on_retry(classified, attempt, delay)

            if delay > 0:
                sleep_fn(delay)


def with_retry(
    policy_or_call: RetryPolicy | Callable[..., Any] | None = None,
    call: Callable[..., Any] | None = None,
    *args: Any,
    policy: RetryPolicy | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_retry: Callable[[Exception, int, float], None] | None = None,
    **kwargs: Any,
) -> Any:
    """Decorator or wrapper to execute calls with retry policy.

    Usages:
        - As wrapper: ``with_retry(policy, func, *args, **kwargs)``
        - As decorator: ``@with_retry(policy)``
        - As default decorator: ``@with_retry``
    """
    # Pattern 1: with_retry(policy, func, *args, **kwargs)
    if isinstance(policy_or_call, RetryPolicy) and callable(call):
        target = call
        pol = policy_or_call
        return execute_with_retry(
            lambda: target(*args, **kwargs),
            policy=pol,
            sleep_fn=sleep_fn,
            on_retry=on_retry,
        )

    # Pattern 2: with_retry(func, *args, **kwargs) or @with_retry
    if callable(policy_or_call) and not isinstance(policy_or_call, RetryPolicy):
        target = policy_or_call
        if args or kwargs or call is not None:
            pol = call if isinstance(call, RetryPolicy) else (policy or RetryPolicy())
            return execute_with_retry(
                lambda: target(*args, **kwargs),
                policy=pol,
                sleep_fn=sleep_fn,
                on_retry=on_retry,
            )
        # Bare decorator: @with_retry
        @functools.wraps(target)
        def bare_wrapper(*a: Any, **kw: Any) -> Any:
            return execute_with_retry(
                lambda: target(*a, **kw),
                policy=RetryPolicy(),
                sleep_fn=sleep_fn,
                on_retry=on_retry,
            )

        return bare_wrapper

    # Pattern 3: @with_retry(policy)
    pol = (
        policy_or_call
        if isinstance(policy_or_call, RetryPolicy)
        else (policy or RetryPolicy())
    )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*a: Any, **kw: Any) -> Any:
            return execute_with_retry(
                lambda: fn(*a, **kw),
                policy=pol,
                sleep_fn=sleep_fn,
                on_retry=on_retry,
            )

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Token-bucket rate limiter.

    Thread-safe rate limiter that restricts throughput to ``requests_per_second``.
    Supports context manager usage (``with limiter: ...``).

    Attributes:
        requests_per_second: Maximum permitted sustained request rate.
        capacity: Maximum burst capacity in tokens.
    """

    def __init__(
        self,
        requests_per_second: float,
        *,
        burst: float | None = None,
        time_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError(
                f"requests_per_second must be positive, got {requests_per_second}"
            )
        self.requests_per_second = float(requests_per_second)
        self.capacity = (
            float(burst)
            if burst is not None
            else max(1.0, float(requests_per_second))
        )
        if self.capacity <= 0:
            raise ValueError(f"burst capacity must be positive, got {self.capacity}")

        self._tokens = self.capacity
        self._time_fn = time_fn
        self._sleep_fn = sleep_fn
        self._last_time = time_fn()
        self._lock = threading.Lock()

    def _refill(self, now: float) -> None:
        elapsed = now - self._last_time
        if elapsed > 0:
            self._tokens = min(
                self.capacity,
                self._tokens + elapsed * self.requests_per_second,
            )
            self._last_time = now

    def acquire(self, tokens: float = 1.0) -> float:
        """Acquire `tokens` from the bucket, sleeping if necessary.

        Args:
            tokens: Number of tokens to acquire (defaults to 1.0).

        Returns:
            Seconds waited before tokens became available (0.0 if immediate).
        """
        if tokens <= 0:
            raise ValueError(f"tokens must be positive, got {tokens}")

        with self._lock:
            now = self._time_fn()
            self._refill(now)

            if self._tokens + 1e-9 >= tokens:
                self._tokens = max(0.0, self._tokens - tokens)
                return 0.0

            # Calculate wait time for deficit
            deficit = max(0.0, tokens - self._tokens)
            wait_time = deficit / self.requests_per_second
            self._tokens = 0.0
            self._last_time = now + wait_time

        if wait_time > 0:
            self._sleep_fn(wait_time)
        return wait_time

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Attempt to acquire `tokens` without sleeping.

        Returns:
            True if tokens were acquired, False if insufficient tokens were available.
        """
        if tokens <= 0:
            raise ValueError(f"tokens must be positive, got {tokens}")

        with self._lock:
            now = self._time_fn()
            self._refill(now)
            if self._tokens + 1e-9 >= tokens:
                self._tokens = max(0.0, self._tokens - tokens)
                return True
            return False

    def __enter__(self) -> RateLimiter:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


__all__ = [
    "RateLimiter",
    "RetryPolicy",
    "classify_source_error",
    "execute_with_retry",
    "redact_credentials",
    "with_retry",
]
