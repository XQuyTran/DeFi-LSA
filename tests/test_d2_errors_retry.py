"""Tests for error taxonomy, credential redaction, retry policy, and rate limiter (A04)."""

from __future__ import annotations

import unittest
from unittest.mock import Mock

from defi_lsa.errors import (
    AuthenticationError,
    IncompleteResponseError,
    InvalidRequestError,
    PermanentSourceError,
    RateLimitError,
    SourceError,
    TransientSourceError,
)
from defi_lsa.retry import (
    RateLimiter,
    RetryPolicy,
    classify_source_error,
    execute_with_retry,
    redact_credentials,
    with_retry,
)


class TestErrorTaxonomy(unittest.TestCase):
    """Verify exception hierarchy, instantiation, and attributes."""

    def test_inheritance_hierarchy(self) -> None:
        self.assertTrue(issubclass(SourceError, Exception))
        self.assertTrue(issubclass(TransientSourceError, SourceError))
        self.assertTrue(issubclass(RateLimitError, TransientSourceError))
        self.assertTrue(issubclass(IncompleteResponseError, TransientSourceError))
        self.assertTrue(issubclass(PermanentSourceError, SourceError))
        self.assertTrue(issubclass(AuthenticationError, PermanentSourceError))
        self.assertTrue(issubclass(InvalidRequestError, PermanentSourceError))

        # Distinct branches
        self.assertFalse(issubclass(PermanentSourceError, TransientSourceError))
        self.assertFalse(issubclass(TransientSourceError, PermanentSourceError))
        self.assertFalse(issubclass(AuthenticationError, TransientSourceError))
        self.assertFalse(issubclass(RateLimitError, PermanentSourceError))

    def test_source_error_attributes(self) -> None:
        err = SourceError("connection failed", source="rpc", details={"host": "127.0.0.1"})
        self.assertEqual(err.message, "connection failed")
        self.assertEqual(err.source, "rpc")
        self.assertEqual(err.details, {"host": "127.0.0.1"})
        self.assertIn("[rpc] connection failed", str(err))

    def test_source_error_defaults(self) -> None:
        err = SourceError("bare message")
        self.assertEqual(err.message, "bare message")
        self.assertEqual(err.source, "")
        self.assertEqual(err.details, {})
        self.assertEqual(str(err), "bare message")

    def test_rate_limit_error_retry_after(self) -> None:
        err = RateLimitError("rate limited", source="coingecko", retry_after=12.5)
        self.assertEqual(err.message, "rate limited")
        self.assertEqual(err.source, "coingecko")
        self.assertEqual(err.retry_after, 12.5)

        err_no_ra = RateLimitError("throttled", source="etherscan")
        self.assertIsNone(err_no_ra.retry_after)

    def test_repr_contains_class_and_fields(self) -> None:
        err = RateLimitError("throttled", source="rpc", retry_after=2.0)
        rep = repr(err)
        self.assertIn("RateLimitError", rep)
        self.assertIn("throttled", rep)
        self.assertIn("retry_after=2.0", rep)


class TestRedactCredentials(unittest.TestCase):
    """Verify sensitive token redaction across URLs, headers, and payloads."""

    def test_redact_url_query_apikey(self) -> None:
        url = "https://api.etherscan.io/api?apikey=SECRET123"
        redacted = redact_credentials(url)
        self.assertEqual(redacted, "https://api.etherscan.io/api?apikey=[REDACTED]")

    def test_redact_url_multiple_query_params(self) -> None:
        url = "https://api.etherscan.io/api?module=account&apikey=SECRET123&action=balance"
        redacted = redact_credentials(url)
        self.assertEqual(
            redacted,
            "https://api.etherscan.io/api?module=account&apikey=[REDACTED]&action=balance",
        )

    def test_redact_query_param_variations(self) -> None:
        urls = [
            ("https://api.foo.com/?api_key=SECRET456", "https://api.foo.com/?api_key=[REDACTED]"),
            ("https://api.foo.com/?key=SECRET789", "https://api.foo.com/?key=[REDACTED]"),
            ("https://api.foo.com/?token=SEC_TOK", "https://api.foo.com/?token=[REDACTED]"),
            ("https://api.foo.com/?access_token=SEC_TOK", "https://api.foo.com/?access_token=[REDACTED]"),
            ("https://api.foo.com/?secret=SEC_VAL", "https://api.foo.com/?secret=[REDACTED]"),
        ]
        for raw, expected in urls:
            self.assertEqual(redact_credentials(raw), expected)

    def test_redact_authorization_header(self) -> None:
        header = "Authorization: Bearer my-jwt-secret-token"
        redacted = redact_credentials(header)
        self.assertEqual(redacted, "Authorization: Bearer [REDACTED]")

        basic_header = "Authorization: Basic dXNlcjpwYXNz"
        self.assertEqual(redact_credentials(basic_header), "Authorization: Basic [REDACTED]")

    def test_redact_embedded_url_basic_auth(self) -> None:
        url = "https://user:super_secret_pw@node.geth.org:8545"
        self.assertEqual(
            redact_credentials(url),
            "https://user:[REDACTED]@node.geth.org:8545",
        )

    def test_redact_provider_path_endpoints(self) -> None:
        infura = "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
        self.assertEqual(
            redact_credentials(infura),
            "https://mainnet.infura.io/v3/[REDACTED]",
        )
        alchemy = "https://eth-mainnet.g.alchemy.com/v2/demo_alchemy_key_here"
        self.assertEqual(
            redact_credentials(alchemy),
            "https://eth-mainnet.g.alchemy.com/v2/[REDACTED]",
        )

    def test_redact_json_key_value(self) -> None:
        json_payload = '{"module": "proxy", "apikey": "SECRET_KEY_123", "action": "eth_blockNumber"}'
        redacted = redact_credentials(json_payload)
        self.assertNotIn("SECRET_KEY_123", redacted)
        self.assertIn('"apikey": "[REDACTED]"', redacted)

    def test_redact_custom_secrets_list(self) -> None:
        text = "request to node with internal key 0xdeadbeefbadpass in payload"
        redacted = redact_credentials(text, secrets=["0xdeadbeefbadpass", "extra_key"])
        self.assertNotIn("0xdeadbeefbadpass", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_redact_overlapping_secrets_order(self) -> None:
        text = "key1: supersecret_extended, key2: supersecret"
        redacted = redact_credentials(text, secrets=["supersecret", "supersecret_extended"])
        self.assertEqual(redacted, "key1: [REDACTED], key2: [REDACTED]")


class TestClassifySourceError(unittest.TestCase):
    """Verify HTTP status codes, exception types, and RPC error classifications."""

    def test_http_401_and_403_are_authentication_errors(self) -> None:
        err_401 = classify_source_error(status_code=401, source="etherscan")
        self.assertIsInstance(err_401, AuthenticationError)
        self.assertEqual(err_401.source, "etherscan")

        err_403 = classify_source_error(status_code=403, source="coingecko")
        self.assertIsInstance(err_403, AuthenticationError)

    def test_http_429_is_rate_limit_error_with_retry_after(self) -> None:
        err = classify_source_error(
            status_code=429,
            source="rpc",
            headers={"Retry-After": "7.5"},
        )
        self.assertIsInstance(err, RateLimitError)
        self.assertEqual(err.retry_after, 7.5)

    def test_http_429_extracts_retry_after_from_json_body(self) -> None:
        body = '{"error": {"message": "rate limit", "retry_after": 10.0}}'
        err = classify_source_error(status_code=429, response_body=body, source="coingecko")
        self.assertIsInstance(err, RateLimitError)
        self.assertEqual(err.retry_after, 10.0)

    def test_http_400_404_422_are_invalid_request_errors(self) -> None:
        for code in (400, 404, 422):
            err = classify_source_error(status_code=code, source="rpc")
            self.assertIsInstance(err, InvalidRequestError)
            self.assertEqual(err.details.get("status_code"), code)

    def test_http_5xx_are_transient_source_errors(self) -> None:
        for code in (500, 502, 503, 504):
            err = classify_source_error(status_code=code, source="rpc")
            self.assertIsInstance(err, TransientSourceError)
            self.assertEqual(err.details.get("status_code"), code)

    def test_exceptions_classified_as_transient(self) -> None:
        for exc in (
            TimeoutError("gateway timed out"),
            ConnectionError("connection reset by peer"),
            OSError("network is unreachable"),
        ):
            err = classify_source_error(exc, source="rpc")
            self.assertIsInstance(err, TransientSourceError)

    def test_incomplete_response_classification(self) -> None:
        exc = Exception("incomplete response: unexpected EOF in chunked body")
        err = classify_source_error(exc, source="http")
        self.assertIsInstance(err, IncompleteResponseError)

    def test_rpc_error_codes(self) -> None:
        # Invalid request / params
        rpc_invalid = classify_source_error(
            response_body='{"jsonrpc": "2.0", "error": {"code": -32602, "message": "invalid params"}}',
            source="rpc",
        )
        self.assertIsInstance(rpc_invalid, InvalidRequestError)

        # Infura / Alchemy rate limit
        rpc_rate = classify_source_error(
            response_body='{"jsonrpc": "2.0", "error": {"code": -32005, "message": "daily request count exceeded"}}',
            source="rpc",
        )
        self.assertIsInstance(rpc_rate, RateLimitError)

        # Internal server / transient error
        rpc_transient = classify_source_error(
            response_body='{"jsonrpc": "2.0", "error": {"code": -32603, "message": "internal error"}}',
            source="rpc",
        )
        self.assertIsInstance(rpc_transient, TransientSourceError)

        # Unauthorized
        rpc_auth = classify_source_error(
            response_body='{"jsonrpc": "2.0", "error": {"code": 401, "message": "invalid project id"}}',
            source="rpc",
        )
        self.assertIsInstance(rpc_auth, AuthenticationError)

    def test_etherscan_error_format(self) -> None:
        body_rate = '{"status": "0", "message": "NOTOK", "result": "Max rate limit reached"}'
        err_rate = classify_source_error(response_body=body_rate, source="etherscan")
        self.assertIsInstance(err_rate, RateLimitError)

        body_auth = '{"status": "0", "message": "NOTOK", "result": "Invalid API Key"}'
        err_auth = classify_source_error(response_body=body_auth, source="etherscan")
        self.assertIsInstance(err_auth, AuthenticationError)

    def test_redacts_credentials_in_classified_error_message(self) -> None:
        exc = Exception("Failed request to https://api.etherscan.io/api?apikey=SUPERSECRET")
        err = classify_source_error(exc, source="etherscan")
        self.assertNotIn("SUPERSECRET", err.message)
        self.assertIn("apikey=[REDACTED]", err.message)


class TestRetryPolicyAndExecution(unittest.TestCase):
    """Verify RetryPolicy and execute_with_retry under all execution paths."""

    def test_initial_attempt_succeeds(self) -> None:
        fn = Mock(return_value={"result": "0x123"})
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=3, initial_delay=0.1, jitter=False)

        res = execute_with_retry(fn, policy, sleep_fn=sleep_mock)
        self.assertEqual(res, {"result": "0x123"})
        self.assertEqual(fn.call_count, 1)
        sleep_mock.assert_not_called()

    def test_retry_succeeds_after_transient_failures(self) -> None:
        # Fails twice with TransientSourceError, succeeds on 3rd attempt
        fn = Mock(
            side_effect=[
                TransientSourceError("timeout 1", source="rpc"),
                TransientSourceError("timeout 2", source="rpc"),
                {"block": 100},
            ]
        )
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=4, initial_delay=1.0, backoff_factor=2.0, jitter=False)

        res = execute_with_retry(fn, policy, sleep_fn=sleep_mock)
        self.assertEqual(res, {"block": 100})
        self.assertEqual(fn.call_count, 3)
        # Attempt 1 failed -> sleep(1.0); Attempt 2 failed -> sleep(2.0)
        self.assertEqual(sleep_mock.call_count, 2)
        sleep_mock.assert_any_call(1.0)
        sleep_mock.assert_any_call(2.0)

    def test_retry_obeys_rate_limit_retry_after(self) -> None:
        fn = Mock(
            side_effect=[
                RateLimitError("rate limited", source="coingecko", retry_after=4.5),
                "success",
            ]
        )
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=3, initial_delay=0.1, max_delay=10.0, jitter=False)

        res = execute_with_retry(fn, policy, sleep_fn=sleep_mock)
        self.assertEqual(res, "success")
        self.assertEqual(fn.call_count, 2)
        sleep_mock.assert_called_once_with(4.5)

    def test_fails_fast_on_permanent_authentication_error(self) -> None:
        fn = Mock(side_effect=AuthenticationError("invalid api key", source="etherscan"))
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=5)

        with self.assertRaises(AuthenticationError):
            execute_with_retry(fn, policy, sleep_fn=sleep_mock)

        self.assertEqual(fn.call_count, 1)
        sleep_mock.assert_not_called()

    def test_fails_fast_on_permanent_invalid_request_error(self) -> None:
        fn = Mock(side_effect=InvalidRequestError("bad block number", source="rpc"))
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=5)

        with self.assertRaises(InvalidRequestError):
            execute_with_retry(fn, policy, sleep_fn=sleep_mock)

        self.assertEqual(fn.call_count, 1)
        sleep_mock.assert_not_called()

    def test_retry_exhaustion_raises_classified_error(self) -> None:
        fn = Mock(side_effect=TransientSourceError("persistent failure", source="rpc"))
        sleep_mock = Mock()
        policy = RetryPolicy(max_attempts=3, initial_delay=0.1, jitter=False)

        with self.assertRaises(TransientSourceError) as ctx:
            execute_with_retry(fn, policy, sleep_fn=sleep_mock)

        self.assertEqual(fn.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 2)
        self.assertEqual(ctx.exception.details.get("attempts"), 3)
        self.assertTrue(ctx.exception.details.get("exhausted"))

    def test_retry_exhaustion_with_permanent_option(self) -> None:
        fn = Mock(side_effect=TransientSourceError("fail", source="rpc"))
        sleep_mock = Mock()
        policy = RetryPolicy(
            max_attempts=2,
            initial_delay=0.1,
            jitter=False,
            raise_permanent_on_exhaustion=True,
        )

        with self.assertRaises(PermanentSourceError) as ctx:
            execute_with_retry(fn, policy, sleep_fn=sleep_mock)

        self.assertEqual(fn.call_count, 2)
        self.assertIn("Retries exhausted", str(ctx.exception))

    def test_with_retry_as_decorator(self) -> None:
        mock_sleep = Mock()
        calls = [0]

        @with_retry(RetryPolicy(max_attempts=3, initial_delay=0.01, jitter=False), sleep_fn=mock_sleep)
        def query_data() -> str:
            calls[0] += 1
            if calls[0] < 2:
                raise TransientSourceError("temporary error")
            return "data"

        res = query_data()
        self.assertEqual(res, "data")
        self.assertEqual(calls[0], 2)
        mock_sleep.assert_called_once()

    def test_with_retry_as_wrapper_function(self) -> None:
        mock_sleep = Mock()
        policy = RetryPolicy(max_attempts=3, initial_delay=0.01, jitter=False)
        func = Mock(return_value="wrapper_success")

        res = with_retry(policy, func, "arg1", key="kw1", sleep_fn=mock_sleep)
        self.assertEqual(res, "wrapper_success")
        func.assert_called_once_with("arg1", key="kw1")

    def test_execute_with_retry_inverted_argument_order(self) -> None:
        mock_sleep = Mock()
        policy = RetryPolicy(max_attempts=2, initial_delay=0.01, jitter=False)
        func = Mock(return_value=99)

        # Call with (policy, func) instead of (func, policy)
        res = execute_with_retry(policy, func, sleep_fn=mock_sleep)
        self.assertEqual(res, 99)
        func.assert_called_once()

    def test_retry_policy_delay_deterministic_without_jitter(self) -> None:
        policy = RetryPolicy(
            max_attempts=5,
            initial_delay=0.5,
            backoff_factor=2.0,
            max_delay=10.0,
            jitter=False,
        )
        self.assertEqual(policy.compute_delay(1), 0.5)
        self.assertEqual(policy.compute_delay(2), 1.0)
        self.assertEqual(policy.compute_delay(3), 2.0)
        self.assertEqual(policy.compute_delay(4), 4.0)
        self.assertEqual(policy.compute_delay(5), 8.0)
        # Bounded by max_delay
        self.assertEqual(policy.compute_delay(10), 10.0)

    def test_retry_policy_delay_bounded_with_jitter(self) -> None:
        policy = RetryPolicy(
            max_attempts=5,
            initial_delay=1.0,
            backoff_factor=2.0,
            max_delay=5.0,
            jitter=True,
        )
        for attempt in range(1, 6):
            d = policy.compute_delay(attempt)
            self.assertGreaterEqual(d, 0.0)
            self.assertLessEqual(d, 5.0)

    def test_retry_policy_validation_raises(self) -> None:
        with self.assertRaises(ValueError):
            RetryPolicy(max_attempts=0)
        with self.assertRaises(ValueError):
            RetryPolicy(initial_delay=-1.0)
        with self.assertRaises(ValueError):
            RetryPolicy(initial_delay=10.0, max_delay=5.0)
        with self.assertRaises(ValueError):
            RetryPolicy(backoff_factor=0.5)

    def test_on_retry_callback_invoked(self) -> None:
        fn = Mock(side_effect=[TransientSourceError("fail 1"), "ok"])
        retry_events: list[tuple[Exception, int, float]] = []

        def on_retry(exc: Exception, attempt: int, delay: float) -> None:
            retry_events.append((exc, attempt, delay))

        policy = RetryPolicy(max_attempts=3, initial_delay=0.2, jitter=False)
        execute_with_retry(fn, policy, sleep_fn=Mock(), on_retry=on_retry)

        self.assertEqual(len(retry_events), 1)
        self.assertIsInstance(retry_events[0][0], TransientSourceError)
        self.assertEqual(retry_events[0][1], 1)
        self.assertEqual(retry_events[0][2], 0.2)


class TestRateLimiter(unittest.TestCase):
    """Verify TokenBucket RateLimiter throughput constraints and wait times."""

    def test_initial_burst_acquires_immediately(self) -> None:
        limiter = RateLimiter(requests_per_second=10.0, burst=5.0)
        # Should acquire immediately without sleep
        wait = limiter.acquire(1.0)
        self.assertEqual(wait, 0.0)

    def test_exhausted_burst_sleeps_for_deficit(self) -> None:
        current_time = [100.0]
        sleeps: list[float] = []

        def mock_time() -> float:
            return current_time[0]

        def mock_sleep(d: float) -> None:
            sleeps.append(d)
            current_time[0] += d

        limiter = RateLimiter(
            requests_per_second=2.0,  # 0.5s per request
            burst=1.0,
            time_fn=mock_time,
            sleep_fn=mock_sleep,
        )

        # 1st acquire consumes the 1 token burst
        w1 = limiter.acquire(1.0)
        self.assertEqual(w1, 0.0)

        # 2nd acquire immediately at same time t=100.0 has 0 tokens, needs 0.5s
        w2 = limiter.acquire(1.0)
        self.assertAlmostEqual(w2, 0.5, places=5)
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.5, places=5)

    def test_replenishment_over_time(self) -> None:
        current_time = [100.0]

        def mock_time() -> float:
            return current_time[0]

        limiter = RateLimiter(
            requests_per_second=10.0,
            burst=5.0,
            time_fn=mock_time,
            sleep_fn=Mock(),
        )

        # Consume all 5 tokens
        for _ in range(5):
            self.assertTrue(limiter.try_acquire(1.0))

        # Empty bucket
        self.assertFalse(limiter.try_acquire(1.0))

        # Advance time by 0.3 seconds -> 3 tokens should be replenished
        current_time[0] += 0.3
        self.assertTrue(limiter.try_acquire(2.0))
        self.assertTrue(limiter.try_acquire(1.0))
        self.assertFalse(limiter.try_acquire(1.0))

    def test_try_acquire(self) -> None:
        limiter = RateLimiter(requests_per_second=1.0, burst=1.0)
        self.assertTrue(limiter.try_acquire(1.0))
        self.assertFalse(limiter.try_acquire(1.0))

    def test_context_manager_usage(self) -> None:
        limiter = RateLimiter(requests_per_second=5.0, burst=2.0)
        with limiter:
            x = 42
        self.assertEqual(x, 42)

    def test_invalid_parameters_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            RateLimiter(requests_per_second=0.0)
        with self.assertRaises(ValueError):
            RateLimiter(requests_per_second=-5.0)
        with self.assertRaises(ValueError):
            RateLimiter(requests_per_second=1.0, burst=-1.0)

        limiter = RateLimiter(requests_per_second=1.0)
        with self.assertRaises(ValueError):
            limiter.acquire(0.0)
        with self.assertRaises(ValueError):
            limiter.try_acquire(-1.0)


if __name__ == "__main__":
    unittest.main()
