"""Unit and integration tests for D2 data adapters (A05, A06).

Tests CoinGecko, Discourse, and GDELT adapters with deterministic stubs,
verifying crash-safety, deduplication, coverage auditing, copyright compliance,
and error classification without live API calls.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError

from defi_lsa.adapters.coingecko import (
    CoinGeckoAdapter,
    PriceCoverageReport,
    calculate_price_coverage,
)
from defi_lsa.adapters.discourse import DiscourseAdapter
from defi_lsa.adapters.gdelt import (
    GDELTAdapter,
    _format_gdelt_seendate_to_utc,
    _format_to_gdelt_datetime,
    _sanitize_article_metadata,
)
from defi_lsa.errors import (
    AuthenticationError,
    InvalidRequestError,
    RateLimitError,
)
from defi_lsa.retry import RetryPolicy
from defi_lsa.schemas import PriceRecord, PublicInfoRecord


class MockResponse:
    """Mock HTTP response object implementing context manager protocol."""

    def __init__(
        self,
        body: bytes | str | dict,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        if isinstance(body, dict):
            self._data = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            self._data = body.encode("utf-8")
        else:
            self._data = body
        self.status = status
        self.code = status
        self.headers = headers or {"Content-Type": "application/json"}

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> MockResponse:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


def make_http_error(
    code: int,
    message: str = "HTTP Error",
    body: str = '{"error": "failure"}',
    headers: dict[str, str] | None = None,
) -> HTTPError:
    """Construct an HTTPError with readable response body stream."""
    fp = io.BytesIO(body.encode("utf-8"))
    hdrs = headers or {}
    return HTTPError("https://api.example.com", code, message, hdrs, fp)


class TestCoinGeckoAdapter(unittest.TestCase):
    """Tests for CoinGeckoAdapter (A05)."""

    def setUp(self) -> None:
        self.token_address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"  # USDC
        self.coin_id = "usd-coin"
        self.event_id = "euler_2023-03-13"

    def test_fetch_market_chart_range_saves_raw_artifact(self) -> None:
        chart_payload = {
            "prices": [
                [1678665600000, 0.9985],  # 2023-03-13T00:00:00Z
                [1678669200000, 0.9990],  # 2023-03-13T01:00:00Z
            ],
            "market_caps": [],
            "total_volumes": [],
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            self.assertIn("market_chart/range", req.full_url)
            self.assertIn("from=1678665600", req.full_url)
            self.assertIn("to=1678669200", req.full_url)
            return MockResponse(chart_payload)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = CoinGeckoAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            result = adapter.fetch_market_chart_range(
                coin_id=self.coin_id,
                vs_currency="usd",
                from_timestamp=1678665600,
                to_timestamp=1678669200,
                event_id=self.event_id,
                raw_dir=root,
            )

            self.assertEqual(len(result["prices"]), 2)
            self.assertIn("_source_sha256", result)

            artifact_path = (
                root
                / "data"
                / "raw"
                / "source"
                / "coingecko"
                / self.event_id
                / f"{self.coin_id}_1678665600_1678669200.json"
            )
            self.assertTrue(artifact_path.exists())
            saved_json = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_json["prices"], chart_payload["prices"])

    def test_no_stablecoin_price_fabrication(self) -> None:
        # Crucial invariant: Stablecoin depegs (e.g. USDC at $0.88) must NOT be forced to 1.0!
        depegged_price = 0.8845
        chart_payload = {
            "prices": [
                [1678665600000, depegged_price],
            ]
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            return MockResponse(chart_payload)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = CoinGeckoAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            records = adapter.collect_hourly_prices(
                token_address=self.token_address,
                coin_id=self.coin_id,
                event_id=self.event_id,
                start_dt="2023-03-13T00:00:00Z",
                end_dt="2023-03-13T00:00:00Z",
                output_dir=root,
                raw_dir=root,
            )

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertIsInstance(record, PriceRecord)
            self.assertEqual(record.token_address, self.token_address.lower())
            self.assertEqual(record.coingecko_id, self.coin_id)
            self.assertEqual(record.hour_utc, "2023-03-13T00:00:00Z")
            self.assertEqual(record.usd_price, depegged_price)
            self.assertNotEqual(record.usd_price, 1.0)

            # Check normalized JSONL artifact
            jsonl_path = (
                root
                / "data"
                / "raw"
                / "normalized"
                / "prices"
                / "coingecko"
                / f"{self.event_id}.jsonl"
            )
            self.assertTrue(jsonl_path.exists())
            lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["usd_price"], depegged_price)

    def test_coverage_report_can_be_persisted(self) -> None:
        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            return MockResponse({"prices": [[1678665600000, 0.99]]})

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report = root / "reports" / "price_coverage.json"
            adapter = CoinGeckoAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            adapter.collect_hourly_prices(
                token_address=self.token_address,
                coin_id=self.coin_id,
                event_id=self.event_id,
                start_dt="2023-03-13T00:00:00Z",
                end_dt="2023-03-13T01:00:00Z",
                output_dir=root,
                raw_dir=root,
                coverage_report_path=report,
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["expected_hours"], 2)
            self.assertEqual(payload["collected_hours"], 1)

    def test_hourly_price_deduplication(self) -> None:
        # Multiple points within the same hour boundary (12:05 and 12:45)
        # Should deduplicate to a single PriceRecord closest to 12:00:00
        chart_payload = {
            "prices": [
                [1678709100000, 1.0002],  # 12:05:00 (+300 sec from 12:00)
                [1678711500000, 0.9995],  # 12:45:00 (+2700 sec from 12:00)
                [1678712700000, 1.0005],  # 13:05:00 (+300 sec from 13:00)
            ]
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            return MockResponse(chart_payload)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = CoinGeckoAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            records = adapter.collect_hourly_prices(
                token_address=self.token_address,
                coin_id=self.coin_id,
                event_id=self.event_id,
                start_dt="2023-03-13T12:00:00Z",
                end_dt="2023-03-13T13:00:00Z",
                output_dir=root,
                raw_dir=root,
            )

            # Two hours: 12:00:00Z and 13:00:00Z
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0].hour_utc, "2023-03-13T12:00:00Z")
            self.assertEqual(records[0].usd_price, 1.0002)  # picked 12:05:00 (closest to 12:00:00)
            self.assertEqual(records[1].hour_utc, "2023-03-13T13:00:00Z")
            self.assertEqual(records[1].usd_price, 1.0005)

    def test_coverage_metrics_calculation(self) -> None:
        # Window: 00:00, 01:00, 02:00, 03:00, 04:00 (5 expected hours)
        # Supply: 00:00, 01:00, 04:00 (3 collected, 2 missing)
        records = [
            PriceRecord(
                record_key=f"{self.token_address}:2023-03-13T00:00:00Z",
                event_id=self.event_id,
                token_address=self.token_address,
                coingecko_id=self.coin_id,
                source_timestamp=1678665600,
                hour_utc="2023-03-13T00:00:00Z",
                usd_price=1.0,
                source="coingecko",
                retrieved_at_utc="2023-03-13T12:00:00Z",
                source_sha256="a" * 64,
                normalization_version="1.0.0",
            ),
            PriceRecord(
                record_key=f"{self.token_address}:2023-03-13T01:00:00Z",
                event_id=self.event_id,
                token_address=self.token_address,
                coingecko_id=self.coin_id,
                source_timestamp=1678669200,
                hour_utc="2023-03-13T01:00:00Z",
                usd_price=1.0,
                source="coingecko",
                retrieved_at_utc="2023-03-13T12:00:00Z",
                source_sha256="a" * 64,
                normalization_version="1.0.0",
            ),
            PriceRecord(
                record_key=f"{self.token_address}:2023-03-13T04:00:00Z",
                event_id=self.event_id,
                token_address=self.token_address,
                coingecko_id=self.coin_id,
                source_timestamp=1678680000,
                hour_utc="2023-03-13T04:00:00Z",
                usd_price=1.0,
                source="coingecko",
                retrieved_at_utc="2023-03-13T12:00:00Z",
                source_sha256="a" * 64,
                normalization_version="1.0.0",
            ),
        ]

        report = calculate_price_coverage(
            records=records,
            start_dt="2023-03-13T00:00:00Z",
            end_dt="2023-03-13T04:00:00Z",
            coin_id=self.coin_id,
            token_address=self.token_address,
        )

        self.assertEqual(report.expected_hours, 5)
        self.assertEqual(report.collected_hours, 3)
        self.assertEqual(
            report.missing_hours,
            ("2023-03-13T02:00:00Z", "2023-03-13T03:00:00Z"),
        )
        self.assertEqual(report.max_consecutive_gap_hours, 2)
        self.assertEqual(report.coverage_percentage, 60.0)

    def test_coingecko_rate_limit_retry(self) -> None:
        attempts = 0

        def flaky_opener(req: Any, timeout: float = 30) -> MockResponse:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise make_http_error(
                    429,
                    message="Too Many Requests",
                    headers={"Retry-After": "0.001"},
                )
            return MockResponse({"prices": [[1678665600000, 1.0]]})

        adapter = CoinGeckoAdapter(
            opener=flaky_opener,
            retry_policy=RetryPolicy(
                max_attempts=3,
                initial_delay=0.001,
                max_delay=0.01,
                jitter=False,
            ),
            sleep_fn=lambda _: None,
        )
        result = adapter.fetch_market_chart_range(
            coin_id=self.coin_id,
            from_timestamp=1678665600,
            to_timestamp=1678669200,
        )
        self.assertEqual(attempts, 2)
        self.assertEqual(len(result["prices"]), 1)

    def test_coingecko_auth_error_not_retried(self) -> None:
        attempts = 0

        def unauthorized_opener(req: Any, timeout: float = 30) -> MockResponse:
            nonlocal attempts
            attempts += 1
            raise make_http_error(401, message="Unauthorized")

        adapter = CoinGeckoAdapter(
            opener=unauthorized_opener,
            retry_policy=RetryPolicy(max_attempts=3),
            sleep_fn=lambda _: None,
        )
        with self.assertRaises(AuthenticationError):
            adapter.fetch_market_chart_range(
                coin_id=self.coin_id,
                from_timestamp=1678665600,
                to_timestamp=1678669200,
            )
        self.assertEqual(attempts, 1)


class TestDiscourseAdapter(unittest.TestCase):
    """Tests for DiscourseAdapter (A06)."""

    def setUp(self) -> None:
        self.base_url = "https://governance.euler.finance"
        self.topic_id = "123"
        self.event_id = "euler_2023-03-13"

    def test_fetch_topic_success(self) -> None:
        topic_payload = {
            "id": 123,
            "title": "Euler Exploit Incident Review",
            "slug": "euler-exploit-incident-review",
            "created_at": "2023-03-13T10:00:00.000Z",
            "post_stream": {
                "posts": [
                    {
                        "id": 501,
                        "post_number": 1,
                        "created_at": "2023-03-13T10:00:00.000Z",
                    },
                    {
                        "id": 502,
                        "post_number": 2,
                        "created_at": "2023-03-13T11:30:00.000Z",
                    },
                ]
            },
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            self.assertEqual(
                req.full_url,
                "https://governance.euler.finance/t/123.json",
            )
            return MockResponse(topic_payload)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = DiscourseAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            records = adapter.fetch_topic(
                base_url=self.base_url,
                topic_id=self.topic_id,
                event_id=self.event_id,
                raw_dir=root,
                output_dir=root,
            )

            self.assertEqual(len(records), 2)
            self.assertIsInstance(records[0], PublicInfoRecord)
            self.assertEqual(
                records[0].canonical_url,
                "https://governance.euler.finance/t/euler-exploit-incident-review/123/1",
            )
            self.assertEqual(records[0].title, "Euler Exploit Incident Review")
            self.assertEqual(records[0].published_at_utc, "2023-03-13T10:00:00Z")
            self.assertEqual(records[0].source, "discourse")

            self.assertEqual(
                records[1].canonical_url,
                "https://governance.euler.finance/t/euler-exploit-incident-review/123/2",
            )
            self.assertEqual(
                records[1].title,
                "Euler Exploit Incident Review (Post #2)",
            )
            self.assertEqual(records[1].published_at_utc, "2023-03-13T11:30:00Z")

            # Check raw artifact
            raw_path = (
                root
                / "data"
                / "raw"
                / "source"
                / "discourse"
                / self.event_id
                / f"topic_{self.topic_id}.json"
            )
            self.assertTrue(raw_path.exists())

    def test_discourse_403_raises_auth_error_no_storage(self) -> None:
        def forbidden_opener(req: Any, timeout: float = 30) -> MockResponse:
            raise make_http_error(403, message="Forbidden: private category")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = DiscourseAdapter(
                opener=forbidden_opener,
                retry_policy=RetryPolicy(max_attempts=2),
                sleep_fn=lambda _: None,
            )
            with self.assertRaises(AuthenticationError):
                adapter.fetch_topic(
                    base_url=self.base_url,
                    topic_id="999",
                    event_id=self.event_id,
                    raw_dir=root,
                )

            # Ensure unauthorized content is never stored
            raw_path = (
                root
                / "data"
                / "raw"
                / "source"
                / "discourse"
                / self.event_id
                / "topic_999.json"
            )
            self.assertFalse(raw_path.exists())

    def test_discourse_404_raises_invalid_request_error(self) -> None:
        def not_found_opener(req: Any, timeout: float = 30) -> MockResponse:
            raise make_http_error(404, message="Topic Not Found")

        adapter = DiscourseAdapter(
            opener=not_found_opener,
            retry_policy=RetryPolicy(max_attempts=2),
            sleep_fn=lambda _: None,
        )
        with self.assertRaises(InvalidRequestError):
            adapter.fetch_topic(
                base_url=self.base_url,
                topic_id="404",
                event_id=self.event_id,
            )


class TestGDELTAdapter(unittest.TestCase):
    """Tests for GDELTAdapter (A06)."""

    def setUp(self) -> None:
        self.query = "euler finance exploit"
        self.start_date = "2023-03-13T00:00:00Z"
        self.end_date = "2023-03-14T00:00:00Z"
        self.event_id = "euler_2023-03-13"

    def test_query_articles_success(self) -> None:
        gdelt_payload = {
            "articles": [
                {
                    "url": "https://coindesk.com/article/euler-hack-1",
                    "title": "Euler Finance Hacked for $197M",
                    "seendate": "20230313T120000Z",
                    "domain": "coindesk.com",
                    "language": "English",
                    "sourcecountry": "United States",
                },
                {
                    "url": "https://theblock.co/article/euler-hack-2",
                    "title": "Flash Loan Attack Drains Euler",
                    "seendate": "20230313143000",
                    "domain": "theblock.co",
                    "language": "English",
                    "sourcecountry": "United States",
                },
            ]
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            self.assertIn("mode=artlist", req.full_url)
            self.assertIn("format=json", req.full_url)
            self.assertIn("startdatetime=20230313000000", req.full_url)
            return MockResponse(gdelt_payload)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = GDELTAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            records = adapter.query_articles(
                query=self.query,
                start_date=self.start_date,
                end_date=self.end_date,
                event_id=self.event_id,
                max_records=10,
                raw_dir=root,
                output_dir=root,
            )

            self.assertEqual(len(records), 2)
            self.assertIsInstance(records[0], PublicInfoRecord)
            self.assertEqual(records[0].source, "gdelt")
            self.assertEqual(
                records[0].url,
                "https://coindesk.com/article/euler-hack-1",
            )
            self.assertEqual(records[0].title, "Euler Finance Hacked for $197M")
            self.assertEqual(records[0].published_at_utc, "2023-03-13T12:00:00Z")

            self.assertEqual(records[1].published_at_utc, "2023-03-13T14:30:00Z")

    def test_copyright_invariant_no_article_body_stored(self) -> None:
        # Crucial invariant: Ensure full copyrighted article text is NEVER fetched or stored!
        gdelt_payload_with_body = {
            "articles": [
                {
                    "url": "https://news.example.com/item1",
                    "title": "Protocol Exploited",
                    "seendate": "20230313T120000Z",
                    "domain": "news.example.com",
                    "language": "English",
                    # Simulated forbidden body fields that must be stripped
                    "body": "This is copyrighted full article text that must never be saved.",
                    "article_text": "More proprietary article text.",
                    "content": "Secret journalistic reporting.",
                }
            ]
        }

        def mock_opener(req: Any, timeout: float = 30) -> MockResponse:
            return MockResponse(gdelt_payload_with_body)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            adapter = GDELTAdapter(
                opener=mock_opener,
                retry_policy=RetryPolicy(max_attempts=1),
                sleep_fn=lambda _: None,
            )
            records = adapter.query_articles(
                query=self.query,
                start_date=self.start_date,
                end_date=self.end_date,
                event_id=self.event_id,
                raw_dir=root,
                output_dir=root,
            )

            self.assertEqual(len(records), 1)

            # Check that raw source artifact stripped forbidden body fields
            source_files = list(
                (root / "data" / "raw" / "source" / "gdelt" / self.event_id).glob("*.json")
            )
            self.assertEqual(len(source_files), 1)
            raw_stored = json.loads(source_files[0].read_text(encoding="utf-8"))

            for article in raw_stored["articles"]:
                self.assertNotIn("body", article)
                self.assertNotIn("article_text", article)
                self.assertNotIn("content", article)
                self.assertIn("url", article)
                self.assertIn("title", article)

    def test_gdelt_helpers(self) -> None:
        # Test GDELT datetime formatting
        formatted = _format_to_gdelt_datetime("2023-03-13T15:30:00Z")
        self.assertEqual(formatted, "20230313153000")

        # Test date-only format
        start_fmt = _format_to_gdelt_datetime("2023-03-13", is_end=False)
        self.assertEqual(start_fmt, "20230313000000")
        end_fmt = _format_to_gdelt_datetime("2023-03-13", is_end=True)
        self.assertEqual(end_fmt, "20230313235959")

        # Test GDELT seendate parsing
        self.assertEqual(
            _format_gdelt_seendate_to_utc("20230313T120000Z"),
            "2023-03-13T12:00:00Z",
        )
        self.assertEqual(
            _format_gdelt_seendate_to_utc("20230313120000"),
            "2023-03-13T12:00:00Z",
        )

        # Test metadata sanitization
        sanitized = _sanitize_article_metadata(
            {
                "url": "https://a.com",
                "title": "T",
                "body": "B",
                "content": "C",
            }
        )
        self.assertEqual(sanitized, {"url": "https://a.com", "title": "T"})


if __name__ == "__main__":
    unittest.main()
