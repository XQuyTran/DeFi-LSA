import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defi_lsa.adapters.defillama import DefiLlamaAdapter
from defi_lsa.retry import RateLimiter, RetryPolicy


class MockResponse:
    def __init__(self, body: dict[str, Any]):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return self.body


def _payload(address: str, *, timestamp: int, price: float = 1.0):
    return {
        "coins": {
            f"ethereum:{address}": {
                "symbol": "TKN",
                "price": price,
                "timestamp": timestamp,
                "confidence": 0.99,
            }
        }
    }


def test_defillama_backtracks_when_nearest_observation_is_after_anchor(tmp_path: Path):
    token_address = "0x" + "11" * 20
    anchor = 1678697794
    requested_urls: list[str] = []
    payloads = [
        _payload(token_address, timestamp=anchor + 85, price=10.0),
        _payload(token_address, timestamp=anchor - 218, price=9.0),
    ]

    def opener(request, timeout=30):
        requested_urls.append(request.full_url)
        return MockResponse(payloads.pop(0))

    adapter = DefiLlamaAdapter(
        opener=opener,
        retry_policy=RetryPolicy(max_attempts=1),
        rate_limiter=RateLimiter(requests_per_second=1000),
    )
    report_path = tmp_path / "reports" / "price_anchor_report.json"
    result = adapter.fetch_anchor_prices(
        event_id="euler",
        tokens=[{"symbol": "TKN", "address": token_address}],
        anchor_timestamp=datetime.fromtimestamp(anchor, timezone.utc),
        output_root=tmp_path,
        report_path=report_path,
    )

    assert result["prices"] == {"TKN": 9.0}
    assert result["records"][0]["observed_timestamp_utc"] == "2023-03-13T08:52:56Z"
    assert len(requested_urls) == 2
    assert not result["fallback_required"]
    assert report_path.exists()


def test_defillama_reports_exact_manual_fallback_timestamp(tmp_path: Path):
    token_address = "0x" + "22" * 20
    anchor = 1678697794

    def opener(request, timeout=30):
        return MockResponse({"coins": {}})

    adapter = DefiLlamaAdapter(
        opener=opener,
        retry_policy=RetryPolicy(max_attempts=1),
        rate_limiter=RateLimiter(requests_per_second=1000),
    )
    result = adapter.fetch_anchor_prices(
        event_id="euler",
        tokens=[{"symbol": "TKN", "address": token_address}],
        anchor_timestamp="2023-03-13T08:56:34Z",
        output_root=tmp_path,
        report_path=tmp_path / "price_anchor_report.json",
    )

    assert result["fallback_required"] == ["TKN"]
    assert result["fallback_price_timestamp_utc"] == "2023-03-13T08:56:34Z"