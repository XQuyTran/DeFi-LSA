import json
from pathlib import Path
from urllib.error import HTTPError

from defi_lsa.config import SourceConfig, load_source_config
from defi_lsa.connectivity import probe_source
from defi_lsa.observability import CollectionMetrics


class FakeResponse:
    def __init__(self, payload: object):
        self.payload = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


def make_config(**overrides):
    values = {
        "ethereum_rpc_url": "https://rpc.example.test/token",
        "etherscan_api_key": "ETHERSCAN_SECRET",
        "coingecko_api_key": "COINGECKO_SECRET",
        "forums": {"probe_url": "https://forum.example.test/latest.json"},
        "aws_public_blockchain": {
            "bucket": "bucket",
            "region": "us-east-2",
            "tables": {"logs": "logs/date={YYYY-MM-DD}/"},
        },
    }
    values.update(overrides)
    return SourceConfig(**values)


def test_default_config_loads_committed_source_file(monkeypatch):
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    config = load_source_config()

    assert config.source_priority["prices"] == ("chainlink", "onchain_pool", "coingecko")
    assert config.aws_public_blockchain["bucket"] == "aws-public-blockchain"


def test_priority_for_filters_without_reordering():
    config = make_config(source_priority={"prices": ("chainlink", "coingecko")})

    assert config.priority_for("prices") == ("chainlink", "coingecko")
    assert config.priority_for("prices", {"coingecko"}) == ("coingecko",)


def test_duplicate_priority_is_rejected():
    config = make_config(source_priority={"prices": ("coingecko", "coingecko")})

    try:
        config.validate()
    except ValueError as exc:
        assert "duplicates" in str(exc)
    else:
        raise AssertionError("duplicate source priority was accepted")


def test_unknown_priority_source_is_rejected():
    config = make_config(source_priority={"logs": ("unknown_source",)})

    try:
        config.validate()
    except ValueError as exc:
        assert "unknown sources" in str(exc)
    else:
        raise AssertionError("unknown source priority was accepted")


def test_select_source_uses_configured_order():
    config = make_config(source_priority={"logs": ("aws_public_blockchain", "ethereum_rpc")})

    assert config.select_source("logs", {"ethereum_rpc"}) == "ethereum_rpc"


def test_select_source_rejects_empty_available_sources():
    config = make_config(source_priority={"logs": ("ethereum_rpc",)})

    try:
        config.select_source("logs", set())
    except ValueError as exc:
        assert "no configured source" in str(exc)
    else:
        raise AssertionError("empty source selection was accepted")


def test_nested_aws_configuration_is_validated():
    config = make_config(aws_public_blockchain={"enabled": True, "bucket": "bucket"})

    try:
        config.validate()
    except ValueError as exc:
        assert "aws_public_blockchain.region" in str(exc)
    else:
        raise AssertionError("incomplete AWS configuration was accepted")


def test_rpc_probe_rejects_wrong_chain():
    config = make_config()

    result = probe_source(
        config,
        "rpc",
        opener=lambda request, timeout: FakeResponse({"jsonrpc": "2.0", "id": 1, "result": "0x89"}),
    )

    assert result.status == "invalid_request"
    assert result.details["error_type"] == "InvalidRequestError"


def test_etherscan_probe_classifies_authentication_response():
    config = make_config()

    result = probe_source(
        config,
        "etherscan",
        opener=lambda request, timeout: FakeResponse({
            "status": "0",
            "message": "NOTOK",
            "result": "Invalid API Key",
        }),
    )

    assert result.status == "authentication_error"


def test_forum_probe_performs_json_request():
    config = make_config()

    result = probe_source(
        config,
        "forums",
        opener=lambda request, timeout: FakeResponse({"topic_list": {"topics": []}}),
    )

    assert result.status == "reachable"


def test_disabled_source_is_not_requested():
    config = make_config(enabled_sources={"coingecko": False})

    def opener(request, timeout):
        raise AssertionError("disabled source was requested")

    result = probe_source(config, "coingecko", opener=opener)

    assert result.status == "disabled"


def test_probe_maps_http_authentication_error():
    config = make_config()

    def opener(request, timeout):
        raise HTTPError(request.full_url, 403, "Forbidden", {}, None)

    result = probe_source(config, "coingecko", opener=opener)

    assert result.status == "authentication_error"


def test_probe_retries_transient_failure_before_success():
    config = make_config(maximum_attempts=3, requests_per_second=1000.0)
    attempts = []
    sleeps = []

    def opener(request, timeout):
        attempts.append(1)
        if len(attempts) < 3:
            raise TimeoutError("temporary timeout")
        return FakeResponse({"gecko_says": "(V3) To the moon!"})

    result = probe_source(
        config,
        "coingecko",
        opener=opener,
        sleep_fn=sleeps.append,
    )

    assert result.status == "reachable"
    assert len(attempts) == 3
    assert sleeps == [0.1, 0.2]


def test_probe_does_not_retry_authentication_failure():
    config = make_config(maximum_attempts=3, requests_per_second=1000.0)
    attempts = []

    def opener(request, timeout):
        attempts.append(1)
        raise HTTPError(request.full_url, 403, "Forbidden", {}, None)

    result = probe_source(
        config,
        "coingecko",
        opener=opener,
        sleep_fn=lambda delay: (_ for _ in ()).throw(AssertionError("unexpected retry")),
    )

    assert result.status == "authentication_error"
    assert len(attempts) == 1


def test_metrics_redact_error_message_and_context(tmp_path: Path):
    metrics = CollectionMetrics(event_id="fixture", collector="connectivity")
    metrics.record_error(
        RuntimeError("request https://node.example.test/v3/SUPER_SECRET failed"),
        response_url="https://api.example.test/?apikey=API_SECRET",
    )
    output = tmp_path / "summary.json"
    metrics.write_summary(output)
    payload = output.read_text(encoding="utf-8")

    assert "SUPER_SECRET" not in payload
    assert "API_SECRET" not in payload
    assert "[REDACTED]" in payload
