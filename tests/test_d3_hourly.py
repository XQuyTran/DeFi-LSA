import hashlib
import json
import math
from pathlib import Path

import pytest

from defi_lsa.d3_hourly import build_hourly_panel, freeze_hourly_dataset


def _panel_inputs():
    token = {"symbol": "WETH", "address": "0xweth", "decimals": 18}
    coverage = {
        "2023-03-13T00:00:00Z": {"missing_blocks": 0, "missing_receipts": 0},
        "2023-03-13T01:00:00Z": {"missing_blocks": 1, "missing_receipts": 0},
    }
    legs = [
        {
            "token_address": "0xweth",
            "block_number": 10,
            "flow_label": "user_net_flow",
            "value_wei": "2000000000000000000",
        }
    ]
    return token, coverage, legs


def test_hourly_panel_distinguishes_empty_complete_from_missing_chain_data():
    token, coverage, legs = _panel_inputs()
    rows = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=2,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 1600},
    )

    assert rows[0]["data_status"] == "COMPLETE"
    assert rows[0]["user_net_flow_token"] == 2.0
    assert rows[0]["user_net_flow_usd"] == 3200.0
    assert rows[1]["data_status"] == "MISSING_CHAIN_DATA"
    assert math.isnan(rows[1]["user_net_flow_token"])
    assert rows[0]["attacker_drain_token"] == 0.0


def test_hourly_panel_never_substitutes_zero_for_missing_price():
    token, coverage, legs = _panel_inputs()
    rows = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=1,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 0},
    )

    assert rows[0]["price_status"] == "MISSING_PRICE"
    assert math.isnan(rows[0]["usd_price_anchor"])
    assert math.isnan(rows[0]["user_net_flow_usd"])


def test_hourly_schema_rejects_zero_price_and_non_nan_missing_metrics():
    from defi_lsa.d3_schemas import validate_d3_record

    token, coverage, legs = _panel_inputs()
    row = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=1,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 1600},
    )[0]
    row["usd_price_anchor"] = 0

    with pytest.raises(ValueError, match="positive"):
        validate_d3_record("hourly_panel", row)


def test_freeze_validates_rows_and_records_output_hashes(tmp_path: Path, monkeypatch):
    token, coverage, legs = _panel_inputs()
    rows = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=2,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 1600},
    )

    def fake_parquet(jsonl_path: Path, schema_name: str, output_path: Path):
        assert schema_name == "hourly_panel"
        output_path.write_bytes(b"test parquet bytes")
        return 2

    monkeypatch.setattr("defi_lsa.d3_hourly.jsonl_to_parquet", fake_parquet)
    manifest = freeze_hourly_dataset(
        rows,
        tmp_path,
        required_hours=2,
        required_tokens={"WETH"},
    )

    csv_path = tmp_path / "dataset_euler_v1.csv"
    parquet_path = tmp_path / "dataset_euler_v1.parquet"
    assert manifest["row_count"] == 2
    assert manifest["artifacts"][csv_path.name] == hashlib.sha256(csv_path.read_bytes()).hexdigest()
    assert manifest["artifacts"][parquet_path.name] == hashlib.sha256(parquet_path.read_bytes()).hexdigest()
    assert json.loads((tmp_path / "dataset_manifest.json").read_text())["hour_count"] == 2


def test_freeze_rejects_non_contiguous_hours(tmp_path: Path):
    token, coverage, legs = _panel_inputs()
    rows = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=2,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 1600},
    )
    rows[1]["hour_start_utc"] = "2023-03-13T03:00:00Z"

    with pytest.raises(ValueError, match="contiguous"):
        freeze_hourly_dataset(
            rows,
            tmp_path,
            required_hours=2,
            required_tokens={"WETH"},
        )


def test_freeze_refuses_to_overwrite_an_existing_version(tmp_path: Path, monkeypatch):
    token, coverage, legs = _panel_inputs()
    rows = build_hourly_panel(
        "euler",
        start_utc="2023-03-13T00:00:00Z",
        hours=2,
        tokens=[token],
        hourly_coverage=coverage,
        flow_legs=legs,
        block_timestamps={10: 1678667400},
        anchor_prices={"WETH": 1600},
    )
    (tmp_path / "dataset_euler_v1.csv").write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        freeze_hourly_dataset(
            rows,
            tmp_path,
            required_hours=2,
            required_tokens={"WETH"},
        )