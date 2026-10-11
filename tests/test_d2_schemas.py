"""Tests for A16 normalized record schemas (test_d2_schemas.py).

All tests use deterministic local fixture dicts — no live I/O, no network
calls.  pyarrow is intentionally NOT imported here; Parquet-level tests
are exercised separately and are skipped automatically if pyarrow is absent.
"""

from __future__ import annotations

import pytest

from defi_lsa.schemas import (
    NORMALIZATION_VERSION,
    BlockRecord,
    LogRecord,
    PriceRecord,
    PublicInfoRecord,
    ReceiptRecord,
    TransactionRecord,
    normalize_block_record,
    normalize_log_record,
    normalize_price_record,
    normalize_public_info_record,
    normalize_receipt_record,
    normalize_transaction_record,
)

# ---------------------------------------------------------------------------
# Shared fixture values
# ---------------------------------------------------------------------------

_EVENT_ID = "evt-euler-2023"
_SHA256 = "a" * 64  # placeholder; any 64-char hex string works as a fixture
_TX_HASH = "0x" + "ab" * 32  # valid 64-hex-char tx hash
_BLOCK_HASH = "0x" + "cd" * 32  # valid 64-hex-char block hash
_ADDRESS = "0x" + "de" * 20  # valid 40-hex-char address
_TOPIC = "0x" + "ff" * 32  # valid 64-hex-char topic

# ---------------------------------------------------------------------------
# BlockRecord tests
# ---------------------------------------------------------------------------


def _block_raw(overrides: dict | None = None) -> dict:
    base = {
        "number": "0x109A2B0",  # 17,408,688 decimal
        "timestamp": "0x6411B793",  # ~1678892947
        "gasUsed": "0xE4E1C0",
        "hash": _BLOCK_HASH,
        "chainId": 1,
        "source": "rpc",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizeBlockRecord:
    def test_happy_path(self):
        rec = normalize_block_record(_block_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, BlockRecord)
        assert rec.block_number == 0x109A2B0
        assert rec.block_timestamp == 0x6411B793
        assert rec.gas_used == 0xE4E1C0
        assert rec.block_hash == _BLOCK_HASH.lower()
        assert rec.chain_id == 1
        assert rec.source == "rpc"
        assert rec.event_id == _EVENT_ID
        assert rec.source_sha256 == _SHA256
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_record_key_is_str_block_number(self):
        rec = normalize_block_record(_block_raw(), _EVENT_ID, _SHA256)
        assert rec.record_key == str(rec.block_number)

    def test_block_hash_lowercased(self):
        raw = _block_raw({"hash": _BLOCK_HASH.upper()})
        rec = normalize_block_record(raw, _EVENT_ID, _SHA256)
        assert rec.block_hash == _BLOCK_HASH.upper().lower()

    def test_missing_number_raises(self):
        raw = _block_raw()
        del raw["number"]
        with pytest.raises(ValueError, match="missing required field 'number'"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)

    def test_missing_timestamp_raises(self):
        raw = _block_raw()
        del raw["timestamp"]
        with pytest.raises(ValueError, match="missing required field 'timestamp'"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)

    def test_missing_gasused_raises(self):
        raw = _block_raw()
        del raw["gasUsed"]
        with pytest.raises(ValueError, match="missing required field 'gasUsed'"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)

    def test_missing_hash_raises(self):
        raw = _block_raw()
        del raw["hash"]
        with pytest.raises(ValueError, match="missing required field 'hash'"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)

    def test_invalid_source_raises(self):
        raw = _block_raw({"source": "infura"})
        with pytest.raises(ValueError, match="invalid source"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)

    def test_empty_event_id_raises(self):
        with pytest.raises(ValueError, match="event_id"):
            normalize_block_record(_block_raw(), "", _SHA256)

    def test_aws_source_accepted(self):
        raw = _block_raw({"source": "aws"})
        rec = normalize_block_record(raw, _EVENT_ID, _SHA256)
        assert rec.source == "aws"

    def test_chain_id_as_hex_string(self):
        raw = _block_raw({"chainId": "0x1"})
        rec = normalize_block_record(raw, _EVENT_ID, _SHA256)
        assert rec.chain_id == 1

    def test_invalid_block_hash_short_raises(self):
        raw = _block_raw({"hash": "0xdeadbeef"})
        with pytest.raises(ValueError, match="invalid block hash"):
            normalize_block_record(raw, _EVENT_ID, _SHA256)


# ---------------------------------------------------------------------------
# TransactionRecord tests
# ---------------------------------------------------------------------------


def _tx_raw(overrides: dict | None = None) -> dict:
    base = {
        "hash": _TX_HASH,
        "blockNumber": "0x109A2B0",
        "from": _ADDRESS,
        "to": "0x" + "aa" * 20,
        "value": "0xDE0B6B3A7640000",  # 1 ETH in wei = 10^18
        "gas": "0x15F90",
        "gasPrice": "0x3B9ACA00",  # 1 Gwei
        "nonce": "0x5",
        "chainId": 1,
        "source": "rpc",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizeTransactionRecord:
    def test_happy_path(self):
        rec = normalize_transaction_record(_tx_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, TransactionRecord)
        assert rec.tx_hash == _TX_HASH.lower()
        assert rec.record_key == rec.tx_hash
        assert rec.from_address == _ADDRESS.lower()
        assert rec.to_address == ("0x" + "aa" * 20).lower()
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_value_wei_exact_int(self):
        rec = normalize_transaction_record(_tx_raw(), _EVENT_ID, _SHA256)
        # 1 ETH = 1_000_000_000_000_000_000 wei
        assert rec.value_wei == 1_000_000_000_000_000_000
        assert isinstance(rec.value_wei, int)

    def test_gas_price_exact_int(self):
        rec = normalize_transaction_record(_tx_raw(), _EVENT_ID, _SHA256)
        assert rec.gas_price == 1_000_000_000  # 1 Gwei
        assert isinstance(rec.gas_price, int)

    def test_contract_creation_no_to(self):
        raw = _tx_raw()
        del raw["to"]
        rec = normalize_transaction_record(raw, _EVENT_ID, _SHA256)
        assert rec.to_address == ""

    def test_contract_creation_null_to(self):
        raw = _tx_raw({"to": None})
        rec = normalize_transaction_record(raw, _EVENT_ID, _SHA256)
        assert rec.to_address == ""

    def test_inclusion_reasons_default(self):
        rec = normalize_transaction_record(_tx_raw(), _EVENT_ID, _SHA256)
        assert rec.inclusion_reasons == ("direct_call",)

    def test_inclusion_reasons_custom(self):
        rec = normalize_transaction_record(
            _tx_raw(),
            _EVENT_ID,
            _SHA256,
            inclusion_reasons=("scoped_log", "registry_anchor"),
        )
        assert rec.inclusion_reasons == ("scoped_log", "registry_anchor")

    def test_invalid_inclusion_reason_raises(self):
        with pytest.raises(ValueError, match="invalid inclusion_reason"):
            normalize_transaction_record(
                _tx_raw(),
                _EVENT_ID,
                _SHA256,
                inclusion_reasons=("unknown_reason",),
            )

    def test_empty_inclusion_reasons_raises(self):
        with pytest.raises(ValueError, match="inclusion_reasons"):
            normalize_transaction_record(
                _tx_raw(), _EVENT_ID, _SHA256, inclusion_reasons=()
            )

    def test_missing_hash_raises(self):
        raw = _tx_raw()
        del raw["hash"]
        with pytest.raises(ValueError, match="missing required field 'hash'"):
            normalize_transaction_record(raw, _EVENT_ID, _SHA256)

    def test_missing_value_raises(self):
        raw = _tx_raw()
        del raw["value"]
        with pytest.raises(ValueError, match="missing required field 'value'"):
            normalize_transaction_record(raw, _EVENT_ID, _SHA256)

    def test_missing_gas_price_raises(self):
        raw = _tx_raw()
        del raw["gasPrice"]
        with pytest.raises(ValueError, match="missing required field 'gasPrice'"):
            normalize_transaction_record(raw, _EVENT_ID, _SHA256)

    def test_large_value_wei_preserved(self):
        # 100 ETH — check Python big int is preserved
        hundred_eth = 100 * 10**18
        raw = _tx_raw({"value": hex(hundred_eth)})
        rec = normalize_transaction_record(raw, _EVENT_ID, _SHA256)
        assert rec.value_wei == hundred_eth


# ---------------------------------------------------------------------------
# ReceiptRecord tests
# ---------------------------------------------------------------------------


def _receipt_raw(overrides: dict | None = None) -> dict:
    base = {
        "transactionHash": _TX_HASH,
        "blockNumber": "0x109A2B0",
        "status": "0x1",
        "gasUsed": "0x7A120",
        "logs": [{}, {}, {}],  # 3 dummy log objects
        "chainId": 1,
        "source": "rpc",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizeReceiptRecord:
    def test_happy_path(self):
        rec = normalize_receipt_record(_receipt_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, ReceiptRecord)
        assert rec.tx_hash == _TX_HASH.lower()
        assert rec.record_key == rec.tx_hash
        assert rec.status == 1
        assert rec.log_count == 3
        assert rec.gas_used == 0x7A120
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_status_zero(self):
        raw = _receipt_raw({"status": "0x0"})
        rec = normalize_receipt_record(raw, _EVENT_ID, _SHA256)
        assert rec.status == 0

    def test_invalid_status_raises(self):
        raw = _receipt_raw({"status": "0x2"})
        with pytest.raises(ValueError, match="invalid receipt status"):
            normalize_receipt_record(raw, _EVENT_ID, _SHA256)

    def test_missing_status_raises(self):
        raw = _receipt_raw()
        del raw["status"]
        with pytest.raises(ValueError, match="missing required field 'status'"):
            normalize_receipt_record(raw, _EVENT_ID, _SHA256)

    def test_logs_not_list_raises(self):
        raw = _receipt_raw({"logs": "not-a-list"})
        with pytest.raises(ValueError, match="'logs' must be a list"):
            normalize_receipt_record(raw, _EVENT_ID, _SHA256)

    def test_log_count_from_logs_length(self):
        raw = _receipt_raw({"logs": [{}, {}, {}, {}, {}]})
        rec = normalize_receipt_record(raw, _EVENT_ID, _SHA256)
        assert rec.log_count == 5


# ---------------------------------------------------------------------------
# LogRecord tests
# ---------------------------------------------------------------------------


def _log_raw(overrides: dict | None = None) -> dict:
    base = {
        "transactionHash": _TX_HASH,
        "logIndex": "0x3",
        "blockNumber": "0x109A2B0",
        "address": _ADDRESS,
        "topics": [_TOPIC, "0x" + "00" * 32],
        "data": "0xdeadbeef",
        "chainId": 1,
        "source": "rpc",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizeLogRecord:
    def test_happy_path(self):
        rec = normalize_log_record(_log_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, LogRecord)
        assert rec.tx_hash == _TX_HASH.lower()
        assert rec.log_index == 3
        assert rec.block_number == 0x109A2B0
        assert rec.address == _ADDRESS.lower()
        assert rec.data == "0xdeadbeef"
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_record_key_format(self):
        """Log record key must be '{chain_id}:{tx_hash}:{log_index}'."""
        rec = normalize_log_record(_log_raw(), _EVENT_ID, _SHA256)
        expected = f"1:{_TX_HASH.lower()}:3"
        assert rec.record_key == expected

    def test_record_key_format_with_different_chain(self):
        raw = _log_raw({"chainId": 137, "logIndex": "0xa"})
        rec = normalize_log_record(raw, _EVENT_ID, _SHA256)
        assert rec.record_key == f"137:{_TX_HASH.lower()}:10"

    def test_topics_are_tuple(self):
        rec = normalize_log_record(_log_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec.topics, tuple)
        assert len(rec.topics) == 2

    def test_topics_lowercased(self):
        upper_topic = ("0x" + "FF" * 32)
        raw = _log_raw({"topics": [upper_topic]})
        rec = normalize_log_record(raw, _EVENT_ID, _SHA256)
        assert rec.topics[0] == upper_topic.lower()

    def test_empty_topics_allowed(self):
        raw = _log_raw({"topics": []})
        rec = normalize_log_record(raw, _EVENT_ID, _SHA256)
        assert rec.topics == ()

    def test_invalid_topic_raises(self):
        raw = _log_raw({"topics": ["not-a-valid-topic"]})
        with pytest.raises(ValueError, match="invalid topic"):
            normalize_log_record(raw, _EVENT_ID, _SHA256)

    def test_missing_address_raises(self):
        raw = _log_raw()
        del raw["address"]
        with pytest.raises(ValueError, match="missing required field 'address'"):
            normalize_log_record(raw, _EVENT_ID, _SHA256)

    def test_data_not_0x_prefixed_raises(self):
        raw = _log_raw({"data": "deadbeef"})
        with pytest.raises(ValueError, match="must be 0x-prefixed"):
            normalize_log_record(raw, _EVENT_ID, _SHA256)

    def test_empty_data_field(self):
        """data='0x' (empty) is valid for logs with no data."""
        raw = _log_raw({"data": "0x"})
        rec = normalize_log_record(raw, _EVENT_ID, _SHA256)
        assert rec.data == "0x"


# ---------------------------------------------------------------------------
# PriceRecord tests
# ---------------------------------------------------------------------------

# Unix timestamp for 2023-03-13T12:34:56Z (within hour 12:00)
_TS_IN_HOUR_12 = 1678710896  # 2023-03-13T12:34:56Z


def _price_raw(overrides: dict | None = None) -> dict:
    base = {
        "token_address": _ADDRESS,
        "coingecko_id": "euler",
        "source_timestamp": _TS_IN_HOUR_12,
        "usd_price": 4.52,
        "source": "coingecko",
        "retrieved_at_utc": "2023-03-13T12:35:00Z",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizePriceRecord:
    def test_happy_path(self):
        rec = normalize_price_record(_price_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, PriceRecord)
        assert rec.token_address == _ADDRESS.lower()
        assert rec.coingecko_id == "euler"
        assert rec.usd_price == 4.52
        assert rec.source == "coingecko"
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_hour_utc_truncated_to_hour(self):
        """source_timestamp in the middle of an hour → hour_utc at :00:00."""
        rec = normalize_price_record(_price_raw(), _EVENT_ID, _SHA256)
        # 2023-03-13T12:34:56Z truncated to hour = 2023-03-13T12:00:00Z
        assert rec.hour_utc == "2023-03-13T12:00:00Z"

    def test_hour_utc_on_exact_boundary(self):
        """source_timestamp exactly on the hour stays at :00:00."""
        # 2023-03-13T12:00:00Z in unix seconds
        exact_hour_ts = 1678708800
        raw = _price_raw({"source_timestamp": exact_hour_ts})
        rec = normalize_price_record(raw, _EVENT_ID, _SHA256)
        assert rec.hour_utc == "2023-03-13T12:00:00Z"

    def test_record_key_format(self):
        rec = normalize_price_record(_price_raw(), _EVENT_ID, _SHA256)
        assert rec.record_key == f"{_ADDRESS.lower()}:2023-03-13T12:00:00Z"

    def test_missing_token_address_raises(self):
        raw = _price_raw()
        del raw["token_address"]
        with pytest.raises(ValueError, match="missing required field 'token_address'"):
            normalize_price_record(raw, _EVENT_ID, _SHA256)

    def test_missing_usd_price_raises(self):
        raw = _price_raw()
        del raw["usd_price"]
        with pytest.raises(ValueError, match="missing required field 'usd_price'"):
            normalize_price_record(raw, _EVENT_ID, _SHA256)

    def test_non_numeric_source_timestamp_raises(self):
        raw = _price_raw({"source_timestamp": "not-a-number"})
        with pytest.raises(ValueError, match="source_timestamp must be numeric"):
            normalize_price_record(raw, _EVENT_ID, _SHA256)

    def test_usd_price_non_numeric_raises(self):
        raw = _price_raw({"usd_price": "expensive"})
        with pytest.raises(ValueError, match="usd_price must be numeric"):
            normalize_price_record(raw, _EVENT_ID, _SHA256)

    def test_float_source_timestamp_truncated(self):
        raw = _price_raw({"source_timestamp": 1678708496.9})
        rec = normalize_price_record(raw, _EVENT_ID, _SHA256)
        assert rec.source_timestamp == 1678708496
        assert isinstance(rec.source_timestamp, int)


# ---------------------------------------------------------------------------
# PublicInfoRecord tests
# ---------------------------------------------------------------------------


def _pub_raw(overrides: dict | None = None) -> dict:
    base = {
        "url": "https://forum.euler.finance/t/euler-hack/42",
        "canonical_url": "https://forum.euler.finance/t/euler-hack/42",
        "title": "Euler Finance Post-Mortem",
        "published_at_utc": "2023-03-13T14:00:00Z",
        "source": "discourse",
    }
    if overrides:
        base.update(overrides)
    return base


class TestNormalizePublicInfoRecord:
    def test_happy_path(self):
        rec = normalize_public_info_record(_pub_raw(), _EVENT_ID, _SHA256)
        assert isinstance(rec, PublicInfoRecord)
        assert rec.url == "https://forum.euler.finance/t/euler-hack/42"
        assert rec.title == "Euler Finance Post-Mortem"
        assert rec.source == "discourse"
        assert rec.normalization_version == NORMALIZATION_VERSION

    def test_record_key_format(self):
        rec = normalize_public_info_record(_pub_raw(), _EVENT_ID, _SHA256)
        expected = f"discourse:{_pub_raw()['url']}"
        assert rec.record_key == expected

    def test_protocol_source_accepted(self):
        raw = _pub_raw({"source": "protocol"})
        rec = normalize_public_info_record(raw, _EVENT_ID, _SHA256)
        assert rec.source == "protocol"

    def test_gdelt_source_accepted(self):
        raw = _pub_raw({"source": "gdelt"})
        rec = normalize_public_info_record(raw, _EVENT_ID, _SHA256)
        assert rec.source == "gdelt"

    def test_invalid_source_raises(self):
        raw = _pub_raw({"source": "twitter"})
        with pytest.raises(ValueError, match="invalid source"):
            normalize_public_info_record(raw, _EVENT_ID, _SHA256)

    def test_missing_url_raises(self):
        raw = _pub_raw()
        del raw["url"]
        with pytest.raises(ValueError, match="missing required field 'url'"):
            normalize_public_info_record(raw, _EVENT_ID, _SHA256)

    def test_missing_title_raises(self):
        raw = _pub_raw()
        del raw["title"]
        with pytest.raises(ValueError, match="missing required field 'title'"):
            normalize_public_info_record(raw, _EVENT_ID, _SHA256)

    def test_missing_published_at_utc_raises(self):
        raw = _pub_raw()
        del raw["published_at_utc"]
        with pytest.raises(ValueError, match="missing required field 'published_at_utc'"):
            normalize_public_info_record(raw, _EVENT_ID, _SHA256)


# ---------------------------------------------------------------------------
# Cross-cutting: normalization_version constant
# ---------------------------------------------------------------------------


class TestNormalizationVersion:
    def test_version_is_string(self):
        assert isinstance(NORMALIZATION_VERSION, str)

    def test_version_format(self):
        parts = NORMALIZATION_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_all_record_types_carry_version(self):
        block = normalize_block_record(_block_raw(), _EVENT_ID, _SHA256)
        tx = normalize_transaction_record(_tx_raw(), _EVENT_ID, _SHA256)
        receipt = normalize_receipt_record(_receipt_raw(), _EVENT_ID, _SHA256)
        log = normalize_log_record(_log_raw(), _EVENT_ID, _SHA256)
        price = normalize_price_record(_price_raw(), _EVENT_ID, _SHA256)
        pub = normalize_public_info_record(_pub_raw(), _EVENT_ID, _SHA256)

        for rec in (block, tx, receipt, log, price, pub):
            assert rec.normalization_version == NORMALIZATION_VERSION


# ---------------------------------------------------------------------------
# Integer precision tests
# ---------------------------------------------------------------------------


class TestIntegerPrecision:
    def test_value_wei_no_float_drift(self):
        """1 ETH must be stored as exact int, not a float that loses precision."""
        one_eth_wei = 10**18
        raw = _tx_raw({"value": hex(one_eth_wei)})
        rec = normalize_transaction_record(raw, _EVENT_ID, _SHA256)
        assert rec.value_wei == one_eth_wei
        assert type(rec.value_wei) is int

    def test_gas_price_exact_int(self):
        gwei_100 = 100 * 10**9
        raw = _tx_raw({"gasPrice": hex(gwei_100)})
        rec = normalize_transaction_record(raw, _EVENT_ID, _SHA256)
        assert rec.gas_price == gwei_100
        assert type(rec.gas_price) is int

    def test_block_timestamp_exact_int(self):
        raw = _block_raw({"timestamp": "0x6411B793"})
        rec = normalize_block_record(raw, _EVENT_ID, _SHA256)
        assert type(rec.block_timestamp) is int
        assert rec.block_timestamp == 0x6411B793
