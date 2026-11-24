from defi_lsa.aws import (
    AWS_TABLE_CONTRACTS,
    AwsPublicBlockchainAdapter,
    AwsSchemaError,
    estimate_block_date,
    filter_aws_records_by_scope,
    normalize_aws_block_record,
    normalize_aws_contract_record,
    normalize_aws_log_record,
    normalize_aws_token_transfer_record,
    normalize_aws_transaction_record,
    normalize_aws_trace_record,
    reconcile_source_records,
    _post_filter_rows,
)


def test_aws_partition_dates_are_expanded_deterministically():
    adapter = AwsPublicBlockchainAdapter(lambda *_: [])

    assert adapter.list_aws_partitions("2023-03-13", "2023-03-15") == [
        {"date": "2023-03-13"},
        {"date": "2023-03-14"},
        {"date": "2023-03-15"},
    ]


def test_estimate_block_date_and_partition_inference():
    # Genesis and post-merge known dates
    assert estimate_block_date(0).isoformat() == "2015-07-30"
    assert estimate_block_date(15537393).isoformat() == "2022-09-15"
    assert estimate_block_date(16818024).isoformat() == "2023-03-13"

    adapter = AwsPublicBlockchainAdapter()
    # When start_date and end_date are None, partition_paths infers from blocks in _fetch
    paths = adapter._partition_paths("logs", "2023-03-13", "2023-03-13")
    assert paths == ["s3://aws-public-blockchain/v1.0/eth/logs/date=2023-03-13"]


def test_aws_query_seam_preserves_filters_and_table_contracts():
    calls = []

    def query(table, filters):
        calls.append((table, filters))
        return [{"transaction_hash": "0xabc", "block_number": 12}]

    adapter = AwsPublicBlockchainAdapter(query)
    rows = adapter.fetch_table(
        "logs",
        start_block=10,
        end_block=20,
        transaction_hashes=["0xABC"],
        addresses=["0xDef"],
    )

    assert rows == [{"transaction_hash": "0xabc", "block_number": 12}]
    assert calls == [
        (
            "logs",
            {
                "start_block": 10,
                "end_block": 20,
                "transaction_hashes": ["0xABC"],
                "addresses": ["0xDef"],
            },
        )
    ]
    assert set(AWS_TABLE_CONTRACTS) == {
        "blocks",
        "transactions",
        "logs",
        "token_transfers",
        "traces",
        "contracts",
    }


def test_aws_block_filter_ignores_transaction_hash_without_block_column():
    row = {
        "number": 18630392,
        "timestamp": 1700693711,
        "gas_used": 1,
        "hash": "0x" + "a" * 64,
    }

    assert _post_filter_rows(
        [row],
        AWS_TABLE_CONTRACTS["blocks"],
        {
            "start_block": 18630392,
            "end_block": 18630392,
            "transaction_hashes": ["0x" + "b" * 64],
        },
    ) == [
        {
            "number": 18630392,
            "timestamp": 1700693711,
            "gas_used": 1,
            "hash": "0x" + "a" * 64,
        }
    ]


def test_aws_transaction_filter_uses_transaction_hash_column():
    matching = {"hash": "0x" + "a" * 64, "block_number": 12}
    other = {"hash": "0x" + "b" * 64, "block_number": 12}

    assert _post_filter_rows(
        [matching, other],
        AWS_TABLE_CONTRACTS["transactions"],
        {"transaction_hashes": [matching["hash"]]},
    ) == [matching]


def test_aws_scope_filter_matches_sender_recipient_or_emitter():
    rows = [
        {"from": "0xA", "to": "0xB", "address": "0xC"},
        {"from": "0xD", "to": "0xE", "address": "0xF"},
    ]

    assert filter_aws_records_by_scope(rows, ["0xa", "0xf"]) == rows


def test_aws_schema_error_is_explicit():
    adapter = AwsPublicBlockchainAdapter()
    try:
        adapter._validate_columns(["block_number"], AWS_TABLE_CONTRACTS["blocks"])
    except AwsSchemaError as exc:
        assert "missing required columns" in str(exc)
    else:
        raise AssertionError("missing AWS columns must fail explicitly")


def test_aws_rows_use_canonical_record_shapes():
    block = normalize_aws_block_record(
        {
            "block_number": 12,
            "timestamp": 1678708800,
            "gas_used": 100,
            "hash": "0x" + "a" * 64,
        },
        "event",
        "b" * 64,
    )
    transaction = normalize_aws_transaction_record(
        {
            "hash": "0x" + "b" * 64,
            "block_number": 12,
            "from": "0x" + "1" * 40,
            "to": "0x" + "2" * 40,
            "value": 0,
            "gas": 21000,
            "gas_price": 1,
            "nonce": 0,
        },
        "event",
        "c" * 64,
    )
    log = normalize_aws_log_record(
        {
            "transaction_hash": "0x" + "b" * 64,
            "log_index": 0,
            "block_number": 12,
            "address": "0x" + "3" * 40,
            "topics": ["0x" + "4" * 64],
            "data": "0x",
        },
        "event",
        "d" * 64,
    )

    assert block["source"] == "aws"
    assert transaction["record_key"] == "0x" + "b" * 64
    assert log["record_key"] == f"1:0x{'b' * 64}:0"


def test_aws_extended_rows_preserve_exact_values_and_identity():
    tx_hash = "0x" + "b" * 64
    transfer = normalize_aws_token_transfer_record(
        {
            "transaction_hash": tx_hash,
            "log_index": 4,
            "block_number": 12,
            "token_address": "0x" + "1" * 40,
            "from": "0x" + "2" * 40,
            "to": "0x" + "3" * 40,
            "value": 2**255 + 1,
        },
        "event",
        "a" * 64,
    )
    trace = normalize_aws_trace_record(
        {
            "transaction_hash": tx_hash,
            "trace_address": [0, 3, 1],
            "block_number": 12,
            "from": "0x" + "2" * 40,
            "to": None,
            "value": 7,
        },
        "event",
        "b" * 64,
    )
    contract = normalize_aws_contract_record(
        {"address": "0x" + "4" * 40, "block_number": 12},
        "event",
        "c" * 64,
    )

    assert transfer["value_wei"] == 2**255 + 1
    assert transfer["record_key"] == f"1:{tx_hash}:4"
    assert trace["trace_address"] == (0, 3, 1)
    assert trace["record_key"] == f"1:{tx_hash}:0.3.1"
    assert trace["to_address"] == ""
    assert contract["record_key"] == f"1:0x{'4' * 40}"


def test_aws_extended_rows_unpad_abi_encoded_addresses():
    padded_address = "0x" + "0" * 24 + "4d5f47fa6a74757f35c14fd3a6ef8e3c9bc514e8"

    transfer = normalize_aws_token_transfer_record(
        {
            "transaction_hash": "0x" + "b" * 64,
            "log_index": 0,
            "block_number": 12,
            "token_address": padded_address,
            "from_address": padded_address,
            "to_address": padded_address,
            "value": 1,
        },
        "event",
        "a" * 64,
    )

    expected_address = "0x" + padded_address[-40:].lower()
    assert transfer["token_address"] == expected_address
    assert transfer["from_address"] == expected_address


def test_aws_trace_rows_parse_serialized_trace_address():
    trace = normalize_aws_trace_record(
        {
            "transaction_hash": "0x" + "b" * 64,
            "trace_address": "[0, 3, 1]",
            "block_number": 12,
            "from_address": "0x" + "2" * 40,
            "to_address": "0x" + "3" * 40,
            "value": 7,
        },
        "event",
        "b" * 64,
    )

    assert trace["trace_address"] == (0, 3, 1)


def test_aws_trace_rows_treat_null_trace_address_as_root():
    trace = normalize_aws_trace_record(
        {
            "transaction_hash": "0x" + "b" * 64,
            "trace_address": None,
            "block_number": 12,
            "from_address": "0x" + "2" * 40,
            "to_address": "0x" + "3" * 40,
            "value": 7,
        },
        "event",
        "b" * 64,
    )

    assert trace["trace_address"] == ()
    assert trace["record_key"].endswith(":root")


def test_aws_trace_rows_parse_scalar_trace_address_encodings():
    base = {
        "transaction_hash": "0x" + "b" * 64,
        "block_number": 12,
        "from_address": "0x" + "2" * 40,
        "to_address": "0x" + "3" * 40,
        "value": 7,
    }

    for encoded in (b"[0, 3, 1]", 0, 0.0, "0.0", "{0;3;1}", "root"):
        trace = normalize_aws_trace_record(
            {**base, "trace_address": encoded}, "event", "b" * 64
        )
        assert trace["trace_address"] in {(0, 3, 1), (0,), ()}


def test_aws_rpc_conflict_retains_both_source_records():
    aws_record = {
        "record_key": "1:0x" + "a" * 64 + ":0",
        "tx_hash": "0x" + "a" * 64,
        "log_index": 0,
        "data": "0x01",
        "source": "aws",
        "source_sha256": "a" * 64,
    }
    rpc_record = {
        **aws_record,
        "data": "0x02",
        "source": "rpc",
        "source_sha256": "b" * 64,
    }

    report = reconcile_source_records([aws_record], [rpc_record], "record_key")

    assert report["status"] == "mismatch"
    assert report["conflicts"][0]["primary"]["data"] == "0x01"
    assert report["conflicts"][0]["secondary"]["data"] == "0x02"
