from defi_lsa.aws import (
    AWS_TABLE_CONTRACTS,
    AwsPublicBlockchainAdapter,
    AwsSchemaError,
    filter_aws_records_by_scope,
    normalize_aws_block_record,
    normalize_aws_log_record,
    normalize_aws_transaction_record,
)


def test_aws_partition_dates_are_expanded_deterministically():
    adapter = AwsPublicBlockchainAdapter(lambda *_: [])

    assert adapter.list_aws_partitions("2023-03-13", "2023-03-15") == [
        {"date": "2023-03-13"},
        {"date": "2023-03-14"},
        {"date": "2023-03-15"},
    ]


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
