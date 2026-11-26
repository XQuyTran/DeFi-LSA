from eth_abi import encode
from eth_utils import keccak

from defi_lsa.d3_decoding import (
    aggregate_unknown_records,
    decode_input_data,
    decode_log,
    event_topic0,
    function_selector,
    unknown_record,
)


TRANSFER_EVENT = {
    "type": "event",
    "name": "Transfer",
    "inputs": [
        {"name": "from", "type": "address", "indexed": True},
        {"name": "to", "type": "address", "indexed": True},
        {"name": "value", "type": "uint256", "indexed": False},
    ],
}

FLASH_LOAN_FUNCTION = {
    "type": "function",
    "name": "flashLoan",
    "inputs": [
        {"name": "receiver", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ],
}


def test_decode_indexed_transfer_event():
    from_address = "0x" + "11" * 20
    to_address = "0x" + "22" * 20
    log = {
        "topics": [
            event_topic0(TRANSFER_EVENT),
            "0x" + ("00" * 12) + from_address[2:],
            "0x" + ("00" * 12) + to_address[2:],
        ],
        "data": "0x" + encode(["uint256"], [123]).hex(),
    }

    decoded = decode_log(log, [TRANSFER_EVENT])

    assert decoded is not None
    assert decoded["event_name"] == "Transfer"
    assert decoded["arguments"] == {
        "from": from_address,
        "to": to_address,
        "value": 123,
    }


def test_decode_function_input():
    receiver = "0x" + "33" * 20
    calldata = function_selector(FLASH_LOAN_FUNCTION) + encode(
        ["address", "uint256"], [receiver, 456]
    ).hex()

    decoded = decode_input_data(calldata, [FLASH_LOAN_FUNCTION])

    assert decoded is not None
    assert decoded["function_name"] == "flashLoan"
    assert decoded["arguments"] == {"receiver": receiver, "amount": 456}


def test_aws_transaction_input_survives_normalization_and_d3_decoding():
    import json
    import tempfile
    from pathlib import Path

    from defi_lsa.abi import LocalABIFallback
    from defi_lsa.aws import normalize_aws_transaction_record
    from defi_lsa.d3_pipeline import _decode_call_records

    address = "0x" + "44" * 20
    receiver = "0x" + "33" * 20
    input_data = function_selector(FLASH_LOAN_FUNCTION) + encode(
        ["address", "uint256"], [receiver, 456]
    ).hex()
    transaction = normalize_aws_transaction_record(
        {
            "hash": "0x" + "b" * 64,
            "block_number": 12,
            "from_address": "0x" + "11" * 20,
            "to_address": address,
            "value": 0,
            "gas": 21000,
            "gas_price": 1,
            "nonce": 0,
            "input": input_data,
        },
        "event",
        "c" * 64,
    )

    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, f"{address}.json").write_text(json.dumps([FLASH_LOAN_FUNCTION]))
        decoded, unknown = _decode_call_records(
            "event", [transaction], LocalABIFallback(Path(tmp))
        )

    assert len(decoded) == 1
    assert decoded[0]["function_name"] == "flashLoan"
    assert decoded[0]["raw_input"] == input_data
    assert unknown == []


def test_unknown_records_are_aggregated_without_decoder_failure():
    records = [
        unknown_record(
            event_id="evt",
            contract="0xabc",
            tx_hash="0xtx1",
            topic0="0xdead",
        ),
        unknown_record(
            event_id="evt",
            contract="0xabc",
            tx_hash="0xtx2",
            topic0="0xdead",
        ),
    ]

    aggregated = aggregate_unknown_records(records)

    assert len(aggregated) == 2
    assert {item["occurrence_count"] for item in aggregated} == {2}