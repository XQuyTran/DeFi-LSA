import json
import tempfile
import unittest
from pathlib import Path

from defi_lsa.collectors import (
    fetch_blocks,
    fetch_logs,
    fetch_receipts,
    fetch_transactions,
    fetch_hourly_prices,
    fetch_public_information,
)
from defi_lsa.registry import ContractScope


SCOPE = ContractScope(
    event_id="test",
    chain_id=1,
    addresses=("0x" + "1" * 40,),
    rationale="fixture",
)


class CollectorTests(unittest.TestCase):
    def test_collectors_are_resumable_and_contract_scoped(self) -> None:
        calls = []

        def rpc(method, params):
            calls.append((method, params))
            if method == "eth_getBlockByNumber" and params[1] is False:
                return {
                    "hash": "0x" + "a" * 64,
                    "timestamp": hex(100),
                    "gasUsed": hex(200),
                }
            if method == "eth_getBlockByNumber":
                return {
                    "transactions": [
                        {
                            "hash": "0x" + "b" * 64,
                            "from": SCOPE.addresses[0],
                            "to": "0x" + "2" * 40,
                        },
                        {
                            "hash": "0x" + "c" * 64,
                            "from": "0x" + "3" * 40,
                            "to": "0x" + "4" * 40,
                        },
                    ]
                }
            if method == "eth_getLogs":
                return [
                    {
                        "transactionHash": "0x" + "b" * 64,
                        "logIndex": "0x0",
                    }
                ]
            if method == "eth_getTransactionReceipt":
                return {"transactionHash": params[0], "logs": []}
            raise AssertionError(method)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocks = fetch_blocks(rpc, 10, 10, root / "blocks.jsonl")
            transactions = fetch_transactions(rpc, [10], SCOPE, root / "tx.jsonl")
            receipts = fetch_receipts(rpc, ["0x" + "b" * 64], SCOPE, root / "receipts.jsonl")
            logs = fetch_logs(rpc, 10, 10, SCOPE, root / "logs.jsonl")
            transactions_again = fetch_transactions(rpc, [10], SCOPE, root / "tx.jsonl")

        self.assertEqual(blocks.records_written, 1)
        self.assertEqual(transactions.records_written, 1)
        self.assertEqual(receipts.records_written, 1)
        self.assertEqual(logs.records_written, 1)
        self.assertEqual(transactions_again.records_skipped, 1)
        self.assertTrue(any(method == "eth_getLogs" for method, _ in calls))

    def test_prices_and_public_information_deduplicate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            price = fetch_hourly_prices(
                [
                    {"timestamp_utc": "2023-01-01T00:00:00Z", "token_id": "eth", "price": 1},
                    {"timestamp_utc": "2023-01-01T00:00:00Z", "token_id": "eth", "price": 1},
                ],
                root / "prices.jsonl",
            )
            info = fetch_public_information(
                [
                    {
                        "published_at_utc": "2023-01-01T00:00:00Z",
                        "url": "https://example.test/a",
                        "title": "A",
                        "source": "forum",
                    },
                    {
                        "published_at_utc": "2023-01-01T00:00:00Z",
                        "url": "https://example.test/a",
                        "title": "A",
                        "source": "forum",
                    },
                ],
                root / "info.jsonl",
            )
            self.assertEqual(price.records_written, 1)
            self.assertEqual(info.records_written, 1)
            self.assertEqual(len((root / "prices.jsonl").read_text().splitlines()), 1)
            json.loads((root / "info.jsonl").read_text())
