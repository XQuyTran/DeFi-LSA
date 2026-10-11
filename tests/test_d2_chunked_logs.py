import json
import tempfile
import unittest
from pathlib import Path

from defi_lsa.collectors import fetch_logs_chunked
from defi_lsa.errors import TransientSourceError
from defi_lsa.checkpoints import CheckpointStore
from defi_lsa.registry import ContractScope
from defi_lsa.retry import RetryPolicy


SCOPE = ContractScope(
    event_id="chunked-test",
    chain_id=1,
    addresses=("0x" + "1" * 40,),
    rationale="fixture",
)
POLICY = RetryPolicy(max_attempts=1, initial_delay=0, max_delay=0, jitter=False)


def log_for(block: int, index: int = 0) -> dict:
    return {
        "address": SCOPE.addresses[0],
        "blockNumber": hex(block),
        "transactionHash": "0x" + f"{block:064x}",
        "logIndex": hex(index),
        "topics": [],
        "data": "0x",
    }


class ChunkedLogTests(unittest.TestCase):
    def test_log_collection_splits_large_ranges(self) -> None:
        requests = []

        def rpc(method, params):
            requests.append(params[0])
            start = int(params[0]["fromBlock"], 16)
            end = int(params[0]["toBlock"], 16)
            return [log_for(start)]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = fetch_logs_chunked(
                rpc, 1, 5, SCOPE, root / "logs.jsonl",
                checkpoint_store=CheckpointStore(root / "checkpoints"),
                initial_chunk_size=2,
                minimum_chunk_size=1,
                maximum_chunk_size=2,
                retry_policy=POLICY,
            )
        self.assertEqual(result.records_written, 3)
        self.assertEqual([(int(r["fromBlock"], 16), int(r["toBlock"], 16)) for r in requests],
                         [(1, 2), (3, 4), (5, 5)])

    def test_log_collection_reduces_chunk_after_provider_error(self) -> None:
        requests = []

        def rpc(method, params):
            query = params[0]
            start = int(query["fromBlock"], 16)
            end = int(query["toBlock"], 16)
            requests.append((start, end))
            if end - start + 1 > 1:
                raise TransientSourceError("range too large", source="rpc")
            return [log_for(start)]

        with tempfile.TemporaryDirectory() as directory:
            result = fetch_logs_chunked(
                rpc, 10, 12, SCOPE, Path(directory) / "logs.jsonl",
                checkpoint_store=CheckpointStore(Path(directory) / "checkpoints"),
                initial_chunk_size=3,
                minimum_chunk_size=1,
                maximum_chunk_size=3,
                retry_policy=POLICY,
            )
        self.assertEqual(result.records_written, 3)
        self.assertIn((10, 12), requests)
        self.assertIn((10, 10), requests)

    def test_log_collection_resumes_from_checkpoint(self) -> None:
        requests = []

        def rpc(method, params):
            query = params[0]
            start = int(query["fromBlock"], 16)
            end = int(query["toBlock"], 16)
            requests.append((start, end))
            return [log_for(start)]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = CheckpointStore(root / "checkpoints")
            fetch_logs_chunked(
                rpc, 1, 2, SCOPE, root / "logs.jsonl",
                checkpoint_store=store, initial_chunk_size=1,
                minimum_chunk_size=1, maximum_chunk_size=1,
                retry_policy=POLICY,
            )
            requests.clear()
            result = fetch_logs_chunked(
                rpc, 1, 2, SCOPE, root / "logs.jsonl",
                checkpoint_store=store, initial_chunk_size=1,
                minimum_chunk_size=1, maximum_chunk_size=1,
                retry_policy=POLICY,
            )
        self.assertEqual(result.records_written, 0)
        self.assertEqual(requests, [])

    def test_log_collection_does_not_duplicate_records(self) -> None:
        def rpc(method, params):
            start = int(params[0]["fromBlock"], 16)
            return [log_for(start)]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = CheckpointStore(root / "checkpoints")
            first = fetch_logs_chunked(
                rpc, 1, 1, SCOPE, root / "logs.jsonl",
                checkpoint_store=store, initial_chunk_size=1,
                minimum_chunk_size=1, maximum_chunk_size=1,
                retry_policy=POLICY,
            )
            self.assertEqual(first.records_written, 1)
            lines = (root / "logs.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["record_key"], "1:0x" + f"{1:064x}" + ":0")

    def test_log_collection_records_irrecoverable_range(self) -> None:
        def rpc(method, params):
            raise TransientSourceError("provider unavailable", source="rpc")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = CheckpointStore(root / "checkpoints")
            with self.assertRaises(TransientSourceError):
                fetch_logs_chunked(
                    rpc, 20, 20, SCOPE, root / "logs.jsonl",
                    checkpoint_store=store, initial_chunk_size=1,
                    minimum_chunk_size=1, maximum_chunk_size=1,
                    retry_policy=POLICY,
                )
            checkpoint = store.load_checkpoint(SCOPE.event_id, "logs")
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.failed_ranges[0]["start"], 20)


if __name__ == "__main__":
    unittest.main()
