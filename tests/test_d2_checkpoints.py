"""Deterministic unit tests for defi_lsa.checkpoints (A02).

Exercises Checkpoint dataclass, CheckpointStore, scope hashing,
interval coalescing, pending-range computation, scope validation,
and failure tracking using standard library unittest.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from defi_lsa.checkpoints import (
    Checkpoint,
    CheckpointStore,
    DEFAULT_CHECKPOINT_DIR,
    checkpoint_path,
    coalesce_ranges,
    compute_pending_ranges,
    compute_scope_hash,
    get_pending_ranges,
    validate_checkpoint_scope,
)
from defi_lsa.registry import ContractScope


class CoalesceRangesTests(unittest.TestCase):
    """Tests for coalesce_ranges interval merging logic."""

    def test_empty_input_returns_empty_list(self) -> None:
        self.assertEqual(coalesce_ranges([]), [])

    def test_single_interval_returned_unchanged(self) -> None:
        self.assertEqual(coalesce_ranges([(10, 20)]), [(10, 20)])

    def test_adjacent_intervals_coalesce(self) -> None:
        # [1, 5] and [6, 10] are contiguous in integer space
        self.assertEqual(coalesce_ranges([(1, 5), (6, 10)]), [(1, 10)])

    def test_overlapping_intervals_coalesce(self) -> None:
        self.assertEqual(coalesce_ranges([(1, 5), (3, 8)]), [(1, 8)])

    def test_subset_intervals_coalesce(self) -> None:
        self.assertEqual(coalesce_ranges([(1, 10), (3, 7)]), [(1, 10)])

    def test_identical_intervals_coalesce(self) -> None:
        self.assertEqual(coalesce_ranges([(1, 5), (1, 5)]), [(1, 5)])

    def test_out_of_order_intervals_are_sorted_and_merged(self) -> None:
        raw = [(20, 25), (1, 5), (6, 10), (12, 15)]
        expected = [(1, 10), (12, 15), (20, 25)]
        self.assertEqual(coalesce_ranges(raw), expected)

    def test_disjoint_intervals_with_gap_remain_separate(self) -> None:
        # Gap at 6
        self.assertEqual(coalesce_ranges([(1, 5), (7, 10)]), [(1, 5), (7, 10)])

    def test_single_point_intervals_coalesce(self) -> None:
        self.assertEqual(coalesce_ranges([(1, 1), (2, 2), (3, 3)]), [(1, 3)])

    def test_inverted_range_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            coalesce_ranges([(10, 5)])


class ComputeScopeHashTests(unittest.TestCase):
    """Tests for compute_scope_hash deterministic hashing."""

    def _sample_scope(
        self,
        event_id: str = "euler_2023-03-13",
        chain_id: int = 1,
        addresses: tuple[str, ...] = (
            "0x27182842e098f60e3d576794712fda55cc22e067",
            "0xb01e8419d8329b307ad7656c02287d37e6f8b66e",
        ),
    ) -> ContractScope:
        return ContractScope(
            event_id=event_id,
            chain_id=chain_id,
            addresses=addresses,
            rationale="Test scope",
        )

    def test_returns_64_character_hex_string(self) -> None:
        scope = self._sample_scope()
        digest = compute_scope_hash(scope)
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # Must be valid hex

    def test_deterministic_output(self) -> None:
        scope = self._sample_scope()
        self.assertEqual(compute_scope_hash(scope), compute_scope_hash(scope))

    def test_address_order_does_not_affect_hash(self) -> None:
        scope1 = self._sample_scope(
            addresses=("0xaaaa" + "0" * 36, "0xbbbb" + "0" * 36)
        )
        scope2 = self._sample_scope(
            addresses=("0xbbbb" + "0" * 36, "0xaaaa" + "0" * 36)
        )
        self.assertEqual(compute_scope_hash(scope1), compute_scope_hash(scope2))

    def test_address_casing_does_not_affect_hash(self) -> None:
        scope_lower = self._sample_scope(
            addresses=("0xabcdef" + "0" * 34,)
        )
        scope_upper = self._sample_scope(
            addresses=("0xABCDEF" + "0" * 34,)
        )
        self.assertEqual(compute_scope_hash(scope_lower), compute_scope_hash(scope_upper))

    def test_different_chain_id_produces_different_hash(self) -> None:
        scope1 = self._sample_scope(chain_id=1)
        scope2 = self._sample_scope(chain_id=137)
        self.assertNotEqual(compute_scope_hash(scope1), compute_scope_hash(scope2))

    def test_different_addresses_produce_different_hash(self) -> None:
        scope1 = self._sample_scope(addresses=("0xaaaa" + "0" * 36,))
        scope2 = self._sample_scope(addresses=("0xbbbb" + "0" * 36,))
        self.assertNotEqual(compute_scope_hash(scope1), compute_scope_hash(scope2))


class GetPendingRangesTests(unittest.TestCase):
    """Tests for get_pending_ranges and compute_pending_ranges."""

    def _sample_checkpoint(
        self,
        requested_start: int = 1,
        requested_end: int = 100,
        completed_ranges: list[tuple[int, int]] | None = None,
        failed_ranges: list[dict] | None = None,
    ) -> Checkpoint:
        return Checkpoint(
            event_id="test_event",
            collector="logs",
            scope_hash="a" * 64,
            requested_start=requested_start,
            requested_end=requested_end,
            completed_ranges=completed_ranges or [],
            failed_ranges=failed_ranges or [],
            updated_at_utc="2023-01-01T00:00:00Z",
            adapter_version="1.0.0",
        )

    def test_no_completed_ranges_returns_full_requested_window(self) -> None:
        cp = self._sample_checkpoint(requested_start=10, requested_end=50)
        self.assertEqual(get_pending_ranges(cp), [(10, 50)])

    def test_fully_completed_returns_empty_list(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(1, 100)],
        )
        self.assertEqual(get_pending_ranges(cp), [])

    def test_partial_completed_at_start(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(1, 20)],
        )
        self.assertEqual(get_pending_ranges(cp), [(21, 100)])

    def test_partial_completed_at_end(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(80, 100)],
        )
        self.assertEqual(get_pending_ranges(cp), [(1, 79)])

    def test_partial_completed_in_middle_creates_two_gaps(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(40, 60)],
        )
        self.assertEqual(get_pending_ranges(cp), [(1, 39), (61, 100)])

    def test_multiple_gaps_between_completed_ranges(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(10, 20), (40, 50), (80, 90)],
        )
        self.assertEqual(
            get_pending_ranges(cp),
            [(1, 9), (21, 39), (51, 79), (91, 100)],
        )

    def test_completed_range_exceeding_boundaries_is_clamped(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=10,
            requested_end=50,
            completed_ranges=[(5, 20), (45, 60)],
        )
        self.assertEqual(get_pending_ranges(cp), [(21, 44)])

    def test_failed_ranges_excluded_when_retry_failed_false(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(1, 20)],
            failed_ranges=[
                {
                    "start": 40,
                    "end": 50,
                    "error_type": "TimeoutError",
                    "message": "Timed out",
                    "retries": 3,
                    "timestamp_utc": "2023-01-01T00:00:00Z",
                }
            ],
        )
        # 40..50 should NOT be in pending because it's failed and retry_failed=False
        expected = [(21, 39), (51, 100)]
        self.assertEqual(get_pending_ranges(cp, retry_failed=False), expected)

    def test_failed_ranges_included_when_retry_failed_true(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(1, 20)],
            failed_ranges=[
                {
                    "start": 40,
                    "end": 50,
                    "error_type": "TimeoutError",
                    "message": "Timed out",
                    "retries": 3,
                    "timestamp_utc": "2023-01-01T00:00:00Z",
                }
            ],
        )
        # 40..50 should be included in pending when retry_failed=True
        expected = [(21, 100)]
        self.assertEqual(get_pending_ranges(cp, retry_failed=True), expected)

    def test_include_failed_alias_works(self) -> None:
        cp = self._sample_checkpoint(
            requested_start=1,
            requested_end=100,
            completed_ranges=[(1, 20)],
            failed_ranges=[
                {
                    "start": 40,
                    "end": 50,
                    "error_type": "TimeoutError",
                    "message": "Timed out",
                    "retries": 3,
                    "timestamp_utc": "2023-01-01T00:00:00Z",
                }
            ],
        )
        self.assertEqual(get_pending_ranges(cp, include_failed=True), [(21, 100)])

    def test_invalid_requested_window_raises(self) -> None:
        with self.assertRaises(ValueError):
            compute_pending_ranges(100, 50, [])


class ScopeValidationTests(unittest.TestCase):
    """Tests for validate_checkpoint_scope."""

    def setUp(self) -> None:
        self.scope = ContractScope(
            event_id="euler_2023-03-13",
            chain_id=1,
            addresses=(
                "0x27182842e098f60e3d576794712fda55cc22e067",
                "0xb01e8419d8329b307ad7656c02287d37e6f8b66e",
            ),
            rationale="Test",
        )
        self.scope_hash = compute_scope_hash(self.scope)
        self.checkpoint = Checkpoint(
            event_id="euler_2023-03-13",
            collector="blocks",
            scope_hash=self.scope_hash,
            requested_start=100,
            requested_end=200,
            completed_ranges=[(100, 150)],
            failed_ranges=[],
            updated_at_utc="2023-03-13T12:00:00Z",
            adapter_version="1.0.0",
        )

    def test_matching_checkpoint_validates_true(self) -> None:
        self.assertTrue(
            validate_checkpoint_scope(
                self.checkpoint,
                self.scope,
                requested_start=100,
                requested_end=200,
            )
        )

    def test_scope_address_mismatch_fails_validation(self) -> None:
        altered_scope = ContractScope(
            event_id="euler_2023-03-13",
            chain_id=1,
            addresses=("0x1111" + "0" * 36,),
            rationale="Changed",
        )
        self.assertFalse(
            validate_checkpoint_scope(
                self.checkpoint,
                altered_scope,
                requested_start=100,
                requested_end=200,
            )
        )

    def test_scope_address_mismatch_raises_in_strict_mode(self) -> None:
        altered_scope = ContractScope(
            event_id="euler_2023-03-13",
            chain_id=1,
            addresses=("0x1111" + "0" * 36,),
            rationale="Changed",
        )
        with self.assertRaises(ValueError) as ctx:
            validate_checkpoint_scope(
                self.checkpoint,
                altered_scope,
                requested_start=100,
                requested_end=200,
                strict=True,
            )
        self.assertIn("scope_hash mismatch", str(ctx.exception))

    def test_event_id_mismatch_fails_validation(self) -> None:
        altered_scope = ContractScope(
            event_id="different_event",
            chain_id=1,
            addresses=self.scope.addresses,
            rationale="Test",
        )
        self.assertFalse(
            validate_checkpoint_scope(
                self.checkpoint,
                altered_scope,
                requested_start=100,
                requested_end=200,
            )
        )

    def test_requested_start_mismatch_fails_validation(self) -> None:
        self.assertFalse(
            validate_checkpoint_scope(
                self.checkpoint,
                self.scope,
                requested_start=99,
                requested_end=200,
            )
        )

    def test_requested_end_mismatch_fails_validation(self) -> None:
        self.assertFalse(
            validate_checkpoint_scope(
                self.checkpoint,
                self.scope,
                requested_start=100,
                requested_end=201,
            )
        )

    def test_store_validate_checkpoint_scope_method(self) -> None:
        store = CheckpointStore()
        self.assertTrue(
            store.validate_checkpoint_scope(
                self.checkpoint,
                self.scope,
                requested_start=100,
                requested_end=200,
            )
        )


class CheckpointStoreIoTests(unittest.TestCase):
    """Tests for CheckpointStore persistence, atomic save, and load."""

    def test_save_and_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            cp = Checkpoint(
                event_id="evt_01",
                collector="transactions",
                scope_hash="b" * 64,
                requested_start=1000,
                requested_end=2000,
                completed_ranges=[(1000, 1500), (1600, 1800)],
                failed_ranges=[
                    {
                        "start": 1501,
                        "end": 1599,
                        "error_type": "RateLimitError",
                        "message": "Too many requests",
                        "retries": 2,
                        "timestamp_utc": "2023-01-01T00:00:00Z",
                    }
                ],
                updated_at_utc="2023-01-01T01:00:00Z",
                adapter_version="2.1.0",
                metadata={"worker_id": "w1", "chunk_size": 50},
            )

            store.save_checkpoint_atomic(cp)

            expected_path = Path(tmp_dir) / "evt_01" / "transactions.json"
            self.assertTrue(expected_path.exists())

            loaded = store.load_checkpoint("evt_01", "transactions")
            self.assertIsNotNone(loaded)
            assert loaded is not None

            self.assertEqual(loaded.event_id, "evt_01")
            self.assertEqual(loaded.collector, "transactions")
            self.assertEqual(loaded.scope_hash, "b" * 64)
            self.assertEqual(loaded.requested_start, 1000)
            self.assertEqual(loaded.requested_end, 2000)
            self.assertEqual(loaded.completed_ranges, [(1000, 1500), (1600, 1800)])
            self.assertEqual(len(loaded.failed_ranges), 1)
            self.assertEqual(loaded.failed_ranges[0]["error_type"], "RateLimitError")
            self.assertEqual(loaded.failed_ranges[0]["retries"], 2)
            self.assertEqual(loaded.updated_at_utc, "2023-01-01T01:00:00Z")
            self.assertEqual(loaded.adapter_version, "2.1.0")
            self.assertEqual(loaded.metadata, {"worker_id": "w1", "chunk_size": 50})

    def test_load_nonexistent_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            self.assertIsNone(store.load_checkpoint("unknown_evt", "logs"))

    def test_load_corrupted_json_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            path = store.checkpoint_path("evt_bad", "logs")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{corrupt json content...", encoding="utf-8")

            with self.assertRaises(ValueError):
                store.load_checkpoint("evt_bad", "logs")

    def test_save_atomic_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            cp1 = Checkpoint(
                event_id="evt_02",
                collector="blocks",
                scope_hash="c" * 64,
                requested_start=1,
                requested_end=10,
                completed_ranges=[(1, 5)],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )
            store.save_checkpoint_atomic(cp1)

            cp2 = Checkpoint(
                event_id="evt_02",
                collector="blocks",
                scope_hash="c" * 64,
                requested_start=1,
                requested_end=10,
                completed_ranges=[(1, 10)],
                failed_ranges=[],
                updated_at_utc="2023-01-01T01:00:00Z",
                adapter_version="1.0.0",
            )
            store.save_checkpoint_atomic(cp2)

            loaded = store.load_checkpoint("evt_02", "blocks")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.completed_ranges, [(1, 10)])

    def test_checkpoint_path_helper(self) -> None:
        path = checkpoint_path("event_a", "receipts", Path("/data/cp"))
        self.assertEqual(path, Path("/data/cp/event_a/receipts.json"))

        default_path = checkpoint_path("event_a", "receipts")
        self.assertEqual(default_path, DEFAULT_CHECKPOINT_DIR / "event_a" / "receipts.json")


class MarkRangeCompletedTests(unittest.TestCase):
    """Tests for mark_range_completed."""

    def test_initial_mark_completed_creates_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            cp = store.mark_range_completed(
                event_id="evt_new",
                collector="logs",
                start=100,
                end=150,
                scope_hash="d" * 64,
                requested_start=100,
                requested_end=500,
                adapter_version="1.0.0",
            )
            self.assertEqual(cp.completed_ranges, [(100, 150)])
            self.assertEqual(cp.requested_start, 100)
            self.assertEqual(cp.requested_end, 500)
            self.assertEqual(cp.failed_ranges, [])

            # Verify persisted
            loaded = store.load_checkpoint("evt_new", "logs")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.completed_ranges, [(100, 150)])

    def test_subsequent_mark_coalesces_adjacent_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            store.mark_range_completed(
                event_id="evt_01",
                collector="logs",
                start=1,
                end=10,
                requested_start=1,
                requested_end=50,
            )
            cp = store.mark_range_completed(
                event_id="evt_01",
                collector="logs",
                start=11,
                end=20,
            )
            self.assertEqual(cp.completed_ranges, [(1, 20)])

    def test_mark_completed_removes_exact_failed_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            # Record a failure
            store.mark_range_failed(
                event_id="evt_01",
                collector="logs",
                start=10,
                end=20,
                error="Temporary RPC error",
                requested_start=1,
                requested_end=50,
            )

            # Now mark it completed
            cp = store.mark_range_completed(
                event_id="evt_01",
                collector="logs",
                start=10,
                end=20,
            )
            self.assertEqual(cp.completed_ranges, [(10, 20)])
            self.assertEqual(cp.failed_ranges, [])

    def test_mark_completed_trims_partially_overlapping_failed_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            # Record failure for [10, 30]
            store.mark_range_failed(
                event_id="evt_01",
                collector="logs",
                start=10,
                end=30,
                error="Connection reset",
                requested_start=1,
                requested_end=50,
            )

            # Now complete [10, 20]
            cp = store.mark_range_completed(
                event_id="evt_01",
                collector="logs",
                start=10,
                end=20,
            )
            self.assertEqual(cp.completed_ranges, [(10, 20)])
            # Failed range should be trimmed to [21, 30]
            self.assertEqual(len(cp.failed_ranges), 1)
            self.assertEqual(cp.failed_ranges[0]["start"], 21)
            self.assertEqual(cp.failed_ranges[0]["end"], 30)

    def test_invalid_range_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            with self.assertRaises(ValueError):
                store.mark_range_completed("evt", "logs", 50, 20)


class MarkRangeFailedTests(unittest.TestCase):
    """Tests for mark_range_failed."""

    def test_initial_mark_failed_creates_checkpoint_with_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            exc = TimeoutError("Request timed out after 30s")
            cp = store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=50,
                end=60,
                error=exc,
                retries=2,
                requested_start=1,
                requested_end=100,
            )

            self.assertEqual(len(cp.failed_ranges), 1)
            fail = cp.failed_ranges[0]
            self.assertEqual(fail["start"], 50)
            self.assertEqual(fail["end"], 60)
            self.assertEqual(fail["error_type"], "TimeoutError")
            self.assertEqual(fail["message"], "Request timed out after 30s")
            self.assertEqual(fail["retries"], 2)
            self.assertTrue(fail["timestamp_utc"].endswith("Z"))

    def test_string_error_handled_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            cp = store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=1,
                end=10,
                error="Node out of sync",
                error_type="CustomNodeError",
            )
            self.assertEqual(cp.failed_ranges[0]["error_type"], "CustomNodeError")
            self.assertEqual(cp.failed_ranges[0]["message"], "Node out of sync")

    def test_duplicate_failed_range_updates_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=1,
                end=10,
                error="Attempt 1 error",
                retries=1,
            )
            cp = store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=1,
                end=10,
                error="Attempt 2 error",
                retries=2,
            )
            self.assertEqual(len(cp.failed_ranges), 1)
            self.assertEqual(cp.failed_ranges[0]["message"], "Attempt 2 error")
            self.assertEqual(cp.failed_ranges[0]["retries"], 2)

    def test_distinct_failed_ranges_appended(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = CheckpointStore(base_dir=tmp_dir)
            store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=1,
                end=10,
                error="Error 1",
            )
            cp = store.mark_range_failed(
                event_id="evt_fail",
                collector="blocks",
                start=20,
                end=30,
                error="Error 2",
            )
            self.assertEqual(len(cp.failed_ranges), 2)


class CheckpointDataclassValidationTests(unittest.TestCase):
    """Tests for Checkpoint dataclass construction and serialization."""

    def test_empty_event_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="",
                collector="logs",
                scope_hash="a" * 64,
                requested_start=1,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )

    def test_empty_collector_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="e1",
                collector="",
                scope_hash="a" * 64,
                requested_start=1,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )

    def test_empty_scope_hash_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="e1",
                collector="logs",
                scope_hash="",
                requested_start=1,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )

    def test_negative_requested_start_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="e1",
                collector="logs",
                scope_hash="a" * 64,
                requested_start=-1,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )

    def test_requested_end_less_than_start_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="e1",
                collector="logs",
                scope_hash="a" * 64,
                requested_start=20,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01T00:00:00Z",
                adapter_version="1.0.0",
            )

    def test_naive_timestamp_in_updated_at_utc_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint(
                event_id="e1",
                collector="logs",
                scope_hash="a" * 64,
                requested_start=1,
                requested_end=10,
                completed_ranges=[],
                failed_ranges=[],
                updated_at_utc="2023-01-01 12:00:00",  # No timezone
                adapter_version="1.0.0",
            )

    def test_to_dict_and_from_dict_round_trip(self) -> None:
        cp = Checkpoint(
            event_id="evt_rt",
            collector="logs",
            scope_hash="e" * 64,
            requested_start=10,
            requested_end=100,
            completed_ranges=[(10, 20), (21, 30)],  # Coalesces to (10, 30)
            failed_ranges=[
                {
                    "start": 50,
                    "end": 60,
                    "error_type": "HttpError",
                    "message": "500 Internal Server Error",
                    "retries": 1,
                    "timestamp_utc": "2023-01-01T00:00:00Z",
                }
            ],
            updated_at_utc="2023-01-01T00:00:00Z",
            adapter_version="1.2.3",
            metadata={"meta_key": "meta_val"},
        )
        d = cp.to_dict()
        self.assertEqual(d["completed_ranges"], [[10, 30]])
        reconstructed = Checkpoint.from_dict(d)
        self.assertEqual(reconstructed.event_id, cp.event_id)
        self.assertEqual(reconstructed.completed_ranges, [(10, 30)])
        self.assertEqual(reconstructed.metadata, {"meta_key": "meta_val"})

    def test_from_dict_missing_required_fields_raises(self) -> None:
        with self.assertRaises(ValueError):
            Checkpoint.from_dict({"event_id": "e1"})


if __name__ == "__main__":
    unittest.main()
