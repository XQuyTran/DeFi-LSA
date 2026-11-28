"""Deterministic unit tests for defi_lsa.storage (A09 + A12)."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from defi_lsa.storage import (
    append_normalized_records,
    read_jsonl_records,
    source_path,
    normalized_path,
    write_source_artifact,
    SOURCE_BASE,
    NORMALIZED_BASE,
)


class SourcePathTests(unittest.TestCase):
    """Tests for path helper functions."""

    def test_source_path_structure(self) -> None:
        root = Path("/data")
        result = source_path("blocks", "euler_2023", "response.json", root)
        self.assertEqual(
            result,
            root / SOURCE_BASE / "blocks" / "euler_2023" / "response.json",
        )

    def test_normalized_path_structure(self) -> None:
        root = Path("/data")
        result = normalized_path("logs", "curve_2023", root)
        self.assertEqual(
            result,
            root / NORMALIZED_BASE / "logs" / "curve_2023.jsonl",
        )


class WriteSourceArtifactTests(unittest.TestCase):
    """Tests for write_source_artifact."""

    def test_writes_content_and_returns_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "artifact.json"
            content = b'{"hello": "world"}'
            digest = write_source_artifact(path, content)

            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), content)
            expected = hashlib.sha256(content).hexdigest()
            self.assertEqual(digest, expected)

    def test_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a" / "b" / "c" / "file.bin"
            write_source_artifact(path, b"data")
            self.assertTrue(path.exists())

    def test_accepts_str_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "text.txt"
            content_str = "hello world"
            digest = write_source_artifact(path, content_str)
            expected = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
            self.assertEqual(digest, expected)
            self.assertEqual(path.read_text(encoding="utf-8"), content_str)

    def test_raises_file_exists_error_if_path_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            write_source_artifact(path, b"first")
            with self.assertRaises(FileExistsError):
                write_source_artifact(path, b"second")
            # Original content must be intact.
            self.assertEqual(path.read_bytes(), b"first")


class AppendNormalizedRecordsTests(unittest.TestCase):
    """Tests for append_normalized_records."""

    def _make_record(self, key: str, value: str = "data") -> dict:
        return {"record_key": key, "value": value}

    def test_writes_new_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            records = [self._make_record("a"), self._make_record("b")]
            written, skipped = append_normalized_records(path, records)

            self.assertEqual(written, 2)
            self.assertEqual(skipped, 0)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)

    def test_skips_duplicate_keys_within_same_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            records = [
                self._make_record("dup"),
                self._make_record("dup"),  # duplicate
            ]
            written, skipped = append_normalized_records(path, records)

            self.assertEqual(written, 1)
            self.assertEqual(skipped, 1)

    def test_skips_duplicates_across_batches(self) -> None:
        """Second batch with overlapping keys should skip existing records."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            batch_1 = [self._make_record("x"), self._make_record("y")]
            batch_2 = [
                self._make_record("y"),  # already written
                self._make_record("z"),  # new
            ]

            written_1, skipped_1 = append_normalized_records(path, batch_1)
            written_2, skipped_2 = append_normalized_records(path, batch_2)

            self.assertEqual(written_1, 2)
            self.assertEqual(skipped_1, 0)
            self.assertEqual(written_2, 1)
            self.assertEqual(skipped_2, 1)

            # Exactly 3 records on disk.
            lines = [
                l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()
            ]
            self.assertEqual(len(lines), 3)
            keys = {json.loads(l)["record_key"] for l in lines}
            self.assertEqual(keys, {"x", "y", "z"})

    def test_append_quarantines_trailing_corruption_without_loading_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            path.write_bytes(b'{"record_key":"existing"}\n{{corrupt}}\n')

            written, skipped = append_normalized_records(path, [self._make_record("new")])

            self.assertEqual((written, skipped), (1, 0))
            self.assertEqual(
                [record["record_key"] for record in read_jsonl_records(path)],
                ["existing", "new"],
            )
            self.assertIn(b"corrupt", path.with_suffix(".quarantine").read_bytes())

    def test_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep" / "dir" / "records.jsonl"
            append_normalized_records(path, [self._make_record("k")])
            self.assertTrue(path.exists())

    def test_tolerates_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "new.jsonl"
            written, skipped = append_normalized_records(path, [self._make_record("a")])
            self.assertEqual(written, 1)
            self.assertEqual(skipped, 0)

    def test_custom_key_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            records = [
                {"tx_hash": "0x" + "a" * 64, "value": 1},
                {"tx_hash": "0x" + "a" * 64, "value": 2},  # duplicate
            ]
            written, skipped = append_normalized_records(
                path, records, key_field="tx_hash"
            )
            self.assertEqual(written, 1)
            self.assertEqual(skipped, 1)


class ReadJsonlRecordsTests(unittest.TestCase):
    """Tests for read_jsonl_records."""

    def test_reads_valid_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            records = [{"record_key": "a"}, {"record_key": "b"}]
            path.write_text(
                "\n".join(json.dumps(r) for r in records) + "\n",
                encoding="utf-8",
            )
            result = read_jsonl_records(path)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["record_key"], "a")
            self.assertEqual(result[1]["record_key"], "b")

    def test_skips_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            path.write_text(
                '{"record_key":"a"}\n\n{"record_key":"b"}\n\n',
                encoding="utf-8",
            )
            result = read_jsonl_records(path)
            self.assertEqual(len(result), 2)

    def test_returns_empty_list_for_missing_file(self) -> None:
        path = Path("/nonexistent/path/file.jsonl")
        self.assertEqual(read_jsonl_records(path), [])

    def test_detects_and_quarantines_malformed_trailing_record(self) -> None:
        """A corrupt last line is moved to a .quarantine sidecar and main file is truncated."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            good_line_1 = json.dumps({"record_key": "a"}) + "\n"
            good_line_2 = json.dumps({"record_key": "b"}) + "\n"
            corrupt_line = b"{{corrupt json...}\n"

            path.write_bytes(
                good_line_1.encode("utf-8")
                + good_line_2.encode("utf-8")
                + corrupt_line
            )

            result = read_jsonl_records(path)

            # Only valid records returned.
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["record_key"], "a")
            self.assertEqual(result[1]["record_key"], "b")

            # Quarantine sidecar created.
            quarantine_path = path.with_suffix(".quarantine")
            self.assertTrue(quarantine_path.exists())
            self.assertIn(b"corrupt", quarantine_path.read_bytes())

            # Main file truncated to good content only.
            remaining = path.read_text(encoding="utf-8")
            lines = [l for l in remaining.splitlines() if l.strip()]
            self.assertEqual(len(lines), 2)
            for line in lines:
                json.loads(line)  # must be valid JSON

    def test_mid_file_corruption_raises(self) -> None:
        """A bad line with good lines after it should raise json.JSONDecodeError."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            path.write_text(
                '{"record_key":"a"}\n'
                "{{corrupt}}\n"
                '{"record_key":"c"}\n',
                encoding="utf-8",
            )
            import json as _json
            with self.assertRaises(_json.JSONDecodeError):
                read_jsonl_records(path)


if __name__ == "__main__":
    unittest.main()

