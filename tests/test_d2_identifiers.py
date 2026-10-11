"""Deterministic unit tests for defi_lsa.identifiers (A11)."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta

from defi_lsa.identifiers import (
    normalize_address,
    validate_address,
    normalize_tx_hash,
    validate_tx_hash,
    parse_rpc_quantity,
    normalize_utc_timestamp,
)


class NormalizeAddressTests(unittest.TestCase):
    """Tests for normalize_address / validate_address."""

    def test_lowercase_hex_address_is_returned_unchanged(self) -> None:
        addr = "0x" + "a" * 40
        self.assertEqual(normalize_address(addr), addr)

    def test_mixed_case_address_is_lowercased(self) -> None:
        addr = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"
        expected = addr.lower()
        self.assertEqual(normalize_address(addr), expected)

    def test_whitespace_is_stripped_before_validation(self) -> None:
        addr = "  0x" + "b" * 40 + "  "
        self.assertEqual(normalize_address(addr), "0x" + "b" * 40)

    def test_validate_address_is_alias_for_normalize_address(self) -> None:
        addr = "0x" + "1" * 40
        self.assertEqual(validate_address(addr), normalize_address(addr))

    def test_missing_0x_prefix_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address("a" * 40)

    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address("0x" + "a" * 39)

    def test_too_long_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address("0x" + "a" * 41)

    def test_non_hex_characters_raise(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address("0x" + "g" * 40)

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address("")

    def test_non_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_address(123)  # type: ignore[arg-type]


class NormalizeTxHashTests(unittest.TestCase):
    """Tests for normalize_tx_hash / validate_tx_hash."""

    def test_lowercase_hash_is_returned_unchanged(self) -> None:
        h = "0x" + "a" * 64
        self.assertEqual(normalize_tx_hash(h), h)

    def test_uppercase_hash_is_lowercased(self) -> None:
        h = "0x" + "A" * 64
        self.assertEqual(normalize_tx_hash(h), "0x" + "a" * 64)

    def test_whitespace_is_stripped(self) -> None:
        h = " 0x" + "c" * 64 + " "
        self.assertEqual(normalize_tx_hash(h), "0x" + "c" * 64)

    def test_validate_tx_hash_is_alias(self) -> None:
        h = "0x" + "d" * 64
        self.assertEqual(validate_tx_hash(h), normalize_tx_hash(h))

    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_tx_hash("0x" + "a" * 63)

    def test_too_long_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_tx_hash("0x" + "a" * 65)

    def test_missing_prefix_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_tx_hash("a" * 64)

    def test_non_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_tx_hash(0)  # type: ignore[arg-type]


class ParseRpcQuantityTests(unittest.TestCase):
    """Tests for parse_rpc_quantity."""

    def test_plain_int_is_returned_unchanged(self) -> None:
        self.assertEqual(parse_rpc_quantity(255), 255)

    def test_zero_int(self) -> None:
        self.assertEqual(parse_rpc_quantity(0), 0)

    def test_hex_string_parsed_correctly(self) -> None:
        self.assertEqual(parse_rpc_quantity("0x1a"), 26)

    def test_hex_string_zero(self) -> None:
        self.assertEqual(parse_rpc_quantity("0x0"), 0)

    def test_large_hex_block_number(self) -> None:
        self.assertEqual(parse_rpc_quantity("0xf4240"), 1_000_000)

    def test_non_hex_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_rpc_quantity("1000")

    def test_float_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_rpc_quantity(1.0)  # type: ignore[arg-type]

    def test_none_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_rpc_quantity(None)  # type: ignore[arg-type]

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_rpc_quantity("")

    def test_bool_raises(self) -> None:
        # bool is a subclass of int; we explicitly reject it.
        with self.assertRaises(ValueError):
            parse_rpc_quantity(True)  # type: ignore[arg-type]


class NormalizeUtcTimestampTests(unittest.TestCase):
    """Tests for normalize_utc_timestamp."""

    def test_aware_utc_datetime_returns_z_suffix(self) -> None:
        dt = datetime(2023, 3, 13, 8, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(normalize_utc_timestamp(dt), "2023-03-13T08:00:00Z")

    def test_aware_non_utc_datetime_is_converted(self) -> None:
        # UTC+7
        tz = timezone(timedelta(hours=7))
        dt = datetime(2023, 3, 13, 15, 0, 0, tzinfo=tz)
        self.assertEqual(normalize_utc_timestamp(dt), "2023-03-13T08:00:00Z")

    def test_naive_datetime_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_utc_timestamp(datetime(2023, 3, 13, 8, 0, 0))

    def test_iso_string_with_z_suffix(self) -> None:
        self.assertEqual(
            normalize_utc_timestamp("2023-03-13T08:00:00Z"),
            "2023-03-13T08:00:00Z",
        )

    def test_iso_string_with_plus_offset(self) -> None:
        self.assertEqual(
            normalize_utc_timestamp("2023-03-13T15:00:00+07:00"),
            "2023-03-13T08:00:00Z",
        )

    def test_iso_string_with_zero_offset(self) -> None:
        self.assertEqual(
            normalize_utc_timestamp("2023-03-13T08:00:00+00:00"),
            "2023-03-13T08:00:00Z",
        )

    def test_naive_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_utc_timestamp("2023-03-13T08:00:00")

    def test_unparseable_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_utc_timestamp("not-a-date")

    def test_non_string_non_datetime_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_utc_timestamp(1234567890)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

