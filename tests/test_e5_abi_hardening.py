"""Tests for Epic 5: ABI and Proxy Metadata Hardening.

All tests run without live network calls. Each test covers one or more of
the E5 acceptance criteria:

  - Required ABI coverage 100%, or CONDITIONAL_GO/NO_GO.
  - Cached ABI checksum and source URL are recorded.
  - Proxy contracts have implementation addresses and appropriate ABI evidence.
  - Credential redaction in all error paths.
  - Immutable raw Etherscan response persistence.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from defi_lsa.abi import (
    ABIMetadata,
    EtherscanABIClient,
    LocalABIFallback,
    build_etherscan_v2_url,
    compute_abi_coverage_report,
    fetch_raw_etherscan_response,
    resolve_proxy_implementation,
    validate_abi_cache,
    _write_abi_metadata,
    _sha256_file,
)
from defi_lsa.collectors import fetch_abi
from defi_lsa.errors import AuthenticationError, PermanentSourceError
from defi_lsa.retry import RetryPolicy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ABI = [{"name": "Transfer", "type": "event", "inputs": []}]
SAMPLE_ABI_STR = json.dumps(SAMPLE_ABI)

ADDR_A = "0x" + "a" * 40
ADDR_B = "0x" + "b" * 40
IMPL_ADDR = "0x" + "c" * 40

API_KEY = "FAKE_KEY_DO_NOT_LOG"
API_BASE = "https://api.etherscan.io/v2/api"


def _etherscan_ok_response(abi_json: str = SAMPLE_ABI_STR) -> bytes:
    return json.dumps({"status": "1", "message": "OK", "result": abi_json}).encode()


def _etherscan_err_response(message: str = "Contract source code not verified") -> bytes:
    return json.dumps({"status": "0", "message": "NOTOK", "result": message}).encode()


def _getsourcecode_proxy_response(impl: str) -> bytes:
    return json.dumps({
        "status": "1",
        "message": "OK",
        "result": [{"Implementation": impl, "ABI": SAMPLE_ABI_STR}],
    }).encode()


def _getsourcecode_non_proxy_response() -> bytes:
    return json.dumps({
        "status": "1",
        "message": "OK",
        "result": [{"Implementation": "", "ABI": SAMPLE_ABI_STR}],
    }).encode()


class _MockOpener:
    """Controllable stub HTTP opener for testing."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        self._responses = responses  # keyed by substring of URL

    def __call__(self, req: Any, timeout: float = 30.0) -> Any:
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for key, body in self._responses.items():
            if key in url:
                return _Resp(body)
        raise RuntimeError(f"No stub for URL: {url}")


class _Resp:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


# ---------------------------------------------------------------------------
# E5.1  Etherscan V2 URL includes chainid=1
# ---------------------------------------------------------------------------

class TestBuildEtherscanV2Url(unittest.TestCase):
    def test_chainid_present_in_url(self) -> None:
        url = build_etherscan_v2_url(API_BASE, "contract", "getabi", ADDR_A, API_KEY)
        self.assertIn("chainid=1", url)

    def test_chainid_parameter_uses_supplied_chain(self) -> None:
        url = build_etherscan_v2_url(
            API_BASE, "contract", "getabi", ADDR_A, API_KEY, chain_id=137
        )
        self.assertIn("chainid=137", url)
        self.assertNotIn("chainid=1&", url)

    def test_module_and_action_present(self) -> None:
        url = build_etherscan_v2_url(API_BASE, "contract", "getabi", ADDR_A, API_KEY)
        self.assertIn("module=contract", url)
        self.assertIn("action=getabi", url)
        self.assertIn(f"address={ADDR_A}", url)

    def test_extra_params_appended(self) -> None:
        url = build_etherscan_v2_url(
            API_BASE, "contract", "getabi", ADDR_A, API_KEY, extra={"foo": "bar"}
        )
        self.assertIn("foo=bar", url)


# ---------------------------------------------------------------------------
# E5.3  Immutable raw Etherscan response is persisted
# ---------------------------------------------------------------------------

class TestRawResponsePersistence(unittest.TestCase):
    def test_raw_artifact_written_before_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            abi_dir = Path(tmp) / "abi"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_non_proxy_response(),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            meta = client.fetch_abi(ADDR_A, abi_dir, raw_dir)

            raw_artifacts = list(raw_dir.glob("*.json"))
            self.assertEqual(len(raw_artifacts), 1, "raw response artifact must be written")
            self.assertTrue(raw_artifacts[0].name.endswith("_abi.json"))

    def test_raw_artifact_not_overwritten_if_present(self) -> None:
        """Immutable: existing raw artifact must not be replaced."""
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            raw_dir.mkdir()
            abi_dir = Path(tmp) / "abi"
            abi_dir.mkdir()

            # Pre-seed raw artifact
            addr_lower = ADDR_A.lower()
            existing = raw_dir / f"{addr_lower}_abi.json"
            original_content = b'{"status":"1","message":"OK","result":"[]"}'
            existing.write_bytes(original_content)

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_non_proxy_response(),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            client.fetch_abi(ADDR_A, abi_dir, raw_dir)

            # Content must not have been overwritten
            self.assertEqual(existing.read_bytes(), original_content)


# ---------------------------------------------------------------------------
# E5.4  ABI cache validation (checksum + source URL recorded)
# ---------------------------------------------------------------------------

class TestABICacheValidation(unittest.TestCase):
    def _create_valid_cache(self, abi_dir: Path, address: str) -> ABIMetadata:
        addr = address.lower()
        abi_path = abi_dir / f"{addr}.json"
        content = json.dumps(SAMPLE_ABI, indent=2, sort_keys=True) + "\n"
        abi_path.write_text(content, encoding="utf-8")
        checksum = _sha256_file(abi_path)
        meta = ABIMetadata(
            address=addr,
            abi=SAMPLE_ABI,
            source="etherscan",
            raw_artifact_path="",
            source_url="https://api.etherscan.io/v2/api?chainid=1&...",
            checksum=checksum,
            coverage_status="verified",
        )
        _write_abi_metadata(meta, abi_dir)
        return meta

    def test_valid_cache_passes_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._create_valid_cache(abi_dir, ADDR_A)
            abi_path = abi_dir / f"{ADDR_A.lower()}.json"
            valid, reason = validate_abi_cache(abi_path)
            self.assertTrue(valid, f"Expected valid, got: {reason}")

    def test_corrupted_abi_fails_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._create_valid_cache(abi_dir, ADDR_A)
            abi_path = abi_dir / f"{ADDR_A.lower()}.json"
            # Tamper with content
            abi_path.write_text("[{\"corrupted\": true}]\n", encoding="utf-8")
            valid, reason = validate_abi_cache(abi_path)
            self.assertFalse(valid)
            self.assertIn("mismatch", reason.lower())

    def test_missing_abi_file_fails_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_path = Path(tmp) / "0xnonexistent.json"
            valid, reason = validate_abi_cache(abi_path)
            self.assertFalse(valid)
            self.assertIn("missing", reason.lower())

    def test_missing_metadata_sidecar_fails_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_path = Path(tmp) / f"{ADDR_A.lower()}.json"
            abi_path.write_text(json.dumps(SAMPLE_ABI), encoding="utf-8")
            valid, reason = validate_abi_cache(abi_path)
            self.assertFalse(valid)
            self.assertIn("sidecar", reason.lower())

    def test_meta_checksum_and_source_url_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_non_proxy_response(),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            client.fetch_abi(ADDR_A, abi_dir, raw_dir)

            meta_path = abi_dir / f"{ADDR_A.lower()}.meta.json"
            self.assertTrue(meta_path.exists(), ".meta.json sidecar must exist")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertIn("checksum", meta)
            self.assertTrue(meta["checksum"], "checksum must not be empty")
            self.assertIn("source_url", meta)
            self.assertTrue(meta["source_url"], "source_url must not be empty")


# ---------------------------------------------------------------------------
# E5.5  Proxy contract resolution
# ---------------------------------------------------------------------------

class TestProxyResolution(unittest.TestCase):
    def test_proxy_implementation_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_proxy_response(IMPL_ADDR),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            meta = client.fetch_abi(ADDR_A, abi_dir, raw_dir, resolve_proxy=True)

            self.assertTrue(meta.is_proxy, "is_proxy must be True")
            self.assertEqual(meta.implementation_address, IMPL_ADDR.lower())

    def test_non_proxy_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_non_proxy_response(),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            meta = client.fetch_abi(ADDR_A, abi_dir, raw_dir, resolve_proxy=True)
            self.assertFalse(meta.is_proxy)
            self.assertEqual(meta.implementation_address, "")

    def test_resolve_proxy_implementation_standalone(self) -> None:
        opener = _MockOpener({
            "getsourcecode": _getsourcecode_proxy_response(IMPL_ADDR),
        })
        result = resolve_proxy_implementation(
            ADDR_A, API_BASE, API_KEY, opener=opener
        )
        self.assertEqual(result, IMPL_ADDR.lower())

    def test_resolve_proxy_returns_none_for_non_proxy(self) -> None:
        opener = _MockOpener({
            "getsourcecode": _getsourcecode_non_proxy_response(),
        })
        result = resolve_proxy_implementation(
            ADDR_A, API_BASE, API_KEY, opener=opener
        )
        self.assertIsNone(result)

    def test_proxy_meta_json_has_implementation_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_proxy_response(IMPL_ADDR),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            client.fetch_abi(ADDR_A, abi_dir, raw_dir, resolve_proxy=True)

            meta_path = abi_dir / f"{ADDR_A.lower()}.meta.json"
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertTrue(meta["is_proxy"])
            self.assertEqual(meta["implementation_address"], IMPL_ADDR.lower())


# ---------------------------------------------------------------------------
# E5.6  Local protocol-repository ABI fallback
# ---------------------------------------------------------------------------

class TestLocalABIFallback(unittest.TestCase):
    def test_fallback_used_when_etherscan_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            local_dir = Path(tmp) / "protocol_abis"
            abi_dir.mkdir()
            local_dir.mkdir()

            # Seed local fallback
            addr = ADDR_A.lower()
            (local_dir / f"{addr}.json").write_text(
                json.dumps(SAMPLE_ABI), encoding="utf-8"
            )

            # Etherscan always fails
            def bad_opener(req: Any, timeout: float = 30.0) -> Any:
                raise ConnectionError("simulated network failure")

            # fetch_abi should succeed via local fallback
            paths = fetch_abi(
                [ADDR_A],
                API_BASE,
                API_KEY,
                abi_dir,
                local_fallback_dir=local_dir,
                opener=bad_opener,
                retry_policy=RetryPolicy(max_attempts=1),
            )
            self.assertTrue(len(paths) == 1)
            self.assertTrue((abi_dir / f"{addr}.json").exists())

            # .meta.json must say protocol_repository
            meta_path = abi_dir / f"{addr}.meta.json"
            self.assertTrue(meta_path.exists())
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(meta["source"], "protocol_repository")
            self.assertEqual(meta["coverage_status"], "fallback")

            valid, reason = validate_abi_cache(
                abi_dir / f"{addr}.json", meta_path
            )
            self.assertTrue(valid, reason)

    def test_fallback_works_without_etherscan_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            local_dir = Path(tmp) / "protocol_abis"
            abi_dir.mkdir()
            local_dir.mkdir()
            addr = ADDR_A.lower()
            (local_dir / f"{addr}.json").write_text(
                json.dumps(SAMPLE_ABI), encoding="utf-8"
            )

            paths = fetch_abi(
                [ADDR_A], API_BASE, "", abi_dir,
                local_fallback_dir=local_dir,
                retry_policy=RetryPolicy(max_attempts=1),
            )

            self.assertEqual(paths, [abi_dir / f"{addr}.json"])
            meta = json.loads(
                (abi_dir / f"{addr}.meta.json").read_text(encoding="utf-8")
            )
            self.assertTrue(meta["source_url"])

    def test_fallback_returns_none_for_unknown_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fallback = LocalABIFallback(Path(tmp))
            result = fallback.find_abi(ADDR_A)
            self.assertIsNone(result)

    def test_fallback_absent_directory_returns_none(self) -> None:
        fallback = LocalABIFallback(Path("/nonexistent/protocol_abis"))
        result = fallback.find_abi(ADDR_A)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------

class TestCredentialRedaction(unittest.TestCase):
    def test_api_key_not_in_error_message(self) -> None:
        """API key must never appear in exception messages."""
        def bad_opener(req: Any, timeout: float = 30.0) -> Any:
            raise ConnectionError(f"connection refused while fetching with key={API_KEY}")

        url = build_etherscan_v2_url(API_BASE, "contract", "getabi", ADDR_A, API_KEY)
        try:
            fetch_raw_etherscan_response(url, opener=bad_opener)
            self.fail("Expected exception")
        except Exception as exc:
            self.assertNotIn(API_KEY, str(exc), "API key must not appear in exception message")

    def test_api_key_redacted_in_source_url_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            raw_dir = Path(tmp) / "raw"
            abi_dir.mkdir()

            opener = _MockOpener({
                "getabi": _etherscan_ok_response(),
                "getsourcecode": _getsourcecode_non_proxy_response(),
            })
            client = EtherscanABIClient(
                API_BASE, API_KEY,
                retry_policy=RetryPolicy(max_attempts=1),
                opener=opener,
            )
            meta = client.fetch_abi(ADDR_A, abi_dir, raw_dir)

            self.assertNotIn(API_KEY, meta.source_url)

            meta_path = abi_dir / f"{ADDR_A.lower()}.meta.json"
            stored = meta_path.read_text(encoding="utf-8")
            self.assertNotIn(API_KEY, stored)

    def test_authentication_error_on_invalid_key(self) -> None:
        auth_err_body = json.dumps({
            "status": "0",
            "message": "NOTOK",
            "result": "Invalid API Key",
        }).encode()

        opener = _MockOpener({"getabi": auth_err_body})
        url = build_etherscan_v2_url(API_BASE, "contract", "getabi", ADDR_A, API_KEY)
        with self.assertRaises(AuthenticationError):
            fetch_raw_etherscan_response(url, opener=opener)


# ---------------------------------------------------------------------------
# ABI coverage reporting
# ---------------------------------------------------------------------------

class TestABICoverageReport(unittest.TestCase):
    def _seed_verified(self, abi_dir: Path, address: str) -> None:
        addr = address.lower()
        abi_path = abi_dir / f"{addr}.json"
        abi_path.write_text(json.dumps(SAMPLE_ABI, indent=2) + "\n", encoding="utf-8")
        checksum = _sha256_file(abi_path)
        meta = ABIMetadata(
            address=addr, abi=SAMPLE_ABI, source="etherscan",
            raw_artifact_path="", source_url="https://example.test",
            checksum=checksum, coverage_status="verified",
        )
        _write_abi_metadata(meta, abi_dir)

    def _seed_fallback(self, abi_dir: Path, address: str) -> None:
        addr = address.lower()
        abi_path = abi_dir / f"{addr}.json"
        abi_path.write_text(json.dumps(SAMPLE_ABI, indent=2) + "\n", encoding="utf-8")
        checksum = _sha256_file(abi_path)
        meta = ABIMetadata(
            address=addr, abi=SAMPLE_ABI, source="protocol_repository",
            raw_artifact_path="", source_url="",
            checksum=checksum, coverage_status="fallback",
        )
        _write_abi_metadata(meta, abi_dir)

    def test_100_percent_coverage_returns_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._seed_verified(abi_dir, ADDR_A)
            self._seed_verified(abi_dir, ADDR_B)
            report = compute_abi_coverage_report([ADDR_A, ADDR_B], abi_dir)
            self.assertEqual(report["status"], "GO")
            self.assertEqual(report["abi_coverage_percentage"], 100.0)

    def test_fallback_address_returns_conditional_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._seed_verified(abi_dir, ADDR_A)
            self._seed_fallback(abi_dir, ADDR_B)
            report = compute_abi_coverage_report([ADDR_A, ADDR_B], abi_dir)
            self.assertEqual(report["status"], "CONDITIONAL_GO")
            self.assertEqual(report["fallback_count"], 1)

    def test_missing_address_returns_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._seed_verified(abi_dir, ADDR_A)
            # ADDR_B has no ABI
            report = compute_abi_coverage_report([ADDR_A, ADDR_B], abi_dir)
            self.assertEqual(report["status"], "NO_GO")
            self.assertEqual(report["missing_count"], 1)
            self.assertIn(ADDR_B.lower(), report["missing_addresses"])

    def test_empty_address_list_returns_go(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = compute_abi_coverage_report([], Path(tmp))
            self.assertEqual(report["status"], "GO")
            self.assertEqual(report["abi_coverage_percentage"], 100.0)

    def test_report_contains_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            self._seed_verified(abi_dir, ADDR_A)
            report = compute_abi_coverage_report([ADDR_A], abi_dir, event_id="test_event")
            for key in (
                "event_id", "total_addresses", "verified_count", "fallback_count",
                "missing_count", "abi_coverage_percentage", "proxy_addresses", "status",
            ):
                self.assertIn(key, report, f"Report missing field: {key}")

    def test_proxy_without_implementation_evidence_is_conditional(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp)
            abi_path = abi_dir / f"{ADDR_A.lower()}.json"
            abi_path.write_text(json.dumps(SAMPLE_ABI), encoding="utf-8")
            checksum = _sha256_file(abi_path)
            _write_abi_metadata(
                ABIMetadata(
                    address=ADDR_A.lower(),
                    abi=SAMPLE_ABI,
                    source="etherscan",
                    raw_artifact_path="",
                    source_url="https://example.test",
                    checksum=checksum,
                    is_proxy=True,
                    implementation_address=IMPL_ADDR.lower(),
                    implementation_checksum="",
                    coverage_status="verified",
                ),
                abi_dir,
            )

            report = compute_abi_coverage_report([ADDR_A], abi_dir)

            self.assertEqual(report["status"], "CONDITIONAL_GO")
            self.assertEqual(report["fallback_count"], 1)


# ---------------------------------------------------------------------------
# Integration: fetch_abi backward compatibility
# ---------------------------------------------------------------------------

class TestFetchABIBackwardCompatibility(unittest.TestCase):
    def test_fetch_abi_with_http_get_kwarg(self) -> None:
        """Existing callers using http_get= must still work."""
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            abi_dir.mkdir()

            def http_get(url: str) -> bytes:
                return _etherscan_ok_response()

            paths = fetch_abi(
                [ADDR_A],
                API_BASE,
                API_KEY,
                abi_dir,
                http_get=http_get,
                retry_policy=RetryPolicy(max_attempts=1),
            )
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].exists())

    def test_fetch_abi_deduplicates_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            abi_dir = Path(tmp) / "abi"
            abi_dir.mkdir()

            calls = []

            def http_get(url: str) -> bytes:
                calls.append(url)
                return _etherscan_ok_response()

            # Same address passed twice (different case)
            fetch_abi(
                [ADDR_A, ADDR_A.upper()],
                API_BASE,
                API_KEY,
                abi_dir,
                http_get=http_get,
                retry_policy=RetryPolicy(max_attempts=1),
            )
            # Should only fetch once
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()

