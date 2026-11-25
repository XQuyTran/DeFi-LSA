"""Unit and integration tests for D2 collection orchestration (E3).

Tests CollectionContext, stage dispatch (logs, transactions, receipts, abi, prices,
public sources, all), dry-run planning, checkpoint resumption, versioned force,
and CLI invocations with deterministic stubs and no live network calls.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

from defi_lsa.cli import build_parser
from defi_lsa.config import SourceConfig
from defi_lsa.collectors import DiscoveredTransactions
from defi_lsa.orchestration import CollectionContext
from defi_lsa.registry import ContractScope, IncidentLeg
from defi_lsa.storage import read_jsonl_records


def _make_scope() -> ContractScope:
    return ContractScope(
        event_id="euler_2023-03-13",
        chain_id=1,
        addresses=(
            "0x27182842e098f60e3d576794a5bffb0777e025d3",
            "0x036cec1a199234fc02f72d29e596a09440825f1c",
        ),
        rationale="test scope",
    )


def _make_context(output_root: Path, **overrides: Any) -> CollectionContext:
    event = {
        "event_id": "euler_2023-03-13",
        "chain_id": 1,
        "protocol": "Euler Finance",
        "start_block": 16818024,
        "end_block": 16818025,
        "collection_start_utc": "2023-03-13T08:56:35Z",
        "collection_end_utc": "2023-03-13T08:56:35Z",
        "event_date_utc": "2023-03-13",
        "exploit_tx_hash": "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",
        "tokens_related": ["WETH", "DAI", "USDC"],
    }
    config = SourceConfig(
        ethereum_rpc_url="https://rpc.example.test/token",
        etherscan_api_key="TEST_ETHERSCAN_KEY",
        etherscan_api_url="https://api.etherscan.io/v2/api",
        coingecko_api_key="TEST_CG_KEY",
        coingecko_api_url="https://api.coingecko.com/api/v3",
        requests_per_second=100.0,
    )
    legs = (
        IncidentLeg(
            leg_id="euler-leg-1",
            event_id="euler_2023-03-13",
            chain_id=1,
            affected_address="0x27182842e098f60e3d576794a5bffb0777e025d3",
            asset_pair="WETH/DAI",
            transaction_hash="0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",
            block_number=16818024,
            actor_address="0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
            role="attacker",
            evidence_urls=("https://etherscan.io/tx/0x47ac",),
        ),
    )
    params: dict[str, Any] = {
        "event": event,
        "scope": _make_scope(),
        "source_config": config,
        "output_root": output_root,
        "run_id": "test-run-123",
        "incident_legs": legs,
    }
    params.update(overrides)
    return CollectionContext(**params)


class MockHttpResponse:
    def __init__(self, data: Any):
        if isinstance(data, (dict, list)):
            self.content = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            self.content = data.encode("utf-8")
        else:
            self.content = data

    def read(self) -> bytes:
        return self.content

    def __enter__(self) -> MockHttpResponse:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class OrchestrationTests(unittest.TestCase):
    def test_canonical_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root)

            self.assertEqual(
                ctx.logs_path,
                root / "data" / "raw" / "normalized" / "logs" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.transactions_path,
                root / "data" / "raw" / "normalized" / "transactions" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.receipts_path,
                root / "data" / "raw" / "normalized" / "receipts" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.transaction_index_path,
                root / "data" / "raw" / "normalized" / "transaction_index" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.abi_dir,
                root / "data" / "raw" / "source" / "abi" / "euler_2023-03-13",
            )
            self.assertEqual(
                ctx.prices_path,
                root / "reports" / "euler_2023-03-13" / "price_anchor_report.json",
            )
            self.assertEqual(
                ctx.discourse_path,
                root / "data" / "raw" / "normalized" / "discourse" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.gdelt_path,
                root / "data" / "raw" / "normalized" / "gdelt" / "euler_2023-03-13.jsonl",
            )
            self.assertEqual(
                ctx.protocol_path,
                root / "data" / "raw" / "normalized" / "protocol" / "euler_2023-03-13.jsonl",
            )

    def test_dry_run_plan_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root, dry_run=True)
            plan = ctx.dry_run_plan()

            self.assertTrue(plan["dry_run"])
            self.assertEqual(plan["event_id"], "euler_2023-03-13")
            self.assertEqual(plan["start_block"], 16818024)
            self.assertEqual(plan["end_block"], 16818025)
            self.assertIn("0x27182842e098f60e3d576794a5bffb0777e025d3", plan["scope_addresses"])
            self.assertIn("0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f", plan["registered_tx_hashes"])
            self.assertIn("logs", plan["paths"])

    def test_dry_run_plan_uses_effective_range_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(
                Path(tmp),
                dry_run=True,
                requested_start_block=16818024,
                requested_end_block=16818024,
            )

            plan = ctx.dry_run_plan()

            self.assertEqual(plan["start_block"], 16818024)
            self.assertEqual(plan["end_block"], 16818024)
            self.assertEqual(plan["registry_end_block"], 16818025)
            self.assertTrue(plan["range_override"])

    def test_from_files_requires_paired_range_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "supplied together"):
                CollectionContext.from_files(
                    "euler",
                    events_path=Path("configs/events.json"),
                    source_config=_make_context(Path(tmp)).source_config,
                    output_root=Path(tmp),
                    start_block=16818024,
                )

    def test_from_files_rejects_inverted_range_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "non-negative and ordered"):
                CollectionContext.from_files(
                    "euler",
                    events_path=Path("configs/events.json"),
                    source_config=_make_context(Path(tmp)).source_config,
                    output_root=Path(tmp),
                    start_block=16818025,
                    end_block=16818024,
                )

    def test_collect_logs_rpc_and_checkpoints(self) -> None:
        def rpc_handler(method: str, params: list[Any]) -> Any:
            if method == "eth_getLogs":
                return [
                    {
                        "address": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                        "blockNumber": hex(16818024),
                        "transactionHash": "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f",
                        "logIndex": "0x0",
                        "topics": [],
                        "data": "0x",
                    }
                ]
            raise AssertionError(f"unexpected rpc method {method}")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root, rpc=rpc_handler)
            res = ctx.collect_logs()

            self.assertEqual(res.records_written, 1)
            self.assertTrue(ctx.logs_path.exists())
            records = read_jsonl_records(ctx.logs_path)
            self.assertEqual(len(records), 1)

            # Checkpoint verification
            cp = ctx.checkpoints.load_checkpoint(ctx.event_id, "logs")
            self.assertIsNotNone(cp)
            self.assertEqual(cp.completed_ranges, [(16818024, 16818025)])

    def test_collect_logs_checkpoint_uses_effective_override(self) -> None:
        def rpc_handler(method: str, params: list[Any]) -> Any:
            if method == "eth_getLogs":
                return []
            raise AssertionError(f"unexpected rpc method {method}")

        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(
                Path(tmp),
                rpc=rpc_handler,
                requested_start_block=16818024,
                requested_end_block=16818024,
            )
            ctx.collect_logs()

            checkpoint = ctx.checkpoints.load_checkpoint(ctx.event_id, "logs")
            self.assertIsNotNone(checkpoint)
            self.assertEqual(checkpoint.requested_start, 16818024)
            self.assertEqual(checkpoint.requested_end, 16818024)

    def test_collect_transactions_and_receipts(self) -> None:
        def rpc_handler(method: str, params: list[Any]) -> Any:
            tx_h = "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f"
            if method == "eth_getTransactionByHash":
                return {
                    "hash": tx_h,
                    "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                    "to": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                    "blockNumber": hex(16818024),
                    "value": "0x0",
                    "gas": "0x5208",
                    "gasPrice": "0x4a817c800",
                    "nonce": "0x0",
                }
            if method == "eth_getTransactionReceipt":
                return {
                    "transactionHash": tx_h,
                    "status": "0x1",
                    "blockNumber": hex(16818024),
                    "gasUsed": "0x1000",
                    "logs": [],
                }
            raise AssertionError(f"unexpected rpc method {method}")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root, rpc=rpc_handler)
            tx_res = ctx.collect_transactions()
            rc_res = ctx.collect_receipts()

            self.assertEqual(tx_res.records_written, 1)
            self.assertEqual(rc_res.records_written, 1)
            self.assertTrue(ctx.transactions_path.exists())
            self.assertTrue(ctx.receipts_path.exists())
            self.assertTrue(ctx.transaction_index_path.exists())

    def test_collect_transactions_from_aws(self) -> None:
        tx_hash = "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f"
        aws_adapter = MagicMock()
        aws_adapter.fetch_table.return_value = [
            {
                "hash": tx_hash,
                "block_number": 16818024,
                "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                "to": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                "value": 0,
                "gas": 21000,
                "gas_price": 1,
                "nonce": 0,
            }
        ]

        def rpc_handler(method: str, params: list[Any]) -> Any:
            if method == "eth_getTransactionByHash":
                return {
                    "hash": tx_hash,
                    "blockNumber": hex(16818024),
                    "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                    "to": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                    "value": "0x0",
                    "gas": "0x5208",
                    "gasPrice": "0x1",
                    "nonce": "0x0",
                }
            raise AssertionError(f"unexpected rpc method {method}")

        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp))
            discovered = DiscoveredTransactions({(tx_hash, ("registry_anchor",))})
            with patch.object(CollectionContext, "aws_adapter", new_callable=PropertyMock) as aws_property, patch.object(
                CollectionContext, "discover_transactions", return_value=discovered
            ), patch.object(
                CollectionContext, "_rpc_caller", return_value=(rpc_handler, MagicMock())
            ):
                aws_property.return_value = aws_adapter
                result = ctx.collect_transactions(source="aws")

            self.assertEqual(result.records_written, 1)
            self.assertEqual(read_jsonl_records(ctx.transactions_path)[0]["source"], "aws")
            aws_adapter.fetch_table.assert_called_once()
            report = json.loads(
                (ctx.reports_dir / "transactions_aws_rpc_reconciliation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["status"], "match")

    def test_auto_transaction_source_falls_back_from_aws_http_400(self) -> None:
        tx_hash = "0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f"
        aws_adapter = MagicMock()
        aws_adapter.fetch_table.side_effect = RuntimeError("HTTP Error 400: Bad Request")

        def rpc_handler(method: str, params: list[Any]) -> Any:
            if method == "eth_getTransactionByHash":
                return {
                    "hash": tx_hash,
                    "blockNumber": hex(16818024),
                    "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                    "to": "0x27182842e098f60e3d576794a5bffb0777e025d3",
                    "value": "0x0",
                    "gas": "0x5208",
                    "gasPrice": "0x1",
                    "nonce": "0x0",
                }
            raise AssertionError(f"unexpected rpc method {method}")

        config = SourceConfig(
            ethereum_rpc_url="https://rpc.example.test/token",
            source_priority={"transactions": ("aws_public_blockchain", "ethereum_rpc")},
        )
        discovered = DiscoveredTransactions({(tx_hash, ("registry_anchor",))})
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp), source_config=config)
            with patch.object(CollectionContext, "aws_adapter", new_callable=PropertyMock) as aws_property, patch.object(
                CollectionContext, "discover_transactions", return_value=discovered
            ), patch.object(
                CollectionContext, "_rpc_caller", return_value=(rpc_handler, MagicMock())
            ):
                aws_property.return_value = aws_adapter
                result = ctx.collect_transactions(source="auto")

            self.assertEqual(result.records_written, 1)
            self.assertEqual(read_jsonl_records(ctx.transactions_path)[0]["source"], "rpc")

    def test_collect_aws_table_streams_batches_to_normalized_storage(self) -> None:
        batch = [{
            "number": 16818024,
            "timestamp": 1678708800,
            "gas_used": 100,
            "hash": "0x" + "a" * 64,
        }]
        aws_adapter = MagicMock()
        aws_adapter.iter_table_batches.return_value = iter([batch])

        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp))
            with patch.object(CollectionContext, "aws_adapter", new_callable=PropertyMock) as aws_property:
                aws_property.return_value = aws_adapter
                result = ctx.collect_aws_table("blocks")

            records = read_jsonl_records(ctx.blocks_path)
            self.assertEqual(result.records_written, 1)
            self.assertEqual(records[0]["source"], "aws")
            expected_digest = hashlib.sha256(
                json.dumps(batch, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            self.assertEqual(result.source_sha256, expected_digest)
            aws_adapter.iter_table_batches.assert_called_once()

    def test_auto_transaction_source_selects_configured_aws(self) -> None:
        config = SourceConfig(
            ethereum_rpc_url="https://rpc.example.test/token",
            source_priority={"transactions": ("aws_public_blockchain", "ethereum_rpc")},
        )
        aws_adapter = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp), source_config=config)
            with patch.object(CollectionContext, "aws_adapter", new_callable=PropertyMock) as aws_property, patch.object(
                CollectionContext, "discover_transactions", return_value=DiscoveredTransactions()
            ):
                aws_property.return_value = aws_adapter
                result = ctx.collect_transactions(source="auto")

            self.assertEqual(result.records_written, 0)
            aws_adapter.fetch_table.assert_not_called()

    def test_aws_verification_report_retains_mismatch_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp))
            aws_record = {"record_key": "key", "data": "0x01", "source": "aws"}
            rpc_record = {"record_key": "key", "data": "0x02", "source": "rpc"}

            ctx._write_aws_verification_report(
                "logs", [aws_record], [rpc_record], "record_key"
            )
            report = json.loads(
                (ctx.reports_dir / "logs_aws_rpc_reconciliation.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(report["status"], "mismatch")
            conflict = report["comparison"]["conflicts"][0]
            self.assertEqual(conflict["primary"]["data"], "0x01")
            self.assertEqual(conflict["secondary"]["data"], "0x02")

    def test_aws_verification_report_marks_rpc_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp))
            aws_record = {"record_key": "key", "source": "aws"}

            ctx._write_aws_verification_report(
                "transactions",
                [aws_record],
                [],
                "record_key",
                ["RPC verification unavailable"],
            )
            report = json.loads(
                (ctx.reports_dir / "transactions_aws_rpc_reconciliation.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(report["status"], "unavailable")
            self.assertEqual(report["comparison"]["missing_from_secondary"], ["key"])

    def test_aws_verification_report_marks_missing_aws_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _make_context(Path(tmp))
            rpc_record = {"record_key": "key", "source": "rpc"}

            ctx._write_aws_verification_report(
                "logs", [], [rpc_record], "record_key"
            )
            report = json.loads(
                (ctx.reports_dir / "logs_aws_rpc_reconciliation.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(report["status"], "mismatch")
            self.assertEqual(report["comparison"]["missing_from_primary"], ["key"])

    def test_collect_abi_cached_and_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root)

            # Pre-seed cache for one address
            ctx.abi_dir.mkdir(parents=True, exist_ok=True)
            cached_addr = "0x27182842e098f60e3d576794a5bffb0777e025d3"
            (ctx.abi_dir / f"{cached_addr}.json").write_text(json.dumps([{"name": "test"}]), encoding="utf-8")

            # Mock fetch_abi for missing address
            def mock_fetch(addresses, api_url, api_key, out_dir, **kwargs):
                self.assertEqual(len(addresses), 1)
                p = out_dir / f"{addresses[0]}.json"
                p.write_text("[]", encoding="utf-8")
                return [p]

            with patch("defi_lsa.orchestration.fetch_abi", side_effect=mock_fetch):
                res = ctx.collect_abi()

            self.assertEqual(res.records_skipped, 1)  # 1 cached
            self.assertEqual(res.records_written, 1)  # 1 fetched

    def test_collect_prices_defillama_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            addresses = {
                "weth": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                "dai": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "usdc": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            }

            def mock_opener(req: Any, timeout: float = 30) -> MockHttpResponse:
                url = req.full_url
                address = next(value for value in addresses.values() if value in url)
                return MockHttpResponse({
                    "coins": {
                        f"ethereum:{address}": {
                            "price": 1.0,
                            "timestamp": 1678697700,
                            "confidence": 0.99,
                        }
                    }
                })

            ctx = _make_context(root, opener=mock_opener)
            res = ctx.collect_prices()

            self.assertEqual(res.records_written, 3)
            self.assertTrue(ctx.prices_path.exists())
            report = json.loads(ctx.prices_path.read_text(encoding="utf-8"))
            self.assertEqual(report["anchor_timestamp_utc"], "2023-03-13T08:56:34Z")
            self.assertEqual(set(report["prices"]), {"WETH", "DAI", "USDC"})

    def test_collect_prices_skips_disabled_defillama(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            opener = MagicMock()
            config = SourceConfig(enabled_sources={"defillama": False})
            ctx = _make_context(Path(tmp), source_config=config, opener=opener)

            result = ctx.collect_prices(source="auto")

            self.assertEqual(result.records_written, 0)
            opener.assert_not_called()
            self.assertFalse(ctx.prices_path.exists())

    def test_collect_public_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def mock_urlopen(req: Any, timeout: float = 30) -> MockHttpResponse:
                url = req.full_url if hasattr(req, "full_url") else str(req)
                if "gdeltproject" in url:
                    return MockHttpResponse({"articles": [
                        {"url": "https://news.example/1", "title": "Euler exploit", "seendate": "20230313T090000Z"}
                    ]})
                if "feed" in url or "blog" in url:
                    return MockHttpResponse({
                        "items": [{"title": "Postmortem", "url": "https://euler.finance/blog/1", "published_at": "2023-03-13T09:00:00Z"}]
                    })
                return MockHttpResponse({})

            ctx = _make_context(root, opener=mock_urlopen)
            results = ctx.collect_public_sources()

            self.assertIn("gdelt", results)
            self.assertIn("protocol", results)

    def test_collect_all_dependency_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root)

            execution_order = []
            def track_abi(**kwargs):
                execution_order.append("abi")
                return MagicMock(records_written=1, records_skipped=0)
            def track_logs(**kwargs):
                execution_order.append("logs")
                return MagicMock(records_written=1, records_skipped=0)
            def track_tx(**kwargs):
                execution_order.append("transactions")
                return MagicMock(records_written=1, records_skipped=0)
            def track_rc(**kwargs):
                execution_order.append("receipts")
                return MagicMock(records_written=1, records_skipped=0)
            def track_prices(**kwargs):
                execution_order.append("prices")
                return MagicMock(records_written=1, records_skipped=0)
            def track_public(**kwargs):
                execution_order.append("public_sources")
                return {"gdelt": MagicMock(records_written=1, records_skipped=0)}

            with patch.object(CollectionContext, "collect_abi", side_effect=track_abi), \
                 patch.object(CollectionContext, "collect_logs", side_effect=track_logs), \
                 patch.object(CollectionContext, "collect_transactions", side_effect=track_tx), \
                 patch.object(CollectionContext, "collect_receipts", side_effect=track_rc), \
                 patch.object(CollectionContext, "collect_prices", side_effect=track_prices), \
                 patch.object(CollectionContext, "collect_public_sources", side_effect=track_public):
                ctx.collect_all()

            expected_order = ["abi", "logs", "transactions", "receipts", "prices", "public_sources"]
            self.assertEqual(execution_order, expected_order)

    def test_versioned_force_archives_prior_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = _make_context(root, force=True)

            # Pre-create a logs file and checkpoint
            ctx.logs_path.parent.mkdir(parents=True, exist_ok=True)
            ctx.logs_path.write_text('{"record_key": "1"}\n', encoding="utf-8")
            cp_path = ctx.checkpoints.checkpoint_path(ctx.event_id, "logs")
            cp_path.parent.mkdir(parents=True, exist_ok=True)
            cp_path.write_text("{}", encoding="utf-8")

            # Call handle force
            ctx._handle_force("logs", [ctx.logs_path])

            self.assertFalse(ctx.logs_path.exists())
            self.assertFalse(cp_path.exists())
            # Archive directory should have captured the files
            archive_dirs = list((root / "data" / "raw" / "archive").glob("*"))
            self.assertGreater(len(archive_dirs), 0)

    def test_cli_collect_dry_run_invocation(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["collect", "--event", "euler", "--stage", "all", "--dry-run"])
        self.assertEqual(args.event, "euler")
        self.assertEqual(args.stage, "all")
        self.assertTrue(args.dry_run)
        ret = args.handler(args)
        self.assertEqual(ret, 0)

    def test_cli_collect_all_parser_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "collect",
            "--event", "euler",
            "--stage", "all",
            "--source", "auto",
            "--resume",
            "--force",
        ])
        self.assertEqual(args.stage, "all")
        self.assertEqual(args.source, "auto")
        self.assertTrue(args.resume)
        self.assertTrue(args.force)

    def test_cli_accepts_extended_aws_stages(self) -> None:
        parser = build_parser()
        for stage in ("blocks", "token_transfers", "traces", "contracts"):
            args = parser.parse_args(["collect", "--event", "euler", "--stage", stage])
            self.assertEqual(args.stage, stage)


if __name__ == "__main__":
    unittest.main()
