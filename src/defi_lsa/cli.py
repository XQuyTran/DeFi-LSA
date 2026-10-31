"""Command-line entry points for the data-readiness pipeline."""



import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .collectors import ADAPTER_VERSION, collect_source_manifest
from .config import load_source_config
from .observability import CollectionMetrics
from .audit import (
    audit_abi_coverage,
    audit_block_coverage,
    audit_log_range_coverage,
    audit_receipt_coverage,
    audit_registered_transaction_coverage,
    build_d2_gate_report,
)
from .checkpoints import CheckpointStore
from .orchestration import CollectionContext
from .registry import (
    build_contract_scope,
    candidates_as_dicts,
    load_event_candidates,
    load_incident_legs,
    load_public_source_registry,
    load_token_registry,
    validate_executable_candidates,
    write_registry_manifest,
)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _registry_command(args: argparse.Namespace) -> int:
    candidates = load_event_candidates(args.input)
    incident_legs = (
        load_incident_legs(args.incident_legs)
        if args.incident_legs.exists()
        else []
    )
    validate_executable_candidates(candidates, incident_legs)
    load_token_registry(args.tokens)
    load_public_source_registry(args.public_sources)
    scopes = [build_contract_scope(candidate, incident_legs) for candidate in candidates]
    args.events_output.parent.mkdir(parents=True, exist_ok=True)
    args.events_output.write_text(
        json.dumps(candidates_as_dicts(candidates), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.scope_output.write_text(
        json.dumps([scope.__dict__ for scope in scopes], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    write_registry_manifest(
        args.manifest_output,
        [
            args.input,
            args.events_output,
            args.scope_output,
            *([args.incident_legs] if args.incident_legs.exists() else []),
            args.tokens,
            args.public_sources,
        ],
    )
    print(f"Validated {len(candidates)} event candidates")
    print(f"Wrote contract scopes to {args.scope_output}")
    return 0


def _build_command(args: argparse.Namespace) -> int:
    candidates = load_event_candidates(args.input)
    selected = [candidate for candidate in candidates if candidate.event_id.startswith(args.event)]
    if not selected:
        raise SystemExit(f"No event matched: {args.event}")
    print(
        "Registry validation passed; D2-D5 collectors are not yet implemented "
        f"for {selected[0].event_id}."
    )
    return 0


def _source_manifest_command(args: argparse.Namespace) -> int:
    artifacts = []
    for item in args.artifact:
        first_sep = item.find("=")
        last_sep = item.rfind("=")
        if first_sep <= 0 or last_sep <= first_sep:
            raise ValueError(
                f"invalid --artifact value {item!r}; expected SOURCE=URL=PATH"
            )
        source = item[:first_sep]
        url = item[first_sep + 1:last_sep]
        path = item[last_sep + 1:]
        artifact_path = Path(path)
        artifacts.append((source, url, artifact_path, ADAPTER_VERSION))
    collect_source_manifest(args.output, artifacts)
    print(f"Wrote source manifest to {args.output}")
    return 0


def _connectivity_command(args: argparse.Namespace) -> int:
    config = load_source_config(args.config)
    config.validate()
    statuses: dict[str, str] = {}

    def probe_http(name: str, url: str, *, headers: dict[str, str] | None = None) -> None:
        try:
            request = Request(url, headers=headers or {"Accept": "application/json"})
            with urlopen(request, timeout=config.request_timeout_seconds) as response:
                response.read(1)
        except Exception as exc:
            status = getattr(exc, "code", None)
            statuses[name] = "authentication_error" if status in (401, 403) else "unreachable"
        else:
            statuses[name] = "reachable"

    if args.source in ("rpc", "auto"):
        if not config.ethereum_rpc_url:
            statuses["ethereum_rpc"] = "authentication_error"
        else:
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
            ).encode("utf-8")
            try:
                request = Request(
                    config.ethereum_rpc_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(request, timeout=config.request_timeout_seconds) as response:
                    body = json.loads(response.read().decode("utf-8"))
                if body.get("error") or body.get("result") != "0x1":
                    statuses["ethereum_rpc"] = "unreachable"
                else:
                    statuses["ethereum_rpc"] = "reachable"
            except Exception as exc:
                status = getattr(exc, "code", None)
                statuses["ethereum_rpc"] = "authentication_error" if status in (401, 403) else "unreachable"

    if args.source in ("etherscan", "auto"):
        query = urlencode(
            {
                "module": "contract",
                "action": "getabi",
                "address": "0x0000000000000000000000000000000000000000",
                "chainid": config.etherscan_chain_id,
                "apikey": config.etherscan_api_key,
            }
        )
        probe_http("etherscan", f"{config.etherscan_api_url}?{query}")

    if args.source in ("coingecko", "auto"):
        headers = {"Accept": "application/json"}
        if config.coingecko_api_key:
            headers[config.coingecko_api_key_header] = config.coingecko_api_key
        probe_http("coingecko", f"{config.coingecko_api_url.rstrip('/')}/ping", headers=headers)

    if args.source in ("gdelt", "auto"):
        probe_http("gdelt", f"{config.gdelt_doc_api_url}?query=ethereum&mode=artlist&format=json&maxrecords=1")

    if args.source in ("aws", "auto"):
        aws = config.aws_public_blockchain
        bucket = aws.get("bucket", "aws-public-blockchain")
        region = aws.get("region", "us-east-2")
        probe_http(
            "aws_public_blockchain",
            f"https://{bucket}.s3.{region}.amazonaws.com/?list-type=2&prefix=v1.0/eth/&max-keys=1",
        )

    result = {"event": args.event, "run_id": uuid.uuid4().hex, "statuses": statuses}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if all(status == "reachable" for status in statuses.values()) else 1


def _collect_command(args: argparse.Namespace) -> int:
    config = load_source_config(args.config)
    config.validate()
    metrics = CollectionMetrics(event_id=args.event, collector=args.stage)
    if args.dry_run:
        print(json.dumps({"run_id": metrics.run_id, "event_id": args.event, "stage": args.stage,
                          "source": args.source, "dry_run": True}, sort_keys=True))
        return 0
    context = None
    try:
        context = CollectionContext.from_files(
            args.event,
            events_path=_default_root() / "configs" / "events.json",
            source_config=config,
            output_root=args.output,
            resume=args.resume,
        )
        if args.source not in ("rpc", "auto"):
            raise ValueError("the logs stage requires --source rpc or --source auto")
        result = context.collect_logs()
        metrics.run_id = context.run_id
        metrics.records_written = result.records_written
        metrics.records_skipped = result.records_skipped
        summary = args.output / args.event / f"{context.run_id}.json"
        metrics.write_summary(summary)
        print(json.dumps({"run_id": context.run_id, "status": "completed", "records_written": result.records_written,
                          "records_skipped": result.records_skipped}, sort_keys=True))
        return 0
    except Exception as exc:
        metrics.record_error(exc, stage=args.stage, source=args.source)
        summary_event = context.event_id if context is not None else args.event
        summary = args.output / summary_event / f"{metrics.run_id}.json"
        metrics.write_summary(summary)
        print(json.dumps({"run_id": metrics.run_id, "status": "failed", "error": str(exc)}, sort_keys=True))
        return 1


def _audit_command(args: argparse.Namespace) -> int:
    run_root = args.output / "runs"
    events_payload = json.loads(
        (_default_root() / "configs" / "events.json").read_text(encoding="utf-8")
    )
    if not isinstance(events_payload, list):
        raise ValueError("materialized events registry must be a JSON array")
    selected_events = [
        item
        for item in events_payload
        if item.get("event_id") == args.event
        or str(item.get("event_id", "")).startswith(f"{args.event}_")
    ]
    if not selected_events:
        raise ValueError(f"No event matched: {args.event}")
    if len(selected_events) > 1:
        raise ValueError(f"Event prefix is ambiguous: {args.event}")
    event = selected_events[0]
    event_id = str(event["event_id"])

    start_block = event.get("start_block")
    end_block = event.get("end_block")
    logs_jsonl = run_root / "data" / "raw" / "normalized" / "logs" / f"{event_id}.jsonl"
    transactions_jsonl = run_root / "data" / "raw" / "normalized" / "transactions" / f"{event_id}.jsonl"
    receipts_jsonl = run_root / "data" / "raw" / "normalized" / "receipts" / f"{event_id}.jsonl"
    abi_dir = run_root / "data" / "raw" / "source" / "abi" / event_id
    checkpoint = CheckpointStore(run_root / "checkpoints").load_checkpoint(event_id, "logs")

    block = (
        audit_block_coverage(int(start_block), int(end_block), logs_jsonl)
        if start_block is not None and end_block is not None
        else {"missing_block_count": 1}
    )
    tx_hashes = [event["exploit_tx_hash"]] if event.get("exploit_tx_hash") else []
    transactions = audit_registered_transaction_coverage(tx_hashes, transactions_jsonl)
    receipts = audit_receipt_coverage(tx_hashes, receipts_jsonl)
    logs = audit_log_range_coverage(checkpoint)
    addresses = (
        list(event.get("protocol_or_vulnerable_contracts", []))
        + list(event.get("attack_contracts", []))
        + list(event.get("attacker_addresses", []))
    )
    abi = audit_abi_coverage(
        [str(address) for address in addresses if str(address).strip()],
        abi_dir,
    )
    prices_present = (
        run_root / "data" / "raw" / "normalized" / "prices" / "coingecko" / f"{event_id}.jsonl"
    ).exists()
    public_present = any(
        (run_root / "data" / "raw" / "normalized" / source / f"{event_id}.jsonl").exists()
        for source in ("discourse", "gdelt", "protocol")
    )
    report = build_d2_gate_report(
        args.output / event_id / "d2_collection_audit.json",
        block=block,
        transactions=transactions,
        receipts=receipts,
        logs=logs,
        abi=abi,
        prices={"status": "conditional" if prices_present else "failed"},
        public_sources={"status": "conditional" if public_present else "failed"},
    )
    print(report["status"])
    return 0 if report["status"] != "NO_GO" else 2


def build_parser() -> argparse.ArgumentParser:
    root = _default_root()
    parser = argparse.ArgumentParser(prog="defi_lsa")
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry = subparsers.add_parser("registry", help="validate and materialize D1 scope")
    registry.add_argument(
        "--input",
        type=Path,
        default=root / "data" / "raw" / "event_candidates.csv",
    )
    registry.add_argument(
        "--events-output",
        type=Path,
        default=root / "configs" / "events.json",
    )
    registry.add_argument(
        "--scope-output",
        type=Path,
        default=root / "configs" / "contract_scopes.json",
    )
    registry.add_argument(
        "--manifest-output",
        type=Path,
        default=root / "configs" / "registry_manifest.json",
    )
    registry.add_argument(
        "--incident-legs",
        type=Path,
        default=root / "configs" / "incident_legs.json",
    )
    registry.add_argument("--tokens", type=Path, default=root / "configs" / "tokens.json")
    registry.add_argument(
        "--public-sources", type=Path, default=root / "configs" / "public_sources.json"
    )
    registry.set_defaults(handler=_registry_command)

    build = subparsers.add_parser("build", help="run an event build")
    build.add_argument("--event", required=True, choices=("euler", "curve", "kyber"))
    build.add_argument(
        "--input",
        type=Path,
        default=root / "data" / "raw" / "event_candidates.csv",
    )
    build.set_defaults(handler=_build_command)

    source_manifest = subparsers.add_parser(
        "source-manifest",
        help="record provenance for persisted raw artifacts",
    )
    source_manifest.add_argument("--output", type=Path, required=True)
    source_manifest.add_argument(
        "--artifact",
        action="append",
        required=True,
        metavar="SOURCE=URL=PATH",
        help="repeat for each raw artifact",
    )
    source_manifest.set_defaults(handler=_source_manifest_command)

    connectivity = subparsers.add_parser("connectivity", help="validate source connectivity configuration")
    connectivity.add_argument("--event")
    connectivity.add_argument(
        "--source",
        choices=("rpc", "etherscan", "coingecko", "gdelt", "aws", "auto"),
        default="rpc",
    )
    connectivity.add_argument("--config", type=Path)
    connectivity.add_argument("--output", type=Path)
    connectivity.set_defaults(handler=_connectivity_command)

    collect = subparsers.add_parser("collect", help="start or resume a collection run")
    collect.add_argument("--event", required=True)
    collect.add_argument("--source", default="rpc", choices=("rpc", "auto"))
    collect.add_argument("--stage", default="logs", choices=("logs",))
    collect.add_argument("--config", type=Path)
    collect.add_argument("--output", type=Path, default=root / "reports" / "runs")
    collect.add_argument("--resume", action="store_true")
    collect.add_argument("--dry-run", action="store_true")
    collect.set_defaults(handler=_collect_command)

    audit = subparsers.add_parser("audit", help="run the D2 readiness gate")
    audit.add_argument("--event", required=True)
    audit.add_argument("--stage", default="d2")
    audit.add_argument("--output", type=Path, default=root / "reports")
    audit.set_defaults(handler=_audit_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)
