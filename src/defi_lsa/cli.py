"""Command-line entry points for the data-readiness pipeline."""



import argparse
import json
import traceback
import uuid
from dataclasses import asdict
from pathlib import Path

from .collectors import ADAPTER_VERSION, collect_source_manifest
from .config import load_source_config
from .connectivity import probe_sources
from .retry import redact_credentials
from .observability import CollectionMetrics
from .audit import (
    audit_abi_coverage,
    audit_block_coverage,
    audit_duplicate_records,
    audit_log_range_coverage,
    audit_public_sources_coverage,
    audit_receipt_coverage,
    audit_registered_transaction_coverage,
    audit_registry_consistency,
    audit_source_manifest,
    audit_token_price_coverage,
    build_d2_gate_report,
    render_d2_gate_markdown,
)
from .checkpoints import CheckpointStore
from .orchestration import CollectionContext
from .runtime import preflight_output_root, resolve_output_root
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
from .d3_pipeline import run_d3


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
    evidence_paths = [
        args.alert_benchmarks,
        args.events_master,
    ]
    write_registry_manifest(
        args.manifest_output,
        [
            args.input,
            args.events_output,
            args.scope_output,
            *([args.incident_legs] if args.incident_legs.exists() else []),
            args.tokens,
            args.public_sources,
            *[path for path in evidence_paths if path.exists()],
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


def _d3_command(args: argparse.Namespace) -> int:
    try:
        report = run_d3(
            args.event,
            output_root=args.output,
            events_path=args.events,
            incident_legs_path=args.incident_legs,
        )
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": redact_credentials(str(exc))}, sort_keys=True))
        return 1


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
    results = probe_sources(config, args.source)
    source_names = {"rpc": "ethereum_rpc", "aws": "aws_public_blockchain"}
    statuses = {source_names.get(name, name): result.status for name, result in results.items()}
    details = {source_names.get(name, name): result.details for name, result in results.items()}
    result = {
        "event": args.event,
        "run_id": uuid.uuid4().hex,
        "statuses": statuses,
        "details": details,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if all(status == "reachable" for status in statuses.values()) else 1


def _collect_command(args: argparse.Namespace) -> int:
    config = load_source_config(args.config)
    config.validate()
    metrics = CollectionMetrics(event_id=args.event, collector=args.stage)
    context = None
    output_root = resolve_output_root(args.output)
    try:
        metrics.runtime_preflight = preflight_output_root(output_root)
        if not metrics.runtime_preflight["passed"]:
            raise RuntimeError("runtime preflight failed for collection output root")
        force = getattr(args, "force", False)
        context = CollectionContext.from_files(
            args.event,
            events_path=_default_root() / "configs" / "events.json",
            source_config=config,
            output_root=output_root,
            resume=args.resume,
            dry_run=args.dry_run,
            force=force,
            start_block=args.start_block,
            end_block=args.end_block,
        )
        if args.dry_run:
            plan = context.dry_run_plan()
            plan["stage"] = args.stage
            plan["source"] = args.source
            print(json.dumps(plan, sort_keys=True))
            return 0

        written = 0
        skipped = 0
        stage = args.stage

        if stage == "logs":
            res = context.collect_logs(source=args.source)
            written, skipped = res.records_written, res.records_skipped
        elif stage in ("blocks", "token_transfers", "traces", "contracts"):
            aws_source = "aws" if args.source == "auto" else args.source
            res = context.collect_aws_table(stage, source=aws_source)
            written, skipped = res.records_written, res.records_skipped
        elif stage == "transactions":
            res = context.collect_transactions(source=args.source)
            written, skipped = res.records_written, res.records_skipped
        elif stage == "receipts":
            res = context.collect_receipts(source=args.source)
            written, skipped = res.records_written, res.records_skipped
        elif stage == "abi":
            res = context.collect_abi(source=args.source)
            written, skipped = res.records_written, res.records_skipped
        elif stage == "prices":
            res = context.collect_prices(source=args.source)
            written, skipped = res.records_written, res.records_skipped
        elif stage in ("public_sources", "public_information"):
            results_dict = context.collect_public_sources(source=args.source)
            for res in results_dict.values():
                written += res.records_written
                skipped += res.records_skipped
        elif stage == "all":
            all_res = context.collect_all(source=args.source)
            for key, val in all_res.items():
                if isinstance(val, dict):
                    for sub_res in val.values():
                        written += getattr(sub_res, "records_written", 0)
                        skipped += getattr(sub_res, "records_skipped", 0)
                else:
                    written += getattr(val, "records_written", 0)
                    skipped += getattr(val, "records_skipped", 0)
        else:
            raise ValueError(f"collection stage {stage!r} is not implemented")

        metrics.run_id = context.run_id
        metrics.records_written = written
        metrics.records_skipped = skipped
        summary = output_root / context.event_id / f"{context.run_id}.json"
        metrics.write_summary(summary)
        print(json.dumps({"run_id": context.run_id, "status": "completed", "records_written": written,
                          "records_skipped": skipped}, sort_keys=True))
        return 0
    except Exception as exc:
        metrics.record_error(exc, stage=args.stage, source=args.source)
        summary_event = context.event_id if context is not None else args.event
        summary = output_root / summary_event / f"{metrics.run_id}.json"
        metrics.write_summary(summary)
        traceback_tail = "\n".join(traceback.format_exc().splitlines()[-12:])
        print(json.dumps({
            "run_id": metrics.run_id,
            "status": "failed",
            "stage": args.stage,
            "source": args.source,
            "error_type": type(exc).__name__,
            "error": redact_credentials(str(exc)),
            "traceback_tail": redact_credentials(traceback_tail),
        }, sort_keys=True))
        return 1


def _resolve_run_root(output: Path, data_dir: Path | None) -> Path:
    """Resolve the artifact collection root from CLI arguments.

    Priority:
    1. ``--data-dir`` if explicitly supplied.
    2. ``output`` itself when it contains a ``data/`` or ``checkpoints/`` child.
    3. ``output / "runs"`` as the conventional default.
    """
    return resolve_output_root(output, data_dir)


def _is_effective_range_overridden(
    start_block: int | None,
    end_block: int | None,
    registry_start_block: int | None,
    registry_end_block: int | None,
) -> bool:
    """Return whether effective audit bounds differ from registry bounds."""
    if start_block is None or end_block is None:
        return False
    if registry_start_block is None or registry_end_block is None:
        return True
    return (
        int(start_block) != int(registry_start_block)
        or int(end_block) != int(registry_end_block)
    )


def _audit_command(args: argparse.Namespace) -> int:
    cfg_root = _default_root()
    data_dir = getattr(args, "data_dir", None)
    run_root = _resolve_run_root(args.output, data_dir)

    # ---- Load event registry ------------------------------------------------
    events_payload = json.loads(
        (cfg_root / "configs" / "events.json").read_text(encoding="utf-8")
    )
    if not isinstance(events_payload, list):
        raise ValueError("materialized events registry must be a JSON array")
    selector_aliases = {"kyber": "kyberswap"}
    event_selector = selector_aliases.get(str(args.event).strip(), str(args.event).strip())
    selected_events = [
        item
        for item in events_payload
        if item.get("event_id") == event_selector
        or str(item.get("event_id", "")).startswith(f"{event_selector}_")
    ]
    if not selected_events:
        raise ValueError(f"No event matched: {args.event}")
    if len(selected_events) > 1:
        raise ValueError(f"Event prefix is ambiguous: {args.event}")
    event = selected_events[0]
    event_id = str(event["event_id"])

    # ---- Load supporting registries -----------------------------------------
    incident_legs_path = cfg_root / "configs" / "incident_legs.json"
    incident_legs = (
        [asdict(leg) for leg in load_incident_legs(incident_legs_path)]
        if incident_legs_path.exists()
        else []
    )
    token_registry = []
    tokens_path = cfg_root / "configs" / "tokens.json"
    if tokens_path.exists():
        token_registry = json.loads(tokens_path.read_text(encoding="utf-8"))
    public_source_registry = []
    ps_path = cfg_root / "configs" / "public_sources.json"
    if ps_path.exists():
        public_source_registry = json.loads(ps_path.read_text(encoding="utf-8"))
    contract_scopes = []
    scopes_path = cfg_root / "configs" / "contract_scopes.json"
    if scopes_path.exists():
        contract_scopes = json.loads(scopes_path.read_text(encoding="utf-8"))

    # ---- Canonical artifact paths -------------------------------------------
    normalized = run_root / "data" / "raw" / "normalized"
    logs_jsonl = normalized / "logs" / event_id
    transactions_jsonl = normalized / "transactions" / event_id
    receipts_jsonl = normalized / "receipts" / event_id
    abi_dir = run_root / "data" / "raw" / "source" / "abi" / event_id
    prices_jsonl = normalized / "prices" / "defillama_anchor" / event_id
    reports_dir = run_root / "reports" / event_id
    manifest_path = reports_dir / "source_manifest.json"

    checkpoint = CheckpointStore(run_root / "checkpoints").load_checkpoint(event_id, "logs")

    # ---- Build complete registered tx hash set (event + all incident legs) --
    exploit_hash = event.get("exploit_tx_hash")
    tx_hashes: list[str] = [exploit_hash] if exploit_hash else []
    for leg in incident_legs:
        if str(leg.get("event_id", "")) == event_id:
            leg_tx = str(leg.get("transaction_hash", ""))
            if leg_tx and leg_tx.lower() not in {h.lower() for h in tx_hashes}:
                tx_hashes.append(leg_tx)

    # ---- Addresses for scope and ABI checks ---------------------------------
    addresses = (
        list(event.get("protocol_or_vulnerable_contracts", []))
        + list(event.get("attack_contracts", []))
        + list(event.get("attacker_addresses", []))
    )
    # Use the materialized ContractScope as the independent registry input.
    scope_addresses = {
        str(address).lower()
        for scope in contract_scopes
        if str(scope.get("event_id", "")) == event_id
        for address in (scope.get("addresses") or [])
    }

    # ---- Run all audit checks -----------------------------------------------
    start_block = event.get("start_block")
    end_block = event.get("end_block")
    if (args.start_block is None) != (args.end_block is None):
        raise ValueError("audit start_block and end_block must be supplied together")
    if args.start_block is not None:
        if args.start_block < 0 or args.end_block < args.start_block:
            raise ValueError("audit start_block and end_block must be non-negative and ordered")
        start_block = args.start_block
        end_block = args.end_block
    elif checkpoint is not None:
        start_block = checkpoint.requested_start
        end_block = checkpoint.requested_end

    block = (
        audit_block_coverage(int(start_block), int(end_block), logs_jsonl)
        if start_block is not None and end_block is not None
        else {"missing_block_count": 1}
    )
    transactions = audit_registered_transaction_coverage(tx_hashes, transactions_jsonl)
    receipts = audit_receipt_coverage(tx_hashes, receipts_jsonl)
    logs = audit_log_range_coverage(checkpoint)
    abi = audit_abi_coverage(
        [str(a) for a in addresses if str(a).strip()],
        abi_dir,
    )

    # Token price coverage (artifact-derived)
    prices = audit_token_price_coverage(
        event=event,
        token_registry=token_registry,
        prices_path=prices_jsonl,
        price_coverage_reports_dir=reports_dir,
    )

    # Public source query-level coverage
    public_sources = audit_public_sources_coverage(
        event=event,
        public_source_registry=public_source_registry,
        normalized_base=normalized,
    )

    # Registry consistency
    registry_consistency = audit_registry_consistency(
        event=event,
        scope_addresses=scope_addresses,
        token_registry=token_registry,
        incident_legs=incident_legs,
        public_source_registry=public_source_registry,
    )

    # Duplicate record checks across key tables
    total_duplicates = 0
    duplicate_detail: dict[str, dict] = {}
    duplicate_paths = {
        "logs": normalized / "logs" / event_id,
        "transactions": normalized / "transactions" / event_id,
        "receipts": normalized / "receipts" / event_id,
        "blocks": normalized / "blocks" / event_id,
        "prices": normalized / "prices" / "defillama_anchor" / event_id,
    }
    for schema, p in duplicate_paths.items():
        dup = audit_duplicate_records(p, schema)
        duplicate_detail[schema] = dup
        total_duplicates += dup.get("duplicate_count", 0)
    duplicates_summary = {
        "total_duplicate_count": total_duplicates,
        "by_schema": duplicate_detail,
    }

    # Source manifest integrity
    source_manifest = audit_source_manifest(manifest_path)

    # ---- Compile gate report (JSON + Markdown) ------------------------------
    output_base = args.output / event_id
    registry_start_block = event.get("start_block")
    registry_end_block = event.get("end_block")
    range_overridden = _is_effective_range_overridden(
        start_block,
        end_block,
        registry_start_block,
        registry_end_block,
    )
    report = build_d2_gate_report(
        output_base / "d2_collection_audit.json",
        block=block,
        transactions=transactions,
        receipts=receipts,
        logs=logs,
        abi=abi,
        prices=prices,
        public_sources=public_sources,
        registry_consistency=registry_consistency,
        duplicates=duplicates_summary,
        source_manifest=source_manifest,
        effective_range={
            "start_block": int(start_block) if start_block is not None else None,
            "end_block": int(end_block) if end_block is not None else None,
            "registry_start_block": registry_start_block,
            "registry_end_block": registry_end_block,
            "overridden": range_overridden,
        },
    )
    render_d2_gate_markdown(report, output_base / "d2_collection_audit.md")

    print(report["status"])
    strict = getattr(args, "strict", False)
    if report["status"] == "NO_GO":
        return 2
    if strict and report["status"] == "CONDITIONAL_GO":
        return 2
    return 0


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
    registry.add_argument(
        "--alert-benchmarks",
        type=Path,
        default=root / "configs" / "alert_benchmarks.json",
    )
    registry.add_argument(
        "--events-master",
        type=Path,
        default=root / "data" / "evidence" / "events_master_verified.csv",
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
        choices=("rpc", "etherscan", "defillama", "gdelt", "aws", "forums", "auto"),
        default="rpc",
    )
    connectivity.add_argument("--config", type=Path)
    connectivity.add_argument("--output", type=Path)
    connectivity.set_defaults(handler=_connectivity_command)

    collect = subparsers.add_parser("collect", help="start or resume a collection run")
    collect.add_argument("--event", required=True)
    collect.add_argument(
        "--source",
        default="rpc",
        choices=("rpc", "etherscan", "defillama", "gdelt", "forums", "aws", "auto"),
    )
    collect.add_argument(
        "--stage",
        default="logs",
        choices=(
            "logs",
            "blocks",
            "transactions",
            "receipts",
            "token_transfers",
            "traces",
            "contracts",
            "abi",
            "prices",
            "public_sources",
            "public_information",
            "all",
        ),
    )
    collect.add_argument("--config", type=Path)
    collect.add_argument("--output", type=Path, default=root / "reports" / "runs")
    collect.add_argument("--resume", action="store_true")
    collect.add_argument("--dry-run", action="store_true")
    collect.add_argument("--force", action="store_true")
    collect.add_argument("--start-block", type=int)
    collect.add_argument("--end-block", type=int)
    collect.set_defaults(handler=_collect_command)

    audit = subparsers.add_parser("audit", help="run the D2 readiness gate")
    audit.add_argument("--event", required=True)
    audit.add_argument("--stage", default="d2")
    audit.add_argument("--output", type=Path, default=root / "reports")
    audit.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        dest="data_dir",
        help="Explicit path to the collection root (data/, checkpoints/ parent). "
             "Overrides automatic detection from --output.",
    )
    audit.add_argument(
        "--strict",
        action="store_true",
        help="Treat CONDITIONAL_GO as failure (exit code 2).",
    )
    audit.add_argument("--start-block", type=int)
    audit.add_argument("--end-block", type=int)
    audit.set_defaults(handler=_audit_command)

    d3 = subparsers.add_parser("d3", help="decode and classify D2 artifacts")
    d3.add_argument("--event", required=True)
    d3.add_argument("--output", type=Path, default=root)
    d3.add_argument("--events", type=Path, default=root / "configs" / "events.json")
    d3.add_argument(
        "--incident-legs",
        type=Path,
        default=root / "configs" / "incident_legs.json",
    )
    d3.set_defaults(handler=_d3_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)
