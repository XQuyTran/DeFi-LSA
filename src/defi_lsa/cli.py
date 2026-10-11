"""Command-line entry points for the data-readiness pipeline."""



import argparse
import json
import uuid
from pathlib import Path

from .collectors import ADAPTER_VERSION, collect_source_manifest
from .config import load_source_config
from .observability import CollectionMetrics
from .audit import build_d2_gate_report
from .registry import (
    build_contract_scope,
    candidates_as_dicts,
    load_event_candidates,
    write_registry_manifest,
)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _registry_command(args: argparse.Namespace) -> int:
    candidates = load_event_candidates(args.input)
    scopes = [build_contract_scope(candidate) for candidate in candidates]
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
        [args.input, args.events_output, args.scope_output],
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
        source, url, path = item.split("=", maxsplit=2)
        artifact_path = Path(path)
        artifacts.append((source, url, artifact_path, ADAPTER_VERSION))
    collect_source_manifest(args.output, artifacts)
    print(f"Wrote source manifest to {args.output}")
    return 0


def _connectivity_command(args: argparse.Namespace) -> int:
    config = load_source_config(args.config)
    config.validate(require_rpc=args.source == "rpc")
    print(json.dumps({"source": args.source, "status": "configured", "run_id": uuid.uuid4().hex}))
    return 0


def _collect_command(args: argparse.Namespace) -> int:
    config = load_source_config(args.config)
    config.validate(require_rpc=args.source == "rpc")
    metrics = CollectionMetrics(event_id=args.event, collector=args.stage)
    if args.dry_run:
        print(json.dumps({"run_id": metrics.run_id, "event_id": args.event, "stage": args.stage,
                          "source": args.source, "dry_run": True}, sort_keys=True))
        return 0
    summary = args.output / args.event / f"{metrics.run_id}.json"
    metrics.write_summary(summary)
    print(f"Collection run {metrics.run_id} completed; orchestration artifacts are ready")
    return 0


def _audit_command(args: argparse.Namespace) -> int:
    report = build_d2_gate_report(
        args.output / args.event / "d2_collection_audit.json",
        block={}, transactions={}, receipts={}, logs={}, abi={},
        prices={"status": "conditional"}, public_sources={"status": "conditional"},
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
    connectivity.add_argument("--source", choices=("rpc", "aws", "coingecko", "gdelt"), default="rpc")
    connectivity.add_argument("--config", type=Path)
    connectivity.set_defaults(handler=_connectivity_command)

    collect = subparsers.add_parser("collect", help="start or resume a collection run")
    collect.add_argument("--event", required=True)
    collect.add_argument("--source", default="rpc")
    collect.add_argument("--stage", default="all")
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
