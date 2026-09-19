"""CLI-first interface; presentation and transport remain outside core services."""
import argparse
import json
import sys
from pathlib import Path
from uuid import UUID


def load_json(path):
    def reject_constant(value):
        raise ValueError(f"Nonfinite JSON number: {value}")
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=reject_constant)


def build_parser():
    parser = argparse.ArgumentParser(prog="ssc", description="Authorized internal exposure assessment")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan one approved inventory target")
    scan.add_argument("--target", required=True, help="Inventory hostname, domain or registered IP; URLs are not accepted")
    scan.add_argument("--output", choices=["report", "sygnos"], default="report")
    scan.add_argument("--output-dir", default="reports", help="Parent directory for HTML and JSON results")
    scan.add_argument("--scan-config", help="JSON executor configuration")
    scan.add_argument("--scoring-model", help="JSON internal scoring definition")
    scan.add_argument("--executors", help="Comma-separated executor names: http,tls,dns,tcp")
    scan.add_argument("--tcp-ports", help="Comma-separated explicit TCP ports; no range scanning")
    scan.add_argument("--organization-id", type=UUID, help="Disambiguate inventory targets")
    scan.add_argument("--rule-key", action="append", help="Select an active rule by stable key; repeat for multiple rules")
    report = commands.add_parser("report", help="Render a persisted run without rescanning")
    report.add_argument("--run-id", type=UUID, required=True)
    report.add_argument("--output-dir", default="reports")
    report.add_argument("--scoring-model")
    targets = commands.add_parser("targets", help="Manage target inventory without the Web/API")
    target_commands = targets.add_subparsers(dest="target_command", required=True)
    add = target_commands.add_parser("add", help="Register one domain or host and its authorization")
    add.add_argument("--organization", required=True)
    add.add_argument("--domain", required=True)
    add.add_argument("--hostname")
    add.add_argument("--ip")
    add.add_argument("--approve", action="store_true", help="Explicitly authorize this concrete target")
    add.add_argument("--allow-sensitive", action="store_true", help="Explicitly permit private/loopback target networks")
    add.add_argument("--approval-notes")
    rules = commands.add_parser("rules", help="Load internal detectors without the Web/API")
    rule_commands = rules.add_subparsers(dest="rule_command", required=True)
    load = rule_commands.add_parser("load", help="Load a versioned internal detector bundle")
    load.add_argument("--input", required=True)
    baseline = commands.add_parser("baseline", help="Acquire and review an SSC taxonomy baseline")
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    pull = baseline_commands.add_parser("pull-ssc", help="Preview and import SSC API metadata using SSC_TOKEN")
    pull.add_argument("--dry-run", action="store_true", help="Preview without changing the catalog")
    pull.add_argument("--enrich-details", action="store_true",
                      help="Optionally enrich issues from bounded detail requests; individual failures are nonfatal")
    pull.add_argument("--yes", action="store_true", help="Approve importing the displayed metadata")
    pull.add_argument("--expect-hash", help="Require the exact content hash from an earlier review")
    baseline_commands.add_parser("status", help="Show INTERNAL_ONLY or SSC_ALIGNED without SSC access")
    baseline_commands.add_parser("discover-details", help="Read the three sample issue detail endpoints; report field names")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "baseline":
        from app.cli.ssc_baseline import run
        return run(args)
    if args.command == "scan" and args.output == "sygnos":
        print("SYGNOS output is deferred until its ingestion interface is known. Use --output report. No scan was started.", file=sys.stderr)
        return 2
    from sqlalchemy.exc import SQLAlchemyError
    from app.db.session import SessionLocal
    from app.outputs.report import write_report
    from app.services.scoring_engine import ScoringDefinition
    try:
        with SessionLocal() as db:
            if args.command == "targets":
                from app.services.cli_setup import add_inventory_target
                target = add_inventory_target(db, organization=args.organization, domain_name=args.domain, hostname=args.hostname,
                                              ip=args.ip, approved=args.approve, allow_sensitive=args.allow_sensitive, approval_notes=args.approval_notes)
                print(json.dumps(target))
                return 0
            if args.command == "rules":
                from app.services.cli_setup import load_detector_bundle
                print(json.dumps(load_detector_bundle(db, load_json(args.input))))
                return 0
            model = ScoringDefinition.model_validate(load_json(args.scoring_model)) if args.scoring_model else ScoringDefinition()
            if args.command == "scan":
                from app.services.cli_scan import scan_inventory_target
                config = load_json(args.scan_config) if args.scan_config else {}
                if not isinstance(config, dict):
                    raise ValueError("scan_config must be an object")
                if args.executors:
                    config["executors"] = [name.strip().lower() for name in args.executors.split(",")]
                if args.tcp_ports:
                    config["tcp_ports"] = [int(port.strip()) for port in args.tcp_ports.split(",")]
                result = scan_inventory_target(db, name=args.target, scan_config=config, model=model,
                                               organization_id=args.organization_id, rule_keys=args.rule_key)
            else:
                from app.services.score_results import build_score_result
                result = build_score_result(db, args.run_id, model)
        html_path, json_path = write_report(result, args.output_dir)
        print(f"scan_run={result.scan_run_id} status={result.status} overall_score={result.overall_score if result.overall_score is not None else 'unassessed'}")
        print(f"html={html_path}\njson={json_path}")
        return 0 if result.status == "complete" else 3
    except (ValueError, OSError, SQLAlchemyError) as exc:
        print(f"ssc: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
