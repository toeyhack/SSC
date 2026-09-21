"""Presentation for explicit SSC acquisition; no scan runtime dependency."""
import json
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.db.session import SessionLocal
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.ssc_api_baseline import acquire_baseline, discover_issue_details, taxonomy_status


def run(args) -> int:
    try:
        if args.baseline_command == "activate-wave1":
            if not args.yes:
                raise ValueError("Review the Wave 1 evaluator definitions, then pass --yes to activate")
            from app.services.wave1_rules import activate_wave1_rules
            with SessionLocal() as db:
                result = activate_wave1_rules(db)
            print(json.dumps(result, indent=2))
            return 0 if not result["unavailable"] else 3
        if args.baseline_command == "activate-wave2":
            if not args.yes:
                raise ValueError("Review the Wave 2 evaluator definitions, then pass --yes to activate")
            from app.services.wave2_rules import activate_wave2_rules
            with SessionLocal() as db:
                result = activate_wave2_rules(db)
            print(json.dumps(result, indent=2))
            return 0 if not result["unavailable"] else 3
        if args.baseline_command == "discover-details":
            result = discover_issue_details()
            print(json.dumps(result, indent=2))
            return 1 if any("error" in item for item in result.values()) else 0
        if args.baseline_command == "status":
            with SessionLocal() as db:
                print(taxonomy_status(db))
            return 0
        # Finish and validate both requests before opening a catalog transaction.
        baseline = acquire_baseline(enrich_details=args.enrich_details)
        with SessionLocal() as db:
            preview = import_golden_baseline(db, baseline, dry_run=True)
            print("Source          : SSC_API")
            print(f"Factors         : {len(baseline.factors)}")
            print(f"Issue Types     : {sum(len(factor.issues) for factor in baseline.factors)}")
            if baseline.detail_enrichment_requested:
                issue_count = sum(len(factor.issues) for factor in baseline.factors)
                failed_count = len(baseline.detail_enrichment_failures)
                print(f"Detail Enriched : {issue_count - failed_count}/{issue_count}")
                if failed_count:
                    print("Detail Failures : " + ", ".join(sorted(baseline.detail_enrichment_failures)))
            print(f"Captured At     : {baseline.captured_at.isoformat()}")
            print(f"Content Hash    : {preview.content_hash}")
            print(f"Existing Match  : {'yes' if preview.snapshot_action == 'reused_existing' else 'no'}")
            print(f"Issue Versions  : {preview.versions_created} new")
            for warning in preview.warnings:
                print(f"Warning         : {warning}")
            if args.expect_hash and args.expect_hash != preview.content_hash:
                raise ValueError("SSC content changed since review; expected hash does not match")
            if args.dry_run:
                return 0
            if preview.snapshot_action != "reused_existing" and not args.yes:
                if not sys.stdin.isatty():
                    raise ValueError("Review the summary, then pass --yes (optionally --expect-hash) to import")
                if input("Import this SSC baseline? [y/N] ").strip().lower() not in ("y", "yes"):
                    print("No baseline imported")
                    return 0
            result = import_golden_baseline(db, baseline, attest_real_source=True)
            print(f"Snapshot        : {result.snapshot_id} ({result.snapshot_action})")
            print(f"Taxonomy Status : {taxonomy_status(db)}")
        return 0
    except SQLAlchemyError:
        # SQL exception text can include bound raw payloads; keep diagnostics bounded.
        print("ssc baseline: database operation failed; import was not committed", file=sys.stderr)
        return 1
    except (ValueError, OSError, EOFError) as exc:
        print(f"ssc baseline: {exc}", file=sys.stderr)
        return 1
