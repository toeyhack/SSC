import argparse
import json
import sys

from pydantic import ValidationError

from app.db.session import SessionLocal
from app.services.golden_baseline_importer import (
    GoldenBaselineImportError,
    import_golden_baseline,
    load_golden_baseline_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import an SSC licensed-UI golden baseline catalog JSON file.")
    parser.add_argument("--input", required=True, help="Path to canonical Phase 1B baseline JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview without writing catalog rows.")
    parser.add_argument("--json", action="store_true", help="Print the import result as JSON.")
    parser.add_argument("--attest-real-source", action="store_true",
                        help="Attest this is a real licensed SSC capture, not synthetic data; enables SSC_ALIGNED.")
    args = parser.parse_args()

    try:
        baseline = load_golden_baseline_file(args.input)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Unable to read baseline input: {exc}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    with SessionLocal() as db:
        try:
            result = import_golden_baseline(db, baseline, dry_run=args.dry_run,
                                            attest_real_source=args.attest_real_source)
        except GoldenBaselineImportError as exc:
            for error in exc.errors:
                print(error, file=sys.stderr)
            return 2

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(f"snapshot_action={result.snapshot_action}")
        print(f"content_hash={result.content_hash}")
        if result.snapshot_id:
            print(f"snapshot_id={result.snapshot_id}")
        print(f"factors_created={result.factors_created}")
        print(f"issues_created={result.issues_created}")
        print(f"versions_created={result.versions_created}")
        print(f"snapshot_items={result.snapshot_items}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
