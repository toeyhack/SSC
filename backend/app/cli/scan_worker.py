import argparse
import time

from app.db.session import SessionLocal
from app.services.scan_engine import process_next_scan_job


def main() -> int:
    parser = argparse.ArgumentParser(description="Process queued scan jobs.")
    parser.add_argument("--once", action="store_true", help="Process at most one queued scan job and exit.")
    parser.add_argument("--sleep", type=float, default=5.0, help="Seconds to sleep between polling attempts.")
    args = parser.parse_args()

    while True:
        with SessionLocal() as db:
            run = process_next_scan_job(db)
            if run is not None:
                print(f"processed scan_run={run.id} scan_job={run.scan_job_id} status={run.status}")
            elif args.once:
                print("no queued scan jobs")

        if args.once:
            return 0
        time.sleep(args.sleep)


if __name__ == "__main__":
    raise SystemExit(main())
