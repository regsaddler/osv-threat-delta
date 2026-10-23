from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from .core import scan_lock, summarize, verify_report


DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "osv-threat-delta"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query OSV for the exact pinned Python dependency lock."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--root", default=".")
    scan.add_argument("--lock", default="requirements.lock")
    scan.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    scan.add_argument("--format", choices=("summary", "json"), default="summary")
    scan.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit status 1 when applicable findings exist (for CI gates).",
    )

    verify = subparsers.add_parser("verify")
    verify.add_argument("--root", default=".")
    verify.add_argument("--lock", default="requirements.lock")
    verify.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    verify.add_argument("--format", choices=("summary", "json"), default="summary")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    lock_path = (root / args.lock).resolve()
    state_dir = Path(args.state_dir).expanduser().resolve()
    try:
        try:
            lock_path.relative_to(root)
        except ValueError as exc:
            raise ValueError("requirements lock must remain inside the repository") from exc
        if args.command == "scan":
            report = scan_lock(root=root, lock_path=lock_path, state_dir=state_dir)
            if args.format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(summarize(report))
                print(f"report={state_dir / 'current.json'}")
            if args.fail_on_findings and report["result"]["active_finding_count"]:
                return 1
            return 0

        audit = verify_report(
            report_path=state_dir / "current.json",
            raw_dir=state_dir / "raw",
            lock_path=lock_path,
            previous_report_path=state_dir / "previous.json",
        )
        if args.format == "json":
            print(json.dumps(audit, indent=2, sort_keys=True))
        else:
            print(f"THREAT_DELTA_AUDIT: {audit['status']}")
            for issue in audit["errors"]:
                print(f"- {issue}")
        return 0 if audit["passed"] else 1
    except (OSError, ValueError) as exc:
        print(f"THREAT_DELTA: UNAVAILABLE reason={exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
