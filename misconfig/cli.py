"""Command line: run a scan, print a report, save JSON, store in the database.

    python -m misconfig scan --regions us-east-1 eu-west-1 --out report.json
    python -m misconfig scan --fail-on HIGH       # non-zero exit for CI gating
    python -m misconfig scan --remediate --apply  # actually fix auto-remediable findings
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import boto3

from .checks import load_all
from .logging_config import setup_logging
from .models import Severity
from .remediation import REMEDIATIONS, remediate
from .scanner import run_scan
from .storage import Store

COLORS = {"CRITICAL": "\033[41;97m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="misconfig")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--regions", nargs="+")
    s.add_argument("--checks", nargs="+", help="check ids or service names")
    s.add_argument("--out", help="write JSON report here")
    s.add_argument("--db", default=os.environ.get("DATABASE_URL"), help="store results in this database")
    s.add_argument("--fail-on", choices=[x.value for x in Severity], help="exit 2 if findings at/above this")
    s.add_argument("--remediate", action="store_true", help="remediate auto-remediable findings")
    s.add_argument("--apply", action="store_true", help="with --remediate: make changes (default dry run)")
    s.add_argument("--log-file", default=os.environ.get("SCAN_LOG_FILE"))
    sub.add_parser("checks")
    args = p.parse_args(argv)

    if args.cmd == "checks":
        for spec in load_all().values():
            print(f"{spec.id:9} {spec.severity.value:9} {spec.service:11} {spec.title}")
        return 0

    setup_logging(args.log_file)
    session = boto3.session.Session()
    result = run_scan(session, regions=args.regions, only=args.checks)
    color = sys.stdout.isatty()

    print(f"\nAccount {result.account_id}  regions={','.join(result.regions)}  checks={result.checks_run}")
    print(f"Risk score {result.risk_score}/100  grade {result.grade}  {result.severity_counts()}\n")
    for f in result.findings:
        sev = f"{COLORS[f.severity.value]}{f.severity.value:8}\033[0m" if color else f"{f.severity.value:8}"
        print(f"{sev} {f.check_id:8} {f.resource}\n         {f.details}")

    if args.remediate:
        print("\nRemediation" + ("" if args.apply else " (dry run)"))
        for f in result.findings:
            if f.check_id in REMEDIATIONS:
                print(f"  {f.check_id} {remediate(f, session, dry_run=not args.apply)['message']}")

    if args.db:
        store = Store(args.db)
        store.init_schema()
        print(f"\nSaved as scan #{store.save_scan(result)}")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result.to_dict(), fh, indent=2)
    if args.fail_on:
        threshold = Severity(args.fail_on).weight
        if any(f.severity.weight >= threshold for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
