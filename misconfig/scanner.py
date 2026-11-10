from __future__ import annotations

import logging
from datetime import datetime, timezone

import boto3

from .checks import load_all
from .context import ScanContext
from .models import Finding, ScanResult
from .scoring import score_scan

log = logging.getLogger("misconfig.scanner")


def run_scan(session: boto3.session.Session | None = None, regions: list[str] | None = None,
             only: list[str] | None = None) -> ScanResult:
    session = session or boto3.session.Session()
    regions = regions or [session.region_name or "us-east-1"]
    specs = load_all()
    selected = {k: v for k, v in specs.items() if not only or k in only or v.service in only}
    account_id = session.client("sts", region_name=regions[0]).get_caller_identity()["Account"]

    result = ScanResult(account_id=account_id, regions=regions,
                        started_at=datetime.now(timezone.utc).isoformat())
    log.info("scan started", extra={"event": "scan_started", "account": account_id, "regions": regions,
                                    "checks": len(selected)})
    contexts = {r: ScanContext(session, r, account_id) for r in regions}

    for spec in selected.values():
        targets = [regions[0]] if spec.scope == "global" else regions
        for region in targets:
            try:
                for item in spec.func(contexts[region]):
                    resource, details, *rest = item
                    f = Finding(spec.id, spec.title, spec.service, spec.severity, resource,
                                "global" if spec.scope == "global" else region, details,
                                spec.remediation, spec.auto_remediable, bool(rest and rest[0]))
                    result.findings.append(f)
                    log.warning("finding", extra={"event": "finding", "check_id": spec.id,
                                                  "severity": spec.severity.value, "resource": resource,
                                                  "region": f.region, "account": account_id})
                result.checks_run += 1
            except Exception as exc:  # one broken check must not stop the scan
                result.checks_failed_to_run.append(f"{spec.id}@{region}: {exc.__class__.__name__}")
                log.error("check failed", extra={"event": "check_error", "check_id": spec.id,
                                                 "region": region, "error": str(exc)})

    score_scan(result, selected)
    result.findings.sort(key=lambda f: -f.risk_score)
    result.finished_at = datetime.now(timezone.utc).isoformat()
    log.info("scan finished", extra={"event": "scan_finished", "account": account_id,
                                     "findings": len(result.findings), "risk_score": result.risk_score,
                                     "grade": result.grade})
    return result
