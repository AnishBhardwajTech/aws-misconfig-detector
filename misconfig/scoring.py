"""Risk scoring.

Finding risk = severity weight x 1.5 if the resource is exposed to the internet.
Scan risk score (0-100) = sum of finding risks scaled against the worst case
of every check failing, so it is comparable across accounts of any size.
"""

from __future__ import annotations

from .models import Finding, ScanResult

PUBLIC_MULTIPLIER = 1.5
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (101, "F")]


def finding_risk(f: Finding) -> float:
    return round(f.severity.weight * (PUBLIC_MULTIPLIER if f.public_exposure else 1.0), 1)


def score_scan(result: ScanResult, specs: dict) -> None:
    for f in result.findings:
        f.risk_score = finding_risk(f)
    # Count each failing check once at its highest risk, so 500 open SGs don't
    # swamp the score but a single critical issue still shows up clearly.
    worst_per_check: dict[str, float] = {}
    for f in result.findings:
        worst_per_check[f.check_id] = max(worst_per_check.get(f.check_id, 0), f.risk_score)
    max_possible = sum(s.severity.weight * PUBLIC_MULTIPLIER for s in specs.values()) or 1
    raw = sum(worst_per_check.values())
    # Square-root curve: a few serious issues already move the score a lot.
    result.risk_score = round(min(100.0, 100 * (raw / max_possible) ** 0.5), 1)
    result.grade = next(g for limit, g in GRADES if result.risk_score < limit)
