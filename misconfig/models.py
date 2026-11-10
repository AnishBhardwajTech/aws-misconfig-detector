from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}[self.value]


@dataclass
class Finding:
    check_id: str
    title: str
    service: str
    severity: Severity
    resource: str
    region: str
    details: str
    remediation: str
    auto_remediable: bool = False
    public_exposure: bool = False
    risk_score: float = 0.0
    id: int | None = None
    status: str = "OPEN"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    checks_failed_to_run: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    grade: str = "A"
    id: int | None = None
    started_at: str = ""
    finished_at: str = ""

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "account_id": self.account_id,
            "regions": self.regions,
            "checks_run": self.checks_run,
            "checks_failed_to_run": self.checks_failed_to_run,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "severity_counts": self.severity_counts(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [f.to_dict() for f in self.findings],
        }
