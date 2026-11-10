from misconfig.checks import REGISTRY, load_all
from misconfig.models import Finding, ScanResult, Severity
from misconfig.scanner import run_scan
from misconfig.scoring import finding_risk, score_scan

from helpers import open_sg, public_bucket


def test_47_checks_registered():
    specs = load_all()
    assert len(specs) == 47
    assert {s.service for s in specs.values()} == {"IAM", "S3", "EC2", "CloudTrail", "KMS"}


def test_full_scan_runs_every_check_without_errors(aws):
    r = run_scan(aws)
    assert r.checks_failed_to_run == []
    assert r.checks_run == 47
    assert r.account_id == "123456789012"


def test_multi_region(aws):
    r = run_scan(aws, regions=["us-east-1", "eu-west-1"], only=["EC2-008"])
    assert sorted(f.region for f in r.findings) == ["eu-west-1", "us-east-1"]


def test_broken_check_is_isolated(aws, monkeypatch):
    spec = load_all()["KMS-001"]

    def boom(ctx):
        raise RuntimeError("api down")
        yield

    monkeypatch.setitem(REGISTRY, "KMS-001", spec.__class__(**{**spec.__dict__, "func": boom}))
    r = run_scan(aws, only=["KMS-001", "S3-012"])
    assert r.checks_failed_to_run == ["KMS-001@us-east-1: RuntimeError"]
    assert any(f.check_id == "S3-012" for f in r.findings)


def test_public_exposure_increases_risk():
    f = Finding("X", "t", "S3", Severity.HIGH, "r", "global", "d", "fix")
    assert finding_risk(f) == 7
    f.public_exposure = True
    assert finding_risk(f) == 10.5


def test_risk_score_and_grade_get_worse(aws):
    clean = run_scan(aws, only=["EC2-001", "S3-001"])
    open_sg(aws, 22)
    public_bucket(aws)
    dirty = run_scan(aws, only=["EC2-001", "S3-001"])
    assert clean.risk_score == 0 and clean.grade == "A"
    assert dirty.risk_score > 50 and dirty.grade in "DF"
    assert dirty.findings[0].severity == Severity.CRITICAL


def test_score_empty():
    r = ScanResult("1", ["us-east-1"])
    score_scan(r, load_all())
    assert (r.risk_score, r.grade) == (0, "A")
