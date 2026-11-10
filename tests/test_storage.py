from helpers import open_sg, public_bucket
from misconfig.scanner import run_scan


def test_save_and_report(aws, store):
    open_sg(aws, 22)
    public_bucket(aws)
    r = run_scan(aws)
    scan_id = store.save_scan(r)
    scan = store.get_scan(scan_id)
    assert scan["risk_score"] == r.risk_score
    assert scan["severity_counts"] == r.severity_counts()
    assert len(store.findings(scan_id)) == len(r.findings)
    crit = store.findings(scan_id, severity="critical")
    assert crit and all(f.severity.value == "CRITICAL" for f in crit)
    by_service = {s["service"] for s in store.service_breakdown(scan_id)}
    assert {"EC2", "S3", "IAM"} <= by_service
    assert store.top_resources(scan_id, 3)[0]["risk"] >= store.top_resources(scan_id, 3)[-1]["risk"]


def test_trend_and_status(aws, store):
    first = store.save_scan(run_scan(aws, only=["EC2-001"]))
    open_sg(aws, 22)
    second = store.save_scan(run_scan(aws, only=["EC2-001"]))
    trend = store.trend("123456789012")
    assert [t["scan_id"] for t in trend] == [first, second]
    assert trend[1]["risk_score"] > trend[0]["risk_score"]
    fid = store.findings(second)[0].id
    store.set_finding_status(fid, "REMEDIATED")
    assert store.get_finding(fid).status == "REMEDIATED"
    assert store.findings(second, status="open") == []
