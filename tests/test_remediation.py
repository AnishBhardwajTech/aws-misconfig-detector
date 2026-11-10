from helpers import admin_access_policy, ids, open_sg, public_bucket, scan
from misconfig.remediation import remediate


def _fix_all(session, result, dry_run=False):
    return [remediate(f, session, dry_run=dry_run) for f in result.findings]


def test_dry_run_changes_nothing(aws):
    open_sg(aws, 22)
    r = scan(aws, "EC2-001")
    assert _fix_all(aws, r, dry_run=True)[0]["status"] == "dry_run"
    assert "EC2-001" in ids(scan(aws, "EC2-001"))


def test_fix_open_ssh(aws):
    open_sg(aws, 22)
    assert _fix_all(aws, scan(aws, "EC2-001"))[0]["status"] == "remediated"
    assert not scan(aws, "EC2-001").findings


def test_fix_public_bucket(aws):
    public_bucket(aws)
    _fix_all(aws, scan(aws, "S3-001", "S3-004", "S3-005", "S3-006"))
    assert not ids(scan(aws, "S3-001", "S3-004", "S3-005", "S3-006"))


def test_fix_password_policy_and_ebs(aws):
    _fix_all(aws, scan(aws, "IAM-003", "EC2-008"))
    assert not ids(scan(aws, "IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007", "EC2-008"))


def test_manual_only(aws):
    aws.client("iam").create_user(UserName="x")
    aws.client("iam").attach_user_policy(UserName="x", PolicyArn=admin_access_policy(aws))
    out = _fix_all(aws, scan(aws, "IAM-013"))
    assert out[0]["status"] == "manual"
