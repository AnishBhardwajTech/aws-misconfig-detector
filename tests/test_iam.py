import json

from helpers import admin_access_policy, ADMIN_POLICY, ids, scan


def test_no_password_policy_flagged(aws):
    assert "IAM-003" in ids(scan(aws, "IAM-003"))


def test_weak_password_policy(aws):
    aws.client("iam").update_account_password_policy(MinimumPasswordLength=8)
    found = ids(scan(aws, "IAM"))
    assert {"IAM-004", "IAM-005", "IAM-006"} <= found
    assert "IAM-003" not in found


def test_strong_password_policy_passes(aws):
    aws.client("iam").update_account_password_policy(
        MinimumPasswordLength=16, RequireSymbols=True, RequireNumbers=True, RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True, MaxPasswordAge=60, PasswordReusePrevention=24)
    assert not ids(scan(aws, "IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007"))


def test_console_user_without_mfa(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-secret-pw!")
    iam.create_user(UserName="ci-bot")  # no console password -> not flagged
    findings = [f for f in scan(aws, "IAM-008").findings]
    assert [f.resource.split("/")[-1] for f in findings] == ["alice"]


def test_two_active_keys(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="bob")
    iam.create_access_key(UserName="bob")
    iam.create_access_key(UserName="bob")
    assert "IAM-010" in ids(scan(aws, "IAM-010"))


def test_admin_customer_policy_and_admin_user(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="carol")
    iam.attach_user_policy(UserName="carol", PolicyArn=admin_access_policy(aws))
    found = ids(scan(aws, "IAM-011", "IAM-012", "IAM-013"))
    assert found == {"IAM-011", "IAM-012", "IAM-013"}


def test_inline_wildcard(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="dave")
    iam.put_user_policy(UserName="dave", PolicyName="s3-all", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
    assert "IAM-014" in ids(scan(aws, "IAM-014"))


def test_role_assumable_by_anyone(aws):
    aws.client("iam").create_role(RoleName="open", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}))
    f = scan(aws, "IAM-016").findings
    assert len(f) == 1 and f[0].public_exposure


def test_role_with_service_principal_ok(aws):
    aws.client("iam").create_role(RoleName="lambda", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    assert not scan(aws, "IAM-016").findings
