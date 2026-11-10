"""Automatic remediation for low-risk, well-understood fixes.

Every action defaults to dry run. Destructive changes (deleting users, keys or
volumes) are deliberately never automated.
"""

from __future__ import annotations

import logging

import boto3

from .models import Finding

log = logging.getLogger("misconfig.remediation")
REMEDIATIONS = {}


def remediates(*check_ids):
    def deco(fn):
        for cid in check_ids:
            REMEDIATIONS[cid] = fn
        return fn
    return deco


def _bucket(f: Finding) -> str:
    return f.resource.split(":::")[-1]


def _sg_id(f: Finding) -> str:
    return f.resource.rsplit("/", 1)[-1]


@remediates("S3-001", "S3-002", "S3-004")
def s3_block_public(session, f):
    s3 = session.client("s3")
    s3.put_public_access_block(Bucket=_bucket(f), PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_acl(Bucket=_bucket(f), ACL="private")
    return f"Enabled Block Public Access and reset ACL to private on {_bucket(f)}"


@remediates("S3-005")
def s3_encrypt(session, f):
    session.client("s3").put_bucket_encryption(Bucket=_bucket(f), ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]})
    return f"Enabled SSE-KMS default encryption on {_bucket(f)}"


@remediates("S3-006")
def s3_versioning(session, f):
    session.client("s3").put_bucket_versioning(Bucket=_bucket(f), VersioningConfiguration={"Status": "Enabled"})
    return f"Enabled versioning on {_bucket(f)}"


@remediates("EC2-001", "EC2-002")
def revoke_admin_port(session, f):
    port = 22 if f.check_id == "EC2-001" else 3389
    region = f.resource.split(":")[3]
    ec2 = session.client("ec2", region_name=region)
    sg = ec2.describe_security_groups(GroupIds=[_sg_id(f)])["SecurityGroups"][0]
    revoked = 0
    for rule in sg["IpPermissions"]:
        if rule.get("IpProtocol") in ("tcp", "6") and rule.get("FromPort", 0) <= port <= rule.get("ToPort", 0) \
                and any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])):
            ec2.revoke_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[{
                "IpProtocol": rule["IpProtocol"], "FromPort": rule["FromPort"], "ToPort": rule["ToPort"],
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
            revoked += 1
    return f"Revoked {revoked} world-open rule(s) for port {port} on {sg['GroupId']}"


@remediates("EC2-008")
def ebs_default(session, f):
    region = f.resource.split(":")[3]
    session.client("ec2", region_name=region).enable_ebs_encryption_by_default()
    return f"Enabled EBS encryption by default in {region}"


@remediates("EC2-011")
def require_imdsv2(session, f):
    region, instance = f.resource.split(":")[3], f.resource.rsplit("/", 1)[-1]
    session.client("ec2", region_name=region).modify_instance_metadata_options(
        InstanceId=instance, HttpTokens="required", HttpEndpoint="enabled")
    return f"Required IMDSv2 on {instance}"


@remediates("IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007")
def password_policy(session, f):
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True, RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True, AllowUsersToChangePassword=True, MaxPasswordAge=90,
        PasswordReusePrevention=24)
    return "Applied CIS-aligned account password policy"


def remediate(finding: Finding, session: boto3.session.Session | None = None, dry_run: bool = True) -> dict:
    fn = REMEDIATIONS.get(finding.check_id)
    if fn is None:
        return {"status": "manual", "message": finding.remediation}
    if dry_run:
        return {"status": "dry_run", "message": f"Would run {fn.__name__} on {finding.resource}"}
    message = fn(session or boto3.session.Session(), finding)
    log.warning("remediated", extra={"event": "remediation", "check_id": finding.check_id,
                                     "resource": finding.resource, "action": fn.__name__})
    return {"status": "remediated", "message": message}
