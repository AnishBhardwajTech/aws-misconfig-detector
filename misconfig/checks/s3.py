"""S3 checks (global: buckets are listed account-wide)."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..models import Severity
from . import check

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def _err(e: ClientError) -> str:
    return e.response["Error"]["Code"]


def _grantees(ctx, bucket) -> list[str]:
    acl = ctx.client("s3").get_bucket_acl(Bucket=bucket)
    return [g["Grantee"].get("URI", "") for g in acl.get("Grants", [])]


def _policy(ctx, bucket) -> dict | None:
    try:
        return json.loads(ctx.client("s3").get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as e:
        if _err(e) in ("NoSuchBucketPolicy",):
            return None
        raise


def _statements(policy: dict) -> list[dict]:
    st = policy.get("Statement", [])
    return st if isinstance(st, list) else [st]


@check("S3-001", "S3", C, "Bucket ACL grants access to everyone",
       "Remove AllUsers grants from the bucket ACL and enable Block Public Access.",
       scope="global", auto_remediable=True)
def public_acl(ctx):
    for b in ctx.buckets():
        if ALL_USERS in _grantees(ctx, b):
            yield f"arn:aws:s3:::{b}", "The ACL grants access to AllUsers (the public internet).", True


@check("S3-002", "S3", H, "Bucket ACL grants access to any AWS user",
       "Remove AuthenticatedUsers grants from the bucket ACL.", scope="global", auto_remediable=True)
def auth_users_acl(ctx):
    for b in ctx.buckets():
        if AUTH_USERS in _grantees(ctx, b):
            yield f"arn:aws:s3:::{b}", "The ACL grants access to every authenticated AWS account.", True


@check("S3-003", "S3", H, "Bucket policy allows public access",
       "Restrict the bucket policy's Principal or add conditions such as aws:SourceVpce.", scope="global")
def public_policy(ctx):
    for b in ctx.buckets():
        policy = _policy(ctx, b)
        for st in _statements(policy or {}):
            p = st.get("Principal")
            if st.get("Effect") == "Allow" and (p == "*" or (isinstance(p, dict) and p.get("AWS") == "*")) \
                    and not st.get("Condition"):
                yield f"arn:aws:s3:::{b}", "The bucket policy allows Principal '*' without conditions.", True
                break


@check("S3-004", "S3", H, "Bucket Block Public Access is not fully enabled",
       "Enable all four Block Public Access settings on the bucket.", scope="global", auto_remediable=True)
def block_public_access(ctx):
    for b in ctx.buckets():
        try:
            cfg = ctx.client("s3").get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if _err(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            cfg = {}
        off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
               if not cfg.get(k)]
        if off:
            yield f"arn:aws:s3:::{b}", "Disabled: " + ", ".join(off)


@check("S3-005", "S3", M, "Bucket default encryption is not configured",
       "Enable default encryption (SSE-KMS preferred).", scope="global", auto_remediable=True)
def default_encryption(ctx):
    for b in ctx.buckets():
        try:
            ctx.client("s3").get_bucket_encryption(Bucket=b)
        except ClientError as e:
            if _err(e) == "ServerSideEncryptionConfigurationNotFoundError":
                yield f"arn:aws:s3:::{b}", "No default server-side encryption rule."
            else:
                raise


@check("S3-006", "S3", M, "Bucket versioning is not enabled",
       "Enable versioning to protect against accidental deletion and ransomware.",
       scope="global", auto_remediable=True)
def versioning(ctx):
    for b in ctx.buckets():
        if ctx.client("s3").get_bucket_versioning(Bucket=b).get("Status") != "Enabled":
            yield f"arn:aws:s3:::{b}", "Versioning is off or suspended."


@check("S3-007", "S3", L, "Bucket MFA Delete is not enabled",
       "Enable MFA Delete (requires the root user) on buckets holding critical data.", scope="global")
def mfa_delete(ctx):
    for b in ctx.buckets():
        v = ctx.client("s3").get_bucket_versioning(Bucket=b)
        if v.get("Status") == "Enabled" and v.get("MFADelete") != "Enabled":
            yield f"arn:aws:s3:::{b}", "Objects can be permanently deleted without MFA."


@check("S3-008", "S3", L, "Bucket server access logging is disabled",
       "Enable server access logging to a dedicated log bucket.", scope="global")
def access_logging(ctx):
    for b in ctx.buckets():
        if "LoggingEnabled" not in ctx.client("s3").get_bucket_logging(Bucket=b):
            yield f"arn:aws:s3:::{b}", "No access logs are recorded."


@check("S3-009", "S3", M, "Bucket policy does not enforce HTTPS",
       "Add a Deny statement for requests where aws:SecureTransport is false.", scope="global")
def enforce_tls(ctx):
    for b in ctx.buckets():
        policy = _policy(ctx, b) or {}
        enforced = any(
            st.get("Effect") == "Deny"
            and str(st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport", "")).lower() == "false"
            for st in _statements(policy)
        )
        if not enforced:
            yield f"arn:aws:s3:::{b}", "Plain HTTP requests are not denied."


@check("S3-010", "S3", L, "Bucket has no lifecycle policy",
       "Add lifecycle rules to expire or archive old objects and versions.", scope="global")
def lifecycle(ctx):
    for b in ctx.buckets():
        try:
            ctx.client("s3").get_bucket_lifecycle_configuration(Bucket=b)
        except ClientError as e:
            if _err(e) == "NoSuchLifecycleConfiguration":
                yield f"arn:aws:s3:::{b}", "No lifecycle rules configured."
            else:
                raise


@check("S3-011", "S3", M, "Bucket static website hosting is enabled",
       "Disable website hosting or serve the site through CloudFront with OAC.", scope="global")
def website(ctx):
    for b in ctx.buckets():
        try:
            ctx.client("s3").get_bucket_website(Bucket=b)
            yield f"arn:aws:s3:::{b}", "The bucket is served as a public website endpoint.", True
        except ClientError as e:
            if _err(e) != "NoSuchWebsiteConfiguration":
                raise


@check("S3-012", "S3", H, "Account-level S3 Block Public Access is not enabled",
       "Enable all four Block Public Access settings for the account.", scope="global")
def account_block_public_access(ctx):
    try:
        cfg = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if _err(e) not in ("NoSuchPublicAccessBlockConfiguration",):
            raise
        cfg = {}
    if not all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
        yield f"arn:aws:s3::{ctx.account_id}:account", "New buckets can be made public."
