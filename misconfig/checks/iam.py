"""IAM checks (global, run once per account)."""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ..models import Severity
from . import check

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
KEY_MAX_AGE_DAYS = 90
UNUSED_DAYS = 90


def _now():
    return datetime.now(timezone.utc)


def _summary(ctx) -> dict:
    return ctx.client("iam").get_account_summary()["SummaryMap"]


def _password_policy(ctx) -> dict | None:
    try:
        return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise


def _doc(document) -> dict:
    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    return document


def _statements(doc: dict) -> list[dict]:
    st = doc.get("Statement", [])
    return st if isinstance(st, list) else [st]


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _is_admin_statement(st: dict) -> bool:
    if st.get("Effect") != "Allow":
        return False
    actions = _as_list(st.get("Action", []))
    resources = _as_list(st.get("Resource", []))
    return any(a in ("*", "*:*") for a in actions) and "*" in resources


def _has_wildcard_action(st: dict) -> bool:
    return st.get("Effect") == "Allow" and any(
        a == "*" or a.endswith(":*") for a in _as_list(st.get("Action", []))
    )


@check("IAM-001", "IAM", C, "Root account has active access keys",
       "Delete the root user's access keys and use IAM roles or users instead.", scope="global")
def root_access_keys(ctx):
    if _summary(ctx).get("AccountAccessKeysPresent", 0):
        yield "root", "The root user has access keys, which grant unrestricted account access."


@check("IAM-002", "IAM", C, "Root account MFA is not enabled",
       "Enable a hardware or virtual MFA device for the root user.", scope="global")
def root_mfa(ctx):
    if not _summary(ctx).get("AccountMFAEnabled", 0):
        yield "root", "The root user can sign in with only a password."


@check("IAM-003", "IAM", H, "No IAM password policy is set",
       "Create an account password policy (min length 14, complexity, reuse prevention).",
       scope="global", auto_remediable=True)
def password_policy_exists(ctx):
    if _password_policy(ctx) is None:
        yield "account-password-policy", "The account uses the AWS default password rules."


@check("IAM-004", "IAM", M, "Password policy minimum length is below 14",
       "Set MinimumPasswordLength to at least 14.", scope="global", auto_remediable=True)
def password_length(ctx):
    p = _password_policy(ctx)
    if p and p.get("MinimumPasswordLength", 0) < 14:
        yield "account-password-policy", f"Minimum length is {p.get('MinimumPasswordLength')}."


@check("IAM-005", "IAM", M, "Password policy does not require all character types",
       "Require uppercase, lowercase, numbers and symbols.", scope="global", auto_remediable=True)
def password_complexity(ctx):
    p = _password_policy(ctx)
    if not p:
        return
    missing = [k for k in ("RequireUppercaseCharacters", "RequireLowercaseCharacters",
                           "RequireNumbers", "RequireSymbols") if not p.get(k)]
    if missing:
        yield "account-password-policy", "Not required: " + ", ".join(missing)


@check("IAM-006", "IAM", L, "Password reuse prevention is below 24",
       "Set PasswordReusePrevention to 24.", scope="global", auto_remediable=True)
def password_reuse(ctx):
    p = _password_policy(ctx)
    if p and p.get("PasswordReusePrevention", 0) < 24:
        yield "account-password-policy", f"Reuse prevention is {p.get('PasswordReusePrevention', 0)}."


@check("IAM-007", "IAM", L, "Passwords do not expire within 90 days",
       "Set MaxPasswordAge to 90 days or less.", scope="global", auto_remediable=True)
def password_expiry(ctx):
    p = _password_policy(ctx)
    if p and (not p.get("ExpirePasswords") or p.get("MaxPasswordAge", 0) > 90):
        yield "account-password-policy", f"Max password age: {p.get('MaxPasswordAge', 'never')}."


def _has_console_password(iam, user: str) -> bool:
    try:
        iam.get_login_profile(UserName=user)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


@check("IAM-008", "IAM", H, "Console user without MFA",
       "Require MFA for every IAM user with a console password.", scope="global")
def users_without_mfa(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        name = u["UserName"]
        if _has_console_password(iam, name) and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            yield u["Arn"], f"User {name} can sign in to the console without MFA."


@check("IAM-009", "IAM", M, f"Access key older than {KEY_MAX_AGE_DAYS} days",
       "Rotate access keys at least every 90 days.", scope="global")
def old_access_keys(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
            age = (_now() - k["CreateDate"]).days
            if k["Status"] == "Active" and age > KEY_MAX_AGE_DAYS:
                yield f"{u['Arn']}/{k['AccessKeyId']}", f"Key is {age} days old."


@check("IAM-010", "IAM", L, "User has more than one active access key",
       "Keep at most one active access key per user.", scope="global")
def multiple_keys(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        active = [k for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                  if k["Status"] == "Active"]
        if len(active) > 1:
            yield u["Arn"], f"{len(active)} active access keys."


@check("IAM-011", "IAM", L, "Policies attached directly to a user",
       "Grant permissions through groups or roles instead of directly to users.", scope="global")
def direct_user_policies(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        n = u["UserName"]
        attached = iam.list_attached_user_policies(UserName=n)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=n)["PolicyNames"]
        if attached or inline:
            yield u["Arn"], f"{len(attached)} managed and {len(inline)} inline policies on the user."


@check("IAM-012", "IAM", C, "Customer managed policy grants full admin (*:*)",
       "Replace '*' actions on '*' resources with least-privilege permissions.", scope="global")
def admin_customer_policies(ctx):
    iam = ctx.client("iam")
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=False):
        for p in page["Policies"]:
            doc = _doc(iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
                       ["PolicyVersion"]["Document"])
            if any(_is_admin_statement(s) for s in _statements(doc)):
                yield p["Arn"], f"Policy {p['PolicyName']} allows every action on every resource."


@check("IAM-013", "IAM", H, "User has AdministratorAccess attached",
       "Use a role with admin rights assumed only when needed, protected by MFA.", scope="global")
def admin_users(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        for p in iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]:
            if p["PolicyName"] == "AdministratorAccess":
                yield u["Arn"], f"User {u['UserName']} has AdministratorAccess."


@check("IAM-014", "IAM", H, "Inline user policy uses wildcard actions",
       "Replace wildcard actions like s3:* with the specific actions needed.", scope="global")
def inline_wildcards(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        for name in iam.list_user_policies(UserName=u["UserName"])["PolicyNames"]:
            doc = _doc(iam.get_user_policy(UserName=u["UserName"], PolicyName=name)["PolicyDocument"])
            if any(_has_wildcard_action(s) for s in _statements(doc)):
                yield f"{u['Arn']}/{name}", f"Inline policy {name} allows wildcard actions."


@check("IAM-015", "IAM", M, f"Access key unused for {UNUSED_DAYS}+ days",
       "Deactivate or delete access keys that are not in use.", scope="global")
def unused_keys(ctx):
    iam = ctx.client("iam")
    for u in ctx.iam_users():
        for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
            if k["Status"] != "Active":
                continue
            last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"].get("LastUsedDate")
            ref = last or k["CreateDate"]
            if (_now() - ref).days > UNUSED_DAYS:
                yield f"{u['Arn']}/{k['AccessKeyId']}", "Key has not been used in over 90 days."


@check("IAM-016", "IAM", C, "Role trust policy allows any AWS principal",
       "Restrict the role's trust policy to specific accounts, services or roles.", scope="global")
def open_role_trust(ctx):
    iam = ctx.client("iam")
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            for st in _statements(_doc(r["AssumeRolePolicyDocument"])):
                principal = st.get("Principal", {})
                aws = principal if principal == "*" else principal.get("AWS", []) if isinstance(principal, dict) else []
                if st.get("Effect") == "Allow" and "*" in _as_list(aws) and not st.get("Condition"):
                    yield r["Arn"], f"Anyone can assume role {r['RoleName']}.", True
