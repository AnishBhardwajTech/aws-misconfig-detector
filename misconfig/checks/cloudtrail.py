"""CloudTrail checks (regional, trails are returned with shadow trails included)."""

from ..models import Severity
from . import check


def _trails(ctx):
    return ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"]


@check("CT-001", "CloudTrail", Severity.CRITICAL, "No multi-region CloudTrail is logging",
       "Create a multi-region trail with logging enabled.", scope="regional")
def multi_region_trail(ctx):
    ct = ctx.client("cloudtrail")
    ok = any(t.get("IsMultiRegionTrail") and ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")
             for t in _trails(ctx))
    if not ok:
        yield f"arn:aws:cloudtrail:{ctx.region}:{ctx.account_id}:trail/*", "API activity in this region is not fully recorded."


@check("CT-002", "CloudTrail", Severity.MEDIUM, "CloudTrail log file validation is disabled",
       "Enable log file validation so tampering with logs can be detected.", scope="regional")
def log_validation(ctx):
    for t in _trails(ctx):
        if t.get("HomeRegion") == ctx.region and not t.get("LogFileValidationEnabled"):
            yield t["TrailARN"], f"Trail {t['Name']} does not validate log files."


@check("CT-003", "CloudTrail", Severity.LOW, "CloudTrail logs are not encrypted with KMS",
       "Configure a KMS key for the trail.", scope="regional")
def trail_kms(ctx):
    for t in _trails(ctx):
        if t.get("HomeRegion") == ctx.region and not t.get("KmsKeyId"):
            yield t["TrailARN"], f"Trail {t['Name']} uses only S3-managed encryption."
