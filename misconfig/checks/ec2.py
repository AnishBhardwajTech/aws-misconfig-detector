"""EC2 / VPC checks (regional)."""

from __future__ import annotations

from ..models import Severity
from . import check

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MS SQL", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis"}


def _open_v4(rule) -> bool:
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))


def _open_v6(rule) -> bool:
    return any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))


def _covers(rule, port: int) -> bool:
    if rule.get("IpProtocol") == "-1":
        return True
    if rule.get("IpProtocol") not in ("tcp", "6"):
        return False
    return rule.get("FromPort", 0) <= port <= rule.get("ToPort", 65535)


def _sg_arn(ctx, sg) -> str:
    return f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:security-group/{sg['GroupId']}"


def _world_port(ctx, port):
    for sg in ctx.security_groups():
        for rule in sg.get("IpPermissions", []):
            if _open_v4(rule) and _covers(rule, port):
                yield sg
                break


@check("EC2-001", "EC2", C, "Security group allows SSH (22) from the internet",
       "Restrict port 22 to known IP ranges or use SSM Session Manager.", auto_remediable=True)
def ssh_open(ctx):
    for sg in _world_port(ctx, 22):
        yield _sg_arn(ctx, sg), f"{sg['GroupId']} ({sg['GroupName']}) allows 0.0.0.0/0 on port 22.", True


@check("EC2-002", "EC2", C, "Security group allows RDP (3389) from the internet",
       "Restrict port 3389 to known IP ranges or use a bastion / Fleet Manager.", auto_remediable=True)
def rdp_open(ctx):
    for sg in _world_port(ctx, 3389):
        yield _sg_arn(ctx, sg), f"{sg['GroupId']} ({sg['GroupName']}) allows 0.0.0.0/0 on port 3389.", True


@check("EC2-003", "EC2", C, "Security group allows all traffic from the internet",
       "Remove rules allowing all protocols from 0.0.0.0/0.")
def all_open(ctx):
    for sg in ctx.security_groups():
        if any(r.get("IpProtocol") == "-1" and _open_v4(r) for r in sg.get("IpPermissions", [])):
            yield _sg_arn(ctx, sg), f"{sg['GroupId']} allows every port and protocol from 0.0.0.0/0.", True


@check("EC2-004", "EC2", H, "Database port open to the internet",
       "Keep databases in private subnets and allow only application security groups.")
def db_open(ctx):
    for sg in ctx.security_groups():
        exposed = sorted({name for port, name in DB_PORTS.items()
                          for r in sg.get("IpPermissions", []) if _open_v4(r) and _covers(r, port)
                          and r.get("IpProtocol") != "-1"})
        if exposed:
            yield _sg_arn(ctx, sg), f"{sg['GroupId']} exposes {', '.join(exposed)} to 0.0.0.0/0.", True


@check("EC2-005", "EC2", H, "Admin port open to the internet over IPv6",
       "Remove ::/0 rules on ports 22 and 3389.")
def ipv6_admin_open(ctx):
    for sg in ctx.security_groups():
        if any(_open_v6(r) and (_covers(r, 22) or _covers(r, 3389)) for r in sg.get("IpPermissions", [])):
            yield _sg_arn(ctx, sg), f"{sg['GroupId']} allows ::/0 on SSH or RDP.", True


@check("EC2-006", "EC2", M, "Default security group allows inbound traffic",
       "Remove all inbound rules from default security groups.")
def default_sg(ctx):
    for sg in ctx.security_groups():
        if sg["GroupName"] == "default" and any(
            _open_v4(r) or _open_v6(r) or r.get("IpRanges") for r in sg.get("IpPermissions", [])
        ):
            yield _sg_arn(ctx, sg), f"Default group {sg['GroupId']} in {sg.get('VpcId')} has inbound CIDR rules."


@check("EC2-007", "EC2", H, "EBS volume is not encrypted",
       "Snapshot the volume, copy the snapshot with encryption, and replace the volume.")
def unencrypted_volumes(ctx):
    for page in ctx.client("ec2").get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            if not v.get("Encrypted"):
                yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:volume/{v['VolumeId']}", f"{v['VolumeId']} is unencrypted."


@check("EC2-008", "EC2", M, "EBS encryption by default is disabled",
       "Enable EBS encryption by default in every region.", auto_remediable=True)
def ebs_default_encryption(ctx):
    if not ctx.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:ebs-default-encryption", "New volumes are not encrypted automatically."


@check("EC2-009", "EC2", C, "EBS snapshot is public",
       "Remove the 'all' group from the snapshot's createVolumePermission.")
def public_snapshots(ctx):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
        for s in page["Snapshots"]:
            perms = ec2.describe_snapshot_attribute(SnapshotId=s["SnapshotId"], Attribute="createVolumePermission")
            if any(p.get("Group") == "all" for p in perms.get("CreateVolumePermissions", [])):
                yield f"arn:aws:ec2:{ctx.region}::snapshot/{s['SnapshotId']}", f"{s['SnapshotId']} can be copied by anyone.", True


@check("EC2-010", "EC2", M, "Instance has a public IP address",
       "Place instances in private subnets behind a load balancer or NAT.")
def public_instances(ctx):
    for i in ctx.instances():
        if i.get("PublicIpAddress"):
            yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:instance/{i['InstanceId']}", \
                f"{i['InstanceId']} has public IP {i['PublicIpAddress']}.", True


@check("EC2-011", "EC2", H, "Instance allows IMDSv1",
       "Require IMDSv2 (HttpTokens=required) to protect against SSRF credential theft.", auto_remediable=True)
def imdsv1(ctx):
    for i in ctx.instances():
        if i.get("MetadataOptions", {}).get("HttpTokens", "optional") != "required":
            yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:instance/{i['InstanceId']}", \
                f"{i['InstanceId']} accepts IMDSv1 requests."


@check("EC2-012", "EC2", L, "Instance has no IAM instance profile",
       "Attach a role so the instance does not need long-lived keys on disk.")
def no_instance_profile(ctx):
    for i in ctx.instances():
        if not i.get("IamInstanceProfile"):
            yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:instance/{i['InstanceId']}", \
                f"{i['InstanceId']} has no instance profile."


@check("EC2-013", "EC2", H, "AMI owned by this account is public",
       "Make the AMI private or share it only with specific accounts.")
def public_amis(ctx):
    for img in ctx.client("ec2").describe_images(Owners=["self"])["Images"]:
        if img.get("Public"):
            yield f"arn:aws:ec2:{ctx.region}::image/{img['ImageId']}", f"{img['ImageId']} is public.", True


@check("EC2-014", "EC2", M, "VPC flow logs are not enabled",
       "Enable VPC flow logs to CloudWatch Logs or S3.")
def flow_logs(ctx):
    ec2 = ctx.client("ec2")
    logged = {f["ResourceId"] for f in ec2.describe_flow_logs()["FlowLogs"]}
    for vpc in ec2.describe_vpcs()["Vpcs"]:
        if vpc["VpcId"] not in logged:
            yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:vpc/{vpc['VpcId']}", f"{vpc['VpcId']} has no flow logs."


@check("EC2-015", "EC2", L, "Elastic IP is not associated",
       "Release unused Elastic IPs (they cost money and can be reused by attackers in DNS takeovers).")
def unused_eips(ctx):
    for a in ctx.client("ec2").describe_addresses()["Addresses"]:
        if not a.get("AssociationId"):
            yield f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:eip/{a.get('AllocationId')}", f"{a['PublicIp']} is unattached."
