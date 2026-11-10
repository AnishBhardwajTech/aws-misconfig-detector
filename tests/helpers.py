"""Builders that create insecure resources in the mocked account."""

import json

from misconfig.scanner import run_scan


def ids(result):
    return {f.check_id for f in result.findings}


def scan(session, *checks):
    return run_scan(session, only=list(checks) or None)


def open_sg(session, port, cidr="0.0.0.0/0", name="web", v6=False):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName=name, Description="t", VpcId=vpc)["GroupId"]
    perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port}
    perm["Ipv6Ranges" if v6 else "IpRanges"] = [{"CidrIpv6": cidr} if v6 else {"CidrIp": cidr}]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[perm])
    return sg


def public_bucket(session, name="public-data"):
    s3 = session.client("s3")
    s3.create_bucket(Bucket=name)
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    return name


def secure_bucket(session, name="locked-down"):
    s3 = session.client("s3")
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    return name


ADMIN_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})


def admin_access_policy(session):
    """Stand-in for the AWS managed AdministratorAccess policy (moto does not load
    managed policies by default because it is slow)."""
    return session.client("iam").create_policy(PolicyName="AdministratorAccess", PolicyDocument=ADMIN_POLICY)["Policy"]["Arn"]
