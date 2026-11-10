import json

from helpers import ids, public_bucket, scan, secure_bucket


def test_public_acl(aws):
    public_bucket(aws)
    f = [x for x in scan(aws, "S3-001").findings]
    assert len(f) == 1 and f[0].public_exposure and f[0].resource == "arn:aws:s3:::public-data"


def test_public_policy(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="leaky")
    s3.put_bucket_policy(Bucket="leaky", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::leaky/*"}]}))
    assert "S3-003" in ids(scan(aws, "S3-003"))


def test_new_bucket_has_hygiene_findings(aws):
    aws.client("s3").create_bucket(Bucket="plain")
    found = ids(scan(aws, "S3"))
    assert {"S3-004", "S3-006", "S3-008", "S3-009", "S3-010", "S3-012"} <= found
    assert "S3-001" not in found


def test_secure_bucket_passes_key_checks(aws):
    secure_bucket(aws)
    found = ids(scan(aws, "S3-001", "S3-003", "S3-004", "S3-005", "S3-006", "S3-009"))
    assert found == set()


def test_website_hosting(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="site")
    s3.put_bucket_website(Bucket="site", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    assert "S3-011" in ids(scan(aws, "S3-011"))
