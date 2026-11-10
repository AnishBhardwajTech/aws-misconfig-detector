from helpers import ids, scan


def test_no_trail(aws):
    assert "CT-001" in ids(scan(aws, "CT-001"))


def test_good_trail(aws):
    aws.client("s3").create_bucket(Bucket="trail-logs")
    ct = aws.client("cloudtrail")
    ct.create_trail(Name="org", S3BucketName="trail-logs", IsMultiRegionTrail=True,
                    EnableLogFileValidation=True)
    ct.start_logging(Name="org")
    found = ids(scan(aws, "CT-001", "CT-002"))
    assert found == set()


def test_trail_without_validation_or_kms(aws):
    aws.client("s3").create_bucket(Bucket="trail-logs")
    aws.client("cloudtrail").create_trail(Name="basic", S3BucketName="trail-logs")
    assert {"CT-001", "CT-002", "CT-003"} <= ids(scan(aws, "CloudTrail"))


def test_kms_rotation(aws):
    kms = aws.client("kms")
    k = kms.create_key()["KeyMetadata"]["KeyId"]
    assert "KMS-001" in ids(scan(aws, "KMS-001"))
    kms.enable_key_rotation(KeyId=k)
    assert "KMS-001" not in ids(scan(aws, "KMS-001"))
