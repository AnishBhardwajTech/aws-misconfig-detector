from helpers import ids, open_sg, scan


def test_ssh_open(aws):
    open_sg(aws, 22)
    f = scan(aws, "EC2-001").findings
    assert len(f) == 1 and f[0].public_exposure


def test_ssh_restricted_is_fine(aws):
    open_sg(aws, 22, cidr="10.0.0.0/8")
    assert not scan(aws, "EC2-001").findings


def test_rdp_and_db_ports(aws):
    open_sg(aws, 3389, name="rdp")
    open_sg(aws, 5432, name="pg")
    found = ids(scan(aws, "EC2-002", "EC2-004"))
    assert found == {"EC2-002", "EC2-004"}


def test_all_traffic_open(aws):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="any", Description="t", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert {"EC2-001", "EC2-002", "EC2-003"} <= ids(scan(aws, "EC2-001", "EC2-002", "EC2-003"))


def test_ipv6_ssh(aws):
    open_sg(aws, 22, cidr="::/0", v6=True)
    assert "EC2-005" in ids(scan(aws, "EC2-005"))


def test_unencrypted_volume_and_default_encryption(aws):
    aws.client("ec2").create_volume(AvailabilityZone="us-east-1a", Size=8)
    assert {"EC2-007", "EC2-008"} <= ids(scan(aws, "EC2-007", "EC2-008"))
    aws.client("ec2").enable_ebs_encryption_by_default()
    assert "EC2-008" not in ids(scan(aws, "EC2-008"))


def test_public_snapshot(aws):
    ec2 = aws.client("ec2")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)["VolumeId"]
    snap = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    ec2.modify_snapshot_attribute(SnapshotId=snap, Attribute="createVolumePermission",
                                  OperationType="add", GroupNames=["all"])
    assert "EC2-009" in ids(scan(aws, "EC2-009"))


def test_instance_imdsv1_and_no_profile(aws):
    ec2 = aws.client("ec2")
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                      MetadataOptions={"HttpTokens": "optional"})
    assert {"EC2-011", "EC2-012"} <= ids(scan(aws, "EC2-011", "EC2-012"))


def test_flow_logs_and_unused_eip(aws):
    aws.client("ec2").allocate_address(Domain="vpc")
    assert {"EC2-014", "EC2-015"} <= ids(scan(aws, "EC2-014", "EC2-015"))
