"""EC2 and VPC through boto3: resources, waiters, paginators, errors."""

import base64
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def ec2(endpoint, session_for):
    return session_for().client("ec2", endpoint_url=endpoint)


def code(exc):
    return exc.value.response["Error"]["Code"]


def alpine(ec2):
    images = ec2.describe_images(Owners=["amazon"], Filters=[{"Name": "name", "Values": ["mws-alpine-*"]}])
    return images["Images"][0]["ImageId"]


def test_vpc_subnet_and_security_group(ec2):
    vpc = ec2.create_vpc(
        CidrBlock="10.50.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "py"}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    assert vpc["State"] in ("pending", "available")
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.50.1.0/24", AvailabilityZone="us-east-1c")["Subnet"]
    assert subnet["AvailableIpAddressCount"] == 251
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.50.1.0/28")
    assert code(e) == "InvalidSubnet.Conflict"

    sg = ec2.create_security_group(GroupName=f"py-{uuid.uuid4().hex[:6]}", Description="py", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    got = ec2.describe_security_groups(GroupIds=[sg["GroupId"]])["SecurityGroups"][0]
    assert got["IpPermissions"][0]["FromPort"] == 80
    with pytest.raises(ClientError) as e:
        ec2.delete_vpc(VpcId=vpc_id)
    assert code(e) == "DependencyViolation"
    ec2.delete_security_group(GroupId=sg["GroupId"])
    ec2.delete_subnet(SubnetId=subnet["SubnetId"])
    ec2.delete_vpc(VpcId=vpc_id)
    with pytest.raises(ClientError) as e:
        ec2.describe_vpcs(VpcIds=[vpc_id])
    assert code(e) == "InvalidVpcID.NotFound"


def test_instances_with_waiters_and_paginators(ec2):
    ami = alpine(ec2)
    name = f"py-{uuid.uuid4().hex[:6]}"
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, DryRun=True)
    assert code(e) == "DryRunOperation"
    run = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        # Two t3.micro instances fit the default 5 vCPU On-Demand quota.
        MinCount=2,
        MaxCount=2,
        UserData="#!/bin/sh\necho hi\n",
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ids = [i["InstanceId"] for i in run["Instances"]]
    assert run["Instances"][0]["State"]["Name"] == "pending"
    ec2.get_waiter("instance_running").wait(InstanceIds=ids)
    ec2.get_waiter("instance_status_ok").wait(InstanceIds=ids)

    # boto3 base64-encodes user data for RunInstances.
    attr = ec2.describe_instance_attribute(InstanceId=ids[0], Attribute="userData")
    assert base64.b64decode(attr["UserData"]["Value"]) == b"#!/bin/sh\necho hi\n"

    pages = ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:Name", "Values": [name]}], PaginationConfig={"PageSize": 5}
    )
    found = [i["InstanceId"] for p in pages for r in p["Reservations"] for i in r["Instances"]]
    assert sorted(found) == sorted(ids)

    ec2.stop_instances(InstanceIds=ids[:1])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=ids[:1])
    ec2.start_instances(InstanceIds=ids[:1])
    ec2.get_waiter("instance_running").wait(InstanceIds=ids[:1])
    ec2.terminate_instances(InstanceIds=ids)
    ec2.get_waiter("instance_terminated").wait(InstanceIds=ids)
    with pytest.raises(ClientError) as e:
        ec2.stop_instances(InstanceIds=ids[:1])
    assert code(e) == "IncorrectInstanceState"


def test_key_pairs_volumes_and_addresses(ec2):
    name = f"py-{uuid.uuid4().hex[:6]}"
    key = ec2.create_key_pair(KeyName=name, KeyType="ed25519")
    assert key["KeyMaterial"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    with pytest.raises(ClientError) as e:
        ec2.create_key_pair(KeyName=name)
    assert code(e) == "InvalidKeyPair.Duplicate"
    ec2.delete_key_pair(KeyName=name)

    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=5, VolumeType="gp3")
    ec2.get_waiter("volume_available").wait(VolumeIds=[vol["VolumeId"]])
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"])
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap["SnapshotId"]])
    ec2.delete_snapshot(SnapshotId=snap["SnapshotId"])
    ec2.delete_volume(VolumeId=vol["VolumeId"])

    eip = ec2.allocate_address(Domain="vpc")
    assert eip["Domain"] == "vpc"
    ec2.release_address(AllocationId=eip["AllocationId"])
    with pytest.raises(ClientError) as e:
        ec2.release_address(AllocationId=eip["AllocationId"])
    assert code(e) == "InvalidAllocationID.NotFound"


def test_unauthorized_operation(endpoint, session_for):
    root = session_for()
    iam = root.client("iam", endpoint_url=endpoint)
    user = f"py-ec2-{uuid.uuid4().hex[:6]}"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    ec2 = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("ec2", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        ec2.describe_vpcs()
    assert code(e) == "UnauthorizedOperation"
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
