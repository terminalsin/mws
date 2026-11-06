import io
import json
import zipfile

from ..dsl import aws_error, aws_ok, scenario

LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)


def handler_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "index.py",
            "import json\n\ndef handler(event, context):\n    return {'echo': event, 'ok': True}\n",
        )
    return buf.getvalue()


ZIP = handler_zip()


@scenario("lambda", "function lifecycle", needs=("iam",))
def _(s):
    s.call("create_role", service="iam", RoleName="${name}-fn", AssumeRolePolicyDocument=LAMBDA_TRUST, save={"role": "Role.Arn"})
    s.call(
        "create_function",
        FunctionName="${name}",
        Runtime="python3.12",
        Role="${role}",
        Handler="index.handler",
        Code={"ZipFile": ZIP},
        Timeout=10,
        Environment={"Variables": {"MODE": "parity"}},
        Tags={"team": "parity"},
        _until=lambda r: True,
        _wait=15,
        _note="AWS may answer InvalidParameterValueException until the new role propagates",
        save={"arn": "FunctionArn"},
    )
    s.call("get_function", FunctionName="${name}", _until="Configuration.State == 'Active'", _wait=60, _ignore=["Code.Location"])
    s.call("get_function_configuration", FunctionName="${name}")
    s.call("invoke", FunctionName="${name}", Payload=json.dumps({"hello": "parity"}).encode(), _note="needs a Python runtime on the MWS side and Docker on the LocalStack side")
    s.call("invoke", FunctionName="${name}", InvocationType="DryRun", expect=aws_ok(status=204))
    s.call("invoke", FunctionName="${name}", InvocationType="Event", expect=aws_ok(status=202))
    s.call("update_function_configuration", FunctionName="${name}", MemorySize=256, Description="updated")
    s.call("get_function_configuration", FunctionName="${name}", _until="LastUpdateStatus == 'Successful'", _wait=30)
    s.call("publish_version", FunctionName="${name}", save={"version": "Version"})
    s.call("list_versions_by_function", FunctionName="${name}")
    s.call("create_alias", FunctionName="${name}", Name="live", FunctionVersion="${version}")
    s.call("get_alias", FunctionName="${name}", Name="live")
    s.call("list_aliases", FunctionName="${name}")
    s.call(
        "add_permission",
        FunctionName="${name}",
        StatementId="s3",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn="arn:aws:s3:::${name}",
    )
    s.call("get_policy", FunctionName="${name}")
    s.call("remove_permission", FunctionName="${name}", StatementId="s3")
    s.call("put_function_concurrency", FunctionName="${name}", ReservedConcurrentExecutions=5)
    s.call("get_function_concurrency", FunctionName="${name}")
    s.call("list_tags", Resource="${arn}")
    s.call("tag_resource", Resource="${arn}", Tags={"env": "test"})
    s.call("create_function_url_config", FunctionName="${name}", AuthType="AWS_IAM")
    s.call("get_function_url_config", FunctionName="${name}")
    s.call("delete_function_url_config", FunctionName="${name}")
    s.call("get_function", FunctionName="${name}-none", expect=aws_error("ResourceNotFoundException", 404))
    s.call(
        "create_function",
        FunctionName="${name}",
        Runtime="python3.12",
        Role="${role}",
        Handler="index.handler",
        Code={"ZipFile": ZIP},
        expect=aws_error("ResourceConflictException", 409),
    )
    s.call(
        "create_function",
        FunctionName="${name}-badrt",
        Runtime="cobol85",
        Role="${role}",
        Handler="index.handler",
        Code={"ZipFile": ZIP},
        _raw=True,
        _note="unknown runtime: compare how each side rejects it",
    )
    s.call("get_account_settings", _shape_only=True)
    s.cleanup("delete_alias", FunctionName="${name}", Name="live")
    s.cleanup("delete_function", FunctionName="${name}")
    s.cleanup("delete_role", service="iam", RoleName="${name}-fn")


@scenario("lambda", "layers")
def _(s):
    s.call("publish_layer_version", LayerName="${name}", Content={"ZipFile": ZIP}, CompatibleRuntimes=["python3.12"], save={"lv": "Version"})
    s.call("get_layer_version", LayerName="${name}", VersionNumber="${lv}", _ignore=["Content.Location"])
    s.call("list_layer_versions", LayerName="${name}")
    s.call("get_layer_version", LayerName="${name}", VersionNumber=99, expect=aws_error("ResourceNotFoundException", 404))
    s.cleanup("delete_layer_version", LayerName="${name}", VersionNumber="${lv}")


@scenario("ec2", "vpc networking")
def _(s):
    s.call("create_vpc", CidrBlock="10.77.0.0/16", save={"vpc": "Vpc.VpcId"})
    s.call("describe_vpcs", VpcIds=["${vpc}"])
    s.call("modify_vpc_attribute", VpcId="${vpc}", EnableDnsHostnames={"Value": True})
    s.call("describe_vpc_attribute", VpcId="${vpc}", Attribute="enableDnsHostnames")
    s.call("create_subnet", VpcId="${vpc}", CidrBlock="10.77.1.0/24", AvailabilityZone="${region}a", save={"subnet": "Subnet.SubnetId"})
    s.call("describe_subnets", SubnetIds=["${subnet}"])
    s.call("create_subnet", VpcId="${vpc}", CidrBlock="10.99.1.0/24", expect=aws_error("InvalidSubnet.Range", 400))
    s.call("create_security_group", GroupName="${name}", Description="parity", VpcId="${vpc}", save={"sg": "GroupId"})
    s.call(
        "authorize_security_group_ingress",
        GroupId="${sg}",
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    s.call("describe_security_groups", GroupIds=["${sg}"])
    s.call("describe_security_group_rules", Filters=[{"Name": "group-id", "Values": ["${sg}"]}])
    s.call("create_internet_gateway", save={"igw": "InternetGateway.InternetGatewayId"})
    s.call("attach_internet_gateway", InternetGatewayId="${igw}", VpcId="${vpc}")
    s.call("create_route_table", VpcId="${vpc}", save={"rtb": "RouteTable.RouteTableId"})
    s.call("create_route", RouteTableId="${rtb}", DestinationCidrBlock="0.0.0.0/0", GatewayId="${igw}")
    s.call("describe_route_tables", RouteTableIds=["${rtb}"])
    s.call("create_tags", Resources=["${vpc}"], Tags=[{"Key": "team", "Value": "parity"}])
    s.call("describe_tags", Filters=[{"Name": "resource-id", "Values": ["${vpc}"]}])
    s.call("describe_vpcs", VpcIds=["vpc-00000000000000000"], expect=aws_error("InvalidVpcID.NotFound", 400))
    s.call("delete_vpc", VpcId="${vpc}", expect=aws_error("DependencyViolation", 400))
    s.cleanup("delete_route_table", RouteTableId="${rtb}")
    s.cleanup("detach_internet_gateway", InternetGatewayId="${igw}", VpcId="${vpc}")
    s.cleanup("delete_internet_gateway", InternetGatewayId="${igw}")
    s.cleanup("delete_security_group", GroupId="${sg}")
    s.cleanup("delete_subnet", SubnetId="${subnet}")
    s.cleanup("delete_vpc", VpcId="${vpc}")


@scenario("ec2", "key pairs, volumes and regions")
def _(s):
    s.call("create_key_pair", KeyName="${name}", _ignore=["KeyMaterial"])
    s.call("describe_key_pairs", KeyNames=["${name}"])
    s.call("create_key_pair", KeyName="${name}", expect=aws_error("InvalidKeyPair.Duplicate", 400))
    s.call("delete_key_pair", KeyName="${name}")
    s.call("create_volume", AvailabilityZone="${region}a", Size=1, VolumeType="gp3", save={"vol": "VolumeId"})
    s.call("describe_volumes", VolumeIds=["${vol}"])
    s.cleanup("delete_volume", VolumeId="${vol}")
    s.call("describe_regions", RegionNames=["us-east-1", "eu-west-1"])
    s.call("describe_availability_zones", Filters=[{"Name": "region-name", "Values": ["${region}"]}], _shape_only=True)
    s.call("allocate_address", Domain="vpc", save={"alloc": "AllocationId"})
    s.call("describe_addresses", AllocationIds=["${alloc}"])
    s.cleanup("release_address", AllocationId="${alloc}")
