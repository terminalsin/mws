"""Route 53 through boto3."""

import uuid

import pytest
from botocore.exceptions import ClientError


@pytest.fixture
def r53(endpoint, session_for):
    return session_for().client("route53", endpoint_url=endpoint)


def new_zone(r53, name):
    out = r53.create_hosted_zone(Name=name, CallerReference=uuid.uuid4().hex)
    return out["HostedZone"]["Id"]


def a_record(action, name, ip, ttl=60):
    return {
        "Action": action,
        "ResourceRecordSet": {"Name": name, "Type": "A", "TTL": ttl, "ResourceRecords": [{"Value": ip}]},
    }


def test_zone_records_and_waiter(r53):
    zone = new_zone(r53, f"{uuid.uuid4().hex[:8]}.example")
    name = r53.get_hosted_zone(Id=zone)["HostedZone"]["Name"]
    out = r53.change_resource_record_sets(
        HostedZoneId=zone, ChangeBatch={"Changes": [a_record("CREATE", f"www.{name}", "192.0.2.10")]}
    )
    # botocore's waiter polls GetChange until INSYNC.
    r53.get_waiter("resource_record_sets_changed").wait(
        Id=out["ChangeInfo"]["Id"], WaiterConfig={"Delay": 1, "MaxAttempts": 3}
    )
    sets = r53.list_resource_record_sets(HostedZoneId=zone)["ResourceRecordSets"]
    assert [s["Type"] for s in sets] == ["NS", "SOA", "A"]
    assert sets[2]["ResourceRecords"] == [{"Value": "192.0.2.10"}]

    paginator = r53.get_paginator("list_resource_record_sets")
    pages = list(paginator.paginate(HostedZoneId=zone, PaginationConfig={"PageSize": 1}))
    assert sum(len(p["ResourceRecordSets"]) for p in pages) == 3


def test_invalid_change_batch(r53):
    zone = new_zone(r53, f"{uuid.uuid4().hex[:8]}.example")
    name = r53.get_hosted_zone(Id=zone)["HostedZone"]["Name"]
    with pytest.raises(ClientError) as e:
        r53.change_resource_record_sets(
            HostedZoneId=zone, ChangeBatch={"Changes": [a_record("DELETE", f"x.{name}", "192.0.2.1")]}
        )
    err = e.value.response["Error"]
    assert err["Code"] == "InvalidChangeBatch"
    assert f"Tried to delete resource record set [name='x.{name}', type='A'] but it was not found" in err["Message"]
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400


def test_missing_zone(r53):
    with pytest.raises(ClientError) as e:
        r53.get_hosted_zone(Id="Z0000000000000000000")
    assert e.value.response["Error"]["Code"] == "NoSuchHostedZone"
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404
