"""AWS Organizations through boto3: member accounts and SCPs."""

import json
import uuid

import pytest
from botocore.exceptions import ClientError

DENY_CREATE_USER = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:CreateUser", "Resource": "*"}]}
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def test_scp_limits_a_created_account(endpoint, session_for, iam):
    orgs = session_for().client("organizations", endpoint_url=endpoint, region_name="us-east-1")
    org = orgs.create_organization(FeatureSet="ALL")["Organization"]
    try:
        root_id = orgs.list_roots()["Roots"][0]["Id"]
        name = f"acct-{uuid.uuid4().hex[:6]}"
        status = orgs.create_account(Email=f"{name}@example.com", AccountName=name)["CreateAccountStatus"]
        status = orgs.describe_create_account_status(CreateAccountRequestId=status["Id"])["CreateAccountStatus"]
        assert status["State"] == "SUCCEEDED"
        account = status["AccountId"]

        orgs.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
        policy = orgs.create_policy(
            Name="no-users", Description="deny", Type="SERVICE_CONTROL_POLICY", Content=json.dumps(DENY_CREATE_USER)
        )["Policy"]["PolicySummary"]
        orgs.attach_policy(PolicyId=policy["Id"], TargetId=account)

        admin = f"orgadmin-{uuid.uuid4().hex[:6]}"
        iam.create_user(UserName=admin)
        iam.put_user_policy(UserName=admin, PolicyName="admin", PolicyDocument=json.dumps(ADMIN))
        key = iam.create_access_key(UserName=admin)["AccessKey"]
        sts = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("sts", endpoint_url=endpoint)
        creds = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account}:role/OrganizationAccountAccessRole", RoleSessionName="ops"
        )["Credentials"]
        member = session_for(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
        assert member.client("sts", endpoint_url=endpoint).get_caller_identity()["Account"] == account
        member_iam = member.client("iam", endpoint_url=endpoint)
        with pytest.raises(ClientError) as e:
            member_iam.create_user(UserName="blocked")
        assert e.value.response["Error"]["Code"] == "AccessDenied"
        assert e.value.response["Error"]["Message"].endswith("with an explicit deny in a service control policy")

        with pytest.raises(ClientError) as e:
            member.client("organizations", endpoint_url=endpoint, region_name="us-east-1").list_accounts()
        assert e.value.response["Error"]["Code"] == "AccessDeniedException"
    finally:
        for a in orgs.list_accounts()["Accounts"]:
            if a["Id"] != org["MasterAccountId"]:
                orgs.remove_account_from_organization(AccountId=a["Id"])
        orgs.delete_organization()
