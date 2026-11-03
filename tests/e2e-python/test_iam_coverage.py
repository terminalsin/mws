"""IAM operations through boto3: the lifecycle of every IAM entity, with
the errors AWS returns once something is gone."""

import json
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"
TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
READ_S3 = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
)
LIST_S3 = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def code(exc):
    return exc.value.response["Error"]["Code"]


def managed_policy(iam, doc=READ_S3):
    return iam.create_policy(PolicyName=unique("pol"), PolicyDocument=doc)["Policy"]["Arn"]


def test_user_updates_inline_policies_and_tags(iam):
    name, renamed = unique("user"), unique("renamed")
    iam.create_user(UserName=name, Path="/a/")
    iam.update_user(UserName=name, NewUserName=renamed, NewPath="/b/")
    with pytest.raises(ClientError) as e:
        iam.get_user(UserName=name)
    assert code(e) == "NoSuchEntity"
    user = iam.get_user(UserName=renamed)["User"]
    assert user["Path"] == "/b/"
    assert user["Arn"] == f"arn:aws:iam::{ACCOUNT}:user/b/{renamed}"

    iam.put_user_policy(UserName=renamed, PolicyName="inline", PolicyDocument=READ_S3)
    assert iam.list_user_policies(UserName=renamed)["PolicyNames"] == ["inline"]
    got = iam.get_user_policy(UserName=renamed, PolicyName="inline")
    assert got["PolicyDocument"]["Statement"][0]["Action"] == "s3:GetObject"
    iam.delete_user_policy(UserName=renamed, PolicyName="inline")
    assert iam.list_user_policies(UserName=renamed)["PolicyNames"] == []
    with pytest.raises(ClientError) as e:
        iam.get_user_policy(UserName=renamed, PolicyName="inline")
    assert code(e) == "NoSuchEntity"

    arn = managed_policy(iam)
    iam.attach_user_policy(UserName=renamed, PolicyArn=arn)
    attached = iam.list_attached_user_policies(UserName=renamed)["AttachedPolicies"]
    assert [p["PolicyArn"] for p in attached] == [arn]
    iam.put_user_permissions_boundary(UserName=renamed, PermissionsBoundary=arn)
    assert iam.get_user(UserName=renamed)["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == arn
    iam.delete_user_permissions_boundary(UserName=renamed)
    assert "PermissionsBoundary" not in iam.get_user(UserName=renamed)["User"]

    iam.tag_user(UserName=renamed, Tags=[{"Key": "team", "Value": "a"}, {"Key": "env", "Value": "dev"}])
    iam.untag_user(UserName=renamed, TagKeys=["env"])
    assert iam.list_user_tags(UserName=renamed)["Tags"] == [{"Key": "team", "Value": "a"}]


def test_user_credentials_lifecycle(iam):
    name = unique("creds")
    iam.create_user(UserName=name)

    iam.create_login_profile(UserName=name, Password="Str0ng!Passw0rd", PasswordResetRequired=True)
    profile = iam.get_login_profile(UserName=name)["LoginProfile"]
    assert profile["UserName"] == name and profile["PasswordResetRequired"] is True
    iam.update_login_profile(UserName=name, PasswordResetRequired=False)
    assert iam.get_login_profile(UserName=name)["LoginProfile"]["PasswordResetRequired"] is False
    iam.delete_login_profile(UserName=name)
    with pytest.raises(ClientError) as e:
        iam.get_login_profile(UserName=name)
    assert code(e) == "NoSuchEntity"

    ssh_key = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3F6tyPEFEzV0LX3X8BsXdMsQz1x2cEikKDEY0aIj41qgxMCP/iteneqXSIFZBp5vizPvaoIR3Um9xK7PGoW8giupGn+EPuxIA4cDM4vzOqOkiMPhz5XK0whEjkVzTo4+S0puvDZuwIsdiW9mxhJc7tgBNL0cYlWSYVkz4G/fslNfRPW5mYAM49f4fhtxPb5ok4Q2Lg9dPKVHO/Bgeu5woMc7RY0p1ej6D4CKFE6lymSDJpW0YHX/wqE9+cfEauh7xZcG0q9t2ta6F6fmX0agvpFyZo8aFbXeUBr7osSCJNgvavWbM/06niWrOvYX2xwWdhXmXSrbX8ZbabVohBK41 test@example.com"
    )
    uploaded = iam.upload_ssh_public_key(UserName=name, SSHPublicKeyBody=ssh_key)["SSHPublicKey"]
    key_id = uploaded["SSHPublicKeyId"]
    listed = iam.list_ssh_public_keys(UserName=name)["SSHPublicKeys"]
    assert [k["SSHPublicKeyId"] for k in listed] == [key_id]
    iam.delete_ssh_public_key(UserName=name, SSHPublicKeyId=key_id)
    assert iam.list_ssh_public_keys(UserName=name)["SSHPublicKeys"] == []

    cred = iam.create_service_specific_credential(UserName=name, ServiceName="codecommit.amazonaws.com")
    cred_id = cred["ServiceSpecificCredential"]["ServiceSpecificCredentialId"]
    iam.update_service_specific_credential(UserName=name, ServiceSpecificCredentialId=cred_id, Status="Inactive")
    creds = iam.list_service_specific_credentials(UserName=name)["ServiceSpecificCredentials"]
    assert [(c["ServiceSpecificCredentialId"], c["Status"]) for c in creds] == [(cred_id, "Inactive")]
    iam.delete_service_specific_credential(UserName=name, ServiceSpecificCredentialId=cred_id)
    assert iam.list_service_specific_credentials(UserName=name)["ServiceSpecificCredentials"] == []

    cert = _self_signed_pem()
    uploaded = iam.upload_signing_certificate(UserName=name, CertificateBody=cert)["Certificate"]
    cert_id = uploaded["CertificateId"]
    iam.update_signing_certificate(UserName=name, CertificateId=cert_id, Status="Inactive")
    certs = iam.list_signing_certificates(UserName=name)["Certificates"]
    assert [(c["CertificateId"], c["Status"]) for c in certs] == [(cert_id, "Inactive")]
    iam.delete_signing_certificate(UserName=name, CertificateId=cert_id)
    assert iam.list_signing_certificates(UserName=name)["Certificates"] == []


def _self_signed_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "signing")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_groups(iam):
    group, renamed, user = unique("grp"), unique("grp2"), unique("member")
    iam.create_group(GroupName=group)
    iam.create_user(UserName=user)
    iam.add_user_to_group(GroupName=group, UserName=user)
    got = iam.get_group(GroupName=group)
    assert [u["UserName"] for u in got["Users"]] == [user]
    assert got["Group"]["Arn"] == f"arn:aws:iam::{ACCOUNT}:group/{group}"

    iam.update_group(GroupName=group, NewGroupName=renamed, NewPath="/teams/")
    names = [g["GroupName"] for g in iam.list_groups(PathPrefix="/teams/")["Groups"]]
    assert names == [renamed]

    iam.put_group_policy(GroupName=renamed, PolicyName="g-inline", PolicyDocument=READ_S3)
    assert iam.list_group_policies(GroupName=renamed)["PolicyNames"] == ["g-inline"]
    assert iam.get_group_policy(GroupName=renamed, PolicyName="g-inline")["GroupName"] == renamed
    iam.delete_group_policy(GroupName=renamed, PolicyName="g-inline")
    assert iam.list_group_policies(GroupName=renamed)["PolicyNames"] == []

    arn = managed_policy(iam)
    iam.attach_group_policy(GroupName=renamed, PolicyArn=arn)
    assert [p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=renamed)["AttachedPolicies"]] == [arn]
    with pytest.raises(ClientError) as e:
        iam.delete_group(GroupName=renamed)
    assert code(e) == "DeleteConflict"
    iam.detach_group_policy(GroupName=renamed, PolicyArn=arn)
    with pytest.raises(ClientError) as e:
        iam.detach_group_policy(GroupName=renamed, PolicyArn=arn)
    assert code(e) == "NoSuchEntity"

    iam.remove_user_from_group(GroupName=renamed, UserName=user)
    assert iam.get_group(GroupName=renamed)["Users"] == []
    iam.delete_group(GroupName=renamed)


def test_roles(iam):
    name = unique("role")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST, Description="first")
    iam.update_role(RoleName=name, Description="second", MaxSessionDuration=7200)
    role = iam.get_role(RoleName=name)["Role"]
    assert (role["Description"], role["MaxSessionDuration"]) == ("second", 7200)
    updated = iam.update_role_description(RoleName=name, Description="third")["Role"]
    assert updated["Description"] == "third"

    trust = json.loads(TRUST)
    trust["Statement"][0]["Principal"] = {"Service": "lambda.amazonaws.com"}
    iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
    doc = iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]
    assert doc["Statement"][0]["Principal"] == {"Service": "lambda.amazonaws.com"}
    with pytest.raises(ClientError) as e:
        iam.update_assume_role_policy(RoleName=name, PolicyDocument="{not json")
    assert code(e) == "MalformedPolicyDocument"

    iam.put_role_policy(RoleName=name, PolicyName="r-inline", PolicyDocument=READ_S3)
    got = iam.get_role_policy(RoleName=name, PolicyName="r-inline")
    assert (got["RoleName"], got["PolicyName"]) == (name, "r-inline")

    arn = managed_policy(iam)
    iam.put_role_permissions_boundary(RoleName=name, PermissionsBoundary=arn)
    assert iam.get_role(RoleName=name)["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == arn
    iam.delete_role_permissions_boundary(RoleName=name)
    assert "PermissionsBoundary" not in iam.get_role(RoleName=name)["Role"]

    iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    iam.detach_role_policy(RoleName=name, PolicyArn=arn)
    assert iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"] == []

    iam.tag_role(RoleName=name, Tags=[{"Key": "owner", "Value": "ops"}, {"Key": "tmp", "Value": "1"}])
    iam.untag_role(RoleName=name, TagKeys=["tmp"])
    assert iam.list_role_tags(RoleName=name)["Tags"] == [{"Key": "owner", "Value": "ops"}]


def test_instance_profiles(iam):
    role, profile = unique("ip-role"), unique("profile")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)
    iam.create_instance_profile(InstanceProfileName=profile, Path="/ec2/")
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
    listed = iam.list_instance_profiles(PathPrefix="/ec2/")["InstanceProfiles"]
    assert [p["InstanceProfileName"] for p in listed] == [profile]
    for_role = iam.list_instance_profiles_for_role(RoleName=role)["InstanceProfiles"]
    assert [p["InstanceProfileName"] for p in for_role] == [profile]
    with pytest.raises(ClientError) as e:
        iam.delete_instance_profile(InstanceProfileName=profile)
    assert code(e) == "DeleteConflict"

    iam.tag_instance_profile(InstanceProfileName=profile, Tags=[{"Key": "k", "Value": "v"}, {"Key": "x", "Value": "y"}])
    iam.untag_instance_profile(InstanceProfileName=profile, TagKeys=["x"])
    assert iam.list_instance_profile_tags(InstanceProfileName=profile)["Tags"] == [{"Key": "k", "Value": "v"}]

    iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    assert iam.list_instance_profiles_for_role(RoleName=role)["InstanceProfiles"] == []
    iam.delete_instance_profile(InstanceProfileName=profile)
    with pytest.raises(ClientError) as e:
        iam.get_instance_profile(InstanceProfileName=profile)
    assert code(e) == "NoSuchEntity"


def test_managed_policies(iam):
    arn = managed_policy(iam)
    name = arn.rsplit("/", 1)[1]
    local = [p["Arn"] for p in iam.get_paginator("list_policies").paginate(Scope="Local").build_full_result()["Policies"]]
    assert arn in local
    aws = iam.list_policies(Scope="AWS", MaxItems=5)
    assert all(p["Arn"].startswith("arn:aws:iam::aws:policy/") for p in aws["Policies"])
    assert aws["IsTruncated"] is True

    v2 = iam.create_policy_version(PolicyArn=arn, PolicyDocument=LIST_S3, SetAsDefault=True)["PolicyVersion"]["VersionId"]
    assert iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"] == v2
    iam.set_default_policy_version(PolicyArn=arn, VersionId="v1")
    assert iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"] == "v1"
    with pytest.raises(ClientError) as e:
        iam.set_default_policy_version(PolicyArn=arn, VersionId="v9")
    assert code(e) == "NoSuchEntity"

    iam.tag_policy(PolicyArn=arn, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    iam.untag_policy(PolicyArn=arn, TagKeys=["a"])
    assert iam.list_policy_tags(PolicyArn=arn)["Tags"] == [{"Key": "b", "Value": "2"}]

    user, role, group = unique("pu"), unique("pr"), unique("pg")
    iam.create_user(UserName=user)
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)
    iam.create_group(GroupName=group)
    iam.attach_user_policy(UserName=user, PolicyArn=arn)
    iam.attach_role_policy(RoleName=role, PolicyArn=arn)
    iam.attach_group_policy(GroupName=group, PolicyArn=arn)
    entities = iam.list_entities_for_policy(PolicyArn=arn)
    assert [u["UserName"] for u in entities["PolicyUsers"]] == [user]
    assert [r["RoleName"] for r in entities["PolicyRoles"]] == [role]
    assert [g["GroupName"] for g in entities["PolicyGroups"]] == [group]
    only_roles = iam.list_entities_for_policy(PolicyArn=arn, EntityFilter="Role")
    assert only_roles["PolicyUsers"] == [] and len(only_roles["PolicyRoles"]) == 1
    assert iam.get_policy(PolicyArn=arn)["Policy"]["AttachmentCount"] == 3


def test_account_alias_properties_and_details(iam):
    alias = unique("alias")
    iam.create_account_alias(AccountAlias=alias)
    assert iam.list_account_aliases()["AccountAliases"] == [alias]
    iam.delete_account_alias(AccountAlias=alias)
    assert iam.list_account_aliases()["AccountAliases"] == []

    iam.put_account_properties(Properties={"Console/SessionTimeout": "3600"})
    props = iam.get_account_properties()["Properties"]
    assert props["Console/SessionTimeout"] == "3600"
    with pytest.raises(ClientError) as e:
        iam.put_account_properties(Properties={"A/x": "1", "B/y": "2"})
    assert code(e) == "InvalidInput"

    role = unique("details")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)
    iam.put_role_policy(RoleName=role, PolicyName="p", PolicyDocument=READ_S3)
    details = iam.get_paginator("get_account_authorization_details").paginate(Filter=["Role"]).build_full_result()
    assert details["UserDetailList"] == []
    mine = [r for r in details["RoleDetailList"] if r["RoleName"] == role][0]
    assert mine["RolePolicyList"][0]["PolicyName"] == "p"
    assert mine["AssumeRolePolicyDocument"]["Statement"][0]["Action"] == "sts:AssumeRole"

    # MaxItems pages through users, groups, roles and policies in turn.
    everything = iam.get_paginator("get_account_authorization_details").paginate().build_full_result()
    first = iam.get_account_authorization_details(MaxItems=1)
    assert first["IsTruncated"] is True
    assert sum(len(first[k]) for k in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")) == 1
    paged = iam.get_paginator("get_account_authorization_details").paginate(PaginationConfig={"PageSize": 2})
    paged = paged.build_full_result()
    for k in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
        assert len(paged[k]) == len(everything[k]), k


def test_policy_context_keys_and_custom_simulation(iam):
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1", "s3:prefix": "home/"}},
                }
            ],
        }
    )
    keys = iam.get_context_keys_for_custom_policy(PolicyInputList=[doc])["ContextKeyNames"]
    assert sorted(k.lower() for k in keys) == ["aws:requestedregion", "s3:prefix"]

    user = unique("ctx")
    iam.create_user(UserName=user)
    iam.put_user_policy(UserName=user, PolicyName="c", PolicyDocument=doc)
    principal_keys = iam.get_context_keys_for_principal_policy(PolicySourceArn=f"arn:aws:iam::{ACCOUNT}:user/{user}")
    assert sorted(k.lower() for k in principal_keys["ContextKeyNames"]) == ["aws:requestedregion", "s3:prefix"]

    def decide(region):
        out = iam.simulate_custom_policy(
            PolicyInputList=[doc],
            ActionNames=["s3:GetObject"],
            ContextEntries=[
                {"ContextKeyName": "aws:RequestedRegion", "ContextKeyValues": [region], "ContextKeyType": "string"},
                {"ContextKeyName": "s3:prefix", "ContextKeyValues": ["home/"], "ContextKeyType": "string"},
            ],
        )
        return out["EvaluationResults"][0]["EvalDecision"]

    assert decide("us-east-1") == "allowed"
    assert decide("eu-west-1") == "implicitDeny"


def test_federation_providers(iam):
    url = f"https://{unique('oidc')}.example.com"
    arn = iam.create_open_id_connect_provider(Url=url, ClientIDList=["app"], ThumbprintList=["a" * 40])[
        "OpenIDConnectProviderArn"
    ]
    assert arn in [p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]]
    iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID="cli")
    iam.remove_client_id_from_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID="app")
    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert got["ClientIDList"] == ["cli"]
    assert got["Url"] == url.removeprefix("https://")
    iam.tag_open_id_connect_provider(OpenIDConnectProviderArn=arn, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["a"])
    assert iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"] == [{"Key": "b", "Value": "2"}]
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    with pytest.raises(ClientError) as e:
        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert code(e) == "NoSuchEntity"

    def metadata(entity):
        return (
            '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'entityID="{entity}"><IDPSSODescriptor protocolSupportEnumeration='
            '"urn:oasis:names:tc:SAML:2.0:protocol"/>'
            # Metadata documents are at least 1000 characters.
            + "<!-- " + "padding " * 120 + "-->"
            + "</EntityDescriptor>"
        )

    name = unique("saml")
    saml_arn = iam.create_saml_provider(Name=name, SAMLMetadataDocument=metadata("https://idp-1"))["SAMLProviderArn"]
    iam.update_saml_provider(SAMLProviderArn=saml_arn, SAMLMetadataDocument=metadata("https://idp-2"))
    assert "https://idp-2" in iam.get_saml_provider(SAMLProviderArn=saml_arn)["SAMLMetadataDocument"]
    iam.tag_saml_provider(SAMLProviderArn=saml_arn, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    iam.untag_saml_provider(SAMLProviderArn=saml_arn, TagKeys=["b"])
    assert iam.list_saml_provider_tags(SAMLProviderArn=saml_arn)["Tags"] == [{"Key": "a", "Value": "1"}]
    iam.delete_saml_provider(SAMLProviderArn=saml_arn)
    with pytest.raises(ClientError) as e:
        iam.get_saml_provider(SAMLProviderArn=saml_arn)
    assert code(e) == "NoSuchEntity"


def test_server_certificate_and_mfa_tags(iam):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    name = unique("cert")
    iam.upload_server_certificate(
        ServerCertificateName=name,
        CertificateBody=cert.public_bytes(serialization.Encoding.PEM).decode(),
        PrivateKey=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        ).decode(),
    )
    iam.tag_server_certificate(ServerCertificateName=name, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    iam.untag_server_certificate(ServerCertificateName=name, TagKeys=["a"])
    assert iam.list_server_certificate_tags(ServerCertificateName=name)["Tags"] == [{"Key": "b", "Value": "2"}]

    user = unique("mfa-user")
    iam.create_user(UserName=user)
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=unique("mfa"))["VirtualMFADevice"]
    serial = device["SerialNumber"]
    iam.tag_mfa_device(SerialNumber=serial, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["b"])
    assert iam.list_mfa_device_tags(SerialNumber=serial)["Tags"] == [{"Key": "a", "Value": "1"}]

    import base64

    from test_iam_advanced import totp

    seed = base64.b32encode(base64.b32decode(device["Base32StringSeed"])).decode()
    iam.enable_mfa_device(
        UserName=user, SerialNumber=serial, AuthenticationCode1=totp(seed, -1), AuthenticationCode2=totp(seed)
    )
    got = iam.get_mfa_device(SerialNumber=serial)
    assert got["UserName"] == user and got["SerialNumber"] == serial
    iam.resync_mfa_device(
        UserName=user, SerialNumber=serial, AuthenticationCode1=totp(seed), AuthenticationCode2=totp(seed, 1)
    )
    with pytest.raises(ClientError) as e:
        iam.resync_mfa_device(UserName=user, SerialNumber=serial, AuthenticationCode1="000000", AuthenticationCode2="000000")
    assert code(e) == "InvalidAuthenticationCode"


def test_delegation_rejection_and_role_templates(iam):
    created = iam.create_delegation_request(
        Description="Partner wants read access",
        Permissions={"PolicyTemplateArn": "arn:aws:iam::aws:policy/IAMReadOnlyAccess"},
        RequestorWorkflowId="workflow-2",
        NotificationChannel="arn:aws:sns:us-east-1:111122223333:partner",
        SessionDuration=3600,
    )
    request_id = created["DelegationRequestId"]
    iam.reject_delegation_request(DelegationRequestId=request_id, Notes="not now")
    request = iam.get_delegation_request(DelegationRequestId=request_id)["DelegationRequest"]
    assert request["State"] == "REJECTED"
    with pytest.raises(ClientError) as e:
        iam.reject_delegation_request(DelegationRequestId=request_id)
    assert code(e) == "InvalidInput"

    template = "arn:aws:iam::aws:role-template/NoSuchTemplate"
    with pytest.raises(ClientError) as e:
        iam.acquire_role(TemplateArn=template)
    assert code(e) == "NoSuchEntity"
