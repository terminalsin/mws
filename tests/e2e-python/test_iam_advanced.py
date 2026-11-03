"""Newer IAM features and the STS calls that use them, through boto3."""

import base64
import hashlib
import hmac
import json
import struct
import time
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def totp(seed_b32, offset=0):
    key = base64.b32decode(seed_b32)
    step = int(time.time()) // 30 + offset
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[19] & 0xF
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def test_virtual_mfa_and_session_token(iam, endpoint, session_for):
    user = unique("mfa")
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=unique("dev"))["VirtualMFADevice"]
    seed = device["Base32StringSeed"].decode()
    serial = device["SerialNumber"]
    iam.enable_mfa_device(
        UserName=user, SerialNumber=serial, AuthenticationCode1=totp(seed, -2), AuthenticationCode2=totp(seed, -1)
    )
    assert iam.list_mfa_devices(UserName=user)["MFADevices"][0]["SerialNumber"] == serial

    sts = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("sts", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        sts.get_session_token(SerialNumber=serial, TokenCode="000000")
    assert e.value.response["Error"]["Code"] == "AccessDenied"
    creds = sts.get_session_token(SerialNumber=serial, TokenCode=totp(seed))["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA")


def test_password_policy_and_credential_report(iam):
    iam.update_account_password_policy(MinimumPasswordLength=14, RequireNumbers=True)
    try:
        user = unique("pw")
        iam.create_user(UserName=user)
        with pytest.raises(ClientError) as e:
            iam.create_login_profile(UserName=user, Password="tooshort1")
        assert e.value.response["Error"]["Code"] == "PasswordPolicyViolation"
        iam.create_login_profile(UserName=user, Password="long-enough-password-1")
        assert iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"] == 14
    finally:
        iam.delete_account_password_policy()

    iam.generate_credential_report()
    report = iam.get_credential_report()
    assert report["ReportFormat"] == "text/csv"
    rows = report["Content"].decode().splitlines()
    assert any(r.startswith(f"{user},arn:aws:iam::{ACCOUNT}:user/{user},") for r in rows)


def test_saml_provider_and_assume_role_with_saml(iam, endpoint, session_for):
    issuer = f"https://{unique('idp')}.example.test"
    metadata = (
        f'<?xml version="1.0"?><!-- {"x" * 1000} --><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{issuer}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>'
        "</md:EntityDescriptor>"
    )
    provider = iam.create_saml_provider(Name=unique("corp"), SAMLMetadataDocument=metadata)["SAMLProviderArn"]
    role = unique("sso")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider}, "Action": "sts:AssumeRoleWithSAML"}]}
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    assertion = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        f"<saml:Assertion><saml:Issuer>{issuer}</saml:Issuer>"
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">bob</saml:NameID></saml:Subject>'
        "<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://signin.aws.amazon.com/saml</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement>"
        f'<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>{provider},{role_arn}</saml:AttributeValue></saml:Attribute>'
        '<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>bob</saml:AttributeValue></saml:Attribute>'
        "</saml:AttributeStatement></saml:Assertion></samlp:Response>"
    )
    sts = session_for().client("sts", endpoint_url=endpoint)
    out = sts.assume_role_with_saml(
        RoleArn=role_arn, PrincipalArn=provider, SAMLAssertion=base64.b64encode(assertion.encode()).decode()
    )
    assert out["AssumedRoleUser"]["Arn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/bob"
    assert out["SubjectType"] == "transient"
    assert out["Issuer"] == issuer


def test_server_certificate_errors(iam):
    with pytest.raises(ClientError) as e:
        iam.upload_server_certificate(ServerCertificateName=unique("c"), CertificateBody="nope", PrivateKey="nope")
    assert e.value.response["Error"]["Code"] == "MalformedCertificate"
    with pytest.raises(ClientError) as e:
        iam.get_server_certificate(ServerCertificateName=unique("missing"))
    assert e.value.response["Error"]["Code"] == "NoSuchEntity"


def test_simulator_policy_exclusions(iam):
    user = unique("sim")
    iam.create_user(UserName=user)
    allow = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:List*", "Resource": "*"}]})
    iam.put_user_policy(UserName=user, PolicyName="lists", PolicyDocument=allow)
    arn = f"arn:aws:iam::{ACCOUNT}:user/{user}"

    def decide(**kwargs):
        out = iam.simulate_principal_policy(PolicySourceArn=arn, ActionNames=["iam:ListRoles"], **kwargs)
        return out["EvaluationResults"][0]["EvalDecision"]

    assert decide() == "allowed"
    inline = {"InlinePolicyIdentifier": {"PolicyName": "lists", "AttachmentType": "user", "AttachmentName": user}}
    assert decide(PolicyExclusionList=[inline]) == "implicitDeny"
    assert decide(PolicyExclusionList=[{"PolicyType": "inline"}]) == "implicitDeny"
    assert decide(PolicyExclusionList=[{"PolicyType": "aws-managed"}]) == "allowed"
    with pytest.raises(ClientError) as e:
        decide(PolicyExclusionList=[{"PolicyArn": "arn:aws:s3:::not-a-policy"}])
    assert e.value.response["Error"]["Code"] == "InvalidInput"
