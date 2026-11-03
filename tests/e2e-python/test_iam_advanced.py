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


def _saml_signer():
    """An RSA key and self-signed certificate for a test SAML identity provider."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _sign_response(key, inner):
    """A SAML Response signed as a whole (enveloped, exclusive c14n). The
    XML is written in canonical form, so its digest is that of the text."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    ds = "http://www.w3.org/2000/09/xmldsig#"
    open_tag = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" Version="2.0">'
    canonical = f"{open_tag}{inner}</samlp:Response>"
    digest = base64.b64encode(hashlib.sha256(canonical.encode()).digest()).decode()
    signed_info = (
        f'<ds:SignedInfo xmlns:ds="{ds}">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>'
        '<ds:Reference URI="#_resp1"><ds:Transforms>'
        f'<ds:Transform Algorithm="{ds}enveloped-signature"></ds:Transform>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>'
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>'
        f"<ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    )
    sig = base64.b64encode(key.sign(signed_info.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
    signature = f'<ds:Signature xmlns:ds="{ds}">{signed_info}<ds:SignatureValue>{sig}</ds:SignatureValue></ds:Signature>'
    return f"{open_tag}{signature}{inner}</samlp:Response>"


def test_saml_provider_and_assume_role_with_saml(iam, endpoint, session_for):
    issuer = f"https://{unique('idp')}.example.test"
    key, cert = _saml_signer()
    metadata = (
        f'<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{issuer}">'
        '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f"<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>"
    )
    provider = iam.create_saml_provider(Name=unique("corp"), SAMLMetadataDocument=metadata)["SAMLProviderArn"]
    role = unique("sso")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider}, "Action": "sts:AssumeRoleWithSAML"}]}
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]

    def assertion(session):
        return (
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0">'
            f"<saml:Issuer>{issuer}</saml:Issuer>"
            '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">bob</saml:NameID></saml:Subject>'
            "<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://signin.aws.amazon.com/saml</saml:Audience>"
            "</saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement>"
            f'<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>{provider},{role_arn}</saml:AttributeValue></saml:Attribute>'
            f'<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>{session}</saml:AttributeValue></saml:Attribute>'
            "</saml:AttributeStatement></saml:Assertion>"
        )

    sts = session_for().client("sts", endpoint_url=endpoint)

    def assume(xml):
        return sts.assume_role_with_saml(
            RoleArn=role_arn, PrincipalArn=provider, SAMLAssertion=base64.b64encode(xml.encode()).decode()
        )

    out = assume(_sign_response(key, assertion("bob")))
    assert out["AssumedRoleUser"]["Arn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/bob"
    assert out["SubjectType"] == "transient"
    assert out["Issuer"] == issuer

    # Swapping the assertion under a valid signature is caught.
    signed = _sign_response(key, assertion("bob"))
    with pytest.raises(ClientError) as e:
        assume(signed.replace(">bob</saml:AttributeValue>", ">eve</saml:AttributeValue>"))
    assert e.value.response["Error"]["Code"] == "InvalidIdentityToken"
    assert e.value.response["Error"]["Message"] == "Response signature invalid"
    # An unsigned response is refused too.
    with pytest.raises(ClientError) as e:
        assume(f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">{assertion("bob")}</samlp:Response>')
    assert e.value.response["Error"]["Message"] == "Response signature invalid"


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
