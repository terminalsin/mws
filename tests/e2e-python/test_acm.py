"""AWS Certificate Manager through boto3, with certificates and exported keys
checked by `cryptography`, and a managed ACME endpoint driven by a small
RFC 8555 client."""

import base64
import json
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID


@pytest.fixture
def acm(endpoint, session_for):
    return session_for().client("acm", endpoint_url=endpoint)


@pytest.fixture
def r53(endpoint, session_for):
    return session_for().client("route53", endpoint_url=endpoint)


@pytest.fixture
def pca(endpoint, session_for):
    return session_for().client("acm-pca", endpoint_url=endpoint)


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def make_zone(r53, name):
    zone = r53.create_hosted_zone(Name=name, CallerReference=unique("ref"))["HostedZone"]
    return zone["Id"].split("/")[-1]


def upsert_cname(r53, zone_id, name, value, action="UPSERT"):
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {"Name": name, "Type": "CNAME", "TTL": 300, "ResourceRecords": [{"Value": value}]},
                }
            ]
        },
    )


def with_records(acm, arn):
    """The certificate once ACM has filled in its DNS validation records,
    which appear a moment after RequestCertificate (IaC tools poll too)."""
    for _ in range(100):
        cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        if all("ResourceRecord" in dv for dv in cert["DomainValidationOptions"]):
            return cert
        time.sleep(0.1)
    raise AssertionError(f"no validation records for {arn}")


def settled(acm, arn):
    """A private certificate once Private CA has issued it (or failed)."""
    for _ in range(100):
        cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        if cert["Status"] != "PENDING_VALIDATION":
            return cert
        time.sleep(0.1)
    raise AssertionError(f"{arn} is still pending")


def publish(acm, r53, zone_id, arn):
    cert = with_records(acm, arn)
    for dv in cert["DomainValidationOptions"]:
        rr = dv["ResourceRecord"]
        upsert_cname(r53, zone_id, rr["Name"], rr["Value"])


def code(err):
    return err.value.response["Error"]["Code"]


def test_dns_validation_with_waiter(acm, r53):
    domain = f"{unique('site')}.example.com"
    zone_id = make_zone(r53, domain)
    arn = acm.request_certificate(
        DomainName=domain,
        SubjectAlternativeNames=[f"www.{domain}"],
        ValidationMethod="DNS",
        Tags=[{"Key": "team", "Value": "web"}],
    )["CertificateArn"]
    with pytest.raises(ClientError) as e:
        acm.get_certificate(CertificateArn=arn)
    assert code(e) == "RequestInProgressException"
    publish(acm, r53, zone_id, arn)
    acm.get_waiter("certificate_validated").wait(CertificateArn=arn, WaiterConfig={"Delay": 1, "MaxAttempts": 3})

    cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert cert["Status"] == "ISSUED"
    assert cert["Issuer"] == "Amazon"
    assert cert["Type"] == "AMAZON_ISSUED"
    assert cert["KeyAlgorithm"] == "RSA-2048"
    assert (cert["NotAfter"] - cert["NotBefore"]).days == 198

    out = acm.get_certificate(CertificateArn=arn)
    leaf = x509.load_pem_x509_certificate(out["Certificate"].encode())
    chain = x509.load_pem_x509_certificates(out["CertificateChain"].encode())
    leaf.verify_directly_issued_by(chain[0])
    chain[0].verify_directly_issued_by(chain[1])
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert sans == [domain, f"www.{domain}"]

    summaries = acm.list_certificates(CertificateStatuses=["ISSUED"])["CertificateSummaryList"]
    assert arn in [s["CertificateArn"] for s in summaries]
    paginated = acm.get_paginator("list_certificates").paginate(PaginationConfig={"PageSize": 1})
    assert arn in [s["CertificateArn"] for page in paginated for s in page["CertificateSummaryList"]]

    found = acm.search_certificates(
        FilterStatement={
            "Filter": {"X509AttributeFilter": {"SubjectAlternativeName": {"DnsName": {"Value": f"www.{domain}", "ComparisonOperator": "EQUALS"}}}}
        }
    )["Results"]
    assert [r["CertificateArn"] for r in found] == [arn]
    assert found[0]["CertificateMetadata"]["AcmCertificateMetadata"]["ValidationMethod"] == "DNS"

    listed = acm.list_certificate_domain_validations(CertificateArn=arn)["DomainValidationSummaryList"]
    assert listed[0]["ActiveValidationConfiguration"]["ValidationStatus"] == "SUCCESS"

    acm.add_tags_to_certificate(CertificateArn=arn, Tags=[{"Key": "env", "Value": "prod"}])
    acm.remove_tags_from_certificate(CertificateArn=arn, Tags=[{"Key": "team"}])
    assert acm.list_tags_for_certificate(CertificateArn=arn)["Tags"] == [{"Key": "env", "Value": "prod"}]

    with pytest.raises(ClientError) as e:
        acm.update_certificate_options(CertificateArn=arn, Options={"CertificateTransparencyLoggingPreference": "DISABLED"})
    assert code(e) == "ValidationException"
    assert acm.describe_certificate(CertificateArn=arn)["Certificate"]["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED"

    acm.delete_certificate(CertificateArn=arn)
    with pytest.raises(ClientError) as e:
        acm.describe_certificate(CertificateArn=arn)
    assert code(e) == "ResourceNotFoundException"


def test_email_validation_approval_link(acm, endpoint):
    domain = f"{unique('mail')}.example.org"
    arn = acm.request_certificate(DomainName=domain, ValidationMethod="EMAIL")["CertificateArn"]
    dv = acm.describe_certificate(CertificateArn=arn)["Certificate"]["DomainValidationOptions"][0]
    assert f"hostmaster@{domain}" in dv["ValidationEmails"]
    acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain=domain)
    query = urllib.parse.urlencode({"certificate": arn, "domain": domain})
    with urllib.request.urlopen(f"{endpoint}/_acm/approvals?{query}") as resp:
        assert resp.status == 200
    assert acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"] == "ISSUED"
    with pytest.raises(ClientError) as e:
        acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain=domain)
    assert code(e) == "InvalidStateException"


def test_export_decrypts_with_the_passphrase(acm, r53):
    domain = f"{unique('exp')}.example.com"
    zone_id = make_zone(r53, domain)
    arn = acm.request_certificate(
        DomainName=domain, ValidationMethod="DNS", KeyAlgorithm="EC_secp384r1", Options={"Export": "ENABLED"}
    )["CertificateArn"]
    publish(acm, r53, zone_id, arn)
    out = acm.export_certificate(CertificateArn=arn, Passphrase=b"open sesame")
    key = serialization.load_pem_private_key(out["PrivateKey"].encode(), password=b"open sesame")
    cert = x509.load_pem_x509_certificate(out["Certificate"].encode())
    assert isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1"
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    with pytest.raises(ValueError):
        serialization.load_pem_private_key(out["PrivateKey"].encode(), password=b"wrong")
    assert acm.revoke_certificate(CertificateArn=arn, RevocationReason="SUPERSEDED")["CertificateArn"] == arn
    cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert cert["Status"] == "REVOKED" and cert["RevocationReason"] == "SUPERSEDED"


def make_ca(pca):
    arn = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": "ACM test root", "Organization": "Boto Corp"},
        },
        CertificateAuthorityType="ROOT",
    )["CertificateAuthorityArn"]
    pca.get_waiter("certificate_authority_csr_created").wait(
        CertificateAuthorityArn=arn, WaiterConfig={"Delay": 1, "MaxAttempts": 10}
    )
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.encode(),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 5, "Type": "YEARS"},
    )["CertificateArn"]
    pca.get_waiter("certificate_issued").wait(
        CertificateAuthorityArn=arn, CertificateArn=cert_arn, WaiterConfig={"Delay": 1, "MaxAttempts": 10}
    )
    pem = pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)["Certificate"]
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=pem.encode())
    return arn, x509.load_pem_x509_certificate(pem.encode())


def test_private_certificate_renewal(acm, pca):
    ca_arn, root = make_ca(pca)
    arn = acm.request_certificate(DomainName="db.corp.internal", CertificateAuthorityArn=ca_arn)["CertificateArn"]
    # Issued asynchronously: PENDING_VALIDATION first.
    with pytest.raises(ClientError) as e:
        acm.get_certificate(CertificateArn=arn)
    assert code(e) == "RequestInProgressException"
    cert = settled(acm, arn)
    assert cert["Type"] == "PRIVATE" and cert["Status"] == "ISSUED" and cert["Issuer"] == "Boto Corp"
    leaf = x509.load_pem_x509_certificate(acm.get_certificate(CertificateArn=arn)["Certificate"].encode())
    leaf.verify_directly_issued_by(root)
    pca.create_permission(
        CertificateAuthorityArn=ca_arn,
        Principal="acm.amazonaws.com",
        Actions=["IssueCertificate", "GetCertificate", "ListPermissions"],
    )
    acm.renew_certificate(CertificateArn=arn)
    renewed = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert renewed["RenewalSummary"]["RenewalStatus"] == "SUCCESS"
    assert renewed["Serial"] != cert["Serial"]
    out = acm.export_certificate(CertificateArn=arn, Passphrase=b"private!")
    key = serialization.load_pem_private_key(out["PrivateKey"].encode(), password=b"private!")
    assert key.public_key().public_numbers() == x509.load_pem_x509_certificate(out["Certificate"].encode()).public_key().public_numbers()


def self_signed(name):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    # A SEC1 ("EC PRIVATE KEY") key, as openssl writes them.
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def test_import_and_account_configuration(acm):
    cert, key = self_signed("legacy.example.com")
    arn = acm.import_certificate(Certificate=cert, PrivateKey=key, Tags=[{"Key": "k", "Value": "v"}])["CertificateArn"]
    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Type"] == "IMPORTED" and desc["DomainName"] == "legacy.example.com"
    assert "ImportedAt" in desc
    _, other_key = self_signed("other.example.com")
    with pytest.raises(ClientError) as e:
        acm.import_certificate(Certificate=cert, PrivateKey=other_key)
    assert code(e) == "ValidationException"
    cert2, key2 = self_signed("legacy.example.com")
    assert acm.import_certificate(CertificateArn=arn, Certificate=cert2, PrivateKey=key2)["CertificateArn"] == arn

    acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": 14}, IdempotencyToken=uuid.uuid4().hex)
    assert acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"] == 14


def test_validation_errors_match_the_model(acm):
    with pytest.raises(ClientError) as e:
        acm.request_certificate(DomainName="a" * 300 + ".com")
    assert code(e) == "ValidationException"
    with pytest.raises(ClientError) as e:
        acm.describe_certificate(CertificateArn="arn:aws:acm:us-east-1:123456789012:certificate/nope-nope-nope")
    assert code(e) == "ResourceNotFoundException"


# --- ACME ---


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def int_bytes(n, size):
    return n.to_bytes(size, "big")


class Acme:
    def __init__(self, directory_url):
        self.directory = json.load(urllib.request.urlopen(directory_url))
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = None

    def jwk(self):
        nums = self.key.public_key().public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": b64(int_bytes(nums.x, 32)), "y": b64(int_bytes(nums.y, 32))}

    def nonce(self):
        req = urllib.request.Request(self.directory["newNonce"], method="HEAD")
        return urllib.request.urlopen(req).headers["Replay-Nonce"]

    def post(self, url, payload):
        protected = {"alg": "ES256", "nonce": self.nonce(), "url": url}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk()
        p = b64(json.dumps(protected).encode())
        body = "" if payload is None else b64(json.dumps(payload).encode())
        r, s = decode_dss_signature(self.key.sign(f"{p}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        jws = {"protected": p, "payload": body, "signature": b64(int_bytes(r, 32) + int_bytes(s, 32))}
        req = urllib.request.Request(url, data=json.dumps(jws).encode(), headers={"Content-Type": "application/jose+json"})
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read()

    def register(self, kid, mac_key):
        url = self.directory["newAccount"]
        ep = b64(json.dumps({"alg": "HS256", "kid": kid, "url": url}).encode())
        pl = b64(json.dumps(self.jwk()).encode())
        h = hmac.HMAC(base64.urlsafe_b64decode(mac_key + "=" * (-len(mac_key) % 4)), hashes.SHA256())
        h.update(f"{ep}.{pl}".encode())
        eab = {"protected": ep, "payload": pl, "signature": b64(h.finalize())}
        status, headers, body = self.post(url, {"termsOfServiceAgreed": True, "externalAccountBinding": eab})
        if status in (200, 201):
            self.kid = headers["Location"]
        return status, json.loads(body)


def test_acme_endpoint_end_to_end(acm, r53, session_for, endpoint):
    iam = session_for().client("iam", endpoint_url=endpoint)
    role_name = unique("acme-role")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "acm.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="acme",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "acm:*", "Resource": "*"}]}),
    )
    domain = f"{unique('acme')}.example.com"
    zone_id = make_zone(r53, domain)

    ep_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Tags=[{"Key": "a", "Value": "b"}],
    )["AcmeEndpointArn"]
    ep = acm.describe_acme_endpoint(AcmeEndpointArn=ep_arn)["AcmeEndpoint"]
    assert ep["Status"] == "ACTIVE"
    assert ep_arn in [e["AcmeEndpointArn"] for e in acm.list_acme_endpoints()["AcmeEndpoints"]]
    acm.update_acme_endpoint(AcmeEndpointArn=ep_arn, Contact="REQUIRED")
    acm.update_acme_endpoint(AcmeEndpointArn=ep_arn, Contact="NOT_REQUIRED")
    acm.tag_resource(ResourceArn=ep_arn, Tags=[{"Key": "c", "Value": "d"}])
    acm.untag_resource(ResourceArn=ep_arn, TagKeys=["a"])
    assert acm.list_tags_for_resource(ResourceArn=ep_arn)["Tags"] == [{"Key": "c", "Value": "d"}]

    # Without a hosted zone, publish the record ourselves.
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=ep_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED", "Wildcards": "ENABLED"}}},
    )["AcmeDomainValidationArn"]
    dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert dv["Status"] == "VALIDATING"
    rr = dv["PrevalidationDetails"]["DnsPrevalidation"]["ResourceRecord"]
    upsert_cname(r53, zone_id, rr["Name"], rr["Value"])
    assert acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]["Status"] == "VALID"
    acm.update_acme_domain_validation(
        AcmeDomainValidationArn=dv_arn,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED", "Wildcards": "ENABLED"}}},
    )
    assert len(acm.list_acme_domain_validations(AcmeEndpointArn=ep_arn)["AcmeDomainValidations"]) == 1

    eab = acm.create_acme_external_account_binding(
        AcmeEndpointArn=ep_arn, RoleArn=role_arn, Expiration={"Value": 1, "Type": "DAYS"}
    )["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    assert "ExpiresAt" in acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)["ExternalAccountBinding"]
    assert len(acm.list_acme_external_account_bindings(AcmeEndpointArn=ep_arn)["ExternalAccountBindings"]) == 1
    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)

    client = Acme(ep["EndpointUrl"])
    status, account = client.register(creds["KeyId"], creds["MacKey"])
    assert status == 201, account
    status, headers, body = client.post(
        client.directory["newOrder"], {"identifiers": [{"type": "dns", "value": f"*.{domain}"}, {"type": "dns", "value": domain}]}
    )
    assert status == 201, body
    order = json.loads(body)
    authz = json.loads(client.post(order["authorizations"][0], None)[2])
    assert authz["wildcard"] is True and authz["identifier"]["value"] == domain

    cert_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName(f"*.{domain}")]), critical=False)
        .sign(cert_key, hashes.SHA256())
    )
    status, _, body = client.post(order["finalize"], {"csr": b64(csr.public_bytes(serialization.Encoding.DER))})
    assert status == 200, body
    order = json.loads(body)
    assert order["status"] == "valid"
    status, headers, pem = client.post(order["certificate"], None)
    certs = x509.load_pem_x509_certificates(pem)
    certs[0].verify_directly_issued_by(certs[1])
    assert certs[0].public_key().public_numbers() == cert_key.public_key().public_numbers()

    acme_certs = acm.list_certificates(
        CertificateKeyPairOrigins=["ACME"], Includes={"keyTypes": ["EC_prime256v1"]}
    )["CertificateSummaryList"]
    cert_arn = [c for c in acme_certs if c["DomainName"] == domain][0]["CertificateArn"]
    detail = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert detail["CertificateKeyPairOrigin"] == "ACME" and detail["AcmeEndpointArn"] == ep_arn

    accounts = acm.list_acme_accounts(AcmeEndpointArn=ep_arn)["AcmeAccounts"]
    assert [a["AccountUrl"] for a in accounts] == [client.kid]
    described = acm.describe_acme_account(AcmeEndpointArn=ep_arn, AccountUrl=client.kid)["AcmeAccount"]
    assert described["Status"] == "VALID"
    acm.revoke_acme_account(AcmeEndpointArn=ep_arn, AccountUrl=client.kid)
    with pytest.raises(ClientError) as e:
        acm.revoke_acme_account(AcmeEndpointArn=ep_arn, AccountUrl=client.kid)
    assert code(e) == "ConflictException"

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    acm.delete_acme_endpoint(AcmeEndpointArn=ep_arn)
    with pytest.raises(ClientError) as e:
        acm.describe_acme_endpoint(AcmeEndpointArn=ep_arn)
    assert code(e) == "ResourceNotFoundException"
