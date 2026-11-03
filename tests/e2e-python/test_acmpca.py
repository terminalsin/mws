"""AWS Private CA through boto3, with certificates checked by `cryptography`."""

import json

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture
def pca(endpoint, session_for):
    return session_for().client("acm-pca", endpoint_url=endpoint)


def make_root(pca):
    arn = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "EC_prime256v1",
            "SigningAlgorithm": "SHA256WITHECDSA",
            "Subject": {"CommonName": "boto root", "Organization": "MWS"},
        },
        CertificateAuthorityType="ROOT",
    )["CertificateAuthorityArn"]
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.encode(),
        SigningAlgorithm="SHA256WITHECDSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    pca.get_waiter("certificate_issued").wait(
        CertificateAuthorityArn=arn, CertificateArn=cert_arn, WaiterConfig={"Delay": 1, "MaxAttempts": 3}
    )
    pem = pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)["Certificate"]
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=pem.encode())
    return arn, x509.load_pem_x509_certificate(pem.encode())


def test_issue_and_verify(pca):
    arn, root = make_root(pca)
    ca = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]
    assert ca["Status"] == "ACTIVE"

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.internal")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.internal")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.public_bytes(serialization_pem()),
        SigningAlgorithm="SHA256WITHECDSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    out = pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)
    leaf = x509.load_pem_x509_certificate(out["Certificate"].encode())
    leaf.verify_directly_issued_by(root)
    assert leaf.subject == csr.subject
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["api.internal"]
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_errors(pca):
    with pytest.raises(ClientError) as e:
        pca.describe_certificate_authority(
            CertificateAuthorityArn="arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/00000000-0000-0000-0000-000000000000"
        )
    assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"
    with pytest.raises(ClientError) as e:
        pca.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "RSA_2048",
                "SigningAlgorithm": "NOPE",
                "Subject": {"CommonName": "x"},
            },
            CertificateAuthorityType="ROOT",
        )
    err = e.value.response["Error"]
    assert err["Code"] == "ValidationException"
    assert "Member must satisfy enum value set" in err["Message"]


def _http(url, data=None, content_type=None):
    import urllib.request

    req = urllib.request.Request(url, data=data, headers={"Content-Type": content_type} if content_type else {})
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def pca_bucket(s3, name):
    """A bucket whose policy lets ACM PCA write to it."""
    s3.create_bucket(Bucket=name)
    s3.put_bucket_policy(
        Bucket=name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "acm-pca.amazonaws.com"},
                        "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:GetBucketLocation"],
                        "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
                    }
                ],
            }
        ),
    )


def test_crl_ocsp_and_audit_report(pca, endpoint, session_for):
    from cryptography.x509 import ocsp

    s3 = session_for().client("s3", endpoint_url=endpoint)
    arn, root = make_root(pca)
    ca_id = arn.rsplit("/", 1)[1]
    revocation = {
        "CrlConfiguration": {
            "Enabled": True,
            "S3BucketName": "pca-boto-crls",
            "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
            "CustomCname": "crl.example.internal",
        },
        "OcspConfiguration": {"Enabled": True, "OcspCustomCname": "ocsp.example.internal"},
    }
    with pytest.raises(ClientError) as err:
        pca.update_certificate_authority(CertificateAuthorityArn=arn, RevocationConfiguration=revocation)
    assert err.value.response["Error"]["Code"] == "InvalidArgsException"
    pca_bucket(s3, "pca-boto-crls")
    pca.update_certificate_authority(CertificateAuthorityArn=arn, RevocationConfiguration=revocation)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.internal")]))
        .sign(key, hashes.SHA256())
    )
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.public_bytes(serialization_pem()),
        SigningAlgorithm="SHA256WITHECDSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    leaf = x509.load_pem_x509_certificate(
        pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)["Certificate"].encode()
    )
    cdp = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name[0].value == f"http://crl.example.internal/crl/{ca_id}.crl"
    aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    assert aia[0].access_location.value == "http://ocsp.example.internal"

    def ask_ocsp():
        req = ocsp.OCSPRequestBuilder().add_certificate(leaf, root, hashes.SHA1()).add_extension(
            x509.OCSPNonce(b"boto-nonce"), critical=False
        ).build()
        der = _http(endpoint + "/", req.public_bytes(serialization_der()), "application/ocsp-request")
        resp = ocsp.load_der_ocsp_response(der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        root.public_key().verify(resp.signature, resp.tbs_response_bytes, ec.ECDSA(hashes.SHA256()))
        assert resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce == b"boto-nonce"
        return resp

    assert ask_ocsp().certificate_status == ocsp.OCSPCertStatus.GOOD
    pca.revoke_certificate(
        CertificateAuthorityArn=arn, CertificateSerial=f"{leaf.serial_number:x}", RevocationReason="SUPERSEDED"
    )
    resp = ask_ocsp()
    assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert resp.revocation_reason == x509.ReasonFlags.superseded

    crl_object = s3.get_object(Bucket="pca-boto-crls", Key=f"crl/{ca_id}.crl")
    assert crl_object["ContentType"] == "application/pkix-crl"
    crl = x509.load_der_x509_crl(crl_object["Body"].read())
    assert crl.is_signature_valid(root.public_key())
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None

    pca_bucket(s3, "pca-boto-audits")
    report = pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=arn, S3BucketName="pca-boto-audits", AuditReportResponseFormat="CSV"
    )
    pca.get_waiter("audit_report_created").wait(
        CertificateAuthorityArn=arn, AuditReportId=report["AuditReportId"], WaiterConfig={"Delay": 1, "MaxAttempts": 3}
    )
    csv = s3.get_object(Bucket="pca-boto-audits", Key=report["S3Key"])["Body"].read().decode()
    header, *rows = csv.strip().splitlines()
    assert header.split(",")[:3] == ["awsAccountId", "certificateArn", "serial"]
    assert any(cert_arn in r and "SUPERSEDED" in r for r in rows)


def serialization_der():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def serialization_pem():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.PEM
