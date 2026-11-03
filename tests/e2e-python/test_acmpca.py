"""AWS Private CA through boto3, with certificates checked by `cryptography`."""

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


def serialization_pem():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.PEM
