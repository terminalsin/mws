"""KMS through boto3, with public-key results checked by `cryptography`."""

import json

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding


@pytest.fixture
def kms(endpoint, session_for):
    return session_for().client("kms", endpoint_url=endpoint)


def error_code(excinfo):
    return excinfo.value.response["Error"]["Code"]


def test_encrypt_decrypt_with_context(kms):
    key = kms.create_key(Description="boto")["KeyMetadata"]
    assert key["KeyState"] == "Enabled"
    assert key["KeyManager"] == "CUSTOMER"
    blob = kms.encrypt(KeyId=key["KeyId"], Plaintext=b"hello", EncryptionContext={"app": "x"})["CiphertextBlob"]
    out = kms.decrypt(CiphertextBlob=blob, EncryptionContext={"app": "x"})
    assert out["Plaintext"] == b"hello"
    assert out["KeyId"] == key["Arn"]
    with pytest.raises(ClientError) as e:
        kms.decrypt(CiphertextBlob=blob, EncryptionContext={"app": "y"})
    assert error_code(e) == "InvalidCiphertextException"


def test_not_found_and_aliases(kms):
    with pytest.raises(kms.exceptions.NotFoundException):
        kms.describe_key(KeyId="alias/nope")
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/boto", TargetKeyId=key_id)
    with pytest.raises(kms.exceptions.AlreadyExistsException):
        kms.create_alias(AliasName="alias/boto", TargetKeyId=key_id)
    assert kms.describe_key(KeyId="alias/boto")["KeyMetadata"]["KeyId"] == key_id
    names = [a["AliasName"] for a in kms.list_aliases()["Aliases"]]
    assert "alias/boto" in names
    paginator = kms.get_paginator("list_keys")
    ids = [k["KeyId"] for page in paginator.paginate(PaginationConfig={"PageSize": 1}) for k in page["Keys"]]
    assert key_id in ids


def test_ecdsa_signature_verifies_with_cryptography(kms):
    key_id = kms.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    der = kms.get_public_key(KeyId=key_id)["PublicKey"]
    public = serialization.load_der_public_key(der)
    assert isinstance(public.curve, ec.SECP384R1)
    sig = kms.sign(KeyId=key_id, Message=b"data", SigningAlgorithm="ECDSA_SHA_384")["Signature"]
    public.verify(sig, b"data", ec.ECDSA(hashes.SHA384()))
    assert kms.verify(KeyId=key_id, Message=b"data", Signature=sig, SigningAlgorithm="ECDSA_SHA_384")[
        "SignatureValid"
    ]
    with pytest.raises(kms.exceptions.KMSInvalidSignatureException):
        kms.verify(KeyId=key_id, Message=b"other", Signature=sig, SigningAlgorithm="ECDSA_SHA_384")


def test_rsa_encryption_from_outside(kms):
    key_id = kms.create_key(KeySpec="RSA_2048", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]["KeyId"]
    public = serialization.load_der_public_key(kms.get_public_key(KeyId=key_id)["PublicKey"])
    ct = public.encrypt(
        b"wrapped",
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    out = kms.decrypt(KeyId=key_id, CiphertextBlob=ct, EncryptionAlgorithm="RSAES_OAEP_SHA_256")
    assert out["Plaintext"] == b"wrapped"


def test_key_policy_is_enforced_for_users(kms, iam, endpoint, session_for):
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    iam.create_user(UserName="kmsuser")
    creds = iam.create_access_key(UserName="kmsuser")["AccessKey"]
    user = session_for(creds["AccessKeyId"], creds["SecretAccessKey"]).client("kms", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        user.encrypt(KeyId=key_id, Plaintext=b"x")
    assert error_code(e) == "AccessDeniedException"

    policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:user/kmsuser"},
            "Action": ["kms:Encrypt", "kms:Decrypt"],
            "Resource": "*",
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    blob = user.encrypt(KeyId=key_id, Plaintext=b"x")["CiphertextBlob"]
    assert user.decrypt(CiphertextBlob=blob)["Plaintext"] == b"x"


def test_hmac_and_data_key_pairs(kms):
    mac_key = kms.create_key(KeySpec="HMAC_512", KeyUsage="GENERATE_VERIFY_MAC")["KeyMetadata"]["KeyId"]
    mac = kms.generate_mac(KeyId=mac_key, Message=b"m", MacAlgorithm="HMAC_SHA_512")["Mac"]
    assert len(mac) == 64
    assert kms.verify_mac(KeyId=mac_key, Message=b"m", Mac=mac, MacAlgorithm="HMAC_SHA_512")["MacValid"]

    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    pair = kms.generate_data_key_pair(KeyId=key_id, KeyPairSpec="RSA_2048")
    private = serialization.load_der_private_key(pair["PrivateKeyPlaintext"], password=None)
    assert private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == pair["PublicKey"]
    assert kms.decrypt(CiphertextBlob=pair["PrivateKeyCiphertextBlob"])["Plaintext"] == pair["PrivateKeyPlaintext"]


def test_rotation_and_deletion(kms):
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)
    status = kms.get_key_rotation_status(KeyId=key_id)
    assert status["KeyRotationEnabled"] and status["RotationPeriodInDays"] == 365
    kms.rotate_key_on_demand(KeyId=key_id)
    assert len(kms.list_key_rotations(KeyId=key_id)["Rotations"]) == 1
    out = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert out["KeyState"] == "PendingDeletion"
    with pytest.raises(kms.exceptions.KMSInvalidStateException):
        kms.encrypt(KeyId=key_id, Plaintext=b"x")
