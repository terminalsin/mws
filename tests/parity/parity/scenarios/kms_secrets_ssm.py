import base64

from ..dsl import aws_error, aws_ok, scenario

KMS_DOC = "KMS API reference"


@scenario("kms", "symmetric key lifecycle")
def _(s):
    s.call("create_key", Description="parity", Tags=[{"TagKey": "team", "TagValue": "parity"}], save={"key": "KeyMetadata.KeyId", "arn": "KeyMetadata.Arn"})
    s.call("describe_key", KeyId="${key}")
    s.call("create_alias", AliasName="alias/${name}", TargetKeyId="${key}")
    s.call("describe_key", KeyId="alias/${name}")
    s.call("list_aliases", KeyId="${key}")
    s.call("encrypt", KeyId="alias/${name}", Plaintext=b"secret parity", save={"blob": "CiphertextBlob"})
    s.call("decrypt", CiphertextBlob="${blob}")
    s.call("generate_data_key", KeyId="${key}", KeySpec="AES_256", _ignore=["Plaintext", "CiphertextBlob"])
    s.call("generate_data_key_without_plaintext", KeyId="${key}", NumberOfBytes=32, _ignore=["CiphertextBlob"])
    s.call("generate_random", NumberOfBytes=16, _ignore=["Plaintext"])
    s.call("re_encrypt", CiphertextBlob="${blob}", DestinationKeyId="${key}", _ignore=["CiphertextBlob"])
    s.call("get_key_policy", KeyId="${key}", PolicyName="default")
    s.call("get_key_rotation_status", KeyId="${key}")
    s.call("enable_key_rotation", KeyId="${key}")
    s.call("get_key_rotation_status", KeyId="${key}")
    s.call("list_resource_tags", KeyId="${key}")
    s.call("disable_key", KeyId="${key}")
    s.call("encrypt", KeyId="${key}", Plaintext=b"x", expect=aws_error("DisabledException", source=KMS_DOC))
    s.call("enable_key", KeyId="${key}")
    s.call("decrypt", CiphertextBlob=b"garbage-ciphertext-garbage-ciphertext", expect=aws_error("InvalidCiphertextException", 400, source=KMS_DOC))
    s.call("describe_key", KeyId="alias/${name}-none", expect=aws_error("NotFoundException", source=KMS_DOC))
    s.call("describe_key", KeyId="11111111-2222-3333-4444-555555555555", expect=aws_error("NotFoundException", source=KMS_DOC))
    s.call("create_alias", AliasName="no-prefix", TargetKeyId="${key}")
    s.cleanup("delete_alias", AliasName="alias/${name}")
    s.call("schedule_key_deletion", KeyId="${key}", PendingWindowInDays=7)
    s.call("describe_key", KeyId="${key}")
    s.call("encrypt", KeyId="${key}", Plaintext=b"x", expect=aws_error("KMSInvalidStateException", source=KMS_DOC))
    s.call("schedule_key_deletion", KeyId="${key}", PendingWindowInDays=7, expect=aws_error("KMSInvalidStateException"))


@scenario("kms", "asymmetric and hmac keys")
def _(s):
    s.call("create_key", KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY", save={"key": "KeyMetadata.KeyId"})
    s.call("get_public_key", KeyId="${key}", _ignore=["PublicKey"])
    s.call("sign", KeyId="${key}", Message=b"parity", SigningAlgorithm="RSASSA_PSS_SHA_256", save={"sig": "Signature"}, _ignore=["Signature"])
    s.call("verify", KeyId="${key}", Message=b"parity", Signature="${sig}", SigningAlgorithm="RSASSA_PSS_SHA_256")
    s.call("encrypt", KeyId="${key}", Plaintext=b"x", expect=aws_error("InvalidKeyUsageException", 400, source=KMS_DOC))
    s.call("create_key", KeySpec="HMAC_256", KeyUsage="GENERATE_VERIFY_MAC", save={"hmac": "KeyMetadata.KeyId"})
    s.call("generate_mac", KeyId="${hmac}", Message=b"parity", MacAlgorithm="HMAC_SHA_256", save={"mac": "Mac"}, _ignore=["Mac"])
    s.call("verify_mac", KeyId="${hmac}", Message=b"parity", Mac="${mac}", MacAlgorithm="HMAC_SHA_256")
    s.cleanup("schedule_key_deletion", KeyId="${key}", PendingWindowInDays=7)
    s.cleanup("schedule_key_deletion", KeyId="${hmac}", PendingWindowInDays=7)


@scenario("secretsmanager", "secret lifecycle")
def _(s):
    sm = "Secrets Manager API reference"
    s.call("create_secret", Name="${name}", SecretString='{"user":"parity"}', Description="parity", save={"arn": "ARN", "v1": "VersionId"})
    s.call("describe_secret", SecretId="${name}")
    s.call("get_secret_value", SecretId="${name}")
    s.call("put_secret_value", SecretId="${name}", SecretString="second", save={"v2": "VersionId"})
    s.call("get_secret_value", SecretId="${arn}", VersionStage="AWSPREVIOUS")
    s.call("list_secret_version_ids", SecretId="${name}")
    s.call("update_secret", SecretId="${name}", Description="updated")
    s.call("tag_resource", SecretId="${name}", Tags=[{"Key": "team", "Value": "parity"}])
    s.call("untag_resource", SecretId="${name}", TagKeys=["team"])
    s.call("put_resource_policy", SecretId="${name}", ResourcePolicy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::${account}:root"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}')
    s.call("get_resource_policy", SecretId="${name}")
    s.call("delete_resource_policy", SecretId="${name}")
    s.call("create_secret", Name="${name}", SecretString="dup", expect=aws_error("ResourceExistsException", 400, source=sm))
    s.call("get_secret_value", SecretId="${name}-none", expect=aws_error("ResourceNotFoundException", 400, source=sm))
    s.call("get_random_password", PasswordLength=20, ExcludePunctuation=True, _ignore=["RandomPassword"])
    s.call("list_secrets", Filters=[{"Key": "name", "Values": ["${name}"]}])
    s.call("delete_secret", SecretId="${name}", RecoveryWindowInDays=7)
    s.call("get_secret_value", SecretId="${name}", expect=aws_error("InvalidRequestException", 400, source=sm))
    s.call("restore_secret", SecretId="${name}")
    s.cleanup("delete_secret", SecretId="${name}", ForceDeleteWithoutRecovery=True)


@scenario("secretsmanager", "binary secret")
def _(s):
    s.call("create_secret", Name="${name}", SecretBinary=base64.b64decode("AAECAwQ="))
    s.call("get_secret_value", SecretId="${name}")
    s.cleanup("delete_secret", SecretId="${name}", ForceDeleteWithoutRecovery=True)


@scenario("ssm", "parameter store")
def _(s):
    doc = "SSM API reference"
    s.call("put_parameter", Name="/${name}/plain", Value="v1", Type="String", Description="parity")
    s.call("put_parameter", Name="/${name}/plain", Value="v2", Type="String", Overwrite=True)
    s.call("put_parameter", Name="/${name}/plain", Value="v3", Type="String", expect=aws_error("ParameterAlreadyExists", 400, source=doc))
    s.call("put_parameter", Name="/${name}/list", Value="a,b,c", Type="StringList")
    s.call("put_parameter", Name="/${name}/secure", Value="hush", Type="SecureString")
    s.call("get_parameter", Name="/${name}/plain")
    s.call("get_parameter", Name="/${name}/secure", WithDecryption=True)
    s.call("get_parameter", Name="/${name}/secure")
    s.call("get_parameter", Name="/${name}/plain:1")
    s.call("get_parameters", Names=["/${name}/plain", "/${name}/missing"])
    s.call("get_parameters_by_path", Path="/${name}", Recursive=True)
    s.call("get_parameter_history", Name="/${name}/plain")
    s.call("describe_parameters", ParameterFilters=[{"Key": "Name", "Option": "BeginsWith", "Values": ["/${name}/"]}])
    s.call("label_parameter_version", Name="/${name}/plain", ParameterVersion=1, Labels=["prod"])
    s.call("get_parameter", Name="/${name}/plain:prod")
    s.call("add_tags_to_resource", ResourceType="Parameter", ResourceId="/${name}/plain", Tags=[{"Key": "team", "Value": "parity"}])
    s.call("list_tags_for_resource", ResourceType="Parameter", ResourceId="/${name}/plain")
    s.call("get_parameter", Name="/${name}/missing", expect=aws_error("ParameterNotFound", source=doc))
    s.call("put_parameter", Name="/${name}/bad", Value="x", Type="Nope", _raw=True, expect=aws_error("ValidationException", 400))
    s.call("delete_parameters", Names=["/${name}/plain", "/${name}/list", "/${name}/secure", "/${name}/missing"])
    s.call("delete_parameter", Name="/${name}/plain", expect=aws_error("ParameterNotFound", source=doc))


@scenario("ssm", "public parameters")
def _(s):
    s.call("get_parameter", Name="/aws/service/global-infrastructure/regions/us-east-1/longName", expect=aws_ok({"Parameter.Value": "US East (N. Virginia)"}))
    s.call("get_parameters_by_path", Path="/aws/service/global-infrastructure/regions/us-west-2", _shape_only=True)
