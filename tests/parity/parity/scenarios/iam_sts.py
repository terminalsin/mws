import json

from ..dsl import aws_error, scenario

IAM_DOC = "IAM API reference / error codes"

TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)
TRUST_ACCOUNT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::${account}:root"}, "Action": "sts:AssumeRole"}],
    }
)
POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
)


@scenario("iam", "users, groups and access keys")
def _(s):
    s.call("create_user", UserName="${name}-u", Path="/parity/", Tags=[{"Key": "team", "Value": "parity"}])
    s.call("get_user", UserName="${name}-u")
    s.call("create_user", UserName="${name}-u", expect=aws_error("EntityAlreadyExists", 409, source=IAM_DOC))
    s.call("list_users", PathPrefix="/parity/", _shape_only=True)
    s.call("tag_user", UserName="${name}-u", Tags=[{"Key": "env", "Value": "test"}])
    s.call("list_user_tags", UserName="${name}-u")
    s.call("create_group", GroupName="${name}-g")
    s.call("add_user_to_group", GroupName="${name}-g", UserName="${name}-u")
    s.call("get_group", GroupName="${name}-g")
    s.call("list_groups_for_user", UserName="${name}-u")
    s.call("create_access_key", UserName="${name}-u", save={"akid": "AccessKey.AccessKeyId"})
    s.call("list_access_keys", UserName="${name}-u")
    s.call("update_access_key", UserName="${name}-u", AccessKeyId="${akid}", Status="Inactive")
    s.call("get_access_key_last_used", AccessKeyId="${akid}")
    s.call("create_login_profile", UserName="${name}-u", Password="Parity-Passw0rd!x", PasswordResetRequired=True)
    s.call("get_login_profile", UserName="${name}-u")
    s.call("put_user_policy", UserName="${name}-u", PolicyName="inline", PolicyDocument=POLICY)
    s.call("get_user_policy", UserName="${name}-u", PolicyName="inline")
    s.call("list_user_policies", UserName="${name}-u")
    s.call("get_user", UserName="${name}-nobody", expect=aws_error("NoSuchEntity", 404, source=IAM_DOC))
    s.call("delete_user", UserName="${name}-u", expect=aws_error("DeleteConflict", 409, source=IAM_DOC))
    s.cleanup("delete_user_policy", UserName="${name}-u", PolicyName="inline")
    s.cleanup("delete_login_profile", UserName="${name}-u")
    s.cleanup("delete_access_key", UserName="${name}-u", AccessKeyId="${akid}")
    s.cleanup("remove_user_from_group", GroupName="${name}-g", UserName="${name}-u")
    s.cleanup("delete_group", GroupName="${name}-g")
    s.cleanup("delete_user", UserName="${name}-u")


@scenario("iam", "roles and managed policies")
def _(s):
    s.call("create_role", RoleName="${name}-r", AssumeRolePolicyDocument=TRUST, Description="parity", MaxSessionDuration=7200)
    s.call("get_role", RoleName="${name}-r")
    s.call("update_role", RoleName="${name}-r", Description="parity updated")
    s.call("create_policy", PolicyName="${name}-p", PolicyDocument=POLICY, save={"parn": "Policy.Arn"})
    s.call("get_policy", PolicyArn="${parn}")
    s.call("create_policy_version", PolicyArn="${parn}", PolicyDocument=POLICY, SetAsDefault=True)
    s.call("list_policy_versions", PolicyArn="${parn}")
    s.call("get_policy_version", PolicyArn="${parn}", VersionId="v2")
    s.call("attach_role_policy", RoleName="${name}-r", PolicyArn="${parn}")
    s.call("list_attached_role_policies", RoleName="${name}-r")
    s.call("list_entities_for_policy", PolicyArn="${parn}")
    s.call("create_instance_profile", InstanceProfileName="${name}-ip")
    s.call("add_role_to_instance_profile", InstanceProfileName="${name}-ip", RoleName="${name}-r")
    s.call("get_instance_profile", InstanceProfileName="${name}-ip")
    s.call("list_instance_profiles_for_role", RoleName="${name}-r")
    s.call(
        "create_policy",
        PolicyName="${name}-bad",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Maybe"}]}',
        expect=aws_error("MalformedPolicyDocument", 400, source=IAM_DOC),
    )
    s.call("get_role", RoleName="${name}-none", expect=aws_error("NoSuchEntity", 404, source=IAM_DOC))
    s.call("delete_policy", PolicyArn="${parn}", expect=aws_error("DeleteConflict", 409, source=IAM_DOC))
    s.call("get_policy", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess", _note="AWS managed policy")
    s.cleanup("remove_role_from_instance_profile", InstanceProfileName="${name}-ip", RoleName="${name}-r")
    s.cleanup("delete_instance_profile", InstanceProfileName="${name}-ip")
    s.cleanup("detach_role_policy", RoleName="${name}-r", PolicyArn="${parn}")
    s.cleanup("delete_policy_version", PolicyArn="${parn}", VersionId="v1")
    s.cleanup("delete_policy", PolicyArn="${parn}")
    s.cleanup("delete_role", RoleName="${name}-r")


@scenario("iam", "account settings")
def _(s):
    s.call("get_account_summary", _shape_only=True)
    s.call("update_account_password_policy", MinimumPasswordLength=12, RequireSymbols=True)
    s.call("get_account_password_policy")
    s.call("delete_account_password_policy")
    s.call("get_account_password_policy", expect=aws_error("NoSuchEntity", 404, source=IAM_DOC))
    s.call("list_account_aliases", _shape_only=True)


@scenario("sts", "caller identity and assume role", needs=("iam",))
def _(s):
    s.call("get_caller_identity")
    s.call("create_role", service="iam", RoleName="${name}-assume", AssumeRolePolicyDocument=TRUST_ACCOUNT, save={"rarn": "Role.Arn"})
    s.call(
        "assume_role",
        RoleArn="${rarn}",
        RoleSessionName="parity",
        DurationSeconds=900,
        _until="Credentials",
        _wait=15,
        _note="IAM is eventually consistent on AWS; retried briefly",
    )
    s.call("assume_role", RoleArn="${rarn}", RoleSessionName="parity", DurationSeconds=60, _raw=True, expect=aws_error("ValidationError", 400))
    s.call("assume_role", RoleArn="${rarn}", RoleSessionName="bad name!", expect=aws_error("ValidationError", 400))
    s.call("get_session_token", DurationSeconds=900)
    s.call("get_access_key_info", AccessKeyId="AKIAIOSFODNN7EXAMPLE")
    s.call(
        "decode_authorization_message",
        EncodedMessage="not-a-message",
        expect=aws_error("InvalidAuthorizationMessageException", 400),
    )
    s.cleanup("delete_role", service="iam", RoleName="${name}-assume")
