"""Services LocalStack offers only in its paid tiers (or not at all).

They run when your LocalStack edition offers them and are reported as
skipped otherwise. They stick to cheap resources: nothing here starts a
database, cache cluster, Kubernetes control plane or EC2 instance.
"""

import json

from ..dsl import aws_error, scenario


@scenario("acm-pca", "root certificate authority")
def _(s):
    s.call(
        "create_certificate_authority",
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": "${name}.example.com", "Organization": "Parity"},
        },
        IdempotencyToken="${alnum}",
        save={"ca": "CertificateAuthorityArn"},
    )
    s.call("describe_certificate_authority", CertificateAuthorityArn="${ca}", _until="CertificateAuthority.Status == 'PENDING_CERTIFICATE'", _wait=30)
    s.call("get_certificate_authority_csr", CertificateAuthorityArn="${ca}", _ignore=["Csr"])
    s.call("list_tags", CertificateAuthorityArn="${ca}")
    s.call("tag_certificate_authority", CertificateAuthorityArn="${ca}", Tags=[{"Key": "team", "Value": "parity"}])
    s.call("get_certificate_authority_certificate", CertificateAuthorityArn="${ca}", expect=aws_error("InvalidStateException", 400))
    s.call(
        "describe_certificate_authority",
        CertificateAuthorityArn="arn:aws:acm-pca:${region}:${account}:certificate-authority/00000000-0000-0000-0000-000000000000",
        expect=aws_error("ResourceNotFoundException", 400),
    )
    s.cleanup("delete_certificate_authority", CertificateAuthorityArn="${ca}", PermanentDeletionTimeInDays=7)


@scenario("ecr", "repositories")
def _(s):
    s.call("create_repository", repositoryName="${name}", imageTagMutability="IMMUTABLE", save={"arn": "repository.repositoryArn"})
    s.call("describe_repositories", repositoryNames=["${name}"])
    s.call("create_repository", repositoryName="${name}", expect=aws_error("RepositoryAlreadyExistsException", 400))
    s.call("put_lifecycle_policy", repositoryName="${name}", lifecyclePolicyText=json.dumps({"rules": [{"rulePriority": 1, "selection": {"tagStatus": "untagged", "countType": "imageCountMoreThan", "countNumber": 5}, "action": {"type": "expire"}}]}))
    s.call("get_lifecycle_policy", repositoryName="${name}")
    s.call("list_images", repositoryName="${name}")
    s.call("get_authorization_token", _ignore=["authorizationData[].authorizationToken"], _shape_only=True)
    s.call("list_tags_for_resource", resourceArn="${arn}")
    s.call("describe_repositories", repositoryNames=["${name}-none"], expect=aws_error("RepositoryNotFoundException", 400))
    s.cleanup("delete_repository", repositoryName="${name}", force=True)


@scenario("ecr-public", "public repositories")
def _(s):
    s.call("create_repository", repositoryName="${name}")
    s.call("describe_repositories", repositoryNames=["${name}"])
    s.call("describe_repositories", repositoryNames=["${name}-none"], expect=aws_error("RepositoryNotFoundException", 400))
    s.cleanup("delete_repository", repositoryName="${name}", force=True)


@scenario("ecs", "clusters and task definitions")
def _(s):
    s.call("create_cluster", clusterName="${name}")
    s.call("describe_clusters", clusters=["${name}"])
    s.call(
        "register_task_definition",
        family="${name}",
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:latest", "memory": 128, "essential": True}],
        save={"td": "taskDefinition.taskDefinitionArn"},
    )
    s.call("describe_task_definition", taskDefinition="${td}")
    s.call("list_task_definitions", familyPrefix="${name}")
    s.call("describe_clusters", clusters=["${name}-none"], _note="missing clusters come back in failures, not as an error")
    s.cleanup("deregister_task_definition", taskDefinition="${td}")
    s.cleanup("delete_cluster", cluster="${name}")


@scenario("efs", "file systems")
def _(s):
    s.call("create_file_system", CreationToken="${name}", PerformanceMode="generalPurpose", Tags=[{"Key": "Name", "Value": "${name}"}], save={"fs": "FileSystemId"})
    s.call("describe_file_systems", FileSystemId="${fs}", _until="FileSystems[0].LifeCycleState == 'available'", _wait=30)
    s.call("create_file_system", CreationToken="${name}", expect=aws_error("FileSystemAlreadyExists", 409))
    s.call("put_lifecycle_configuration", FileSystemId="${fs}", LifecyclePolicies=[{"TransitionToIA": "AFTER_30_DAYS"}])
    s.call("describe_lifecycle_configuration", FileSystemId="${fs}")
    s.call("create_access_point", FileSystemId="${fs}", ClientToken="${name}", save={"ap": "AccessPointId"})
    s.call("describe_access_points", FileSystemId="${fs}")
    s.call("describe_file_systems", FileSystemId="fs-00000000", expect=aws_error("FileSystemNotFound", 404))
    s.cleanup("delete_access_point", AccessPointId="${ap}")
    s.cleanup("delete_file_system", FileSystemId="${fs}")


@scenario("eks", "cluster lookups")
def _(s):
    s.call("list_clusters", _shape_only=True)
    s.call("describe_cluster", name="${name}-none", expect=aws_error("ResourceNotFoundException", 404))
    s.call("describe_addon_versions", kubernetesVersion="1.31", _shape_only=True)


@scenario("elasticache", "parameter and subnet groups")
def _(s):
    s.call("create_cache_parameter_group", CacheParameterGroupName="${name}", CacheParameterGroupFamily="redis7", Description="parity")
    s.call("describe_cache_parameter_groups", CacheParameterGroupName="${name}")
    s.call("describe_cache_parameters", CacheParameterGroupName="${name}", MaxRecords=20, _shape_only=True)
    s.call("describe_cache_clusters", CacheClusterId="${name}-none", expect=aws_error("CacheClusterNotFound", 404))
    s.call("describe_cache_engine_versions", Engine="redis", _shape_only=True)
    s.cleanup("delete_cache_parameter_group", CacheParameterGroupName="${name}")


@scenario("rds", "parameter groups and lookups")
def _(s):
    s.call("create_db_parameter_group", DBParameterGroupName="${name}", DBParameterGroupFamily="postgres16", Description="parity")
    s.call("describe_db_parameter_groups", DBParameterGroupName="${name}")
    s.call("modify_db_parameter_group", DBParameterGroupName="${name}", Parameters=[{"ParameterName": "work_mem", "ParameterValue": "8192", "ApplyMethod": "immediate"}])
    s.call("describe_db_instances", DBInstanceIdentifier="${name}-none", expect=aws_error("DBInstanceNotFound", 404))
    s.call("describe_db_clusters", DBClusterIdentifier="${name}-none", expect=aws_error("DBClusterNotFoundFault", 404))
    s.call("describe_db_engine_versions", Engine="postgres", DefaultOnly=True, _shape_only=True)
    s.cleanup("delete_db_parameter_group", DBParameterGroupName="${name}")


@scenario("autoscaling", "launch configurations")
def _(s):
    s.call("create_launch_configuration", LaunchConfigurationName="${name}", ImageId="ami-12345678", InstanceType="t3.micro")
    s.call("describe_launch_configurations", LaunchConfigurationNames=["${name}"])
    s.call("create_launch_configuration", LaunchConfigurationName="${name}", ImageId="ami-12345678", InstanceType="t3.micro", expect=aws_error("AlreadyExists", 400))
    s.call("describe_auto_scaling_groups", AutoScalingGroupNames=["${name}-none"])
    s.call("describe_account_limits", _shape_only=True)
    s.cleanup("delete_launch_configuration", LaunchConfigurationName="${name}")


@scenario("elbv2", "target groups", needs=("ec2",))
def _(s):
    s.call("create_vpc", service="ec2", CidrBlock="10.78.0.0/16", save={"vpc": "Vpc.VpcId"})
    s.call("create_target_group", Name="${name}", Protocol="HTTP", Port=80, VpcId="${vpc}", TargetType="ip", save={"tg": "TargetGroups[0].TargetGroupArn"})
    s.call("describe_target_groups", TargetGroupArns=["${tg}"])
    s.call("describe_target_group_attributes", TargetGroupArn="${tg}")
    s.call("describe_target_health", TargetGroupArn="${tg}")
    s.call("describe_load_balancers", Names=["${name}-none"], expect=aws_error("LoadBalancerNotFound", 400))
    s.cleanup("delete_target_group", TargetGroupArn="${tg}")
    s.cleanup("delete_vpc", service="ec2", VpcId="${vpc}")


@scenario("elb", "classic lookups")
def _(s):
    s.call("describe_load_balancers", LoadBalancerNames=["${name}-none"], expect=aws_error("LoadBalancerNotFound", 400))
    s.call("describe_load_balancer_policy_types", PolicyTypeNames=["ProxyProtocolPolicyType"])


@scenario("globalaccelerator", "accelerators")
def _(s):
    s.call("create_accelerator", Name="${name}", IdempotencyToken="${name}", Enabled=False, save={"arn": "Accelerator.AcceleratorArn"})
    s.call("describe_accelerator", AcceleratorArn="${arn}")
    s.call("list_accelerators", _shape_only=True)
    s.call("describe_accelerator", AcceleratorArn="${arn}-none", expect=aws_error("AcceleratorNotFoundException"))
    s.cleanup("delete_accelerator", AcceleratorArn="${arn}")


@scenario("organizations", "organization lifecycle")
def _(s):
    s.call("describe_organization", _note="a standalone account is in no organization", expect=aws_error("AWSOrganizationsNotInUseException"))
    s.call("create_organization", FeatureSet="ALL")
    s.call("describe_organization")
    s.call("list_roots", save={"root": "Roots[0].Id"})
    s.call("create_organizational_unit", ParentId="${root}", Name="${name}", save={"ou": "OrganizationalUnit.Id"})
    s.call("list_organizational_units_for_parent", ParentId="${root}")
    s.call("list_accounts")
    s.call("describe_organizational_unit", OrganizationalUnitId="ou-zzzz-zzzzzzzz", expect=aws_error("OrganizationalUnitNotFoundException"))
    s.cleanup("delete_organizational_unit", OrganizationalUnitId="${ou}")
    s.cleanup("delete_organization")


@scenario("guardduty", "detectors")
def _(s):
    s.call("create_detector", Enable=True, save={"det": "DetectorId"})
    s.call("get_detector", DetectorId="${det}")
    s.call("list_detectors")
    s.call("update_detector", DetectorId="${det}", FindingPublishingFrequency="ONE_HOUR")
    s.call("get_detector", DetectorId="00000000000000000000000000000000", expect=aws_error("BadRequestException", 400))
    s.cleanup("delete_detector", DetectorId="${det}")


@scenario("securityhub", "hub")
def _(s):
    s.call("enable_security_hub", EnableDefaultStandards=False)
    s.call("describe_hub")
    s.call("get_enabled_standards")
    s.cleanup("disable_security_hub")


@scenario("cloudtrail", "trail lookups")
def _(s):
    s.call("describe_trails", _shape_only=True)
    s.call("get_trail", Name="${name}-none", expect=aws_error("TrailNotFoundException"))
    s.call("lookup_events", MaxResults=5, _shape_only=True)


@scenario("cloudtrail-data", "audit events")
def _(s):
    s.call(
        "put_audit_events",
        channelArn="arn:aws:cloudtrail:${region}:${account}:channel/00000000-0000-0000-0000-000000000000",
        auditEvents=[{"id": "1", "eventData": "{}"}],
        expect=aws_error("ChannelNotFound", 400),
    )


@scenario("ce", "cost and usage")
def _(s):
    s.call(
        "get_cost_and_usage",
        TimePeriod={"Start": "2026-01-01", "End": "2026-02-01"},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        _shape_only=True,
    )
    s.call("get_cost_and_usage", TimePeriod={"Start": "2026-02-01", "End": "2026-01-01"}, Granularity="MONTHLY", Metrics=["UnblendedCost"], expect=aws_error("ValidationException", 400))


@scenario("service-quotas", "quotas")
def _(s):
    s.call("get_service_quota", ServiceCode="ec2", QuotaCode="L-1216C47A")
    s.call("get_aws_default_service_quota", ServiceCode="lambda", QuotaCode="L-B99A9384")
    s.call("list_services", MaxResults=5, _shape_only=True)
    s.call("get_service_quota", ServiceCode="ec2", QuotaCode="L-00000000", expect=aws_error("NoSuchResourceException"))


@scenario("ram", "resource shares")
def _(s):
    s.call("create_resource_share", name="${name}", allowExternalPrincipals=False, save={"share": "resourceShare.resourceShareArn"})
    s.call("get_resource_shares", resourceOwner="SELF", name="${name}")
    s.call("list_permissions", resourceType="acm-pca:CertificateAuthority", _shape_only=True)
    s.call("get_resource_shares", resourceOwner="BOGUS", _raw=True, expect=aws_error("InvalidParameterException", 400))
    s.cleanup("delete_resource_share", resourceShareArn="${share}")


@scenario("codeartifact", "domains and repositories")
def _(s):
    s.call("create_domain", domain="${name}")
    s.call("describe_domain", domain="${name}")
    s.call("create_repository", domain="${name}", repository="repo", description="parity")
    s.call("describe_repository", domain="${name}", repository="repo")
    s.call("list_repositories_in_domain", domain="${name}")
    s.call("get_repository_endpoint", domain="${name}", repository="repo", format="npm")
    s.call("get_authorization_token", domain="${name}", _ignore=["authorizationToken"])
    s.call("describe_repository", domain="${name}", repository="none", expect=aws_error("ResourceNotFoundException", 404))
    s.cleanup("delete_repository", domain="${name}", repository="repo")
    s.cleanup("delete_domain", domain="${name}")


@scenario("amplify", "apps and branches")
def _(s):
    s.call("create_app", name="${name}", platform="WEB", save={"app": "app.appId"})
    s.call("get_app", appId="${app}")
    s.call("create_branch", appId="${app}", branchName="main", stage="PRODUCTION")
    s.call("list_branches", appId="${app}")
    s.call("get_app", appId="d0000000000000", expect=aws_error("NotFoundException", 404))
    s.cleanup("delete_branch", appId="${app}", branchName="main")
    s.cleanup("delete_app", appId="${app}")


@scenario("imagebuilder", "components")
def _(s):
    s.call(
        "create_component",
        name="${name}",
        semanticVersion="1.0.0",
        platform="Linux",
        data="name: parity\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: echo\n        action: ExecuteBash\n        inputs:\n          commands: ['echo hi']\n",
        clientToken="${name}",
        save={"arn": "componentBuildVersionArn"},
    )
    s.call("get_component", componentBuildVersionArn="${arn}")
    s.call("list_components", owner="Self", _shape_only=True)
    s.call("get_component", componentBuildVersionArn="arn:aws:imagebuilder:${region}:${account}:component/none/1.0.0/1", )
    s.cleanup("delete_component", componentBuildVersionArn="${arn}")


@scenario("bedrock", "foundation models")
def _(s):
    s.call("list_foundation_models", byProvider="Anthropic", _shape_only=True)
    s.call("get_foundation_model", modelIdentifier="no.such-model-v1", expect=aws_error("ResourceNotFoundException", 404))


@scenario("bedrock-runtime", "converse")
def _(s):
    s.call(
        "converse",
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        messages=[{"role": "user", "content": [{"text": "Say hi"}]}],
        inferenceConfig={"maxTokens": 32},
        _shape_only=True,
        _note="model output differs by backend; shape only",
    )


@scenario("sso-admin", "instances")
def _(s):
    s.call("list_instances", _shape_only=True)


@scenario("identitystore", "lookups", needs=("sso-admin",))
def _(s):
    s.call("list_instances", service="sso-admin", save={"store": "Instances[0].IdentityStoreId"})
    s.call("list_users", IdentityStoreId="${store}", _shape_only=True)
    s.call("describe_user", IdentityStoreId="${store}", UserId="00000000-0000-0000-0000-000000000000", expect=aws_error("ResourceNotFoundException", 404))


@scenario("sso-oidc", "client registration")
def _(s):
    s.call("register_client", clientName="${name}", clientType="public", _ignore=["clientSecret", "clientId"])


@scenario("sso", "portal with a bad token")
def _(s):
    s.call("list_accounts", accessToken="not-a-token", expect=aws_error("UnauthorizedException", 401))


@scenario("meteringmarketplace", "metering an unknown product")
def _(s):
    s.call(
        "meter_usage",
        ProductCode="${alnum}",
        Timestamp="2026-01-01T00:00:00Z",
        UsageDimension="users",
        UsageQuantity=1,
        expect=aws_error("InvalidProductCodeException", 400),
    )


@scenario("marketplace-entitlement", "entitlements of an unknown product")
def _(s):
    s.call("get_entitlements", ProductCode="${alnum}", _shape_only=True)


@scenario("pca-connector-scep", "connectors")
def _(s):
    s.call("list_connectors", _shape_only=True)
    s.call("get_connector", ConnectorArn="arn:aws:pca-connector-scep:${region}:${account}:connector/00000000-0000-0000-0000-000000000000", expect=aws_error("ResourceNotFoundException", 404))
