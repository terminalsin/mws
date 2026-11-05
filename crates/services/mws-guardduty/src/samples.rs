//! `CreateSampleFindings`: one sample per finding type, shaped like AWS's
//! samples (placeholder `GeneratedFinding*` values, `[SAMPLE]` titles and
//! `sample: true` in `service.additionalInfo`).

use mws_core::RequestContext;

use crate::common::{child_arn, iso, stable_id};
use crate::generated::types;

/// GuardDuty's finding types.
pub const FINDING_TYPES: &[&str] = &[
    // EC2
    "Backdoor:EC2/C&CActivity.B",
    "Backdoor:EC2/C&CActivity.B!DNS",
    "Backdoor:EC2/DenialOfService.Dns",
    "Backdoor:EC2/DenialOfService.Tcp",
    "Backdoor:EC2/DenialOfService.Udp",
    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
    "Backdoor:EC2/DenialOfService.UnusualProtocol",
    "Backdoor:EC2/Spambot",
    "Behavior:EC2/NetworkPortUnusual",
    "Behavior:EC2/TrafficVolumeUnusual",
    "CryptoCurrency:EC2/BitcoinTool.B",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "DefenseEvasion:EC2/UnusualDNSResolver",
    "DefenseEvasion:EC2/UnusualDoHActivity",
    "DefenseEvasion:EC2/UnusualDoTActivity",
    "Impact:EC2/AbusedDomainRequest.Reputation",
    "Impact:EC2/BitcoinDomainRequest.Reputation",
    "Impact:EC2/MaliciousDomainRequest.Reputation",
    "Impact:EC2/PortSweep",
    "Impact:EC2/SuspiciousDomainRequest.Reputation",
    "Impact:EC2/WinRMBruteForce",
    "Recon:EC2/PortProbeEMRUnprotectedPort",
    "Recon:EC2/PortProbeUnprotectedPort",
    "Recon:EC2/Portscan",
    "Trojan:EC2/BlackholeTraffic",
    "Trojan:EC2/BlackholeTraffic!DNS",
    "Trojan:EC2/DGADomainRequest.B",
    "Trojan:EC2/DGADomainRequest.C!DNS",
    "Trojan:EC2/DNSDataExfiltration",
    "Trojan:EC2/DriveBySourceTraffic!DNS",
    "Trojan:EC2/DropPoint",
    "Trojan:EC2/DropPoint!DNS",
    "Trojan:EC2/PhishingDomainRequest!DNS",
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:EC2/MetadataDNSRebind",
    "UnauthorizedAccess:EC2/RDPBruteForce",
    "UnauthorizedAccess:EC2/SSHBruteForce",
    "UnauthorizedAccess:EC2/TorClient",
    "UnauthorizedAccess:EC2/TorRelay",
    // IAM
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "DefenseEvasion:IAMUser/AnomalousBehavior",
    "DefenseEvasion:IAMUser/BedrockLoggingDisabled",
    "Discovery:IAMUser/AnomalousBehavior",
    "Exfiltration:IAMUser/AnomalousBehavior",
    "Impact:IAMUser/AnomalousBehavior",
    "InitialAccess:IAMUser/AnomalousBehavior",
    "PenTest:IAMUser/KaliLinux",
    "PenTest:IAMUser/ParrotLinux",
    "PenTest:IAMUser/PentooLinux",
    "Persistence:IAMUser/AnomalousBehavior",
    "Policy:IAMUser/RootCredentialUsage",
    "Policy:IAMUser/ShortTermRootCredentialUsage",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "Recon:IAMUser/MaliciousIPCaller",
    "Recon:IAMUser/MaliciousIPCaller.Custom",
    "Recon:IAMUser/TorIPCaller",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Stealth:IAMUser/PasswordPolicyChange",
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:IAMUser/TorIPCaller",
    // S3
    "Discovery:S3/AnomalousBehavior",
    "Discovery:S3/MaliciousIPCaller",
    "Discovery:S3/MaliciousIPCaller.Custom",
    "Discovery:S3/TorIPCaller",
    "Exfiltration:S3/AnomalousBehavior",
    "Exfiltration:S3/MaliciousIPCaller",
    "Impact:S3/AnomalousBehavior.Delete",
    "Impact:S3/AnomalousBehavior.Permission",
    "Impact:S3/AnomalousBehavior.Write",
    "Impact:S3/MaliciousIPCaller",
    "Object:S3/MaliciousFile",
    "PenTest:S3/KaliLinux",
    "PenTest:S3/ParrotLinux",
    "PenTest:S3/PentooLinux",
    "Policy:S3/AccountBlockPublicAccessDisabled",
    "Policy:S3/BucketAnonymousAccessGranted",
    "Policy:S3/BucketBlockPublicAccessDisabled",
    "Policy:S3/BucketPublicAccessGranted",
    "Stealth:S3/ServerAccessLoggingDisabled",
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:S3/TorIPCaller",
    // EKS audit logs
    "CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed",
    "CredentialAccess:Kubernetes/MaliciousIPCaller",
    "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom",
    "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess",
    "CredentialAccess:Kubernetes/TorIPCaller",
    "DefenseEvasion:Kubernetes/MaliciousIPCaller",
    "DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom",
    "DefenseEvasion:Kubernetes/SuccessfulAnonymousAccess",
    "DefenseEvasion:Kubernetes/TorIPCaller",
    "Discovery:Kubernetes/AnomalousBehavior.PermissionChecked",
    "Discovery:Kubernetes/MaliciousIPCaller",
    "Discovery:Kubernetes/MaliciousIPCaller.Custom",
    "Discovery:Kubernetes/SuccessfulAnonymousAccess",
    "Discovery:Kubernetes/TorIPCaller",
    "Execution:Kubernetes/AnomalousBehavior.ExecInPod",
    "Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed",
    "Execution:Kubernetes/ExecInKubeSystemPod",
    "Impact:Kubernetes/MaliciousIPCaller",
    "Impact:Kubernetes/MaliciousIPCaller.Custom",
    "Impact:Kubernetes/SuccessfulAnonymousAccess",
    "Impact:Kubernetes/TorIPCaller",
    "Persistence:Kubernetes/ContainerWithSensitiveMount",
    "Persistence:Kubernetes/MaliciousIPCaller",
    "Persistence:Kubernetes/MaliciousIPCaller.Custom",
    "Persistence:Kubernetes/SuccessfulAnonymousAccess",
    "Persistence:Kubernetes/TorIPCaller",
    "Policy:Kubernetes/AdminAccessToDefaultServiceAccount",
    "Policy:Kubernetes/AnonymousAccessGranted",
    "Policy:Kubernetes/ExposedDashboard",
    "Policy:Kubernetes/KubeflowDashboardExposed",
    "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated",
    "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated",
    "PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!ContainerWithSensitiveMount",
    "PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer",
    "PrivilegeEscalation:Kubernetes/PrivilegedContainer",
    // Runtime monitoring
    "Backdoor:Runtime/C&CActivity.B",
    "Backdoor:Runtime/C&CActivity.B!DNS",
    "CryptoCurrency:Runtime/BitcoinTool.B",
    "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
    "DefenseEvasion:Runtime/FilelessExecution",
    "DefenseEvasion:Runtime/ProcessInjection.Proc",
    "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
    "DefenseEvasion:Runtime/SuspiciousCommand",
    "Discovery:Runtime/SuspiciousCommand",
    "Execution:Runtime/MaliciousFileExecuted",
    "Execution:Runtime/NewBinaryExecuted",
    "Execution:Runtime/NewLibraryLoaded",
    "Execution:Runtime/ReverseShell",
    "Execution:Runtime/SuspiciousCommand",
    "Execution:Runtime/SuspiciousShellCreated",
    "Execution:Runtime/SuspiciousTool",
    "Impact:Runtime/AbusedDomainRequest.Reputation",
    "Impact:Runtime/BitcoinDomainRequest.Reputation",
    "Impact:Runtime/CryptoMinerExecuted",
    "Impact:Runtime/MaliciousDomainRequest.Reputation",
    "Impact:Runtime/SuspiciousDomainRequest.Reputation",
    "Persistence:Runtime/SuspiciousCommand",
    "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
    "PrivilegeEscalation:Runtime/DockerSocketAccessed",
    "PrivilegeEscalation:Runtime/ElevationToRoot",
    "PrivilegeEscalation:Runtime/RuncContainerEscape",
    "PrivilegeEscalation:Runtime/SuspiciousCommand",
    "PrivilegeEscalation:Runtime/UserfaultfdUsage",
    "Trojan:Runtime/BlackholeTraffic",
    "Trojan:Runtime/BlackholeTraffic!DNS",
    "Trojan:Runtime/DGADomainRequest.C!DNS",
    "Trojan:Runtime/DriveBySourceTraffic!DNS",
    "Trojan:Runtime/DropPoint",
    "Trojan:Runtime/DropPoint!DNS",
    "Trojan:Runtime/PhishingDomainRequest!DNS",
    "UnauthorizedAccess:Runtime/MetadataDNSRebind",
    "UnauthorizedAccess:Runtime/TorClient",
    "UnauthorizedAccess:Runtime/TorRelay",
    // Malware Protection
    "Execution:EC2/MaliciousFile",
    "Execution:EC2/SuspiciousFile",
    "Execution:ECS/MaliciousFile",
    "Execution:ECS/SuspiciousFile",
    "Execution:Kubernetes/MaliciousFile",
    "Execution:Kubernetes/SuspiciousFile",
    "Execution:Container/MaliciousFile",
    "Execution:Container/SuspiciousFile",
    // RDS Protection
    "CredentialAccess:RDS/AnomalousBehavior.FailedLogin",
    "CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce",
    "CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin",
    "CredentialAccess:RDS/MaliciousIPCaller.FailedLogin",
    "CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin",
    "CredentialAccess:RDS/TorIPCaller.FailedLogin",
    "CredentialAccess:RDS/TorIPCaller.SuccessfulLogin",
    "Discovery:RDS/MaliciousIPCaller",
    "Discovery:RDS/TorIPCaller",
    // Lambda Protection
    "Backdoor:Lambda/C&CActivity.B",
    "CryptoCurrency:Lambda/BitcoinTool.B",
    "Trojan:Lambda/BlackholeTraffic",
    "Trojan:Lambda/DropPoint",
    "UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:Lambda/TorClient",
    "UnauthorizedAccess:Lambda/TorRelay",
    // Extended threat detection
    "AttackSequence:EC2/CompromisedInstanceGroup",
    "AttackSequence:ECS/CompromisedCluster",
    "AttackSequence:EKS/CompromisedCluster",
    "AttackSequence:IAM/CompromisedCredentials",
    "AttackSequence:S3/CompromisedData",
];

/// `(threat purpose, resource type, threat family name)` of a type such as
/// `Backdoor:EC2/C&CActivity.B!DNS`.
fn parts(ty: &str) -> (&str, &str, &str) {
    let (purpose, rest) = ty.split_once(':').unwrap_or(("", ty));
    let (resource, name) = rest.split_once('/').unwrap_or((rest, ""));
    (purpose, resource, name)
}

/// The severity AWS gives the type's samples: Critical (9+) for attack
/// sequences, High (7-8.9), Medium (4-6.9) or Low (1-3.9).
pub fn severity(ty: &str) -> f64 {
    let (purpose, resource, name) = parts(ty);
    if purpose == "AttackSequence" {
        return 9.0;
    }
    if ty.ends_with(".Custom") || name.contains("Tor") && purpose != "UnauthorizedAccess" {
        return 5.0;
    }
    match purpose {
        "Backdoor" | "CryptoCurrency" | "Trojan" | "Object" => 8.0,
        "Execution" if name.contains("MaliciousFile") => 8.0,
        "Execution" if name.contains("SuspiciousFile") => 5.0,
        "UnauthorizedAccess" if name.contains("InstanceCredentialExfiltration") => 8.0,
        "UnauthorizedAccess" if name.contains("BruteForce") || name.contains("Tor") => 5.0,
        "UnauthorizedAccess" | "Exfiltration" | "Impact" | "PrivilegeEscalation" => 8.0,
        "CredentialAccess" if resource == "RDS" && name.contains("FailedLogin") => 5.0,
        "CredentialAccess" | "Persistence" | "DefenseEvasion" => 8.0,
        "Policy" if name.contains("Root") => 2.0,
        "Policy" | "Stealth" | "Behavior" | "PenTest" | "Execution" => 5.0,
        "Recon" | "Discovery" => 2.0,
        _ => 5.0,
    }
}

/// The finding's GuardDuty feature (`service.featureName`).
fn feature_name(ty: &str) -> &'static str {
    let (purpose, resource, name) = parts(ty);
    match (purpose, resource) {
        ("AttackSequence", _) => "Correlation",
        (_, "IAMUser") => "CloudTrail",
        (_, "S3") if purpose == "Object" => "S3MalwareProtection",
        (_, "S3") if name.contains("AnomalousBehavior") || name.contains("IPCaller") || purpose == "PenTest" => {
            "S3DataEvents"
        }
        (_, "S3") => "CloudTrail",
        ("Execution", "Kubernetes" | "ECS" | "Container" | "EC2") if name.contains("File") => "EbsMalwareProtection",
        (_, "Kubernetes") => "EksAuditLogs",
        (_, "Runtime") => "RuntimeMonitoring",
        (_, "RDS") => "RdsLoginEvents",
        (_, "Lambda") => "LambdaNetworkLogs",
        _ if name.contains("!DNS") || name.contains("DomainRequest") || name.contains("DNSData") => "DnsLogs",
        _ => "FlowLogs",
    }
}

fn tag(k: &str, v: &str) -> types::Tag {
    types::Tag { key: Some(k.into()), value: Some(v.into()) }
}

fn remote_ip(v4: &str) -> types::RemoteIpDetails {
    types::RemoteIpDetails {
        city: Some(types::City { city_name: Some("GeneratedFindingCityName".into()) }),
        country: Some(types::Country { country_code: None, country_name: Some("GeneratedFindingCountryName".into()) }),
        geo_location: Some(types::GeoLocation { lat: Some(0.0), lon: Some(0.0) }),
        ip_address_v4: Some(v4.into()),
        ip_address_v6: None,
        organization: Some(types::Organization {
            asn: Some("-1".into()),
            asn_org: Some("GeneratedFindingASNOrg".into()),
            isp: Some("GeneratedFindingISP".into()),
            org: Some("GeneratedFindingORG".into()),
        }),
    }
}

fn instance(ctx: &RequestContext, account: &str) -> types::InstanceDetails {
    types::InstanceDetails {
        availability_zone: Some("GeneratedFindingInstaceAvailabilityZone".into()),
        iam_instance_profile: Some(types::IamInstanceProfile {
            arn: Some(format!("arn:{}:iam::{account}:example/instance/profile", ctx.partition)),
            id: Some("GeneratedFindingInstanceProfileId".into()),
        }),
        image_description: Some("GeneratedFindingInstaceImageDescription".into()),
        image_id: Some("ami-99999999".into()),
        instance_id: Some("i-99999999".into()),
        instance_state: Some("running".into()),
        instance_type: Some("m3.xlarge".into()),
        outpost_arn: None,
        launch_time: Some("2016-08-02T02:05:06.000Z".into()),
        network_interfaces: Some(vec![types::NetworkInterface {
            ipv6_addresses: Some(Vec::new()),
            network_interface_id: Some("eni-abcdef00".into()),
            private_dns_name: Some("GeneratedFindingPrivateDnsName".into()),
            private_ip_address: Some("10.0.0.1".into()),
            private_ip_addresses: Some(vec![types::PrivateIpAddressDetails {
                private_dns_name: Some("GeneratedFindingPrivateName".into()),
                private_ip_address: Some("10.0.0.1".into()),
            }]),
            public_dns_name: Some("GeneratedFindingPublicDNSName".into()),
            public_ip: Some("198.51.100.0".into()),
            security_groups: Some(vec![types::SecurityGroup {
                group_id: Some("GeneratedFindingSecurityId".into()),
                group_name: Some("GeneratedFindingSecurityGroupName".into()),
            }]),
            subnet_id: Some("GeneratedFindingSubnetId".into()),
            vpc_id: Some("GeneratedFindingVPCId".into()),
        }]),
        platform: None,
        product_codes: Some(vec![types::ProductCode {
            code: Some("GeneratedFindingProductCodeId".into()),
            product_type: Some("GeneratedFindingProductCodeType".into()),
        }]),
        tags: Some(vec![
            tag("GeneratedFindingInstaceTag1", "GeneratedFindingInstaceValue1"),
            tag("GeneratedFindingInstaceTag2", "GeneratedFindingInstaceTagValue2"),
        ]),
    }
}

fn access_key() -> types::AccessKeyDetails {
    types::AccessKeyDetails {
        access_key_id: Some("GeneratedFindingAccessKeyId".into()),
        principal_id: Some("GeneratedFindingPrincipalId".into()),
        user_name: Some("GeneratedFindingUserName".into()),
        user_type: Some("IAMUser".into()),
    }
}

fn bucket(ctx: &RequestContext, now: chrono::DateTime<chrono::Utc>) -> types::S3BucketDetail {
    types::S3BucketDetail {
        arn: Some(format!("arn:{}:s3:::bucketName", ctx.partition)),
        name: Some("bucketName".into()),
        r#type: Some("Destination".into()),
        created_at: Some(now),
        owner: Some(types::Owner { id: Some("CanonicalId of Owner".into()) }),
        tags: Some(vec![tag("foo", "bar")]),
        default_server_side_encryption: Some(types::DefaultServerSideEncryption {
            encryption_type: Some("SSEAlgorithm".into()),
            kms_master_key_arn: Some("arn:aws:kms:region:123456789012:key/key-id".into()),
        }),
        public_access: Some(types::PublicAccess {
            permission_configuration: None,
            effective_permission: Some("NOT_PUBLIC".into()),
        }),
        s3_object_details: None,
    }
}

fn eks_cluster(ctx: &RequestContext, account: &str, now: chrono::DateTime<chrono::Utc>) -> types::EksClusterDetails {
    types::EksClusterDetails {
        name: Some("GeneratedFindingEKSClusterName".into()),
        arn: Some(format!("arn:{}:eks:{}:{account}:cluster/GeneratedFindingEKSClusterName", ctx.partition, ctx.region)),
        vpc_id: Some("GeneratedFindingEKSClusterVPCId".into()),
        status: Some("ACTIVE".into()),
        tags: Some(vec![tag("GeneratedFindingEKSClusterTag1", "GeneratedFindingEKSClusterTagValue1")]),
        created_at: Some(now),
    }
}

fn kubernetes() -> types::KubernetesDetails {
    types::KubernetesDetails {
        kubernetes_user_details: Some(types::KubernetesUserDetails {
            username: Some("GeneratedFindingUserName".into()),
            uid: Some("GeneratedFindingUID".into()),
            groups: Some(vec!["GeneratedFindingUserGroup".into()]),
            session_name: None,
            impersonated_user: None,
        }),
        kubernetes_workload_details: Some(types::KubernetesWorkloadDetails {
            name: Some("GeneratedFindingWorkloadName".into()),
            r#type: Some("GeneratedFindingWorkloadType".into()),
            uid: Some("GeneratedFindingWorkloadUID".into()),
            namespace: Some("GeneratedFindingWorkloadNamespace".into()),
            host_network: Some(true),
            containers: Some(vec![container()]),
            ..Default::default()
        }),
    }
}

fn container() -> types::Container {
    types::Container {
        container_runtime: Some("docker".into()),
        id: Some("GeneratedFindingContainerId".into()),
        name: Some("GeneratedFindingContainerName".into()),
        image: Some("GeneratedFindingContainerImage".into()),
        image_prefix: Some("GeneratedFindingContainerImagePrefix".into()),
        ..Default::default()
    }
}

fn process(now: chrono::DateTime<chrono::Utc>) -> types::ProcessDetails {
    types::ProcessDetails {
        name: Some("GeneratedFindingProcessName".into()),
        executable_path: Some("/usr/bin/GeneratedFindingProcessName".into()),
        executable_sha256: Some("GeneratedFindingExecutableSha256".into()),
        namespace_pid: Some(1),
        pwd: Some("/".into()),
        pid: Some(1234),
        start_time: Some(now),
        uuid: Some("GeneratedFindingProcessUuid".into()),
        parent_uuid: Some("GeneratedFindingParentProcessUuid".into()),
        user: Some("root".into()),
        user_id: Some(0),
        euid: Some(0),
        lineage: None,
    }
}

/// The finding's `resource`.
fn resource(ctx: &RequestContext, account: &str, ty: &str, now: chrono::DateTime<chrono::Utc>) -> types::Resource {
    let (purpose, resource, name) = parts(ty);
    let mut r = types::Resource::default();
    match (purpose, resource) {
        ("AttackSequence", "IAM") => {
            r.resource_type = Some("AccessKey".into());
            r.access_key_details = Some(access_key());
        }
        ("AttackSequence", "S3") | (_, "S3") => {
            r.resource_type = Some("S3Bucket".into());
            r.access_key_details = Some(access_key());
            let mut b = bucket(ctx, now);
            if purpose == "Object" {
                b.r#type = None;
                b.s3_object_details = Some(vec![types::S3ObjectDetail {
                    object_arn: Some(format!("arn:{}:s3:::bucketName/objectKey", ctx.partition)),
                    key: Some("objectKey".into()),
                    e_tag: Some("GeneratedFindingETag".into()),
                    hash: Some("GeneratedFindingObjectHash".into()),
                    version_id: Some("GeneratedFindingVersionId".into()),
                }]);
                r.resource_type = Some("S3Object".into());
                r.access_key_details = None;
            }
            r.s3_bucket_details = Some(vec![b]);
        }
        (_, "IAMUser") => {
            r.resource_type = Some("AccessKey".into());
            r.access_key_details = Some(access_key());
        }
        ("AttackSequence", "EKS") | (_, "Kubernetes") => {
            r.resource_type = Some("EKSCluster".into());
            r.eks_cluster_details = Some(eks_cluster(ctx, account, now));
            r.kubernetes_details = Some(kubernetes());
        }
        ("AttackSequence", "ECS") | (_, "ECS") => {
            r.resource_type = Some("ECSCluster".into());
            r.ecs_cluster_details = Some(types::EcsClusterDetails {
                name: Some("GeneratedFindingECSClusterName".into()),
                arn: Some(format!(
                    "arn:{}:ecs:{}:{account}:cluster/GeneratedFindingECSClusterName",
                    ctx.partition, ctx.region
                )),
                status: Some("ACTIVE".into()),
                active_services_count: Some(1),
                registered_container_instances_count: Some(1),
                running_tasks_count: Some(1),
                tags: Some(vec![tag("GeneratedFindingECSClusterTag1", "GeneratedFindingECSClusterTagValue1")]),
                task_details: None,
            });
        }
        (_, "Container") => {
            r.resource_type = Some("Container".into());
            r.container_details = Some(container());
        }
        (_, "RDS") => {
            r.resource_type = Some("RDSDBInstance".into());
            r.rds_db_instance_details = Some(types::RdsDbInstanceDetails {
                db_instance_identifier: Some("GeneratedFindingDBInstanceId".into()),
                engine: Some("aurora-postgresql".into()),
                engine_version: Some("15.4".into()),
                db_cluster_identifier: Some("GeneratedFindingDBClusterId".into()),
                db_instance_arn: Some(format!(
                    "arn:{}:rds:{}:{account}:db:GeneratedFindingDBInstanceId",
                    ctx.partition, ctx.region
                )),
                dbi_resource_id: Some("db-GENERATEDFINDINGRESOURCEID".into()),
                tags: Some(vec![tag("GeneratedFindingDBTag1", "GeneratedFindingDBTagValue1")]),
            });
        }
        (_, "Lambda") => {
            r.resource_type = Some("Lambda".into());
            r.lambda_details = Some(types::LambdaDetails {
                function_arn: Some(format!(
                    "arn:{}:lambda:{}:{account}:function:GeneratedFindingFunctionName",
                    ctx.partition, ctx.region
                )),
                function_name: Some("GeneratedFindingFunctionName".into()),
                description: Some("GeneratedFindingDescription".into()),
                last_modified_at: Some(now),
                revision_id: Some("GeneratedFindingRevisionId".into()),
                function_version: Some("$LATEST".into()),
                role: Some(format!("arn:{}:iam::{account}:role/GeneratedFindingRoleName", ctx.partition)),
                vpc_config: None,
                tags: Some(vec![tag("GeneratedFindingFunctionTag1", "GeneratedFindingFunctionTagValue1")]),
            });
        }
        _ => {
            r.resource_type = Some("Instance".into());
            r.instance_details = Some(instance(ctx, account));
            if name.contains("MaliciousFile") || name.contains("SuspiciousFile") {
                r.ebs_volume_details = Some(types::EbsVolumeDetails::default());
            }
        }
    }
    r
}

/// The finding's `service.action`.
fn action(ty: &str) -> Option<types::Action> {
    let (purpose, resource, name) = parts(ty);
    let mut a = types::Action::default();
    match resource {
        "IAMUser" | "S3" | "IAM" if purpose != "Object" => {
            a.action_type = Some("AWS_API_CALL".into());
            a.aws_api_call_action = Some(types::AwsApiCallAction {
                api: Some("GeneratedFindingAPIName".into()),
                caller_type: Some("Remote IP".into()),
                service_name: Some("GeneratedFindingAPIServiceName".into()),
                user_agent: Some("GeneratedFindingUserAgent".into()),
                remote_ip_details: Some(remote_ip("198.51.100.0")),
                error_code: None,
                ..Default::default()
            });
        }
        "Kubernetes" if !name.contains("File") => {
            a.action_type = Some("KUBERNETES_API_CALL".into());
            a.kubernetes_api_call_action = Some(types::KubernetesApiCallAction {
                request_uri: Some("GeneratedFindingRequestURI".into()),
                verb: Some("list".into()),
                source_ips: Some(vec!["198.51.100.0".into()]),
                user_agent: Some("GeneratedFindingUserAgent".into()),
                remote_ip_details: Some(remote_ip("198.51.100.0")),
                status_code: Some(200),
                ..Default::default()
            });
        }
        "RDS" => {
            a.action_type = Some("RDS_LOGIN_ATTEMPT".into());
        }
        "EC2" | "Runtime" | "Lambda" if !name.contains("File") && purpose != "AttackSequence" => {
            if name.contains("!DNS") || name.contains("DomainRequest") || name.contains("DNSData") {
                a.action_type = Some("DNS_REQUEST".into());
                a.dns_request_action = Some(types::DnsRequestAction {
                    domain: Some("GeneratedFindingDomainName".into()),
                    protocol: Some("UDP".into()),
                    blocked: Some(false),
                    ..Default::default()
                });
            } else if name.starts_with("PortProbe") {
                a.action_type = Some("PORT_PROBE".into());
                a.port_probe_action = Some(types::PortProbeAction {
                    blocked: Some(false),
                    port_probe_details: Some(vec![types::PortProbeDetail {
                        local_port_details: Some(types::LocalPortDetails {
                            port: Some(80),
                            port_name: Some("HTTP".into()),
                        }),
                        local_ip_details: Some(types::LocalIpDetails {
                            ip_address_v4: Some("10.0.0.23".into()),
                            ip_address_v6: None,
                        }),
                        remote_ip_details: Some(remote_ip("198.51.100.0")),
                    }]),
                });
            } else if resource != "Runtime" {
                let inbound = name.contains("BruteForce") || name.contains("Portscan") || name.contains("TorRelay");
                a.action_type = Some("NETWORK_CONNECTION".into());
                a.network_connection_action = Some(types::NetworkConnectionAction {
                    blocked: Some(false),
                    connection_direction: Some(if inbound { "INBOUND" } else { "OUTBOUND" }.into()),
                    local_port_details: Some(types::LocalPortDetails {
                        port: Some(39677),
                        port_name: Some("Unknown".into()),
                    }),
                    protocol: Some("TCP".into()),
                    local_ip_details: Some(types::LocalIpDetails {
                        ip_address_v4: Some("10.0.0.23".into()),
                        ip_address_v6: None,
                    }),
                    local_network_interface: None,
                    remote_ip_details: Some(remote_ip("198.51.100.0")),
                    remote_port_details: Some(types::RemotePortDetails {
                        port: Some(80),
                        port_name: Some("HTTP".into()),
                    }),
                });
            } else {
                return None;
            }
        }
        _ => return None,
    }
    Some(a)
}

/// Whether the type is about a threat list match.
fn threat_list(ty: &str) -> bool {
    let (_, _, name) = parts(ty);
    ["MaliciousIPCaller", "TorIPCaller", "C&CActivity", "BlackholeTraffic", "DropPoint", "BitcoinTool", "Reputation"]
        .iter()
        .any(|k| name.contains(k))
}

fn describe(ty: &str) -> (String, String) {
    let (purpose, resource, name) = parts(ty);
    let subject = match resource {
        "EC2" | "Runtime" => "EC2 instance i-99999999",
        "IAMUser" | "IAM" => "IAM user GeneratedFindingUserName",
        "S3" => "S3 bucket bucketName",
        "Kubernetes" | "EKS" => "EKS cluster GeneratedFindingEKSClusterName",
        "ECS" => "ECS cluster GeneratedFindingECSClusterName",
        "Container" => "container GeneratedFindingContainerName",
        "RDS" => "RDS DB instance GeneratedFindingDBInstanceId",
        "Lambda" => "Lambda function GeneratedFindingFunctionName",
        _ => "resource",
    };
    let family = name.split(['.', '!']).next().unwrap_or(name);
    let title = format!("{purpose} activity {family} detected for {subject}.");
    let description = format!(
        "This is a sample finding of type {ty}: {purpose} activity ({family}) was detected for {subject}. \
         GuardDuty generated it to show what a finding of this type looks like."
    );
    (title, description)
}

/// A sample finding of type `ty`; `existing` is the same sample from an
/// earlier call, which it updates (count, last seen) as AWS does.
pub fn sample(
    ctx: &RequestContext,
    account: &str,
    detector: &str,
    ty: &str,
    existing: Option<&types::Finding>,
) -> types::Finding {
    let now = ctx.received_at;
    let now_s = iso(now);
    if let Some(prev) = existing {
        let mut f = prev.clone();
        f.updated_at = now_s.clone();
        if let Some(s) = f.service.as_mut() {
            s.count = Some(s.count.unwrap_or(1) + 1);
            s.event_last_seen = Some(now_s);
        }
        return f;
    }
    let id = stable_id(&["sample", account, &ctx.region, detector, ty]);
    let (title, description) = describe(ty);
    let threat = threat_list(ty);
    let mut info = serde_json::json!({ "sample": true });
    if threat {
        info["threatName"] = "GeneratedFindingThreatName".into();
        info["threatListName"] = "GeneratedFindingThreatListName".into();
    }
    let (_, resource_part, _) = parts(ty);
    let runtime = resource_part == "Runtime";
    types::Finding {
        account_id: account.to_string(),
        arn: child_arn(ctx, account, detector, "finding", &id),
        confidence: Some(5.0),
        created_at: now_s.clone(),
        description: Some(description),
        id: id.clone(),
        partition: Some(ctx.partition.clone()),
        region: ctx.region.clone(),
        resource: resource(ctx, account, ty, now),
        schema_version: "2.0".into(),
        service: Some(types::Service {
            action: action(ty),
            evidence: threat.then(|| types::Evidence {
                threat_intelligence_details: Some(vec![types::ThreatIntelligenceDetail {
                    threat_list_name: Some("GeneratedFindingThreatListName".into()),
                    threat_names: Some(vec!["GeneratedFindingThreatName".into()]),
                    threat_file_sha256: None,
                }]),
            }),
            archived: Some(false),
            count: Some(1),
            detector_id: Some(detector.to_string()),
            event_first_seen: Some(now_s.clone()),
            event_last_seen: Some(now_s.clone()),
            resource_role: Some("TARGET".into()),
            service_name: Some("guardduty".into()),
            user_feedback: None,
            additional_info: Some(types::ServiceAdditionalInfo {
                value: Some(info.to_string()),
                r#type: Some("default".into()),
            }),
            feature_name: Some(feature_name(ty).into()),
            runtime_details: runtime.then(|| types::RuntimeDetails { process: Some(process(now)), context: None }),
            ..Default::default()
        }),
        severity: severity(ty),
        title: Some(format!("[SAMPLE] {title}")),
        r#type: ty.to_string(),
        updated_at: now_s,
        associated_attack_sequence_arn: None,
        custom_detection_rule_name: None,
    }
}

impl crate::GuardDuty {
    pub(crate) fn create_sample_findings(
        &self,
        ctx: &RequestContext,
        input: types::CreateSampleFindingsRequest,
    ) -> Result<types::CreateSampleFindingsResponse, mws_core::ServiceError> {
        self.authorize_detector(ctx, "CreateSampleFindings", &input.detector_id)?;
        let wanted: Vec<String> = match input.finding_types.filter(|t| !t.is_empty()) {
            Some(t) => t,
            None => FINDING_TYPES.iter().map(|s| s.to_string()).collect(),
        };
        for t in &wanted {
            if !FINDING_TYPES.contains(&t.as_str()) {
                return Err(crate::common::invalid_input(format!(
                    "The request is rejected because the finding type {t} is invalid."
                )));
            }
        }
        let account = ctx.caller.account_id.clone();
        let findings = {
            let state = self.lock();
            let det = Self::owned(&state, ctx, &input.detector_id)?;
            wanted
                .iter()
                .map(|t| {
                    let id = stable_id(&["sample", &account, &ctx.region, &det.id, t]);
                    sample(ctx, &account, &det.id, t, det.findings.get(&id))
                })
                .collect::<Vec<_>>()
        };
        self.record_findings(ctx, &account, findings);
        Ok(Default::default())
    }
}
