//! What EKS creates and reads in the account outside EKS itself: subnets
//! and VPCs, security groups, instance profiles and node instances. AWS does
//! this through EC2, IAM and Auto Scaling as the EKS service-linked roles;
//! the composition root implements it on the services MWS has.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

/// The account and Region a call acts in.
#[derive(Debug, Clone)]
pub struct Scope<'a> {
    pub account: &'a str,
    pub region: &'a str,
    pub partition: &'a str,
    pub now: DateTime<Utc>,
}

/// A subnet as EKS needs to know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetFacts {
    pub subnet_id: String,
    pub vpc_id: String,
    pub availability_zone: String,
    /// The VPC's primary IPv4 CIDR block (EKS picks the service CIDR so it
    /// does not overlap).
    pub vpc_cidr: Option<String>,
}

/// An error from the service EKS called, as AWS reports it inside EKS
/// errors: `(Service: AmazonEC2; Status Code: 400; Error Code: ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfrastructureError {
    /// `AmazonEC2`, `AmazonIdentityManagement`, ...
    pub service: String,
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for InfrastructureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (Service: {}; Status Code: {}; Error Code: {}; Request ID: {}; Proxy: null)",
            self.message,
            self.service,
            self.status,
            self.code,
            uuid::Uuid::new_v4()
        )
    }
}

/// What a managed node group runs: EKS's launch template and the Auto
/// Scaling group built from it.
#[derive(Debug, Clone, Default)]
pub struct NodeGroupSpec {
    pub cluster_name: String,
    pub nodegroup_name: String,
    /// The node group's Auto Scaling group name (`eks-<nodegroup>-<uuid>`).
    pub group_name: String,
    /// The EKS-managed launch template's name (`eks-<uuid>`).
    pub template_name: String,
    /// The EKS-optimized AMI; `None` when the source launch template names
    /// its own (custom AMIs).
    pub image_id: Option<String>,
    /// Instance types for the group's overrides; empty when the source
    /// launch template names one.
    pub instance_types: Vec<String>,
    /// `ON_DEMAND`, `SPOT` or `CAPACITY_BLOCK`.
    pub capacity_type: String,
    pub subnets: Vec<String>,
    pub min_size: i32,
    pub max_size: i32,
    pub desired_size: i32,
    /// Used unless the source launch template names security groups.
    pub security_group_ids: Vec<String>,
    pub instance_profile_arn: Option<String>,
    pub key_name: Option<String>,
    pub disk_size_gib: Option<i32>,
    /// The customer's launch template, which EKS copies into its own.
    pub source_template: Option<LaunchTemplateRef>,
    /// Tags on the group, propagated to its instances.
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct LaunchTemplateRef {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

/// The launch template EKS made for a node group.
#[derive(Debug, Clone, Default)]
pub struct NodeGroupTemplate {
    pub id: String,
    pub version: String,
}

/// A node group's Auto Scaling group as it is now.
#[derive(Debug, Clone, Default)]
pub struct GroupState {
    pub min_size: i32,
    pub max_size: i32,
    pub desired_capacity: i32,
    /// Instances that are not leaving the group.
    pub instance_ids: Vec<String>,
    pub suspended_processes: Vec<String>,
}

#[async_trait::async_trait]
pub trait Infrastructure: Send + Sync {
    /// The named subnets, in the order given; an error names a missing one.
    async fn subnets(&self, scope: &Scope<'_>, ids: &[String]) -> Result<Vec<SubnetFacts>, InfrastructureError>;

    /// Check that the security groups exist.
    async fn security_groups_exist(&self, scope: &Scope<'_>, ids: &[String]) -> Result<(), InfrastructureError>;

    /// Create a security group in `vpc_id`. With `self_ingress`, members of
    /// the group may reach each other on every port (the cluster security
    /// group); with `ssh_from_anywhere`, port 22 is open to the world (the
    /// remote access group).
    #[allow(clippy::too_many_arguments)]
    async fn create_security_group(
        &self,
        scope: &Scope<'_>,
        vpc_id: &str,
        name: &str,
        description: &str,
        tags: &BTreeMap<String, String>,
        self_ingress: bool,
        ssh_from_anywhere: bool,
    ) -> Result<String, InfrastructureError>;

    async fn delete_security_group(&self, scope: &Scope<'_>, group_id: &str) -> Result<(), InfrastructureError>;

    /// The image a managed node group of `ami_type` runs for Kubernetes
    /// `version` (the EKS-optimized AMI, or the closest image there is).
    async fn node_image(&self, scope: &Scope<'_>, version: &str, ami_type: &str) -> Option<String>;

    /// Create an instance profile holding the node role; returns its ARN.
    async fn create_instance_profile(
        &self,
        scope: &Scope<'_>,
        name: &str,
        role_arn: &str,
    ) -> Result<String, InfrastructureError>;

    async fn delete_instance_profile(&self, scope: &Scope<'_>, name: &str, role_arn: &str);

    /// Create the node group's launch template and Auto Scaling group.
    async fn create_node_group(
        &self,
        scope: &Scope<'_>,
        spec: &NodeGroupSpec,
    ) -> Result<NodeGroupTemplate, InfrastructureError>;

    /// Change the group's size.
    async fn scale_node_group(
        &self,
        scope: &Scope<'_>,
        group: &str,
        min: i32,
        max: i32,
        desired: i32,
    ) -> Result<(), InfrastructureError>;

    /// A new version of the node group's launch template from `spec`, and
    /// every node replaced from it. Returns the new version.
    async fn roll_node_group(
        &self,
        scope: &Scope<'_>,
        spec: &NodeGroupSpec,
        template_id: &str,
    ) -> Result<String, InfrastructureError>;

    /// The group, or `None` when it no longer exists.
    async fn node_group_state(&self, scope: &Scope<'_>, group: &str) -> Option<GroupState>;

    /// Delete the group (terminating its instances) and the launch template.
    async fn delete_node_group(&self, scope: &Scope<'_>, group: &str, template_id: Option<&str>);
}
