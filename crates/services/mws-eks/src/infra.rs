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

/// Instances to start for a node group.
#[derive(Debug, Clone)]
pub struct NodeLaunch {
    pub cluster_name: String,
    pub nodegroup_name: String,
    /// The node group's Auto Scaling group name.
    pub group_name: String,
    pub image_id: String,
    pub instance_type: String,
    /// Subnets to spread the instances over, in order.
    pub subnets: Vec<String>,
    pub count: usize,
    pub security_group_ids: Vec<String>,
    pub instance_profile_arn: Option<String>,
    pub key_name: Option<String>,
    pub disk_size_gib: Option<i32>,
    pub tags: BTreeMap<String, String>,
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

    /// Start instances; returns their ids.
    async fn launch(&self, scope: &Scope<'_>, launch: &NodeLaunch) -> Result<Vec<String>, InfrastructureError>;

    async fn terminate(&self, scope: &Scope<'_>, instance_ids: &[String]);
}
