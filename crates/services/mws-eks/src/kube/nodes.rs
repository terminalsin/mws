//! The Node objects a managed node group's instances appear as.
//!
//! Instances don't run a kubelet, so EKS registers each one itself: a
//! Ready node named for the instance's private DNS name, with the labels
//! and taints a managed node group's nodes carry on EKS.

use std::collections::BTreeMap;

use super::NodeObject;
use crate::catalog;
use crate::generated::types;
use crate::infra::InstanceFacts;

/// vCPUs, memory (GiB) and max pods (the VPC CNI's limit) of common
/// instance types.
fn capacity(instance_type: &str) -> (u32, u32, u32) {
    match instance_type {
        "t3.micro" | "t4g.micro" => (2, 1, 4),
        "t3.small" | "t4g.small" => (2, 2, 11),
        "t3.medium" | "t4g.medium" => (2, 4, 17),
        "t3.large" | "t4g.large" => (2, 8, 35),
        "t3.xlarge" | "t4g.xlarge" => (4, 16, 58),
        "t3.2xlarge" | "t4g.2xlarge" => (8, 32, 58),
        t if t.ends_with(".large") => (2, 8, 29),
        t if t.ends_with(".xlarge") => (4, 16, 58),
        t if t.ends_with(".2xlarge") => (8, 32, 58),
        t if t.ends_with(".4xlarge") => (16, 64, 234),
        _ => (2, 4, 17),
    }
}

/// The node objects for `ng`'s `instances` in a cluster in `region`.
pub(crate) fn node_objects(ng: &types::Nodegroup, region: &str, instances: &[InstanceFacts]) -> Vec<NodeObject> {
    let name = ng.nodegroup_name.clone().unwrap_or_default();
    let version = ng.version.clone().unwrap_or_default();
    let patch = catalog::version(&version).map(|v| v.patch).unwrap_or("1.34.2");
    let taints: Vec<(String, Option<String>, String)> = ng
        .taints
        .iter()
        .flatten()
        .map(|t| {
            let effect = match t.effect.as_deref() {
                Some("NO_EXECUTE") => "NoExecute",
                Some("PREFER_NO_SCHEDULE") => "PreferNoSchedule",
                _ => "NoSchedule",
            };
            (t.key.clone().unwrap_or_default(), t.value.clone(), effect.to_string())
        })
        .collect();
    instances
        .iter()
        .map(|i| {
            let arch = if catalog::instance_arch(&i.instance_type) == "arm64" { "arm64" } else { "amd64" };
            let mut labels: BTreeMap<String, String> = ng.labels.clone().unwrap_or_default().into_iter().collect();
            for (k, v) in [
                ("eks.amazonaws.com/nodegroup", name.clone()),
                ("eks.amazonaws.com/capacityType", ng.capacity_type.clone().unwrap_or_else(|| "ON_DEMAND".into())),
                ("eks.amazonaws.com/nodegroup-image", i.image_id.clone()),
                ("node.kubernetes.io/instance-type", i.instance_type.clone()),
                ("beta.kubernetes.io/instance-type", i.instance_type.clone()),
                ("topology.kubernetes.io/zone", i.availability_zone.clone()),
                ("failure-domain.beta.kubernetes.io/zone", i.availability_zone.clone()),
                ("topology.kubernetes.io/region", region.to_string()),
                ("failure-domain.beta.kubernetes.io/region", region.to_string()),
                ("kubernetes.io/arch", arch.to_string()),
                ("beta.kubernetes.io/arch", arch.to_string()),
                ("kubernetes.io/os", "linux".to_string()),
                ("beta.kubernetes.io/os", "linux".to_string()),
                ("kubernetes.io/hostname", i.private_dns_name.clone()),
                ("k8s.io/cloud-provider-aws", "12b0fd1c5d8d8f5d8f1a3b0e8c2a7f60".to_string()),
            ] {
                labels.insert(k.to_string(), v);
            }
            let (cpu, memory, pods) = capacity(&i.instance_type);
            NodeObject {
                name: i.private_dns_name.clone(),
                provider_id: format!("aws:///{}/{}", i.availability_zone, i.instance_id),
                labels,
                taints: taints.clone(),
                internal_ip: i.private_ip.clone(),
                kubelet_version: format!("v{patch}-eks-3025e55"),
                cpu: cpu.to_string(),
                memory: format!("{}Ki", u64::from(memory) * 1024 * 1024 - 400 * 1024),
                pods: pods.to_string(),
            }
        })
        .collect()
}
