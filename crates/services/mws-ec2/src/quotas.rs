//! Service Quotas: the limits EC2 enforces (On-Demand vCPUs by instance
//! class, Elastic IPs, VPCs, subnets, internet and NAT gateways, security
//! groups and their rules, routes, network ACL rules) and the usage it
//! reports back.

use chrono::{DateTime, Utc};

use crate::ops::instance::state_name;
use crate::state::RegionState;
use crate::{catalog, Ec2, State};

pub(crate) const ELASTIC_IPS: (&str, &str) = ("ec2", "L-0263D0A3");
pub(crate) const VPCS: (&str, &str) = ("vpc", "L-F678F1CE");
pub(crate) const RULES_PER_GROUP: (&str, &str) = ("vpc", "L-0EA8095F");
pub(crate) const SUBNETS_PER_VPC: (&str, &str) = ("vpc", "L-407747CB");
pub(crate) const INTERNET_GATEWAYS: (&str, &str) = ("vpc", "L-A4707A72");
pub(crate) const SECURITY_GROUPS: (&str, &str) = ("vpc", "L-E79EC296");
pub(crate) const GROUPS_PER_INTERFACE: (&str, &str) = ("vpc", "L-2AFB9258");
pub(crate) const NAT_GATEWAYS_PER_AZ: (&str, &str) = ("vpc", "L-FE5A380F");
pub(crate) const ROUTES_PER_TABLE: (&str, &str) = ("vpc", "L-93826ACB");
pub(crate) const RULES_PER_ACL: (&str, &str) = ("vpc", "L-2AEEBF1A");

/// Every Running On-Demand vCPU quota.
pub(crate) const VCPU_QUOTAS: &[&str] = &[
    "L-1216C47A",
    "L-DB2E81BA",
    "L-417A185B",
    "L-7295265B",
    "L-74FC7D96",
    "L-1945791B",
    "L-6E869C2A",
    "L-2C3B7624",
    "L-F7808C92",
    "L-43DA4232",
];

/// The Running On-Demand quota an instance type's vCPUs count against.
pub(crate) fn vcpu_quota(instance_type: &str) -> &'static str {
    let family = instance_type.split('.').next().unwrap_or_default();
    let starts = |p: &str| family.starts_with(p);
    if starts("u-") || starts("u7") {
        "L-43DA4232"
    } else if starts("hpc") {
        "L-F7808C92"
    } else if starts("trn") {
        "L-2C3B7624"
    } else if starts("inf") {
        "L-1945791B"
    } else if starts("dl") {
        "L-6E869C2A"
    } else if starts("g") || starts("vt") {
        "L-DB2E81BA"
    } else if starts("p") {
        "L-417A185B"
    } else if starts("x") {
        "L-7295265B"
    } else if starts("f") {
        "L-74FC7D96"
    } else {
        "L-1216C47A"
    }
}

/// vCPUs of pending and running instances whose type counts against
/// `quota`.
pub(crate) fn running_vcpus(r: &RegionState, quota: &str) -> f64 {
    r.instances
        .values()
        .filter(|i| matches!(state_name(i).as_str(), "pending" | "running"))
        .filter_map(|i| i.instance.instance_type.as_deref())
        .filter(|ty| vcpu_quota(ty) == quota)
        .filter_map(catalog::instance_type)
        .map(|t| t.vcpus as f64)
        .sum()
}

impl Ec2 {
    /// Read applied quota values from Service Quotas (defaults otherwise).
    pub fn set_service_quotas(&self, quotas: mws_servicequotas::ServiceQuotas) {
        let _ = self.inner.quotas.set(quotas);
    }

    /// The applied value of a quota. Never call with the EC2 state lock
    /// held.
    pub(crate) fn quota(&self, account: &str, region: &str, (service, code): (&str, &str), now: DateTime<Utc>) -> f64 {
        match self.inner.quotas.get() {
            Some(q) => q.applied_value(account, region, service, code, now),
            None => {
                mws_servicequotas::catalog::quota(service, code).map(|d| d.default_in(region)).unwrap_or(f64::INFINITY)
            }
        }
    }

    /// Current usage of a quota EC2 measures, for Service Quotas.
    pub fn quota_usage(&self, account: &str, region: &str, service: &str, code: &str) -> Option<f64> {
        let state = self.lock();
        let r = state.regions.get(&State::key(account, region));
        match (service, code) {
            ("ec2", c) if c == ELASTIC_IPS.1 => Some(r.map_or(0, |r| r.addresses.len()) as f64),
            ("vpc", c) if c == VPCS.1 => Some(r.map_or(1, |r| r.vpcs.len()) as f64),
            ("ec2", c)
                if mws_servicequotas::catalog::quota("ec2", c).is_some_and(|d| {
                    d.usage.is_some_and(|u| u.dimensions.iter().any(|(_, v)| v.ends_with("/OnDemand")))
                }) =>
            {
                Some(r.map_or(0.0, |r| running_vcpus(r, c)))
            }
            _ => None,
        }
    }
}
