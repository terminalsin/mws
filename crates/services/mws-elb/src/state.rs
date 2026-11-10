//! Control-plane state: every load balancer, listener, rule, target group
//! and trust store, per account and Region. What the data plane observes
//! (health check results, bound sockets) lives in [`crate::data`] and
//! [`crate::health`] and is rebuilt from this after a restart.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::classic_api::types as ct;
use crate::v2::types as t;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By `account|region`.
    pub regions: BTreeMap<String, RegionState>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}|{region}")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    pub load_balancers: BTreeMap<String, LoadBalancerRecord>,
    pub listeners: BTreeMap<String, ListenerRecord>,
    pub rules: BTreeMap<String, RuleRecord>,
    pub target_groups: BTreeMap<String, TargetGroupRecord>,
    pub trust_stores: BTreeMap<String, TrustStoreRecord>,
    /// ELBv2 tags by resource ARN, in the order they were added.
    pub tags: BTreeMap<String, Vec<t::Tag>>,
    /// Classic Load Balancers by name.
    pub classic: BTreeMap<String, ClassicLoadBalancer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoadBalancerRecord {
    pub lb: t::LoadBalancer,
    pub attributes: BTreeMap<String, String>,
    /// `MinimumLoadBalancerCapacity` set by `ModifyCapacityReservation`.
    pub capacity_units: Option<i32>,
    pub capacity_modified_at: Option<DateTime<Utc>>,
    pub capacity_decreases: Vec<DateTime<Utc>>,
    /// The requester-managed network interface in each enabled subnet, by
    /// subnet id.
    pub network_interfaces: BTreeMap<String, String>,
}

impl LoadBalancerRecord {
    pub fn arn(&self) -> &str {
        self.lb.load_balancer_arn.as_deref().unwrap_or_default()
    }
    pub fn ty(&self) -> &str {
        self.lb.r#type.as_deref().unwrap_or("application")
    }
    pub fn name(&self) -> &str {
        self.lb.load_balancer_name.as_deref().unwrap_or_default()
    }
    pub fn zones(&self) -> Vec<String> {
        self.lb.availability_zones.iter().flatten().filter_map(|z| z.zone_name.clone()).collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ListenerRecord {
    pub listener: t::Listener,
    pub attributes: BTreeMap<String, String>,
    /// Certificates added with `AddListenerCertificates` (not the default).
    pub extra_certificates: Vec<String>,
    /// The default rule's ARN.
    pub default_rule_arn: String,
}

impl ListenerRecord {
    pub fn arn(&self) -> &str {
        self.listener.listener_arn.as_deref().unwrap_or_default()
    }
    pub fn lb_arn(&self) -> &str {
        self.listener.load_balancer_arn.as_deref().unwrap_or_default()
    }
    pub fn protocol(&self) -> &str {
        self.listener.protocol.as_deref().unwrap_or_default()
    }
    pub fn port(&self) -> i32 {
        self.listener.port.unwrap_or_default()
    }
    pub fn default_certificate(&self) -> Option<&str> {
        self.listener.certificates.iter().flatten().find_map(|c| c.certificate_arn.as_deref())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleRecord {
    pub rule: t::Rule,
    pub listener_arn: String,
}

impl RuleRecord {
    pub fn arn(&self) -> &str {
        self.rule.rule_arn.as_deref().unwrap_or_default()
    }
    pub fn is_default(&self) -> bool {
        self.rule.is_default == Some(true)
    }
    /// The numeric priority; the default rule sorts last.
    pub fn priority(&self) -> i64 {
        self.rule.priority.as_deref().and_then(|p| p.parse().ok()).unwrap_or(i64::MAX)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TargetGroupRecord {
    pub tg: t::TargetGroup,
    pub attributes: BTreeMap<String, String>,
    pub targets: Vec<RegisteredTarget>,
}

impl TargetGroupRecord {
    pub fn arn(&self) -> &str {
        self.tg.target_group_arn.as_deref().unwrap_or_default()
    }
    pub fn name(&self) -> &str {
        self.tg.target_group_name.as_deref().unwrap_or_default()
    }
    pub fn target_type(&self) -> &str {
        self.tg.target_type.as_deref().unwrap_or("instance")
    }
    pub fn protocol(&self) -> &str {
        self.tg.protocol.as_deref().unwrap_or_default()
    }
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RegisteredTarget {
    pub id: String,
    pub port: i32,
    pub availability_zone: Option<String>,
    pub registered_at: Option<DateTime<Utc>>,
    /// Set while deregistration delay runs.
    pub draining_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustStoreRecord {
    pub store: t::TrustStore,
    pub bundle_pem: String,
    pub bundle_source: (String, String, Option<String>),
    pub revocations: Vec<Revocation>,
    pub next_revocation_id: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Revocation {
    pub id: i64,
    pub ty: String,
    pub source: (String, String, Option<String>),
    /// Revoked serial numbers (hex, lower case).
    pub serials: Vec<String>,
    /// The CRL itself (DER), which listeners check client certificates
    /// against.
    pub crl: Vec<u8>,
}

// ---- Classic Load Balancers ---------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassicLoadBalancer {
    pub description: ct::LoadBalancerDescription,
    pub attributes: ct::LoadBalancerAttributes,
    pub policies: Vec<ct::PolicyDescription>,
    pub tags: Vec<ct::Tag>,
    /// Registered instance ids, in registration order.
    pub instances: Vec<String>,
}

impl ClassicLoadBalancer {
    pub fn name(&self) -> &str {
        self.description.load_balancer_name.as_deref().unwrap_or_default()
    }
}
