//! Global Accelerator state. The service is global: accelerators live in
//! their owner's account with no Region. Times are epoch milliseconds on
//! the emulated clock.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// How long an accelerator stays `IN_PROGRESS` after a change, and a BYOIP
/// address range in a `PENDING_*` state, in milliseconds.
pub fn transition_ms() -> i64 {
    mws_core::settle::window_ms(1_000)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By accelerator ARN (standard and custom routing).
    pub accelerators: BTreeMap<String, Accelerator>,
    /// Cross-account attachments by ARN.
    pub attachments: BTreeMap<String, Attachment>,
    /// BYOIP address ranges by `{account}/{cidr}`.
    pub byoip: BTreeMap<String, ByoipCidr>,
    /// Every static IP address an accelerator holds, across accounts.
    pub used_ips: BTreeSet<String>,
    /// Idempotency tokens: `{account}/{operation}/{token}` to the ARN made.
    pub idempotency: BTreeMap<String, String>,
    /// Creation order, for listings.
    pub sequence: u64,
}

impl State {
    pub fn next_seq(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Finish the transitions whose time has come.
    pub fn settle(&mut self, now: i64) {
        for a in self.accelerators.values_mut() {
            if a.status == "IN_PROGRESS" && a.settles_at <= now {
                a.status = "DEPLOYED".into();
            }
        }
        for c in self.byoip.values_mut() {
            if let Some(next) = &c.pending {
                if c.settles_at <= now {
                    let message = match c.state.as_str() {
                        "PENDING_PROVISIONING" => "Successfully provisioned the address range.",
                        "PENDING_ADVERTISING" => "Successfully advertised the address range.",
                        "PENDING_WITHDRAWING" => "Successfully withdrew the address range from advertising.",
                        "PENDING_DEPROVISIONING" => "Successfully deprovisioned the address range.",
                        _ => "",
                    };
                    c.state = next.clone();
                    c.pending = None;
                    if !message.is_empty() {
                        c.events.push(Event { message: message.into(), timestamp: c.settles_at });
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    pub message: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Accelerator {
    pub arn: String,
    pub account: String,
    pub seq: u64,
    /// A custom routing accelerator.
    pub custom: bool,
    pub name: String,
    /// `IPV4` or `DUAL_STACK`.
    pub ip_address_type: String,
    pub enabled: bool,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// The addresses that came from BYOIP ranges (the caller's or shared).
    pub byoip_ips: Vec<String>,
    pub dns_name: String,
    pub dual_stack_dns_name: Option<String>,
    /// `DEPLOYED` or `IN_PROGRESS`.
    pub status: String,
    pub settles_at: i64,
    pub created: i64,
    pub modified: i64,
    pub tags: BTreeMap<String, String>,
    pub flow_logs_enabled: bool,
    pub flow_logs_bucket: Option<String>,
    pub flow_logs_prefix: Option<String>,
    pub listeners: BTreeMap<String, Listener>,
    pub events: Vec<Event>,
}

impl Accelerator {
    /// A change was made: the accelerator deploys it.
    pub fn touch(&mut self, now: i64) {
        self.status = "IN_PROGRESS".into();
        self.settles_at = now + transition_ms();
        self.modified = now;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortRange {
    pub from: i32,
    pub to: i32,
}

impl PortRange {
    pub fn len(&self) -> u32 {
        (self.to - self.from + 1) as u32
    }

    pub fn overlaps(&self, other: &PortRange) -> bool {
        self.from <= other.to && other.from <= self.to
    }

    pub fn contains(&self, port: i32) -> bool {
        self.from <= port && port <= self.to
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Listener {
    pub arn: String,
    pub seq: u64,
    /// `TCP` or `UDP`; empty for custom routing listeners.
    pub protocol: String,
    pub client_affinity: String,
    pub port_ranges: Vec<PortRange>,
    pub groups: BTreeMap<String, EndpointGroup>,
}

impl Listener {
    pub fn port_count(&self) -> u32 {
        self.port_ranges.iter().map(PortRange::len).sum()
    }

    /// The `index`th port of the listener's ranges, in ascending order.
    pub fn port_at(&self, mut index: u32) -> Option<i32> {
        let mut ranges = self.port_ranges.clone();
        ranges.sort_by_key(|r| r.from);
        for r in ranges {
            if index < r.len() {
                return Some(r.from + index as i32);
            }
            index -= r.len();
        }
        None
    }

    pub fn contains_port(&self, port: i32) -> bool {
        self.port_ranges.iter().any(|r| r.contains(port))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointGroup {
    pub arn: String,
    pub seq: u64,
    pub region: String,
    pub endpoints: Vec<Endpoint>,
    pub traffic_dial: f32,
    pub health_check_port: Option<i32>,
    pub health_check_protocol: String,
    pub health_check_path: Option<String>,
    pub health_check_interval: i32,
    pub threshold_count: i32,
    pub port_overrides: Vec<(i32, i32)>,
    /// Custom routing: the destination port ranges and their protocols.
    pub destinations: Vec<Destination>,
}

impl EndpointGroup {
    /// Custom routing: the destination ports in mapping order, each with
    /// its protocols.
    pub fn destination_ports(&self) -> Vec<(i32, Vec<String>)> {
        self.destinations.iter().flat_map(|d| (d.from..=d.to).map(move |p| (p, d.protocols.clone()))).collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Destination {
    pub from: i32,
    pub to: i32,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Endpoint {
    pub id: String,
    /// The account that owns the endpoint (another one through a
    /// cross-account attachment).
    pub owner: String,
    pub attachment_arn: Option<String>,
    pub weight: i32,
    pub client_ip_preservation: bool,
    /// When it was added (health checks start then).
    pub added: i64,
    /// Custom routing: the subnet's IPv4 CIDR block.
    pub cidr: Option<String>,
    /// Custom routing: the first listener port index of this subnet's block.
    pub port_base: u32,
    /// Custom routing: traffic to every destination is allowed.
    pub allow_all: bool,
    /// Custom routing: allow/deny rules applied in order after `allow_all`.
    pub traffic_rules: Vec<TrafficRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficRule {
    pub allow: bool,
    /// `None`: every address in the subnet.
    pub addresses: Option<Vec<String>>,
    /// `None`: every destination port.
    pub ports: Option<Vec<i32>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Attachment {
    pub arn: String,
    pub account: String,
    pub seq: u64,
    pub name: String,
    pub principals: Vec<String>,
    pub resources: Vec<AttachmentResource>,
    pub created: i64,
    pub modified: i64,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttachmentResource {
    pub endpoint_id: Option<String>,
    pub cidr: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ByoipCidr {
    pub account: String,
    pub cidr: String,
    pub seq: u64,
    pub state: String,
    /// The state a `PENDING_*` state settles into.
    pub pending: Option<String>,
    pub settles_at: i64,
    pub events: Vec<Event>,
}
