//! Inventory: `PutInventory` and what State Manager's
//! `AWS-GatherSoftwareInventory` collects from managed nodes (installed
//! applications and network interfaces, read from the node), plus the
//! `AWS:InstanceInformation` every managed node reports. `GetInventory`
//! filters and aggregates it, `ListInventoryEntries` pages one type of one
//! node, custom types define their schema on first put, and
//! `DeleteInventory` removes a custom type everywhere.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::commands::{ManagedNode, AGENT_VERSION};
use crate::generated::{errors, types};
use crate::names::{now, page};
use crate::Ssm;

/// One inventory type collected from one node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ItemRecord {
    pub schema_version: String,
    pub capture_time: String,
    pub content_hash: Option<String>,
    pub content: Vec<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryState {
    /// Node id -> type name -> item.
    pub items: BTreeMap<String, BTreeMap<String, ItemRecord>>,
    /// Custom types' attributes, from the first item put.
    pub custom_schemas: BTreeMap<String, (String, Vec<String>)>,
    /// Newest first.
    pub deletions: Vec<types::InventoryDeletionStatusItem>,
}

/// An inventory type: name, schema version and attributes (with types).
type TypeDef = (&'static str, &'static str, &'static [(&'static str, &'static str)]);
/// Inventory content: one map of attributes per entry.
type Content = Vec<BTreeMap<String, String>>;

/// AWS-defined inventory types and their attributes.
const AWS_TYPES: &[TypeDef] = &[
    (
        "AWS:InstanceInformation",
        "1.0",
        &[
            ("AgentType", "string"),
            ("AgentVersion", "string"),
            ("ComputerName", "string"),
            ("InstanceId", "string"),
            ("IpAddress", "string"),
            ("PlatformName", "string"),
            ("PlatformType", "string"),
            ("PlatformVersion", "string"),
            ("ResourceType", "string"),
            ("InstanceStatus", "string"),
        ],
    ),
    (
        "AWS:Application",
        "1.1",
        &[
            ("Name", "string"),
            ("ApplicationType", "string"),
            ("Publisher", "string"),
            ("Version", "string"),
            ("Release", "string"),
            ("Epoch", "string"),
            ("InstalledTime", "string"),
            ("Architecture", "string"),
            ("URL", "string"),
            ("Summary", "string"),
            ("PackageId", "string"),
        ],
    ),
    (
        "AWS:Network",
        "1.0",
        &[
            ("Name", "string"),
            ("SubnetMask", "string"),
            ("Gateway", "string"),
            ("DHCPServer", "string"),
            ("DNSServer", "string"),
            ("MacAddress", "string"),
            ("IPV4", "string"),
            ("IPV6", "string"),
        ],
    ),
    (
        "AWS:PatchSummary",
        "1.0",
        &[
            ("PatchGroup", "string"),
            ("BaselineId", "string"),
            ("SnapshotId", "string"),
            ("OwnerInformation", "string"),
            ("InstalledCount", "number"),
            ("InstalledOtherCount", "number"),
            ("InstalledPendingRebootCount", "number"),
            ("InstalledRejectedCount", "number"),
            ("NotApplicableCount", "number"),
            ("MissingCount", "number"),
            ("FailedCount", "number"),
            ("OperationType", "string"),
            ("OperationStartTime", "string"),
            ("OperationEndTime", "string"),
            ("RebootOption", "string"),
        ],
    ),
    (
        "AWS:ComplianceItem",
        "1.0",
        &[
            ("ComplianceType", "string"),
            ("ExecutionId", "string"),
            ("ExecutionType", "string"),
            ("ExecutionTime", "string"),
            ("Id", "string"),
            ("Title", "string"),
            ("Status", "string"),
            ("Severity", "string"),
            ("DocumentName", "string"),
            ("DocumentVersion", "string"),
            ("Classification", "string"),
            ("PatchBaselineId", "string"),
            ("PatchSeverity", "string"),
            ("PatchState", "string"),
            ("PatchGroup", "string"),
            ("InstalledTime", "string"),
        ],
    ),
    (
        "AWS:ComplianceSummary",
        "1.0",
        &[
            ("ComplianceType", "string"),
            ("PatchGroup", "string"),
            ("PatchBaselineId", "string"),
            ("Status", "string"),
            ("OverallSeverity", "string"),
            ("ExecutionId", "string"),
            ("ExecutionType", "string"),
            ("ExecutionTime", "string"),
            ("CompliantCriticalCount", "number"),
            ("CompliantHighCount", "number"),
            ("CompliantMediumCount", "number"),
            ("CompliantLowCount", "number"),
            ("CompliantInformationalCount", "number"),
            ("CompliantUnspecifiedCount", "number"),
            ("NonCompliantCriticalCount", "number"),
            ("NonCompliantHighCount", "number"),
            ("NonCompliantMediumCount", "number"),
            ("NonCompliantLowCount", "number"),
            ("NonCompliantInformationalCount", "number"),
            ("NonCompliantUnspecifiedCount", "number"),
        ],
    ),
    ("AWS:Tag", "1.0", &[("Key", "string"), ("Value", "string")]),
    (
        "AWS:Service",
        "1.0",
        &[
            ("Name", "string"),
            ("DisplayName", "string"),
            ("ServiceType", "string"),
            ("Status", "string"),
            ("DependentServices", "string"),
            ("ServicesDependedOn", "string"),
            ("StartType", "string"),
        ],
    ),
    (
        "AWS:File",
        "1.0",
        &[
            ("Name", "string"),
            ("Size", "string"),
            ("Description", "string"),
            ("FileVersion", "string"),
            ("InstalledDate", "string"),
            ("ModificationTime", "string"),
            ("LastAccessTime", "string"),
            ("ProductName", "string"),
            ("InstalledDir", "string"),
            ("ProductLanguage", "string"),
            ("CompanyName", "string"),
            ("ProductVersion", "string"),
        ],
    ),
];

fn aws_type(name: &str) -> Option<&'static TypeDef> {
    AWS_TYPES.iter().find(|(n, _, _)| *n == name)
}

fn iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// `AWS:InstanceInformation` of a node.
fn instance_information(n: &ManagedNode, at: DateTime<Utc>) -> ItemRecord {
    let mut c = BTreeMap::new();
    c.insert("AgentType".into(), "amazon-ssm-agent".into());
    c.insert("AgentVersion".into(), AGENT_VERSION.into());
    c.insert("ComputerName".into(), n.computer_name.clone().unwrap_or_else(|| n.instance_id.clone()));
    c.insert("InstanceId".into(), n.instance_id.clone());
    c.insert("IpAddress".into(), n.ip_address.clone().unwrap_or_default());
    c.insert("PlatformName".into(), n.platform_name.clone());
    c.insert("PlatformType".into(), n.platform_type.clone());
    c.insert("PlatformVersion".into(), n.platform_version.clone());
    c.insert("ResourceType".into(), "EC2Instance".into());
    c.insert("InstanceStatus".into(), if n.ping_status == "Online" { "Active" } else { "Stopped" }.into());
    ItemRecord { schema_version: "1.0".into(), capture_time: iso(at), content_hash: None, content: vec![c] }
}

/// Whether an attribute value passes a filter.
fn passes(value: Option<&String>, kind: &str, values: &[String]) -> bool {
    match kind {
        "Exists" => value.is_some(),
        "NotEqual" => value.is_some_and(|v| !values.contains(v)),
        "BeginWith" => value.is_some_and(|v| values.iter().any(|p| v.starts_with(p.as_str()))),
        "LessThan" | "GreaterThan" => value.is_some_and(|v| {
            values.iter().any(|x| {
                let ord = match (v.parse::<f64>(), x.parse::<f64>()) {
                    (Ok(a), Ok(b)) => a.partial_cmp(&b),
                    _ => Some(v.as_str().cmp(x.as_str())),
                };
                if kind == "LessThan" {
                    ord == Some(std::cmp::Ordering::Less)
                } else {
                    ord == Some(std::cmp::Ordering::Greater)
                }
            })
        }),
        _ => value.is_some_and(|v| values.contains(v)),
    }
}

/// A shell script that prints a node's software and network inventory
/// as tab-separated `A` (application) and `N` (network) lines.
pub(crate) const INVENTORY_SCRIPT: &str = r#"
if command -v rpm >/dev/null 2>&1; then
  rpm -qa --queryformat 'A\t%{NAME}\t%{VERSION}\t%{RELEASE}\t%{EPOCH}\t%{ARCH}\t%{INSTALLTIME}\t%{VENDOR}\t%{URL}\t%{SUMMARY}\n' 2>/dev/null
elif command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='A\t${Package}\t${Version}\t\t\t${Architecture}\t\t${Maintainer}\t${Homepage}\t${binary:Summary}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | sed 's/^\(.*\)-\([0-9][^-]*\)-\(r[0-9]*\)$/A\t\1\t\2\t\3\t\t\t\t\t\t/'
fi
for d in /sys/class/net/*; do
  n=$(basename "$d"); [ "$n" = lo ] && continue
  mac=$(cat "$d/address" 2>/dev/null)
  v4=$(ip -o -4 addr show dev "$n" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)
  v6=$(ip -o -6 addr show dev "$n" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)
  gw=$(ip route show default dev "$n" 2>/dev/null | awk '{print $3; exit}')
  dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, -)
  printf 'N\t%s\t%s\t%s\t%s\t%s\n' "$n" "$mac" "$v4" "$v6" "$gw,$dns"
done
"#;

/// Parse what [`INVENTORY_SCRIPT`] printed into `AWS:Application` and
/// `AWS:Network` content.
pub(crate) fn parse_inventory(out: &str) -> (Content, Content) {
    let mut apps = Vec::new();
    let mut nets = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| f.get(i).map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "(none)").unwrap_or("");
        match f.first() {
            Some(&"A") if f.len() >= 3 => {
                let mut m = BTreeMap::new();
                m.insert("Name".to_string(), get(1).to_string());
                m.insert("Version".to_string(), get(2).to_string());
                m.insert("Release".to_string(), get(3).to_string());
                m.insert("Epoch".to_string(), get(4).to_string());
                m.insert("Architecture".to_string(), get(5).to_string());
                let installed = get(6)
                    .parse::<i64>()
                    .ok()
                    .and_then(|s| DateTime::from_timestamp(s, 0))
                    .map(iso)
                    .unwrap_or_default();
                m.insert("InstalledTime".to_string(), installed);
                m.insert("Publisher".to_string(), get(7).to_string());
                m.insert("URL".to_string(), get(8).to_string());
                m.insert("Summary".to_string(), get(9).to_string());
                m.insert("ApplicationType".to_string(), String::new());
                let package =
                    [get(1), get(2), get(3), get(5)].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>();
                m.insert("PackageId".to_string(), package.join("-"));
                m.retain(|_, v| !v.is_empty());
                if m.contains_key("Name") {
                    apps.push(m);
                }
            }
            Some(&"N") if f.len() >= 2 => {
                let mut m = BTreeMap::new();
                m.insert("Name".to_string(), get(1).to_string());
                m.insert("MacAddress".to_string(), get(2).to_string());
                m.insert("IPV4".to_string(), get(3).to_string());
                m.insert("IPV6".to_string(), get(4).to_string());
                let (gw, dns) = get(5).split_once(',').unwrap_or(("", ""));
                m.insert("Gateway".to_string(), gw.to_string());
                m.insert("DNSServer".to_string(), dns.to_string());
                m.retain(|_, v| !v.is_empty());
                nets.push(m);
            }
            _ => {}
        }
    }
    (apps, nets)
}

impl Ssm {
    /// Store an inventory type collected from a node (as the agent does).
    pub(crate) fn record_inventory(
        &self,
        account: &str,
        region: &str,
        instance: &str,
        type_name: &str,
        content: Vec<BTreeMap<String, String>>,
        at: DateTime<Utc>,
    ) {
        let version = aws_type(type_name).map(|t| t.1).unwrap_or("1.0");
        let hash = crate::documents::sha256(&serde_json::to_string(&content).unwrap_or_default());
        self.lock().region(account, region).inventory.items.entry(instance.to_string()).or_default().insert(
            type_name.to_string(),
            ItemRecord { schema_version: version.into(), capture_time: iso(at), content_hash: Some(hash), content },
        );
        self.data_changed(account, region);
    }

    /// Every node's inventory, with `AWS:InstanceInformation` for each
    /// managed node.
    fn inventory_of(
        &self,
        account: &str,
        region: &str,
        at: DateTime<Utc>,
    ) -> BTreeMap<String, BTreeMap<String, ItemRecord>> {
        let nodes = self.nodes_of(account, region);
        let mut all = {
            let st = self.lock();
            st.region_ref(account, region).map(|r| r.inventory.items.clone()).unwrap_or_default()
        };
        for n in &nodes {
            let entry = all.entry(n.instance_id.clone()).or_default();
            entry.entry("AWS:InstanceInformation".into()).or_insert_with(|| instance_information(n, at));
            if !n.tags.is_empty() {
                entry.entry("AWS:Tag".into()).or_insert_with(|| ItemRecord {
                    schema_version: "1.0".into(),
                    capture_time: iso(at),
                    content_hash: None,
                    content: n
                        .tags
                        .iter()
                        .map(|(k, v)| {
                            BTreeMap::from([("Key".to_string(), k.clone()), ("Value".to_string(), v.clone())])
                        })
                        .collect(),
                });
            }
        }
        all
    }

    /// Every node's inventory by type, for resource data syncs: type ->
    /// node -> ((capture time, schema version), content).
    #[allow(clippy::type_complexity)]
    pub(crate) fn inventory_of_all(
        &self,
        account: &str,
        region: &str,
        at: DateTime<Utc>,
    ) -> BTreeMap<String, BTreeMap<String, ((String, String), Content)>> {
        let mut out: BTreeMap<String, BTreeMap<String, ((String, String), Content)>> = BTreeMap::new();
        for (node, types_) in self.inventory_of(account, region, at) {
            for (t, item) in types_ {
                out.entry(t)
                    .or_default()
                    .insert(node.clone(), ((item.capture_time, item.schema_version), item.content));
            }
        }
        out
    }

    pub(crate) fn put_inventory(
        &self,
        ctx: &RequestContext,
        input: types::PutInventoryRequest,
    ) -> Result<types::PutInventoryResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:PutInventory", &arn, ConditionContext::new())?;
        if !self.nodes_of(&ctx.caller.account_id, &ctx.region).iter().any(|n| n.instance_id == input.instance_id) {
            return Err(errors::invalid_instance_id("Invalid instance ID."));
        }
        if input.items.is_empty() || input.items.len() > 30 {
            return Err(errors::validation("Items must contain between 1 and 30 inventory items."));
        }
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        for item in &input.items {
            let custom = item.type_name.starts_with("Custom:");
            if !custom && aws_type(&item.type_name).is_none() {
                return Err(errors::invalid_type_name(format!("The type name {} is not valid.", item.type_name)));
            }
            let content = item.content.clone().unwrap_or_default();
            if content.len() > 10_000 {
                return Err(errors::item_size_limit_exceeded("The inventory item size exceeds the limit."));
            }
            if custom {
                let attrs: Vec<String> = content
                    .iter()
                    .flat_map(|c| c.keys().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                match r.inventory.custom_schemas.get(&item.type_name) {
                    Some((version, _)) if version != &item.schema_version => {
                        return Err(errors::unsupported_inventory_schema_version(format!(
                            "Inventory type {} already uses schema version {version}.",
                            item.type_name
                        )));
                    }
                    Some(_) => {}
                    None => {
                        if r.inventory.custom_schemas.len() >= 20 {
                            return Err(errors::custom_schema_count_limit_exceeded(
                                "You have exceeded the limit for custom schemas.",
                            ));
                        }
                        r.inventory.custom_schemas.insert(item.type_name.clone(), (item.schema_version.clone(), attrs));
                    }
                }
            }
            let entry = r.inventory.items.entry(input.instance_id.clone()).or_default();
            if let (Some(old), Some(new)) =
                (entry.get(&item.type_name).and_then(|o| o.content_hash.clone()), &item.content_hash)
            {
                if &old == new {
                    continue;
                }
            }
            entry.insert(
                item.type_name.clone(),
                ItemRecord {
                    schema_version: item.schema_version.clone(),
                    capture_time: item.capture_time.clone(),
                    content_hash: item.content_hash.clone(),
                    content,
                },
            );
        }
        drop(st);
        self.data_changed(&ctx.caller.account_id, &ctx.region);
        Ok(types::PutInventoryResult { message: Some("Success".into()) })
    }

    pub(crate) fn get_inventory(
        &self,
        ctx: &RequestContext,
        input: types::GetInventoryRequest,
    ) -> Result<types::GetInventoryResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:GetInventory", &list_arn, ConditionContext::new())?;
        let all = self.inventory_of(&ctx.caller.account_id, &ctx.region, now(ctx));
        let filters = input.filters.unwrap_or_default();
        for f in &filters {
            if !f.key.contains('.') {
                return Err(errors::invalid_filter("The filter key must be TypeName.AttributeName."));
            }
        }
        // Nodes whose inventory passes every filter.
        let matching: Vec<(&String, &BTreeMap<String, ItemRecord>)> = all
            .iter()
            .filter(|(_, types_)| {
                filters.iter().all(|f| {
                    let (type_name, attr) = f.key.split_once('.').unwrap_or_default();
                    let kind = f.r#type.as_deref().unwrap_or("Equal");
                    match types_.get(type_name) {
                        Some(item) => item.content.iter().any(|c| passes(c.get(attr), kind, &f.values)),
                        None => false,
                    }
                })
            })
            .collect();
        if let Some(aggregators) = input.aggregators.filter(|a| !a.is_empty()) {
            let mut data = BTreeMap::new();
            for a in aggregators {
                let Some(expr) = a.expression.clone() else {
                    return Err(errors::invalid_aggregator("Aggregators need an Expression."));
                };
                let Some((type_name, attr)) = expr.split_once('.') else {
                    return Err(errors::invalid_aggregator(format!("The aggregator expression {expr} is not valid.")));
                };
                let mut counts: BTreeMap<String, i64> = BTreeMap::new();
                for (_, types_) in &matching {
                    if let Some(item) = types_.get(type_name) {
                        let values: std::collections::BTreeSet<&String> =
                            item.content.iter().filter_map(|c| c.get(attr)).collect();
                        for v in values {
                            *counts.entry(v.clone()).or_default() += 1;
                        }
                    }
                }
                let content = counts
                    .into_iter()
                    .map(|(v, n)| BTreeMap::from([(attr.to_string(), v), ("Count".to_string(), n.to_string())]))
                    .collect();
                let version = aws_type(type_name).map(|t| t.1).unwrap_or("1.0");
                data.insert(
                    type_name.to_string(),
                    types::InventoryResultItem {
                        type_name: type_name.to_string(),
                        schema_version: version.to_string(),
                        capture_time: None,
                        content_hash: None,
                        content,
                    },
                );
            }
            return Ok(types::GetInventoryResult {
                entities: Some(vec![types::InventoryResultEntity { id: None, data: Some(data) }]),
                next_token: None,
            });
        }
        let wanted: Vec<String> =
            input.result_attributes.unwrap_or_default().into_iter().map(|r| r.type_name).collect();
        let entities: Vec<types::InventoryResultEntity> = matching
            .into_iter()
            .map(|(id, types_)| types::InventoryResultEntity {
                id: Some(id.clone()),
                data: Some(
                    types_
                        .iter()
                        .filter(|(t, _)| wanted.is_empty() || wanted.contains(t))
                        .map(|(t, item)| {
                            (
                                t.clone(),
                                types::InventoryResultItem {
                                    type_name: t.clone(),
                                    schema_version: item.schema_version.clone(),
                                    capture_time: Some(item.capture_time.clone()),
                                    content_hash: item.content_hash.clone(),
                                    content: item.content.clone(),
                                },
                            )
                        })
                        .collect(),
                ),
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(entities, input.next_token.as_deref(), limit)?;
        Ok(types::GetInventoryResult { entities: Some(items), next_token: next })
    }

    pub(crate) fn get_inventory_schema(
        &self,
        ctx: &RequestContext,
        input: types::GetInventorySchemaRequest,
    ) -> Result<types::GetInventorySchemaResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:GetInventorySchema", &list_arn, ConditionContext::new())?;
        let custom = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.inventory.custom_schemas.clone())
                .unwrap_or_default()
        };
        let mut schemas: Vec<types::InventoryItemSchema> = AWS_TYPES
            .iter()
            .map(|(name, version, attrs)| types::InventoryItemSchema {
                type_name: name.to_string(),
                version: Some(version.to_string()),
                attributes: attrs
                    .iter()
                    .map(|(n, t)| types::InventoryItemAttribute { name: n.to_string(), data_type: t.to_string() })
                    .collect(),
                display_name: None,
            })
            .collect();
        schemas.extend(custom.into_iter().map(|(name, (version, attrs))| {
            types::InventoryItemSchema {
                type_name: name,
                version: Some(version),
                attributes: attrs
                    .into_iter()
                    .map(|n| types::InventoryItemAttribute { name: n, data_type: "string".into() })
                    .collect(),
                display_name: None,
            }
        }));
        if let Some(t) = &input.type_name {
            schemas.retain(|s| &s.type_name == t);
            if schemas.is_empty() {
                return Err(errors::invalid_type_name(format!("The type name {t} is not valid.")));
            }
        }
        if input.aggregator {
            // Aggregatable attributes are the string ones.
            for s in &mut schemas {
                s.attributes.retain(|a| a.data_type == "string");
            }
        }
        let limit = input.max_results.unwrap_or(200).clamp(50, 200) as usize;
        let (items, next) = page(schemas, input.next_token.as_deref(), limit)?;
        Ok(types::GetInventorySchemaResult { schemas: Some(items), next_token: next })
    }

    pub(crate) fn list_inventory_entries(
        &self,
        ctx: &RequestContext,
        input: types::ListInventoryEntriesRequest,
    ) -> Result<types::ListInventoryEntriesResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:ListInventoryEntries", &arn, ConditionContext::new())?;
        let all = self.inventory_of(&ctx.caller.account_id, &ctx.region, now(ctx));
        let Some(types_) = all.get(&input.instance_id) else {
            return Err(errors::invalid_instance_id("Invalid instance ID."));
        };
        if !input.type_name.starts_with("Custom:") && aws_type(&input.type_name).is_none() {
            return Err(errors::invalid_type_name(format!("The type name {} is not valid.", input.type_name)));
        }
        let item = types_.get(&input.type_name).cloned().unwrap_or_default();
        let filters = input.filters.unwrap_or_default();
        let entries: Vec<BTreeMap<String, String>> = item
            .content
            .into_iter()
            .filter(|c| {
                filters.iter().all(|f| {
                    let attr = f.key.rsplit('.').next().unwrap_or_default();
                    passes(c.get(attr), f.r#type.as_deref().unwrap_or("Equal"), &f.values)
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(entries, input.next_token.as_deref(), limit)?;
        Ok(types::ListInventoryEntriesResult {
            type_name: Some(input.type_name),
            instance_id: Some(input.instance_id),
            schema_version: (!item.schema_version.is_empty()).then_some(item.schema_version),
            capture_time: (!item.capture_time.is_empty()).then_some(item.capture_time),
            entries: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn delete_inventory(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInventoryRequest,
    ) -> Result<types::DeleteInventoryResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:DeleteInventory", &list_arn, ConditionContext::new())?;
        if !input.type_name.starts_with("Custom:") {
            return Err(errors::invalid_type_name("Only custom inventory types can be deleted."));
        }
        if let Some(o) = &input.schema_delete_option {
            if o != "DisableSchema" && o != "DeleteSchema" {
                return Err(errors::invalid_option(format!("Invalid SchemaDeleteOption: {o}")));
            }
        }
        let t = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let Some((version, _)) = r.inventory.custom_schemas.get(&input.type_name).cloned() else {
            return Err(errors::invalid_type_name(format!("The type name {} is not valid.", input.type_name)));
        };
        let count = r.inventory.items.values().filter(|m| m.contains_key(&input.type_name)).count() as i32;
        let summary = types::InventoryDeletionSummary {
            total_count: count,
            remaining_count: 0,
            summary_items: Some(vec![types::InventoryDeletionSummaryItem {
                version: Some(version),
                count,
                remaining_count: 0,
            }]),
        };
        if input.dry_run {
            return Ok(types::DeleteInventoryResult {
                deletion_id: None,
                type_name: Some(input.type_name),
                deletion_summary: Some(summary),
            });
        }
        for m in r.inventory.items.values_mut() {
            m.remove(&input.type_name);
        }
        if input.schema_delete_option.as_deref() == Some("DeleteSchema") {
            r.inventory.custom_schemas.remove(&input.type_name);
        }
        let id = uuid::Uuid::new_v4().to_string();
        r.inventory.deletions.insert(
            0,
            types::InventoryDeletionStatusItem {
                deletion_id: Some(id.clone()),
                type_name: Some(input.type_name.clone()),
                deletion_start_time: Some(t),
                last_status: Some("Complete".into()),
                last_status_message: Some("Deletion is successful".into()),
                deletion_summary: Some(summary.clone()),
                last_status_update_time: Some(t),
            },
        );
        Ok(types::DeleteInventoryResult {
            deletion_id: Some(id),
            type_name: Some(input.type_name),
            deletion_summary: Some(summary),
        })
    }

    pub(crate) fn describe_inventory_deletions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInventoryDeletionsRequest,
    ) -> Result<types::DescribeInventoryDeletionsResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:DescribeInventoryDeletions", &list_arn, ConditionContext::new())?;
        let mut all = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.inventory.deletions.clone())
                .unwrap_or_default()
        };
        if let Some(id) = &input.deletion_id {
            all.retain(|d| d.deletion_id.as_ref() == Some(id));
            if all.is_empty() {
                return Err(errors::invalid_deletion_id("The ID specified for the delete operation does not exist."));
            }
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInventoryDeletionsResult { inventory_deletions: Some(items), next_token: next })
    }
}

impl Ssm {
    /// Run an `aws:softwareInventory` step on a node: collect what its
    /// inputs enable and store it as the node's inventory.
    pub(crate) async fn gather_inventory(
        &self,
        nodes: &Option<std::sync::Arc<dyn crate::commands::ManagedNodes>>,
        account: &str,
        region: &str,
        instance: &str,
        inputs: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> crate::commands::StepOutcome {
        let enabled = |k: &str| inputs.get(k).and_then(|v| v.as_str()).is_none_or(|v| v != "Disabled");
        let out = match nodes {
            Some(m) => match m.run_shell(account, region, instance, INVENTORY_SCRIPT).await {
                Ok(o) => o,
                Err(e) => return ("Failed", "Undeliverable", -1, String::new(), e),
            },
            None => None,
        };
        let (apps, nets) = out.map(|o| parse_inventory(&o.stdout)).unwrap_or_default();
        let mut collected = Vec::new();
        if enabled("applications") {
            collected.push(format!("AWS:Application ({})", apps.len()));
            self.record_inventory(account, region, instance, "AWS:Application", apps, at);
        }
        if enabled("networkConfig") {
            collected.push(format!("AWS:Network ({})", nets.len()));
            self.record_inventory(account, region, instance, "AWS:Network", nets, at);
        }
        if let Some(n) = self.nodes_of(account, region).into_iter().find(|n| n.instance_id == instance) {
            let info = instance_information(&n, at);
            self.record_inventory(account, region, instance, "AWS:InstanceInformation", info.content, at);
        }
        ("Success", "Success", 0, format!("Collected inventory: {}\n", collected.join(", ")), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_inventory;

    #[test]
    fn parses_rpm_and_network_lines() {
        let out = "A\tbash\t5.2.15\t1.amzn2023\t(none)\tx86_64\t1700000000\tAmazon Linux\thttps://www.gnu.org\tThe GNU Bourne Again shell\nN\teth0\t02:42:ac:11:00:02\t172.17.0.2\t\t172.17.0.1,10.0.0.2\n";
        let (apps, nets) = parse_inventory(out);
        assert_eq!(apps[0]["Name"], "bash");
        assert_eq!(apps[0]["Release"], "1.amzn2023");
        assert!(!apps[0].contains_key("Epoch"));
        assert_eq!(apps[0]["InstalledTime"], "2023-11-14T22:13:20Z");
        assert_eq!(nets[0]["IPV4"], "172.17.0.2");
        assert_eq!(nets[0]["Gateway"], "172.17.0.1");
        assert_eq!(nets[0]["DNSServer"], "10.0.0.2");
    }
}
