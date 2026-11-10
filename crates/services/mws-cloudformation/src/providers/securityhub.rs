//! Security Hub resource types: the hub, standards, automation rules,
//! insights, finding aggregators and the delegated administrator.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::rds::{coerce, settle, stabilize};
use super::{boolean, changed, copy, gone_ok, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SecurityHub::Hub", Arc::new(Hub));
    m.insert("AWS::SecurityHub::Standard", Arc::new(Standard));
    m.insert("AWS::SecurityHub::AutomationRule", Arc::new(AutomationRule));
    m.insert("AWS::SecurityHub::Insight", Arc::new(Insight));
    m.insert("AWS::SecurityHub::FindingAggregator", Arc::new(FindingAggregator));
    m.insert("AWS::SecurityHub::DelegatedAdmin", Arc::new(DelegatedAdmin));
}

const NUMS: &[&str] =
    &["RuleOrder", "Gte", "Lte", "Eq", "Gt", "Lt", "Confidence", "Criticality", "Normalized", "Product"];
const BOOLS: &[&str] = &["IsTerminal", "AutoEnableControls", "EnableDefaultStandards"];

fn coerced(mut m: Map<String, Value>) -> Map<String, Value> {
    let mut v = Value::Object(std::mem::take(&mut m));
    coerce(&mut v, NUMS, BOOLS, &[]);
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let (o, n) = (cx.tag_map(old), cx.tag_map(new));
    let removed: Vec<&String> = o.keys().filter(|k| !n.contains_key(*k)).collect();
    if !removed.is_empty() {
        cx.call("securityhub", "UntagResource", json!({"ResourceArn": arn, "TagKeys": removed})).await?;
    }
    let set: Map<String, Value> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
    if !set.is_empty() {
        cx.call("securityhub", "TagResource", json!({"ResourceArn": arn, "Tags": set})).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The hub.

struct Hub;

#[async_trait::async_trait]
impl Provider for Hub {
    fn attributes(&self) -> &'static [&'static str] {
        &["ARN", "SubscribedAt"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        input.insert("EnableDefaultStandards".into(), json!(boolean(props, "EnableDefaultStandards").unwrap_or(true)));
        copy(props, &mut input, &["ControlFindingGenerator"]);
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Object(tags));
        }
        cx.call("securityhub", "EnableSecurityHub", Value::Object(input)).await?;
        if let Some(b) = boolean(props, "AutoEnableControls") {
            cx.call("securityhub", "UpdateSecurityHubConfiguration", json!({"AutoEnableControls": b})).await?;
        }
        let hub = cx.call("securityhub", "DescribeHub", json!({})).await?;
        let arn = text(&hub["HubArn"]);
        Ok(Created::new(&arn).attr("ARN", arn.clone()).attr("SubscribedAt", text(&hub["SubscribedAt"])))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "AutoEnableControls") || changed(old, new, "ControlFindingGenerator") {
            let mut input = Map::new();
            input.insert("AutoEnableControls".into(), json!(boolean(new, "AutoEnableControls").unwrap_or(true)));
            copy(new, &mut input, &["ControlFindingGenerator"]);
            cx.call("securityhub", "UpdateSecurityHubConfiguration", Value::Object(input)).await?;
        }
        retag(cx, arn, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("securityhub", "DisableSecurityHub", json!({})).await {
            Err(e) if e.not_found || e.code == "InvalidAccessException" => Ok(()),
            r => r.map(|_| ()),
        }
    }
}

// ---------------------------------------------------------------------
// Standards.

fn disabled_controls(props: &Props) -> BTreeMap<String, String> {
    props
        .get("DisabledStandardsControls")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().map(|c| (text(&c["SecurityControlId"]), c.get("Reason").map(text).unwrap_or_default())).collect()
        })
        .unwrap_or_default()
}

async fn subscription(cx: &Cx<'_>, arn: &str) -> HResult<Option<Value>> {
    let out = cx.call("securityhub", "GetEnabledStandards", json!({"StandardsSubscriptionArns": [arn]})).await?;
    Ok(out["StandardsSubscriptions"].as_array().and_then(|a| a.first()).cloned())
}

async fn set_controls(cx: &Cx<'_>, standard: &str, updates: Vec<Value>) -> HResult<()> {
    for chunk in updates.chunks(100) {
        let out = cx
            .call(
                "securityhub",
                "BatchUpdateStandardsControlAssociations",
                json!({"StandardsControlAssociationUpdates": chunk}),
            )
            .await?;
        if let Some(u) = out["UnprocessedAssociationUpdates"].as_array().and_then(|a| a.first()) {
            return Err(HandlerError::handler(
                "InvalidRequest",
                format!(
                    "Could not update control {} in {standard}: {}",
                    text(&u["StandardsControlAssociationUpdate"]["SecurityControlId"]),
                    text(&u["ErrorReason"])
                ),
            ));
        }
    }
    Ok(())
}

fn control_update(standard: &str, id: &str, status: &str, reason: Option<&str>) -> Value {
    let mut v = json!({"StandardsArn": standard, "SecurityControlId": id, "AssociationStatus": status});
    if let Some(r) = reason.filter(|r| !r.is_empty()) {
        v["UpdatedReason"] = json!(r);
    }
    v
}

struct Standard;

#[async_trait::async_trait]
impl Provider for Standard {
    fn create_only(&self) -> &'static [&'static str] {
        &["StandardsArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["StandardsArn"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["StandardsSubscriptionArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let standard = req(props, "StandardsArn")?;
        let out = cx
            .call(
                "securityhub",
                "BatchEnableStandards",
                json!({"StandardsSubscriptionRequests": [{"StandardsArn": standard}]}),
            )
            .await?;
        let arn = text(&out["StandardsSubscriptions"][0]["StandardsSubscriptionArn"]);
        let arn_ref = &arn;
        let std_ref = &standard;
        settle(&format!("standard {standard} to be ready"), || async move {
            let s = subscription(cx, arn_ref).await?;
            match s.as_ref().map(|s| text(&s["StandardsStatus"])).as_deref() {
                Some("READY") | Some("INCOMPLETE") => Ok(Some(())),
                Some("FAILED") => Err(HandlerError::handler("NotStabilized", format!("Standard {std_ref} failed"))),
                _ => Ok(None),
            }
        })
        .await?;
        let updates: Vec<Value> = disabled_controls(props)
            .iter()
            .map(|(id, reason)| control_update(&standard, id, "DISABLED", Some(reason)))
            .collect();
        set_controls(cx, &standard, updates).await?;
        Ok(Created::new(&arn).attr("StandardsSubscriptionArn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "DisabledStandardsControls") {
            let standard = req(new, "StandardsArn")?;
            let (o, n) = (disabled_controls(old), disabled_controls(new));
            let mut updates: Vec<Value> = o
                .keys()
                .filter(|k| !n.contains_key(*k))
                .map(|id| control_update(&standard, id, "ENABLED", None))
                .collect();
            updates.extend(
                n.iter()
                    .filter(|(k, v)| o.get(*k) != Some(v))
                    .map(|(id, reason)| control_update(&standard, id, "DISABLED", Some(reason))),
            );
            set_controls(cx, &standard, updates).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("securityhub", "BatchDisableStandards", json!({"StandardsSubscriptionArns": [arn]})).await {
            Err(e) if e.not_found || e.code == "InvalidAccessException" => return Ok(()),
            r => {
                r?;
            }
        }
        stabilize(&format!("standard subscription {arn} to be removed"), || async move {
            match subscription(cx, arn).await {
                Ok(None) => Ok(true),
                Ok(Some(s)) => Ok(text(&s["StandardsStatus"]) != "DELETING"),
                Err(e) if e.not_found || e.code == "InvalidAccessException" => Ok(true),
                Err(e) => Err(e),
            }
        })
        .await
    }
}

// ---------------------------------------------------------------------
// Automation rules.

const RULE_FIELDS: &[&str] =
    &["RuleStatus", "RuleOrder", "RuleName", "Description", "IsTerminal", "Criteria", "Actions"];

async fn rule(cx: &Cx<'_>, arn: &str) -> HResult<Value> {
    let out = cx.call("securityhub", "BatchGetAutomationRules", json!({"AutomationRulesArns": [arn]})).await?;
    match out["Rules"].as_array().and_then(|a| a.first()) {
        Some(r) => Ok(r.clone()),
        None => Err(HandlerError::handler("NotFound", format!("Automation rule {arn} not found"))),
    }
}

fn rule_attributes(r: &Value) -> Props {
    let mut a = Props::new();
    for k in ["RuleArn", "CreatedAt", "CreatedBy", "UpdatedAt"] {
        a.insert(k.into(), json!(text(&r[k])));
    }
    a
}

struct AutomationRule;

#[async_trait::async_trait]
impl Provider for AutomationRule {
    fn attributes(&self) -> &'static [&'static str] {
        &["RuleArn", "CreatedAt", "CreatedBy", "UpdatedAt"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, RULE_FIELDS);
        let mut input = coerced(input);
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Object(tags));
        }
        let out = cx.call("securityhub", "CreateAutomationRule", Value::Object(input)).await?;
        let arn = text(&out["RuleArn"]);
        let r = rule(cx, &arn).await?;
        Ok(Created { physical_id: arn, attributes: rule_attributes(&r) })
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if RULE_FIELDS.iter().any(|k| changed(old, new, k)) {
            let mut item = Map::new();
            copy(new, &mut item, RULE_FIELDS);
            let mut item = coerced(item);
            item.insert("RuleArn".into(), json!(arn));
            let out = cx
                .call("securityhub", "BatchUpdateAutomationRules", json!({"UpdateAutomationRulesRequestItems": [item]}))
                .await?;
            if let Some(u) = out["UnprocessedAutomationRules"].as_array().and_then(|a| a.first()) {
                return Err(HandlerError::handler("InvalidRequest", text(&u["ErrorMessage"])));
            }
        }
        retag(cx, arn, old, new).await?;
        Ok(rule_attributes(&rule(cx, arn).await?))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        cx.call("securityhub", "BatchDeleteAutomationRules", json!({"AutomationRulesArns": [arn]})).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Insights.

struct Insight;

#[async_trait::async_trait]
impl Provider for Insight {
    fn required(&self) -> &'static [&'static str] {
        &["Name", "Filters", "GroupByAttribute"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["InsightArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["Name", "Filters", "GroupByAttribute"]);
        let out = cx.call("securityhub", "CreateInsight", Value::Object(coerced(input))).await?;
        let arn = text(&out["InsightArn"]);
        Ok(Created::new(&arn).attr("InsightArn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = Map::new();
        copy(new, &mut input, &["Name", "Filters", "GroupByAttribute"]);
        input.insert("InsightArn".into(), json!(arn));
        cx.call("securityhub", "UpdateInsight", Value::Object(coerced(input))).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("securityhub", "DeleteInsight", json!({"InsightArn": arn})).await)
    }
}

// ---------------------------------------------------------------------
// Finding aggregators.

struct FindingAggregator;

#[async_trait::async_trait]
impl Provider for FindingAggregator {
    fn required(&self) -> &'static [&'static str] {
        &["RegionLinkingMode"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["FindingAggregatorArn", "FindingAggregationRegion"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"RegionLinkingMode": req(props, "RegionLinkingMode")?});
        if props.contains_key("Regions") {
            input["Regions"] = json!(list(props, "Regions"));
        }
        let out = cx.call("securityhub", "CreateFindingAggregator", input).await?;
        let arn = text(&out["FindingAggregatorArn"]);
        Ok(Created::new(&arn)
            .attr("FindingAggregatorArn", arn.clone())
            .attr("FindingAggregationRegion", text(&out["FindingAggregationRegion"])))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = json!({"FindingAggregatorArn": arn, "RegionLinkingMode": req(new, "RegionLinkingMode")?});
        if new.contains_key("Regions") {
            input["Regions"] = json!(list(new, "Regions"));
        }
        cx.call("securityhub", "UpdateFindingAggregator", input).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("securityhub", "DeleteFindingAggregator", json!({"FindingAggregatorArn": arn})).await)
    }
}

// ---------------------------------------------------------------------
// The delegated administrator.

struct DelegatedAdmin;

#[async_trait::async_trait]
impl Provider for DelegatedAdmin {
    fn create_only(&self) -> &'static [&'static str] {
        &["AdminAccountId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AdminAccountId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["DelegatedAdminIdentifier", "Status"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let account = req(props, "AdminAccountId")?;
        cx.call("securityhub", "EnableOrganizationAdminAccount", json!({"AdminAccountId": account})).await?;
        let out = cx.call("securityhub", "ListOrganizationAdminAccounts", json!({})).await?;
        let status = out["AdminAccounts"]
            .as_array()
            .and_then(|a| a.iter().find(|x| text(&x["AccountId"]) == account))
            .map(|x| text(&x["Status"]))
            .unwrap_or_else(|| "ENABLED".into());
        let id = format!("{account}/{}", cx.region());
        Ok(Created::new(&id).attr("DelegatedAdminIdentifier", id.clone()).attr("Status", status))
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let account = s(props, "AdminAccountId").unwrap_or_default();
        gone_ok(cx.call("securityhub", "DisableOrganizationAdminAccount", json!({"AdminAccountId": account})).await)
    }
}
