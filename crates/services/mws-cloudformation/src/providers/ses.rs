//! Amazon SES resource types. Identities, configuration sets, contact
//! lists and dedicated IP pools go through the SES v2 API; templates,
//! receipt rule sets, receipt rules and receipt filters through v1, which
//! is the only API that has them (and whose shapes CloudFormation uses).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::ecs::{coerce, gone_codes, tag_changes};
use super::{changed, copy, gone_ok, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SES::EmailIdentity", Arc::new(EmailIdentity));
    m.insert("AWS::SES::ConfigurationSet", Arc::new(ConfigurationSet));
    m.insert("AWS::SES::ConfigurationSetEventDestination", Arc::new(EventDestination));
    m.insert("AWS::SES::Template", Arc::new(Template));
    m.insert("AWS::SES::ContactList", Arc::new(ContactList));
    m.insert("AWS::SES::DedicatedIpPool", Arc::new(DedicatedIpPool));
    m.insert("AWS::SES::ReceiptRuleSet", Arc::new(ReceiptRuleSet));
    m.insert("AWS::SES::ReceiptRule", Arc::new(ReceiptRule));
    m.insert("AWS::SES::ReceiptFilter", Arc::new(ReceiptFilter));
}

const V2: &str = "sesv2";
const V1: &str = "ses";

/// A generated SES name: letters, digits, `_` and `-` only.
fn generated(cx: &Cx<'_>, max: usize) -> String {
    cx.physical_name(max).chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect()
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if let Some((set, removed)) = tag_changes(cx, old, new, "Tags") {
        if !removed.is_empty() {
            cx.call(V2, "UntagResource", json!({"ResourceArn": arn, "TagKeys": removed})).await?;
        }
        if !set.is_empty() {
            cx.call(V2, "TagResource", json!({"ResourceArn": arn, "Tags": set})).await?;
        }
    }
    Ok(())
}

fn with_tags(cx: &Cx<'_>, props: &Props, input: &mut Value) {
    let tags = cx.tags(props);
    if !tags.is_empty() {
        input["Tags"] = Value::Array(tags);
    }
}

fn obj(props: &Props, key: &str) -> Map<String, Value> {
    props.get(key).and_then(Value::as_object).cloned().unwrap_or_default()
}

// ---- EmailIdentity -----------------------------------------------------

struct EmailIdentity;

async fn identity_attrs(cx: &Cx<'_>, identity: &str) -> HResult<Props> {
    let out = cx.call(V2, "GetEmailIdentity", json!({"EmailIdentity": identity})).await?;
    let tokens: Vec<String> =
        out["DkimAttributes"]["Tokens"].as_array().map(|a| a.iter().map(text).collect()).unwrap_or_default();
    let mut a = Props::new();
    for i in 0..3 {
        let (name, value) = match tokens.get(i) {
            Some(t) => (format!("{t}._domainkey.{identity}"), format!("{t}.dkim.amazonses.com")),
            None => (String::new(), String::new()),
        };
        a.insert(format!("DkimDNSTokenName{}", i + 1), json!(name));
        a.insert(format!("DkimDNSTokenValue{}", i + 1), json!(value));
    }
    Ok(a)
}

async fn put_identity_attributes(cx: &Cx<'_>, id: &str, old: Option<&Props>, new: &Props) -> HResult<()> {
    let differs = |k: &str| old.map_or(new.contains_key(k), |o| changed(o, new, k));
    if differs("DkimAttributes") {
        let enabled = obj(new, "DkimAttributes").get("SigningEnabled").map(|v| v == &json!(true) || v == "true");
        cx.call(
            V2,
            "PutEmailIdentityDkimAttributes",
            json!({"EmailIdentity": id, "SigningEnabled": enabled.unwrap_or(true)}),
        )
        .await?;
    }
    if differs("MailFromAttributes") {
        let mut input = json!({"EmailIdentity": id});
        let m = obj(new, "MailFromAttributes");
        if let Some(d) = m.get("MailFromDomain") {
            input["MailFromDomain"] = d.clone();
        }
        if let Some(b) = m.get("BehaviorOnMxFailure") {
            input["BehaviorOnMxFailure"] = b.clone();
        }
        cx.call(V2, "PutEmailIdentityMailFromAttributes", input).await?;
    }
    if differs("FeedbackAttributes") {
        let f = obj(new, "FeedbackAttributes");
        let enabled = f.get("EmailForwardingEnabled").map(|v| v == &json!(true) || v == "true").unwrap_or(true);
        cx.call(
            V2,
            "PutEmailIdentityFeedbackAttributes",
            json!({"EmailIdentity": id, "EmailForwardingEnabled": enabled}),
        )
        .await?;
    }
    if old.is_some_and(|o| changed(o, new, "ConfigurationSetAttributes")) {
        let mut input = json!({"EmailIdentity": id});
        if let Some(c) = obj(new, "ConfigurationSetAttributes").get("ConfigurationSetName") {
            input["ConfigurationSetName"] = c.clone();
        }
        cx.call(V2, "PutEmailIdentityConfigurationSetAttributes", input).await?;
    }
    if old.is_some_and(|o| changed(o, new, "DkimSigningAttributes")) {
        let mut attrs = obj(new, "DkimSigningAttributes");
        let origin = if attrs.contains_key("DomainSigningPrivateKey") { "EXTERNAL" } else { "AWS_SES" };
        attrs.remove("DomainSigningAttributesOrigin");
        cx.call(
            V2,
            "PutEmailIdentityDkimSigningAttributes",
            json!({"EmailIdentity": id, "SigningAttributesOrigin": origin, "SigningAttributes": attrs}),
        )
        .await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl Provider for EmailIdentity {
    fn create_only(&self) -> &'static [&'static str] {
        &["EmailIdentity"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["EmailIdentity"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "DkimDNSTokenName1",
            "DkimDNSTokenName2",
            "DkimDNSTokenName3",
            "DkimDNSTokenValue1",
            "DkimDNSTokenValue2",
            "DkimDNSTokenValue3",
        ]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let id = req(props, "EmailIdentity")?;
        let mut input = json!({"EmailIdentity": id});
        if let Some(c) = obj(props, "ConfigurationSetAttributes").get("ConfigurationSetName") {
            input["ConfigurationSetName"] = c.clone();
        }
        if let Some(Value::Object(d)) = props.get("DkimSigningAttributes") {
            input["DkimSigningAttributes"] = Value::Object(d.clone());
        }
        cx.call(V2, "CreateEmailIdentity", input).await?;
        put_identity_attributes(cx, &id, None, props).await?;
        Ok(Created { physical_id: id.clone(), attributes: identity_attrs(cx, &id).await? })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        put_identity_attributes(cx, id, Some(old), new).await?;
        identity_attrs(cx, id).await
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteEmailIdentity", json!({"EmailIdentity": id})).await)
    }
}

// ---- ConfigurationSet --------------------------------------------------

struct ConfigurationSet;

/// The option groups of a configuration set: property, `Put…` operation.
const OPTIONS: &[(&str, &str)] = &[
    ("TrackingOptions", "PutConfigurationSetTrackingOptions"),
    ("DeliveryOptions", "PutConfigurationSetDeliveryOptions"),
    ("ReputationOptions", "PutConfigurationSetReputationOptions"),
    ("SendingOptions", "PutConfigurationSetSendingOptions"),
    ("SuppressionOptions", "PutConfigurationSetSuppressionOptions"),
    ("VdmOptions", "PutConfigurationSetVdmOptions"),
];

fn option_value(props: &Props, key: &str) -> Option<Value> {
    let mut v = props.get(key).filter(|v| !v.is_null())?.clone();
    coerce(
        &mut v,
        &["MaxDeliverySeconds"],
        &["ReputationMetricsEnabled", "SendingEnabled"],
        &["EngagementMetrics", "OptimizedSharedDelivery"],
    );
    Some(v)
}

fn config_set_arn(cx: &Cx<'_>, name: &str) -> String {
    cx.arn("ses", &format!("configuration-set/{name}"))
}

#[async_trait::async_trait]
impl Provider for ConfigurationSet {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| generated(cx, 64));
        let mut input = json!({"ConfigurationSetName": name});
        for (k, _) in OPTIONS {
            if let Some(v) = option_value(props, k) {
                input[*k] = v;
            }
        }
        with_tags(cx, props, &mut input);
        cx.call(V2, "CreateConfigurationSet", input).await?;
        Ok(Created::new(&name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        for (k, op) in OPTIONS {
            if !changed(old, new, k) {
                continue;
            }
            let mut input = json!({"ConfigurationSetName": name});
            match (option_value(new, k), *k) {
                (Some(v), "VdmOptions") => input["VdmOptions"] = v,
                (Some(Value::Object(m)), _) => {
                    for (mk, mv) in m {
                        input[mk.as_str()] = mv;
                    }
                }
                // Removed groups go back to their defaults.
                (_, "ReputationOptions") => input["ReputationMetricsEnabled"] = json!(false),
                (_, "SendingOptions") => input["SendingEnabled"] = json!(true),
                (_, "VdmOptions") => input["VdmOptions"] = json!({}),
                _ => {}
            }
            cx.call(V2, op, input).await?;
        }
        retag(cx, &config_set_arn(cx, name), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteConfigurationSet", json!({"ConfigurationSetName": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call(V2, "GetConfigurationSet", json!({"ConfigurationSetName": name})).await?;
                let mut p = Props::new();
                if props.contains_key("Name") {
                    p.insert("Name".into(), out["ConfigurationSetName"].clone());
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- ConfigurationSetEventDestination ----------------------------------

struct EventDestination;

/// CloudFormation's event destination (v1 member names) as SES v2's.
fn destination(props: &Props) -> Value {
    let d = obj(props, "EventDestination");
    let mut out = Map::new();
    copy(&d, &mut out, &["Enabled", "CloudWatchDestination", "EventBridgeDestination"]);
    // CloudFormation takes v1 event type names (`send`, `renderingFailure`);
    // SES v2 wants `SEND`, `RENDERING_FAILURE`.
    if let Some(Value::Array(types)) = d.get("MatchingEventTypes") {
        let v2: Vec<Value> = types
            .iter()
            .map(|t| {
                let t = text(t);
                if t.chars().all(|c| !c.is_ascii_lowercase()) {
                    return Value::String(t);
                }
                let mut upper = String::new();
                for c in t.chars() {
                    if c.is_ascii_uppercase() && !upper.is_empty() && !upper.ends_with('_') {
                        upper.push('_');
                    }
                    upper.push(c.to_ascii_uppercase());
                }
                Value::String(upper)
            })
            .collect();
        out.insert("MatchingEventTypes".into(), Value::Array(v2));
    }
    if let Some(Value::Object(k)) = d.get("KinesisFirehoseDestination") {
        out.insert(
            "KinesisFirehoseDestination".into(),
            json!({"IamRoleArn": k.get("IAMRoleARN"), "DeliveryStreamArn": k.get("DeliveryStreamARN")}),
        );
    }
    if let Some(Value::Object(sns)) = d.get("SnsDestination") {
        out.insert("SnsDestination".into(), json!({"TopicArn": sns.get("TopicARN")}));
    }
    let mut v = Value::Object(out);
    coerce(&mut v, &[], &["Enabled"], &[]);
    v
}

#[async_trait::async_trait]
impl Provider for EventDestination {
    fn create_only(&self) -> &'static [&'static str] {
        &["ConfigurationSetName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ConfigurationSetName", "EventDestination"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let set = req(props, "ConfigurationSetName")?;
        let name = obj(props, "EventDestination").get("Name").map(text).unwrap_or_else(|| generated(cx, 64));
        cx.call(
            V2,
            "CreateConfigurationSetEventDestination",
            json!({"ConfigurationSetName": set, "EventDestinationName": name, "EventDestination": destination(props)}),
        )
        .await?;
        Ok(Created::new(&name).attr("Id", name.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let name_of = |p: &Props| obj(p, "EventDestination").get("Name").map(text);
        if name_of(old) != name_of(new) {
            return Err(HandlerError::handler(
                "NotUpdatable",
                "Resource of type 'AWS::SES::ConfigurationSetEventDestination' cannot change EventDestination.Name in place",
            ));
        }
        cx.call(
            V2,
            "UpdateConfigurationSetEventDestination",
            json!({
                "ConfigurationSetName": req(new, "ConfigurationSetName")?,
                "EventDestinationName": name,
                "EventDestination": destination(new),
            }),
        )
        .await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let set = req(props, "ConfigurationSetName")?;
        gone_ok(
            cx.call(
                V2,
                "DeleteConfigurationSetEventDestination",
                json!({"ConfigurationSetName": set, "EventDestinationName": name}),
            )
            .await,
        )
    }
}

// ---- Template ----------------------------------------------------------

struct Template;

fn template(props: &Props, name: &str) -> Value {
    let t = obj(props, "Template");
    let mut out = Map::new();
    out.insert("TemplateName".into(), json!(name));
    copy(&t, &mut out, &["SubjectPart", "TextPart", "HtmlPart"]);
    Value::Object(out)
}

#[async_trait::async_trait]
impl Provider for Template {
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = obj(props, "Template").get("TemplateName").map(text).unwrap_or_else(|| generated(cx, 64));
        cx.call(V1, "CreateTemplate", json!({"Template": template(props, &name)})).await?;
        Ok(Created::new(&name).attr("Id", name.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let name_of = |p: &Props| obj(p, "Template").get("TemplateName").map(text);
        if name_of(old) != name_of(new) {
            return Err(HandlerError::handler(
                "NotUpdatable",
                "Resource of type 'AWS::SES::Template' cannot change Template.TemplateName in place",
            ));
        }
        cx.call(V1, "UpdateTemplate", json!({"Template": template(new, name)})).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_codes(cx.call(V1, "DeleteTemplate", json!({"TemplateName": name})).await, &["TemplateDoesNotExist"])
    }
}

// ---- ContactList -------------------------------------------------------

struct ContactList;

#[async_trait::async_trait]
impl Provider for ContactList {
    fn create_only(&self) -> &'static [&'static str] {
        &["ContactListName"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ContactListName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "ContactListName").unwrap_or_else(|| generated(cx, 64));
        let mut input = json!({"ContactListName": name});
        if let Some(d) = s(props, "Description") {
            input["Description"] = json!(d);
        }
        if let Some(t) = props.get("Topics") {
            input["Topics"] = t.clone();
        }
        with_tags(cx, props, &mut input);
        cx.call(V2, "CreateContactList", input).await?;
        Ok(Created::new(&name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Topics") || changed(old, new, "Description") {
            let mut input = json!({"ContactListName": name, "Topics": new.get("Topics").cloned().unwrap_or(json!([]))});
            if let Some(d) = s(new, "Description") {
                input["Description"] = json!(d);
            }
            cx.call(V2, "UpdateContactList", input).await?;
        }
        retag(cx, &cx.arn("ses", &format!("contact-list/{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteContactList", json!({"ContactListName": name})).await)
    }
}

// ---- DedicatedIpPool ---------------------------------------------------

struct DedicatedIpPool;

#[async_trait::async_trait]
impl Provider for DedicatedIpPool {
    fn create_only(&self) -> &'static [&'static str] {
        &["PoolName"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("PoolName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "PoolName").unwrap_or_else(|| generated(cx, 64));
        let mut input = json!({"PoolName": name});
        if let Some(m) = s(props, "ScalingMode") {
            input["ScalingMode"] = json!(m);
        }
        with_tags(cx, props, &mut input);
        cx.call(V2, "CreateDedicatedIpPool", input).await?;
        Ok(Created::new(&name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "ScalingMode") {
            let mode = s(new, "ScalingMode").unwrap_or_else(|| "STANDARD".into());
            cx.call(V2, "PutDedicatedIpPoolScalingAttributes", json!({"PoolName": name, "ScalingMode": mode})).await?;
        }
        retag(cx, &cx.arn("ses", &format!("dedicated-ip-pool/{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteDedicatedIpPool", json!({"PoolName": name})).await)
    }
}

// ---- ReceiptRuleSet ----------------------------------------------------

struct ReceiptRuleSet;

#[async_trait::async_trait]
impl Provider for ReceiptRuleSet {
    fn create_only(&self) -> &'static [&'static str] {
        &["RuleSetName"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("RuleSetName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "RuleSetName").unwrap_or_else(|| generated(cx, 64));
        cx.call(V1, "CreateReceiptRuleSet", json!({"RuleSetName": name})).await?;
        Ok(Created::new(&name))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_codes(cx.call(V1, "DeleteReceiptRuleSet", json!({"RuleSetName": name})).await, &["RuleSetDoesNotExist"])
    }
}

// ---- ReceiptRule -------------------------------------------------------

struct ReceiptRule;

fn rule(props: &Props, name: &str) -> Value {
    let mut r = Value::Object(obj(props, "Rule"));
    r["Name"] = json!(name);
    coerce(&mut r, &[], &["Enabled", "ScanEnabled"], &[]);
    r
}

#[async_trait::async_trait]
impl Provider for ReceiptRule {
    fn create_only(&self) -> &'static [&'static str] {
        &["RuleSetName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["RuleSetName", "Rule"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let set = req(props, "RuleSetName")?;
        let name = obj(props, "Rule").get("Name").map(text).unwrap_or_else(|| generated(cx, 64));
        let mut input = json!({"RuleSetName": set, "Rule": rule(props, &name)});
        if let Some(a) = s(props, "After") {
            input["After"] = json!(a);
        }
        cx.call(V1, "CreateReceiptRule", input).await?;
        Ok(Created::new(&name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let name_of = |p: &Props| obj(p, "Rule").get("Name").map(text);
        if name_of(old) != name_of(new) {
            return Err(HandlerError::handler(
                "NotUpdatable",
                "Resource of type 'AWS::SES::ReceiptRule' cannot change Rule.Name in place",
            ));
        }
        let set = req(new, "RuleSetName")?;
        if changed(old, new, "Rule") {
            cx.call(V1, "UpdateReceiptRule", json!({"RuleSetName": set, "Rule": rule(new, name)})).await?;
        }
        if changed(old, new, "After") {
            let mut input = json!({"RuleSetName": set, "RuleName": name});
            if let Some(a) = s(new, "After") {
                input["After"] = json!(a);
            }
            cx.call(V1, "SetReceiptRulePosition", input).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let set = req(props, "RuleSetName")?;
        gone_codes(
            cx.call(V1, "DeleteReceiptRule", json!({"RuleSetName": set, "RuleName": name})).await,
            &["RuleSetDoesNotExist", "RuleDoesNotExist"],
        )
    }
}

// ---- ReceiptFilter -----------------------------------------------------

struct ReceiptFilter;

#[async_trait::async_trait]
impl Provider for ReceiptFilter {
    fn required(&self) -> &'static [&'static str] {
        &["Filter"]
    }
    fn updatable(&self) -> bool {
        false
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let f = obj(props, "Filter");
        let name = f.get("Name").map(text).unwrap_or_else(|| generated(cx, 64));
        let mut filter = Map::new();
        filter.insert("Name".into(), json!(name));
        copy(&f, &mut filter, &["IpFilter"]);
        cx.call(V1, "CreateReceiptFilter", json!({"Filter": filter})).await?;
        Ok(Created::new(&name))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V1, "DeleteReceiptFilter", json!({"FilterName": name})).await)
    }
}
