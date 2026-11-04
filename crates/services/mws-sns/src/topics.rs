//! Topics: lifecycle, attributes, access policy, tags and data protection
//! policies.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};

use crate::generated::types;
use crate::names::{self, account_of};
use crate::state::{State, Topic};
use crate::{errors, Sns};

const PAGE: usize = 100;
const MAX_TAGS: usize = 50;

const FEEDBACK_PROTOCOLS: &[&str] = &["HTTP", "Lambda", "SQS", "Application", "Firehose"];

/// Attributes `CreateTopic` accepts (`FifoTopic` only there).
fn settable(name: &str) -> bool {
    const PLAIN: &[&str] = &[
        "DeliveryPolicy",
        "DisplayName",
        "Policy",
        "SignatureVersion",
        "TracingConfig",
        "KmsMasterKeyId",
        "ContentBasedDeduplication",
        "ArchivePolicy",
        "FifoThroughputScope",
    ];
    PLAIN.contains(&name)
        || FEEDBACK_PROTOCOLS.iter().any(|p| {
            name.strip_prefix(p).is_some_and(|rest| {
                matches!(rest, "SuccessFeedbackRoleArn" | "SuccessFeedbackSampleRate" | "FailureFeedbackRoleArn")
            })
        })
}

pub(crate) fn default_policy(arn: &str, account: &str) -> String {
    serde_json::json!({
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [{
            "Sid": "__default_statement_ID",
            "Effect": "Allow",
            "Principal": { "AWS": "*" },
            "Action": [
                "SNS:GetTopicAttributes",
                "SNS:SetTopicAttributes",
                "SNS:AddPermission",
                "SNS:RemovePermission",
                "SNS:DeleteTopic",
                "SNS:Subscribe",
                "SNS:ListSubscriptionsByTopic",
                "SNS:Publish"
            ],
            "Resource": arn,
            "Condition": { "StringEquals": { "AWS:SourceOwner": account } }
        }]
    })
    .to_string()
}

pub(crate) const DEFAULT_DELIVERY_POLICY: &str = r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false,"defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}}"#;

/// Check one topic attribute value.
fn validate_attribute(name: &str, value: &str, fifo: bool) -> Result<(), ServiceError> {
    match name {
        "Policy" => {
            Policy::parse(value, PolicyKind::Resource)
                .map_err(|e| errors::invalid(format!("Policy Error: {}", e.0)))?;
        }
        "DeliveryPolicy" => {
            if !value.is_empty() {
                let v: serde_json::Value =
                    serde_json::from_str(value).map_err(|_| errors::invalid("DeliveryPolicy: failed to parse JSON"))?;
                if !v.is_object() {
                    return Err(errors::invalid("DeliveryPolicy: failed to parse JSON"));
                }
            }
        }
        "DisplayName" => {
            if value.chars().count() > 100 {
                return Err(errors::invalid("DisplayName"));
            }
        }
        "SignatureVersion" => {
            if !matches!(value, "1" | "2") {
                return Err(errors::invalid("SignatureVersion"));
            }
        }
        "TracingConfig" => {
            if !matches!(value, "PassThrough" | "Active") {
                return Err(errors::invalid("TracingConfig"));
            }
        }
        "ContentBasedDeduplication" => {
            if !fifo {
                return Err(errors::invalid(
                    "ContentBasedDeduplication Reason: Content-based deduplication can only be set for FIFO topics",
                ));
            }
            if !matches!(value, "true" | "false") {
                return Err(errors::invalid("ContentBasedDeduplication"));
            }
        }
        "FifoThroughputScope" => {
            if !fifo {
                return Err(errors::invalid(
                    "FifoThroughputScope Reason: FifoThroughputScope can only be set for FIFO topics",
                ));
            }
            if !matches!(value, "Topic" | "MessageGroup") {
                return Err(errors::invalid("FifoThroughputScope"));
            }
        }
        "ArchivePolicy" => {
            if !fifo {
                return Err(errors::invalid("ArchivePolicy Reason: Archive policy can only be set for FIFO topics"));
            }
            if !value.is_empty() {
                let v: serde_json::Value = serde_json::from_str(value).map_err(|_| errors::invalid("ArchivePolicy"))?;
                let days = v.get("MessageRetentionPeriod").and_then(|d| match d {
                    serde_json::Value::String(s) => s.parse::<i64>().ok(),
                    serde_json::Value::Number(n) => n.as_i64(),
                    _ => None,
                });
                if !days.is_some_and(|d| (1..=365).contains(&d)) {
                    return Err(errors::invalid(
                        "ArchivePolicy Reason: MessageRetentionPeriod must be between 1 and 365 days",
                    ));
                }
            }
        }
        n if n.ends_with("SuccessFeedbackSampleRate") => {
            if !value.parse::<u32>().is_ok_and(|r| r <= 100) {
                return Err(errors::invalid(n));
            }
        }
        n if n.ends_with("FeedbackRoleArn") && !value.starts_with("arn:") => {
            return Err(errors::invalid(n));
        }
        _ => {}
    }
    Ok(())
}

fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    for t in tags {
        if t.key.is_empty() || t.key.chars().count() > 128 {
            return Err(errors::invalid("Tags Reason: Tag keys must be between 1 and 128 characters long"));
        }
        if t.value.chars().count() > 256 {
            return Err(errors::invalid("Tags Reason: Tag values must be at most 256 characters long"));
        }
        if t.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid("Tags Reason: Tag keys must not start with 'aws:'"));
        }
    }
    Ok(())
}

fn tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for t in tags {
        c.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

pub(crate) fn validate_data_protection_policy(doc: &str) -> Result<(), ServiceError> {
    crate::data_protection::DataProtection::parse(doc).map(|_| ())
}

impl Sns {
    /// Authorize `action` on a topic, evaluating its access policy and
    /// exposing its tags as `aws:ResourceTag/...`.
    pub(crate) fn authorize_topic(
        &self,
        ctx: &RequestContext,
        action: &str,
        topic_arn: &str,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let (policy, tags) = {
            let st = self.lock();
            match st.topics.get(topic_arn) {
                Some(t) => (t.policy().map(str::to_string), t.tags.clone()),
                None => (None, Vec::new()),
            }
        };
        for t in tags {
            extra.entry(format!("aws:ResourceTag/{}", t.key)).or_insert_with(|| vec![t.value]);
        }
        ctx.authorize_with_resource_policy(action, topic_arn, policy.as_deref(), extra)
    }

    pub(crate) fn topic<'a>(st: &'a State, arn: &str) -> Result<&'a Topic, ServiceError> {
        st.topics.get(arn).ok_or_else(errors::topic_not_found)
    }

    pub(crate) fn topic_mut<'a>(st: &'a mut State, arn: &str) -> Result<&'a mut Topic, ServiceError> {
        st.topics.get_mut(arn).ok_or_else(errors::topic_not_found)
    }

    pub(crate) fn create_topic_impl(
        &self,
        ctx: &RequestContext,
        input: types::CreateTopicInput,
    ) -> Result<types::CreateTopicResponse, ServiceError> {
        let account = account_of(ctx);
        let attributes = input.attributes.unwrap_or_default();
        let fifo = match attributes.get("FifoTopic").map(String::as_str) {
            None => false,
            Some(v) if v.eq_ignore_ascii_case("true") => true,
            Some(v) if v.eq_ignore_ascii_case("false") => false,
            Some(_) => return Err(errors::invalid("FifoTopic")),
        };
        if !names::valid_topic_name(&input.name, fifo) {
            return Err(errors::invalid("Topic Name"));
        }
        let arn = names::topic_arn(ctx, &account, &input.name);
        let tags = input.tags.unwrap_or_default();
        validate_tags(&tags)?;
        let mut c = tag_context(&tags);
        ctx.authorize("sns:CreateTopic", &arn, c.clone())?;
        if !tags.is_empty() {
            c.extend(ConditionContext::new());
            ctx.authorize("sns:TagResource", &arn, c)?;
        }
        for (name, value) in &attributes {
            if name == "FifoTopic" {
                continue;
            }
            if !settable(name) {
                return Err(errors::invalid(format!("Attributes Reason: Unknown attribute {name}")));
            }
            validate_attribute(name, value, fifo)?;
        }
        if let Some(doc) = &input.data_protection_policy {
            validate_data_protection_policy(doc)?;
        }
        if tags.len() > MAX_TAGS {
            return Err(errors::tag_limit_exceeded("Could not complete request: tag quota of per resource exceeded"));
        }
        let mut st = self.lock();
        if let Some(existing) = st.topics.get(&arn) {
            // CreateTopic is idempotent for the same name and settings.
            let differs = attributes.iter().any(|(k, v)| {
                let current = match k.as_str() {
                    "FifoTopic" => existing.is_fifo().to_string(),
                    _ => existing.attributes.get(k).cloned().unwrap_or_default(),
                };
                !current.eq_ignore_ascii_case(v)
            });
            if differs {
                return Err(errors::invalid("Attributes Reason: Topic already exists with different attributes"));
            }
            let tags_differ = tags.iter().any(|t| !existing.tags.iter().any(|e| e.key == t.key && e.value == t.value));
            if tags_differ {
                return Err(errors::invalid("Tags Reason: Topic already exists with different tags"));
            }
            return Ok(types::CreateTopicResponse { topic_arn: Some(arn) });
        }
        let mut stored: BTreeMap<String, String> = attributes;
        stored.remove("FifoTopic");
        if fifo {
            stored.insert("FifoTopic".into(), "true".into());
            stored.entry("ContentBasedDeduplication".into()).or_insert_with(|| "false".into());
        }
        stored.entry("Policy".into()).or_insert_with(|| default_policy(&arn, &account));
        let mut deduped: Vec<types::Tag> = Vec::new();
        for t in tags {
            match deduped.iter_mut().find(|e| e.key == t.key) {
                Some(e) => e.value = t.value,
                None => deduped.push(t),
            }
        }
        let mut topic = Topic {
            arn: arn.clone(),
            name: input.name,
            account,
            region: ctx.region.clone(),
            attributes: stored,
            tags: deduped,
            data_protection_policy: input.data_protection_policy.filter(|d| !d.is_empty()),
            ..Topic::default()
        };
        topic.sync_archive(ctx.received_at);
        st.topics.insert(arn.clone(), topic);
        Ok(types::CreateTopicResponse { topic_arn: Some(arn) })
    }

    pub(crate) fn delete_topic_impl(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTopicInput,
    ) -> Result<(), ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:DeleteTopic", &input.topic_arn, ConditionContext::new())?;
        let mut st = self.lock();
        // DeleteTopic is idempotent.
        if st.topics.remove(&input.topic_arn).is_some() {
            st.subscriptions.retain(|_, s| s.topic_arn != input.topic_arn);
        }
        Ok(())
    }

    pub(crate) fn list_topics_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListTopicsInput,
    ) -> Result<types::ListTopicsResponse, ServiceError> {
        let account = account_of(ctx);
        ctx.authorize(
            "sns:ListTopics",
            &format!("arn:{}:sns:{}:{account}:*", ctx.partition, ctx.region),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let arns: Vec<&String> =
            st.topics.values().filter(|t| t.account == account && t.region == ctx.region).map(|t| &t.arn).collect();
        let (page, next) = paginate(&arns, input.next_token.as_deref(), PAGE)?;
        Ok(types::ListTopicsResponse {
            topics: Some(page.into_iter().map(|a| types::Topic { topic_arn: Some(a.to_string()) }).collect()),
            next_token: next,
        })
    }

    pub(crate) fn get_topic_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetTopicAttributesInput,
    ) -> Result<types::GetTopicAttributesResponse, ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:GetTopicAttributes", &input.topic_arn, ConditionContext::new())?;
        let st = self.lock();
        let t = Self::topic(&st, &input.topic_arn)?;
        let mut out = t.attributes.clone();
        let (mut confirmed, mut pending) = (0, 0);
        for s in st.subscriptions.values().filter(|s| s.topic_arn == t.arn) {
            if s.pending {
                pending += 1;
            } else {
                confirmed += 1;
            }
        }
        out.insert("TopicArn".into(), t.arn.clone());
        out.insert("Owner".into(), t.account.clone());
        out.insert("SubscriptionsConfirmed".into(), confirmed.to_string());
        out.insert("SubscriptionsPending".into(), pending.to_string());
        out.insert("SubscriptionsDeleted".into(), t.subscriptions_deleted.to_string());
        out.entry("DisplayName".into()).or_default();
        out.entry("Policy".into()).or_insert_with(|| default_policy(&t.arn, &t.account));
        let effective = match t.attributes.get("DeliveryPolicy").filter(|d| !d.is_empty()) {
            Some(d) => merge_delivery_policy(d),
            None => DEFAULT_DELIVERY_POLICY.to_string(),
        };
        out.insert("EffectiveDeliveryPolicy".into(), effective);
        if let Some(since) = &t.archive_since {
            out.insert("BeginningArchiveTime".into(), mws_proto_query::format_timestamp(since));
        }
        Ok(types::GetTopicAttributesResponse { attributes: Some(out) })
    }

    pub(crate) fn set_topic_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::SetTopicAttributesInput,
    ) -> Result<(), ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:SetTopicAttributes", &input.topic_arn, ConditionContext::new())?;
        let name = input.attribute_name;
        if !settable(&name) {
            return Err(errors::invalid("AttributeName"));
        }
        let value = input.attribute_value.unwrap_or_default();
        let mut st = self.lock();
        let t = Self::topic_mut(&mut st, &input.topic_arn)?;
        let fifo = t.is_fifo();
        if name == "Policy" && value.is_empty() {
            t.attributes.insert(name, default_policy(&t.arn, &t.account));
            return Ok(());
        }
        validate_attribute(&name, &value, fifo)?;
        if value.is_empty() && name != "DisplayName" {
            t.attributes.remove(&name);
        } else {
            t.attributes.insert(name, value);
        }
        t.sync_archive(ctx.received_at);
        Ok(())
    }

    pub(crate) fn add_permission_impl(
        &self,
        ctx: &RequestContext,
        input: types::AddPermissionInput,
    ) -> Result<(), ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:AddPermission", &input.topic_arn, ConditionContext::new())?;
        if input.aws_account_id.is_empty() {
            return Err(errors::invalid("AWSAccountId"));
        }
        if input.action_name.is_empty() {
            return Err(errors::invalid("ActionName"));
        }
        const ACTIONS: &[&str] = &[
            "AddPermission",
            "ConfirmSubscription",
            "DeleteTopic",
            "GetTopicAttributes",
            "ListSubscriptionsByTopic",
            "Publish",
            "RemovePermission",
            "SetTopicAttributes",
            "Subscribe",
            "Receive",
            "GetDataProtectionPolicy",
            "PutDataProtectionPolicy",
        ];
        for a in &input.action_name {
            if !ACTIONS.contains(&a.as_str()) {
                return Err(errors::invalid("Policy statement action out of service scope!"));
            }
        }
        let mut st = self.lock();
        let t = Self::topic_mut(&mut st, &input.topic_arn)?;
        let partition = ctx.partition.clone();
        let doc = t.policy().map(str::to_string).unwrap_or_else(|| default_policy(&t.arn, &t.account));
        let mut policy: serde_json::Value = serde_json::from_str(&doc).unwrap_or_else(|_| serde_json::json!({}));
        let statements = statement_list(&mut policy);
        if statements.iter().any(|s| s.get("Sid").and_then(|v| v.as_str()) == Some(input.label.as_str())) {
            return Err(errors::invalid("Statement already exists"));
        }
        let principals: Vec<serde_json::Value> = input
            .aws_account_id
            .iter()
            .map(|a| {
                if a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit()) {
                    serde_json::Value::String(format!("arn:{partition}:iam::{a}:root"))
                } else {
                    serde_json::Value::String(a.clone())
                }
            })
            .collect();
        let principal =
            if principals.len() == 1 { principals[0].clone() } else { serde_json::Value::Array(principals) };
        let actions: Vec<serde_json::Value> =
            input.action_name.iter().map(|a| serde_json::Value::String(format!("SNS:{a}"))).collect();
        let action = if actions.len() == 1 { actions[0].clone() } else { serde_json::Value::Array(actions) };
        statements.push(serde_json::json!({
            "Sid": input.label,
            "Effect": "Allow",
            "Principal": { "AWS": principal },
            "Action": action,
            "Resource": t.arn,
        }));
        t.attributes.insert("Policy".into(), policy.to_string());
        Ok(())
    }

    pub(crate) fn remove_permission_impl(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionInput,
    ) -> Result<(), ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:RemovePermission", &input.topic_arn, ConditionContext::new())?;
        let mut st = self.lock();
        let t = Self::topic_mut(&mut st, &input.topic_arn)?;
        let Some(doc) = t.policy().map(str::to_string) else { return Ok(()) };
        let mut policy: serde_json::Value = serde_json::from_str(&doc).unwrap_or_else(|_| serde_json::json!({}));
        let statements = statement_list(&mut policy);
        statements.retain(|s| s.get("Sid").and_then(|v| v.as_str()) != Some(input.label.as_str()));
        t.attributes.insert("Policy".into(), policy.to_string());
        Ok(())
    }

    // ---- tags --------------------------------------------------------------

    pub(crate) fn tag_resource_impl(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        validate_tags(&input.tags)?;
        self.authorize_topic(ctx, "sns:TagResource", &input.resource_arn, tag_context(&input.tags))?;
        let mut st = self.lock();
        let t = st.topics.get_mut(&input.resource_arn).ok_or_else(errors::resource_missing)?;
        let mut tags = t.tags.clone();
        for tag in input.tags {
            match tags.iter_mut().find(|e| e.key == tag.key) {
                Some(e) => e.value = tag.value,
                None => tags.push(tag),
            }
        }
        if tags.len() > MAX_TAGS {
            return Err(errors::tag_limit_exceeded("Could not complete request: tag quota of per resource exceeded"));
        }
        t.tags = tags;
        Ok(types::TagResourceResponse {})
    }

    pub(crate) fn untag_resource_impl(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut c = ConditionContext::new();
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize_topic(ctx, "sns:UntagResource", &input.resource_arn, c)?;
        let mut st = self.lock();
        let t = st.topics.get_mut(&input.resource_arn).ok_or_else(errors::resource_missing)?;
        t.tags.retain(|tag| !input.tag_keys.contains(&tag.key));
        Ok(types::UntagResourceResponse {})
    }

    pub(crate) fn list_tags_for_resource_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.authorize_topic(ctx, "sns:ListTagsForResource", &input.resource_arn, ConditionContext::new())?;
        let st = self.lock();
        let t = st.topics.get(&input.resource_arn).ok_or_else(errors::resource_missing)?;
        Ok(types::ListTagsForResourceResponse { tags: Some(t.tags.clone()) })
    }

    // ---- data protection ---------------------------------------------------

    pub(crate) fn put_data_protection_policy_impl(
        &self,
        ctx: &RequestContext,
        input: types::PutDataProtectionPolicyInput,
    ) -> Result<(), ServiceError> {
        names::check_topic_arn(ctx, &input.resource_arn, "ResourceArn")?;
        self.authorize_topic(ctx, "sns:PutDataProtectionPolicy", &input.resource_arn, ConditionContext::new())?;
        if !input.data_protection_policy.is_empty() {
            validate_data_protection_policy(&input.data_protection_policy)?;
        }
        let mut st = self.lock();
        let t = st.topics.get_mut(&input.resource_arn).ok_or_else(errors::resource_missing)?;
        t.data_protection_policy = Some(input.data_protection_policy).filter(|d| !d.is_empty());
        Ok(())
    }

    pub(crate) fn get_data_protection_policy_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetDataProtectionPolicyInput,
    ) -> Result<types::GetDataProtectionPolicyResponse, ServiceError> {
        names::check_topic_arn(ctx, &input.resource_arn, "ResourceArn")?;
        self.authorize_topic(ctx, "sns:GetDataProtectionPolicy", &input.resource_arn, ConditionContext::new())?;
        let st = self.lock();
        let t = st.topics.get(&input.resource_arn).ok_or_else(errors::resource_missing)?;
        Ok(types::GetDataProtectionPolicyResponse { data_protection_policy: t.data_protection_policy.clone() })
    }
}

fn statement_list(policy: &mut serde_json::Value) -> &mut Vec<serde_json::Value> {
    if !policy.is_object() {
        *policy = serde_json::json!({});
    }
    let obj = policy.as_object_mut().expect("object");
    obj.entry("Version").or_insert_with(|| "2008-10-17".into());
    let st = obj.entry("Statement").or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !st.is_array() {
        let single = st.take();
        *st = serde_json::Value::Array(vec![single]);
    }
    st.as_array_mut().expect("array")
}

/// The topic's delivery policy with SNS's defaults filled in.
fn merge_delivery_policy(doc: &str) -> String {
    let mut base: serde_json::Value = serde_json::from_str(DEFAULT_DELIVERY_POLICY).expect("default parses");
    if let Ok(over) = serde_json::from_str::<serde_json::Value>(doc) {
        merge(&mut base, &over);
    }
    base.to_string()
}

fn merge(base: &mut serde_json::Value, over: &serde_json::Value) {
    match (base, over) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                merge(b.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
        (b, o) => *b = o.clone(),
    }
}

/// A page of `items` starting after the item a previous page's token named.
pub(crate) fn paginate<'a, T: AsRef<str>>(
    items: &'a [T],
    token: Option<&str>,
    page: usize,
) -> Result<(Vec<&'a str>, Option<String>), ServiceError> {
    use base64::Engine;
    let start = match token.filter(|t| !t.is_empty()) {
        None => 0,
        Some(t) => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(t)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| errors::invalid("NextToken"))?;
            items.iter().position(|i| i.as_ref() >= decoded.as_str()).unwrap_or(items.len())
        }
    };
    let end = (start + page).min(items.len());
    let next =
        (end < items.len()).then(|| base64::engine::general_purpose::STANDARD.encode(items[end].as_ref().as_bytes()));
    Ok((items[start..end].iter().map(AsRef::as_ref).collect(), next))
}
