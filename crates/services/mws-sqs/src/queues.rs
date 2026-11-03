//! Queue lifecycle, attributes, tags and permissions.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::attributes::{self, unknown_attribute};
use crate::generated::{errors, types};
use crate::names::{
    arn_for_url, authorize_queue, authorize_queue_with, b64, invalid_parameter, invalid_parameter_value,
    missing_parameter, now_ms, queue_arn, queue_url, valid_queue_name,
};
use crate::state::Queue;
use crate::Sqs;

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

fn check_tags(tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(invalid_parameter_value("Too many tags added for queue. The maximum number of tags is 50."));
    }
    for (k, v) in tags {
        if k.is_empty() || k.chars().count() > 128 {
            return Err(invalid_parameter_value("Tag keys must be between 1 and 128 characters in length."));
        }
        if v.chars().count() > 256 {
            return Err(invalid_parameter_value("Tag values must be less than 256 characters in length."));
        }
        if k.to_ascii_lowercase().starts_with("aws:") {
            return Err(invalid_parameter_value("Tag keys cannot start with the reserved prefix 'aws:'."));
        }
    }
    Ok(())
}

/// Validate a full attribute map for a queue of the given type, adding the
/// derived encryption settings.
fn validated_attributes(
    given: &BTreeMap<String, String>,
    fifo: bool,
    creating: bool,
) -> Result<BTreeMap<String, String>, ServiceError> {
    let mut out = BTreeMap::new();
    for (name, value) in given {
        out.insert(name.clone(), attributes::validate(name, value, fifo, creating)?);
    }
    let kms = out.get("KmsMasterKeyId").is_some_and(|k| !k.is_empty());
    if kms && out.get("SqsManagedSseEnabled").map(String::as_str) == Some("true") {
        return Err(errors::invalid_attribute_name(
            "You can use one type of server-side encryption (SSE) at one time. You can either enable KMS SSE or SQS SSE.",
        ));
    }
    if out.get("FifoThroughputLimit").map(String::as_str) == Some("perMessageGroupId")
        && out.get("DeduplicationScope").map(String::as_str) == Some("queue")
    {
        return Err(errors::invalid_attribute_value(
            "Invalid value for the parameter FifoThroughputLimit. perMessageGroupId requires DeduplicationScope messageGroup.",
        ));
    }
    Ok(out)
}

/// Apply validated attributes to a queue's stored ones, keeping the two
/// server-side encryption modes exclusive.
fn apply_attributes(stored: &mut BTreeMap<String, String>, changes: BTreeMap<String, String>) {
    for (name, value) in changes {
        match name.as_str() {
            "KmsMasterKeyId" if !value.is_empty() => {
                stored.insert("SqsManagedSseEnabled".into(), "false".into());
                stored.entry("KmsDataKeyReusePeriodSeconds".into()).or_insert_with(|| "300".into());
            }
            "SqsManagedSseEnabled" if value == "true" => {
                stored.remove("KmsMasterKeyId");
                stored.remove("KmsDataKeyReusePeriodSeconds");
            }
            _ => {}
        }
        if value.is_empty()
            && matches!(name.as_str(), "Policy" | "RedrivePolicy" | "RedriveAllowPolicy" | "KmsMasterKeyId")
        {
            stored.remove(&name);
        } else {
            stored.insert(name, value);
        }
    }
}

impl Sqs {
    pub fn create_queue(
        &self,
        ctx: &RequestContext,
        input: types::CreateQueueRequest,
    ) -> Result<types::CreateQueueResult, ServiceError> {
        let name = input.queue_name;
        let given = input.attributes.unwrap_or_default();
        let tags = input.tags.unwrap_or_default();
        let fifo = given.get("FifoQueue").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if !valid_queue_name(&name, fifo) {
            return Err(invalid_parameter_value(if fifo {
                "The name of a FIFO queue can only include alphanumeric characters, hyphens, or underscores, must end with .fifo suffix and be 1 to 80 in length."
            } else {
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
            }));
        }
        let account = ctx.caller.account_id.clone();
        let arn = queue_arn(&ctx.partition, &ctx.region, &account, &name);
        let mut context = request_tag_context(&tags);
        ctx.authorize("sqs:CreateQueue", &arn, context.clone())?;
        if !tags.is_empty() {
            context.retain(|k, _| k.starts_with("aws:"));
            ctx.authorize("sqs:TagQueue", &arn, context)?;
        }
        let mut changes = validated_attributes(&given, fifo, true)?;
        check_tags(&tags)?;
        let now = now_ms(ctx);
        let url = queue_url(ctx, &account, &name);
        let mut st = self.lock();
        if let Some(existing) = st.queues.get(&arn) {
            for (k, v) in &changes {
                let current = existing.attr(k).unwrap_or_default();
                let same = current == v || (k == "FifoQueue" && v == "false" && !existing.fifo);
                if !same {
                    return Err(errors::queue_name_exists(format!(
                        "A queue already exists with the same name and a different value for attribute {k}"
                    )));
                }
            }
            return Ok(types::CreateQueueResult { queue_url: Some(url) });
        }
        if st.deleted.get(&arn).is_some_and(|at| at + 60_000 > now) {
            return Err(errors::queue_deleted_recently(
                "You must wait 60 seconds after deleting a queue before you can create another with the same name.",
            ));
        }
        if let Some(policy) = changes.get("RedrivePolicy") {
            attributes::check_redrive_target(&st, &arn, fifo, policy)?;
        }
        if !fifo {
            changes.remove("FifoQueue");
        }
        let mut stored = attributes::defaults(fifo);
        apply_attributes(&mut stored, changes);
        st.deleted.remove(&arn);
        st.queues.insert(
            arn.clone(),
            Queue {
                name,
                arn,
                account,
                region: ctx.region.clone(),
                fifo,
                created_at: now,
                last_modified_at: now,
                attributes: stored,
                tags,
                ..Queue::default()
            },
        );
        Ok(types::CreateQueueResult { queue_url: Some(url) })
    }

    pub fn delete_queue(&self, ctx: &RequestContext, input: types::DeleteQueueRequest) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        authorize_queue(ctx, "sqs:DeleteQueue", st.queue(&arn)?)?;
        st.queues.remove(&arn);
        st.deleted.insert(arn, now_ms(ctx));
        drop(st);
        self.arrivals.notify_waiters();
        Ok(())
    }

    pub fn get_queue_url(
        &self,
        ctx: &RequestContext,
        input: types::GetQueueUrlRequest,
    ) -> Result<types::GetQueueUrlResult, ServiceError> {
        let account = input.queue_owner_aws_account_id.unwrap_or_else(|| ctx.caller.account_id.clone());
        let arn = queue_arn(&ctx.partition, &ctx.region, &account, &input.queue_name);
        let st = self.lock();
        let q = st.queue(&arn)?;
        authorize_queue(ctx, "sqs:GetQueueUrl", q)?;
        Ok(types::GetQueueUrlResult { queue_url: Some(queue_url(ctx, &q.account, &q.name)) })
    }

    pub fn list_queues(
        &self,
        ctx: &RequestContext,
        input: types::ListQueuesRequest,
    ) -> Result<types::ListQueuesResult, ServiceError> {
        ctx.authorize("sqs:ListQueues", "*", ConditionContext::new())?;
        let prefix = input.queue_name_prefix.unwrap_or_default();
        let account = &ctx.caller.account_id;
        let st = self.lock();
        let names: Vec<&Queue> = st
            .queues
            .values()
            .filter(|q| &q.account == account && q.region == ctx.region && q.name.starts_with(&prefix))
            .collect();
        let (page, next) = paginate(names, input.max_results, input.next_token.as_deref(), |q| &q.name)?;
        let urls: Vec<String> = page.iter().map(|q| queue_url(ctx, &q.account, &q.name)).collect();
        Ok(types::ListQueuesResult { queue_urls: (!urls.is_empty()).then_some(urls), next_token: next })
    }

    pub fn list_dead_letter_source_queues(
        &self,
        ctx: &RequestContext,
        input: types::ListDeadLetterSourceQueuesRequest,
    ) -> Result<types::ListDeadLetterSourceQueuesResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let st = self.lock();
        authorize_queue(ctx, "sqs:ListDeadLetterSourceQueues", st.queue(&arn)?)?;
        let sources: Vec<&Queue> =
            st.queues.values().filter(|q| q.redrive().is_some_and(|(target, _)| target == arn)).collect();
        let (page, next) = paginate(sources, input.max_results, input.next_token.as_deref(), |q| &q.name)?;
        Ok(types::ListDeadLetterSourceQueuesResult {
            queue_urls: page.iter().map(|q| queue_url(ctx, &q.account, &q.name)).collect(),
            next_token: next,
        })
    }

    pub fn get_queue_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetQueueAttributesRequest,
    ) -> Result<types::GetQueueAttributesResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        authorize_queue(ctx, "sqs:GetQueueAttributes", st.queue(&arn)?)?;
        self.progress(&mut st, now);
        let q = st.queue_mut(&arn)?;
        q.expire(now);
        let requested = input.attribute_names.unwrap_or_default();
        for name in &requested {
            if !attributes::known(name) {
                return Err(unknown_attribute(name));
            }
        }
        let names: Vec<String> = if requested.iter().any(|n| n == "All") {
            let mut all: Vec<String> = q.attributes.keys().cloned().collect();
            all.extend(attributes::READ_ONLY.iter().map(|s| s.to_string()));
            all
        } else {
            requested
        };
        let attrs: BTreeMap<String, String> =
            names.iter().filter_map(|n| attributes::get(q, n, now).map(|v| (n.clone(), v))).collect();
        Ok(types::GetQueueAttributesResult { attributes: (!attrs.is_empty()).then_some(attrs) })
    }

    pub fn set_queue_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetQueueAttributesRequest,
    ) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue(&arn)?;
        authorize_queue(ctx, "sqs:SetQueueAttributes", q)?;
        let fifo = q.fifo;
        let changes = validated_attributes(&input.attributes, fifo, false)?;
        if let Some(policy) = changes.get("RedrivePolicy") {
            attributes::check_redrive_target(&st, &arn, fifo, policy)?;
        }
        let now = now_ms(ctx);
        let q = st.queue_mut(&arn)?;
        if changes.contains_key("KmsMasterKeyId") || changes.contains_key("SqsManagedSseEnabled") {
            q.data_keys.clear();
        }
        apply_attributes(&mut q.attributes, changes);
        q.last_modified_at = now;
        drop(st);
        self.arrivals.notify_waiters();
        Ok(())
    }

    pub fn purge_queue(&self, ctx: &RequestContext, input: types::PurgeQueueRequest) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:PurgeQueue", q)?;
        if q.last_purge_at.is_some_and(|at| at + 60_000 > now) {
            return Err(errors::purge_queue_in_progress(format!(
                "Only one PurgeQueue operation on {} is allowed every 60 seconds.",
                q.name
            )));
        }
        q.messages.clear();
        q.receive_attempts.clear();
        q.last_purge_at = Some(now);
        Ok(())
    }

    pub fn tag_queue(&self, ctx: &RequestContext, input: types::TagQueueRequest) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue_with(ctx, "sqs:TagQueue", q, request_tag_context(&input.tags))?;
        let mut merged = q.tags.clone();
        merged.extend(input.tags);
        check_tags(&merged)?;
        q.tags = merged;
        Ok(())
    }

    pub fn untag_queue(&self, ctx: &RequestContext, input: types::UntagQueueRequest) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        let mut context = ConditionContext::new();
        if !input.tag_keys.is_empty() {
            context.insert("aws:TagKeys".into(), input.tag_keys.clone());
        }
        authorize_queue_with(ctx, "sqs:UntagQueue", q, context)?;
        for k in &input.tag_keys {
            q.tags.remove(k);
        }
        Ok(())
    }

    pub fn list_queue_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListQueueTagsRequest,
    ) -> Result<types::ListQueueTagsResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let st = self.lock();
        let q = st.queue(&arn)?;
        authorize_queue(ctx, "sqs:ListQueueTags", q)?;
        Ok(types::ListQueueTagsResult { tags: (!q.tags.is_empty()).then(|| q.tags.clone()) })
    }

    pub fn add_permission(&self, ctx: &RequestContext, input: types::AddPermissionRequest) -> Result<(), ServiceError> {
        const ACTIONS: &[&str] = &[
            "*",
            "SendMessage",
            "ReceiveMessage",
            "DeleteMessage",
            "ChangeMessageVisibility",
            "GetQueueAttributes",
            "GetQueueUrl",
            "ListDeadLetterSourceQueues",
            "ListQueueTags",
            "PurgeQueue",
        ];
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:AddPermission", q)?;
        let label = &input.label;
        let label_ok = !label.is_empty()
            && label.len() <= 80
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !label_ok {
            return Err(invalid_parameter(
                "Label",
                label,
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length",
            ));
        }
        if input.aws_account_ids.is_empty() {
            return Err(missing_parameter("AWSAccountIds"));
        }
        if input.actions.is_empty() {
            return Err(missing_parameter("Actions"));
        }
        for a in &input.actions {
            if !ACTIONS.contains(&a.as_str()) {
                return Err(invalid_parameter(
                    "ActionName",
                    a,
                    "Please refer to the appropriate WSDL for a list of valid actions.",
                ));
            }
        }
        for id in &input.aws_account_ids {
            if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_parameter("PrincipalId", id, "Unable to verify."));
            }
        }
        let mut policy: serde_json::Value = match q.policy() {
            Some(p) => serde_json::from_str(p).unwrap_or_default(),
            None => serde_json::json!({
                "Version": "2012-10-17",
                "Id": format!("{arn}/SQSDefaultPolicy"),
                "Statement": [],
            }),
        };
        if !policy["Statement"].is_array() {
            let single = policy["Statement"].take();
            policy["Statement"] = serde_json::Value::Array(if single.is_null() { vec![] } else { vec![single] });
        }
        let statements = policy["Statement"].as_array_mut().expect("normalized to an array");
        if statements.iter().any(|s| s["Sid"].as_str() == Some(label.as_str())) {
            return Err(invalid_parameter("Label", label, "Already exists."));
        }
        let one_or_many = |v: Vec<String>| {
            if v.len() == 1 {
                serde_json::Value::String(v.into_iter().next().unwrap())
            } else {
                serde_json::Value::from(v)
            }
        };
        let principals: Vec<String> =
            input.aws_account_ids.iter().map(|id| format!("arn:{}:iam::{id}:root", ctx.partition)).collect();
        let actions: Vec<String> = input.actions.iter().map(|a| format!("SQS:{a}")).collect();
        statements.push(serde_json::json!({
            "Sid": label,
            "Effect": "Allow",
            "Principal": { "AWS": one_or_many(principals) },
            "Action": one_or_many(actions),
            "Resource": arn,
        }));
        q.attributes.insert("Policy".into(), policy.to_string());
        q.last_modified_at = now_ms(ctx);
        Ok(())
    }

    pub fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionRequest,
    ) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:RemovePermission", q)?;
        let not_found = || invalid_parameter("Label", &input.label, "can't find label on existing policy.");
        let mut policy: serde_json::Value =
            q.policy().and_then(|p| serde_json::from_str(p).ok()).ok_or_else(not_found)?;
        let statements = policy["Statement"].as_array_mut().ok_or_else(not_found)?;
        let before = statements.len();
        statements.retain(|s| s["Sid"].as_str() != Some(input.label.as_str()));
        if statements.len() == before {
            return Err(not_found());
        }
        if statements.is_empty() {
            q.attributes.remove("Policy");
        } else {
            q.attributes.insert("Policy".into(), policy.to_string());
        }
        q.last_modified_at = now_ms(ctx);
        Ok(())
    }
}

/// Page through items sorted by `key`. Tokens are opaque (the last key
/// returned); without `MaxResults` up to 1000 come back and no token.
fn paginate<'a, T>(
    items: Vec<&'a T>,
    max_results: Option<i32>,
    next_token: Option<&str>,
    key: impl Fn(&T) -> &str,
) -> Result<(Vec<&'a T>, Option<String>), ServiceError> {
    if let Some(m) = max_results {
        if !(1..=1000).contains(&m) {
            return Err(invalid_parameter("MaxResults", m, "MaxResults must be an integer between 1 and 1000."));
        }
    }
    let after = match next_token {
        Some(t) => Some(
            b64()
                .decode(t)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| invalid_parameter_value("Invalid NextToken value."))?,
        ),
        None => None,
    };
    let mut rest: Vec<&T> = items.into_iter().filter(|i| after.as_deref().is_none_or(|a| key(i) > a)).collect();
    rest.sort_by(|a, b| key(a).cmp(key(b)));
    let limit = max_results.map(|m| m as usize).unwrap_or(1000);
    let more = rest.len() > limit;
    rest.truncate(limit);
    let next = (more && max_results.is_some()).then(|| b64().encode(key(rest.last().unwrap())));
    Ok((rest, next))
}
