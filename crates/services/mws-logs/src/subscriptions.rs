//! Metric filters, subscription filters and (cross-account) destinations.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};

use crate::events::parse_pattern;
use crate::generated::{errors, types};
use crate::names::{arn, check_tags, now_ms, page, request_tag_conditions, GroupRef};
use crate::state::Destination;
use crate::Logs;

const MAX_METRIC_FILTERS: usize = 100;
const MAX_SUBSCRIPTION_FILTERS: usize = 2;

fn check_metric_value(v: &str) -> Result<(), ServiceError> {
    let ok = v.parse::<f64>().is_ok() || (v.starts_with('$') && v.len() > 1);
    if ok {
        Ok(())
    } else {
        Err(errors::invalid_parameter(format!("Invalid metric value: {v}")))
    }
}

impl Logs {
    // ---- metric filters ------------------------------------------------------

    pub(crate) fn put_metric_filter(
        &self,
        ctx: &RequestContext,
        input: types::PutMetricFilterRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "PutMetricFilter", &g, None, ConditionContext::new())?;
        parse_pattern(Some(&input.filter_pattern))
            .map_err(|_| errors::invalid_parameter("Invalid metric filter pattern"))?;
        for t in &input.metric_transformations {
            check_metric_value(&t.metric_value)?;
            let dims = t.dimensions.as_ref().map_or(0, |d| d.len());
            if dims > 3 {
                return Err(errors::invalid_parameter("A metric transformation can have at most 3 dimensions."));
            }
            if dims > 0 && t.default_value.is_some() {
                return Err(errors::invalid_parameter(
                    "Invalid metric transformation: a default value cannot be set when dimensions are specified.",
                ));
            }
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        if !group.metric_filters.contains_key(&input.filter_name) && group.metric_filters.len() >= MAX_METRIC_FILTERS {
            return Err(errors::limit_exceeded("Resource limit exceeded."));
        }
        let created = group.metric_filters.get(&input.filter_name).and_then(|f| f.creation_time).unwrap_or(now);
        group.metric_filters.insert(
            input.filter_name.clone(),
            types::MetricFilter {
                filter_name: Some(input.filter_name),
                filter_pattern: Some(input.filter_pattern),
                metric_transformations: Some(input.metric_transformations),
                creation_time: Some(created),
                log_group_name: Some(g.name.clone()),
                apply_on_transformed_logs: input.apply_on_transformed_logs,
                field_selection_criteria: input.field_selection_criteria,
                emit_system_field_dimensions: input.emit_system_field_dimensions,
            },
        );
        Ok(())
    }

    pub(crate) fn delete_metric_filter(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMetricFilterRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DeleteMetricFilter", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        st.group_mut(&g)?
            .metric_filters
            .remove(&input.filter_name)
            .ok_or_else(|| errors::resource_not_found("The specified metric filter does not exist."))?;
        Ok(())
    }

    pub(crate) fn describe_metric_filters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMetricFiltersRequest,
    ) -> Result<types::DescribeMetricFiltersResponse, ServiceError> {
        if input.filter_name_prefix.is_some() && input.log_group_name.is_none() {
            return Err(errors::invalid_parameter("filterNamePrefix requires logGroupName."));
        }
        if input.metric_name.is_some() != input.metric_namespace.is_some() {
            return Err(errors::invalid_parameter("metricName and metricNamespace must be specified together."));
        }
        let mut out = Vec::new();
        match &input.log_group_name {
            Some(name) => {
                let g = GroupRef::own(ctx, name);
                self.authorize_group(ctx, "DescribeMetricFilters", &g, None, ConditionContext::new())?;
                let st = self.lock();
                out.extend(st.group(&g)?.metric_filters.values().cloned());
            }
            None => {
                self.authorize(ctx, "DescribeMetricFilters", &arn(ctx, "log-group:*"), ConditionContext::new())?;
                let st = self.lock();
                if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
                    out.extend(r.log_groups.values().flat_map(|g| g.metric_filters.values().cloned()));
                }
            }
        }
        out.retain(|f| {
            input
                .filter_name_prefix
                .as_ref()
                .is_none_or(|p| f.filter_name.as_deref().unwrap_or("").starts_with(p.as_str()))
                && input.metric_name.as_ref().is_none_or(|m| {
                    f.metric_transformations
                        .iter()
                        .flatten()
                        .any(|t| &t.metric_name == m && input.metric_namespace.as_ref() == Some(&t.metric_namespace))
                })
        });
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeMetricFiltersResponse { metric_filters: Some(out), next_token })
    }

    pub(crate) fn test_metric_filter(
        &self,
        ctx: &RequestContext,
        input: types::TestMetricFilterRequest,
    ) -> Result<types::TestMetricFilterResponse, ServiceError> {
        self.authorize(ctx, "TestMetricFilter", "*", ConditionContext::new())?;
        let pattern = parse_pattern(Some(&input.filter_pattern))
            .map_err(|_| errors::invalid_parameter("Invalid metric filter pattern"))?;
        let matches = input
            .log_event_messages
            .iter()
            .enumerate()
            .filter_map(|(i, m)| {
                pattern.extract(m).map(|values| types::MetricFilterMatchRecord {
                    event_number: i as i64 + 1,
                    event_message: Some(m.clone()),
                    extracted_values: Some(values),
                })
            })
            .collect();
        Ok(types::TestMetricFilterResponse { matches: Some(matches) })
    }

    // ---- subscription filters ------------------------------------------------

    /// A CloudWatch Logs destination as a subscription target: it must
    /// exist, and another account's destination must allow the caller in
    /// its access policy.
    fn check_destination(&self, ctx: &RequestContext, destination_arn: &str) -> Result<(), ServiceError> {
        let parts: Vec<&str> = destination_arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[2] != "logs" {
            return Ok(());
        }
        let Some(name) = parts[5].strip_prefix("destination:") else {
            return Err(errors::invalid_parameter(format!("Invalid destination ARN: {destination_arn}")));
        };
        let (region, account) = (parts[3], parts[4]);
        let st = self.lock();
        let d = st
            .region_ref(account, region)
            .and_then(|r| r.destinations.get(name))
            .ok_or_else(|| errors::resource_not_found("The specified destination does not exist."))?;
        if account == ctx.caller.account_id {
            return Ok(());
        }
        let denied = || {
            errors::access_denied(format!(
                "User with accountId: {} is not authorized to perform: logs:PutSubscriptionFilter on resource: {destination_arn}",
                ctx.caller.account_id
            ))
        };
        let doc = d.record.access_policy.as_deref().ok_or_else(denied)?;
        let policy = Policy::parse(doc, PolicyKind::Resource).map_err(|_| denied())?;
        let principal = PrincipalInfo {
            account_id: ctx.caller.account_id.clone(),
            arns: vec![ctx.caller.arn.clone()],
            ..Default::default()
        };
        let context = mws_iam_policy::ConditionContext::new();
        let e = policy.evaluate(&Request {
            action: "logs:PutSubscriptionFilter",
            resource: destination_arn,
            principal: &principal,
            context: &context,
        });
        if e.allowed() && !e.denied() {
            Ok(())
        } else {
            Err(denied())
        }
    }

    pub(crate) fn put_subscription_filter(
        &self,
        ctx: &RequestContext,
        input: types::PutSubscriptionFilterRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "PutSubscriptionFilter", &g, None, ConditionContext::new())?;
        parse_pattern(Some(&input.filter_pattern))?;
        if !input.destination_arn.starts_with("arn:") {
            return Err(errors::invalid_parameter(format!("Invalid destination ARN: {}", input.destination_arn)));
        }
        self.check_destination(ctx, &input.destination_arn)?;
        if let Some(role) = &input.role_arn {
            pass_role(ctx, role)?;
        }
        self.check_subscription_target(ctx, &g, &input.destination_arn, input.role_arn.as_deref())?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        if !group.subscription_filters.contains_key(&input.filter_name)
            && group.subscription_filters.len() >= MAX_SUBSCRIPTION_FILTERS
        {
            return Err(errors::limit_exceeded("Resource limit exceeded."));
        }
        let created = group.subscription_filters.get(&input.filter_name).and_then(|f| f.creation_time).unwrap_or(now);
        group.subscription_filters.insert(
            input.filter_name.clone(),
            types::SubscriptionFilter {
                filter_name: Some(input.filter_name),
                log_group_name: Some(g.name.clone()),
                filter_pattern: Some(input.filter_pattern),
                destination_arn: Some(input.destination_arn),
                role_arn: input.role_arn,
                distribution: Some(input.distribution.unwrap_or_else(|| "ByLogStream".into())),
                apply_on_transformed_logs: input.apply_on_transformed_logs,
                creation_time: Some(created),
                field_selection_criteria: input.field_selection_criteria,
                emit_system_fields: input.emit_system_fields,
            },
        );
        Ok(())
    }

    pub(crate) fn delete_subscription_filter(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSubscriptionFilterRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DeleteSubscriptionFilter", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        st.group_mut(&g)?
            .subscription_filters
            .remove(&input.filter_name)
            .ok_or_else(|| errors::resource_not_found("The specified subscription filter does not exist."))?;
        Ok(())
    }

    pub(crate) fn describe_subscription_filters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSubscriptionFiltersRequest,
    ) -> Result<types::DescribeSubscriptionFiltersResponse, ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DescribeSubscriptionFilters", &g, None, ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<_> = st
            .group(&g)?
            .subscription_filters
            .values()
            .filter(|f| {
                input
                    .filter_name_prefix
                    .as_ref()
                    .is_none_or(|p| f.filter_name.as_deref().unwrap_or("").starts_with(p.as_str()))
            })
            .cloned()
            .collect();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeSubscriptionFiltersResponse { subscription_filters: Some(out), next_token })
    }

    // ---- destinations ----------------------------------------------------------

    pub(crate) fn put_destination(
        &self,
        ctx: &RequestContext,
        input: types::PutDestinationRequest,
    ) -> Result<types::PutDestinationResponse, ServiceError> {
        let d_arn = arn(ctx, &format!("destination:{}", input.destination_name));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "PutDestination", &d_arn, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        for (what, a) in [("targetArn", &input.target_arn), ("roleArn", &input.role_arn)] {
            if !a.starts_with("arn:") {
                return Err(errors::invalid_parameter(format!("Invalid {what}: {a}")));
            }
        }
        pass_role(ctx, &input.role_arn)?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let existing = region.destinations.get(&input.destination_name).cloned();
        let record = types::Destination {
            destination_name: Some(input.destination_name.clone()),
            target_arn: Some(input.target_arn),
            role_arn: Some(input.role_arn),
            access_policy: existing.as_ref().and_then(|d| d.record.access_policy.clone()),
            arn: Some(d_arn),
            creation_time: Some(existing.as_ref().and_then(|d| d.record.creation_time).unwrap_or(now)),
        };
        let mut all_tags = existing.map(|d| d.tags).unwrap_or_default();
        all_tags.extend(tags);
        region.destinations.insert(input.destination_name, Destination { record: record.clone(), tags: all_tags });
        Ok(types::PutDestinationResponse { destination: Some(record) })
    }

    pub(crate) fn put_destination_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDestinationPolicyRequest,
    ) -> Result<(), ServiceError> {
        let d_arn = arn(ctx, &format!("destination:{}", input.destination_name));
        self.authorize(ctx, "PutDestinationPolicy", &d_arn, ConditionContext::new())?;
        Policy::parse(&input.access_policy, PolicyKind::Resource)
            .map_err(|e| errors::invalid_parameter(format!("Invalid access policy: {}", e.0)))?;
        let mut st = self.lock();
        let d = st
            .region(&ctx.caller.account_id, &ctx.region)
            .destinations
            .get_mut(&input.destination_name)
            .ok_or_else(|| errors::resource_not_found("The specified destination does not exist."))?;
        d.record.access_policy = Some(input.access_policy);
        Ok(())
    }

    pub(crate) fn describe_destinations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDestinationsRequest,
    ) -> Result<types::DescribeDestinationsResponse, ServiceError> {
        self.authorize(ctx, "DescribeDestinations", &arn(ctx, "destination:*"), ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<_> =
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| {
                    r.destinations
                        .values()
                        .filter(|d| {
                            input.destination_name_prefix.as_ref().is_none_or(|p| {
                                d.record.destination_name.as_deref().unwrap_or("").starts_with(p.as_str())
                            })
                        })
                        .map(|d| d.record.clone())
                        .collect()
                })
                .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeDestinationsResponse { destinations: Some(out), next_token })
    }

    pub(crate) fn delete_destination(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDestinationRequest,
    ) -> Result<(), ServiceError> {
        let d_arn = arn(ctx, &format!("destination:{}", input.destination_name));
        self.authorize(ctx, "DeleteDestination", &d_arn, ConditionContext::new())?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .destinations
            .remove(&input.destination_name)
            .ok_or_else(|| errors::resource_not_found("The specified destination does not exist."))?;
        Ok(())
    }
}

/// `iam:PassRole`, which `PutSubscriptionFilter` and `PutDestination` need
/// on the role they hand CloudWatch Logs.
fn pass_role(ctx: &RequestContext, role: &str) -> Result<(), ServiceError> {
    let mut c = ConditionContext::new();
    c.insert("iam:PassedToService".into(), vec!["logs.amazonaws.com".into()]);
    ctx.authorize("iam:PassRole", role, c)
}
