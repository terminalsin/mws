//! Accelerators (standard and custom routing): lifecycle, static IP
//! addresses, attributes and tags.

use std::net::Ipv4Addr;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::ips::{self, Cidr};
use crate::names::{
    self, accelerator_not_found, account, attachment_not_found, authorize, check_tags, invalid, now_ms, page,
    request_tags, resource_tags, tag_list, tag_map, time,
};
use crate::state::{Accelerator, State};
use crate::GlobalAccelerator;

/// Accelerators per account, of each kind.
const ACCELERATOR_LIMIT: usize = 20;

fn ip_sets(a: &Accelerator) -> Vec<types::IpSet> {
    let set = |family: &str, addresses: &[String]| types::IpSet {
        ip_family: Some(family.into()),
        ip_addresses: Some(addresses.to_vec()),
        ip_address_family: Some(family.into()),
        ip_address_details: None,
    };
    let mut sets = vec![set("IPv4", &a.ipv4)];
    if !a.ipv6.is_empty() {
        sets.push(set("IPv6", &a.ipv6));
    }
    sets
}

pub fn describe(a: &Accelerator) -> types::Accelerator {
    types::Accelerator {
        accelerator_arn: Some(a.arn.clone()),
        name: Some(a.name.clone()),
        ip_address_type: Some(a.ip_address_type.clone()),
        enabled: Some(a.enabled),
        ip_sets: Some(ip_sets(a)),
        dns_name: Some(a.dns_name.clone()),
        status: Some(a.status.clone()),
        created_time: Some(time(a.created)),
        last_modified_time: Some(time(a.modified)),
        dual_stack_dns_name: a.dual_stack_dns_name.clone(),
        events: (!a.events.is_empty()).then(|| {
            a.events
                .iter()
                .map(|e| types::AcceleratorEvent {
                    message: Some(e.message.clone()),
                    timestamp: Some(time(e.timestamp)),
                })
                .collect()
        }),
    }
}

pub fn describe_custom(a: &Accelerator) -> types::CustomRoutingAccelerator {
    let d = describe(a);
    types::CustomRoutingAccelerator {
        accelerator_arn: d.accelerator_arn,
        name: d.name,
        ip_address_type: d.ip_address_type,
        enabled: d.enabled,
        ip_sets: d.ip_sets,
        dns_name: d.dns_name,
        status: d.status,
        created_time: d.created_time,
        last_modified_time: d.last_modified_time,
    }
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !ok {
        return Err(invalid(
            "The name can have a maximum of 64 characters, must contain only alphanumeric characters or hyphens (-), and must not begin or end with a hyphen.",
        ));
    }
    Ok(())
}

fn check_ip_address_type(t: &str) -> Result<(), ServiceError> {
    if t != "IPV4" && t != "DUAL_STACK" {
        return Err(invalid(format!("IpAddressType {t} is not valid. Valid values are IPV4 and DUAL_STACK.")));
    }
    Ok(())
}

/// Whether `account` may use addresses from `cidr` (owned by `owner`):
/// its own range, or one shared through a cross-account attachment.
fn may_use_range(st: &State, account: &str, owner: &str, cidr: &str, accelerator: Option<&str>) -> bool {
    owner == account
        || st.attachments.values().any(|t| {
            t.account == owner
                && t.principals.iter().any(|p| p == account || Some(p.as_str()) == accelerator)
                && t.resources.iter().any(|r| r.cidr.as_deref() == Some(cidr))
        })
}

/// The BYOIP addresses an accelerator asks for, checked against the ranges
/// the caller may use.
fn byoip_addresses(
    st: &State,
    caller: &str,
    accelerator: Option<&str>,
    requested: &[String],
) -> Result<Vec<String>, ServiceError> {
    if requested.len() > 2 {
        return Err(invalid("You can specify at most two IP addresses."));
    }
    let mut out = Vec::new();
    for ip in requested {
        let parsed: Ipv4Addr = ip.parse().map_err(|_| invalid(format!("The IP address {ip} is not valid.")))?;
        if out.contains(ip) {
            return Err(invalid(format!("The IP address {ip} is specified more than once.")));
        }
        let range = st.byoip.values().find(|c| {
            Cidr::parse(&c.cidr).is_some_and(|r| r.contains(parsed))
                && matches!(c.state.as_str(), "READY" | "PENDING_ADVERTISING" | "ADVERTISING" | "PENDING_WITHDRAWING")
                && may_use_range(st, caller, &c.account, &c.cidr, accelerator)
        });
        if range.is_none() {
            return Err(invalid(format!(
                "The IP address {ip} is not in an address range that you have provisioned for use with Global Accelerator."
            )));
        }
        if st.used_ips.contains(ip) {
            return Err(invalid(format!("The IP address {ip} is already in use.")));
        }
        out.push(ip.clone());
    }
    Ok(out)
}

fn assign_ipv4(st: &mut State, byoip: &[String]) -> Vec<String> {
    let mut v4 = byoip.to_vec();
    while v4.len() < 2 {
        let ip = ips::allocate_ipv4(v4.len(), &st.used_ips);
        st.used_ips.insert(ip.clone());
        v4.push(ip);
    }
    for ip in byoip {
        st.used_ips.insert(ip.clone());
    }
    v4
}

fn assign_ipv6(st: &mut State) -> Vec<String> {
    (0..2)
        .map(|zone| {
            let ip = ips::allocate_ipv6(zone, &st.used_ips);
            st.used_ips.insert(ip.clone());
            ip
        })
        .collect()
}

fn release(st: &mut State, ips: &[String]) {
    for ip in ips {
        st.used_ips.remove(ip);
    }
}

pub struct NewAccelerator<'a> {
    pub name: &'a str,
    pub ip_address_type: Option<&'a str>,
    pub ip_addresses: Option<&'a [String]>,
    pub enabled: Option<bool>,
    pub token: &'a str,
    pub tags: Option<&'a [types::Tag]>,
}

/// Look an accelerator of the right kind up in the caller's account.
pub fn find<'a>(st: &'a State, ctx: &RequestContext, arn: &str, custom: bool) -> Result<&'a Accelerator, ServiceError> {
    st.accelerators
        .get(arn)
        .filter(|a| a.account == ctx.caller.account_id && a.custom == custom)
        .ok_or_else(|| accelerator_not_found(arn))
}

pub fn find_mut<'a>(
    st: &'a mut State,
    ctx: &RequestContext,
    arn: &str,
    custom: bool,
) -> Result<&'a mut Accelerator, ServiceError> {
    st.accelerators
        .get_mut(arn)
        .filter(|a| a.account == ctx.caller.account_id && a.custom == custom)
        .ok_or_else(|| accelerator_not_found(arn))
}

impl GlobalAccelerator {
    pub(crate) fn create_accelerator_common(
        &self,
        ctx: &RequestContext,
        input: NewAccelerator<'_>,
        custom: bool,
    ) -> Result<Accelerator, ServiceError> {
        let op = if custom { "CreateCustomRoutingAccelerator" } else { "CreateAccelerator" };
        let tags = tag_map(input.tags.unwrap_or_default());
        authorize(ctx, op, "*", request_tags(&tags))?;
        if !tags.is_empty() {
            authorize(ctx, "TagResource", "*", request_tags(&tags))?;
        }
        check_name(input.name)?;
        check_tags(&tags)?;
        let ip_address_type = input.ip_address_type.unwrap_or("IPV4");
        check_ip_address_type(ip_address_type)?;
        let now = now_ms(ctx);
        let caller = account(ctx);
        let mut st = self.settled(ctx);
        let key = format!("{caller}/{op}/{}", input.token);
        if let Some(a) = st.idempotency.get(&key).and_then(|arn| st.accelerators.get(arn)) {
            return Ok(a.clone());
        }
        let count = st.accelerators.values().filter(|a| a.account == caller && a.custom == custom).count();
        if count >= ACCELERATOR_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "You have reached the maximum number of accelerators ({ACCELERATOR_LIMIT}) for this account."
            )));
        }
        let byoip = byoip_addresses(&st, &caller, None, input.ip_addresses.unwrap_or_default())?;
        let ipv4 = assign_ipv4(&mut st, &byoip);
        let dual = ip_address_type == "DUAL_STACK";
        let ipv6 = if dual { assign_ipv6(&mut st) } else { Vec::new() };
        let seq = st.next_seq();
        let a = Accelerator {
            arn: names::accelerator_arn(ctx),
            account: caller,
            seq,
            custom,
            name: input.name.to_string(),
            ip_address_type: ip_address_type.to_string(),
            enabled: input.enabled.unwrap_or(true),
            ipv4,
            ipv6,
            byoip_ips: byoip,
            dns_name: names::dns_name(),
            dual_stack_dns_name: (dual && !custom).then(names::dual_stack_dns_name),
            status: "IN_PROGRESS".into(),
            settles_at: now + crate::state::transition_ms(),
            created: now,
            modified: now,
            tags,
            ..Default::default()
        };
        st.idempotency.insert(key, a.arn.clone());
        st.accelerators.insert(a.arn.clone(), a.clone());
        Ok(a)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_accelerator_common(
        &self,
        ctx: &RequestContext,
        arn: &str,
        name: Option<&str>,
        ip_address_type: Option<&str>,
        ip_addresses: Option<&[String]>,
        enabled: Option<bool>,
        custom: bool,
    ) -> Result<Accelerator, ServiceError> {
        let op = if custom { "UpdateCustomRoutingAccelerator" } else { "UpdateAccelerator" };
        let now = now_ms(ctx);
        let caller = account(ctx);
        let mut st = self.settled(ctx);
        let a = find(&st, ctx, arn, custom)?;
        authorize(ctx, op, arn, resource_tags(&a.tags))?;
        if let Some(n) = name {
            check_name(n)?;
        }
        if let Some(t) = ip_address_type {
            check_ip_address_type(t)?;
        }
        let mut a = a.clone();
        if let Some(requested) = ip_addresses {
            let mut wanted: Vec<String> = requested.to_vec();
            wanted.sort();
            let mut have = a.byoip_ips.clone();
            have.sort();
            if wanted != have {
                // Free the current addresses first so they can be asked for again.
                release(&mut st, &a.ipv4);
                match byoip_addresses(&st, &caller, Some(arn), requested) {
                    Ok(byoip) => {
                        a.ipv4 = assign_ipv4(&mut st, &byoip);
                        a.byoip_ips = byoip;
                    }
                    Err(e) => {
                        for ip in &a.ipv4 {
                            st.used_ips.insert(ip.clone());
                        }
                        return Err(e);
                    }
                }
            }
        }
        if let Some(t) = ip_address_type {
            if t != a.ip_address_type {
                if t == "DUAL_STACK" {
                    a.ipv6 = assign_ipv6(&mut st);
                    if !custom {
                        a.dual_stack_dns_name = Some(names::dual_stack_dns_name());
                    }
                } else {
                    release(&mut st, &a.ipv6);
                    a.ipv6.clear();
                    a.dual_stack_dns_name = None;
                }
                a.ip_address_type = t.to_string();
            }
        }
        if let Some(n) = name {
            a.name = n.to_string();
        }
        if let Some(e) = enabled {
            a.enabled = e;
        }
        a.touch(now);
        st.accelerators.insert(arn.to_string(), a.clone());
        Ok(a)
    }

    pub(crate) fn delete_accelerator_common(
        &self,
        ctx: &RequestContext,
        arn: &str,
        custom: bool,
    ) -> Result<(), ServiceError> {
        let op = if custom { "DeleteCustomRoutingAccelerator" } else { "DeleteAccelerator" };
        let mut st = self.settled(ctx);
        let a = find(&st, ctx, arn, custom)?;
        authorize(ctx, op, arn, resource_tags(&a.tags))?;
        if a.enabled || a.status != "DEPLOYED" {
            return Err(errors::accelerator_not_disabled(
                "The accelerator must be disabled and in the DEPLOYED state before you can delete it.",
            ));
        }
        if !a.listeners.is_empty() {
            return Err(errors::associated_listener_found(
                "The accelerator has listeners associated with it. Delete the listeners before deleting the accelerator.",
            ));
        }
        let a = st.accelerators.remove(arn).expect("accelerator present");
        release(&mut st, &a.ipv4);
        release(&mut st, &a.ipv6);
        st.idempotency.retain(|_, v| v != arn);
        Ok(())
    }

    fn list_accelerators_common(
        &self,
        ctx: &RequestContext,
        custom: bool,
        max_results: Option<i32>,
        next_token: Option<&str>,
    ) -> Result<(Vec<Accelerator>, Option<String>), ServiceError> {
        let op = if custom { "ListCustomRoutingAccelerators" } else { "ListAccelerators" };
        authorize(ctx, op, "*", ConditionContext::new())?;
        let st = self.settled(ctx);
        let mut items: Vec<Accelerator> = st
            .accelerators
            .values()
            .filter(|a| a.account == ctx.caller.account_id && a.custom == custom)
            .cloned()
            .collect();
        items.sort_by_key(|a| a.seq);
        page(items, max_results, next_token, 10)
    }

    fn attributes_common(
        &self,
        ctx: &RequestContext,
        arn: &str,
        custom: bool,
        update: Option<(Option<bool>, Option<String>, Option<String>)>,
    ) -> Result<(bool, Option<String>, Option<String>), ServiceError> {
        let op = match (custom, update.is_some()) {
            (false, false) => "DescribeAcceleratorAttributes",
            (false, true) => "UpdateAcceleratorAttributes",
            (true, false) => "DescribeCustomRoutingAcceleratorAttributes",
            (true, true) => "UpdateCustomRoutingAcceleratorAttributes",
        };
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let a = find_mut(&mut st, ctx, arn, custom)?;
        authorize(ctx, op, arn, resource_tags(&a.tags))?;
        if let Some((enabled, bucket, prefix)) = update {
            let enabled = enabled.unwrap_or(a.flow_logs_enabled);
            let bucket = bucket.or_else(|| a.flow_logs_bucket.clone());
            if enabled && bucket.as_deref().unwrap_or_default().is_empty() {
                return Err(invalid("FlowLogsS3Bucket is required when FlowLogsEnabled is true."));
            }
            if let Some(b) = &bucket {
                let valid = (3..=63).contains(&b.len())
                    && b.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
                if !valid {
                    return Err(invalid(format!("FlowLogsS3Bucket {b} is not a valid bucket name.")));
                }
            }
            if let Some(p) = &prefix {
                if p.starts_with('/') || p.starts_with("AWSLogs") {
                    return Err(invalid("FlowLogsS3Prefix can't begin with a slash (/) or AWSLogs."));
                }
            }
            a.flow_logs_enabled = enabled;
            a.flow_logs_bucket = bucket;
            if prefix.is_some() {
                a.flow_logs_prefix = prefix;
            }
            a.touch(now);
        }
        let shown = |v: &Option<String>| if a.flow_logs_enabled { v.clone() } else { None };
        Ok((a.flow_logs_enabled, shown(&a.flow_logs_bucket), shown(&a.flow_logs_prefix)))
    }

    // ---- standard accelerators ----

    pub fn create_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcceleratorRequest,
    ) -> Result<types::CreateAcceleratorResponse, ServiceError> {
        let a = self.create_accelerator_common(
            ctx,
            NewAccelerator {
                name: &input.name,
                ip_address_type: input.ip_address_type.as_deref(),
                ip_addresses: input.ip_addresses.as_deref(),
                enabled: input.enabled,
                token: &input.idempotency_token,
                tags: input.tags.as_deref(),
            },
            false,
        )?;
        Ok(types::CreateAcceleratorResponse { accelerator: Some(describe(&a)) })
    }

    pub fn describe_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcceleratorRequest,
    ) -> Result<types::DescribeAcceleratorResponse, ServiceError> {
        let st = self.settled(ctx);
        let a = find(&st, ctx, &input.accelerator_arn, false)?;
        authorize(ctx, "DescribeAccelerator", &a.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeAcceleratorResponse { accelerator: Some(describe(a)) })
    }

    pub fn list_accelerators(
        &self,
        ctx: &RequestContext,
        input: types::ListAcceleratorsRequest,
    ) -> Result<types::ListAcceleratorsResponse, ServiceError> {
        let (items, next_token) =
            self.list_accelerators_common(ctx, false, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAcceleratorsResponse { accelerators: Some(items.iter().map(describe).collect()), next_token })
    }

    pub fn update_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcceleratorRequest,
    ) -> Result<types::UpdateAcceleratorResponse, ServiceError> {
        let a = self.update_accelerator_common(
            ctx,
            &input.accelerator_arn,
            input.name.as_deref(),
            input.ip_address_type.as_deref(),
            input.ip_addresses.as_deref(),
            input.enabled,
            false,
        )?;
        Ok(types::UpdateAcceleratorResponse { accelerator: Some(describe(&a)) })
    }

    pub fn delete_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcceleratorRequest,
    ) -> Result<(), ServiceError> {
        self.delete_accelerator_common(ctx, &input.accelerator_arn, false)
    }

    pub fn describe_accelerator_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcceleratorAttributesRequest,
    ) -> Result<types::DescribeAcceleratorAttributesResponse, ServiceError> {
        let (e, b, p) = self.attributes_common(ctx, &input.accelerator_arn, false, None)?;
        Ok(types::DescribeAcceleratorAttributesResponse {
            accelerator_attributes: Some(types::AcceleratorAttributes {
                flow_logs_enabled: Some(e),
                flow_logs_s3_bucket: b,
                flow_logs_s3_prefix: p,
            }),
        })
    }

    pub fn update_accelerator_attributes(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcceleratorAttributesRequest,
    ) -> Result<types::UpdateAcceleratorAttributesResponse, ServiceError> {
        let (e, b, p) = self.attributes_common(
            ctx,
            &input.accelerator_arn,
            false,
            Some((input.flow_logs_enabled, input.flow_logs_s3_bucket, input.flow_logs_s3_prefix)),
        )?;
        Ok(types::UpdateAcceleratorAttributesResponse {
            accelerator_attributes: Some(types::AcceleratorAttributes {
                flow_logs_enabled: Some(e),
                flow_logs_s3_bucket: b,
                flow_logs_s3_prefix: p,
            }),
        })
    }

    // ---- custom routing accelerators ----

    pub fn create_custom_routing_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomRoutingAcceleratorRequest,
    ) -> Result<types::CreateCustomRoutingAcceleratorResponse, ServiceError> {
        let a = self.create_accelerator_common(
            ctx,
            NewAccelerator {
                name: &input.name,
                ip_address_type: input.ip_address_type.as_deref(),
                ip_addresses: input.ip_addresses.as_deref(),
                enabled: input.enabled,
                token: &input.idempotency_token,
                tags: input.tags.as_deref(),
            },
            true,
        )?;
        Ok(types::CreateCustomRoutingAcceleratorResponse { accelerator: Some(describe_custom(&a)) })
    }

    pub fn describe_custom_routing_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomRoutingAcceleratorRequest,
    ) -> Result<types::DescribeCustomRoutingAcceleratorResponse, ServiceError> {
        let st = self.settled(ctx);
        let a = find(&st, ctx, &input.accelerator_arn, true)?;
        authorize(ctx, "DescribeCustomRoutingAccelerator", &a.arn, resource_tags(&a.tags))?;
        Ok(types::DescribeCustomRoutingAcceleratorResponse { accelerator: Some(describe_custom(a)) })
    }

    pub fn list_custom_routing_accelerators(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomRoutingAcceleratorsRequest,
    ) -> Result<types::ListCustomRoutingAcceleratorsResponse, ServiceError> {
        let (items, next_token) =
            self.list_accelerators_common(ctx, true, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCustomRoutingAcceleratorsResponse {
            accelerators: Some(items.iter().map(describe_custom).collect()),
            next_token,
        })
    }

    pub fn update_custom_routing_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomRoutingAcceleratorRequest,
    ) -> Result<types::UpdateCustomRoutingAcceleratorResponse, ServiceError> {
        let a = self.update_accelerator_common(
            ctx,
            &input.accelerator_arn,
            input.name.as_deref(),
            input.ip_address_type.as_deref(),
            input.ip_addresses.as_deref(),
            input.enabled,
            true,
        )?;
        Ok(types::UpdateCustomRoutingAcceleratorResponse { accelerator: Some(describe_custom(&a)) })
    }

    pub fn delete_custom_routing_accelerator(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomRoutingAcceleratorRequest,
    ) -> Result<(), ServiceError> {
        self.delete_accelerator_common(ctx, &input.accelerator_arn, true)
    }

    pub fn describe_custom_routing_accelerator_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomRoutingAcceleratorAttributesRequest,
    ) -> Result<types::DescribeCustomRoutingAcceleratorAttributesResponse, ServiceError> {
        let (e, b, p) = self.attributes_common(ctx, &input.accelerator_arn, true, None)?;
        Ok(types::DescribeCustomRoutingAcceleratorAttributesResponse {
            accelerator_attributes: Some(types::CustomRoutingAcceleratorAttributes {
                flow_logs_enabled: Some(e),
                flow_logs_s3_bucket: b,
                flow_logs_s3_prefix: p,
            }),
        })
    }

    pub fn update_custom_routing_accelerator_attributes(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomRoutingAcceleratorAttributesRequest,
    ) -> Result<types::UpdateCustomRoutingAcceleratorAttributesResponse, ServiceError> {
        let (e, b, p) = self.attributes_common(
            ctx,
            &input.accelerator_arn,
            true,
            Some((input.flow_logs_enabled, input.flow_logs_s3_bucket, input.flow_logs_s3_prefix)),
        )?;
        Ok(types::UpdateCustomRoutingAcceleratorAttributesResponse {
            accelerator_attributes: Some(types::CustomRoutingAcceleratorAttributes {
                flow_logs_enabled: Some(e),
                flow_logs_s3_bucket: b,
                flow_logs_s3_prefix: p,
            }),
        })
    }

    // ---- tags ----

    /// The tags of a taggable resource the caller owns.
    fn tags_mut<'a>(
        st: &'a mut State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'a mut std::collections::BTreeMap<String, String>, ServiceError> {
        if arn.contains(":attachment/") {
            return st
                .attachments
                .get_mut(arn)
                .filter(|t| t.account == ctx.caller.account_id)
                .map(|t| &mut t.tags)
                .ok_or_else(|| attachment_not_found(arn));
        }
        let path = names::parse(arn).ok_or_else(|| accelerator_not_found(arn))?;
        if path.listener.is_some() {
            return Err(invalid(format!(
                "Resource {arn} can't be tagged. Only accelerators and attachments have tags."
            )));
        }
        st.accelerators
            .get_mut(arn)
            .filter(|a| a.account == ctx.caller.account_id)
            .map(|a| &mut a.tags)
            .ok_or_else(|| accelerator_not_found(arn))
    }

    pub fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let new = tag_map(&input.tags);
        let mut st = self.settled(ctx);
        let tags = Self::tags_mut(&mut st, ctx, &input.resource_arn)?;
        let mut cx = resource_tags(tags);
        cx.extend(request_tags(&new));
        authorize(ctx, "TagResource", &input.resource_arn, cx)?;
        let mut merged = tags.clone();
        merged.extend(new);
        check_tags(&merged)?;
        *tags = merged;
        Ok(types::TagResourceResponse {})
    }

    pub fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut st = self.settled(ctx);
        let tags = Self::tags_mut(&mut st, ctx, &input.resource_arn)?;
        let mut cx = resource_tags(tags);
        cx.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize(ctx, "UntagResource", &input.resource_arn, cx)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(types::UntagResourceResponse {})
    }

    pub fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let arn = &input.resource_arn;
        let st = self.settled(ctx);
        let tags = if arn.contains(":attachment/") {
            st.attachments
                .get(arn)
                .filter(|t| t.account == ctx.caller.account_id)
                .map(|t| t.tags.clone())
                .ok_or_else(|| attachment_not_found(arn))?
        } else {
            let path = names::parse(arn).ok_or_else(|| accelerator_not_found(arn))?;
            let a = st
                .accelerators
                .get(&path.accelerator)
                .filter(|a| a.account == ctx.caller.account_id)
                .ok_or_else(|| accelerator_not_found(arn))?;
            match (&path.listener, &path.group) {
                (None, _) => a.tags.clone(),
                (Some(l), None) => {
                    a.listeners.get(l).ok_or_else(|| names::listener_not_found(l))?;
                    Default::default()
                }
                (Some(l), Some(g)) => {
                    a.listeners.get(l).and_then(|l| l.groups.get(g)).ok_or_else(|| names::group_not_found(g))?;
                    Default::default()
                }
            }
        };
        authorize(ctx, "ListTagsForResource", arn, resource_tags(&tags))?;
        Ok(types::ListTagsForResourceResponse { tags: Some(tag_list(&tags)) })
    }
}
