//! Filters (and suppression rules), IP sets, threat intel sets, threat
//! entity sets, trusted entity sets and publishing destinations.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::types;
use crate::state::{Destination, Detector, Filter, ThreatList};
use crate::GuardDuty;

const MAX_FILTERS: usize = 100;

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Kind {
    IpSet,
    ThreatIntelSet,
    ThreatEntitySet,
    TrustedEntitySet,
}

impl Kind {
    fn segment(self) -> &'static str {
        match self {
            Kind::IpSet => "ipset",
            Kind::ThreatIntelSet => "threatintelset",
            Kind::ThreatEntitySet => "threatentityset",
            Kind::TrustedEntitySet => "trustedentityset",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Kind::IpSet => "IPSet",
            Kind::ThreatIntelSet => "ThreatIntelSet",
            Kind::ThreatEntitySet => "ThreatEntitySet",
            Kind::TrustedEntitySet => "TrustedEntitySet",
        }
    }

    /// Per detector: one trusted list, six threat lists.
    fn limit(self) -> usize {
        match self {
            Kind::IpSet | Kind::TrustedEntitySet => 1,
            Kind::ThreatIntelSet | Kind::ThreatEntitySet => 6,
        }
    }

    fn map(self, d: &Detector) -> &BTreeMap<String, ThreatList> {
        match self {
            Kind::IpSet => &d.ip_sets,
            Kind::ThreatIntelSet => &d.threat_intel_sets,
            Kind::ThreatEntitySet => &d.threat_entity_sets,
            Kind::TrustedEntitySet => &d.trusted_entity_sets,
        }
    }

    fn map_mut(self, d: &mut Detector) -> &mut BTreeMap<String, ThreatList> {
        match self {
            Kind::IpSet => &mut d.ip_sets,
            Kind::ThreatIntelSet => &mut d.threat_intel_sets,
            Kind::ThreatEntitySet => &mut d.threat_entity_sets,
            Kind::TrustedEntitySet => &mut d.trusted_entity_sets,
        }
    }
}

/// A threat list's file location: an S3 URL.
fn check_location(location: &str) -> Result<(), ServiceError> {
    let ok = location.starts_with("s3://")
        || (location.starts_with("https://") && location.contains("s3") && location.contains("amazonaws.com"));
    if ok {
        Ok(())
    } else {
        Err(invalid_input("The request is rejected because the location is not a valid S3 URL."))
    }
}

fn active(activate: bool) -> String {
    if activate { "ACTIVE" } else { "INACTIVE" }.to_string()
}

pub struct NewList {
    pub name: String,
    pub format: String,
    pub location: String,
    pub activate: bool,
    pub expected_bucket_owner: Option<String>,
    pub tags: Option<Tags>,
    pub client_token: Option<String>,
}

pub struct ListUpdate {
    pub name: Option<String>,
    pub location: Option<String>,
    pub activate: Option<bool>,
    pub expected_bucket_owner: Option<String>,
}

impl GuardDuty {
    /// Authorize `action` on a child resource of the caller's detector.
    #[allow(clippy::too_many_arguments)]
    fn authorize_child(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_id: &str,
        segment: &str,
        id: &str,
        tags: Option<&Tags>,
        cond: mws_core::ConditionContext,
    ) -> Result<(), ServiceError> {
        let arn = child_arn(ctx, &ctx.caller.account_id, detector_id, segment, id);
        let mut c = cond;
        if let Some(t) = tags {
            c.extend(resource_tag_context(t));
        }
        self.authorize(ctx, action, &arn, c)
    }

    // ---- filters ----------------------------------------------------------

    pub(crate) fn create_filter(
        &self,
        ctx: &RequestContext,
        input: types::CreateFilterRequest,
    ) -> Result<types::CreateFilterResponse, ServiceError> {
        if let Some(t) = &input.tags {
            validate_tags(t)?;
        }
        {
            let state = self.lock();
            Self::owned(&state, ctx, &input.detector_id)?;
        }
        self.authorize_child(
            ctx,
            "CreateFilter",
            &input.detector_id,
            "filter",
            &input.name,
            None,
            request_tag_context(input.tags.as_ref()),
        )?;
        if !input.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            return Err(invalid_input(
                "The request is rejected because the filter name is invalid. Valid characters are alphanumeric, period (.), hyphen (-) and underscore (_).",
            ));
        }
        let now = ctx.received_at;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        if det.filters.contains_key(&input.name) {
            return Err(invalid_input("The request is rejected because a filter with the same name already exists."));
        }
        if det.filters.len() >= MAX_FILTERS {
            return Err(invalid_input("The request is rejected because the number of filters reached the limit."));
        }
        let rank = input.rank.unwrap_or(det.filters.len() as i32 + 1);
        if rank < 1 || rank as usize > det.filters.len() + 1 {
            return Err(invalid_input("The request is rejected because the rank is out of range."));
        }
        for f in det.filters.values_mut() {
            if f.rank >= rank {
                f.rank += 1;
            }
        }
        det.filters.insert(
            input.name.clone(),
            Filter {
                name: input.name.clone(),
                description: input.description,
                action: input.action.unwrap_or_else(|| "NOOP".into()),
                rank,
                criteria: input.finding_criteria,
                tags: input.tags.unwrap_or_default(),
                created_at: now,
                updated_at: now,
                version: 1,
            },
        );
        Ok(types::CreateFilterResponse { name: input.name })
    }

    fn filter_tags(&self, ctx: &RequestContext, detector_id: &str, name: &str) -> Result<Tags, ServiceError> {
        let state = self.lock();
        let det = Self::owned(&state, ctx, detector_id)?;
        Ok(det.filters.get(name).map(|f| f.tags.clone()).unwrap_or_default())
    }

    pub(crate) fn get_filter(
        &self,
        ctx: &RequestContext,
        input: types::GetFilterRequest,
    ) -> Result<types::GetFilterResponse, ServiceError> {
        let tags = self.filter_tags(ctx, &input.detector_id, &input.filter_name)?;
        self.authorize_child(
            ctx,
            "GetFilter",
            &input.detector_id,
            "filter",
            &input.filter_name,
            Some(&tags),
            Default::default(),
        )?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let f = det.filters.get(&input.filter_name).ok_or_else(no_such_resource)?;
        Ok(types::GetFilterResponse {
            name: f.name.clone(),
            description: f.description.clone(),
            action: f.action.clone(),
            rank: Some(f.rank),
            finding_criteria: f.criteria.clone(),
            tags: Some(f.tags.clone()),
            created_at: Some(f.created_at),
            updated_at: Some(f.updated_at),
            version: Some(f.version),
        })
    }

    pub(crate) fn update_filter(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFilterRequest,
    ) -> Result<types::UpdateFilterResponse, ServiceError> {
        let tags = self.filter_tags(ctx, &input.detector_id, &input.filter_name)?;
        self.authorize_child(
            ctx,
            "UpdateFilter",
            &input.detector_id,
            "filter",
            &input.filter_name,
            Some(&tags),
            Default::default(),
        )?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        let count = det.filters.len() as i32;
        let old_rank = det.filters.get(&input.filter_name).ok_or_else(no_such_resource)?.rank;
        if let Some(rank) = input.rank {
            if rank < 1 || rank > count {
                return Err(invalid_input("The request is rejected because the rank is out of range."));
            }
            for f in det.filters.values_mut() {
                if rank < old_rank && f.rank >= rank && f.rank < old_rank {
                    f.rank += 1;
                } else if rank > old_rank && f.rank <= rank && f.rank > old_rank {
                    f.rank -= 1;
                }
            }
        }
        let f = det.filters.get_mut(&input.filter_name).expect("checked above");
        if let Some(rank) = input.rank {
            f.rank = rank;
        }
        if input.description.is_some() {
            f.description = input.description;
        }
        if let Some(a) = input.action {
            f.action = a;
        }
        if let Some(c) = input.finding_criteria {
            f.criteria = c;
        }
        f.updated_at = ctx.received_at;
        f.version += 1;
        Ok(types::UpdateFilterResponse { name: input.filter_name })
    }

    pub(crate) fn delete_filter(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFilterRequest,
    ) -> Result<types::DeleteFilterResponse, ServiceError> {
        let tags = self.filter_tags(ctx, &input.detector_id, &input.filter_name)?;
        self.authorize_child(
            ctx,
            "DeleteFilter",
            &input.detector_id,
            "filter",
            &input.filter_name,
            Some(&tags),
            Default::default(),
        )?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        let removed = det.filters.remove(&input.filter_name).ok_or_else(no_such_resource)?;
        for f in det.filters.values_mut() {
            if f.rank > removed.rank {
                f.rank -= 1;
            }
        }
        Ok(Default::default())
    }

    pub(crate) fn list_filters(
        &self,
        ctx: &RequestContext,
        input: types::ListFiltersRequest,
    ) -> Result<types::ListFiltersResponse, ServiceError> {
        self.authorize_detector(ctx, "ListFilters", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let mut filters: Vec<&Filter> = det.filters.values().collect();
        filters.sort_by_key(|f| f.rank);
        let names = filters.into_iter().map(|f| f.name.clone()).collect();
        let (filter_names, next_token) = paginate(names, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListFiltersResponse { filter_names, next_token })
    }

    // ---- threat lists -----------------------------------------------------

    pub(crate) fn create_list(
        &self,
        ctx: &RequestContext,
        kind: Kind,
        detector_id: &str,
        new: NewList,
    ) -> Result<String, ServiceError> {
        if let Some(t) = &new.tags {
            validate_tags(t)?;
        }
        {
            let state = self.lock();
            Self::owned(&state, ctx, detector_id)?;
        }
        self.authorize(
            ctx,
            &format!("Create{}", kind.noun()),
            &detector_arn(ctx, &ctx.caller.account_id, detector_id),
            request_tag_context(new.tags.as_ref()),
        )?;
        check_location(&new.location)?;
        let now = ctx.received_at;
        let mut state = self.lock();
        let account = ctx.caller.account_id.clone();
        let token_key = new.client_token.as_ref().filter(|t| !t.is_empty()).map(|t| format!("{}/{t}", kind.segment()));
        if let Some(k) = &token_key {
            if let Some(id) = state.account(&account, &ctx.region).and_then(|a| a.client_tokens.get(k)).cloned() {
                if Self::owned(&state, ctx, detector_id).is_ok_and(|d| kind.map(d).contains_key(&id)) {
                    return Ok(id);
                }
            }
        }
        let det = Self::owned_mut(&mut state, ctx, detector_id)?;
        let lists = kind.map_mut(det);
        if lists.values().any(|l| l.name == new.name) {
            return Err(invalid_input(format!(
                "The request is rejected because a {} with the same name already exists.",
                kind.noun()
            )));
        }
        if lists.len() >= kind.limit() {
            return Err(invalid_input(format!(
                "The request is rejected because the number of {}s reached the limit.",
                kind.noun()
            )));
        }
        let id = hex_id(32);
        lists.insert(
            id.clone(),
            ThreatList {
                name: new.name,
                format: new.format,
                location: new.location,
                status: active(new.activate),
                expected_bucket_owner: new.expected_bucket_owner,
                tags: new.tags.unwrap_or_default(),
                created_at: now,
                updated_at: now,
            },
        );
        if let Some(k) = token_key {
            state.account_mut(&account, &ctx.region).client_tokens.insert(k, id.clone());
        }
        Ok(id)
    }

    fn list_tags(&self, ctx: &RequestContext, kind: Kind, detector_id: &str, id: &str) -> Result<Tags, ServiceError> {
        let state = self.lock();
        let det = Self::owned(&state, ctx, detector_id)?;
        Ok(kind.map(det).get(id).map(|l| l.tags.clone()).unwrap_or_default())
    }

    pub(crate) fn get_list(
        &self,
        ctx: &RequestContext,
        kind: Kind,
        detector_id: &str,
        id: &str,
    ) -> Result<ThreatList, ServiceError> {
        let tags = self.list_tags(ctx, kind, detector_id, id)?;
        self.authorize_child(
            ctx,
            &format!("Get{}", kind.noun()),
            detector_id,
            kind.segment(),
            id,
            Some(&tags),
            Default::default(),
        )?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, detector_id)?;
        kind.map(det).get(id).cloned().ok_or_else(no_such_resource)
    }

    pub(crate) fn update_list(
        &self,
        ctx: &RequestContext,
        kind: Kind,
        detector_id: &str,
        id: &str,
        update: ListUpdate,
    ) -> Result<(), ServiceError> {
        let tags = self.list_tags(ctx, kind, detector_id, id)?;
        self.authorize_child(
            ctx,
            &format!("Update{}", kind.noun()),
            detector_id,
            kind.segment(),
            id,
            Some(&tags),
            Default::default(),
        )?;
        if let Some(l) = &update.location {
            check_location(l)?;
        }
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, detector_id)?;
        let lists = kind.map_mut(det);
        if let Some(n) = &update.name {
            if lists.iter().any(|(k, l)| k != id && l.name == *n) {
                return Err(invalid_input(format!(
                    "The request is rejected because a {} with the same name already exists.",
                    kind.noun()
                )));
            }
        }
        let l = lists.get_mut(id).ok_or_else(no_such_resource)?;
        if let Some(n) = update.name {
            l.name = n;
        }
        if let Some(loc) = update.location {
            l.location = loc;
        }
        if let Some(a) = update.activate {
            l.status = active(a);
        }
        if update.expected_bucket_owner.is_some() {
            l.expected_bucket_owner = update.expected_bucket_owner;
        }
        l.updated_at = ctx.received_at;
        Ok(())
    }

    pub(crate) fn delete_list(
        &self,
        ctx: &RequestContext,
        kind: Kind,
        detector_id: &str,
        id: &str,
    ) -> Result<(), ServiceError> {
        let tags = self.list_tags(ctx, kind, detector_id, id)?;
        self.authorize_child(
            ctx,
            &format!("Delete{}", kind.noun()),
            detector_id,
            kind.segment(),
            id,
            Some(&tags),
            Default::default(),
        )?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, detector_id)?;
        kind.map_mut(det).remove(id).ok_or_else(no_such_resource)?;
        Ok(())
    }

    pub(crate) fn list_ids(
        &self,
        ctx: &RequestContext,
        kind: Kind,
        detector_id: &str,
        max: Option<i32>,
        token: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>), ServiceError> {
        self.authorize_detector(ctx, &format!("List{}s", kind.noun()), detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, detector_id)?;
        paginate(kind.map(det).keys().cloned().collect(), max, 50, token)
    }

    // ---- publishing destinations -------------------------------------------

    fn check_destination(p: &types::DestinationProperties) -> Result<(), ServiceError> {
        match p.destination_arn.as_deref() {
            Some(a) if a.starts_with("arn:") && a.contains(":s3:::") => {}
            _ => return Err(invalid_input("The request is rejected because the destinationArn is invalid.")),
        }
        match p.kms_key_arn.as_deref() {
            Some(k) if k.starts_with("arn:") && k.contains(":kms:") => Ok(()),
            _ => Err(invalid_input("The request is rejected because the kmsKeyArn is invalid.")),
        }
    }

    pub(crate) fn create_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::CreatePublishingDestinationRequest,
    ) -> Result<types::CreatePublishingDestinationResponse, ServiceError> {
        if let Some(t) = &input.tags {
            validate_tags(t)?;
        }
        {
            let state = self.lock();
            Self::owned(&state, ctx, &input.detector_id)?;
        }
        self.authorize(
            ctx,
            "CreatePublishingDestination",
            &detector_arn(ctx, &ctx.caller.account_id, &input.detector_id),
            request_tag_context(input.tags.as_ref()),
        )?;
        Self::check_destination(&input.destination_properties)?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        if !det.destinations.is_empty() {
            return Err(invalid_input(
                "The request is rejected because the number of publishing destinations reached the limit.",
            ));
        }
        let id = hex_id(32);
        det.destinations.insert(
            id.clone(),
            Destination {
                id: id.clone(),
                ty: input.destination_type,
                properties: input.destination_properties,
                status: "PUBLISHING".into(),
                failure_since: 0,
                tags: input.tags.unwrap_or_default(),
                exported_through: None,
            },
        );
        Ok(types::CreatePublishingDestinationResponse { destination_id: id })
    }

    fn destination_tags(&self, ctx: &RequestContext, detector_id: &str, id: &str) -> Result<Tags, ServiceError> {
        let state = self.lock();
        let det = Self::owned(&state, ctx, detector_id)?;
        Ok(det.destinations.get(id).map(|d| d.tags.clone()).unwrap_or_default())
    }

    pub(crate) fn describe_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::DescribePublishingDestinationRequest,
    ) -> Result<types::DescribePublishingDestinationResponse, ServiceError> {
        let tags = self.destination_tags(ctx, &input.detector_id, &input.destination_id)?;
        self.authorize_child(
            ctx,
            "DescribePublishingDestination",
            &input.detector_id,
            "publishingDestination",
            &input.destination_id,
            Some(&tags),
            Default::default(),
        )?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let d = det.destinations.get(&input.destination_id).ok_or_else(no_such_resource)?;
        Ok(types::DescribePublishingDestinationResponse {
            destination_id: d.id.clone(),
            destination_type: d.ty.clone(),
            status: d.status.clone(),
            publishing_failure_start_timestamp: d.failure_since,
            destination_properties: d.properties.clone(),
            tags: Some(d.tags.clone()),
        })
    }

    pub(crate) fn update_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePublishingDestinationRequest,
    ) -> Result<types::UpdatePublishingDestinationResponse, ServiceError> {
        let tags = self.destination_tags(ctx, &input.detector_id, &input.destination_id)?;
        self.authorize_child(
            ctx,
            "UpdatePublishingDestination",
            &input.detector_id,
            "publishingDestination",
            &input.destination_id,
            Some(&tags),
            Default::default(),
        )?;
        if let Some(p) = &input.destination_properties {
            Self::check_destination(p)?;
        }
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        let d = det.destinations.get_mut(&input.destination_id).ok_or_else(no_such_resource)?;
        if let Some(p) = input.destination_properties {
            d.properties = p;
            d.status = "PUBLISHING".into();
            d.failure_since = 0;
        }
        Ok(Default::default())
    }

    pub(crate) fn delete_publishing_destination(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublishingDestinationRequest,
    ) -> Result<types::DeletePublishingDestinationResponse, ServiceError> {
        let tags = self.destination_tags(ctx, &input.detector_id, &input.destination_id)?;
        self.authorize_child(
            ctx,
            "DeletePublishingDestination",
            &input.detector_id,
            "publishingDestination",
            &input.destination_id,
            Some(&tags),
            Default::default(),
        )?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        det.destinations.remove(&input.destination_id).ok_or_else(no_such_resource)?;
        Ok(Default::default())
    }

    pub(crate) fn list_publishing_destinations(
        &self,
        ctx: &RequestContext,
        input: types::ListPublishingDestinationsRequest,
    ) -> Result<types::ListPublishingDestinationsResponse, ServiceError> {
        self.authorize_detector(ctx, "ListPublishingDestinations", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let all = det
            .destinations
            .values()
            .map(|d| types::Destination {
                destination_id: d.id.clone(),
                destination_type: d.ty.clone(),
                status: d.status.clone(),
            })
            .collect();
        let (destinations, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListPublishingDestinationsResponse { destinations, next_token })
    }
}
