//! The rest of the RDS API: zero-ETL integrations, DB capacity
//! reservations, database activity streams, cross-Region automated backup
//! replication, RDS Custom engine versions, Serverless v2 platform
//! versions, recommendations, and the APIs for engines and platforms MWS
//! does not run (EC2-Classic DB security groups, Oracle tenant databases
//! and switchover, Aurora Serverless v1 capacity).

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::engine_of;
use super::{
    authorize, authorize_create, cluster_arn, cluster_not_found, db_arn, instance_not_found, invalid_cluster_state,
};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::util::{
    account_of, arn, invalid_combination, invalid_parameter, name_of, opt, paginate, parse_arn, request_tag_context,
    resource_tag_context, stable_token, tags_from, zones, Filters,
};
use crate::Rds;

const MAX_INTEGRATIONS: usize = 100;

fn integration_not_found(id: &str) -> ServiceError {
    errors::integration_not_found_fault(format!("Integration {id} not found."))
}

fn reservation_not_found(id: &str) -> ServiceError {
    errors::db_capacity_reservation_not_found_fault(format!("DBCapacityReservation {id} not found."))
}

fn security_group_not_found(name: &str) -> ServiceError {
    errors::db_security_group_not_found_fault(format!("DBSecurityGroup {name} not found."))
}

fn cev_not_found(engine: &str, version: &str) -> ServiceError {
    errors::custom_db_engine_version_not_found_fault(format!(
        "The custom engine version {version} for engine {engine} doesn't exist."
    ))
}

fn cev_key(engine: &str, version: &str) -> String {
    format!("{engine}/{version}")
}

/// Zero-ETL targets: Redshift (provisioned or Serverless) namespaces and
/// SageMaker Lakehouse (Glue) catalogs.
fn check_target(target: &str) -> Result<(), ServiceError> {
    let service = target.split(':').nth(2).unwrap_or_default();
    if target.starts_with("arn:") && matches!(service, "redshift" | "redshift-serverless" | "glue") {
        Ok(())
    } else {
        Err(invalid_parameter(format!("The target ARN {target} isn't valid for a zero-ETL integration.")))
    }
}

impl Rds {
    // ---- zero-ETL integrations ------------------------------------------------

    fn find_integration(&self, ctx: &RequestContext, id: &str) -> Result<t::Integration, ServiceError> {
        self.with_region(ctx, |r| {
            r.integrations
                .values()
                .find(|i| i.integration_name.as_deref() == Some(id) || i.integration_arn.as_deref() == Some(id))
                .cloned()
        })
        .ok_or_else(|| integration_not_found(id))
    }

    /// Integrations move from `creating` (or `modifying`) to `active`, and
    /// leave when deleted.
    async fn settle_integration(&self, ctx: &RequestContext, name: &str, delete: bool) {
        let this = self.clone();
        let ctx = ctx.clone();
        let name = name.to_string();
        self.run_task(async move {
            this.with_region(&ctx, |r| {
                if delete {
                    r.integrations.remove(&name);
                } else if let Some(i) = r.integrations.get_mut(&name) {
                    i.status = Some("active".into());
                }
            });
        })
        .await;
    }

    pub(crate) async fn create_integration_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateIntegrationMessage,
    ) -> Result<t::Integration, ServiceError> {
        let name = input.integration_name.clone();
        if name.is_empty()
            || name.len() > 63
            || !name.starts_with(|c: char| c.is_ascii_alphabetic())
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || name.ends_with('-')
            || name.contains("--")
        {
            return Err(invalid_parameter(format!("The integration name {name} isn't valid.")));
        }
        let tags = tags_from(&input.tags)?;
        let iarn = arn(ctx, "integration", &uuid::Uuid::new_v4().to_string());
        authorize_create(ctx, "CreateIntegration", &iarn, &tags, request_tag_context(&tags))?;
        check_target(&input.target_arn)?;
        let (_, account, kind, source) = parse_arn(&input.source_arn)
            .ok_or_else(|| invalid_parameter(format!("The source ARN {} isn't valid.", input.source_arn)))?;
        if account != account_of(ctx) {
            return Err(invalid_parameter(format!("The source ARN {} isn't valid.", input.source_arn)));
        }
        match kind.as_str() {
            "cluster" => {
                let c = self.cluster(ctx, &source)?;
                if c.cluster.status.as_deref() != Some("available") {
                    return Err(invalid_cluster_state(&source, c.cluster.status.as_deref().unwrap_or_default()));
                }
            }
            "db" => {
                self.instance(ctx, &source)?;
            }
            _ => return Err(invalid_parameter(format!("The source ARN {} isn't valid.", input.source_arn))),
        }
        let kms = match &input.kms_key_id {
            Some(k) => Some(self.storage_key(ctx, Some(k), &name)?),
            None => None,
        };
        let integration = t::Integration {
            source_arn: Some(input.source_arn.clone()),
            target_arn: Some(input.target_arn.clone()),
            integration_name: Some(name.clone()),
            integration_arn: Some(iarn),
            kms_key_id: kms,
            additional_encryption_context: input.additional_encryption_context.clone(),
            status: Some("creating".into()),
            tags: Some(tags),
            data_filter: input.data_filter.clone(),
            description: input.description.clone(),
            create_time: Some(ctx.received_at),
            errors: Some(Vec::new()),
        };
        self.with_region(ctx, |r| {
            if r.integrations.contains_key(&name) {
                return Err(errors::integration_already_exists_fault(format!(
                    "An integration with the name {name} already exists."
                )));
            }
            if r.integrations.values().any(|i| {
                i.source_arn.as_deref() == Some(input.source_arn.as_str())
                    && i.target_arn.as_deref() == Some(input.target_arn.as_str())
            }) {
                return Err(errors::integration_already_exists_fault(
                    "An integration between this source and target already exists.",
                ));
            }
            if r.integrations.len() >= MAX_INTEGRATIONS {
                return Err(errors::integration_quota_exceeded_fault(
                    "You can't create more integrations in this account and Region.",
                ));
            }
            r.integrations.insert(name.clone(), integration.clone());
            Ok(())
        })?;
        self.settle_integration(ctx, &name, false).await;
        Ok(integration)
    }

    pub(crate) async fn modify_integration_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyIntegrationMessage,
    ) -> Result<t::Integration, ServiceError> {
        let i = self.find_integration(ctx, &input.integration_identifier)?;
        let name = i.integration_name.clone().unwrap_or_default();
        authorize(
            ctx,
            "ModifyIntegration",
            i.integration_arn.as_deref().unwrap_or_default(),
            resource_tag_context("integration", &i.tags),
        )?;
        if !matches!(i.status.as_deref(), Some("active") | Some("needs_attention")) {
            return Err(errors::invalid_integration_state_fault(format!(
                "The integration {name} isn't in a state that allows changes."
            )));
        }
        let new_name = input.integration_name.clone().filter(|n| *n != name);
        let updated = self.with_region(ctx, |r| {
            if let Some(n) = &new_name {
                if r.integrations.contains_key(n) {
                    return Err(errors::integration_conflict_operation_fault(format!(
                        "An integration with the name {n} already exists."
                    )));
                }
            }
            let mut i = r.integrations.remove(&name).ok_or_else(|| integration_not_found(&name))?;
            if let Some(n) = &new_name {
                i.integration_name = Some(n.clone());
            }
            if input.data_filter.is_some() {
                i.data_filter = input.data_filter.clone();
            }
            if input.description.is_some() {
                i.description = input.description.clone();
            }
            i.status = Some("modifying".into());
            r.integrations.insert(i.integration_name.clone().unwrap_or_default(), i.clone());
            Ok(i)
        })?;
        self.settle_integration(ctx, updated.integration_name.as_deref().unwrap_or_default(), false).await;
        Ok(updated)
    }

    pub(crate) async fn delete_integration_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteIntegrationMessage,
    ) -> Result<t::Integration, ServiceError> {
        let i = self.find_integration(ctx, &input.integration_identifier)?;
        let name = i.integration_name.clone().unwrap_or_default();
        authorize(
            ctx,
            "DeleteIntegration",
            i.integration_arn.as_deref().unwrap_or_default(),
            resource_tag_context("integration", &i.tags),
        )?;
        if i.status.as_deref() == Some("deleting") {
            return Err(errors::invalid_integration_state_fault(format!(
                "The integration {name} is already being deleted."
            )));
        }
        let shown = self
            .with_region(ctx, |r| {
                let i = r.integrations.get_mut(&name)?;
                i.status = Some("deleting".into());
                Some(i.clone())
            })
            .ok_or_else(|| integration_not_found(&name))?;
        self.settle_integration(ctx, &name, true).await;
        Ok(shown)
    }

    pub(crate) fn describe_integrations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeIntegrationsMessage,
    ) -> Result<t::DescribeIntegrationsResponse, ServiceError> {
        authorize(ctx, "DescribeIntegrations", &arn(ctx, "integration", "*"), ConditionContext::new())?;
        let f = Filters::new(
            &input.filters,
            &["integration-identifier", "integration-arn", "source-arn", "target-arn", "status"],
        )?;
        let all: Vec<t::Integration> = self.with_region(ctx, |r| r.integrations.values().cloned().collect());
        let wanted = input.integration_identifier.clone();
        let all: Vec<t::Integration> = all
            .into_iter()
            .filter(|i| {
                wanted
                    .as_ref()
                    .is_none_or(|w| i.integration_name.as_ref() == Some(w) || i.integration_arn.as_ref() == Some(w))
            })
            .filter(|i| {
                f.matches(|n| match n {
                    "integration-identifier" => {
                        let mut v = opt(&i.integration_name);
                        v.extend(opt(&i.integration_arn));
                        v
                    }
                    "integration-arn" => opt(&i.integration_arn),
                    "source-arn" => opt(&i.source_arn),
                    "target-arn" => opt(&i.target_arn),
                    "status" => opt(&i.status),
                    _ => Vec::new(),
                })
            })
            .collect();
        if let Some(w) = &wanted {
            if all.is_empty() {
                return Err(integration_not_found(w));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeIntegrationsResponse { marker, integrations: Some(page) })
    }

    // ---- DB capacity reservations ----------------------------------------------

    /// A reservation with its state and free capacity as of now.
    fn reservation_view(&self, ctx: &RequestContext, c: &t::DBCapacityReservation) -> t::DBCapacityReservation {
        let mut c = c.clone();
        let now = ctx.received_at;
        if matches!(c.state.as_deref(), Some("scheduled") | Some("active")) {
            c.state = Some(
                if c.end_date.is_some_and(|e| now >= e) {
                    "expired"
                } else if c.start_date.is_some_and(|s| now < s) {
                    "scheduled"
                } else {
                    "active"
                }
                .into(),
            );
        }
        let reserved = c.reserved_capacity_per_availability_zone.unwrap_or(0);
        let class = c.db_instance_class.clone();
        let engine = c.engine.clone();
        let used = |az: &str| -> i32 {
            self.with_region(ctx, |r| {
                r.instances
                    .values()
                    .filter(|i| {
                        i.db.db_instance_class == class
                            && i.db.engine == engine
                            && i.db.availability_zone.as_deref() == Some(az)
                            && i.db.db_instance_status.as_deref() != Some("deleting")
                    })
                    .count() as i32
            })
        };
        let zones: Vec<String> = c
            .available_capacity_per_availability_zone_list
            .iter()
            .flatten()
            .filter_map(|z| z.availability_zone.clone())
            .collect();
        c.available_capacity_per_availability_zone_list = Some(
            zones
                .into_iter()
                .map(|az| t::AvailableCapacityPerAvailabilityZone {
                    available_capacity: Some(if c.state.as_deref() == Some("active") {
                        (reserved - used(&az)).max(0)
                    } else {
                        0
                    }),
                    availability_zone: Some(az),
                })
                .collect(),
        );
        c
    }

    pub(crate) fn create_db_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBCapacityReservationRequest,
    ) -> Result<t::CreateDBCapacityReservationResponse, ServiceError> {
        let name = input.db_capacity_reservation_name.clone();
        if name.is_empty() || name.len() > 255 {
            return Err(invalid_parameter("DBCapacityReservationName must be 1 to 255 characters."));
        }
        let id = format!("cr-{}", stable_token(&uuid::Uuid::new_v4().to_string(), 17));
        let tags = tags_from(&input.tags)?;
        let carn = arn(ctx, "capacity-reservation", &id);
        authorize_create(ctx, "CreateDBCapacityReservation", &carn, &tags, request_tag_context(&tags))?;
        let engine = engine_of(&input.engine)?;
        if !catalog::CLASSES.iter().any(|c| c.0 == input.db_instance_class)
            || input.db_instance_class == "db.serverless"
        {
            return Err(errors::db_capacity_reservation_unsupported_fault(format!(
                "Capacity reservations aren't supported for DB instance class {}.",
                input.db_instance_class
            )));
        }
        let capacity = input.capacity_per_availability_zone;
        if !(1..=1000).contains(&capacity) {
            return Err(invalid_parameter("CapacityPerAvailabilityZone must be between 1 and 1000."));
        }
        let region_zones = zones(&ctx.region);
        if input.availability_zones.is_empty() {
            return Err(invalid_parameter("Specify at least one Availability Zone."));
        }
        for az in &input.availability_zones {
            if !region_zones.contains(az) {
                return Err(invalid_parameter(format!("The Availability Zone {az} doesn't exist in {}.", ctx.region)));
            }
        }
        let now = ctx.received_at;
        let start = input.start_date.unwrap_or(now);
        if let Some(end) = input.end_date {
            if end <= start {
                return Err(invalid_parameter("EndDate must be later than StartDate."));
            }
        }
        let commitment = input.commitment_duration.map(|d| t::DBCapacityReservationCommitmentInfo {
            committed_capacity_per_availability_zone: Some(capacity),
            commitment_end_date: Some(start + Duration::seconds(d)),
        });
        let reservation = t::DBCapacityReservation {
            db_capacity_reservation_name: Some(name.clone()),
            db_instance_class: Some(input.db_instance_class.clone()),
            engine: Some(engine.name.to_string()),
            license_model: Some(input.license_model.clone().unwrap_or_else(|| engine.license.to_string())),
            reserved_capacity_per_availability_zone: Some(capacity),
            available_capacity_per_availability_zone_list: Some(
                input
                    .availability_zones
                    .iter()
                    .map(|az| t::AvailableCapacityPerAvailabilityZone {
                        availability_zone: Some(az.clone()),
                        available_capacity: Some(capacity),
                    })
                    .collect(),
            ),
            end_date: input.end_date,
            create_date: Some(now),
            start_date: Some(start),
            commitment_info: commitment,
            state: Some(if start > now { "scheduled" } else { "active" }.into()),
            db_capacity_reservation_arn: Some(carn),
            db_capacity_reservation_identifier: Some(id.clone()),
            tag_list: Some(tags),
        };
        self.with_region(ctx, |r| {
            if r.capacity_reservations
                .values()
                .any(|c| c.db_capacity_reservation_name.as_deref() == Some(name.as_str()))
            {
                return Err(errors::db_capacity_reservation_already_exists_fault(format!(
                    "A DB capacity reservation named {name} already exists."
                )));
            }
            r.capacity_reservations.insert(id.clone(), reservation.clone());
            Ok(())
        })?;
        Ok(t::CreateDBCapacityReservationResponse {
            db_capacity_reservation: Some(self.reservation_view(ctx, &reservation)),
        })
    }

    fn reservation(&self, ctx: &RequestContext, id: &str) -> Result<t::DBCapacityReservation, ServiceError> {
        self.with_region(ctx, |r| {
            r.capacity_reservations
                .values()
                .find(|c| {
                    c.db_capacity_reservation_identifier.as_deref() == Some(id)
                        || c.db_capacity_reservation_arn.as_deref() == Some(id)
                })
                .cloned()
        })
        .map(|c| self.reservation_view(ctx, &c))
        .ok_or_else(|| reservation_not_found(id))
    }

    pub(crate) fn modify_db_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBCapacityReservationRequest,
    ) -> Result<t::ModifyDBCapacityReservationResponse, ServiceError> {
        let c = self.reservation(ctx, &input.db_capacity_reservation_identifier)?;
        let id = c.db_capacity_reservation_identifier.clone().unwrap_or_default();
        authorize(
            ctx,
            "ModifyDBCapacityReservation",
            c.db_capacity_reservation_arn.as_deref().unwrap_or_default(),
            resource_tag_context("capacity-reservation", &c.tag_list),
        )?;
        if !matches!(c.state.as_deref(), Some("active") | Some("scheduled")) {
            return Err(errors::invalid_db_capacity_reservation_state_fault(format!(
                "The DB capacity reservation {id} is {}.",
                c.state.as_deref().unwrap_or_default()
            )));
        }
        if let Some(n) = input.capacity_per_availability_zone {
            if !(1..=1000).contains(&n) {
                return Err(invalid_parameter("CapacityPerAvailabilityZone must be between 1 and 1000."));
            }
            let committed =
                c.commitment_info.as_ref().and_then(|i| i.committed_capacity_per_availability_zone).unwrap_or(0);
            let committed_until = c.commitment_info.as_ref().and_then(|i| i.commitment_end_date);
            if n < committed && committed_until.is_some_and(|e| ctx.received_at < e) {
                return Err(invalid_parameter(format!(
                    "You can't reduce the capacity below the committed {committed} per Availability Zone."
                )));
            }
        }
        let end = match input.end_date_type.as_deref() {
            None => input.end_date.map(Some),
            Some("unlimited") => {
                if input.end_date.is_some() {
                    return Err(invalid_combination("You can't specify EndDate with EndDateType unlimited."));
                }
                Some(None)
            }
            Some("limited") => match input.end_date {
                Some(e) => Some(Some(e)),
                None => return Err(invalid_parameter("Specify EndDate with EndDateType limited.")),
            },
            Some(other) => return Err(invalid_parameter(format!("Invalid EndDateType: {other}"))),
        };
        if let Some(Some(e)) = end {
            if e <= ctx.received_at {
                return Err(invalid_parameter("EndDate must be in the future."));
            }
        }
        let updated = self
            .with_region(ctx, |r| {
                let c = r.capacity_reservations.get_mut(&id)?;
                if let Some(n) = input.capacity_per_availability_zone {
                    c.reserved_capacity_per_availability_zone = Some(n);
                }
                if let Some(e) = end {
                    c.end_date = e;
                }
                Some(c.clone())
            })
            .ok_or_else(|| reservation_not_found(&id))?;
        Ok(t::ModifyDBCapacityReservationResponse {
            db_capacity_reservation: Some(self.reservation_view(ctx, &updated)),
        })
    }

    pub(crate) fn cancel_db_capacity_reservation_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelDBCapacityReservationRequest,
    ) -> Result<t::CancelDBCapacityReservationResponse, ServiceError> {
        let c = self.reservation(ctx, &input.db_capacity_reservation_identifier)?;
        let id = c.db_capacity_reservation_identifier.clone().unwrap_or_default();
        authorize(
            ctx,
            "CancelDBCapacityReservation",
            c.db_capacity_reservation_arn.as_deref().unwrap_or_default(),
            resource_tag_context("capacity-reservation", &c.tag_list),
        )?;
        if !matches!(c.state.as_deref(), Some("active") | Some("scheduled")) {
            return Err(errors::invalid_db_capacity_reservation_state_fault(format!(
                "The DB capacity reservation {id} is {}.",
                c.state.as_deref().unwrap_or_default()
            )));
        }
        if c.commitment_info.as_ref().and_then(|i| i.commitment_end_date).is_some_and(|e| ctx.received_at < e) {
            return Err(errors::invalid_db_capacity_reservation_state_fault(format!(
                "The DB capacity reservation {id} can't be cancelled during its commitment."
            )));
        }
        let updated = self
            .with_region(ctx, |r| {
                let c = r.capacity_reservations.get_mut(&id)?;
                c.state = Some("cancelled".into());
                Some(c.clone())
            })
            .ok_or_else(|| reservation_not_found(&id))?;
        Ok(t::CancelDBCapacityReservationResponse {
            db_capacity_reservation: Some(self.reservation_view(ctx, &updated)),
        })
    }

    pub(crate) fn describe_db_capacity_reservations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBCapacityReservationsRequest,
    ) -> Result<t::DescribeDBCapacityReservationsResponse, ServiceError> {
        authorize(
            ctx,
            "DescribeDBCapacityReservations",
            &arn(ctx, "capacity-reservation", "*"),
            ConditionContext::new(),
        )?;
        let f = Filters::new(
            &input.filters,
            &["db-capacity-reservation-name", "db-instance-class", "engine", "state", "availability-zone"],
        )?;
        let all: Vec<t::DBCapacityReservation> =
            self.with_region(ctx, |r| r.capacity_reservations.values().cloned().collect());
        let all: Vec<t::DBCapacityReservation> = all
            .iter()
            .map(|c| self.reservation_view(ctx, c))
            .filter(|c| {
                input.db_capacity_reservation_identifier.as_ref().is_none_or(|w| {
                    c.db_capacity_reservation_identifier.as_ref() == Some(w)
                        || c.db_capacity_reservation_arn.as_ref() == Some(w)
                })
            })
            .filter(|c| {
                f.matches(|n| match n {
                    "db-capacity-reservation-name" => opt(&c.db_capacity_reservation_name),
                    "db-instance-class" => opt(&c.db_instance_class),
                    "engine" => opt(&c.engine),
                    "state" => opt(&c.state),
                    "availability-zone" => c
                        .available_capacity_per_availability_zone_list
                        .iter()
                        .flatten()
                        .filter_map(|z| z.availability_zone.clone())
                        .collect(),
                    _ => Vec::new(),
                })
            })
            .collect();
        if let Some(w) = &input.db_capacity_reservation_identifier {
            if all.is_empty() {
                return Err(reservation_not_found(w));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeDBCapacityReservationsResponse { db_capacity_reservations: Some(page), marker })
    }

    // ---- database activity streams ----------------------------------------------

    pub(crate) async fn start_activity_stream_op(
        &self,
        ctx: &RequestContext,
        input: t::StartActivityStreamRequest,
    ) -> Result<t::StartActivityStreamResponse, ServiceError> {
        let (_, _, kind, name) = parse_arn(&input.resource_arn)
            .ok_or_else(|| errors::resource_not_found_fault(format!("Resource {} not found.", input.resource_arn)))?;
        authorize(ctx, "StartActivityStream", &input.resource_arn, ConditionContext::new())?;
        let mode = input.mode.clone();
        if !matches!(mode.as_str(), "sync" | "async") {
            return Err(invalid_parameter(format!("Invalid Mode: {mode}")));
        }
        match kind.as_str() {
            "cluster" => {
                let c = self.cluster(ctx, &name)?;
                let engine = c.cluster.engine.clone().unwrap_or_default();
                if !engine.starts_with("aurora") {
                    return Err(errors::invalid_db_cluster_state_fault(format!(
                        "Database activity streams aren't supported for engine {engine}."
                    )));
                }
                if engine == "aurora-mysql" && mode == "sync" {
                    return Err(invalid_combination("Aurora MySQL supports only the async activity stream mode."));
                }
                let status = c.cluster.status.clone().unwrap_or_default();
                if status != "available" {
                    return Err(invalid_cluster_state(&name, &status));
                }
                if c.cluster.activity_stream_status.as_deref().is_some_and(|s| s != "stopped") {
                    return Err(errors::invalid_db_cluster_state_fault(format!(
                        "The DB cluster {name} already has an activity stream."
                    )));
                }
                let key = self.storage_key(ctx, Some(&input.kms_key_id), &name)?;
                let stream = format!("aws-rds-das-{}", c.cluster.db_cluster_resource_id.clone().unwrap_or_default());
                self.with_region(ctx, |r| {
                    if let Some(c) = r.clusters.get_mut(&name) {
                        c.cluster.activity_stream_status = Some("starting".into());
                        c.cluster.activity_stream_mode = Some(mode.clone());
                        c.cluster.activity_stream_kms_key_id = Some(key.clone());
                        c.cluster.activity_stream_kinesis_stream_name = Some(stream.clone());
                    }
                });
                self.settle_activity_stream(ctx, &name, "started").await;
                Ok(t::StartActivityStreamResponse {
                    kms_key_id: Some(key),
                    kinesis_stream_name: Some(stream),
                    status: Some("starting".into()),
                    mode: Some(mode),
                    engine_native_audit_fields_included: input.engine_native_audit_fields_included,
                    apply_immediately: Some(input.apply_immediately.unwrap_or(false)),
                })
            }
            "db" => {
                let i = self.instance(ctx, &name)?;
                let engine = i.db.engine.clone().unwrap_or_default();
                Err(errors::invalid_db_instance_state_fault(format!(
                    "Database activity streams on DB instances are supported only for RDS for Oracle and RDS for SQL Server, not {engine}."
                )))
            }
            _ => Err(errors::resource_not_found_fault(format!("Resource {} not found.", input.resource_arn))),
        }
    }

    async fn settle_activity_stream(&self, ctx: &RequestContext, cluster: &str, status: &'static str) {
        let this = self.clone();
        let ctx = ctx.clone();
        let cluster = cluster.to_string();
        self.run_task(async move {
            this.with_region(&ctx, |r| {
                if let Some(c) = r.clusters.get_mut(&cluster) {
                    c.cluster.activity_stream_status = Some(status.into());
                    if status == "stopped" {
                        c.cluster.activity_stream_mode = None;
                        c.cluster.activity_stream_kms_key_id = None;
                        c.cluster.activity_stream_kinesis_stream_name = None;
                    }
                }
            });
        })
        .await;
    }

    pub(crate) async fn stop_activity_stream_op(
        &self,
        ctx: &RequestContext,
        input: t::StopActivityStreamRequest,
    ) -> Result<t::StopActivityStreamResponse, ServiceError> {
        let (_, _, kind, name) = parse_arn(&input.resource_arn)
            .ok_or_else(|| errors::resource_not_found_fault(format!("Resource {} not found.", input.resource_arn)))?;
        authorize(ctx, "StopActivityStream", &input.resource_arn, ConditionContext::new())?;
        match kind.as_str() {
            "cluster" => {
                let c = self.cluster(ctx, &name)?;
                if c.cluster.activity_stream_status.as_deref() != Some("started") {
                    return Err(errors::invalid_db_cluster_state_fault(format!(
                        "The DB cluster {name} has no started activity stream."
                    )));
                }
                self.with_region(ctx, |r| {
                    if let Some(c) = r.clusters.get_mut(&name) {
                        c.cluster.activity_stream_status = Some("stopping".into());
                    }
                });
                let out = t::StopActivityStreamResponse {
                    kms_key_id: c.cluster.activity_stream_kms_key_id.clone(),
                    kinesis_stream_name: c.cluster.activity_stream_kinesis_stream_name.clone(),
                    status: Some("stopping".into()),
                };
                self.settle_activity_stream(ctx, &name, "stopped").await;
                Ok(out)
            }
            "db" => {
                self.instance(ctx, &name)?;
                Err(errors::invalid_db_instance_state_fault(format!(
                    "The DB instance {name} has no started activity stream."
                )))
            }
            _ => Err(errors::resource_not_found_fault(format!("Resource {} not found.", input.resource_arn))),
        }
    }

    pub(crate) fn modify_activity_stream_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyActivityStreamRequest,
    ) -> Result<t::ModifyActivityStreamResponse, ServiceError> {
        let resource = input.resource_arn.clone().unwrap_or_default();
        authorize(ctx, "ModifyActivityStream", &resource, ConditionContext::new())?;
        if let Some(p) = &input.audit_policy_state {
            if !matches!(p.as_str(), "locked" | "unlocked") {
                return Err(invalid_parameter(format!("Invalid AuditPolicyState: {p}")));
            }
        }
        match parse_arn(&resource) {
            Some((_, _, kind, name)) if kind == "db" => {
                let i = self.instance(ctx, &name)?;
                Err(errors::invalid_db_instance_state_fault(format!(
                    "Activity stream audit policies apply only to RDS for Oracle, not {}.",
                    i.db.engine.unwrap_or_default()
                )))
            }
            _ => Err(errors::resource_not_found_fault(format!("Resource {resource} not found."))),
        }
    }

    // ---- cross-Region automated backup replication ------------------------------

    pub(crate) fn start_db_instance_automated_backups_replication_op(
        &self,
        ctx: &RequestContext,
        input: t::StartDBInstanceAutomatedBackupsReplicationMessage,
    ) -> Result<t::StartDBInstanceAutomatedBackupsReplicationResult, ServiceError> {
        let (region, account, kind, name) = parse_arn(&input.source_db_instance_arn)
            .filter(|(_, _, k, _)| k == "db")
            .ok_or_else(|| instance_not_found(&input.source_db_instance_arn))?;
        authorize(
            ctx,
            "StartDBInstanceAutomatedBackupsReplication",
            &input.source_db_instance_arn,
            ConditionContext::new(),
        )?;
        let _ = kind;
        if account != account_of(ctx) {
            return Err(instance_not_found(&name));
        }
        if region == ctx.region {
            return Err(invalid_parameter("The source DB instance must be in a different AWS Region."));
        }
        let src = self
            .with_region_of(&account, &region, |r| r.instances.get(&name).cloned())
            .ok_or_else(|| instance_not_found(&name))?;
        if src.db.backup_retention_period.unwrap_or(0) == 0 {
            return Err(errors::invalid_db_instance_state_fault(format!(
                "Automated backups aren't turned on for the DB instance {name}."
            )));
        }
        if !super::maintenance::operational(src.db.db_instance_status.as_deref().unwrap_or_default()) {
            return Err(errors::invalid_db_instance_state_fault(format!("The DB instance {name} isn't available.")));
        }
        let kms = match &input.kms_key_id {
            Some(k) => Some(self.storage_key(ctx, Some(k), &name)?),
            None if src.db.storage_encrypted == Some(true) => {
                return Err(errors::kms_key_not_accessible_fault(
                    "Specify a KMS key in the destination Region to replicate encrypted backups.",
                ))
            }
            None => None,
        };
        let retention = input.backup_retention_period.unwrap_or(7);
        if !(1..=35).contains(&retention) {
            return Err(invalid_parameter("BackupRetentionPeriod must be between 1 and 35."));
        }
        let resource = src.db.dbi_resource_id.clone().unwrap_or_default();
        let src_ctx = RequestContext { region: region.clone(), ..ctx.clone() };
        let mut backup = super::snapshot::automated_backup(&src_ctx, &src);
        let backup_arn = arn(ctx, "auto-backup", &format!("ab-{}", stable_token(&resource, 26)));
        backup.region = Some(ctx.region.clone());
        backup.db_instance_automated_backups_arn = Some(backup_arn.clone());
        backup.status = Some("replicating".into());
        backup.backup_retention_period = Some(retention);
        backup.kms_key_id = kms;
        backup.encrypted = Some(backup.kms_key_id.is_some());
        backup.db_instance_automated_backups_replications = None;
        self.with_region(ctx, |r| {
            if r.replicated_backups.get(&resource).is_some_and(|b| b.status.as_deref() == Some("replicating")) {
                return Err(errors::invalid_db_instance_automated_backup_state_fault(format!(
                    "The DB instance {name} is already replicating automated backups to this Region."
                )));
            }
            r.replicated_backups.insert(resource.clone(), backup.clone());
            Ok(())
        })?;
        self.with_region_of(&account, &region, |r| {
            if let Some(i) = r.instances.get_mut(&name) {
                let list = i.db.db_instance_automated_backups_replications.get_or_insert_with(Vec::new);
                list.retain(|x| x.db_instance_automated_backups_arn.as_deref() != Some(backup_arn.as_str()));
                list.push(t::DBInstanceAutomatedBackupsReplication {
                    db_instance_automated_backups_arn: Some(backup_arn.clone()),
                });
            }
        });
        Ok(t::StartDBInstanceAutomatedBackupsReplicationResult { db_instance_automated_backup: Some(backup) })
    }

    pub(crate) fn stop_db_instance_automated_backups_replication_op(
        &self,
        ctx: &RequestContext,
        input: t::StopDBInstanceAutomatedBackupsReplicationMessage,
    ) -> Result<t::StopDBInstanceAutomatedBackupsReplicationResult, ServiceError> {
        let (region, account, _, name) = parse_arn(&input.source_db_instance_arn)
            .filter(|(_, _, k, _)| k == "db")
            .ok_or_else(|| instance_not_found(&input.source_db_instance_arn))?;
        authorize(
            ctx,
            "StopDBInstanceAutomatedBackupsReplication",
            &input.source_db_instance_arn,
            ConditionContext::new(),
        )?;
        let resource = self
            .with_region_of(&account, &region, |r| r.instances.get(&name).and_then(|i| i.db.dbi_resource_id.clone()))
            .or_else(|| {
                self.with_region(ctx, |r| {
                    r.replicated_backups
                        .values()
                        .find(|b| b.db_instance_arn.as_deref() == Some(input.source_db_instance_arn.as_str()))
                        .and_then(|b| b.dbi_resource_id.clone())
                })
            })
            .ok_or_else(|| instance_not_found(&name))?;
        let backup = self
            .with_region(ctx, |r| {
                let b = r.replicated_backups.get_mut(&resource)?;
                if b.status.as_deref() != Some("replicating") {
                    return None;
                }
                b.status = Some("retained".into());
                Some(b.clone())
            })
            .ok_or_else(|| {
                errors::invalid_db_instance_state_fault(format!(
                    "The DB instance {name} isn't replicating automated backups to this Region."
                ))
            })?;
        let backup_arn = backup.db_instance_automated_backups_arn.clone();
        self.with_region_of(&account, &region, |r| {
            if let Some(i) = r.instances.get_mut(&name) {
                if let Some(list) = i.db.db_instance_automated_backups_replications.as_mut() {
                    list.retain(|x| x.db_instance_automated_backups_arn != backup_arn);
                }
            }
        });
        Ok(t::StopDBInstanceAutomatedBackupsReplicationResult { db_instance_automated_backup: Some(backup) })
    }

    // ---- RDS Custom engine versions -----------------------------------------------

    pub(crate) async fn create_custom_db_engine_version_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCustomDBEngineVersionMessage,
    ) -> Result<t::DBEngineVersion, ServiceError> {
        let engine = input.engine.clone();
        let version = input.engine_version.clone();
        let oracle = engine.starts_with("custom-oracle-");
        let sqlserver = engine.starts_with("custom-sqlserver-");
        if !oracle && !sqlserver {
            return Err(invalid_parameter(format!("Custom engine versions aren't supported for engine {engine}.")));
        }
        if version.is_empty() || version.len() > 60 {
            return Err(invalid_parameter("EngineVersion must be 1 to 60 characters."));
        }
        let tags = tags_from(&input.tags)?;
        let cev_arn = arn(ctx, "cev", &format!("{engine}/{version}/{}", uuid::Uuid::new_v4()));
        authorize_create(ctx, "CreateCustomDBEngineVersion", &cev_arn, &tags, request_tag_context(&tags))?;
        let kms = if oracle {
            if input.database_installation_files_s3_bucket_name.is_none()
                && input.source_custom_db_engine_version_identifier.is_none()
            {
                return Err(invalid_parameter("The parameter DatabaseInstallationFilesS3BucketName must be provided."));
            }
            if input.manifest.is_none() && input.source_custom_db_engine_version_identifier.is_none() {
                return Err(invalid_parameter("The parameter Manifest must be provided."));
            }
            match &input.kms_key_id {
                Some(k) => Some(self.storage_key(ctx, Some(k), &version)?),
                None => return Err(invalid_parameter("The parameter KMSKeyId must be provided.")),
            }
        } else {
            if input.image_id.is_none() && input.use_aws_provided_latest_image != Some(true) {
                return Err(invalid_parameter("The parameter ImageId must be provided."));
            }
            None
        };
        let major = version.split('.').next().unwrap_or_default().to_string();
        let family = format!("{engine}-{major}");
        let cev = t::DBEngineVersion {
            engine: Some(engine.clone()),
            major_engine_version: Some(major),
            engine_version: Some(version.clone()),
            database_installation_files_s3_bucket_name: input.database_installation_files_s3_bucket_name.clone(),
            database_installation_files_s3_prefix: input.database_installation_files_s3_prefix.clone(),
            database_installation_files: input.database_installation_files.clone(),
            custom_db_engine_version_manifest: input.manifest.clone(),
            db_parameter_group_family: Some(family),
            db_engine_description: Some(format!("RDS Custom {engine}")),
            db_engine_version_arn: Some(cev_arn),
            db_engine_version_description: input.description.clone(),
            kms_key_id: kms,
            create_time: Some(ctx.received_at),
            status: Some("creating".into()),
            image: input
                .image_id
                .clone()
                .map(|id| t::CustomDBEngineVersionAMI { image_id: Some(id), status: Some("active".into()) }),
            tag_list: Some(tags),
            ..Default::default()
        };
        let key = cev_key(&engine, &version);
        self.with_region(ctx, |r| {
            if r.custom_engine_versions.contains_key(&key) {
                return Err(errors::custom_db_engine_version_already_exists_fault(format!(
                    "A custom engine version {version} already exists for engine {engine}."
                )));
            }
            if r.custom_engine_versions.len() >= 40 {
                return Err(errors::custom_db_engine_version_quota_exceeded_fault(
                    "You have reached the maximum number of custom engine versions.",
                ));
            }
            r.custom_engine_versions.insert(key.clone(), cev.clone());
            Ok(())
        })?;
        let this = self.clone();
        let tctx = ctx.clone();
        self.run_task(async move {
            this.with_region(&tctx, |r| {
                if let Some(c) = r.custom_engine_versions.get_mut(&key) {
                    c.status = Some("available".into());
                }
            });
        })
        .await;
        Ok(cev)
    }

    pub(crate) fn modify_custom_db_engine_version_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyCustomDBEngineVersionMessage,
    ) -> Result<t::DBEngineVersion, ServiceError> {
        let key = cev_key(&input.engine, &input.engine_version);
        let cev = self
            .with_region(ctx, |r| r.custom_engine_versions.get(&key).cloned())
            .ok_or_else(|| cev_not_found(&input.engine, &input.engine_version))?;
        authorize(
            ctx,
            "ModifyCustomDBEngineVersion",
            cev.db_engine_version_arn.as_deref().unwrap_or_default(),
            resource_tag_context("cev", &cev.tag_list),
        )?;
        if let Some(s) = &input.status {
            if !matches!(s.as_str(), "available" | "inactive" | "inactive-except-restore") {
                return Err(invalid_parameter(format!("Invalid Status: {s}")));
            }
            if !matches!(cev.status.as_deref(), Some("available") | Some("inactive") | Some("inactive-except-restore"))
            {
                return Err(errors::invalid_custom_db_engine_version_state_fault(format!(
                    "The custom engine version {} is {}.",
                    input.engine_version,
                    cev.status.as_deref().unwrap_or_default()
                )));
            }
        }
        Ok(self
            .with_region(ctx, |r| {
                let c = r.custom_engine_versions.get_mut(&key)?;
                if let Some(s) = &input.status {
                    c.status = Some(s.clone());
                }
                if input.description.is_some() {
                    c.db_engine_version_description = input.description.clone();
                }
                Some(c.clone())
            })
            .unwrap_or(cev))
    }

    pub(crate) fn delete_custom_db_engine_version_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteCustomDBEngineVersionMessage,
    ) -> Result<t::DBEngineVersion, ServiceError> {
        let key = cev_key(&input.engine, &input.engine_version);
        let cev = self
            .with_region(ctx, |r| r.custom_engine_versions.get(&key).cloned())
            .ok_or_else(|| cev_not_found(&input.engine, &input.engine_version))?;
        authorize(
            ctx,
            "DeleteCustomDBEngineVersion",
            cev.db_engine_version_arn.as_deref().unwrap_or_default(),
            resource_tag_context("cev", &cev.tag_list),
        )?;
        if cev.status.as_deref() == Some("creating") {
            return Err(errors::invalid_custom_db_engine_version_state_fault(format!(
                "The custom engine version {} is being created.",
                input.engine_version
            )));
        }
        let in_use = self.with_region(ctx, |r| {
            r.instances.values().any(|i| {
                i.db.engine.as_deref() == Some(input.engine.as_str())
                    && i.db.engine_version.as_deref() == Some(input.engine_version.as_str())
            })
        });
        if in_use {
            return Err(errors::invalid_custom_db_engine_version_state_fault(format!(
                "The custom engine version {} is in use by a DB instance.",
                input.engine_version
            )));
        }
        self.with_region(ctx, |r| r.custom_engine_versions.remove(&key));
        let mut shown = cev;
        shown.status = Some("deleting".into());
        Ok(shown)
    }

    /// Custom engine versions matching a DescribeDBEngineVersions request.
    pub(crate) fn custom_engine_versions(
        &self,
        ctx: &RequestContext,
        engine: Option<&str>,
        version: Option<&str>,
    ) -> Vec<t::DBEngineVersion> {
        self.with_region(ctx, |r| {
            r.custom_engine_versions
                .values()
                .filter(|c| engine.is_none_or(|e| c.engine.as_deref() == Some(e)))
                .filter(|c| version.is_none_or(|v| c.engine_version.as_deref() == Some(v)))
                .cloned()
                .collect()
        })
    }

    // ---- Serverless v2 platform versions and recommendations ---------------------

    pub(crate) fn describe_serverless_v2_platform_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeServerlessV2PlatformVersionsMessage,
    ) -> Result<t::ServerlessV2PlatformVersionsMessage, ServiceError> {
        authorize(ctx, "DescribeServerlessV2PlatformVersions", "*", ConditionContext::new())?;
        let f = Filters::new(&input.filters, &["engine", "serverless-v2-platform-version", "status"])?;
        // (version, description, min ACU, max ACU, status, default)
        const VERSIONS: &[(&str, &str, f64, f64, &str, bool)] = &[
            ("1", "Serverless v2 platform version 1", 0.5, 128.0, "deprecated", false),
            ("2", "Serverless v2 platform version 2", 0.0, 256.0, "enabled", false),
            ("3", "Serverless v2 platform version 3", 0.0, 256.0, "enabled", true),
        ];
        let mut all = Vec::new();
        for engine in ["aurora-mysql", "aurora-postgresql"] {
            for v in VERSIONS {
                all.push(t::ServerlessV2PlatformVersionInfo {
                    serverless_v2_platform_version: Some(v.0.into()),
                    serverless_v2_platform_version_description: Some(v.1.into()),
                    engine: Some(engine.into()),
                    serverless_v2_features_support: Some(t::ServerlessV2FeaturesSupport {
                        min_capacity: Some(v.2),
                        max_capacity: Some(v.3),
                    }),
                    status: Some(v.4.into()),
                    is_default: Some(v.5),
                });
            }
        }
        let all: Vec<_> = all
            .into_iter()
            .filter(|v| input.engine.as_ref().is_none_or(|e| v.engine.as_ref() == Some(e)))
            .filter(|v| {
                input
                    .serverless_v2_platform_version
                    .as_ref()
                    .is_none_or(|w| v.serverless_v2_platform_version.as_ref() == Some(w))
            })
            .filter(|v| input.default_only != Some(true) || v.is_default == Some(true))
            .filter(|v| input.include_all == Some(true) || v.status.as_deref() == Some("enabled"))
            .filter(|v| {
                f.matches(|n| match n {
                    "engine" => opt(&v.engine),
                    "serverless-v2-platform-version" => opt(&v.serverless_v2_platform_version),
                    "status" => opt(&v.status),
                    _ => Vec::new(),
                })
            })
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::ServerlessV2PlatformVersionsMessage { marker, serverless_v2_platform_versions: Some(page) })
    }

    pub(crate) fn describe_db_recommendations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBRecommendationsMessage,
    ) -> Result<t::DBRecommendationsMessage, ServiceError> {
        authorize(ctx, "DescribeDBRecommendations", "*", ConditionContext::new())?;
        Filters::new(
            &input.filters,
            &[
                "recommendation-id",
                "status",
                "severity",
                "type-id",
                "dbi-resource-id",
                "cluster-resource-id",
                "pg-arn",
                "cluster-pg-arn",
            ],
        )?;
        let (page, marker) = paginate(Vec::<t::DBRecommendation>::new(), &input.marker, input.max_records)?;
        Ok(t::DBRecommendationsMessage { db_recommendations: Some(page), marker })
    }

    pub(crate) fn modify_db_recommendation_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBRecommendationMessage,
    ) -> Result<t::DBRecommendationMessage, ServiceError> {
        authorize(ctx, "ModifyDBRecommendation", "*", ConditionContext::new())?;
        Err(invalid_parameter(format!("The recommendation {} doesn't exist.", input.recommendation_id)))
    }

    // ---- what MWS's engines and platforms don't have ------------------------------

    pub(crate) fn create_db_security_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBSecurityGroupMessage,
    ) -> Result<t::CreateDBSecurityGroupResult, ServiceError> {
        authorize(
            ctx,
            "CreateDBSecurityGroup",
            &arn(ctx, "secgrp", &input.db_security_group_name),
            ConditionContext::new(),
        )?;
        Err(errors::db_security_group_not_supported_fault(
            "DB security groups are supported only on EC2-Classic, which has been retired. Use VPC security groups instead.",
        ))
    }

    pub(crate) fn describe_db_security_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBSecurityGroupsMessage,
    ) -> Result<t::DBSecurityGroupMessage, ServiceError> {
        authorize(ctx, "DescribeDBSecurityGroups", &arn(ctx, "secgrp", "*"), ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        if let Some(n) = &input.db_security_group_name {
            return Err(security_group_not_found(n));
        }
        let (page, marker) = paginate(Vec::<t::DBSecurityGroup>::new(), &input.marker, input.max_records)?;
        Ok(t::DBSecurityGroupMessage { marker, db_security_groups: Some(page) })
    }

    pub(crate) fn delete_db_security_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBSecurityGroupMessage,
    ) -> Result<(), ServiceError> {
        authorize(
            ctx,
            "DeleteDBSecurityGroup",
            &arn(ctx, "secgrp", &input.db_security_group_name),
            ConditionContext::new(),
        )?;
        Err(security_group_not_found(&input.db_security_group_name))
    }

    pub(crate) fn authorize_db_security_group_ingress_op(
        &self,
        ctx: &RequestContext,
        input: t::AuthorizeDBSecurityGroupIngressMessage,
    ) -> Result<t::AuthorizeDBSecurityGroupIngressResult, ServiceError> {
        authorize(
            ctx,
            "AuthorizeDBSecurityGroupIngress",
            &arn(ctx, "secgrp", &input.db_security_group_name),
            ConditionContext::new(),
        )?;
        Err(security_group_not_found(&input.db_security_group_name))
    }

    pub(crate) fn revoke_db_security_group_ingress_op(
        &self,
        ctx: &RequestContext,
        input: t::RevokeDBSecurityGroupIngressMessage,
    ) -> Result<t::RevokeDBSecurityGroupIngressResult, ServiceError> {
        authorize(
            ctx,
            "RevokeDBSecurityGroupIngress",
            &arn(ctx, "secgrp", &input.db_security_group_name),
            ConditionContext::new(),
        )?;
        Err(security_group_not_found(&input.db_security_group_name))
    }

    /// Tenant databases exist only in RDS for Oracle's multi-tenant
    /// configuration.
    fn no_tenants(&self, ctx: &RequestContext, instance: &str) -> Result<ServiceError, ServiceError> {
        let i = self.instance(ctx, instance)?;
        Ok(errors::invalid_db_instance_state_fault(format!(
            "The DB instance {instance} doesn't use the multi-tenant configuration (engine {}).",
            i.db.engine.unwrap_or_default()
        )))
    }

    pub(crate) fn create_tenant_database_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateTenantDatabaseMessage,
    ) -> Result<t::CreateTenantDatabaseResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        authorize(ctx, "CreateTenantDatabase", &db_arn(ctx, &id), ConditionContext::new())?;
        Err(self.no_tenants(ctx, &id)?)
    }

    pub(crate) fn modify_tenant_database_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyTenantDatabaseMessage,
    ) -> Result<t::ModifyTenantDatabaseResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        authorize(ctx, "ModifyTenantDatabase", &db_arn(ctx, &id), ConditionContext::new())?;
        self.instance(ctx, &id)?;
        Err(errors::tenant_database_not_found_fault(format!("Tenant database {} not found.", input.tenant_db_name)))
    }

    pub(crate) fn delete_tenant_database_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTenantDatabaseMessage,
    ) -> Result<t::DeleteTenantDatabaseResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        authorize(ctx, "DeleteTenantDatabase", &db_arn(ctx, &id), ConditionContext::new())?;
        self.instance(ctx, &id)?;
        Err(errors::tenant_database_not_found_fault(format!("Tenant database {} not found.", input.tenant_db_name)))
    }

    pub(crate) fn describe_tenant_databases_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTenantDatabasesMessage,
    ) -> Result<t::TenantDatabasesMessage, ServiceError> {
        authorize(ctx, "DescribeTenantDatabases", &arn(ctx, "tenant-database", "*"), ConditionContext::new())?;
        Filters::new(
            &input.filters,
            &["tenant-db-name", "tenant-database-resource-id", "dbi-resource-id", "db-instance-id"],
        )?;
        if let Some(i) = &input.db_instance_identifier {
            self.instance(ctx, &name_of(i).to_ascii_lowercase())?;
        }
        let (page, marker) = paginate(Vec::<t::TenantDatabase>::new(), &input.marker, input.max_records)?;
        Ok(t::TenantDatabasesMessage { marker, tenant_databases: Some(page) })
    }

    pub(crate) fn describe_db_snapshot_tenant_databases_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBSnapshotTenantDatabasesMessage,
    ) -> Result<t::DBSnapshotTenantDatabasesMessage, ServiceError> {
        authorize(ctx, "DescribeDBSnapshotTenantDatabases", &arn(ctx, "snapshot", "*"), ConditionContext::new())?;
        Filters::new(
            &input.filters,
            &["tenant-db-name", "tenant-database-resource-id", "dbi-resource-id", "db-instance-id", "db-snapshot-id"],
        )?;
        if let Some(s) = &input.db_snapshot_identifier {
            let name = name_of(s).to_ascii_lowercase();
            if !self.with_region(ctx, |r| r.snapshots.contains_key(&name)) {
                return Err(errors::db_snapshot_not_found_fault(format!("DBSnapshot {name} not found.")));
            }
        }
        let (page, marker) = paginate(Vec::<t::DBSnapshotTenantDatabase>::new(), &input.marker, input.max_records)?;
        Ok(t::DBSnapshotTenantDatabasesMessage { marker, db_snapshot_tenant_databases: Some(page) })
    }

    pub(crate) fn switchover_read_replica_op(
        &self,
        ctx: &RequestContext,
        input: t::SwitchoverReadReplicaMessage,
    ) -> Result<t::SwitchoverReadReplicaResult, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let i = self.instance(ctx, &id)?;
        authorize(ctx, "SwitchoverReadReplica", &db_arn(ctx, &id), resource_tag_context("db", &i.db.tag_list))?;
        if i.db.read_replica_source_db_instance_identifier.is_none() {
            return Err(errors::invalid_db_instance_state_fault(format!("The DB instance {id} isn't a read replica.")));
        }
        Err(errors::invalid_db_instance_state_fault(format!(
            "Switchover is supported only for RDS for Oracle mounted and open replicas, not {}.",
            i.db.engine.unwrap_or_default()
        )))
    }

    pub(crate) fn promote_read_replica_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::PromoteReadReplicaDBClusterMessage,
    ) -> Result<t::PromoteReadReplicaDBClusterResult, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let c = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "PromoteReadReplicaDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &c.cluster.tag_list),
        )?;
        if c.cluster.replication_source_identifier.is_none() || c.cluster.global_cluster_identifier.is_some() {
            return Err(errors::invalid_db_cluster_state_fault(format!("DB cluster {id} is not a read replica.")));
        }
        let status = c.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        let rec = self
            .with_region(ctx, |r| {
                let c = r.clusters.get_mut(&id)?;
                c.cluster.replication_source_identifier = None;
                c.generation += 1;
                Some(c.clone())
            })
            .ok_or_else(|| cluster_not_found(&id))?;
        Ok(t::PromoteReadReplicaDBClusterResult { db_cluster: Some(self.cluster_view(ctx, &rec)) })
    }

    pub(crate) fn modify_current_db_cluster_capacity_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyCurrentDBClusterCapacityMessage,
    ) -> Result<t::DBClusterCapacityInfo, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let c = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "ModifyCurrentDBClusterCapacity",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &c.cluster.tag_list),
        )?;
        Err(errors::invalid_db_cluster_state_fault(format!(
            "The DB cluster {id} isn't an Aurora Serverless v1 cluster (engine mode {}).",
            c.cluster.engine_mode.unwrap_or_else(|| "provisioned".into())
        )))
    }

    pub(crate) async fn restore_db_instance_from_s3_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBInstanceFromS3Message,
    ) -> Result<t::RestoreDBInstanceFromS3Result, ServiceError> {
        authorize(
            ctx,
            "RestoreDBInstanceFromS3",
            &db_arn(ctx, &input.db_instance_identifier.to_ascii_lowercase()),
            ConditionContext::new(),
        )?;
        if input.engine != "mysql" || input.source_engine != "mysql" {
            return Err(invalid_parameter(
                "Restoring from Amazon S3 is supported only for MySQL backups made with Percona XtraBackup.",
            ));
        }
        ctx.authorize("iam:PassRole", &input.s3_ingestion_role_arn, ConditionContext::new())?;
        Err(errors::invalid_s3_bucket_fault(format!(
            "MWS can't read the Percona XtraBackup files in s3://{}/{}: restoring from S3 isn't supported. Create the DB instance and load the data instead.",
            input.s3_bucket_name,
            input.s3_prefix.clone().unwrap_or_default()
        )))
    }

    pub(crate) async fn restore_db_cluster_from_s3_op(
        &self,
        ctx: &RequestContext,
        input: t::RestoreDBClusterFromS3Message,
    ) -> Result<t::RestoreDBClusterFromS3Result, ServiceError> {
        authorize(
            ctx,
            "RestoreDBClusterFromS3",
            &cluster_arn(ctx, &input.db_cluster_identifier.to_ascii_lowercase()),
            ConditionContext::new(),
        )?;
        if input.engine != "aurora-mysql" || input.source_engine != "mysql" {
            return Err(invalid_parameter(
                "Restoring from Amazon S3 is supported only for Aurora MySQL from MySQL backups made with Percona XtraBackup.",
            ));
        }
        ctx.authorize("iam:PassRole", &input.s3_ingestion_role_arn, ConditionContext::new())?;
        Err(errors::invalid_s3_bucket_fault(format!(
            "MWS can't read the Percona XtraBackup files in s3://{}/{}: restoring from S3 isn't supported. Create the DB cluster and load the data instead.",
            input.s3_bucket_name,
            input.s3_prefix.clone().unwrap_or_default()
        )))
    }
}
