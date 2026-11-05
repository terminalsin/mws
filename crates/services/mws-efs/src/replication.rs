//! Replication: a read-only destination file system (new, or an existing
//! one with overwrite protection off) in this or another Region, kept a
//! copy of the source. MWS copies the data when the configuration is made
//! and again whenever it is described.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{FileSystem, State};
use crate::util::{account_of, bad_request, err, fs_arn, fs_not_found, new_id};
use crate::Efs;

fn not_found(id: &str) -> ServiceError {
    err("ReplicationNotFound", 404, format!("No replication configuration found for file system '{id}'."))
}

impl Efs {
    pub(crate) async fn create_replication_configuration(
        &self,
        ctx: &RequestContext,
        input: t::CreateReplicationConfigurationRequest,
    ) -> Result<t::ReplicationConfigurationDescription, ServiceError> {
        let account = account_of(ctx);
        let source = self.file_system(ctx, &input.source_file_system_id)?;
        self.authorize_fs(ctx, "CreateReplicationConfiguration", &source, ConditionContext::new())?;
        if input.destinations.len() != 1 {
            return Err(bad_request("A replication configuration must have exactly one destination."));
        }
        let dest = &input.destinations[0];
        if source.description.life_cycle_state != "available" {
            return Err(crate::util::wrong_state(source.id(), &source.description.life_cycle_state));
        }
        {
            let st = self.lock();
            if st.replication_of(source.id()).is_some() {
                return Err(err(
                    "ReplicationAlreadyExists",
                    409,
                    format!("File system '{}' is already part of a replication configuration.", source.id()),
                ));
            }
        }
        let dest_region = match (&dest.region, &dest.availability_zone_name) {
            (Some(r), _) => r.clone(),
            (None, Some(az)) => az.trim_end_matches(|c: char| c.is_ascii_alphabetic()).to_string(),
            (None, None) => return Err(bad_request("A destination needs a Region or an Availability Zone.")),
        };
        let mut dctx = ctx.clone();
        dctx.region = dest_region.clone();
        let dest_id = match &dest.file_system_id {
            Some(id) => {
                let id = crate::file_systems::fs_id(id).to_string();
                let existing = {
                    let mut st = self.lock();
                    st.region(&account, &dest_region).file_systems.get(&id).cloned().ok_or_else(|| fs_not_found(&id))?
                };
                if existing.id() == source.id() {
                    return Err(bad_request("The source and destination file systems must differ."));
                }
                let protection = existing
                    .description
                    .file_system_protection
                    .as_ref()
                    .and_then(|p| p.replication_overwrite_protection.clone())
                    .unwrap_or_default();
                if protection != "DISABLED" {
                    return Err(err(
                        "ConflictException",
                        409,
                        format!("Destination file system '{id}' has replication overwrite protection enabled."),
                    ));
                }
                if self.lock().replication_of(&id).is_some() {
                    return Err(err(
                        "ReplicationAlreadyExists",
                        409,
                        format!("File system '{id}' is already part of a replication configuration."),
                    ));
                }
                id
            }
            None => {
                let encrypted = dest.kms_key_id.is_some() || source.description.encrypted == Some(true);
                let kms = match (&dest.kms_key_id, encrypted) {
                    (Some(k), _) => Some(k.clone()),
                    (None, true) => Some(self.kms().aws_managed_key(&dctx, "elasticfilesystem")),
                    _ => None,
                };
                let zone = dest
                    .availability_zone_name
                    .as_ref()
                    .and_then(|az| mws_ec2::availability_zones(&dest_region).into_iter().find(|(n, _)| n == az));
                if dest.availability_zone_name.is_some() && zone.is_none() {
                    return Err(err(
                        "UnsupportedAvailabilityZone",
                        400,
                        format!(
                            "The Availability Zone {} is not supported.",
                            dest.availability_zone_name.clone().unwrap_or_default()
                        ),
                    ));
                }
                let mut st = self.lock();
                let long = Self::long_ids(&st, &account, &dest_region);
                let id = new_id("fs", long);
                let description = t::FileSystemDescription {
                    owner_id: account.clone(),
                    creation_token: uuid::Uuid::new_v4().to_string(),
                    file_system_id: id.clone(),
                    file_system_arn: Some(fs_arn(&ctx.partition, &dest_region, &account, &id)),
                    creation_time: ctx.received_at,
                    life_cycle_state: "available".into(),
                    performance_mode: source.description.performance_mode.clone(),
                    encrypted: Some(encrypted),
                    kms_key_id: kms,
                    throughput_mode: Some("elastic".into()),
                    availability_zone_name: zone.as_ref().map(|z| z.0.clone()),
                    availability_zone_id: zone.as_ref().map(|z| z.1.clone()),
                    file_system_protection: Some(t::FileSystemProtectionDescription {
                        replication_overwrite_protection: Some("REPLICATING".into()),
                    }),
                    ..Default::default()
                };
                st.region(&account, &dest_region)
                    .file_systems
                    .insert(id.clone(), FileSystem { description, backup: "DISABLED".into(), ..Default::default() });
                drop(st);
                self.storage().create(&id);
                id
            }
        };
        let source_arn = source.description.file_system_arn.clone().unwrap_or_default();
        let config = t::ReplicationConfigurationDescription {
            source_file_system_id: source.id().into(),
            source_file_system_region: ctx.region.clone(),
            source_file_system_arn: source_arn.clone(),
            original_source_file_system_arn: source_arn.clone(),
            creation_time: ctx.received_at,
            destinations: vec![t::Destination {
                status: "ENABLED".into(),
                file_system_id: dest_id.clone(),
                region: dest_region.clone(),
                last_replicated_timestamp: Some(ctx.received_at),
                owner_id: Some(account.clone()),
                status_message: None,
                role_arn: dest.role_arn.clone(),
            }],
            source_file_system_owner_id: Some(account.clone()),
        };
        {
            let mut st = self.lock();
            if let Some(f) = st.region(&account, &dest_region).file_systems.get_mut(&dest_id) {
                f.description.file_system_protection = Some(t::FileSystemProtectionDescription {
                    replication_overwrite_protection: Some("REPLICATING".into()),
                });
            }
            st.replications.insert(source_arn, config.clone());
        }
        self.storage().replicate(source.id(), &dest_id);
        let mut out = config;
        out.destinations[0].status = "ENABLING".into();
        Ok(out)
    }

    pub(crate) async fn describe_replication_configurations(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReplicationConfigurationsRequest,
    ) -> Result<t::DescribeReplicationConfigurationsResponse, ServiceError> {
        let account = account_of(ctx);
        let filter = match &input.file_system_id {
            Some(id) => {
                let fs = self.file_system(ctx, id)?;
                self.authorize_fs(ctx, "DescribeReplicationConfigurations", &fs, ConditionContext::new())?;
                Some(fs.id().to_string())
            }
            None => {
                ctx.authorize(
                    "elasticfilesystem:DescribeReplicationConfigurations",
                    &fs_arn(&ctx.partition, &ctx.region, &account, "*"),
                    ConditionContext::new(),
                )?;
                None
            }
        };
        let configs: Vec<t::ReplicationConfigurationDescription> = {
            let st = self.lock();
            st.replications
                .values()
                .filter(|r| r.source_file_system_owner_id.as_deref() == Some(account.as_str()))
                .filter(|r| match &filter {
                    Some(id) => {
                        r.source_file_system_id == *id || r.destinations.iter().any(|d| d.file_system_id == *id)
                    }
                    None => {
                        r.source_file_system_region == ctx.region
                            || r.destinations.iter().any(|d| d.region == ctx.region)
                    }
                })
                .cloned()
                .collect()
        };
        if filter.is_some() && configs.is_empty() {
            return Err(not_found(filter.as_deref().unwrap_or_default()));
        }
        // Bring every destination up to date with its source.
        let mut out = Vec::new();
        for mut c in configs {
            for d in &mut c.destinations {
                self.storage().replicate(&c.source_file_system_id, &d.file_system_id);
                d.last_replicated_timestamp = Some(ctx.received_at);
            }
            self.lock().replications.insert(c.source_file_system_arn.clone(), c.clone());
            out.push(c);
        }
        let (items, next) = crate::util::page(
            out,
            |c| c.source_file_system_arn.clone(),
            input.next_token.as_deref(),
            input.max_results,
            100,
        )?;
        Ok(t::DescribeReplicationConfigurationsResponse { replications: Some(items), next_token: next })
    }

    pub(crate) async fn delete_replication_configuration(
        &self,
        ctx: &RequestContext,
        input: t::DeleteReplicationConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.source_file_system_id)?;
        self.authorize_fs(ctx, "DeleteReplicationConfiguration", &fs, ConditionContext::new())?;
        let mut st = self.lock();
        let Some(config) = st.replication_of(fs.id()).cloned() else {
            return Err(not_found(fs.id()));
        };
        st.replications.remove(&config.source_file_system_arn);
        // The destination becomes an ordinary, writable file system again.
        for d in &config.destinations {
            if let Some(f) = st
                .regions
                .get_mut(&State::key(&account, &d.region))
                .and_then(|r| r.file_systems.get_mut(&d.file_system_id))
            {
                f.description.file_system_protection = Some(t::FileSystemProtectionDescription {
                    replication_overwrite_protection: Some("ENABLED".into()),
                });
            }
        }
        Ok(())
    }
}
