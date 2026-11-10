//! Multi-Region secrets. A replica is a read-only copy of its primary in
//! another Region, with every version sealed again under a KMS key of that
//! Region; changes to the primary are carried over as they happen.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names;
use crate::ops::{check_live, check_primary};
use crate::seal::Plain;
use crate::state::{Replica, Secret, Version, FAILED, IN_PROGRESS, IN_SYNC};
use crate::SecretsManager;

impl SecretsManager {
    /// `PrimaryRegion` as reported: set for replicas and replicated
    /// primaries.
    pub(crate) fn primary_region_of(&self, s: &Secret) -> Option<String> {
        match &s.primary_region {
            Some(p) => Some(p.clone()),
            None if !s.replicas.is_empty() => Some(s.region.clone()),
            None => None,
        }
    }

    pub(crate) fn replication_status(&self, s: &Secret) -> Option<Vec<types::ReplicationStatusType>> {
        if s.replicas.is_empty() {
            return None;
        }
        let st = self.lock();
        Some(
            s.replicas
                .iter()
                .map(|r| types::ReplicationStatusType {
                    region: Some(r.region.clone()),
                    kms_key_id: Some(r.kms_key_id.clone().unwrap_or_else(|| "alias/aws/secretsmanager".into())),
                    status: Some(r.status.clone()),
                    status_message: Some(r.status_message.clone()),
                    last_accessed_date: st
                        .secrets
                        .get(&names::arn_in_region(&s.arn, &r.region))
                        .and_then(|x| x.last_accessed),
                })
                .collect(),
        )
    }

    /// Every stored value of a secret, opened as the caller.
    fn open_all(&self, ctx: &RequestContext, s: &Secret) -> Result<Vec<(String, Plain)>, ServiceError> {
        s.versions
            .iter()
            .filter_map(|v| v.value.as_ref().map(|sealed| (v, sealed)))
            .map(|(v, sealed)| Ok((v.id.clone(), self.unseal(ctx, &s.region, &s.arn, &v.id, sealed)?)))
            .collect()
    }

    /// Build the replica of `primary` in `region` from the given values.
    fn build_replica(
        &self,
        ctx: &RequestContext,
        primary: &Secret,
        region: &str,
        kms_key_id: Option<&str>,
        values: &[(String, Plain)],
    ) -> Result<Secret, ServiceError> {
        let arn = names::arn_in_region(&primary.arn, region);
        let mut versions = Vec::new();
        for v in &primary.versions {
            let value = match values.iter().find(|(id, _)| *id == v.id) {
                Some((_, plain)) => Some(self.seal(ctx, region, kms_key_id, &arn, &v.id, plain)?),
                None => None,
            };
            versions.push(Version {
                id: v.id.clone(),
                stages: v.stages.clone(),
                created: v.created,
                last_accessed: None,
                value,
            });
        }
        Ok(Secret {
            arn,
            region: region.to_string(),
            kms_key_id: kms_key_id.map(str::to_string),
            versions,
            last_accessed: None,
            primary_region: Some(primary.region.clone()),
            replicas: Vec::new(),
            deletion_date: None,
            ..primary.clone()
        })
    }

    /// Replicate `arn` to `regions`; `values` are the primary's opened
    /// values. Returns the replication status of every replica.
    pub(crate) fn add_replicas(
        &self,
        ctx: &RequestContext,
        arn: &str,
        regions: &[types::ReplicaRegionType],
        force: bool,
        values: Vec<(String, Plain)>,
    ) -> Result<Vec<types::ReplicationStatusType>, ServiceError> {
        for r in regions {
            let region = r.region.as_deref().unwrap_or_default();
            if region.is_empty() {
                return Err(errors::invalid_parameter("You must specify a Region for each replica."));
            }
        }
        for r in regions {
            let region = r.region.clone().unwrap_or_default();
            let primary = self.lock().secrets.get(arn).cloned().ok_or_else(names::not_found)?;
            if region == primary.region {
                return Err(errors::invalid_parameter(format!(
                    "Invalid replica region: {region} is the primary secret's Region."
                )));
            }
            if primary.replicas.iter().any(|x| x.region == region) {
                continue;
            }
            let replica_arn = names::arn_in_region(arn, &region);
            let clash = {
                let st = self.lock();
                st.secrets
                    .values()
                    .find(|s| s.account == primary.account && s.region == region && s.name == primary.name)
                    .map(|s| s.arn.clone())
            };
            let kms_key_id = r.kms_key_id.clone().filter(|k| !k.is_empty());
            // In progress until replication settles.
            let mut status = Replica {
                region: region.clone(),
                kms_key_id: kms_key_id.clone(),
                status: IN_PROGRESS.into(),
                status_message: "Replication in progress".into(),
                since: Some(ctx.received_at),
            };
            let built = match (&clash, force) {
                (Some(_), false) => Err(format!("Replication failed: Secret name already exists in Region: {region}.")),
                _ => self
                    .build_replica(ctx, &primary, &region, kms_key_id.as_deref(), &values)
                    .map_err(|e| format!("Replication failed: {}", e.message)),
            };
            let mut st = self.lock();
            match built {
                Ok(replica) => {
                    if let Some(old) = clash {
                        st.secrets.remove(&old);
                    }
                    st.secrets.insert(replica_arn, replica);
                }
                Err(message) => {
                    status.status = FAILED.into();
                    status.status_message = message;
                    status.since = None;
                }
            }
            if let Some(p) = st.secrets.get_mut(arn) {
                p.replicas.push(status);
            }
        }
        let primary = {
            let mut st = self.lock();
            // With no settle window, replication finishes in this call.
            st.sweep(ctx.received_at);
            st.secrets.get(arn).cloned().ok_or_else(names::not_found)?
        };
        Ok(self.replication_status(&primary).unwrap_or_default())
    }

    /// Carry the primary's metadata, labels and `new_values` over to its
    /// replicas.
    pub(crate) fn sync_replicas(&self, ctx: &RequestContext, arn: &str, new_values: &[(String, Plain)]) {
        let Some(primary) = self.lock().secrets.get(arn).cloned() else { return };
        for r in primary.replicas.iter().filter(|r| r.status == IN_SYNC || r.status == IN_PROGRESS) {
            let replica_arn = names::arn_in_region(arn, &r.region);
            let Some(replica) = self.lock().secrets.get(&replica_arn).cloned() else { continue };
            let mut sealed = Vec::new();
            let mut failure = None;
            for (id, plain) in new_values {
                if replica.version(id).is_some_and(|v| v.value.is_some()) {
                    continue;
                }
                match self.seal(ctx, &r.region, r.kms_key_id.as_deref(), &replica_arn, id, plain) {
                    Ok(s) => sealed.push((id.clone(), s)),
                    Err(e) => failure = Some(format!("Replication failed: {}", e.message)),
                }
            }
            let mut st = self.lock();
            if let Some(message) = failure {
                if let Some(p) = st.secrets.get_mut(arn) {
                    if let Some(x) = p.replicas.iter_mut().find(|x| x.region == r.region) {
                        x.status = FAILED.into();
                        x.status_message = message;
                        x.since = None;
                    }
                }
                continue;
            }
            let Some(rep) = st.secrets.get_mut(&replica_arn) else { continue };
            rep.description = primary.description.clone();
            rep.tags = primary.tags.clone();
            rep.policy = primary.policy.clone();
            rep.rotation = primary.rotation.clone();
            rep.secret_type = primary.secret_type.clone();
            rep.last_changed = primary.last_changed;
            let mut versions = Vec::new();
            for v in &primary.versions {
                let mut copy = rep.version(&v.id).cloned().unwrap_or_else(|| Version {
                    id: v.id.clone(),
                    stages: Vec::new(),
                    created: v.created,
                    last_accessed: None,
                    value: None,
                });
                if let Some((_, s)) = sealed.iter().find(|(id, _)| *id == v.id) {
                    copy.value = Some(s.clone());
                }
                copy.stages = v.stages.clone();
                versions.push(copy);
            }
            rep.versions = versions;
        }
    }

    pub(crate) fn replicate_secret_to_regions(
        &self,
        ctx: &RequestContext,
        input: types::ReplicateSecretToRegionsRequest,
    ) -> Result<types::ReplicateSecretToRegionsResponse, ServiceError> {
        let mut c = ConditionContext::new();
        c.insert(
            "secretsmanager:AddReplicaRegions".into(),
            input.add_replica_regions.iter().filter_map(|r| r.region.clone()).collect(),
        );
        c.insert(
            "secretsmanager:ForceOverwriteReplicaSecret".into(),
            vec![input.force_overwrite_replica_secret.to_string()],
        );
        let s = self.find(ctx, &input.secret_id, "secretsmanager:ReplicateSecretToRegions", c)?;
        check_live(&s)?;
        check_primary(&s)?;
        let values = self.open_all(ctx, &s)?;
        let status =
            self.add_replicas(ctx, &s.arn, &input.add_replica_regions, input.force_overwrite_replica_secret, values)?;
        Ok(types::ReplicateSecretToRegionsResponse { arn: Some(s.arn), replication_status: Some(status) })
    }

    pub(crate) fn remove_regions_from_replication(
        &self,
        ctx: &RequestContext,
        input: types::RemoveRegionsFromReplicationRequest,
    ) -> Result<types::RemoveRegionsFromReplicationResponse, ServiceError> {
        let s =
            self.find(ctx, &input.secret_id, "secretsmanager:RemoveRegionsFromReplication", ConditionContext::new())?;
        check_primary(&s)?;
        for region in &input.remove_replica_regions {
            if !s.replicas.iter().any(|r| &r.region == region) {
                return Err(errors::invalid_parameter(format!(
                    "Invalid replica region: the secret isn't replicated to {region}."
                )));
            }
        }
        {
            let mut st = self.lock();
            for region in &input.remove_replica_regions {
                st.secrets.remove(&names::arn_in_region(&s.arn, region));
            }
            if let Some(p) = st.secrets.get_mut(&s.arn) {
                p.replicas.retain(|r| !input.remove_replica_regions.contains(&r.region));
            }
        }
        let primary = self.lock().secrets.get(&s.arn).cloned().ok_or_else(names::not_found)?;
        Ok(types::RemoveRegionsFromReplicationResponse {
            arn: Some(s.arn),
            replication_status: Some(self.replication_status(&primary).unwrap_or_default()),
        })
    }

    pub(crate) fn stop_replication_to_replica(
        &self,
        ctx: &RequestContext,
        input: types::StopReplicationToReplicaRequest,
    ) -> Result<types::StopReplicationToReplicaResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:StopReplicationToReplica", ConditionContext::new())?;
        let Some(primary_region) = s.primary_region.clone() else {
            return Err(errors::invalid_request(
                "StopReplicationToReplica can only be called on a replica secret, from the replica's Region.",
            ));
        };
        let mut st = self.lock();
        if let Some(r) = st.secrets.get_mut(&s.arn) {
            r.primary_region = None;
            r.last_changed = ctx.received_at;
        }
        if let Some(p) = st.secrets.get_mut(&names::arn_in_region(&s.arn, &primary_region)) {
            p.replicas.retain(|r| r.region != s.region);
        }
        Ok(types::StopReplicationToReplicaResponse { arn: Some(s.arn) })
    }
}
