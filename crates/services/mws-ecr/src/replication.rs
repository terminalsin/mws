//! Replication: copying pushed images to the Regions and accounts a
//! registry's replication configuration names, and backfills of images
//! pushed before.

use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::{errors, types};
use crate::names::{dt, invalid_parameter, now_ms, repository_arn};
use crate::repos::{build_repo, template_for, NewRepo};
use crate::state::{Backfill, Registry, Repo, State};
use crate::Ecr;

/// Whether a rule's repository filters select `name`.
pub(crate) fn rule_selects(rule: &types::ReplicationRule, name: &str) -> bool {
    rule.repository_filters.as_ref().is_none_or(|f| f.is_empty() || f.iter().any(|f| name.starts_with(&f.filter)))
}

/// The destinations configured for a repository, without duplicates.
fn destinations(reg: &Registry, name: &str) -> Vec<types::ReplicationDestination> {
    let mut out: Vec<types::ReplicationDestination> = Vec::new();
    for rule in reg.replication.iter().flat_map(|c| c.rules.iter()) {
        if !rule_selects(rule, name) {
            continue;
        }
        for d in &rule.destinations {
            if !out.contains(d) && !(d.region == reg.region && d.registry_id == reg.account) {
                out.push(d.clone());
            }
        }
    }
    out
}

/// Whether a destination registry's policy lets the source account do
/// `action` on `resource`.
fn registry_allows(dest: &Registry, partition: &str, source_account: &str, action: &str, resource: &str) -> bool {
    let Some(policy) = dest.policy.as_deref().and_then(|p| Policy::parse(p, PolicyKind::Resource).ok()) else {
        return false;
    };
    let principal = PrincipalInfo {
        account_id: source_account.to_string(),
        arns: vec![format!("arn:{partition}:iam::{source_account}:root")],
        ..Default::default()
    };
    let context = ConditionContext::new();
    let e = policy.evaluate(&Request { action, resource, principal: &principal, context: &context });
    !e.denied() && e.allowed()
}

/// Copy an image (and, for an index, the images it lists) with its blobs
/// and tags.
fn copy_image(src: &Repo, dst: &mut Repo, digest: &str, now: i64) -> Result<(), String> {
    let image = src.content.images.get(digest).ok_or("image not found")?;
    for child in &image.children {
        copy_image(src, dst, child, now)?;
    }
    for b in &image.blobs {
        if let Some(blob) = src.content.blobs.get(b) {
            dst.content.put_blob(b, blob.data.clone(), now);
        }
    }
    let tags = src.content.tags_of(digest);
    let mut puts: Vec<Option<String>> = tags.into_iter().map(Some).collect();
    if puts.is_empty() {
        puts.push(None);
    }
    let locked = dst.clone();
    for tag in puts {
        let put = mws_oci::PutManifest {
            manifest: image.manifest.clone(),
            media_type: Some(image.media_type.clone()),
            tag,
            digest: Some(digest.to_string()),
        };
        dst.content.put_manifest(&put, now, |t| locked.tag_locked(t)).map_err(|e| format!("{e:?}"))?;
    }
    dst.meta.entry(digest.to_string()).or_default();
    Ok(())
}

/// Replicate one image to one destination.
#[allow(clippy::too_many_arguments)]
fn replicate_to(
    st: &mut State,
    partition: &str,
    account: &str,
    region: &str,
    name: &str,
    digest: &str,
    dest: &types::ReplicationDestination,
    now: i64,
) -> Result<(), &'static str> {
    let src = st.registry(account, region).and_then(|r| r.repositories.get(name)).cloned().ok_or("SOURCE_NOT_FOUND")?;
    let dest_reg = st.registry_mut(&dest.registry_id, &dest.region);
    let arn = repository_arn(partition, &dest.region, &dest.registry_id, name);
    let cross_account = dest.registry_id != account;
    if cross_account && !registry_allows(dest_reg, partition, account, "ecr:ReplicateImage", &arn) {
        return Err("REPLICATION_ACCESS_DENIED");
    }
    if !dest_reg.repositories.contains_key(name) {
        if cross_account && !registry_allows(dest_reg, partition, account, "ecr:CreateRepository", &arn) {
            return Err("REPLICATION_ACCESS_DENIED");
        }
        let settings =
            template_for(dest_reg, name, "REPLICATION").map(NewRepo::from_template).unwrap_or_else(|| NewRepo {
                encryption: src.encryption.clone().filter(|e| e.encryption_type == "AES256"),
                ..Default::default()
            });
        let repo = build_repo(partition, dest_reg, name, now, settings);
        dest_reg.repositories.insert(name.to_string(), repo);
    }
    let dst = dest_reg.repositories.get_mut(name).expect("created above");
    copy_image(&src, dst, digest, now).map_err(|_| "IMAGE_REPLICATION_FAILED")
}

/// Replicate a freshly pushed image wherever the source registry's
/// configuration says. Returns the status per destination.
pub(crate) fn replicate(
    st: &mut State,
    partition: &str,
    account: &str,
    region: &str,
    name: &str,
    digest: &str,
    now: i64,
) -> Vec<types::ImageReplicationStatus> {
    let Some(reg) = st.registry(account, region) else { return Vec::new() };
    let dests = destinations(reg, name);
    dests
        .iter()
        .map(|d| {
            let result = replicate_to(st, partition, account, region, name, digest, d, now);
            types::ImageReplicationStatus {
                region: Some(d.region.clone()),
                registry_id: Some(d.registry_id.clone()),
                status: Some(if result.is_ok() { "COMPLETE" } else { "FAILED" }.into()),
                failure_code: result.err().map(str::to_string),
            }
        })
        .collect()
}

fn backfill_summary(b: &Backfill) -> types::ReplicationBackfillSummary {
    let completed = b.results.iter().filter(|r| r.status == "COMPLETE").count() as i32;
    let failed = b.results.iter().filter(|r| r.status == "FAILED").count() as i32;
    let mut codes: Vec<String> = b.results.iter().filter_map(|r| r.failure_code.clone()).collect();
    codes.sort();
    codes.dedup();
    types::ReplicationBackfillSummary {
        replication_backfill_id: b.id.clone(),
        destination: b.destination.clone(),
        status: b.status.clone(),
        failure_code: b.failure_code.clone(),
        progress: Some(types::ReplicationBackfillProgress {
            total_replication_count: b.results.len() as i32,
            completed_replication_count: completed,
            failed_replication_count: failed,
            failure_codes: codes,
        }),
        started_at: dt(b.started_at),
        ended_at: b.ended_at.map(dt),
    }
}

fn backfill_not_found(id: &str) -> ServiceError {
    errors::replication_backfill_not_found(format!("The replication backfill with id '{id}' does not exist."))
}

impl Ecr {
    fn own_registry(ctx: &RequestContext, registry_id: Option<&str>) -> Result<String, ServiceError> {
        let account = Ecr::target(ctx, registry_id);
        if account != ctx.caller.account_id {
            return Err(invalid_parameter(format!(
                "Invalid parameter at 'registryId' failed to satisfy constraint: 'must be the caller's account id {}'",
                ctx.caller.account_id
            )));
        }
        Ok(account)
    }

    pub(crate) fn start_replication_backfill(
        &self,
        ctx: &RequestContext,
        input: types::StartReplicationBackfillRequest,
    ) -> Result<types::StartReplicationBackfillResponse, ServiceError> {
        let account = Self::own_registry(ctx, input.registry_id.as_deref())?;
        crate::names::authorize_registry(
            ctx,
            "ecr:StartReplicationBackfill",
            &crate::names::registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let now = now_ms(ctx);
        let dest = input.destination;
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        let configured = reg.replication.iter().flat_map(|c| c.rules.iter()).any(|r| r.destinations.contains(&dest));
        if !configured {
            return Err(errors::validation(
                "The destination must be configured in the registry's replication configuration.",
            ));
        }
        if reg
            .backfills
            .iter()
            .any(|b| b.destination.region == dest.region && matches!(b.status.as_str(), "PREPARING" | "IN_PROGRESS"))
        {
            return Err(errors::replication_backfill_in_progress(format!(
                "A replication backfill is already in progress for the destination Region '{}'.",
                dest.region
            )));
        }
        type Images = Vec<(String, Vec<String>)>;
        let repos: Vec<(String, Images)> = reg
            .repositories
            .values()
            .filter(|r| {
                reg.replication
                    .iter()
                    .flat_map(|c| c.rules.iter())
                    .any(|rule| rule.destinations.contains(&dest) && rule_selects(rule, &r.name))
            })
            .map(|r| {
                let images = r
                    .content
                    .images
                    .keys()
                    .filter(|d| !r.content.referenced_by_index(d))
                    .map(|d| (d.clone(), r.content.tags_of(d)))
                    .collect();
                (r.name.clone(), images)
            })
            .collect();
        let mut results = Vec::new();
        for (name, images) in repos {
            for (d, tags) in images {
                let outcome = replicate_to(&mut st, &ctx.partition, &account, &ctx.region, &name, &d, &dest, now);
                let mut ids: Vec<Option<String>> = tags.into_iter().map(Some).collect();
                if ids.is_empty() {
                    ids.push(None);
                }
                for tag in ids {
                    results.push(types::ReplicationBackfillResult {
                        repository_name: name.clone(),
                        image_id: types::ImageIdentifier { image_digest: Some(d.clone()), image_tag: tag },
                        status: if outcome.is_ok() { "COMPLETE" } else { "FAILED" }.into(),
                        failure_code: outcome.err().map(str::to_string),
                        sub_image_failure_codes: None,
                    });
                }
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let reg = st.registry_mut(&account, &ctx.region);
        if reg.backfills.len() >= 10 {
            reg.backfills.remove(0);
        }
        reg.backfills.push(Backfill {
            id: id.clone(),
            destination: dest.clone(),
            status: "COMPLETE".into(),
            started_at: now,
            ended_at: Some(now),
            failure_code: None,
            results,
        });
        Ok(types::StartReplicationBackfillResponse {
            replication_backfill_id: Some(id),
            registry_id: Some(account),
            destination: Some(dest),
            status: Some("PREPARING".into()),
            started_at: Some(dt(now)),
        })
    }

    pub(crate) fn stop_replication_backfill(
        &self,
        ctx: &RequestContext,
        input: types::StopReplicationBackfillRequest,
    ) -> Result<types::StopReplicationBackfillResponse, ServiceError> {
        let account = Self::own_registry(ctx, input.registry_id.as_deref())?;
        crate::names::authorize_registry(
            ctx,
            "ecr:StopReplicationBackfill",
            &crate::names::registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        let b = reg
            .backfills
            .iter_mut()
            .find(|b| b.id == input.replication_backfill_id)
            .ok_or_else(|| backfill_not_found(&input.replication_backfill_id))?;
        if !matches!(b.status.as_str(), "PREPARING" | "IN_PROGRESS") {
            return Err(errors::replication_backfill_invalid_status(format!(
                "The replication backfill cannot be stopped because its status is {}.",
                b.status
            )));
        }
        b.status = "STOPPED".into();
        b.ended_at = Some(now);
        Ok(types::StopReplicationBackfillResponse {
            registry_id: Some(account),
            replication_backfill_id: Some(b.id.clone()),
            destination: Some(b.destination.clone()),
            status: Some("STOPPING".into()),
            started_at: Some(dt(b.started_at)),
        })
    }

    pub(crate) fn list_replication_backfills(
        &self,
        ctx: &RequestContext,
        input: types::ListReplicationBackfillsRequest,
    ) -> Result<types::ListReplicationBackfillsResponse, ServiceError> {
        let account = Self::own_registry(ctx, input.registry_id.as_deref())?;
        crate::names::authorize_registry(
            ctx,
            "ecr:ListReplicationBackfills",
            &crate::names::registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let st = self.lock();
        let summaries: Vec<_> = st
            .registry(&account, &ctx.region)
            .map(|r| r.backfills.iter().rev().map(backfill_summary).collect())
            .unwrap_or_default();
        let (backfills, next_token) =
            crate::names::page(&summaries, input.next_token.as_deref(), input.max_results, 50)?;
        Ok(types::ListReplicationBackfillsResponse {
            registry_id: Some(account),
            backfills: Some(backfills),
            next_token,
        })
    }

    pub(crate) fn describe_replication_backfill_results(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReplicationBackfillResultsRequest,
    ) -> Result<types::DescribeReplicationBackfillResultsResponse, ServiceError> {
        let account = Self::own_registry(ctx, input.registry_id.as_deref())?;
        crate::names::authorize_registry(
            ctx,
            "ecr:DescribeReplicationBackfillResults",
            &crate::names::registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let st = self.lock();
        let b = st
            .registry(&account, &ctx.region)
            .and_then(|r| r.backfills.iter().find(|b| b.id == input.replication_backfill_id))
            .ok_or_else(|| backfill_not_found(&input.replication_backfill_id))?;
        let summary = backfill_summary(b);
        let terminal = matches!(b.status.as_str(), "COMPLETE" | "FAILED" | "STOPPED");
        let results: Vec<_> = b
            .results
            .iter()
            .filter(|r| input.result_status_filter.as_ref().is_none_or(|f| *f == r.status))
            .cloned()
            .collect();
        let (results, next_token) = crate::names::page(&results, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::DescribeReplicationBackfillResultsResponse {
            registry_id: Some(account),
            replication_backfill_id: Some(b.id.clone()),
            destination: Some(b.destination.clone()),
            status: Some(b.status.clone()),
            failure_code: b.failure_code.clone(),
            progress: summary.progress,
            results: terminal.then_some(results),
            started_at: Some(dt(b.started_at)),
            ended_at: b.ended_at.map(dt),
            next_token,
        })
    }
}
