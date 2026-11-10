//! Secrets, their versions and staging labels, listing and tags.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, day, marked_for_deletion, not_found, replica_read_only};
use crate::seal::Plain;
use crate::state::{Secret, Version, CURRENT};
use crate::SecretsManager;

const NAME_CHARS: &str = "/_+=.@-";
const MAX_TAGS: usize = 50;

fn cond(pairs: &[(&str, Option<String>)]) -> ConditionContext {
    pairs.iter().filter_map(|(k, v)| v.clone().map(|v| (k.to_string(), vec![v]))).collect()
}

pub fn check_live(s: &Secret) -> Result<(), ServiceError> {
    if s.deletion_date.is_some() {
        return Err(marked_for_deletion());
    }
    Ok(())
}

/// Secrets another service owns (`OwningService`) change only through that
/// service (its public API in `managed.rs`).
pub fn check_not_managed(s: &Secret, verb: &str) -> Result<(), ServiceError> {
    match &s.owning_service {
        Some(owner) => {
            Err(errors::invalid_request(format!("You can't {verb} secret {} because it's managed by {owner}.", s.arn)))
        }
        None => Ok(()),
    }
}

pub fn check_primary(s: &Secret) -> Result<(), ServiceError> {
    if s.primary_region.is_some() {
        return Err(replica_read_only());
    }
    Ok(())
}

fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    if tags.len() > MAX_TAGS {
        return Err(errors::invalid_parameter("Number of tags exceeds the limit of 50."));
    }
    for t in tags {
        let key = t.key.as_deref().unwrap_or_default();
        if key.is_empty() || t.value.is_none() {
            return Err(errors::invalid_parameter("A tag must have both a key and a value."));
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_parameter("Invalid tag key. The 'aws:' prefix is reserved for AWS use."));
        }
    }
    Ok(())
}

fn merge_tags(existing: &mut Vec<types::Tag>, new: &[types::Tag]) {
    for t in new {
        match existing.iter_mut().find(|e| e.key == t.key) {
            Some(e) => e.value = t.value.clone(),
            None => existing.push(t.clone()),
        }
    }
}

pub const MAX_VERSIONS: usize = 100;
pub const MAX_LABELS: usize = 20;

/// The versions-per-secret and staging-labels-per-secret quotas, for
/// adding version `new_version` (if not there yet) and attaching `stages`.
/// Unlabelled versions more than a day old don't count: Secrets Manager
/// removes them to make room.
pub fn check_quotas(
    s: &Secret,
    new_version: Option<&str>,
    stages: &[String],
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    let adding = new_version.is_some_and(|id| s.version(id).is_none());
    let removable =
        s.versions.iter().filter(|v| v.stages.is_empty() && now - v.created > chrono::Duration::hours(24)).count();
    if adding && s.versions.len() + 1 - removable > MAX_VERSIONS {
        return Err(errors::limit_exceeded(
            "You have exceeded the maximum number of versions (100) allowed for this secret. Secrets Manager removes versions without staging labels once they are more than 24 hours old.",
        ));
    }
    let mut labels: Vec<&str> = s.versions.iter().flat_map(|v| v.stages.iter().map(String::as_str)).collect();
    labels.extend(stages.iter().map(String::as_str));
    if stages.iter().any(|x| x == CURRENT) && s.staged(CURRENT).is_some() {
        // Moving AWSCURRENT leaves AWSPREVIOUS behind.
        labels.push(crate::state::PREVIOUS);
    }
    labels.sort_unstable();
    labels.dedup();
    let count = labels.len();
    if count > MAX_LABELS {
        return Err(errors::limit_exceeded(
            "You have exceeded the maximum number of staging labels (20) attached across all versions of this secret.",
        ));
    }
    Ok(())
}

/// The words of a search string or attribute, lowercased, as the Secrets
/// Manager search splits them: at anything but letters and digits, where
/// lowercase turns to uppercase, and between letters and digits
/// (`credsDatabase#892` is `creds`, `database`, `892`).
pub fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev = None;
            continue;
        }
        if let Some(p) = prev {
            let split = (p.is_lowercase() && c.is_uppercase()) || (p.is_alphabetic() != c.is_alphabetic());
            if split && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.extend(c.to_lowercase());
        prev = Some(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The page of `items` a `NextToken` selects.
pub fn paginate<T>(
    items: Vec<T>,
    next_token: Option<&str>,
    max: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token {
        None => 0,
        Some(t) => base64::engine::general_purpose::STANDARD
            .decode(t)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse::<usize>().ok()))
            .filter(|n| *n <= items.len())
            .ok_or_else(|| errors::invalid_next_token("The NextToken value is invalid."))?,
    };
    let end = (start + max).min(items.len());
    let next = (end < items.len()).then(|| base64::engine::general_purpose::STANDARD.encode(format!("mws:{end}")));
    Ok((items.into_iter().skip(start).take(end - start).collect(), next))
}

impl SecretsManager {
    /// The `KmsKeyId` to report for a key reference: an alias name becomes
    /// its alias ARN, a key id its key ARN.
    fn reported_key(&self, ctx: &RequestContext, kms_key_id: Option<&str>) -> Option<String> {
        let k = kms_key_id.filter(|k| !k.is_empty())?;
        if k.starts_with("arn:") {
            return Some(k.to_string());
        }
        let account = names::account_of(ctx);
        Some(if k.starts_with("alias/") {
            format!("arn:{}:kms:{}:{account}:{k}", ctx.partition, ctx.region)
        } else {
            format!("arn:{}:kms:{}:{account}:key/{k}", ctx.partition, ctx.region)
        })
    }

    pub(crate) fn create_secret(
        &self,
        ctx: &RequestContext,
        input: types::CreateSecretRequest,
    ) -> Result<types::CreateSecretResponse, ServiceError> {
        let name = input.name.clone();
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || NAME_CHARS.contains(c)) {
            return Err(errors::invalid_parameter(
                "Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!",
            ));
        }
        let value = Plain::from_input(input.secret_string.clone(), input.secret_binary.clone())?;
        let tags = input.tags.clone().unwrap_or_default();
        validate_tags(&tags)?;
        let account = names::account_of(ctx);
        let arn = names::new_arn(&ctx.partition, &ctx.region, &account, &name);
        let mut c = cond(&[
            ("secretsmanager:Name", Some(name.clone())),
            ("secretsmanager:Description", input.description.clone()),
            ("secretsmanager:KmsKeyArn", input.kms_key_id.clone()),
        ]);
        c.extend(names::request_tag_context(&tags));
        let regions: Vec<String> =
            input.add_replica_regions.iter().flatten().filter_map(|r| r.region.clone()).collect();
        if !regions.is_empty() {
            c.insert("secretsmanager:AddReplicaRegions".into(), regions.clone());
            c.insert(
                "secretsmanager:ForceOverwriteReplicaSecret".into(),
                vec![input.force_overwrite_replica_secret.to_string()],
            );
        }
        ctx.authorize("secretsmanager:CreateSecret", &arn, c.clone())?;
        if !tags.is_empty() {
            ctx.authorize("secretsmanager:TagResource", &arn, c.clone())?;
        }
        if !regions.is_empty() {
            ctx.authorize("secretsmanager:ReplicateSecretToRegions", &arn, c)?;
        }
        if let Some(done) = self.repeated_create(ctx, &account, &name, input.client_request_token.as_deref(), &value)? {
            return Ok(done);
        }
        self.check_name_free(ctx, &account, &ctx.region, &name)?;
        let now = ctx.received_at;
        let version_id = value.as_ref().map(|_| input.client_request_token.clone().unwrap_or_else(names::new_token));
        let kms_key_id = self.reported_key(ctx, input.kms_key_id.as_deref());
        let mut versions = Vec::new();
        if let (Some(v), Some(id)) = (&value, &version_id) {
            let sealed = self.seal(ctx, &ctx.region, kms_key_id.as_deref(), &arn, id, v)?;
            versions.push(Version {
                id: id.clone(),
                stages: vec![CURRENT.into()],
                created: now,
                last_accessed: None,
                value: Some(sealed),
            });
        }
        let secret = Secret {
            arn: arn.clone(),
            name: name.clone(),
            account: account.clone(),
            region: ctx.region.clone(),
            description: input.description.clone(),
            kms_key_id,
            secret_type: input.r#type.clone(),
            created: now,
            last_changed: now,
            tags,
            versions,
            ..Default::default()
        };
        {
            let mut st = self.lock();
            if st.secrets.values().any(|s| s.account == account && s.region == ctx.region && s.name == name) {
                return Err(errors::resource_exists(format!(
                    "The operation failed because the secret {name} already exists."
                )));
            }
            st.secrets.insert(arn.clone(), secret);
        }
        let replication_status = match input.add_replica_regions {
            Some(r) if !r.is_empty() => {
                let plain = match (&value, &version_id) {
                    (Some(v), Some(id)) => vec![(id.clone(), v.clone())],
                    _ => Vec::new(),
                };
                Some(self.add_replicas(ctx, &arn, &r, input.force_overwrite_replica_secret, plain)?)
            }
            _ => None,
        };
        Ok(types::CreateSecretResponse { arn: Some(arn), name: Some(name), version_id, replication_status })
    }

    /// A retried `CreateSecret`: the secret exists with a version for the
    /// same `ClientRequestToken` holding the same value, so the request is
    /// ignored and answered as before.
    fn repeated_create(
        &self,
        ctx: &RequestContext,
        account: &str,
        name: &str,
        token: Option<&str>,
        value: &Option<Plain>,
    ) -> Result<Option<types::CreateSecretResponse>, ServiceError> {
        let (Some(token), Some(value)) = (token, value) else { return Ok(None) };
        let existing = {
            let st = self.lock();
            st.secrets
                .values()
                .find(|s| s.account == account && s.region == ctx.region && s.name == name && s.deletion_date.is_none())
                .cloned()
        };
        let Some(s) = existing else { return Ok(None) };
        let Some(sealed) = s.version(token).and_then(|v| v.value.as_ref()) else { return Ok(None) };
        match self.unseal(ctx, &s.region, &s.arn, token, sealed) {
            Ok(p) if &p == value => Ok(Some(types::CreateSecretResponse {
                arn: Some(s.arn.clone()),
                name: Some(s.name.clone()),
                version_id: Some(token.to_string()),
                replication_status: self.replication_status(&s),
            })),
            Ok(_) => {
                Err(errors::resource_exists("You can't modify an existing version, you can only create a new version."))
            }
            Err(_) => Ok(None),
        }
    }

    /// A name can be taken again only once its secret is gone.
    pub(crate) fn check_name_free(
        &self,
        _ctx: &RequestContext,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), ServiceError> {
        let st = self.lock();
        if let Some(s) = st.secrets.values().find(|s| s.account == account && s.region == region && s.name == name) {
            if s.deletion_date.is_some() {
                return Err(errors::invalid_request(
                    "You can't create this secret because a secret with this name is already scheduled for deletion.",
                ));
            }
            return Err(errors::resource_exists(format!(
                "The operation failed because the secret {name} already exists."
            )));
        }
        Ok(())
    }

    /// Add a version with `value` to a primary secret, attach `stages`, and
    /// bring replicas along. `strict` refuses any existing version id
    /// (`UpdateSecret`); otherwise the same value is accepted again.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_version(
        &self,
        ctx: &RequestContext,
        secret: &Secret,
        token: &str,
        value: &Plain,
        stages: &[String],
        strict: bool,
    ) -> Result<Vec<String>, ServiceError> {
        if let Some(existing) = secret.version(token) {
            if let Some(sealed) = &existing.value {
                if strict {
                    return Err(errors::resource_exists(
                        "You can't modify an existing version, you can only create a new version.",
                    ));
                }
                let same =
                    self.unseal(ctx, &secret.region, &secret.arn, token, sealed).map(|p| &p == value).unwrap_or(false);
                if same {
                    return Ok(existing.stages.clone());
                }
                return Err(errors::resource_exists(
                    "You can't modify an existing version, you can only create a new version.",
                ));
            }
        }
        check_quotas(secret, Some(token), stages, ctx.received_at)?;
        let sealed = self.seal(ctx, &secret.region, secret.kms_key_id.as_deref(), &secret.arn, token, value)?;
        let now = ctx.received_at;
        let stages_out = self.update(&secret.arn, |s| {
            match s.version_mut(token) {
                Some(v) => v.value = Some(sealed),
                None => s.versions.push(Version {
                    id: token.to_string(),
                    stages: Vec::new(),
                    created: now,
                    last_accessed: None,
                    value: Some(sealed),
                }),
            }
            for stage in stages {
                s.attach(stage, token);
            }
            s.last_changed = now;
            s.prune(now);
            Ok(s.version(token).map(|v| v.stages.clone()).unwrap_or_default())
        })?;
        self.sync_replicas(ctx, &secret.arn, &[(token.to_string(), value.clone())]);
        Ok(stages_out)
    }

    pub(crate) fn put_secret_value(
        &self,
        ctx: &RequestContext,
        input: types::PutSecretValueRequest,
    ) -> Result<types::PutSecretValueResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:PutSecretValue", ConditionContext::new())?;
        check_live(&s)?;
        check_primary(&s)?;
        check_not_managed(&s, "modify")?;
        let value = Plain::from_input(input.secret_string, input.secret_binary)?
            .ok_or_else(|| errors::invalid_request("You must provide either SecretString or SecretBinary."))?;
        let token = input.client_request_token.unwrap_or_else(names::new_token);
        let mut stages = input.version_stages.unwrap_or_else(|| vec![CURRENT.into()]);
        // The first version with a value becomes AWSCURRENT whatever labels
        // the request asked for.
        if s.versions.iter().all(|v| v.value.is_none()) && !stages.iter().any(|x| x == CURRENT) {
            stages.push(CURRENT.into());
        }
        let stages = self.add_version(ctx, &s, &token, &value, &stages, false)?;
        Ok(types::PutSecretValueResponse {
            arn: Some(s.arn),
            name: Some(s.name),
            version_id: Some(token),
            version_stages: Some(stages),
        })
    }

    /// The version a `VersionId`/`VersionStage` pair selects, with its value.
    pub(crate) fn read_value(
        &self,
        ctx: &RequestContext,
        s: &Secret,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<(Version, Plain), ServiceError> {
        check_live(s)?;
        let version = match (version_id, version_stage) {
            (Some(id), stage) => {
                let v = s.version(id).ok_or_else(|| {
                    errors::resource_not_found(format!(
                        "Secrets Manager can't find the specified secret value for VersionId: {id}"
                    ))
                })?;
                if let Some(stage) = stage {
                    if !v.stages.iter().any(|x| x == stage) {
                        return Err(errors::invalid_request(
                            "You provided a VersionStage that is not associated to the provided VersionId.",
                        ));
                    }
                }
                v
            }
            (None, stage) => {
                let stage = stage.unwrap_or(CURRENT);
                s.staged(stage).ok_or_else(|| {
                    errors::resource_not_found(format!(
                        "Secrets Manager can't find the specified secret value for staging label: {stage}"
                    ))
                })?
            }
        };
        let missing = || match version_stage {
            Some(stage) if version_id.is_none() => errors::resource_not_found(format!(
                "Secrets Manager can't find the specified secret value for staging label: {stage}"
            )),
            None if version_id.is_none() => errors::resource_not_found(
                "Secrets Manager can't find the specified secret value for staging label: AWSCURRENT",
            ),
            _ => errors::resource_not_found(format!(
                "Secrets Manager can't find the specified secret value for VersionId: {}",
                version.id
            )),
        };
        let sealed = version.value.as_ref().ok_or_else(missing)?;
        let plain = self.unseal(ctx, &s.region, &s.arn, &version.id, sealed)?;
        let today = day(ctx.received_at);
        let id = version.id.clone();
        let _ = self.update(&s.arn, |st| {
            st.last_accessed = Some(today);
            if let Some(v) = st.version_mut(&id) {
                v.last_accessed = Some(today);
            }
            Ok(())
        });
        Ok((version.clone(), plain))
    }

    pub(crate) fn get_secret_value(
        &self,
        ctx: &RequestContext,
        input: types::GetSecretValueRequest,
    ) -> Result<types::GetSecretValueResponse, ServiceError> {
        let c = cond(&[
            ("secretsmanager:VersionId", input.version_id.clone()),
            ("secretsmanager:VersionStage", input.version_stage.clone()),
        ]);
        let s = self.find(ctx, &input.secret_id, "secretsmanager:GetSecretValue", c)?;
        let (v, plain) = self.read_value(ctx, &s, input.version_id.as_deref(), input.version_stage.as_deref())?;
        let (secret_string, secret_binary) = plain.into_parts();
        Ok(types::GetSecretValueResponse {
            arn: Some(s.arn),
            name: Some(s.name),
            version_id: Some(v.id),
            secret_binary,
            secret_string,
            version_stages: Some(v.stages),
            created_date: Some(v.created),
        })
    }

    pub(crate) fn batch_get_secret_value(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetSecretValueRequest,
    ) -> Result<types::BatchGetSecretValueResponse, ServiceError> {
        ctx.authorize("secretsmanager:BatchGetSecretValue", "*", ConditionContext::new())?;
        let (ids, next_token) = match (&input.secret_id_list, &input.filters) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(errors::invalid_parameter(
                    "Either 'SecretIdList' or 'Filters' must be provided, but not both.",
                ))
            }
            (Some(ids), None) => {
                if input.max_results.is_some() {
                    return Err(errors::invalid_parameter(
                        "'MaxResults' is only supported when 'Filters' is provided.",
                    ));
                }
                if ids.len() > 20 {
                    return Err(errors::invalid_parameter("SecretIdList can contain at most 20 secrets."));
                }
                (ids.clone(), None)
            }
            (None, Some(filters)) => {
                ctx.authorize("secretsmanager:ListSecrets", "*", ConditionContext::new())?;
                let matching = self.matching(ctx, filters, false)?;
                let arns: Vec<String> = matching.into_iter().map(|s| s.arn).collect();
                let max = input.max_results.unwrap_or(20).clamp(1, 20) as usize;
                paginate(arns, input.next_token.as_deref(), max)?
            }
        };
        let mut values = Vec::new();
        let mut errs = Vec::new();
        for id in ids {
            let got = self
                .find(ctx, &id, "secretsmanager:GetSecretValue", ConditionContext::new())
                .and_then(|s| self.read_value(ctx, &s, None, None).map(|r| (s, r)));
            match got {
                Ok((s, (v, plain))) => {
                    let (secret_string, secret_binary) = plain.into_parts();
                    values.push(types::SecretValueEntry {
                        arn: Some(s.arn),
                        name: Some(s.name),
                        version_id: Some(v.id),
                        secret_binary,
                        secret_string,
                        version_stages: Some(v.stages),
                        created_date: Some(v.created),
                    });
                }
                Err(e) => {
                    let code =
                        if e.code == "AccessDenied" { "AccessDeniedException".into() } else { e.code.to_string() };
                    errs.push(types::APIErrorType {
                        secret_id: Some(id),
                        error_code: Some(code),
                        message: Some(e.message),
                    })
                }
            }
        }
        Ok(types::BatchGetSecretValueResponse { secret_values: Some(values), next_token, errors: Some(errs) })
    }

    pub(crate) fn describe(&self, s: &Secret) -> types::DescribeSecretResponse {
        let (rotation_enabled, next_rotation_date) = Self::rotation_fields(s);
        types::DescribeSecretResponse {
            arn: Some(s.arn.clone()),
            name: Some(s.name.clone()),
            r#type: s.secret_type.clone(),
            description: s.description.clone(),
            kms_key_id: s.kms_key_id.clone(),
            rotation_enabled,
            rotation_lambda_arn: s.rotation.lambda_arn.clone(),
            rotation_rules: s.rotation.rules.clone(),
            external_secret_rotation_metadata: s.rotation.external_metadata.clone(),
            external_secret_rotation_role_arn: s.rotation.external_role_arn.clone(),
            last_rotated_date: s.rotation.last_rotated,
            last_changed_date: Some(s.last_changed),
            last_accessed_date: s.last_accessed,
            deleted_date: s.deletion_date,
            next_rotation_date,
            tags: (!s.tags.is_empty()).then(|| s.tags.clone()),
            version_ids_to_stages: Some(s.versions_to_stages()),
            owning_service: s.owning_service.clone(),
            created_date: Some(s.created),
            primary_region: self.primary_region_of(s),
            replication_status: self.replication_status(s),
        }
    }

    /// `RotationEnabled` (absent if rotation was never configured) and
    /// `NextRotationDate` (only while enabled).
    fn rotation_fields(s: &Secret) -> (Option<bool>, Option<DateTime<Utc>>) {
        let configured = s.rotation.enabled || s.rotation.lambda_arn.is_some() || s.rotation.rules.is_some();
        (configured.then_some(s.rotation.enabled), s.rotation.next.filter(|_| s.rotation.enabled))
    }

    pub(crate) fn describe_secret(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSecretRequest,
    ) -> Result<types::DescribeSecretResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:DescribeSecret", ConditionContext::new())?;
        Ok(self.describe(&s))
    }

    pub(crate) fn update_secret(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecretRequest,
    ) -> Result<types::UpdateSecretResponse, ServiceError> {
        let c = cond(&[
            ("secretsmanager:Description", input.description.clone()),
            ("secretsmanager:KmsKeyArn", input.kms_key_id.clone()),
        ]);
        let s = self.find(ctx, &input.secret_id, "secretsmanager:UpdateSecret", c)?;
        check_live(&s)?;
        check_primary(&s)?;
        check_not_managed(&s, "modify")?;
        let value = Plain::from_input(input.secret_string, input.secret_binary)?;
        let new_key = input.kms_key_id.as_deref().map(|k| self.reported_key(ctx, Some(k)));
        let now = ctx.received_at;
        if let Some(key) = &new_key {
            if *key != s.kms_key_id {
                self.reencrypt(ctx, &s, key.as_deref())?;
            }
        }
        self.update(&s.arn, |st| {
            if let Some(d) = &input.description {
                st.description = Some(d.clone());
            }
            if let Some(t) = &input.r#type {
                st.secret_type = Some(t.clone());
            }
            if let Some(key) = &new_key {
                st.kms_key_id = key.clone();
            }
            st.last_changed = now;
            Ok(())
        })?;
        let version_id = match value {
            Some(v) => {
                let token = input.client_request_token.unwrap_or_else(names::new_token);
                let fresh = self.lock().secrets.get(&s.arn).cloned().ok_or_else(not_found)?;
                self.add_version(ctx, &fresh, &token, &v, &[CURRENT.into()], true)?;
                Some(token)
            }
            None => {
                self.sync_replicas(ctx, &s.arn, &[]);
                None
            }
        };
        Ok(types::UpdateSecretResponse { arn: Some(s.arn), name: Some(s.name), version_id })
    }

    /// Re-encrypt the labelled versions under a new key. Like Secrets
    /// Manager, versions the caller cannot re-encrypt keep their old key.
    fn reencrypt(&self, ctx: &RequestContext, s: &Secret, key: Option<&str>) -> Result<(), ServiceError> {
        // The new key must be usable at all.
        let probe = self.seal(ctx, &s.region, key, &s.arn, "probe", &Plain::Binary(vec![0]))?;
        drop(probe);
        let mut resealed = Vec::new();
        for v in &s.versions {
            let labelled = v.stages.iter().any(|x| matches!(x.as_str(), "AWSCURRENT" | "AWSPENDING" | "AWSPREVIOUS"));
            let Some(sealed) = v.value.as_ref().filter(|_| labelled) else { continue };
            let Ok(plain) = self.unseal(ctx, &s.region, &s.arn, &v.id, sealed) else { continue };
            if let Ok(n) = self.seal(ctx, &s.region, key, &s.arn, &v.id, &plain) {
                resealed.push((v.id.clone(), n));
            }
        }
        self.update(&s.arn, |st| {
            for (id, n) in resealed {
                if let Some(v) = st.version_mut(&id) {
                    v.value = Some(n);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn update_secret_version_stage(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecretVersionStageRequest,
    ) -> Result<types::UpdateSecretVersionStageResponse, ServiceError> {
        let c = cond(&[("secretsmanager:VersionStage", Some(input.version_stage.clone()))]);
        let s = self.find(ctx, &input.secret_id, "secretsmanager:UpdateSecretVersionStage", c)?;
        check_live(&s)?;
        check_primary(&s)?;
        check_not_managed(&s, "modify")?;
        let stage = input.version_stage.clone();
        if input.move_to_version_id.is_some() {
            check_quotas(&s, None, std::slice::from_ref(&stage), ctx.received_at)?;
        }
        let now = ctx.received_at;
        self.update(&s.arn, |st| {
            let holder = st.staged(&stage).map(|v| v.id.clone());
            if let Some(from) = &input.remove_from_version_id {
                st.version(from).ok_or_else(|| {
                    errors::resource_not_found(format!(
                        "Secrets Manager can't find the specified secret version: {from}"
                    ))
                })?;
                if holder.as_deref() != Some(from.as_str()) {
                    return Err(errors::invalid_parameter(format!(
                        "The staging label {stage} is not attached to the version {from}."
                    )));
                }
            }
            match &input.move_to_version_id {
                Some(to) => {
                    st.version(to).ok_or_else(|| {
                        errors::resource_not_found(format!(
                            "Secrets Manager can't find the specified secret version: {to}"
                        ))
                    })?;
                    if let Some(h) = &holder {
                        if h != to && input.remove_from_version_id.as_deref() != Some(h.as_str()) {
                            return Err(errors::invalid_parameter(format!(
                                "The parameter RemoveFromVersionId can't be empty. Staging label {stage} is currently attached to version {h}, so you must explicitly reference that version in RemoveFromVersionId."
                            )));
                        }
                    }
                    st.attach(&stage, to);
                }
                None => {
                    let Some(from) = &input.remove_from_version_id else {
                        return Err(errors::invalid_parameter(
                            "You must specify MoveToVersionId, RemoveFromVersionId, or both.",
                        ));
                    };
                    if stage == CURRENT {
                        return Err(errors::invalid_parameter(
                            "You can only move staging label AWSCURRENT to a different secret version. It can't be completely removed.",
                        ));
                    }
                    if let Some(v) = st.version_mut(from) {
                        v.stages.retain(|x| *x != stage);
                    }
                }
            }
            st.last_changed = now;
            st.prune(now);
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(types::UpdateSecretVersionStageResponse { arn: Some(s.arn), name: Some(s.name) })
    }

    pub(crate) fn delete_secret(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSecretRequest,
    ) -> Result<types::DeleteSecretResponse, ServiceError> {
        let force = input.force_delete_without_recovery.unwrap_or(false);
        let window = input.recovery_window_in_days.filter(|d| *d != 0);
        let c = cond(&[
            ("secretsmanager:ForceDeleteWithoutRecovery", input.force_delete_without_recovery.map(|b| b.to_string())),
            ("secretsmanager:RecoveryWindowInDays", window.map(|d| d.to_string())),
        ]);
        if force && window.is_some() {
            return Err(errors::invalid_parameter(
                "You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays.",
            ));
        }
        let s = match self.find(ctx, &input.secret_id, "secretsmanager:DeleteSecret", c) {
            Ok(s) => s,
            // Forcibly deleting a secret that is already gone (or never
            // existed) succeeds.
            Err(e) if force && e.code == "ResourceNotFoundException" => {
                let (arn, name) = match input.secret_id.strip_prefix("arn:") {
                    Some(_) => {
                        let name = input.secret_id.rsplit_once(":secret:").map(|(_, n)| n.to_string());
                        (input.secret_id.clone(), name.unwrap_or_else(|| input.secret_id.clone()))
                    }
                    None => (
                        names::new_arn(&ctx.partition, &ctx.region, &names::account_of(ctx), &input.secret_id),
                        input.secret_id.clone(),
                    ),
                };
                return Ok(types::DeleteSecretResponse {
                    arn: Some(arn),
                    name: Some(name),
                    deletion_date: Some(ctx.received_at),
                });
            }
            Err(e) => return Err(e),
        };
        let days = window.unwrap_or(30);
        if !force && !(7..=30).contains(&days) {
            return Err(errors::invalid_parameter(
                "The RecoveryWindowInDays value must be between 7 and 30 days (inclusive).",
            ));
        }
        check_primary(&s)?;
        check_not_managed(&s, "delete")?;
        if !s.replicas.is_empty() {
            return Err(errors::invalid_request(format!(
                "You can't delete secret {} that still has replica regions [{}]",
                s.name,
                s.replicas.iter().map(|r| r.region.as_str()).collect::<Vec<_>>().join(", ")
            )));
        }
        if s.deletion_date.is_some() && !force {
            return Err(marked_for_deletion());
        }
        let now = ctx.received_at;
        let deletion_date = match s.force_deleted {
            Some(at) => at,
            None if force => now,
            None => now + chrono::Duration::days(days),
        };
        {
            let mut st = self.lock();
            if let Some(x) = st.secrets.get_mut(&s.arn) {
                // A forced deletion is asynchronous: the secret is marked for
                // deletion, and its name stays taken, until it settles.
                if force && x.force_deleted.is_none() {
                    x.force_deleted = Some(now);
                }
                x.deletion_date = Some(deletion_date);
                x.last_changed = now;
            }
            if force {
                st.sweep(now);
            }
        }
        Ok(types::DeleteSecretResponse { arn: Some(s.arn), name: Some(s.name), deletion_date: Some(deletion_date) })
    }

    pub(crate) fn restore_secret(
        &self,
        ctx: &RequestContext,
        input: types::RestoreSecretRequest,
    ) -> Result<types::RestoreSecretResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:RestoreSecret", ConditionContext::new())?;
        check_primary(&s)?;
        if s.force_deleted.is_some() {
            // Deleted without recovery: nothing to restore.
            return Err(marked_for_deletion());
        }
        let now = ctx.received_at;
        self.update(&s.arn, |st| {
            st.deletion_date = None;
            st.last_changed = now;
            Ok(())
        })?;
        Ok(types::RestoreSecretResponse { arn: Some(s.arn), name: Some(s.name) })
    }

    /// Secrets in the caller's account and Region that pass `filters`.
    pub(crate) fn matching(
        &self,
        ctx: &RequestContext,
        filters: &[types::Filter],
        include_deleted: bool,
    ) -> Result<Vec<Secret>, ServiceError> {
        for f in filters {
            if f.key.is_none() || f.values.as_ref().is_none_or(|v| v.is_empty()) {
                return Err(errors::invalid_parameter("Invalid filter: a filter needs a key and at least one value."));
            }
        }
        let account = names::account_of(ctx);
        let st = self.lock();
        Ok(st
            .secrets
            .values()
            .filter(|s| s.account == account && s.region == ctx.region)
            .filter(|s| include_deleted || s.deletion_date.is_none())
            .filter(|s| filters.iter().all(|f| self.filter_matches(s, f)))
            .cloned()
            .collect())
    }

    fn filter_matches(&self, s: &Secret, f: &types::Filter) -> bool {
        let key = f.key.as_deref().unwrap_or_default();
        let primary = self.primary_region_of(s).unwrap_or_else(|| s.region.clone());
        let attrs: Vec<String> = match key {
            "name" => vec![s.name.clone()],
            "description" => s.description.clone().into_iter().collect(),
            "tag-key" => s.tags.iter().filter_map(|t| t.key.clone()).collect(),
            "tag-value" => s.tags.iter().filter_map(|t| t.value.clone()).collect(),
            "primary-region" => vec![primary.clone()],
            "owning-service" => s.owning_service.clone().into_iter().collect(),
            _ => {
                let mut all = vec![s.name.clone(), primary.clone()];
                all.extend(s.description.clone());
                all.extend(s.owning_service.clone());
                for t in &s.tags {
                    all.extend(t.key.clone());
                    all.extend(t.value.clone());
                }
                all
            }
        };
        // Names and tags match by case-sensitive prefix; descriptions word
        // by word, ignoring case; owning services by prefix ignoring case;
        // a search over every attribute (`all`) word by word.
        f.values.iter().flatten().any(|raw| {
            let (negate, value) = match raw.strip_prefix('!') {
                Some(v) => (true, v),
                None => (false, raw.as_str()),
            };
            let hit = match key {
                "description" | "all" => {
                    let wanted = words(value);
                    let have: Vec<String> = attrs.iter().flat_map(|a| words(a)).collect();
                    !wanted.is_empty() && wanted.iter().all(|w| have.iter().any(|h| h.starts_with(w.as_str())))
                }
                "owning-service" => attrs.iter().any(|a| a.to_lowercase().starts_with(&value.to_lowercase())),
                _ => attrs.iter().any(|a| a.starts_with(value)),
            };
            hit != negate
        })
    }

    pub(crate) fn list_secrets(
        &self,
        ctx: &RequestContext,
        input: types::ListSecretsRequest,
    ) -> Result<types::ListSecretsResponse, ServiceError> {
        ctx.authorize("secretsmanager:ListSecrets", "*", ConditionContext::new())?;
        let filters = input.filters.clone().unwrap_or_default();
        let mut secrets = self.matching(ctx, &filters, input.include_planned_deletion.unwrap_or(false))?;
        let by = input.sort_by.as_deref().unwrap_or("created-date");
        secrets.sort_by(|a, b| match by {
            "name" => a.name.cmp(&b.name),
            "last-accessed-date" => a.last_accessed.cmp(&b.last_accessed),
            "last-changed-date" => a.last_changed.cmp(&b.last_changed),
            _ => a.created.cmp(&b.created),
        });
        if input.sort_order.as_deref() == Some("desc") {
            secrets.reverse();
        }
        let max = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let (page, next_token) = paginate(secrets, input.next_token.as_deref(), max)?;
        let secret_list = page
            .iter()
            .map(|s| {
                let d = self.describe(s);
                types::SecretListEntry {
                    arn: d.arn,
                    name: d.name,
                    r#type: d.r#type,
                    description: d.description,
                    kms_key_id: d.kms_key_id,
                    rotation_enabled: d.rotation_enabled,
                    rotation_lambda_arn: d.rotation_lambda_arn,
                    rotation_rules: d.rotation_rules,
                    external_secret_rotation_metadata: d.external_secret_rotation_metadata,
                    external_secret_rotation_role_arn: d.external_secret_rotation_role_arn,
                    last_rotated_date: d.last_rotated_date,
                    last_changed_date: d.last_changed_date,
                    last_accessed_date: d.last_accessed_date,
                    deleted_date: d.deleted_date,
                    next_rotation_date: d.next_rotation_date,
                    tags: d.tags,
                    secret_versions_to_stages: d.version_ids_to_stages,
                    owning_service: d.owning_service,
                    created_date: d.created_date,
                    primary_region: d.primary_region,
                }
            })
            .collect();
        Ok(types::ListSecretsResponse { secret_list: Some(secret_list), next_token })
    }

    pub(crate) fn list_secret_version_ids(
        &self,
        ctx: &RequestContext,
        input: types::ListSecretVersionIdsRequest,
    ) -> Result<types::ListSecretVersionIdsResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:ListSecretVersionIds", ConditionContext::new())?;
        let deprecated = input.include_deprecated.unwrap_or(false);
        let entries: Vec<types::SecretVersionsListEntry> = s
            .versions
            .iter()
            .filter(|v| deprecated || !v.stages.is_empty())
            .map(|v| types::SecretVersionsListEntry {
                version_id: Some(v.id.clone()),
                version_stages: Some(v.stages.clone()),
                last_accessed_date: v.last_accessed,
                created_date: Some(v.created),
                kms_key_ids: v.value.as_ref().map(|sealed| {
                    vec![if s.kms_key_id.is_none() {
                        "DefaultEncryptionKey".to_string()
                    } else {
                        sealed.key_arn.clone()
                    }]
                }),
            })
            .collect();
        let max = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let (versions, next_token) = paginate(entries, input.next_token.as_deref(), max)?;
        Ok(types::ListSecretVersionIdsResponse {
            versions: Some(versions),
            next_token,
            arn: Some(s.arn),
            name: Some(s.name),
        })
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        validate_tags(&input.tags)?;
        let s =
            self.find(ctx, &input.secret_id, "secretsmanager:TagResource", names::request_tag_context(&input.tags))?;
        check_primary(&s)?;
        self.update(&s.arn, |st| {
            merge_tags(&mut st.tags, &input.tags);
            if st.tags.len() > MAX_TAGS {
                return Err(errors::invalid_parameter("Number of tags exceeds the limit of 50."));
            }
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(())
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let mut c = ConditionContext::new();
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        let s = self.find(ctx, &input.secret_id, "secretsmanager:UntagResource", c)?;
        check_primary(&s)?;
        self.update(&s.arn, |st| {
            st.tags.retain(|t| !input.tag_keys.iter().any(|k| Some(k) == t.key.as_ref()));
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::words;

    #[test]
    fn search_words_split_like_secrets_manager() {
        assert_eq!(words("credsDatabase#892"), ["creds", "database", "892"]);
        assert_eq!(words("prod/db_main v2"), ["prod", "db", "main", "v", "2"]);
        assert_eq!(words("API key"), ["api", "key"]);
        assert!(words("/_=#").is_empty());
    }
}
