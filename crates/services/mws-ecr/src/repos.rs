//! Repositories: create, describe, delete, settings, policies and tags.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};

use crate::generated::{errors, types};
use crate::names::{
    self, authorize_repo, dt, invalid_parameter, now_ms, repository_already_exists, repository_arn,
    repository_not_found, request_tag_context, tag_list, tag_map,
};
use crate::state::{Registry, Repo};
use crate::Ecr;

const TAG_LIMIT: usize = 50;
const EXCLUSION_FILTER_LIMIT: usize = 5;

/// Repository settings as a creation request (or template) gives them.
#[derive(Debug, Clone, Default)]
pub(crate) struct NewRepo {
    pub tag_mutability: Option<String>,
    pub exclusion_filters: Vec<types::ImageTagMutabilityExclusionFilter>,
    pub scan_on_push: bool,
    pub encryption: Option<types::EncryptionConfiguration>,
    pub tags: BTreeMap<String, String>,
    pub policy: Option<String>,
    pub lifecycle: Option<String>,
}

impl NewRepo {
    /// The settings a creation template gives a repository it creates.
    pub fn from_template(t: &types::RepositoryCreationTemplate) -> Self {
        Self {
            tag_mutability: t.image_tag_mutability.clone(),
            exclusion_filters: t.image_tag_mutability_exclusion_filters.clone().unwrap_or_default(),
            scan_on_push: false,
            encryption: t.encryption_configuration.as_ref().map(|e| types::EncryptionConfiguration {
                encryption_type: e.encryption_type.clone(),
                kms_key: e.kms_key.clone(),
            }),
            tags: t.resource_tags.as_deref().map(tag_map).unwrap_or_default(),
            policy: t.repository_policy.clone(),
            lifecycle: t.lifecycle_policy.clone(),
        }
    }
}

pub(crate) fn build_repo(partition: &str, registry: &Registry, name: &str, now: i64, s: NewRepo) -> Repo {
    Repo {
        name: name.to_string(),
        arn: repository_arn(partition, &registry.region, &registry.account, name),
        created_at: now,
        tag_mutability: s.tag_mutability.unwrap_or_else(|| "MUTABLE".into()),
        exclusion_filters: s.exclusion_filters,
        scan_on_push: s.scan_on_push,
        encryption: Some(
            s.encryption
                .unwrap_or_else(|| types::EncryptionConfiguration { encryption_type: "AES256".into(), kms_key: None }),
        ),
        tags: s.tags,
        policy: s.policy,
        lifecycle: s.lifecycle,
        ..Default::default()
    }
}

/// The creation template that applies to a new repository named `name`
/// created for `applied_for`: the longest matching prefix, else `ROOT`.
pub(crate) fn template_for<'a>(
    registry: &'a Registry,
    name: &str,
    applied_for: &str,
) -> Option<&'a types::RepositoryCreationTemplate> {
    let applies = |t: &types::RepositoryCreationTemplate| {
        t.applied_for.as_ref().is_some_and(|a| a.iter().any(|x| x == applied_for))
    };
    registry
        .templates
        .iter()
        .filter(|(p, t)| {
            p.as_str() != "ROOT" && applies(t) && (name == p.as_str() || name.starts_with(&format!("{p}/")))
        })
        .max_by_key(|(p, _)| p.len())
        .map(|(_, t)| t)
        .or_else(|| registry.templates.get("ROOT").filter(|t| applies(t)))
}

pub(crate) fn check_mutability(
    mutability: &str,
    filters: &[types::ImageTagMutabilityExclusionFilter],
) -> Result<(), ServiceError> {
    let with_exclusion = mutability.ends_with("_WITH_EXCLUSION");
    if with_exclusion && filters.is_empty() {
        return Err(invalid_parameter(format!(
            "Invalid parameter at 'imageTagMutabilityExclusionFilters' failed to satisfy constraint: 'must be specified when imageTagMutability is {mutability}'"
        )));
    }
    if !with_exclusion && !filters.is_empty() {
        return Err(invalid_parameter(
            "Invalid parameter at 'imageTagMutabilityExclusionFilters' failed to satisfy constraint: 'can only be specified when imageTagMutability is IMMUTABLE_WITH_EXCLUSION or MUTABLE_WITH_EXCLUSION'",
        ));
    }
    if filters.len() > EXCLUSION_FILTER_LIMIT {
        return Err(invalid_parameter(format!(
            "Invalid parameter at 'imageTagMutabilityExclusionFilters' failed to satisfy constraint: 'must have at most {EXCLUSION_FILTER_LIMIT} filters'"
        )));
    }
    Ok(())
}

pub(crate) fn check_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    if tags.len() > TAG_LIMIT {
        return Err(errors::too_many_tags(format!("A resource can have at most {TAG_LIMIT} tags.")));
    }
    for t in tags {
        if t.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_tag_parameter("Tag keys must not start with 'aws:'."));
        }
    }
    Ok(())
}

pub(crate) fn check_policy(text: &str) -> Result<(), ServiceError> {
    Policy::parse(text, PolicyKind::Resource).map(|_| ()).map_err(|_| {
        invalid_parameter(
            "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'",
        )
    })
}

impl Ecr {
    pub(crate) fn describe_repo(&self, registry: &Registry, repo: &Repo) -> types::Repository {
        types::Repository {
            repository_arn: Some(repo.arn.clone()),
            registry_id: Some(registry.account.clone()),
            repository_name: Some(repo.name.clone()),
            repository_uri: Some(format!("{}/{}", self.registry_host(&registry.account, &registry.region), repo.name)),
            created_at: Some(dt(repo.created_at)),
            image_tag_mutability: Some(repo.tag_mutability.clone()),
            image_tag_mutability_exclusion_filters: (!repo.exclusion_filters.is_empty())
                .then(|| repo.exclusion_filters.clone()),
            image_scanning_configuration: Some(types::ImageScanningConfiguration { scan_on_push: repo.scan_on_push }),
            encryption_configuration: repo.encryption.clone(),
        }
    }

    /// Resolve a repository encryption setting: KMS keys must exist and be
    /// usable by the caller through ECR; no key means the AWS managed
    /// `alias/aws/ecr`.
    pub(crate) fn resolve_encryption(
        &self,
        ctx: &RequestContext,
        e: Option<types::EncryptionConfiguration>,
    ) -> Result<Option<types::EncryptionConfiguration>, ServiceError> {
        let Some(mut e) = e else { return Ok(None) };
        match e.encryption_type.as_str() {
            "AES256" => {
                if e.kms_key.is_some() {
                    return Err(invalid_parameter(
                        "Invalid parameter at 'kmsKey' failed to satisfy constraint: 'kmsKey can only be specified when encryptionType is KMS or KMS_DSSE'",
                    ));
                }
            }
            _ => {
                let Some(kms) = self.inner.kms.get() else { return Ok(Some(e)) };
                let key = match e.kms_key.as_deref().filter(|k| !k.is_empty()) {
                    Some(k) => k.to_string(),
                    None => kms.aws_managed_key(ctx, "ecr"),
                };
                let context = BTreeMap::new();
                let data_key = kms.generate_data_key_via(ctx, "ecr", &key, &context, 32).map_err(|err| {
                    errors::kms(format!("KMS error: {}", err.message))
                        .with_field("kmsError", mws_core::ErrorValue::String(err.code.to_string()))
                })?;
                e.kms_key = Some(data_key.key_arn);
            }
        }
        Ok(Some(e))
    }

    pub(crate) fn create_repository(
        &self,
        ctx: &RequestContext,
        input: types::CreateRepositoryRequest,
    ) -> Result<types::CreateRepositoryResponse, ServiceError> {
        let account = Ecr::target(ctx, input.registry_id.as_deref());
        let name = input.repository_name;
        let arn = repository_arn(&ctx.partition, &ctx.region, &account, &name);
        let tags = input.tags.unwrap_or_default();
        authorize_repo(ctx, "ecr:CreateRepository", &arn, None, request_tag_context(&tags))?;
        if !tags.is_empty() {
            authorize_repo(ctx, "ecr:TagResource", &arn, None, request_tag_context(&tags))?;
        }
        check_tags(&tags)?;
        let mutability = input.image_tag_mutability.unwrap_or_else(|| "MUTABLE".into());
        let filters = input.image_tag_mutability_exclusion_filters.unwrap_or_default();
        check_mutability(&mutability, &filters)?;
        if self.lock().registry(&account, &ctx.region).is_some_and(|r| r.repositories.contains_key(&name)) {
            return Err(repository_already_exists(&name, &account));
        }
        let encryption = self.resolve_encryption(ctx, input.encryption_configuration)?;
        let mut st = self.lock();
        let registry = st.registry_mut(&account, &ctx.region);
        if registry.repositories.contains_key(&name) {
            return Err(repository_already_exists(&name, &account));
        }
        let repo = build_repo(
            &ctx.partition,
            registry,
            &name,
            now_ms(ctx),
            NewRepo {
                tag_mutability: Some(mutability),
                exclusion_filters: filters,
                scan_on_push: input.image_scanning_configuration.is_some_and(|c| c.scan_on_push),
                encryption,
                tags: tag_map(&tags),
                ..Default::default()
            },
        );
        let out = self.describe_repo(registry, &repo);
        registry.repositories.insert(name, repo);
        Ok(types::CreateRepositoryResponse { repository: Some(out) })
    }

    /// Look up a repository for an API call after authorizing `action` on
    /// it, and run `f` with it.
    pub(crate) fn with_repo<R>(
        &self,
        ctx: &RequestContext,
        registry_id: Option<&str>,
        name: &str,
        action: &str,
        f: impl FnOnce(&Ecr, &mut Registry, &str) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let account = Ecr::target(ctx, registry_id);
        let arn = repository_arn(&ctx.partition, &ctx.region, &account, name);
        let mut st = self.lock();
        let registry = st.registry_mut(&account, &ctx.region);
        authorize_repo(ctx, action, &arn, registry.repositories.get(name), ConditionContext::new())?;
        if !registry.repositories.contains_key(name) {
            return Err(repository_not_found(name, &account));
        }
        f(self, registry, name)
    }

    pub(crate) fn delete_repository(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryRequest,
    ) -> Result<types::DeleteRepositoryResponse, ServiceError> {
        let force = input.force;
        self.with_repo(ctx, input.registry_id.as_deref(), &input.repository_name, "ecr:DeleteRepository", |ecr, reg, name| {
            let repo = &reg.repositories[name];
            if !force && !repo.content.images.is_empty() {
                return Err(errors::repository_not_empty(format!(
                    "The repository with name '{name}' in registry with id '{}' cannot be deleted because it still contains images",
                    reg.account
                )));
            }
            let out = ecr.describe_repo(reg, repo);
            reg.repositories.remove(name);
            Ok(types::DeleteRepositoryResponse { repository: Some(out) })
        })
    }

    pub(crate) fn describe_repositories(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRepositoriesRequest,
    ) -> Result<types::DescribeRepositoriesResponse, ServiceError> {
        let account = Ecr::target(ctx, input.registry_id.as_deref());
        if input.repository_names.is_some() && (input.max_results.is_some() || input.next_token.is_some()) {
            return Err(invalid_parameter(
                "Invalid parameter at 'repositoryNames' failed to satisfy constraint: 'repositoryNames cannot be used together with maxResults or nextToken'",
            ));
        }
        let st = self.lock();
        let empty = Registry { account: account.clone(), region: ctx.region.clone(), ..Default::default() };
        let registry = st.registry(&account, &ctx.region).unwrap_or(&empty);
        let mut repos = Vec::new();
        match &input.repository_names {
            Some(names) => {
                for name in names {
                    let arn = repository_arn(&ctx.partition, &ctx.region, &account, name);
                    let repo = registry.repositories.get(name);
                    authorize_repo(ctx, "ecr:DescribeRepositories", &arn, repo, ConditionContext::new())?;
                    let repo = repo.ok_or_else(|| repository_not_found(name, &account))?;
                    repos.push(self.describe_repo(registry, repo));
                }
            }
            None => {
                let arn = format!("arn:{}:ecr:{}:{account}:repository/*", ctx.partition, ctx.region);
                names::authorize_registry(ctx, "ecr:DescribeRepositories", &arn)?;
                for repo in registry.repositories.values() {
                    let allowed =
                        authorize_repo(ctx, "ecr:DescribeRepositories", &repo.arn, Some(repo), ConditionContext::new())
                            .is_ok();
                    if allowed {
                        repos.push(self.describe_repo(registry, repo));
                    }
                }
            }
        }
        let (repositories, next_token) = names::page(&repos, input.next_token.as_deref(), input.max_results, 1000)?;
        Ok(types::DescribeRepositoriesResponse { repositories: Some(repositories), next_token })
    }

    pub(crate) fn put_image_tag_mutability(
        &self,
        ctx: &RequestContext,
        input: types::PutImageTagMutabilityRequest,
    ) -> Result<types::PutImageTagMutabilityResponse, ServiceError> {
        let filters = input.image_tag_mutability_exclusion_filters.unwrap_or_default();
        check_mutability(&input.image_tag_mutability, &filters)?;
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:PutImageTagMutability",
            |_, reg, name| {
                let repo = reg.repositories.get_mut(name).expect("checked");
                repo.tag_mutability = input.image_tag_mutability.clone();
                repo.exclusion_filters = filters.clone();
                Ok(types::PutImageTagMutabilityResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    image_tag_mutability: Some(input.image_tag_mutability),
                    image_tag_mutability_exclusion_filters: (!filters.is_empty()).then_some(filters),
                })
            },
        )
    }

    pub(crate) fn put_image_scanning_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutImageScanningConfigurationRequest,
    ) -> Result<types::PutImageScanningConfigurationResponse, ServiceError> {
        let scan_on_push = input.image_scanning_configuration.scan_on_push;
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:PutImageScanningConfiguration",
            |_, reg, name| {
                reg.repositories.get_mut(name).expect("checked").scan_on_push = scan_on_push;
                Ok(types::PutImageScanningConfigurationResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    image_scanning_configuration: Some(types::ImageScanningConfiguration { scan_on_push }),
                })
            },
        )
    }

    pub(crate) fn set_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::SetRepositoryPolicyRequest,
    ) -> Result<types::SetRepositoryPolicyResponse, ServiceError> {
        check_policy(&input.policy_text)?;
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:SetRepositoryPolicy",
            |_, reg, name| {
                reg.repositories.get_mut(name).expect("checked").policy = Some(input.policy_text.clone());
                Ok(types::SetRepositoryPolicyResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    policy_text: Some(input.policy_text),
                })
            },
        )
    }

    fn policy_not_found(name: &str, registry: &str) -> ServiceError {
        errors::repository_policy_not_found(format!(
            "Repository policy does not exist for the repository with name '{name}' in the registry with id '{registry}'"
        ))
    }

    pub(crate) fn get_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryPolicyRequest,
    ) -> Result<types::GetRepositoryPolicyResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:GetRepositoryPolicy",
            |_, reg, name| {
                let policy =
                    reg.repositories[name].policy.clone().ok_or_else(|| Self::policy_not_found(name, &reg.account))?;
                Ok(types::GetRepositoryPolicyResponse {
                    registry_id: Some(reg.account.clone()),
                    repository_name: Some(name.to_string()),
                    policy_text: Some(policy),
                })
            },
        )
    }

    pub(crate) fn delete_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryPolicyRequest,
    ) -> Result<types::DeleteRepositoryPolicyResponse, ServiceError> {
        self.with_repo(
            ctx,
            input.registry_id.as_deref(),
            &input.repository_name,
            "ecr:DeleteRepositoryPolicy",
            |_, reg, name| {
                let account = reg.account.clone();
                let repo = reg.repositories.get_mut(name).expect("checked");
                let policy = repo.policy.take().ok_or_else(|| Self::policy_not_found(name, &account))?;
                Ok(types::DeleteRepositoryPolicyResponse {
                    registry_id: Some(account),
                    repository_name: Some(name.to_string()),
                    policy_text: Some(policy),
                })
            },
        )
    }

    /// `(account, region, name)` of a repository ARN.
    fn parse_arn(arn: &str) -> Result<(String, String, String), ServiceError> {
        let invalid =
            || invalid_parameter("Invalid parameter at 'resourceArn' failed to satisfy constraint: 'Invalid ARN'");
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "ecr" {
            return Err(invalid());
        }
        let name = parts[5].strip_prefix("repository/").ok_or_else(invalid)?;
        Ok((parts[4].to_string(), parts[3].to_string(), name.to_string()))
    }

    fn with_tagged<R>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        action: &str,
        extra: ConditionContext,
        f: impl FnOnce(&mut Repo) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let (account, region, name) = Self::parse_arn(arn)?;
        let mut st = self.lock();
        let registry = st.registry_mut(&account, &region);
        authorize_repo(ctx, action, arn, registry.repositories.get(&name), extra)?;
        let repo = registry.repositories.get_mut(&name).ok_or_else(|| repository_not_found(&name, &account))?;
        f(repo)
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        check_tags(&input.tags)?;
        self.with_tagged(ctx, &input.resource_arn, "ecr:TagResource", request_tag_context(&input.tags), |repo| {
            let mut tags = repo.tags.clone();
            tags.extend(tag_map(&input.tags));
            if tags.len() > TAG_LIMIT {
                return Err(errors::too_many_tags(format!("A resource can have at most {TAG_LIMIT} tags.")));
            }
            repo.tags = tags;
            Ok(types::TagResourceResponse {})
        })
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut extra = ConditionContext::new();
        extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.with_tagged(ctx, &input.resource_arn, "ecr:UntagResource", extra, |repo| {
            for k in &input.tag_keys {
                repo.tags.remove(k);
            }
            Ok(types::UntagResourceResponse {})
        })
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.with_tagged(ctx, &input.resource_arn, "ecr:ListTagsForResource", ConditionContext::new(), |repo| {
            Ok(types::ListTagsForResourceResponse { tags: Some(tag_list(&repo.tags)) })
        })
    }

    pub(crate) fn batch_get_repository_scanning_configuration(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetRepositoryScanningConfigurationRequest,
    ) -> Result<types::BatchGetRepositoryScanningConfigurationResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let st = self.lock();
        let empty = Registry::default();
        let registry = st.registry(&account, &ctx.region).unwrap_or(&empty);
        let mut configs = Vec::new();
        let mut failures = Vec::new();
        for name in &input.repository_names {
            let arn = repository_arn(&ctx.partition, &ctx.region, &account, name);
            let repo = registry.repositories.get(name);
            authorize_repo(ctx, "ecr:BatchGetRepositoryScanningConfiguration", &arn, repo, ConditionContext::new())?;
            match repo {
                None => failures.push(types::RepositoryScanningConfigurationFailure {
                    repository_name: Some(name.clone()),
                    failure_code: Some("REPOSITORY_NOT_FOUND".into()),
                    failure_reason: Some("REPOSITORY_NOT_FOUND".into()),
                }),
                Some(repo) => configs.push(crate::registry_config::repository_scanning(registry, repo)),
            }
        }
        Ok(types::BatchGetRepositoryScanningConfigurationResponse {
            scanning_configurations: Some(configs),
            failures: Some(failures),
        })
    }
}
