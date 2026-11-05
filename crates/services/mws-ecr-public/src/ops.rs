//! The ECR Public API.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};
use mws_oci::manifest::ManifestError;
use mws_oci::store::{PutError, PutManifest, PutOutcome};

use crate::generated::{errors, types};
use crate::state::{Catalog, Registry, Repo, State};
use crate::{EcrPublic, LOGO_PATH};

const TAG_LIMIT: usize = 50;
const PART_SIZE: i64 = 10 * 1024 * 1024;
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const ARCHITECTURES: &[&str] = &["ARM", "ARM 64", "x86", "x86-64"];
const OPERATING_SYSTEMS: &[&str] = &["Linux", "Windows"];

pub(crate) fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub(crate) fn dt(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

pub(crate) fn repository_arn(partition: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:ecr-public::{account}:repository/{name}")
}

pub(crate) fn registry_arn(partition: &str, account: &str) -> String {
    format!("arn:{partition}:ecr-public::{account}:registry/{account}")
}

pub(crate) fn denial(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        ServiceError::client("AccessDeniedException", 400, e.message)
    } else {
        e
    }
}

fn invalid(message: impl Into<String>) -> ServiceError {
    errors::invalid_parameter(message)
}

pub(crate) fn repository_not_found(name: &str, registry: &str) -> ServiceError {
    errors::repository_not_found(format!(
        "The repository with name '{name}' does not exist in the registry with id '{registry}'"
    ))
}

pub(crate) fn authorize_repo(
    ctx: &RequestContext,
    action: &str,
    arn: &str,
    repo: Option<&Repo>,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    if let Some(r) = repo {
        extra.extend(r.tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])));
    }
    let account = arn.split(':').nth(4).unwrap_or_default().to_string();
    extra.insert("aws:ResourceAccount".into(), vec![account]);
    ctx.authorize_with_resource_policy(action, arn, repo.and_then(|r| r.policy.as_deref()), extra).map_err(denial)
}

fn tag_pairs(tags: &[types::Tag]) -> Result<BTreeMap<String, String>, ServiceError> {
    if tags.len() > TAG_LIMIT {
        return Err(errors::too_many_tags(format!("A resource can have at most {TAG_LIMIT} tags.")));
    }
    let mut out = BTreeMap::new();
    for t in tags {
        let key = t.key.clone().ok_or_else(|| errors::invalid_tag_parameter("Tag keys must not be empty."))?;
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_tag_parameter("Tag keys must not start with 'aws:'."));
        }
        out.insert(key, t.value.clone().unwrap_or_default());
    }
    Ok(out)
}

fn request_tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

fn page<T: Clone>(
    items: &[T],
    token: Option<&str>,
    max: Option<i32>,
    default: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None | Some("") => 0,
        Some(t) => t.parse::<usize>().map_err(|_| {
            invalid("Invalid parameter at 'nextToken' failed to satisfy constraint: 'must be a valid pagination token'")
        })?,
    };
    let max = max.map(|m| m.max(1) as usize).unwrap_or(default);
    let end = (start + max).min(items.len());
    Ok((items.get(start..end).map(<[T]>::to_vec).unwrap_or_default(), (end < items.len()).then(|| end.to_string())))
}

fn catalog_from(input: types::RepositoryCatalogDataInput) -> Result<Catalog, ServiceError> {
    for a in input.architectures.iter().flatten() {
        if !ARCHITECTURES.contains(&a.as_str()) {
            return Err(invalid(format!(
                "Invalid parameter at 'architectures' failed to satisfy constraint: 'Member must be one of [{}]'",
                ARCHITECTURES.join(", ")
            )));
        }
    }
    for o in input.operating_systems.iter().flatten() {
        if !OPERATING_SYSTEMS.contains(&o.as_str()) {
            return Err(invalid(format!(
                "Invalid parameter at 'operatingSystems' failed to satisfy constraint: 'Member must be one of [{}]'",
                OPERATING_SYSTEMS.join(", ")
            )));
        }
    }
    let logo = match input.logo_image_blob.filter(|b| !b.is_empty()) {
        Some(b) => {
            if !(b.starts_with(&[0x89, b'P', b'N', b'G']) || b.starts_with(&[0xff, 0xd8])) {
                return Err(invalid(
                    "Invalid parameter at 'logoImageBlob' failed to satisfy constraint: 'must be a PNG or JPEG image'",
                ));
            }
            Some(base64::engine::general_purpose::STANDARD.encode(b))
        }
        None => None,
    };
    Ok(Catalog {
        description: input.description,
        architectures: input.architectures,
        operating_systems: input.operating_systems,
        logo,
        about_text: input.about_text,
        usage_text: input.usage_text,
    })
}

fn catalog_out(ctx: &RequestContext, account: &str, repo: &Repo) -> types::RepositoryCatalogData {
    let c = &repo.catalog;
    let endpoint = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
    types::RepositoryCatalogData {
        description: c.description.clone(),
        architectures: c.architectures.clone(),
        operating_systems: c.operating_systems.clone(),
        logo_url: c.logo.as_ref().map(|_| format!("{endpoint}{LOGO_PATH}{account}/{}", repo.name)),
        about_text: c.about_text.clone(),
        usage_text: c.usage_text.clone(),
        marketplace_certified: Some(false),
    }
}

/// The digest an image id names, or the batch failure AWS reports.
fn resolve_id(repo: &Repo, id: &types::ImageIdentifier) -> Result<String, types::ImageFailure> {
    let fail = |code: &str, reason: &str| types::ImageFailure {
        image_id: Some(id.clone()),
        failure_code: Some(code.into()),
        failure_reason: Some(reason.into()),
    };
    match (&id.image_digest, &id.image_tag) {
        (None, None) => {
            Err(fail("MissingDigestAndTag", "Invalid request parameters: both tag and digest cannot be null"))
        }
        (Some(d), Some(t)) => match repo.content.tags.get(t) {
            Some(td) if td == d => Ok(d.clone()),
            Some(_) => Err(fail(
                "ImageTagDoesNotMatchDigest",
                "Invalid request parameters: given tag and digest do not point to the same image",
            )),
            None => Err(fail("ImageNotFound", "Requested image not found")),
        },
        (Some(d), None) => repo
            .content
            .images
            .contains_key(d)
            .then(|| d.clone())
            .ok_or_else(|| fail("ImageNotFound", "Requested image not found")),
        (None, Some(t)) => {
            repo.content.tags.get(t).cloned().ok_or_else(|| fail("ImageNotFound", "Requested image not found"))
        }
    }
}

pub(crate) fn put_error(e: PutError, name: &str, account: &str) -> ServiceError {
    match e {
        PutError::Manifest(ManifestError::MediaTypeMismatch { declared, document }) => invalid(format!(
            "Invalid parameter at 'imageManifestMediaType' failed to satisfy constraint: 'Manifest MediaType '{document}' does not match the provided MediaType '{declared}''"
        )),
        PutError::Manifest(_) => invalid("Invalid parameter at 'ImageManifest' failed to satisfy constraint: 'Invalid JSON syntax'"),
        PutError::DigestMismatch { computed } => errors::image_digest_does_not_match(format!(
            "The provided image digest does not match the digest of the manifest '{computed}'"
        )),
        PutError::InvalidDigest(_) => invalid("Invalid parameter at 'imageDigest' failed to satisfy constraint: 'must be a valid image digest'"),
        PutError::MissingBlobs(d) => errors::layers_not_found(format!(
            "Layers with digests '[{}]' required for pushing image into repository with name '{name}' in registry with id '{account}' do not exist",
            d.join(", ")
        )),
        PutError::MissingManifests(d) => errors::referenced_images_not_found(format!(
            "Images with digests '[{}]' referenced by the manifest list do not exist in the repository with name '{name}' in registry with id '{account}'",
            d.join(", ")
        )),
        PutError::TagImmutable { tag } => errors::image_tag_already_exists(format!("The image tag '{tag}' already exists.")),
    }
}

/// Store a manifest (API or registry push).
pub(crate) fn put_in(
    repo: &mut Repo,
    account: &str,
    put: &PutManifest,
    now: i64,
    api: bool,
) -> Result<PutOutcome, ServiceError> {
    let name = repo.name.clone();
    let (out, _) = repo.content.put_manifest(put, now, |_| false).map_err(|e| put_error(e, &name, account))?;
    if out.unchanged && api {
        return Err(errors::image_already_exists(format!(
            "Image with digest '{}' and tag '{}' already exists in the repository with name '{name}' in registry with id '{account}'",
            out.digest,
            put.tag.as_deref().unwrap_or("null")
        )));
    }
    if let Some(t) = &put.tag {
        if !out.unchanged {
            repo.tag_times.insert(t.clone(), now);
        }
    }
    Ok(out)
}

impl EcrPublic {
    fn describe_repo(&self, reg: &Registry, repo: &Repo) -> types::Repository {
        types::Repository {
            repository_arn: Some(repo.arn.clone()),
            registry_id: Some(reg.account.clone()),
            repository_name: Some(repo.name.clone()),
            repository_uri: Some(format!("{}/{}/{}", self.registry_host(), reg.alias, repo.name)),
            created_at: Some(dt(repo.created_at)),
        }
    }

    /// The account a `registryId` (account id or alias) names; the caller's
    /// when absent.
    fn account(st: &State, ctx: &RequestContext, registry_id: Option<&str>) -> Result<String, ServiceError> {
        match registry_id.filter(|r| !r.is_empty()) {
            None => Ok(ctx.caller.account_id.clone()),
            Some(r) if r == ctx.caller.account_id => Ok(r.to_string()),
            Some(r) => st.account_of(r).ok_or_else(|| {
                errors::registry_not_found(format!("The registry with id or alias '{r}' does not exist."))
            }),
        }
    }

    fn with_repo<R>(
        &self,
        ctx: &RequestContext,
        registry_id: Option<&str>,
        name: &str,
        action: &str,
        f: impl FnOnce(&EcrPublic, &mut Registry) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let mut st = self.lock();
        let account = Self::account(&st, ctx, registry_id)?;
        let arn = repository_arn(&ctx.partition, &account, name);
        let reg = st.registry_mut(&account);
        authorize_repo(ctx, action, &arn, reg.repositories.get(name), ConditionContext::new())?;
        if !reg.repositories.contains_key(name) {
            return Err(repository_not_found(name, &account));
        }
        f(self, reg)
    }

    pub(crate) fn create_repository(
        &self,
        ctx: &RequestContext,
        input: types::CreateRepositoryRequest,
    ) -> Result<types::CreateRepositoryResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let name = input.repository_name;
        let arn = repository_arn(&ctx.partition, &account, &name);
        let tags = tag_pairs(&input.tags.unwrap_or_default())?;
        authorize_repo(ctx, "ecr-public:CreateRepository", &arn, None, request_tag_context(&tags))?;
        if !tags.is_empty() {
            authorize_repo(ctx, "ecr-public:TagResource", &arn, None, request_tag_context(&tags))?;
        }
        let catalog = input.catalog_data.map(catalog_from).transpose()?.unwrap_or_default();
        let mut st = self.lock();
        let reg = st.registry_mut(&account);
        if reg.repositories.contains_key(&name) {
            return Err(errors::repository_already_exists(format!(
                "The repository with name '{name}' already exists in the registry with id '{account}'"
            )));
        }
        let repo = Repo { name: name.clone(), arn, created_at: now_ms(ctx), catalog, tags, ..Default::default() };
        let out = self.describe_repo(reg, &repo);
        let catalog = catalog_out(ctx, &account, &repo);
        reg.repositories.insert(name, repo);
        Ok(types::CreateRepositoryResponse { repository: Some(out), catalog_data: Some(catalog) })
    }

    pub(crate) fn delete_repository(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryRequest,
    ) -> Result<types::DeleteRepositoryResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:DeleteRepository", |me, reg| {
            let repo = &reg.repositories[&name];
            if !input.force && !repo.content.images.is_empty() {
                return Err(errors::repository_not_empty(format!(
                    "The repository with name '{name}' in registry with id '{}' cannot be deleted because it still contains images",
                    reg.account
                )));
            }
            let out = me.describe_repo(reg, repo);
            reg.repositories.remove(&name);
            Ok(types::DeleteRepositoryResponse { repository: Some(out) })
        })
    }

    pub(crate) fn describe_repositories(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRepositoriesRequest,
    ) -> Result<types::DescribeRepositoriesResponse, ServiceError> {
        let mut st = self.lock();
        let account = Self::account(&st, ctx, input.registry_id.as_deref())?;
        let reg = st.registry_mut(&account).clone();
        let mut out = Vec::new();
        match &input.repository_names {
            Some(names) => {
                for n in names {
                    let arn = repository_arn(&ctx.partition, &account, n);
                    let repo = reg.repositories.get(n);
                    authorize_repo(ctx, "ecr-public:DescribeRepositories", &arn, repo, ConditionContext::new())?;
                    out.push(self.describe_repo(&reg, repo.ok_or_else(|| repository_not_found(n, &account))?));
                }
            }
            None => {
                for repo in reg.repositories.values() {
                    if authorize_repo(
                        ctx,
                        "ecr-public:DescribeRepositories",
                        &repo.arn,
                        Some(repo),
                        ConditionContext::new(),
                    )
                    .is_ok()
                    {
                        out.push(self.describe_repo(&reg, repo));
                    }
                }
            }
        }
        let (repositories, next_token) = page(&out, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::DescribeRepositoriesResponse { repositories: Some(repositories), next_token })
    }

    pub(crate) fn describe_registries(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRegistriesRequest,
    ) -> Result<types::DescribeRegistriesResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        ctx.authorize("ecr-public:DescribeRegistries", "*", ConditionContext::new()).map_err(denial)?;
        let mut st = self.lock();
        let reg = st.registry_mut(&account);
        let registry = types::Registry {
            registry_id: account.clone(),
            registry_arn: registry_arn(&ctx.partition, &account),
            registry_uri: format!("{}/{}", self.registry_host(), reg.alias),
            verified: false,
            aliases: vec![types::RegistryAlias {
                name: reg.alias.clone(),
                status: "ACTIVE".into(),
                primary_registry_alias: true,
                default_registry_alias: true,
            }],
        };
        let (registries, next_token) = page(&[registry], input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::DescribeRegistriesResponse { registries, next_token })
    }

    pub(crate) fn get_registry_catalog_data(
        &self,
        ctx: &RequestContext,
        _input: types::GetRegistryCatalogDataRequest,
    ) -> Result<types::GetRegistryCatalogDataResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        ctx.authorize(
            "ecr-public:GetRegistryCatalogData",
            &registry_arn(&ctx.partition, &account),
            ConditionContext::new(),
        )
        .map_err(denial)?;
        let mut st = self.lock();
        let name = st.registry_mut(&account).display_name.clone();
        Ok(types::GetRegistryCatalogDataResponse {
            registry_catalog_data: types::RegistryCatalogData { display_name: Some(name) },
        })
    }

    pub(crate) fn put_registry_catalog_data(
        &self,
        ctx: &RequestContext,
        input: types::PutRegistryCatalogDataRequest,
    ) -> Result<types::PutRegistryCatalogDataResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        ctx.authorize(
            "ecr-public:PutRegistryCatalogData",
            &registry_arn(&ctx.partition, &account),
            ConditionContext::new(),
        )
        .map_err(denial)?;
        let mut st = self.lock();
        let reg = st.registry_mut(&account);
        if let Some(n) = input.display_name {
            reg.display_name = n;
        }
        Ok(types::PutRegistryCatalogDataResponse {
            registry_catalog_data: types::RegistryCatalogData { display_name: Some(reg.display_name.clone()) },
        })
    }

    pub(crate) fn get_repository_catalog_data(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryCatalogDataRequest,
    ) -> Result<types::GetRepositoryCatalogDataResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:GetRepositoryCatalogData", |_, reg| {
            Ok(types::GetRepositoryCatalogDataResponse {
                catalog_data: Some(catalog_out(ctx, &reg.account, &reg.repositories[&name])),
            })
        })
    }

    pub(crate) fn put_repository_catalog_data(
        &self,
        ctx: &RequestContext,
        input: types::PutRepositoryCatalogDataRequest,
    ) -> Result<types::PutRepositoryCatalogDataResponse, ServiceError> {
        let name = input.repository_name.clone();
        let catalog = catalog_from(input.catalog_data)?;
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:PutRepositoryCatalogData", |_, reg| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(&name).expect("checked");
            let logo = catalog.logo.clone().or_else(|| repo.catalog.logo.clone());
            repo.catalog = Catalog { logo, ..catalog };
            Ok(types::PutRepositoryCatalogDataResponse { catalog_data: Some(catalog_out(ctx, &account, repo)) })
        })
    }

    pub(crate) fn set_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::SetRepositoryPolicyRequest,
    ) -> Result<types::SetRepositoryPolicyResponse, ServiceError> {
        Policy::parse(&input.policy_text, PolicyKind::Resource).map_err(|_| {
            invalid(
                "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'",
            )
        })?;
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:SetRepositoryPolicy", |_, reg| {
            reg.repositories.get_mut(&name).expect("checked").policy = Some(input.policy_text.clone());
            Ok(types::SetRepositoryPolicyResponse {
                registry_id: Some(reg.account.clone()),
                repository_name: Some(name.clone()),
                policy_text: Some(input.policy_text),
            })
        })
    }

    fn policy_not_found(name: &str, account: &str) -> ServiceError {
        errors::repository_policy_not_found(format!(
            "Repository policy does not exist for the repository with name '{name}' in the registry with id '{account}'"
        ))
    }

    pub(crate) fn get_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryPolicyRequest,
    ) -> Result<types::GetRepositoryPolicyResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:GetRepositoryPolicy", |_, reg| {
            let p =
                reg.repositories[&name].policy.clone().ok_or_else(|| Self::policy_not_found(&name, &reg.account))?;
            Ok(types::GetRepositoryPolicyResponse {
                registry_id: Some(reg.account.clone()),
                repository_name: Some(name.clone()),
                policy_text: Some(p),
            })
        })
    }

    pub(crate) fn delete_repository_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryPolicyRequest,
    ) -> Result<types::DeleteRepositoryPolicyResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:DeleteRepositoryPolicy", |_, reg| {
            let account = reg.account.clone();
            let p = reg.repositories.get_mut(&name).expect("checked").policy.take();
            let p = p.ok_or_else(|| Self::policy_not_found(&name, &account))?;
            Ok(types::DeleteRepositoryPolicyResponse {
                registry_id: Some(account),
                repository_name: Some(name.clone()),
                policy_text: Some(p),
            })
        })
    }

    fn with_arn<R>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        action: &str,
        extra: ConditionContext,
        f: impl FnOnce(&mut Repo) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let bad = || invalid("Invalid parameter at 'resourceArn' failed to satisfy constraint: 'Invalid ARN'");
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "ecr-public" {
            return Err(bad());
        }
        let name = parts[5].strip_prefix("repository/").ok_or_else(bad)?;
        let account = parts[4];
        let mut st = self.lock();
        let reg = st.registry_mut(account);
        authorize_repo(ctx, action, arn, reg.repositories.get(name), extra)?;
        let repo = reg.repositories.get_mut(name).ok_or_else(|| repository_not_found(name, account))?;
        f(repo)
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let tags = tag_pairs(&input.tags)?;
        self.with_arn(ctx, &input.resource_arn, "ecr-public:TagResource", request_tag_context(&tags), |repo| {
            let mut all = repo.tags.clone();
            all.extend(tags);
            if all.len() > TAG_LIMIT {
                return Err(errors::too_many_tags(format!("A resource can have at most {TAG_LIMIT} tags.")));
            }
            repo.tags = all;
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
        self.with_arn(ctx, &input.resource_arn, "ecr-public:UntagResource", extra, |repo| {
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
        self.with_arn(ctx, &input.resource_arn, "ecr-public:ListTagsForResource", ConditionContext::new(), |repo| {
            let tags =
                repo.tags.iter().map(|(k, v)| types::Tag { key: Some(k.clone()), value: Some(v.clone()) }).collect();
            Ok(types::ListTagsForResourceResponse { tags: Some(tags) })
        })
    }

    pub(crate) fn get_authorization_token(
        &self,
        ctx: &RequestContext,
        _input: types::GetAuthorizationTokenRequest,
    ) -> Result<types::GetAuthorizationTokenResponse, ServiceError> {
        ctx.authorize("ecr-public:GetAuthorizationToken", "*", ConditionContext::new()).map_err(denial)?;
        ctx.authorize("sts:GetServiceBearerToken", "*", ConditionContext::new()).map_err(denial)?;
        if ctx.caller.access_key_id.is_empty() {
            return Err(invalid("The request must be signed with an access key."));
        }
        let key = self.lock().token_key.clone();
        let claims = mws_oci::token::Claims {
            audience: crate::AUDIENCE.into(),
            access_key_id: ctx.caller.access_key_id.clone(),
            session_token: crate::SESSION_TOKEN.try_with(|t| t.clone()).ok().flatten(),
            region: ctx.region.clone(),
            expires: (chrono::Utc::now() + chrono::Duration::hours(12)).timestamp(),
            nonce: mws_oci::token::nonce(),
        };
        let password = mws_oci::token::issue(&claims, &key);
        Ok(types::GetAuthorizationTokenResponse {
            authorization_data: Some(types::AuthorizationData {
                authorization_token: Some(mws_oci::token::basic_credentials("AWS", &password)),
                expires_at: Some(ctx.received_at + chrono::Duration::hours(12)),
            }),
        })
    }

    pub(crate) fn put_image(
        &self,
        ctx: &RequestContext,
        input: types::PutImageRequest,
    ) -> Result<types::PutImageResponse, ServiceError> {
        let name = input.repository_name.clone();
        let now = now_ms(ctx);
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:PutImage", |_, reg| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(&name).expect("checked");
            let put = PutManifest {
                manifest: input.image_manifest.clone(),
                media_type: input.image_manifest_media_type.clone(),
                tag: input.image_tag.clone(),
                digest: input.image_digest.clone(),
            };
            let out = put_in(repo, &account, &put, now, true)?;
            let image = &repo.content.images[&out.digest];
            Ok(types::PutImageResponse {
                image: Some(types::Image {
                    registry_id: Some(account),
                    repository_name: Some(name.clone()),
                    image_id: Some(types::ImageIdentifier {
                        image_digest: Some(out.digest.clone()),
                        image_tag: input.image_tag.clone(),
                    }),
                    image_manifest: Some(image.manifest.clone()),
                    image_manifest_media_type: Some(image.media_type.clone()),
                }),
            })
        })
    }

    pub(crate) fn batch_delete_image(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteImageRequest,
    ) -> Result<types::BatchDeleteImageResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:BatchDeleteImage", |_, reg| {
            let repo = reg.repositories.get_mut(&name).expect("checked");
            let mut deleted = Vec::new();
            let mut failures = Vec::new();
            for id in &input.image_ids {
                let d = match resolve_id(repo, id) {
                    Ok(d) => d,
                    Err(f) => {
                        failures.push(f);
                        continue;
                    }
                };
                if id.image_digest.is_none() && repo.content.tags_of(&d).len() > 1 {
                    let t = id.image_tag.clone().expect("tag-only id");
                    repo.content.untag(&t);
                    repo.tag_times.remove(&t);
                    deleted.push(types::ImageIdentifier { image_digest: Some(d), image_tag: Some(t) });
                    continue;
                }
                if repo.content.referenced_by_index(&d) {
                    failures.push(types::ImageFailure {
                        image_id: Some(id.clone()),
                        failure_code: Some("ImageReferencedByManifestList".into()),
                        failure_reason: Some("Requested image referenced by manifest list".into()),
                    });
                    continue;
                }
                let tags = repo.content.tags_of(&d);
                repo.content.delete_image(&d);
                for t in &tags {
                    repo.tag_times.remove(t);
                    deleted.push(types::ImageIdentifier { image_digest: Some(d.clone()), image_tag: Some(t.clone()) });
                }
                if tags.is_empty() {
                    deleted.push(types::ImageIdentifier { image_digest: Some(d), image_tag: None });
                }
            }
            Ok(types::BatchDeleteImageResponse { image_ids: Some(deleted), failures: Some(failures) })
        })
    }

    fn image_detail(reg: &Registry, repo: &Repo, d: &str) -> types::ImageDetail {
        let i = &repo.content.images[d];
        let tags = repo.content.tags_of(d);
        types::ImageDetail {
            registry_id: Some(reg.account.clone()),
            repository_name: Some(repo.name.clone()),
            image_digest: Some(d.to_string()),
            image_tags: (!tags.is_empty()).then_some(tags),
            image_size_in_bytes: Some(i.size),
            image_pushed_at: Some(dt(i.pushed_at)),
            image_manifest_media_type: Some(i.media_type.clone()),
            artifact_media_type: i.config_media_type.clone(),
        }
    }

    pub(crate) fn describe_images(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImagesRequest,
    ) -> Result<types::DescribeImagesResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:DescribeImages", |_, reg| {
            let repo = &reg.repositories[&name];
            let digests: Vec<String> = match &input.image_ids {
                Some(ids) => ids
                    .iter()
                    .map(|id| {
                        resolve_id(repo, id).map_err(|_| {
                            errors::image_not_found(format!(
                                "The image with imageId {{imageDigest:'{}', imageTag:'{}'}} does not exist within the repository with name '{name}' in the registry with id '{}'",
                                id.image_digest.as_deref().unwrap_or("null"),
                                id.image_tag.as_deref().unwrap_or("null"),
                                reg.account
                            ))
                        })
                    })
                    .collect::<Result<_, _>>()?,
                None => {
                    let mut all: Vec<_> = repo.content.images.values().collect();
                    all.sort_by_key(|i| (i.pushed_at, i.digest.clone()));
                    all.into_iter().map(|i| i.digest.clone()).collect()
                }
            };
            let details: Vec<_> = digests.iter().map(|d| Self::image_detail(reg, repo, d)).collect();
            let (image_details, next_token) = page(&details, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(types::DescribeImagesResponse { image_details: Some(image_details), next_token })
        })
    }

    pub(crate) fn describe_image_tags(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImageTagsRequest,
    ) -> Result<types::DescribeImageTagsResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:DescribeImageTags", |_, reg| {
            let repo = &reg.repositories[&name];
            let details: Vec<_> = repo
                .content
                .tags
                .iter()
                .map(|(t, d)| {
                    let i = &repo.content.images[d];
                    types::ImageTagDetail {
                        image_tag: Some(t.clone()),
                        created_at: Some(dt(repo.tag_times.get(t).copied().unwrap_or(i.pushed_at))),
                        image_detail: Some(types::ReferencedImageDetail {
                            image_digest: Some(d.clone()),
                            image_size_in_bytes: Some(i.size),
                            image_pushed_at: Some(dt(i.pushed_at)),
                            image_manifest_media_type: Some(i.media_type.clone()),
                            artifact_media_type: i.config_media_type.clone(),
                        }),
                    }
                })
                .collect();
            let (image_tag_details, next_token) = page(&details, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(types::DescribeImageTagsResponse { image_tag_details: Some(image_tag_details), next_token })
        })
    }

    pub(crate) fn batch_check_layer_availability(
        &self,
        ctx: &RequestContext,
        input: types::BatchCheckLayerAvailabilityRequest,
    ) -> Result<types::BatchCheckLayerAvailabilityResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:BatchCheckLayerAvailability", |_, reg| {
            let repo = &reg.repositories[&name];
            let mut layers = Vec::new();
            let mut failures = Vec::new();
            for d in &input.layer_digests {
                if !mws_oci::digest::is_valid(d) {
                    failures.push(types::LayerFailure {
                        layer_digest: Some(d.clone()),
                        failure_code: Some("InvalidLayerDigest".into()),
                        failure_reason: Some("Invalid layer digest".into()),
                    });
                } else if let Some(b) = repo.content.blobs.get(d) {
                    layers.push(types::Layer {
                        layer_digest: Some(d.clone()),
                        layer_availability: Some("AVAILABLE".into()),
                        layer_size: Some(b.data.len() as i64),
                        media_type: None,
                    });
                } else {
                    failures.push(types::LayerFailure {
                        layer_digest: Some(d.clone()),
                        failure_code: Some("MissingLayerDigest".into()),
                        failure_reason: Some("Could not find the layer".into()),
                    });
                }
            }
            Ok(types::BatchCheckLayerAvailabilityResponse { layers: Some(layers), failures: Some(failures) })
        })
    }

    pub(crate) fn initiate_layer_upload(
        &self,
        ctx: &RequestContext,
        input: types::InitiateLayerUploadRequest,
    ) -> Result<types::InitiateLayerUploadResponse, ServiceError> {
        let name = input.repository_name.clone();
        let now = now_ms(ctx);
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:InitiateLayerUpload", |_, reg| {
            let id = reg.repositories.get_mut(&name).expect("checked").content.start_upload(now);
            Ok(types::InitiateLayerUploadResponse { upload_id: Some(id), part_size: Some(PART_SIZE) })
        })
    }

    pub(crate) fn upload_layer_part(
        &self,
        ctx: &RequestContext,
        input: types::UploadLayerPartRequest,
    ) -> Result<types::UploadLayerPartResponse, ServiceError> {
        let name = input.repository_name.clone();
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:UploadLayerPart", |_, reg| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(&name).expect("checked");
            let id = &input.upload_id;
            let have = repo.content.uploads.get(id).map(|u| u.data.len() as i64).ok_or_else(|| {
                errors::upload_not_found(format!("The upload with id '{id}' does not exist in the repository with name '{name}' in the registry with id '{account}'"))
            })?;
            let len = input.layer_part_blob.len() as i64;
            if input.part_first_byte != have || input.part_last_byte - input.part_first_byte + 1 != len || len == 0 {
                return Err(errors::invalid_layer_part(format!(
                    "The layer part size is not valid, or the first byte specified is not consecutive to the last byte of a previous layer part upload. Last valid byte received: {}",
                    have - 1
                )));
            }
            let last = repo.content.append_upload(id, Some(have as u64), &input.layer_part_blob).map_err(|_| errors::invalid_layer_part("The layer part is not valid."))?;
            Ok(types::UploadLayerPartResponse {
                registry_id: Some(account.clone()),
                repository_name: Some(name.clone()),
                upload_id: Some(id.clone()),
                last_byte_received: Some(last as i64 - 1),
            })
        })
    }

    pub(crate) fn complete_layer_upload(
        &self,
        ctx: &RequestContext,
        input: types::CompleteLayerUploadRequest,
    ) -> Result<types::CompleteLayerUploadResponse, ServiceError> {
        let name = input.repository_name.clone();
        let now = now_ms(ctx);
        self.with_repo(ctx, input.registry_id.as_deref(), &name, "ecr-public:CompleteLayerUpload", |_, reg| {
            let account = reg.account.clone();
            let repo = reg.repositories.get_mut(&name).expect("checked");
            let id = &input.upload_id;
            let upload = repo.content.uploads.get(id).ok_or_else(|| {
                errors::upload_not_found(format!("The upload with id '{id}' does not exist in the repository with name '{name}' in the registry with id '{account}'"))
            })?;
            if upload.data.is_empty() {
                return Err(errors::empty_upload(format!("The upload with id '{id}' does not contain any layer parts")));
            }
            let parts = upload.parts.clone();
            if parts.len() > 1 && parts[..parts.len() - 1].iter().any(|p| *p < MIN_PART_SIZE) {
                return Err(errors::layer_part_too_small(format!(
                    "Layer part size must be at least {MIN_PART_SIZE} bytes, except for the last part."
                )));
            }
            let expected = input.layer_digests.first().cloned().unwrap_or_default();
            if repo.content.blobs.contains_key(&expected) {
                repo.content.uploads.remove(id);
                return Err(errors::layer_already_exists(format!(
                    "The layer with digest '{expected}' already exists in the repository with name '{name}' in the registry with id '{account}'"
                )));
            }
            let done = repo.content.complete_upload(id, &expected, now).map_err(|e| match e {
                mws_oci::UploadError::DigestMismatch { actual } => errors::invalid_layer(format!(
                    "The layer digest calculated for upload id '{id}' ('{actual}') does not match the expected digest '{expected}'"
                )),
                _ => errors::invalid_layer(format!("The layer digest '{expected}' is not valid.")),
            })?;
            Ok(types::CompleteLayerUploadResponse {
                registry_id: Some(account.clone()),
                repository_name: Some(name.clone()),
                upload_id: Some(id.clone()),
                layer_digest: Some(done.digest),
            })
        })
    }
}
