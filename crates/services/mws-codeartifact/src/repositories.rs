//! Repositories, their upstreams, external connections, endpoints and
//! permissions policies.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::domains::{check_policy_document, check_revision, new_revision, no_policy, policy_out, tags_to_map};
use crate::generated::types;
use crate::names::{self, conflict, domain_not_found, repository_not_found, validation};
use crate::state::{Domain, Repository, ResourcePolicy};
use crate::{external, request_tags, CodeArtifact};

const MAX_UPSTREAMS: usize = 10;

pub(crate) fn describe(d: &Domain, r: &Repository) -> types::RepositoryDescription {
    types::RepositoryDescription {
        name: Some(r.name.clone()),
        administrator_account: Some(r.administrator_account.clone()),
        domain_name: Some(d.name.clone()),
        domain_owner: Some(d.owner.clone()),
        arn: Some(r.arn.clone()),
        description: r.description.clone(),
        upstreams: Some(
            r.upstreams.iter().map(|u| types::UpstreamRepositoryInfo { repository_name: Some(u.clone()) }).collect(),
        ),
        external_connections: Some(
            r.external_connections
                .iter()
                .map(|c| types::RepositoryExternalConnectionInfo {
                    external_connection_name: Some(c.clone()),
                    package_format: external::format_of(c).map(str::to_string),
                    status: Some("Available".into()),
                })
                .collect(),
        ),
        created_time: Some(r.created),
    }
}

fn summary(d: &Domain, r: &Repository) -> types::RepositorySummary {
    types::RepositorySummary {
        name: Some(r.name.clone()),
        administrator_account: Some(r.administrator_account.clone()),
        domain_name: Some(d.name.clone()),
        domain_owner: Some(d.owner.clone()),
        arn: Some(r.arn.clone()),
        description: r.description.clone(),
        created_time: Some(r.created),
    }
}

impl CodeArtifact {
    /// Check `upstreams` against the domain and authorize associating each
    /// with `repo` as its downstream.
    fn check_upstreams(
        &self,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        repo: &str,
        upstreams: &[types::UpstreamRepository],
    ) -> Result<Vec<String>, ServiceError> {
        if upstreams.len() > MAX_UPSTREAMS {
            return Err(names::quota(
                "repository",
                repo,
                format!("A repository can have at most {MAX_UPSTREAMS} upstream repositories."),
            ));
        }
        let mut names_out = Vec::new();
        for u in upstreams {
            let name = &u.repository_name;
            if name == repo {
                return Err(validation("A repository cannot be an upstream of itself."));
            }
            if names_out.contains(name) {
                return Err(validation(format!("Duplicate upstream repository: '{name}'")));
            }
            self.authorize_repo(ctx, owner, domain, name, "codeartifact:AssociateWithDownstreamRepository", None)?;
            let st = self.read();
            let d = st.domains.get(&Self::key(ctx, owner, domain)).ok_or_else(|| domain_not_found(domain))?;
            if !d.repositories.contains_key(name) {
                return Err(repository_not_found(name));
            }
            names_out.push(name.clone());
        }
        Ok(names_out)
    }

    pub(crate) fn create_repository(
        &self,
        ctx: &RequestContext,
        input: types::CreateRepositoryRequest,
    ) -> Result<types::CreateRepositoryResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let arn = names::repository_arn(&ctx.partition, &ctx.region, &owner, &input.domain, &input.repository);
        let tags = input.tags.unwrap_or_default();
        ctx.authorize("codeartifact:CreateRepository", &arn, request_tags(&tags))?;
        if !tags.is_empty() {
            ctx.authorize("codeartifact:TagResource", &arn, request_tags(&tags))?;
        }
        let upstreams = self.check_upstreams(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            input.upstreams.as_deref().unwrap_or_default(),
        )?;
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        if d.repositories.contains_key(&input.repository) {
            return Err(conflict(
                "repository",
                &input.repository,
                format!("Repository already exists. Repository name: '{}'", input.repository),
            ));
        }
        let r = Repository {
            name: input.repository.clone(),
            arn,
            description: input.description,
            administrator_account: ctx.caller.account_id.clone(),
            created: ctx.received_at,
            upstreams,
            tags: tags_to_map(&tags),
            ..Default::default()
        };
        let out = describe(d, &r);
        d.repositories.insert(input.repository, r);
        Ok(types::CreateRepositoryResult { repository: Some(out) })
    }

    pub(crate) fn describe_repository(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRepositoryRequest,
    ) -> Result<types::DescribeRepositoryResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(ctx, &owner, &input.domain, &input.repository, "codeartifact:DescribeRepository", None)?;
        let st = self.read();
        let (d, r) = Self::repo(&st, ctx, &owner, &input.domain, &input.repository)?;
        Ok(types::DescribeRepositoryResult { repository: Some(describe(d, r)) })
    }

    pub(crate) fn repo<'a>(
        st: &'a crate::state::State,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        repo: &str,
    ) -> Result<(&'a Domain, &'a Repository), ServiceError> {
        let d = st.domains.get(&Self::key(ctx, owner, domain)).ok_or_else(|| domain_not_found(domain))?;
        let r = d.repositories.get(repo).ok_or_else(|| repository_not_found(repo))?;
        Ok((d, r))
    }

    pub(crate) fn repo_mut<'a>(
        st: &'a mut crate::state::State,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        repo: &str,
    ) -> Result<&'a mut Domain, ServiceError> {
        let d = st.domains.get_mut(&Self::key(ctx, owner, domain)).ok_or_else(|| domain_not_found(domain))?;
        if !d.repositories.contains_key(repo) {
            return Err(repository_not_found(repo));
        }
        Ok(d)
    }

    pub(crate) fn delete_repository(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryRequest,
    ) -> Result<types::DeleteRepositoryResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(ctx, &owner, &input.domain, &input.repository, "codeartifact:DeleteRepository", None)?;
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        if let Some(down) = d.repositories.values().find(|r| r.upstreams.contains(&input.repository)) {
            return Err(conflict(
                "repository",
                &input.repository,
                format!(
                    "Repository '{}' cannot be deleted because it is an upstream repository of '{}'.",
                    input.repository, down.name
                ),
            ));
        }
        let out = describe(d, &d.repositories[&input.repository]);
        d.repositories.remove(&input.repository);
        for g in d.groups.values_mut() {
            for set in g.allowed_repositories.values_mut() {
                set.remove(&input.repository);
            }
        }
        Ok(types::DeleteRepositoryResult { repository: Some(out) })
    }

    pub(crate) fn update_repository(
        &self,
        ctx: &RequestContext,
        input: types::UpdateRepositoryRequest,
    ) -> Result<types::UpdateRepositoryResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(ctx, &owner, &input.domain, &input.repository, "codeartifact:UpdateRepository", None)?;
        {
            let st = self.read();
            Self::repo(&st, ctx, &owner, &input.domain, &input.repository)?;
        }
        let upstreams = match &input.upstreams {
            Some(u) => Some(self.check_upstreams(ctx, &owner, &input.domain, &input.repository, u)?),
            None => None,
        };
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        let r = d.repositories.get_mut(&input.repository).expect("checked");
        if let Some(desc) = input.description {
            r.description = Some(desc);
        }
        if let Some(u) = upstreams {
            r.upstreams = u;
        }
        let out = describe(d, &d.repositories[&input.repository]);
        Ok(types::UpdateRepositoryResult { repository: Some(out) })
    }

    pub(crate) fn list_repositories(
        &self,
        ctx: &RequestContext,
        input: types::ListRepositoriesRequest,
    ) -> Result<types::ListRepositoriesResult, ServiceError> {
        ctx.authorize("codeartifact:ListRepositories", "*", ConditionContext::new())?;
        let st = self.read();
        let prefix = input.repository_prefix.unwrap_or_default();
        let all: Vec<_> = st
            .domains
            .values()
            .filter(|d| d.region == ctx.region)
            .flat_map(|d| d.repositories.values().map(move |r| (d, r)))
            .filter(|(_, r)| r.administrator_account == ctx.caller.account_id && r.name.starts_with(&prefix))
            .map(|(d, r)| summary(d, r))
            .collect();
        let (repositories, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListRepositoriesResult { repositories: Some(repositories), next_token })
    }

    pub(crate) fn list_repositories_in_domain(
        &self,
        ctx: &RequestContext,
        input: types::ListRepositoriesInDomainRequest,
    ) -> Result<types::ListRepositoriesInDomainResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:ListRepositoriesInDomain")?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let prefix = input.repository_prefix.unwrap_or_default();
        let all: Vec<_> = d
            .repositories
            .values()
            .filter(|r| r.name.starts_with(&prefix))
            .filter(|r| input.administrator_account.as_ref().is_none_or(|a| &r.administrator_account == a))
            .map(|r| summary(d, r))
            .collect();
        let (repositories, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListRepositoriesInDomainResult { repositories: Some(repositories), next_token })
    }

    pub(crate) fn associate_external_connection(
        &self,
        ctx: &RequestContext,
        input: types::AssociateExternalConnectionRequest,
    ) -> Result<types::AssociateExternalConnectionResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            "codeartifact:AssociateExternalConnection",
            None,
        )?;
        let conn = &input.external_connection;
        if external::format_of(conn).is_none() {
            return Err(validation(format!("Invalid external connection name: '{conn}'")));
        }
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        let r = d.repositories.get_mut(&input.repository).expect("checked");
        if r.external_connections.contains(conn) {
            return Err(conflict(
                "repository",
                &input.repository,
                format!("External connection '{conn}' is already associated with repository '{}'.", input.repository),
            ));
        }
        if !r.external_connections.is_empty() {
            return Err(names::quota(
                "repository",
                &input.repository,
                "A repository can have at most 1 external connection.",
            ));
        }
        r.external_connections.push(conn.clone());
        let out = describe(d, &d.repositories[&input.repository]);
        Ok(types::AssociateExternalConnectionResult { repository: Some(out) })
    }

    pub(crate) fn disassociate_external_connection(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateExternalConnectionRequest,
    ) -> Result<types::DisassociateExternalConnectionResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            "codeartifact:DisassociateExternalConnection",
            None,
        )?;
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        let r = d.repositories.get_mut(&input.repository).expect("checked");
        let before = r.external_connections.len();
        r.external_connections.retain(|c| c != &input.external_connection);
        if r.external_connections.len() == before {
            return Err(names::not_found(
                "external-connection",
                &input.external_connection,
                format!(
                    "External connection '{}' is not associated with repository '{}'.",
                    input.external_connection, input.repository
                ),
            ));
        }
        let out = describe(d, &d.repositories[&input.repository]);
        Ok(types::DisassociateExternalConnectionResult { repository: Some(out) })
    }

    pub(crate) fn get_repository_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryEndpointRequest,
    ) -> Result<types::GetRepositoryEndpointResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(ctx, &owner, &input.domain, &input.repository, "codeartifact:GetRepositoryEndpoint", None)?;
        names::check_format(&input.format)?;
        if input.format == "generic" {
            return Err(validation("Repository endpoints are not available for packages of format 'generic'."));
        }
        let st = self.read();
        Self::repo(&st, ctx, &owner, &input.domain, &input.repository)?;
        let url = crate::endpoints::repository_url(ctx, &owner, &input.domain, &input.format, &input.repository);
        Ok(types::GetRepositoryEndpointResult { repository_endpoint: Some(url) })
    }

    pub(crate) fn put_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutRepositoryPermissionsPolicyRequest,
    ) -> Result<types::PutRepositoryPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            "codeartifact:PutRepositoryPermissionsPolicy",
            None,
        )?;
        check_policy_document(&input.policy_document)?;
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        let r = d.repositories.get_mut(&input.repository).expect("checked");
        check_revision(r.policy.as_ref(), input.policy_revision.as_deref(), &r.arn)?;
        let p = ResourcePolicy { document: input.policy_document, revision: new_revision() };
        let out = policy_out(&r.arn, &p);
        r.policy = Some(p);
        Ok(types::PutRepositoryPermissionsPolicyResult { policy: Some(out) })
    }

    pub(crate) fn get_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryPermissionsPolicyRequest,
    ) -> Result<types::GetRepositoryPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            "codeartifact:GetRepositoryPermissionsPolicy",
            None,
        )?;
        let st = self.read();
        let (_, r) = Self::repo(&st, ctx, &owner, &input.domain, &input.repository)?;
        let p = r.policy.as_ref().ok_or_else(|| no_policy("repository", &r.arn))?;
        Ok(types::GetRepositoryPermissionsPolicyResult { policy: Some(policy_out(&r.arn, p)) })
    }

    pub(crate) fn delete_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryPermissionsPolicyRequest,
    ) -> Result<types::DeleteRepositoryPermissionsPolicyResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(
            ctx,
            &owner,
            &input.domain,
            &input.repository,
            "codeartifact:DeleteRepositoryPermissionsPolicy",
            None,
        )?;
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &owner, &input.domain, &input.repository)?;
        let r = d.repositories.get_mut(&input.repository).expect("checked");
        let p = r.policy.as_ref().ok_or_else(|| no_policy("repository", &r.arn))?;
        check_revision(Some(p), input.policy_revision.as_deref(), &r.arn)?;
        let out = policy_out(&r.arn, p);
        r.policy = None;
        Ok(types::DeleteRepositoryPermissionsPolicyResult { policy: Some(out) })
    }
}
