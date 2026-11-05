//! Apps, branches, backend environments, webhooks and tags.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, bad_request, not_found};
use crate::state::{AppRecord, BranchRecord, State, WebhookRecord};
use crate::Amplify;

/// Authorize `amplify:<action>` on `resource`. Denials are
/// `AccessDeniedException`, as Amplify's API answers them.
pub(crate) fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    context: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("amplify:{action}"), resource, context).map_err(|e| {
        if e.code == "AccessDenied" {
            ServiceError::client("AccessDeniedException", 403, e.message)
        } else {
            e
        }
    })
}

/// The caller's app `app_id`.
pub(crate) fn app<'a>(ctx: &RequestContext, st: &'a State, app_id: &str) -> Result<&'a AppRecord, ServiceError> {
    st.apps
        .get(app_id)
        .filter(|a| a.account == ctx.caller.account_id && a.region == ctx.region)
        .ok_or_else(|| not_found("App", app_id))
}

pub(crate) fn app_mut<'a>(
    ctx: &RequestContext,
    st: &'a mut State,
    app_id: &str,
) -> Result<&'a mut AppRecord, ServiceError> {
    st.apps
        .get_mut(app_id)
        .filter(|a| a.account == ctx.caller.account_id && a.region == ctx.region)
        .ok_or_else(|| not_found("App", app_id))
}

pub(crate) fn branch<'a>(app: &'a AppRecord, name: &str) -> Result<&'a BranchRecord, ServiceError> {
    app.branches.get(name).ok_or_else(|| not_found("Branch", name))
}

pub(crate) fn branch_mut<'a>(app: &'a mut AppRecord, name: &str) -> Result<&'a mut BranchRecord, ServiceError> {
    app.branches.get_mut(name).ok_or_else(|| not_found("Branch", name))
}

/// The app as Amplify returns it, with its production branch.
pub(crate) fn render_app(rec: &AppRecord) -> types::App {
    let mut app = rec.app.clone();
    let production = rec
        .branches
        .values()
        .find(|b| b.branch.stage == "PRODUCTION")
        .or_else(|| rec.branches.values().min_by_key(|b| b.branch.create_time));
    app.production_branch = production.map(|b| {
        let last = b.jobs.values().rev().find(|j| j.summary.status == "SUCCEED");
        let latest = b.jobs.values().next_back();
        types::ProductionBranch {
            last_deploy_time: last.and_then(|j| j.summary.end_time),
            status: latest.map(|j| j.summary.status.clone()),
            thumbnail_url: None,
            branch_name: Some(b.branch.branch_name.clone()),
        }
    });
    app
}

pub(crate) fn render_branch(rec: &BranchRecord) -> types::Branch {
    let mut b = rec.branch.clone();
    b.total_number_of_jobs = rec.jobs.len().to_string();
    b.active_job_id = rec.jobs.keys().last().map(u64::to_string).unwrap_or_default();
    b
}

fn check_repository(repository: Option<&str>, token: Option<&str>) -> Result<(), ServiceError> {
    if repository.is_some_and(|r| !r.is_empty()) && token.is_none_or(str::is_empty) {
        return Err(bad_request(
            "You should at least provide one valid token: oauthToken or accessToken to connect to a repository.",
        ));
    }
    Ok(())
}

fn default_rules() -> Vec<types::CustomRule> {
    vec![types::CustomRule {
        source: "/<*>".into(),
        target: "/index.html".into(),
        status: Some("404-200".into()),
        condition: None,
    }]
}

fn check_rules(rules: &[types::CustomRule]) -> Result<(), ServiceError> {
    for r in rules {
        let status = r.status.as_deref().unwrap_or("200");
        if !matches!(status, "200" | "301" | "302" | "404" | "404-200") {
            return Err(bad_request(format!("Invalid custom rule status: {status}")));
        }
        crate::rules::Rule::parse(r).map_err(bad_request)?;
    }
    Ok(())
}

fn check_custom_headers(yaml: Option<&str>) -> Result<(), ServiceError> {
    if let Some(y) = yaml.filter(|y| !y.trim().is_empty()) {
        crate::hosting::parse_custom_headers(y).map_err(bad_request)?;
    }
    Ok(())
}

impl Amplify {
    pub(crate) async fn create_app(
        &self,
        ctx: &RequestContext,
        input: types::CreateAppRequest,
    ) -> Result<types::CreateAppResult, ServiceError> {
        let app_id = names::new_app_id();
        let arn = names::caller_app_arn(ctx, &app_id);
        authorize(ctx, "CreateApp", &arn, names::request_tag_context(input.tags.as_ref()))?;
        if let Some(tags) = &input.tags {
            names::check_tags(tags)?;
        }
        let token = input.access_token.clone().or(input.oauth_token.clone());
        check_repository(input.repository.as_deref(), token.as_deref())?;
        names::check_basic_auth(input.basic_auth_credentials.as_deref(), input.enable_basic_auth)?;
        if let Some(rules) = &input.custom_rules {
            check_rules(rules)?;
        }
        check_custom_headers(input.custom_headers.as_deref())?;
        let now = ctx.received_at;
        let app = types::App {
            app_id: app_id.clone(),
            app_arn: arn,
            name: input.name,
            tags: Some(input.tags.unwrap_or_default()),
            description: input.description.unwrap_or_default(),
            repository: input.repository.unwrap_or_default(),
            platform: input.platform.unwrap_or_else(|| "WEB".into()),
            create_time: now,
            update_time: now,
            compute_role_arn: input.compute_role_arn,
            iam_service_role_arn: input.iam_service_role_arn,
            environment_variables: input.environment_variables.unwrap_or_default(),
            default_domain: format!("{app_id}.amplifyapp.com"),
            enable_branch_auto_build: input.enable_branch_auto_build.unwrap_or(false),
            enable_branch_auto_deletion: Some(input.enable_branch_auto_deletion.unwrap_or(false)),
            enable_basic_auth: input.enable_basic_auth.unwrap_or(false),
            basic_auth_credentials: input.basic_auth_credentials,
            custom_rules: Some(input.custom_rules.unwrap_or_else(default_rules)),
            production_branch: None,
            build_spec: input.build_spec,
            custom_headers: Some(input.custom_headers.unwrap_or_default()),
            enable_auto_branch_creation: Some(input.enable_auto_branch_creation.unwrap_or(false)),
            auto_branch_creation_patterns: input.auto_branch_creation_patterns,
            auto_branch_creation_config: input.auto_branch_creation_config,
            repository_clone_method: token.as_ref().map(|_| "TOKEN".into()),
            cache_config: Some(input.cache_config.unwrap_or(types::CacheConfig { r#type: "AMPLIFY_MANAGED_NO_COOKIES".into() })),
            webhook_create_time: None,
            waf_configuration: None,
            job_config: Some(input.job_config.unwrap_or(types::JobConfig { build_compute_type: "STANDARD_8GB".into() })),
        };
        let rec = AppRecord {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            app,
            repository_token: token,
            ..AppRecord::default()
        };
        let out = render_app(&rec);
        self.write().apps.insert(app_id, rec);
        Ok(types::CreateAppResult { app: out })
    }

    pub(crate) async fn get_app(
        &self,
        ctx: &RequestContext,
        input: types::GetAppRequest,
    ) -> Result<types::GetAppResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        authorize(ctx, "GetApp", &rec.app.app_arn, names::tag_context(rec.app.tags.as_ref()))?;
        Ok(types::GetAppResult { app: render_app(rec) })
    }

    pub(crate) async fn list_apps(
        &self,
        ctx: &RequestContext,
        input: types::ListAppsRequest,
    ) -> Result<types::ListAppsResult, ServiceError> {
        authorize(ctx, "ListApps", &names::caller_app_arn(ctx, "*"), ConditionContext::new())?;
        let st = self.read();
        let mut apps: Vec<&AppRecord> = st
            .apps
            .values()
            .filter(|a| a.account == ctx.caller.account_id && a.region == ctx.region)
            .collect();
        apps.sort_by_key(|a| (a.app.create_time, a.app.app_id.clone()));
        let all: Vec<types::App> = apps.into_iter().map(render_app).collect();
        let (apps, next_token) = names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAppsResult { apps, next_token })
    }

    pub(crate) async fn update_app(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAppRequest,
    ) -> Result<types::UpdateAppResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        authorize(ctx, "UpdateApp", &rec.app.app_arn, names::tag_context(rec.app.tags.as_ref()))?;
        let token = input.access_token.clone().or(input.oauth_token.clone());
        if input.repository.is_some() {
            check_repository(input.repository.as_deref(), token.as_deref().or(rec.repository_token.as_deref()))?;
        }
        let enabled = input.enable_basic_auth.unwrap_or(rec.app.enable_basic_auth);
        let creds = input.basic_auth_credentials.as_deref().or(rec.app.basic_auth_credentials.as_deref());
        names::check_basic_auth(creds, Some(enabled))?;
        if let Some(rules) = &input.custom_rules {
            check_rules(rules)?;
        }
        check_custom_headers(input.custom_headers.as_deref())?;
        let a = &mut rec.app;
        macro_rules! set {
            ($field:ident) => {
                if let Some(v) = input.$field {
                    a.$field = v;
                }
            };
            (opt $field:ident) => {
                if let Some(v) = input.$field {
                    a.$field = Some(v);
                }
            };
        }
        set!(name);
        set!(description);
        set!(platform);
        set!(opt compute_role_arn);
        set!(opt iam_service_role_arn);
        set!(environment_variables);
        set!(enable_branch_auto_build);
        set!(opt enable_branch_auto_deletion);
        set!(enable_basic_auth);
        set!(opt basic_auth_credentials);
        set!(opt custom_rules);
        set!(opt build_spec);
        set!(opt custom_headers);
        set!(opt enable_auto_branch_creation);
        set!(opt auto_branch_creation_patterns);
        set!(opt auto_branch_creation_config);
        set!(repository);
        set!(opt job_config);
        set!(opt cache_config);
        if token.is_some() {
            a.repository_clone_method = Some("TOKEN".into());
            rec.repository_token = token;
        }
        rec.app.update_time = ctx.received_at;
        Ok(types::UpdateAppResult { app: render_app(rec) })
    }

    pub(crate) async fn delete_app(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAppRequest,
    ) -> Result<types::DeleteAppResult, ServiceError> {
        let rec = {
            let mut st = self.write();
            let rec = app(ctx, &st, &input.app_id)?;
            authorize(ctx, "DeleteApp", &rec.app.app_arn, names::tag_context(rec.app.tags.as_ref()))?;
            let rec = st.apps.remove(&input.app_id).expect("app exists");
            st.webhooks.retain(|_, w| w.webhook.app_id.as_deref() != Some(input.app_id.as_str()));
            st.uploads.retain(|_, u| u.app_id != input.app_id);
            st.artifacts.retain(|_, a| a.app_id != input.app_id);
            st.collect_garbage();
            rec
        };
        self.stop_jobs(&format!("{}/", input.app_id));
        Ok(types::DeleteAppResult { app: render_app(&rec) })
    }

    // ----- branches -----

    pub(crate) async fn create_branch(
        &self,
        ctx: &RequestContext,
        input: types::CreateBranchRequest,
    ) -> Result<types::CreateBranchResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let arn = names::branch_arn(&rec.app.app_arn, &input.branch_name);
        authorize(ctx, "CreateBranch", &arn, names::request_tag_context(input.tags.as_ref()))?;
        if let Some(tags) = &input.tags {
            names::check_tags(tags)?;
        }
        if rec.branches.contains_key(&input.branch_name) {
            return Err(bad_request(format!("Branch {} already exists.", input.branch_name)));
        }
        if rec.branches.len() >= 50 {
            return Err(errors::limit_exceeded("The number of branches has reached the limit of 50."));
        }
        names::check_basic_auth(input.basic_auth_credentials.as_deref(), input.enable_basic_auth)?;
        let now = ctx.received_at;
        let display_name =
            input.display_name.filter(|d| !d.is_empty()).unwrap_or_else(|| names::display_name(&input.branch_name));
        if rec.branches.values().any(|b| b.branch.display_name == display_name) {
            return Err(bad_request(format!("Branch with display name {display_name} already exists.")));
        }
        let branch = types::Branch {
            branch_arn: arn,
            branch_name: input.branch_name.clone(),
            description: input.description.unwrap_or_default(),
            tags: Some(input.tags.unwrap_or_default()),
            stage: input.stage.unwrap_or_else(|| "NONE".into()),
            display_name,
            enable_notification: input.enable_notification.unwrap_or(false),
            create_time: now,
            update_time: now,
            environment_variables: input.environment_variables.unwrap_or_default(),
            enable_auto_build: input.enable_auto_build.unwrap_or(true),
            enable_skew_protection: Some(input.enable_skew_protection.unwrap_or(false)),
            custom_domains: Vec::new(),
            framework: input.framework.unwrap_or_default(),
            active_job_id: String::new(),
            total_number_of_jobs: "0".into(),
            enable_basic_auth: input.enable_basic_auth.unwrap_or(false),
            enable_performance_mode: Some(input.enable_performance_mode.unwrap_or(false)),
            thumbnail_url: None,
            basic_auth_credentials: input.basic_auth_credentials,
            build_spec: input.build_spec,
            ttl: input.ttl.unwrap_or_else(|| "5".into()),
            associated_resources: None,
            enable_pull_request_preview: input.enable_pull_request_preview.unwrap_or(false),
            pull_request_environment_name: input.pull_request_environment_name,
            destination_branch: None,
            source_branch: None,
            backend_environment_arn: input.backend_environment_arn,
            backend: input.backend,
            compute_role_arn: input.compute_role_arn,
        };
        let br = BranchRecord { branch, next_job: 1, ..BranchRecord::default() };
        let out = render_branch(&br);
        rec.branches.insert(input.branch_name, br);
        Ok(types::CreateBranchResult { branch: out })
    }

    pub(crate) async fn get_branch(
        &self,
        ctx: &RequestContext,
        input: types::GetBranchRequest,
    ) -> Result<types::GetBranchResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        let b = branch(rec, &input.branch_name)?;
        authorize(ctx, "GetBranch", &b.branch.branch_arn, names::tag_context(b.branch.tags.as_ref()))?;
        Ok(types::GetBranchResult { branch: render_branch(b) })
    }

    pub(crate) async fn list_branches(
        &self,
        ctx: &RequestContext,
        input: types::ListBranchesRequest,
    ) -> Result<types::ListBranchesResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        authorize(ctx, "ListBranches", &format!("{}/branches/*", rec.app.app_arn), ConditionContext::new())?;
        let mut all: Vec<&BranchRecord> = rec.branches.values().collect();
        all.sort_by_key(|b| b.branch.create_time);
        let all: Vec<types::Branch> = all.into_iter().map(render_branch).collect();
        let (branches, next_token) = names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListBranchesResult { branches, next_token })
    }

    pub(crate) async fn update_branch(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBranchRequest,
    ) -> Result<types::UpdateBranchResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let taken: Vec<String> = rec
            .branches
            .values()
            .filter(|b| b.branch.branch_name != input.branch_name)
            .map(|b| b.branch.display_name.clone())
            .collect();
        let br = branch_mut(rec, &input.branch_name)?;
        authorize(ctx, "UpdateBranch", &br.branch.branch_arn, names::tag_context(br.branch.tags.as_ref()))?;
        let enabled = input.enable_basic_auth.unwrap_or(br.branch.enable_basic_auth);
        let creds = input.basic_auth_credentials.as_deref().or(br.branch.basic_auth_credentials.as_deref());
        names::check_basic_auth(creds, Some(enabled))?;
        if let Some(d) = input.display_name.as_ref().filter(|d| !d.is_empty()) {
            if taken.contains(d) {
                return Err(bad_request(format!("Branch with display name {d} already exists.")));
            }
        }
        let b = &mut br.branch;
        macro_rules! set {
            ($field:ident) => {
                if let Some(v) = input.$field {
                    b.$field = v;
                }
            };
            (opt $field:ident) => {
                if let Some(v) = input.$field {
                    b.$field = Some(v);
                }
            };
        }
        set!(description);
        set!(framework);
        set!(stage);
        set!(enable_notification);
        set!(enable_auto_build);
        set!(opt enable_skew_protection);
        set!(environment_variables);
        set!(opt basic_auth_credentials);
        set!(enable_basic_auth);
        set!(opt enable_performance_mode);
        set!(opt build_spec);
        set!(ttl);
        set!(enable_pull_request_preview);
        set!(opt pull_request_environment_name);
        set!(opt backend_environment_arn);
        set!(opt backend);
        set!(opt compute_role_arn);
        if let Some(d) = input.display_name.filter(|d| !d.is_empty()) {
            b.display_name = d;
        }
        b.update_time = ctx.received_at;
        Ok(types::UpdateBranchResult { branch: render_branch(br) })
    }

    pub(crate) async fn delete_branch(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBranchRequest,
    ) -> Result<types::DeleteBranchResult, ServiceError> {
        let removed = {
            let mut st = self.write();
            let rec = app_mut(ctx, &mut st, &input.app_id)?;
            let br = branch(rec, &input.branch_name)?;
            authorize(ctx, "DeleteBranch", &br.branch.branch_arn, names::tag_context(br.branch.tags.as_ref()))?;
            let removed = rec.branches.remove(&input.branch_name).expect("branch exists");
            for d in rec.domains.values_mut() {
                d.domain.sub_domains.retain(|s| s.sub_domain_setting.branch_name != input.branch_name);
            }
            st.webhooks.retain(|_, w| {
                !(w.webhook.app_id.as_deref() == Some(input.app_id.as_str()) && w.webhook.branch_name == input.branch_name)
            });
            st.uploads.retain(|_, u| !(u.app_id == input.app_id && u.branch_name == input.branch_name));
            st.artifacts.retain(|_, a| !(a.app_id == input.app_id && a.branch_name == input.branch_name));
            st.collect_garbage();
            removed
        };
        self.stop_jobs(&format!("{}/{}/", input.app_id, input.branch_name));
        Ok(types::DeleteBranchResult { branch: render_branch(&removed) })
    }

    // ----- backend environments -----

    pub(crate) async fn create_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::CreateBackendEnvironmentRequest,
    ) -> Result<types::CreateBackendEnvironmentResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let arn = format!("{}/backendenvironments/{}", rec.app.app_arn, names::encode_segment(&input.environment_name));
        authorize(ctx, "CreateBackendEnvironment", &arn, ConditionContext::new())?;
        if rec.backends.contains_key(&input.environment_name) {
            return Err(bad_request(format!("Backend environment {} already exists.", input.environment_name)));
        }
        let env = types::BackendEnvironment {
            backend_environment_arn: arn,
            environment_name: input.environment_name.clone(),
            stack_name: input.stack_name,
            deployment_artifacts: input.deployment_artifacts,
            create_time: ctx.received_at,
            update_time: ctx.received_at,
        };
        rec.backends.insert(input.environment_name, env.clone());
        Ok(types::CreateBackendEnvironmentResult { backend_environment: env })
    }

    pub(crate) async fn get_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::GetBackendEnvironmentRequest,
    ) -> Result<types::GetBackendEnvironmentResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        let env = rec
            .backends
            .get(&input.environment_name)
            .ok_or_else(|| not_found("Backend environment", &input.environment_name))?;
        authorize(ctx, "GetBackendEnvironment", &env.backend_environment_arn, ConditionContext::new())?;
        Ok(types::GetBackendEnvironmentResult { backend_environment: env.clone() })
    }

    pub(crate) async fn list_backend_environments(
        &self,
        ctx: &RequestContext,
        input: types::ListBackendEnvironmentsRequest,
    ) -> Result<types::ListBackendEnvironmentsResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        authorize(
            ctx,
            "ListBackendEnvironments",
            &format!("{}/backendenvironments/*", rec.app.app_arn),
            ConditionContext::new(),
        )?;
        let mut all: Vec<types::BackendEnvironment> = rec
            .backends
            .values()
            .filter(|e| input.environment_name.as_ref().is_none_or(|n| &e.environment_name == n))
            .cloned()
            .collect();
        all.sort_by_key(|e| e.create_time);
        let (backend_environments, next_token) =
            names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListBackendEnvironmentsResult { backend_environments, next_token })
    }

    pub(crate) async fn delete_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBackendEnvironmentRequest,
    ) -> Result<types::DeleteBackendEnvironmentResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let env = rec
            .backends
            .get(&input.environment_name)
            .ok_or_else(|| not_found("Backend environment", &input.environment_name))?;
        authorize(ctx, "DeleteBackendEnvironment", &env.backend_environment_arn, ConditionContext::new())?;
        let env = rec.backends.remove(&input.environment_name).expect("environment exists");
        Ok(types::DeleteBackendEnvironmentResult { backend_environment: env })
    }

    // ----- webhooks -----

    fn webhook<'a>(
        ctx: &RequestContext,
        st: &'a State,
        id: &str,
    ) -> Result<&'a WebhookRecord, ServiceError> {
        st.webhooks
            .get(id)
            .filter(|w| w.account == ctx.caller.account_id && w.region == ctx.region)
            .ok_or_else(|| not_found("Webhook", id))
    }

    pub(crate) async fn create_webhook(
        &self,
        ctx: &RequestContext,
        input: types::CreateWebhookRequest,
    ) -> Result<types::CreateWebhookResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let id = uuid::Uuid::new_v4().to_string();
        let arn = format!("{}/webhooks/{id}", rec.app.app_arn);
        authorize(ctx, "CreateWebhook", &arn, ConditionContext::new())?;
        branch(rec, &input.branch_name)?;
        rec.app.webhook_create_time.get_or_insert(ctx.received_at);
        let token = names::random_alnum(40);
        let webhook = types::Webhook {
            webhook_arn: arn,
            webhook_id: id.clone(),
            webhook_url: format!(
                "https://webhooks.amplify.{}.amazonaws.com/prod/webhooks?id={id}&token={token}&operation=startbuild",
                ctx.region
            ),
            app_id: Some(input.app_id.clone()),
            branch_name: input.branch_name,
            description: input.description.unwrap_or_default(),
            create_time: ctx.received_at,
            update_time: ctx.received_at,
        };
        st.webhooks.insert(
            id,
            WebhookRecord {
                account: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                webhook: webhook.clone(),
                token,
            },
        );
        Ok(types::CreateWebhookResult { webhook })
    }

    pub(crate) async fn get_webhook(
        &self,
        ctx: &RequestContext,
        input: types::GetWebhookRequest,
    ) -> Result<types::GetWebhookResult, ServiceError> {
        let st = self.read();
        let w = Self::webhook(ctx, &st, &input.webhook_id)?;
        authorize(ctx, "GetWebhook", &w.webhook.webhook_arn, ConditionContext::new())?;
        Ok(types::GetWebhookResult { webhook: w.webhook.clone() })
    }

    pub(crate) async fn list_webhooks(
        &self,
        ctx: &RequestContext,
        input: types::ListWebhooksRequest,
    ) -> Result<types::ListWebhooksResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        authorize(ctx, "ListWebhooks", &format!("{}/webhooks/*", rec.app.app_arn), ConditionContext::new())?;
        let mut all: Vec<types::Webhook> = st
            .webhooks
            .values()
            .filter(|w| w.webhook.app_id.as_deref() == Some(input.app_id.as_str()))
            .map(|w| w.webhook.clone())
            .collect();
        all.sort_by_key(|w| w.create_time);
        let (webhooks, next_token) = names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListWebhooksResult { webhooks, next_token })
    }

    pub(crate) async fn update_webhook(
        &self,
        ctx: &RequestContext,
        input: types::UpdateWebhookRequest,
    ) -> Result<types::UpdateWebhookResult, ServiceError> {
        let mut st = self.write();
        let w = Self::webhook(ctx, &st, &input.webhook_id)?;
        authorize(ctx, "UpdateWebhook", &w.webhook.webhook_arn, ConditionContext::new())?;
        let app_id = w.webhook.app_id.clone().unwrap_or_default();
        if let Some(b) = &input.branch_name {
            let rec = app(ctx, &st, &app_id)?;
            branch(rec, b)?;
        }
        let w = st.webhooks.get_mut(&input.webhook_id).expect("webhook exists");
        if let Some(b) = input.branch_name {
            w.webhook.branch_name = b;
        }
        if let Some(d) = input.description {
            w.webhook.description = d;
        }
        w.webhook.update_time = ctx.received_at;
        Ok(types::UpdateWebhookResult { webhook: w.webhook.clone() })
    }

    pub(crate) async fn delete_webhook(
        &self,
        ctx: &RequestContext,
        input: types::DeleteWebhookRequest,
    ) -> Result<types::DeleteWebhookResult, ServiceError> {
        let mut st = self.write();
        let w = Self::webhook(ctx, &st, &input.webhook_id)?;
        authorize(ctx, "DeleteWebhook", &w.webhook.webhook_arn, ConditionContext::new())?;
        let w = st.webhooks.remove(&input.webhook_id).expect("webhook exists");
        Ok(types::DeleteWebhookResult { webhook: w.webhook })
    }

    // ----- tags -----

    /// The tags of the app or branch `arn` names.
    fn tags_mut<'a>(
        ctx: &RequestContext,
        st: &'a mut State,
        arn: &str,
    ) -> Result<&'a mut Option<BTreeMap<String, String>>, ServiceError> {
        let missing = || errors::resource_not_found(format!("Resource {arn} not found."));
        let rest = arn.split_once(":apps/").map(|(_, r)| r).ok_or_else(|| bad_request(format!("Invalid ARN: {arn}")))?;
        let mut parts = rest.splitn(3, '/');
        let app_id = parts.next().unwrap_or_default();
        let rec = st
            .apps
            .get_mut(app_id)
            .filter(|a| a.account == ctx.caller.account_id && a.region == ctx.region && arn.starts_with(&a.app.app_arn))
            .ok_or_else(missing)?;
        match (parts.next(), parts.next()) {
            (None, _) => Ok(&mut rec.app.tags),
            (Some("branches"), Some(name)) => {
                let name = percent_encoding::percent_decode_str(name).decode_utf8_lossy().to_string();
                Ok(&mut rec.branches.get_mut(&name).ok_or_else(missing)?.branch.tags)
            }
            _ => Err(missing()),
        }
    }

    pub(crate) async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = Self::tags_mut(ctx, &mut st, &input.resource_arn)?;
        let cond = names::merge(names::tag_context(tags.as_ref()), names::request_tag_context(Some(&input.tags)));
        authorize(ctx, "TagResource", &input.resource_arn, cond)?;
        let mut merged = tags.clone().unwrap_or_default();
        merged.extend(input.tags);
        names::check_tags(&merged)?;
        *tags = Some(merged);
        Ok(types::TagResourceResponse {})
    }

    pub(crate) async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = Self::tags_mut(ctx, &mut st, &input.resource_arn)?;
        let mut cond = names::tag_context(tags.as_ref());
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize(ctx, "UntagResource", &input.resource_arn, cond)?;
        if let Some(t) = tags {
            for k in &input.tag_keys {
                t.remove(k);
            }
        }
        Ok(types::UntagResourceResponse {})
    }

    pub(crate) async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = Self::tags_mut(ctx, &mut st, &input.resource_arn)?;
        authorize(ctx, "ListTagsForResource", &input.resource_arn, names::tag_context(tags.as_ref()))?;
        Ok(types::ListTagsForResourceResponse { tags: Some(tags.clone().unwrap_or_default()) })
    }
}
