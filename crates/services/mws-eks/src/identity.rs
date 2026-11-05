//! OIDC identity provider configs (users authenticating to the cluster
//! with an external IdP) and Pod Identity associations (service accounts
//! that get IAM role credentials).

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::util::{self, param, text};
use crate::Eks;

/// A new Pod Identity association; `owner` is the add-on that manages it.
pub(crate) fn new_association(
    ctx: &RequestContext,
    cluster: &str,
    namespace: &str,
    service_account: &str,
    role_arn: &str,
    tags: Option<util::Tags>,
    owner: Option<String>,
) -> types::PodIdentityAssociation {
    let id = format!("a-{}", util::random(util::LOWER_ALNUM, 17));
    let now = ctx.received_at;
    types::PodIdentityAssociation {
        cluster_name: Some(cluster.into()),
        namespace: Some(namespace.into()),
        service_account: Some(service_account.into()),
        role_arn: Some(role_arn.into()),
        association_arn: Some(util::arn(ctx, &format!("podidentityassociation/{cluster}/{id}"))),
        association_id: Some(id),
        tags: Some(tags.unwrap_or_default()),
        created_at: Some(now),
        modified_at: Some(now),
        owner_arn: owner,
        disable_session_tags: Some(false),
        target_role_arn: None,
        external_id: None,
        policy: None,
    }
}

fn association_not_found(id: &str) -> ServiceError {
    errors::resource_not_found(format!("No Pod Identity association found with id: {id}"))
}

fn idp_not_found(cluster: &str, name: &str) -> ServiceError {
    errors::resource_not_found(format!("No identity provider config found with name: {name}"))
        .with_field("clusterName", text(cluster))
}

fn check_idp_type(t: &str) -> Result<(), ServiceError> {
    if t != "oidc" {
        return Err(errors::invalid_parameter(format!(
            "The identity provider config type {t} is invalid. The only supported type is oidc."
        )));
    }
    Ok(())
}

fn check_session_policy(policy: Option<&str>) -> Result<(), ServiceError> {
    let Some(p) = policy else { return Ok(()) };
    if p.len() > 2048 {
        return Err(errors::invalid_parameter("The session policy must be no longer than 2048 characters."));
    }
    let v: serde_json::Value =
        serde_json::from_str(p).map_err(|_| errors::invalid_parameter("The session policy is not valid JSON."))?;
    if !v.is_object() || v.get("Statement").is_none() {
        return Err(errors::invalid_parameter("The session policy must be an IAM policy document."));
    }
    Ok(())
}

impl Eks {
    fn check_pod_role(&self, ctx: &RequestContext, role: &str) -> Result<(), ServiceError> {
        self.check_role(
            ctx,
            role,
            "pods.eks.amazonaws.com",
            || format!("The role {role} does not exist."),
            || format!("Role {role} must trust pods.eks.amazonaws.com for sts:AssumeRole and sts:TagSession."),
        )
    }

    pub(crate) async fn associate_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::AssociateIdentityProviderConfigRequest,
    ) -> Result<types::AssociateIdentityProviderConfigResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        let oidc = &input.oidc;
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        let mut c = ConditionContext::new();
        c.insert("eks:issuerUrl".into(), vec![oidc.issuer_url.clone()]);
        c.insert("eks:clientId".into(), vec![oidc.client_id.clone()]);
        util::authorize(
            ctx,
            "AssociateIdentityProviderConfig",
            &cluster_arn,
            rec.cluster.tags.as_ref(),
            input.tags.as_ref(),
            c,
        )?;
        util::check_create_tags(input.tags.as_ref())?;
        if rec.registered {
            return Err(errors::invalid_request("Identity provider configs are not supported on registered clusters.")
                .with_field("clusterName", text(&cluster)));
        }
        if !oidc.issuer_url.starts_with("https://") {
            return Err(errors::invalid_parameter("The issuerUrl must use the https scheme."));
        }
        if rec.identity_providers.contains_key(&oidc.identity_provider_config_name) {
            return Err(errors::resource_in_use(format!(
                "Identity provider config {} already exists.",
                oidc.identity_provider_config_name
            ))
            .with_field("clusterName", text(&cluster)));
        }
        if !rec.identity_providers.is_empty() {
            return Err(errors::invalid_request(
                "A cluster can have only one OIDC identity provider config associated.",
            )
            .with_field("clusterName", text(&cluster)));
        }
        let name = oidc.identity_provider_config_name.clone();
        let config = types::OidcIdentityProviderConfig {
            identity_provider_config_name: Some(name.clone()),
            identity_provider_config_arn: Some(util::arn(
                ctx,
                &format!("identityproviderconfig/{cluster}/oidc/{name}/{}", util::uuid()),
            )),
            cluster_name: Some(cluster.clone()),
            issuer_url: Some(oidc.issuer_url.clone()),
            client_id: Some(oidc.client_id.clone()),
            username_claim: oidc.username_claim.clone(),
            username_prefix: oidc.username_prefix.clone(),
            groups_claim: oidc.groups_claim.clone(),
            groups_prefix: oidc.groups_prefix.clone(),
            required_claims: oidc.required_claims.clone(),
            tags: Some(input.tags.clone().unwrap_or_default()),
            status: Some("CREATING".into()),
        };
        rec.identity_providers.insert(name.clone(), config);
        rec.cluster.status = Some("UPDATING".into());
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            "AssociateIdentityProviderConfig",
            vec![param("IdentityProviderConfig", format!("[{{\"type\":\"oidc\",\"name\":\"{name}\"}}]"))],
            None,
        );
        Ok(types::AssociateIdentityProviderConfigResponse { update: Some(update), tags: input.tags.clone() })
    }

    pub(crate) async fn describe_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::DescribeIdentityProviderConfigRequest,
    ) -> Result<types::DescribeIdentityProviderConfigResponse, ServiceError> {
        let idp = &input.identity_provider_config;
        check_idp_type(&idp.r#type)?;
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let p = rec.identity_providers.get(&idp.name).ok_or_else(|| idp_not_found(&input.cluster_name, &idp.name))?;
        util::authorize(
            ctx,
            "DescribeIdentityProviderConfig",
            p.identity_provider_config_arn.as_deref().unwrap_or_default(),
            p.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeIdentityProviderConfigResponse {
            identity_provider_config: Some(types::IdentityProviderConfigResponse { oidc: Some(p.clone()) }),
        })
    }

    pub(crate) async fn list_identity_provider_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListIdentityProviderConfigsRequest,
    ) -> Result<types::ListIdentityProviderConfigsResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "ListIdentityProviderConfigs",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let all: Vec<types::IdentityProviderConfig> = rec
            .identity_providers
            .keys()
            .map(|n| types::IdentityProviderConfig { r#type: "oidc".into(), name: n.clone() })
            .collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListIdentityProviderConfigsResponse { identity_provider_configs: Some(items), next_token: next })
    }

    pub(crate) async fn disassociate_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateIdentityProviderConfigRequest,
    ) -> Result<types::DisassociateIdentityProviderConfigResponse, ServiceError> {
        let idp = &input.identity_provider_config;
        check_idp_type(&idp.r#type)?;
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let p =
            rec.identity_providers.get_mut(&idp.name).ok_or_else(|| idp_not_found(&input.cluster_name, &idp.name))?;
        util::authorize(
            ctx,
            "DisassociateIdentityProviderConfig",
            p.identity_provider_config_arn.as_deref().unwrap_or_default(),
            p.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        if p.status.as_deref() == Some("DELETING") {
            return Err(errors::resource_in_use(format!("Identity provider config {} is being deleted.", idp.name))
                .with_field("clusterName", text(&input.cluster_name)));
        }
        p.status = Some("DELETING".into());
        rec.cluster.status = Some("UPDATING".into());
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            "DisassociateIdentityProviderConfig",
            vec![param("IdentityProviderConfig", format!("[{{\"type\":\"oidc\",\"name\":\"{}\"}}]", idp.name))],
            None,
        );
        Ok(types::DisassociateIdentityProviderConfigResponse { update: Some(update) })
    }

    pub(crate) async fn create_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::CreatePodIdentityAssociationRequest,
    ) -> Result<types::CreatePodIdentityAssociationResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            util::authorize(
                ctx,
                "CreatePodIdentityAssociation",
                &cluster_arn,
                rec.cluster.tags.as_ref(),
                input.tags.as_ref(),
                ConditionContext::new(),
            )?;
        }
        util::check_create_tags(input.tags.as_ref())?;
        check_session_policy(input.policy.as_deref())?;
        self.check_pod_role(ctx, &input.role_arn)?;
        if let Some(target) = &input.target_role_arn {
            if util::iam_principal(target).is_none_or(|(_, k, _)| k != "role") {
                return Err(errors::invalid_parameter(format!("The targetRoleArn {target} is not an IAM role ARN.")));
            }
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        if rec.pod_identities.values().any(|p| {
            p.namespace.as_deref() == Some(input.namespace.as_str())
                && p.service_account.as_deref() == Some(input.service_account.as_str())
        }) {
            return Err(errors::resource_in_use(format!(
                "Association already exists for service account {} in namespace {}.",
                input.service_account, input.namespace
            ))
            .with_field("clusterName", text(&cluster)));
        }
        let mut assoc = new_association(
            ctx,
            &cluster,
            &input.namespace,
            &input.service_account,
            &input.role_arn,
            input.tags.clone(),
            None,
        );
        assoc.disable_session_tags = Some(input.disable_session_tags.unwrap_or(false));
        if input.target_role_arn.is_some() {
            assoc.target_role_arn = input.target_role_arn.clone();
            assoc.external_id = Some(util::uuid());
        }
        assoc.policy = input.policy.clone();
        rec.pod_identities.insert(assoc.association_id.clone().unwrap_or_default(), assoc.clone());
        Ok(types::CreatePodIdentityAssociationResponse { association: Some(assoc) })
    }

    pub(crate) async fn describe_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::DescribePodIdentityAssociationRequest,
    ) -> Result<types::DescribePodIdentityAssociationResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let p = rec
            .pod_identities
            .get(&input.association_id)
            .ok_or_else(|| association_not_found(&input.association_id))?;
        util::authorize(
            ctx,
            "DescribePodIdentityAssociation",
            p.association_arn.as_deref().unwrap_or_default(),
            p.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribePodIdentityAssociationResponse { association: Some(p.clone()) })
    }

    pub(crate) async fn list_pod_identity_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListPodIdentityAssociationsRequest,
    ) -> Result<types::ListPodIdentityAssociationsResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "ListPodIdentityAssociations",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let mut all: Vec<&types::PodIdentityAssociation> = rec
            .pod_identities
            .values()
            .filter(|p| input.namespace.as_ref().is_none_or(|n| p.namespace.as_ref() == Some(n)))
            .filter(|p| input.service_account.as_ref().is_none_or(|s| p.service_account.as_ref() == Some(s)))
            .collect();
        all.sort_by_key(|p| p.created_at);
        let summaries: Vec<types::PodIdentityAssociationSummary> = all
            .into_iter()
            .map(|p| types::PodIdentityAssociationSummary {
                cluster_name: p.cluster_name.clone(),
                namespace: p.namespace.clone(),
                service_account: p.service_account.clone(),
                association_arn: p.association_arn.clone(),
                association_id: p.association_id.clone(),
                owner_arn: p.owner_arn.clone(),
            })
            .collect();
        let (items, next) = util::page(&summaries, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPodIdentityAssociationsResponse { associations: Some(items), next_token: next })
    }

    pub(crate) async fn update_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePodIdentityAssociationRequest,
    ) -> Result<types::UpdatePodIdentityAssociationResponse, ServiceError> {
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
            let p = rec
                .pod_identities
                .get(&input.association_id)
                .ok_or_else(|| association_not_found(&input.association_id))?;
            util::authorize(
                ctx,
                "UpdatePodIdentityAssociation",
                p.association_arn.as_deref().unwrap_or_default(),
                p.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
            if let Some(owner) = &p.owner_arn {
                return Err(errors::invalid_request(format!(
                    "The Pod Identity association {} is managed by {owner}. Update it through the add-on.",
                    input.association_id
                )));
            }
        }
        check_session_policy(input.policy.as_deref())?;
        if let Some(role) = &input.role_arn {
            self.check_pod_role(ctx, role)?;
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let p = rec
            .pod_identities
            .get_mut(&input.association_id)
            .ok_or_else(|| association_not_found(&input.association_id))?;
        if let Some(r) = input.role_arn {
            p.role_arn = Some(r);
        }
        if let Some(d) = input.disable_session_tags {
            p.disable_session_tags = Some(d);
        }
        if let Some(t) = input.target_role_arn {
            if t.is_empty() {
                p.target_role_arn = None;
                p.external_id = None;
            } else {
                if p.target_role_arn.as_deref() != Some(t.as_str()) {
                    p.external_id = Some(util::uuid());
                }
                p.target_role_arn = Some(t);
            }
        }
        if let Some(policy) = input.policy {
            p.policy = (!policy.is_empty()).then_some(policy);
        }
        p.modified_at = Some(ctx.received_at);
        Ok(types::UpdatePodIdentityAssociationResponse { association: Some(p.clone()) })
    }

    pub(crate) async fn delete_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::DeletePodIdentityAssociationRequest,
    ) -> Result<types::DeletePodIdentityAssociationResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let p = rec
            .pod_identities
            .get(&input.association_id)
            .ok_or_else(|| association_not_found(&input.association_id))?;
        util::authorize(
            ctx,
            "DeletePodIdentityAssociation",
            p.association_arn.as_deref().unwrap_or_default(),
            p.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        if let Some(owner) = &p.owner_arn {
            return Err(errors::invalid_request(format!(
                "The Pod Identity association {} is managed by {owner}. Remove it through the add-on.",
                input.association_id
            )));
        }
        let p = rec.pod_identities.remove(&input.association_id).expect("checked");
        Ok(types::DeletePodIdentityAssociationResponse { association: Some(p) })
    }
}
