//! Service-linked roles, and role templates (which only AWS publishes, so a
//! standalone MWS account has none).

use chrono::Utc;
use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{DeletionTask, Role};
use crate::{ids, wire, Iam};

/// Role name stems AWS uses for well-known services; others are derived
/// from the service principal.
const KNOWN: &[(&str, &str)] = &[
    ("autoscaling.amazonaws.com", "AutoScaling"),
    ("elasticloadbalancing.amazonaws.com", "ElasticLoadBalancing"),
    ("ecs.amazonaws.com", "ECS"),
    ("eks.amazonaws.com", "AmazonEKS"),
    ("rds.amazonaws.com", "RDS"),
    ("organizations.amazonaws.com", "Organizations"),
    ("support.amazonaws.com", "Support"),
    ("trustedadvisor.amazonaws.com", "TrustedAdvisor"),
    ("config.amazonaws.com", "Config"),
    ("cloudtrail.amazonaws.com", "CloudTrail"),
    ("ssm.amazonaws.com", "AmazonSSM"),
    ("lambda.amazonaws.com", "Lambda"),
    ("guardduty.amazonaws.com", "AmazonGuardDuty"),
    ("route53resolver.amazonaws.com", "Route53Resolver"),
    ("acm.amazonaws.com", "CertificateManager"),
];

fn stem(service: &str) -> String {
    if let Some((_, s)) = KNOWN.iter().find(|(svc, _)| *svc == service) {
        return s.to_string();
    }
    service
        .trim_end_matches(".amazonaws.com")
        .split(['.', '-'])
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
        })
        .collect()
}

fn is_service_linked(r: &Role) -> bool {
    r.path.starts_with("/aws-service-role/")
}

pub(crate) fn protected(name: &str) -> ServiceError {
    errors::unmodifiable_entity(format!(
        "Cannot perform the operation on the protected role '{name}' - this role is only modifiable by AWS"
    ))
}

fn no_template(arn: &str) -> ServiceError {
    errors::no_such_entity(format!("The role template with ARN {arn} cannot be found."))
}

impl Iam {
    pub fn create_service_linked_role(
        &self,
        ctx: &RequestContext,
        input: types::CreateServiceLinkedRoleRequest,
    ) -> Result<types::CreateServiceLinkedRoleResponse, ServiceError> {
        let service = input.aws_service_name.to_lowercase();
        if !service.ends_with(".amazonaws.com") || service.split('.').count() < 3 {
            return Err(errors::invalid_input(format!("Unrecognized service principal: {}", input.aws_service_name)));
        }
        let mut name = format!("AWSServiceRoleFor{}", stem(&service));
        if let Some(s) = &input.custom_suffix {
            name = format!("{name}_{s}");
        }
        let path = format!("/aws-service-role/{service}/");
        let arn = self.entity_arn("role", &path, &name);
        self.authorize_with(ctx, "CreateServiceLinkedRole", &arn, single("iam:AWSServiceName", service.clone()))?;
        let mut state = self.write();
        let key = name.to_lowercase();
        if state.roles.contains_key(&key) {
            return Err(errors::invalid_input(format!(
                "Service role name {name} has been taken in this account, please try a different suffix."
            )));
        }
        let policy_arn = format!(
            "arn:{}:iam::aws:policy/aws-service-role/{}ServiceRolePolicy",
            self.inner.config.partition,
            stem(&service)
        );
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
        );
        let role = Role {
            name,
            path,
            id: ids::unique_id("AROA"),
            arn,
            created: Utc::now(),
            trust_policy: trust,
            description: input.description,
            max_session_duration: 3600,
            permissions_boundary: None,
            tags: vec![],
            inline: Default::default(),
            attached: state.policies.contains_key(&policy_arn).then(|| policy_arn.clone()).into_iter().collect(),
            last_used: None,
        };
        let mut out = wire::role(&role);
        out.role_last_used = None;
        state.roles.insert(key, role);
        Ok(types::CreateServiceLinkedRoleResponse { role: Some(out) })
    }

    pub fn delete_service_linked_role(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServiceLinkedRoleRequest,
    ) -> Result<types::DeleteServiceLinkedRoleResponse, ServiceError> {
        self.authorize(ctx, "DeleteServiceLinkedRole", &self.role_arn_or_default(&input.role_name))?;
        let mut state = self.write();
        let role = state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if !is_service_linked(role) {
            return Err(errors::invalid_input(format!("Role {} is not a service-linked role.", input.role_name)));
        }
        let service = role.path.trim_start_matches("/aws-service-role/").trim_end_matches('/').to_string();
        let id = format!("task/aws-service-role/{service}/{}/{}", role.name, uuid::Uuid::new_v4());
        state.roles.remove(&input.role_name.to_lowercase());
        state
            .deletion_tasks
            .insert(id.clone(), DeletionTask { id: id.clone(), role: input.role_name, status: "SUCCEEDED".into() });
        Ok(types::DeleteServiceLinkedRoleResponse { deletion_task_id: id })
    }

    pub fn get_service_linked_role_deletion_status(
        &self,
        ctx: &RequestContext,
        input: types::GetServiceLinkedRoleDeletionStatusRequest,
    ) -> Result<types::GetServiceLinkedRoleDeletionStatusResponse, ServiceError> {
        self.authorize(ctx, "GetServiceLinkedRoleDeletionStatus", "*")?;
        if !input.deletion_task_id.starts_with("task/aws-service-role/") {
            return Err(errors::invalid_input(format!("Invalid deletion task id: {}", input.deletion_task_id)));
        }
        let state = self.read();
        let task = state.deletion_tasks.get(&input.deletion_task_id).ok_or_else(|| {
            errors::no_such_entity(format!("Deletion task {} cannot be found.", input.deletion_task_id))
        })?;
        Ok(types::GetServiceLinkedRoleDeletionStatusResponse { status: task.status.clone(), reason: None })
    }

    pub fn get_role_template_version(
        &self,
        ctx: &RequestContext,
        input: types::GetRoleTemplateVersionRequest,
    ) -> Result<types::GetRoleTemplateVersionResponse, ServiceError> {
        self.authorize(ctx, "GetRoleTemplateVersion", &input.template_arn)?;
        Err(no_template(&input.template_arn))
    }

    pub fn acquire_role(
        &self,
        ctx: &RequestContext,
        input: types::AcquireRoleRequest,
    ) -> Result<types::AcquireRoleResponse, ServiceError> {
        self.authorize(ctx, "AcquireRole", &input.template_arn)?;
        Err(no_template(&input.template_arn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names() {
        assert_eq!(stem("elasticloadbalancing.amazonaws.com"), "ElasticLoadBalancing");
        assert_eq!(stem("custom-thing.amazonaws.com"), "CustomThing");
    }
}
