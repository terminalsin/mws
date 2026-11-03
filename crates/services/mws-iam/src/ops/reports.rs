//! Access advisor reports: service last accessed details, the Organizations
//! access report, and ListPoliciesGrantingServiceAccess.
//!
//! The authorizer records when each user and role authenticates to each
//! service (see [`crate::activity`]); reports list the services an entity's
//! policies allow, with that history.

use chrono::Utc;
use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{ReportJob, State};
use crate::Iam;

/// Service namespaces and their display names, as access advisor shows them.
const SERVICES: &[(&str, &str)] = &[
    ("acm", "AWS Certificate Manager"),
    ("acm-pca", "AWS Private Certificate Authority"),
    ("cloudformation", "AWS CloudFormation"),
    ("cloudfront", "Amazon CloudFront"),
    ("cloudtrail", "AWS CloudTrail"),
    ("cloudwatch", "Amazon CloudWatch"),
    ("dynamodb", "Amazon DynamoDB"),
    ("ec2", "Amazon EC2"),
    ("ecr", "Amazon Elastic Container Registry"),
    ("ecs", "Amazon Elastic Container Service"),
    ("eks", "Amazon Elastic Kubernetes Service"),
    ("elasticloadbalancing", "Elastic Load Balancing"),
    ("events", "Amazon EventBridge"),
    ("iam", "AWS Identity and Access Management"),
    ("kms", "AWS Key Management Service"),
    ("lambda", "AWS Lambda"),
    ("logs", "Amazon CloudWatch Logs"),
    ("organizations", "AWS Organizations"),
    ("rds", "Amazon RDS"),
    ("route53", "Amazon Route 53"),
    ("route53domains", "Amazon Route 53 Domains"),
    ("s3", "Amazon S3"),
    ("secretsmanager", "AWS Secrets Manager"),
    ("sns", "Amazon SNS"),
    ("sqs", "Amazon SQS"),
    ("ssm", "AWS Systems Manager"),
    ("sts", "AWS Security Token Service"),
];

fn service_name(ns: &str) -> String {
    SERVICES.iter().find(|(n, _)| *n == ns).map(|(_, name)| name.to_string()).unwrap_or_else(|| ns.to_string())
}

/// Service namespaces a policy document allows actions in.
fn allowed_namespaces(doc: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(doc) else { return vec![] };
    let statements = match &v["Statement"] {
        Value::Array(a) => a.clone(),
        s @ Value::Object(_) => vec![s.clone()],
        _ => vec![],
    };
    let mut out = vec![];
    for s in statements.iter().filter(|s| s["Effect"] == "Allow") {
        let actions = match &s["Action"] {
            Value::String(a) => vec![a.clone()],
            Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => vec![],
        };
        for a in actions {
            let ns = a.split(':').next().unwrap_or_default().to_lowercase();
            let matched: Vec<String> = if ns.contains('*') || ns.contains('?') {
                SERVICES.iter().filter(|(n, _)| glob(&ns, n)).map(|(n, _)| n.to_string()).collect()
            } else {
                vec![ns]
            };
            out.extend(matched);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn glob(pattern: &str, text: &str) -> bool {
    match (pattern.chars().next(), text.chars().next()) {
        (None, None) => true,
        (Some('*'), _) => glob(&pattern[1..], text) || (!text.is_empty() && glob(pattern, &text[1..])),
        (Some('?'), Some(c)) => glob(&pattern[1..], &text[c.len_utf8()..]),
        (Some(p), Some(c)) if p == c => glob(&pattern[p.len_utf8()..], &text[c.len_utf8()..]),
        _ => false,
    }
}

/// A policy that applies to an entity.
struct Applied {
    name: String,
    kind: &'static str,
    arn: Option<String>,
    owner: Option<(&'static str, String)>,
    document: String,
}

/// What an ARN names, for access advisor.
enum Entity {
    User(String),
    Group(String),
    Role(String),
    Policy(String),
}

fn resolve(state: &State, arn: &str) -> Option<Entity> {
    if state.policies.contains_key(arn) {
        return Some(Entity::Policy(arn.to_string()));
    }
    if let Some(u) = state.users.values().find(|u| u.arn == arn) {
        return Some(Entity::User(u.name.clone()));
    }
    if let Some(g) = state.groups.values().find(|g| g.arn == arn) {
        return Some(Entity::Group(g.name.clone()));
    }
    state.roles.values().find(|r| r.arn == arn).map(|r| Entity::Role(r.name.clone()))
}

fn managed(
    state: &State,
    arns: &std::collections::BTreeSet<String>,
    owner: Option<(&'static str, String)>,
) -> Vec<Applied> {
    arns.iter()
        .filter_map(|a| state.policies.get(a))
        .map(|p| Applied {
            name: p.name.clone(),
            kind: "MANAGED",
            arn: Some(p.arn.clone()),
            owner: owner.clone(),
            document: p.default_document().to_string(),
        })
        .collect()
}

fn inline(map: &std::collections::BTreeMap<String, String>, owner: (&'static str, String)) -> Vec<Applied> {
    map.iter()
        .map(|(n, d)| Applied {
            name: n.clone(),
            kind: "INLINE",
            arn: None,
            owner: Some(owner.clone()),
            document: d.clone(),
        })
        .collect()
}

fn group_policies(state: &State, name: &str) -> Vec<Applied> {
    let Some(g) = state.group(name) else { return vec![] };
    let mut out = inline(&g.inline, ("GROUP", g.name.clone()));
    out.extend(managed(state, &g.attached, Some(("GROUP", g.name.clone()))));
    out
}

fn applied(state: &State, entity: &Entity) -> Vec<Applied> {
    match entity {
        Entity::User(n) => {
            let Some(u) = state.user(n) else { return vec![] };
            let mut out = inline(&u.inline, ("USER", u.name.clone()));
            out.extend(managed(state, &u.attached, Some(("USER", u.name.clone()))));
            for g in state.groups_for_user(n) {
                out.extend(group_policies(state, &g.name));
            }
            out
        }
        Entity::Group(n) => group_policies(state, n),
        Entity::Role(n) => {
            let Some(r) = state.role(n) else { return vec![] };
            let mut out = inline(&r.inline, ("ROLE", r.name.clone()));
            out.extend(managed(state, &r.attached, Some(("ROLE", r.name.clone()))));
            out
        }
        Entity::Policy(arn) => managed(state, &std::iter::once(arn.clone()).collect(), None),
    }
}

/// The user and role ARNs whose activity a report on `entity` covers.
fn covered_arns(state: &State, entity: &Entity) -> Vec<String> {
    match entity {
        Entity::User(n) => state.user(n).map(|u| vec![u.arn.clone()]).unwrap_or_default(),
        Entity::Role(n) => state.role(n).map(|r| vec![r.arn.clone()]).unwrap_or_default(),
        Entity::Group(n) => {
            let key = n.to_lowercase();
            let Some(g) = state.groups.get(&key) else { return vec![] };
            state.users.values().filter(|u| g.members.contains(&u.name.to_lowercase())).map(|u| u.arn.clone()).collect()
        }
        Entity::Policy(arn) => {
            let mut out: Vec<String> =
                state.users.values().filter(|u| u.attached.contains(arn)).map(|u| u.arn.clone()).collect();
            out.extend(state.roles.values().filter(|r| r.attached.contains(arn)).map(|r| r.arn.clone()));
            for g in state.groups.values().filter(|g| g.attached.contains(arn)) {
                out.extend(
                    state.users.values().filter(|u| g.members.contains(&u.name.to_lowercase())).map(|u| u.arn.clone()),
                );
            }
            out.sort();
            out.dedup();
            out
        }
    }
}

/// The latest access to `namespace` among `arns`: (when, region, who), and
/// how many of them used it.
fn latest_access(
    state: &State,
    arns: &[String],
    namespace: &str,
) -> (Option<(chrono::DateTime<Utc>, String, String)>, i32) {
    let mut latest: Option<(chrono::DateTime<Utc>, String, String)> = None;
    let mut count = 0;
    for arn in arns {
        if let Some(a) = state.service_access.get(arn).and_then(|m| m.get(namespace)) {
            count += 1;
            if latest.as_ref().is_none_or(|l| a.at > l.0) {
                latest = Some((a.at, a.region.clone(), arn.clone()));
            }
        }
    }
    (latest, count)
}

/// Tracked actions of `namespace` that `arns` used, latest use of each.
fn tracked_actions(state: &State, arns: &[String], namespace: &str) -> Vec<types::TrackedActionLastAccessed> {
    let mut by_action: std::collections::BTreeMap<String, (chrono::DateTime<Utc>, String, String)> =
        std::collections::BTreeMap::new();
    for arn in arns {
        let Some(a) = state.service_access.get(arn).and_then(|m| m.get(namespace)) else { continue };
        for (action, (at, region)) in &a.actions {
            let entry = by_action.entry(action.clone()).or_insert_with(|| (*at, region.clone(), arn.clone()));
            if *at > entry.0 {
                *entry = (*at, region.clone(), arn.clone());
            }
        }
    }
    by_action
        .into_iter()
        .map(|(action, (at, region, arn))| types::TrackedActionLastAccessed {
            action_name: Some(action),
            last_accessed_entity: Some(arn),
            last_accessed_time: Some(at),
            last_accessed_region: Some(region),
        })
        .collect()
}

fn no_such_job(id: &str) -> ServiceError {
    errors::no_such_entity(format!("No report job found with id {id}"))
}

impl Iam {
    pub fn generate_service_last_accessed_details(
        &self,
        ctx: &RequestContext,
        input: types::GenerateServiceLastAccessedDetailsRequest,
    ) -> Result<types::GenerateServiceLastAccessedDetailsResponse, ServiceError> {
        self.authorize(ctx, "GenerateServiceLastAccessedDetails", &input.arn)?;
        let granularity = input.granularity.unwrap_or_else(|| "SERVICE_LEVEL".into());
        if granularity != "SERVICE_LEVEL" && granularity != "ACTION_LEVEL" {
            return Err(validation(format!(
                "1 validation error detected: Value '{granularity}' at 'granularity' failed to satisfy constraint: Member must satisfy enum value set: [SERVICE_LEVEL, ACTION_LEVEL]"
            )));
        }
        let mut state = self.write();
        if resolve(&state, &input.arn).is_none() {
            return Err(errors::no_such_entity(format!("The entity {} cannot be found.", input.arn)));
        }
        let id = uuid::Uuid::new_v4().to_string();
        state.report_jobs.insert(
            id.clone(),
            ReportJob { id: id.clone(), kind: "service".into(), arn: input.arn, granularity, created: Utc::now() },
        );
        Ok(types::GenerateServiceLastAccessedDetailsResponse { job_id: Some(id) })
    }

    pub fn get_service_last_accessed_details(
        &self,
        ctx: &RequestContext,
        input: types::GetServiceLastAccessedDetailsRequest,
    ) -> Result<types::GetServiceLastAccessedDetailsResponse, ServiceError> {
        self.authorize(ctx, "GetServiceLastAccessedDetails", "*")?;
        let state = self.read();
        let job = state
            .report_jobs
            .get(&input.job_id)
            .filter(|j| j.kind == "service")
            .ok_or_else(|| no_such_job(&input.job_id))?;
        let entity = resolve(&state, &job.arn);
        let mut namespaces: Vec<String> = match &entity {
            Some(e) => applied(&state, e).iter().flat_map(|a| allowed_namespaces(&a.document)).collect(),
            None => vec![],
        };
        namespaces.sort();
        namespaces.dedup();
        let arns = entity.as_ref().map(|e| covered_arns(&state, e)).unwrap_or_default();
        let action_level = job.granularity == "ACTION_LEVEL";
        let all: Vec<types::ServiceLastAccessed> = namespaces
            .into_iter()
            .map(|ns| {
                let (latest, count) = latest_access(&state, &arns, &ns);
                let tracked = (action_level && crate::activity::ACTION_TRACKED.contains(&ns.as_str()))
                    .then(|| tracked_actions(&state, &arns, &ns));
                // Only reports on groups and policies name the entity.
                let many = matches!(entity, Some(Entity::Group(_)) | Some(Entity::Policy(_)));
                types::ServiceLastAccessed {
                    service_name: service_name(&ns),
                    last_authenticated: latest.as_ref().map(|l| l.0),
                    last_authenticated_entity: latest.as_ref().filter(|_| many).map(|l| l.2.clone()),
                    last_authenticated_region: latest.as_ref().map(|l| l.1.clone()),
                    total_authenticated_entities: Some(count),
                    tracked_actions_last_accessed: tracked,
                    service_namespace: ns,
                }
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |s| s.service_namespace.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::GetServiceLastAccessedDetailsResponse {
            job_status: "COMPLETED".into(),
            job_type: Some(job.granularity.clone()),
            job_creation_date: job.created,
            services_last_accessed: page,
            job_completion_date: job.created,
            is_truncated: truncated,
            marker,
            error: None,
        })
    }

    pub fn get_service_last_accessed_details_with_entities(
        &self,
        ctx: &RequestContext,
        input: types::GetServiceLastAccessedDetailsWithEntitiesRequest,
    ) -> Result<types::GetServiceLastAccessedDetailsWithEntitiesResponse, ServiceError> {
        self.authorize(ctx, "GetServiceLastAccessedDetailsWithEntities", "*")?;
        let state = self.read();
        let job = state
            .report_jobs
            .get(&input.job_id)
            .filter(|j| j.kind == "service")
            .ok_or_else(|| no_such_job(&input.job_id))?;
        let ns = input.service_namespace.to_lowercase();
        let grants = |e: &Entity| applied(&state, e).iter().any(|a| allowed_namespaces(&a.document).contains(&ns));
        let info = |kind: &str, arn: &str, name: &str, id: &str, path: &str| types::EntityDetails {
            entity_info: types::EntityInfo {
                arn: arn.into(),
                name: name.into(),
                r#type: kind.into(),
                id: id.into(),
                path: Some(path.into()),
            },
            last_authenticated: match kind {
                // A group's last access is its most recent member's.
                "GROUP" => {
                    let members = covered_arns(&state, &Entity::Group(name.to_string()));
                    latest_access(&state, &members, &ns).0.map(|l| l.0)
                }
                _ => state.service_access.get(arn).and_then(|m| m.get(&ns)).map(|a| a.at),
            },
        };
        let mut entities = vec![];
        match resolve(&state, &job.arn) {
            Some(Entity::Group(g)) => {
                let key = g.to_lowercase();
                for u in state
                    .users
                    .values()
                    .filter(|u| state.groups.get(&key).is_some_and(|g| g.members.contains(&u.name.to_lowercase())))
                {
                    if grants(&Entity::User(u.name.clone())) {
                        entities.push(info("USER", &u.arn, &u.name, &u.id, &u.path));
                    }
                }
            }
            Some(Entity::Policy(arn)) => {
                for u in state.users.values().filter(|u| u.attached.contains(&arn)) {
                    entities.push(info("USER", &u.arn, &u.name, &u.id, &u.path));
                }
                for g in state.groups.values().filter(|g| g.attached.contains(&arn)) {
                    entities.push(info("GROUP", &g.arn, &g.name, &g.id, &g.path));
                }
                for r in state.roles.values().filter(|r| r.attached.contains(&arn)) {
                    entities.push(info("ROLE", &r.arn, &r.name, &r.id, &r.path));
                }
                if !allowed_namespaces(state.policies[&arn].default_document()).contains(&ns) {
                    entities.clear();
                }
            }
            _ => {
                return Err(errors::invalid_input(
                    "Entity details are only available for reports generated for a group or a policy.",
                ))
            }
        }
        let (page, truncated, marker) =
            paginate(&entities, |e| e.entity_info.arn.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::GetServiceLastAccessedDetailsWithEntitiesResponse {
            job_status: "COMPLETED".into(),
            job_creation_date: job.created,
            job_completion_date: job.created,
            entity_details_list: page,
            is_truncated: truncated,
            marker,
            error: None,
        })
    }

    pub fn list_policies_granting_service_access(
        &self,
        ctx: &RequestContext,
        input: types::ListPoliciesGrantingServiceAccessRequest,
    ) -> Result<types::ListPoliciesGrantingServiceAccessResponse, ServiceError> {
        self.authorize(ctx, "ListPoliciesGrantingServiceAccess", &input.arn)?;
        let state = self.read();
        let entity = match resolve(&state, &input.arn) {
            Some(Entity::Policy(_)) | None => {
                return Err(errors::no_such_entity(format!("The entity {} cannot be found.", input.arn)))
            }
            Some(e) => e,
        };
        let policies = applied(&state, &entity);
        let all: Vec<types::ListPoliciesGrantingServiceAccessEntry> = input
            .service_namespaces
            .iter()
            .map(|ns| types::ListPoliciesGrantingServiceAccessEntry {
                service_namespace: Some(ns.clone()),
                policies: Some(
                    policies
                        .iter()
                        .filter(|p| allowed_namespaces(&p.document).contains(&ns.to_lowercase()))
                        .map(|p| types::PolicyGrantingServiceAccess {
                            policy_name: p.name.clone(),
                            policy_type: p.kind.into(),
                            policy_arn: p.arn.clone(),
                            entity_type: p.owner.as_ref().filter(|_| p.kind == "INLINE").map(|o| o.0.to_string()),
                            entity_name: p.owner.as_ref().filter(|_| p.kind == "INLINE").map(|o| o.1.clone()),
                        })
                        .collect(),
                ),
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |e| e.service_namespace.clone().unwrap_or_default(), input.marker.as_deref(), None)?;
        Ok(types::ListPoliciesGrantingServiceAccessResponse {
            policies_granting_service_access: page,
            is_truncated: truncated,
            marker,
        })
    }

    pub fn generate_organizations_access_report(
        &self,
        ctx: &RequestContext,
        input: types::GenerateOrganizationsAccessReportRequest,
    ) -> Result<types::GenerateOrganizationsAccessReportResponse, ServiceError> {
        self.authorize(ctx, "GenerateOrganizationsAccessReport", "*")?;
        let id = uuid::Uuid::new_v4().to_string();
        self.write().report_jobs.insert(
            id.clone(),
            ReportJob {
                id: id.clone(),
                kind: "organizations".into(),
                arn: input.entity_path,
                granularity: String::new(),
                created: Utc::now(),
            },
        );
        Ok(types::GenerateOrganizationsAccessReportResponse { job_id: Some(id) })
    }

    pub fn get_organizations_access_report(
        &self,
        ctx: &RequestContext,
        input: types::GetOrganizationsAccessReportRequest,
    ) -> Result<types::GetOrganizationsAccessReportResponse, ServiceError> {
        self.authorize(ctx, "GetOrganizationsAccessReport", "*")?;
        let org = self.organization_of(&ctx.caller.account_id);
        let state = self.read();
        let job = state
            .report_jobs
            .get(&input.job_id)
            .filter(|j| j.kind == "organizations")
            .ok_or_else(|| no_such_job(&input.job_id))?;
        let error = |code: &str, message: &str| types::GetOrganizationsAccessReportResponse {
            job_status: "FAILED".into(),
            job_creation_date: job.created,
            job_completion_date: Some(job.created),
            error_details: Some(types::ErrorDetails { message: message.into(), code: code.into() }),
            ..Default::default()
        };
        let Some(org) = org else {
            return Ok(error(
                "OrganizationNotFoundException",
                "The request was rejected because no organization is associated with your account.",
            ));
        };
        if !org.is_management(&ctx.caller.account_id) {
            return Ok(error(
                "AccessDeniedException",
                "Organizations access reports can only be generated from the management account.",
            ));
        }
        if !job.arn.starts_with(&format!("{}/", org.organization_id)) {
            return Ok(error("InvalidEntityPath", "The entity path is not part of your organization."));
        }
        let created = job.created;
        let path = job.arn.clone();
        drop(state);
        let details = self.organizations_access_details(&path);
        let accessible = details.len() as i32;
        let not_accessed = details.iter().filter(|d| d.last_authenticated_time.is_none()).count() as i32;
        let (page, truncated, marker) = paginate(
            &details,
            |d| format!("{}|{}", d.service_namespace, d.entity_path.clone().unwrap_or_default()),
            input.marker.as_deref(),
            input.max_items,
        )?;
        Ok(types::GetOrganizationsAccessReportResponse {
            job_status: "COMPLETED".into(),
            job_creation_date: created,
            job_completion_date: Some(created),
            number_of_services_accessible: Some(accessible),
            number_of_services_not_accessed: Some(not_accessed),
            access_details: Some(page),
            is_truncated: truncated,
            marker,
            error_details: None,
        })
    }
}

impl Iam {
    /// For each service the SCPs on `path` allow, the latest access by any
    /// account under `path` (an organization entity path such as
    /// `o-a1b2c3d4e5/r-ab12/ou-ab12-11111111` or one ending in an account id).
    fn organizations_access_details(&self, path: &str) -> Vec<types::AccessDetail> {
        // Ask Organizations before taking the IAM lock.
        let account_ids: Vec<String> =
            self.inner.accounts.read().expect("IAM state lock poisoned").keys().cloned().collect();
        let mut under: Vec<(String, String, Option<Vec<crate::org::PolicyLevel>>)> = vec![];
        for id in account_ids {
            let Some(org) = self.organization_of(&id) else { continue };
            let full = format!("{}{id}", org.org_path);
            let full = full.trim_end_matches('/');
            if full == path || full.starts_with(&format!("{path}/")) {
                under.push((id, full.to_string(), org.service_control_policies.clone()));
            }
        }
        let accounts = self.inner.accounts.read().expect("IAM state lock poisoned");
        let mut out = vec![];
        for (ns, display) in SERVICES {
            // SCPs must allow the service at every level for some account.
            let allowed = |levels: &Option<Vec<crate::org::PolicyLevel>>| match levels {
                None => true,
                Some(levels) => levels
                    .iter()
                    .all(|level| level.iter().any(|(_, doc)| allowed_namespaces(doc).iter().any(|n| n == ns))),
            };
            if !under.iter().any(|(_, _, scps)| allowed(scps)) {
                continue;
            }
            let mut latest: Option<(chrono::DateTime<Utc>, String, String)> = None;
            let mut entities = 0;
            for (id, full, _) in &under {
                let Some(a) = accounts.get(id).and_then(|s| s.account_service_access.get(*ns)) else { continue };
                entities += a.entities.len().max(1) as i32;
                if latest.as_ref().is_none_or(|l| a.at > l.0) {
                    latest = Some((a.at, a.region.clone(), full.clone()));
                }
            }
            out.push(types::AccessDetail {
                service_name: display.to_string(),
                service_namespace: ns.to_string(),
                region: latest.as_ref().map(|l| l.1.clone()),
                entity_path: latest.as_ref().map(|l| l.2.clone()),
                last_authenticated_time: latest.as_ref().map(|l| l.0),
                total_authenticated_entities: latest.as_ref().map(|_| entities),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_from_documents() {
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","IAM:List*"],"Resource":"*"},{"Effect":"Deny","Action":"kms:*","Resource":"*"}]}"#;
        assert_eq!(allowed_namespaces(doc), vec!["iam", "s3"]);
        let star = r#"{"Statement":{"Effect":"Allow","Action":"route*:*","Resource":"*"}}"#;
        assert_eq!(allowed_namespaces(star), vec!["route53", "route53domains"]);
    }
}
