//! The webhooks a cluster's API server calls: token review (who is this
//! bearer token?) and subject access review (may they do this?).
//!
//! Tokens are what `aws eks get-token` prints: `k8s-aws-v1.` and the
//! base64url of an STS `GetCallerIdentity` URL presigned with the cluster
//! name in the signed `x-k8s-aws-id` header. MWS checks the signature with
//! the caller's credentials and maps the identity through the cluster's
//! access entries, as EKS does: the entry's username and Kubernetes groups,
//! and its access policies answer authorization.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{Caller, CallerKind, HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::state::{AccessEntryRec, ClusterRec};
use crate::Eks;

pub(crate) const PREFIX: &str = "/_aws/eks/";

/// The identity a token proves, as the cluster sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub username: String,
    pub uid: String,
    pub groups: Vec<String>,
    pub extra: BTreeMap<String, Vec<String>>,
}

fn respond(body: Value) -> HttpResponse {
    let mut r = http::Response::new(bytes::Bytes::from(body.to_string()));
    r.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
    r
}

/// `PREFIX<account>/<region>/<cluster>/<authenticate|authorize>`.
pub(crate) fn route(path: &str) -> Option<(&str, &str, &str, &str)> {
    let rest = path.strip_prefix(PREFIX)?;
    let mut it = rest.splitn(4, '/');
    Some((it.next()?, it.next()?, it.next()?, it.next()?))
}

/// The access entry key (principal ARN) for a caller: assumed roles map to
/// their role.
fn principal_candidates(caller: &Caller, partition: &str) -> (String, Option<String>) {
    match &caller.kind {
        CallerKind::AssumedRole { role_name, .. } => {
            (format!("arn:{partition}:iam::{}:role/{role_name}", caller.account_id), Some(role_name.clone()))
        }
        _ => (caller.arn.clone(), None),
    }
}

fn find_entry<'a>(rec: &'a ClusterRec, caller: &Caller, partition: &str) -> Option<&'a AccessEntryRec> {
    let (arn, role) = principal_candidates(caller, partition);
    if let Some(e) = rec.access_entries.get(&arn) {
        return Some(e);
    }
    // Roles with a path: `role/path/name`.
    let role = role?;
    rec.access_entries.iter().find_map(|(k, e)| {
        let (acct, kind, name) = crate::util::iam_principal(k)?;
        (acct == caller.account_id && kind == "role" && name == role).then_some(e)
    })
}

fn expand(template: &str, caller: &Caller) -> String {
    let session = match &caller.kind {
        CallerKind::AssumedRole { session_name, .. } => session_name.clone(),
        _ => String::new(),
    };
    template
        .replace("{{SessionName}}", &session.replace('@', "-"))
        .replace("{{SessionNameRaw}}", &session)
        .replace("{{AccountID}}", &caller.account_id)
        .replace("{{AccessKeyID}}", &caller.access_key_id)
        .replace("{{EC2PrivateDNSName}}", &session)
}

/// The identity of `caller` in a cluster, from its access entry (or, in a
/// `CONFIG_MAP` cluster, the creator's implicit admin rights).
pub(crate) fn identity(rec: &ClusterRec, caller: &Caller, partition: &str) -> Option<Identity> {
    let mode = rec
        .cluster
        .access_config
        .as_ref()
        .and_then(|a| a.authentication_mode.clone())
        .unwrap_or_else(|| "CONFIG_MAP".into());
    let (canonical, _) = principal_candidates(caller, partition);
    let mut extra = BTreeMap::new();
    extra.insert("arn".to_string(), vec![caller.arn.clone()]);
    extra.insert("principalId".to_string(), vec![caller.user_id.clone()]);
    extra.insert("accessKeyId".to_string(), vec![caller.access_key_id.clone()]);
    if let CallerKind::AssumedRole { session_name, .. } = &caller.kind {
        extra.insert("sessionName".to_string(), vec![session_name.clone()]);
    }
    let uid = format!("aws-iam-authenticator:{}:{}", caller.account_id, caller.user_id);
    if mode != "CONFIG_MAP" {
        if let Some(e) = find_entry(rec, caller, partition) {
            let key = e.entry.principal_arn.clone().unwrap_or(canonical);
            extra.insert("canonicalArn".to_string(), vec![key]);
            let username = e.entry.username.clone().unwrap_or_else(|| caller.arn.clone());
            return Some(Identity {
                username: expand(&username, caller),
                uid,
                groups: e.entry.kubernetes_groups.clone().unwrap_or_default(),
                extra,
            });
        }
    }
    let creator = rec.control_plane.as_ref().and_then(|c| c.creator.clone());
    if mode != "API" && creator.as_deref() == Some(canonical.as_str()) {
        extra.insert("canonicalArn".to_string(), vec![canonical.clone()]);
        return Some(Identity {
            username: "kubernetes-admin".into(),
            uid,
            groups: vec!["system:masters".into()],
            extra,
        });
    }
    None
}

/// Check a token and return the caller it was signed by.
pub(crate) fn verify_token(eks: &Eks, token: &str, cluster: &str, now: DateTime<Utc>) -> Result<Caller, String> {
    let encoded = token.strip_prefix("k8s-aws-v1.").ok_or("the token is not an EKS token")?;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| "the token is not base64url")?;
    let url = String::from_utf8(url).map_err(|_| "the token is not a URL")?;
    let uri: http::Uri = url.parse().map_err(|_| "the token is not a URL")?;
    let host = uri.authority().ok_or("the token URL has no host")?.to_string();
    let query = uri.query().unwrap_or_default();
    let params: Vec<(String, String)> =
        query.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), percent_decode(v))).collect();
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    if get("Action") != Some("GetCallerIdentity") {
        return Err("the token is not a GetCallerIdentity request".into());
    }
    let signed = get("X-Amz-SignedHeaders").unwrap_or_default();
    if !signed.split(';').any(|h| h == "x-k8s-aws-id") {
        return Err("the token does not sign x-k8s-aws-id".into());
    }
    let request = http::Request::get(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
        .header(http::header::HOST, host)
        .header("x-k8s-aws-id", cluster)
        .body(Vec::<u8>::new())
        .map_err(|e| e.to_string())?;
    let parsed = mws_sigv4::parse(&request).map_err(|e| format!("{e:?}"))?;
    if parsed.scope.service != "sts" {
        return Err("the token is not signed for STS".into());
    }
    if parsed.expires_in.is_some_and(|s| s > 15 * 60) {
        return Err("the token is valid for more than 15 minutes".into());
    }
    let resolved = eks
        .credentials()
        .iter()
        .find_map(|store| store.resolve(&parsed.scope.access_key_id, parsed.session_token.as_deref(), now).transpose())
        .ok_or("unknown access key")?
        .map_err(|e| format!("{e:?}"))?;
    mws_sigv4::verify(&request, &parsed, &resolved.secret_access_key, now, mws_sigv4::VerifyOptions::default())
        .map_err(|e| format!("{e:?}"))?;
    let mut caller = resolved.caller;
    caller.access_key_id = parsed.scope.access_key_id.clone();
    Ok(caller)
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', "%20")).decode_utf8_lossy().into_owned()
}

/// Whether access policy `name` with `scope` allows the request a subject
/// access review describes. These follow the Kubernetes roles EKS maps the
/// policies to (cluster-admin, admin, edit, view).
pub(crate) fn policy_allows(name: &str, namespaces: Option<&[String]>, attrs: &Value) -> bool {
    let res = attrs.get("resourceAttributes");
    if let Some(non) = attrs.get("nonResourceAttributes") {
        let verb = non.get("verb").and_then(Value::as_str).unwrap_or_default();
        return match name {
            "AmazonEKSClusterAdminPolicy" => true,
            "AmazonEKSAdminPolicy" | "AmazonEKSEditPolicy" | "AmazonEKSViewPolicy" | "AmazonEKSAdminViewPolicy" => {
                namespaces.is_none() && verb == "get"
            }
            _ => false,
        };
    }
    let Some(res) = res else { return false };
    let s = |k: &str| res.get(k).and_then(Value::as_str).unwrap_or_default();
    let (ns, verb, group, resource) = (s("namespace"), s("verb"), s("group"), s("resource"));
    if let Some(list) = namespaces {
        let matches = list.iter().any(|n| match n.strip_suffix('*') {
            Some(prefix) => ns.starts_with(prefix),
            None => n == ns,
        });
        if ns.is_empty() || !matches {
            return false;
        }
    }
    let read = matches!(verb, "get" | "list" | "watch");
    let rbac = group == "rbac.authorization.k8s.io";
    match name {
        "AmazonEKSClusterAdminPolicy" => true,
        "AmazonEKSAdminPolicy" => !ns.is_empty() || read,
        "AmazonEKSEditPolicy" => {
            (!ns.is_empty() && !rbac && !matches!(verb, "escalate" | "bind" | "impersonate"))
                || (read && resource != "secrets")
        }
        "AmazonEKSViewPolicy" => read && resource != "secrets",
        "AmazonEKSAdminViewPolicy" => read,
        _ => false,
    }
}

fn authorize(rec: &ClusterRec, spec: &Value) -> bool {
    let canonical = spec.pointer("/extra/canonicalArn/0").and_then(Value::as_str).unwrap_or_default();
    let Some(entry) = rec.access_entries.get(canonical) else { return false };
    entry.policies.values().any(|p| {
        let name = p.policy_arn.as_deref().unwrap_or_default().rsplit('/').next().unwrap_or_default().to_string();
        let scope = p.access_scope.as_ref();
        let namespaces = scope
            .filter(|s| s.r#type.as_deref() == Some("namespace"))
            .map(|s| s.namespaces.clone().unwrap_or_default());
        policy_allows(&name, namespaces.as_deref(), spec)
    })
}

impl Eks {
    /// Answer a webhook call from a cluster's API server.
    pub(crate) async fn serve_webhook(
        &self,
        request: &HttpRequest,
        now: DateTime<Utc>,
        partition: &str,
    ) -> HttpResponse {
        let Some((account, region, cluster, what)) = route(request.uri().path()) else {
            return respond(json!({"error": "not found"}));
        };
        let review: Value = serde_json::from_slice(request.body()).unwrap_or(Value::Null);
        let api_version = review.get("apiVersion").cloned().unwrap_or_else(|| json!("authentication.k8s.io/v1"));
        let kind = review.get("kind").cloned().unwrap_or(Value::Null);
        match what {
            "authenticate" => {
                let token = review.pointer("/spec/token").and_then(Value::as_str).unwrap_or_default();
                let caller = verify_token(self, token, cluster, now);
                let identity = caller.as_ref().ok().and_then(|caller| {
                    let st = self.read();
                    let rec = st.regions.get(&format!("{account}/{region}"))?.clusters.get(cluster)?;
                    identity(rec, caller, partition)
                });
                let status = match (identity, caller) {
                    (Some(i), _) => json!({
                        "authenticated": true,
                        "user": {"username": i.username, "uid": i.uid, "groups": i.groups, "extra": i.extra},
                    }),
                    (None, Ok(_)) => json!({"authenticated": false, "error": "no access entry for this principal"}),
                    (None, Err(e)) => json!({"authenticated": false, "error": e}),
                };
                respond(json!({"apiVersion": api_version, "kind": kind, "status": status}))
            }
            "authorize" => {
                let spec = review.get("spec").cloned().unwrap_or(Value::Null);
                let allowed = {
                    let st = self.read();
                    st.regions
                        .get(&format!("{account}/{region}"))
                        .and_then(|r| r.clusters.get(cluster))
                        .is_some_and(|rec| authorize(rec, &spec))
                };
                respond(json!({"apiVersion": api_version, "kind": kind, "status": {"allowed": allowed}}))
            }
            _ => respond(json!({"error": "not found"})),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(ns: &str, verb: &str, group: &str, resource: &str) -> Value {
        json!({"resourceAttributes": {"namespace": ns, "verb": verb, "group": group, "resource": resource}})
    }

    #[test]
    fn access_policies() {
        assert!(policy_allows("AmazonEKSClusterAdminPolicy", None, &res("", "delete", "", "nodes")));
        assert!(policy_allows("AmazonEKSViewPolicy", None, &res("a", "list", "", "pods")));
        assert!(!policy_allows("AmazonEKSViewPolicy", None, &res("a", "get", "", "secrets")));
        assert!(!policy_allows("AmazonEKSViewPolicy", None, &res("a", "create", "", "pods")));
        assert!(policy_allows("AmazonEKSEditPolicy", None, &res("a", "create", "apps", "deployments")));
        assert!(!policy_allows("AmazonEKSEditPolicy", None, &res("a", "create", "rbac.authorization.k8s.io", "roles")));
        let team = vec!["team-*".to_string()];
        assert!(policy_allows("AmazonEKSAdminPolicy", Some(&team), &res("team-a", "delete", "", "pods")));
        assert!(!policy_allows("AmazonEKSAdminPolicy", Some(&team), &res("default", "get", "", "pods")));
        assert!(!policy_allows("AmazonEKSAdminPolicy", Some(&team), &res("", "list", "", "namespaces")));
    }

    #[test]
    fn routes() {
        assert_eq!(
            route("/_aws/eks/123456789012/us-east-1/prod/authenticate"),
            Some(("123456789012", "us-east-1", "prod", "authenticate"))
        );
        assert_eq!(route("/other"), None);
    }
}
