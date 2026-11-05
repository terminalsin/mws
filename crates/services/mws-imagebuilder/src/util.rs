//! Shared helpers: errors in Image Builder's wording, ARNs, semantic
//! versions, pagination, filters and authorization.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;

// ---- errors --------------------------------------------------------------------

pub fn invalid_request(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidRequestException", 400, message)
}

pub fn invalid_parameter_value(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterValueException", 400, message)
}

pub fn invalid_parameter(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterException", 400, message)
}

pub fn invalid_combination(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterCombinationException", 400, message)
}

pub fn invalid_version(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidVersionNumberException", 400, message)
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceNotFoundException", 404, message)
}

pub fn arn_not_found(arn: &str) -> ServiceError {
    not_found(format!("The resource ARN '{arn}' does not exist."))
}

pub fn already_exists(arn: &str) -> ServiceError {
    ServiceError::client("ResourceAlreadyExistsException", 400, format!("The resource ARN '{arn}' already exists."))
}

/// A version of a component or workflow that already exists.
pub fn already_exists_component(version_arn: &str) -> ServiceError {
    in_use(format!("The version '{version_arn}' already exists. Specify a new semantic version."))
}

pub fn in_use(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceInUseException", 400, message)
}

pub fn dependency(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceDependencyException", 400, message)
}

pub fn idempotent_mismatch(token: &str) -> ServiceError {
    ServiceError::client(
        "IdempotentParameterMismatchException",
        400,
        format!("The client token '{token}' was already used with different request parameters."),
    )
}

pub fn invalid_token() -> ServiceError {
    ServiceError::client("InvalidPaginationTokenException", 400, "The pagination token provided is not valid.")
}

pub fn dry_run_ok() -> ServiceError {
    ServiceError::client(
        "DryRunOperationException",
        412,
        "The request would have succeeded, but the DryRun parameter was set.",
    )
}

// ---- time ----------------------------------------------------------------------

/// Image Builder's date strings: ISO 8601 with milliseconds.
pub fn date(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn now(ctx: &RequestContext) -> String {
    date(ctx.received_at)
}

// ---- accounts and ARNs ---------------------------------------------------------

/// The account a request works in.
pub fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

/// A resource name as ARNs spell it: lower case, spaces as hyphens.
pub fn slug(name: &str) -> String {
    name.trim().to_lowercase().replace(' ', "-")
}

pub fn arn(ctx: &RequestContext, account: &str, path: &str) -> String {
    format!("arn:{}:imagebuilder:{}:{account}:{path}", ctx.partition, ctx.region)
}

/// The parts of an Image Builder ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arn {
    pub partition: String,
    pub region: String,
    /// A 12-digit account, `aws` for AWS-managed resources.
    pub account: String,
    /// `component`, `image`, `image-recipe`, `workflow/build`, ...
    pub kind: String,
    pub name: String,
    pub version: Option<String>,
    pub build: Option<u32>,
}

impl Arn {
    pub fn parse(s: &str) -> Option<Arn> {
        let mut parts = s.splitn(6, ':');
        if parts.next()? != "arn" {
            return None;
        }
        let partition = parts.next()?.to_string();
        if parts.next()? != "imagebuilder" {
            return None;
        }
        let region = parts.next()?.to_string();
        let account = parts.next()?.to_string();
        let resource = parts.next()?;
        let segs: Vec<&str> = resource.split('/').collect();
        let (kind, rest) = if segs.first() == Some(&"workflow") {
            if segs.len() < 3 {
                return None;
            }
            (format!("workflow/{}", segs[1]), &segs[2..])
        } else {
            (segs.first()?.to_string(), &segs[1..])
        };
        let name = rest.first()?.to_string();
        if name.is_empty() {
            return None;
        }
        let version = rest.get(1).map(|v| v.to_string());
        let build = match rest.get(2) {
            Some(b) => Some(b.parse().ok()?),
            None => None,
        };
        if rest.len() > 3 {
            return None;
        }
        Some(Arn { partition, region, account, kind, name, version, build })
    }

    /// The same resource without its build number.
    pub fn version_arn(&self) -> String {
        let mut s =
            format!("arn:{}:imagebuilder:{}:{}:{}/{}", self.partition, self.region, self.account, self.kind, self.name);
        if let Some(v) = &self.version {
            s.push('/');
            s.push_str(v);
        }
        s
    }

    /// The ARN without version or build.
    pub fn base(&self) -> String {
        format!("arn:{}:imagebuilder:{}:{}:{}/{}", self.partition, self.region, self.account, self.kind, self.name)
    }
}

// ---- semantic versions ---------------------------------------------------------

/// `major.minor.patch`, each at most 2^30 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u32, pub u32, pub u32);

const NODE_MAX: u64 = (1 << 30) - 1;

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let n: Vec<u32> = s
            .split('.')
            .map(|p| p.parse::<u64>().ok().filter(|v| *v <= NODE_MAX).map(|v| v as u32))
            .collect::<Option<_>>()?;
        (n.len() == 3).then(|| Version(n[0], n[1], n[2]))
    }

    /// A version for a new resource, with AWS's message when it is not one.
    pub fn for_create(s: &str) -> Result<Version, ServiceError> {
        Version::parse(s).ok_or_else(|| {
            invalid_version(format!(
                "The semantic version '{s}' is not valid. A semantic version must be in the format \
                 <major>.<minor>.<patch>, where each node is a non-negative integer no greater than 1073741823."
            ))
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// A version with `x` wildcards: `1.2.3`, `1.2.x`, `1.x.x` or `x.x.x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPattern([Option<u32>; 3]);

impl VersionPattern {
    pub fn parse(s: &str) -> Option<VersionPattern> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let mut out = [None; 3];
        let mut wild = false;
        for (i, p) in parts.iter().enumerate() {
            if *p == "x" {
                wild = true;
            } else {
                // A number cannot follow a wildcard.
                if wild {
                    return None;
                }
                out[i] = Some(p.parse::<u64>().ok().filter(|v| *v <= NODE_MAX)? as u32);
            }
        }
        Some(VersionPattern(out))
    }

    pub fn matches(&self, v: Version) -> bool {
        let n = [v.0, v.1, v.2];
        self.0.iter().zip(n).all(|(p, n)| p.is_none_or(|p| p == n))
    }
}

/// Latest-version references for `arn_of(name, version, build)` among the
/// builds `all` (version, build) of one resource.
pub fn latest_references(
    base: &str,
    current: Version,
    all: impl Iterator<Item = (Version, u32)> + Clone,
) -> t::LatestVersionReferences {
    let best = |keep: &dyn Fn(Version) -> bool| -> Option<String> {
        all.clone().filter(|(v, _)| keep(*v)).max().map(|(v, b)| format!("{base}/{v}/{b}"))
    };
    t::LatestVersionReferences {
        latest_version_arn: best(&|_| true),
        latest_major_version_arn: best(&|v| v.0 == current.0),
        latest_minor_version_arn: best(&|v| v.0 == current.0 && v.1 == current.1),
        latest_patch_version_arn: best(&|v| v == current),
    }
}

/// Like [`latest_references`] for resources without build numbers
/// (recipes).
pub fn latest_references_unbuilt(
    base: &str,
    current: Version,
    all: impl Iterator<Item = Version> + Clone,
) -> t::LatestVersionReferences {
    let best = |keep: &dyn Fn(Version) -> bool| -> Option<String> {
        all.clone().filter(|v| keep(*v)).max().map(|v| format!("{base}/{v}"))
    };
    t::LatestVersionReferences {
        latest_version_arn: best(&|_| true),
        latest_major_version_arn: best(&|v| v.0 == current.0),
        latest_minor_version_arn: best(&|v| v.0 == current.0 && v.1 == current.1),
        latest_patch_version_arn: best(&|v| v == current),
    }
}

// ---- pagination ----------------------------------------------------------------

pub fn paginate<T>(
    items: Vec<T>,
    max_results: Option<i32>,
    token: &Option<String>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None => 0,
        Some(tok) => tok
            .strip_prefix("ib1.")
            .and_then(|n| usize::from_str_radix(n, 16).ok())
            .filter(|n| *n <= items.len())
            .ok_or_else(invalid_token)?,
    };
    let max = max_results.unwrap_or(25).clamp(1, 25) as usize;
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + page.len() < total).then(|| format!("ib1.{:x}", start + page.len()));
    Ok((page, next))
}

// ---- filters -------------------------------------------------------------------

/// Checks `filters` against a resource, where `value` gives the resource's
/// values for a filter name. Unknown names are an error.
pub fn filters_match(
    filters: &Option<Vec<t::Filter>>,
    allowed: &[&str],
    value: impl Fn(&str) -> Vec<String>,
) -> Result<bool, ServiceError> {
    for f in filters.iter().flatten() {
        let name = f.name.as_deref().unwrap_or_default();
        if !allowed.contains(&name) {
            return Err(invalid_request(format!(
                "The filter name '{name}' is not valid. Valid filter names are: {}.",
                allowed.join(", ")
            )));
        }
        let wanted = f.values.clone().unwrap_or_default();
        let have = value(name);
        if !wanted.iter().any(|w| have.iter().any(|h| h == w)) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn s(v: &Option<String>) -> Vec<String> {
    v.iter().cloned().collect()
}

// ---- authorization -------------------------------------------------------------

pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    cond: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("imagebuilder:{action}"), resource, cond)
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags a request sets.
pub fn request_tags(tags: &Option<BTreeMap<String, String>>) -> ConditionContext {
    let mut c = ConditionContext::new();
    if let Some(tags) = tags {
        for (k, v) in tags {
            c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
        if !tags.is_empty() {
            c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
        }
    }
    c
}

/// `aws:ResourceTag/*` for an existing resource.
pub fn resource_tags(tags: &Option<BTreeMap<String, String>>) -> ConditionContext {
    let mut c = ConditionContext::new();
    for (k, v) in tags.iter().flatten() {
        c.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
    }
    c
}

pub fn merge(mut a: ConditionContext, b: ConditionContext) -> ConditionContext {
    a.extend(b);
    a
}

/// Checks a resource policy document: valid JSON with statements that
/// only use the actions Image Builder lets a policy share.
pub fn check_policy(policy: &str, allowed: &[&str]) -> Result<(), ServiceError> {
    let bad =
        |why: &str| invalid_parameter_value(format!("The value supplied for parameter 'policy' is not valid. {why}"));
    let v: serde_json::Value = serde_json::from_str(policy).map_err(|_| bad("The policy is not valid JSON."))?;
    let statements = match v.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
        _ => return Err(bad("The policy must contain a Statement.")),
    };
    for st in &statements {
        let actions: Vec<String> = match st.get("Action") {
            Some(serde_json::Value::String(a)) => vec![a.clone()],
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => return Err(bad("Every statement must name an Action.")),
        };
        for a in actions {
            if !allowed.iter().any(|x| x.eq_ignore_ascii_case(&a)) {
                return Err(bad(&format!(
                    "The action '{a}' is not allowed. Allowed actions are: {}.",
                    allowed.join(", ")
                )));
            }
        }
        if st.get("Principal").is_none() {
            return Err(bad("Every statement must name a Principal."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arns() {
        let a = Arn::parse("arn:aws:imagebuilder:us-east-1:123456789012:component/my-comp/1.0.0/1").unwrap();
        assert_eq!(
            (a.kind.as_str(), a.name.as_str(), a.version.as_deref(), a.build),
            ("component", "my-comp", Some("1.0.0"), Some(1))
        );
        let w = Arn::parse("arn:aws:imagebuilder:us-east-1:aws:workflow/build/build-image/1.0.x").unwrap();
        assert_eq!((w.kind.as_str(), w.account.as_str(), w.build), ("workflow/build", "aws", None));
        assert!(Arn::parse("arn:aws:s3:::b").is_none());
    }

    #[test]
    fn versions() {
        let p = VersionPattern::parse("1.x.x").unwrap();
        assert!(p.matches(Version(1, 4, 2)));
        assert!(!p.matches(Version(2, 0, 0)));
        assert!(VersionPattern::parse("x.1.x").is_none());
        assert!(Version::parse("1.2").is_none());
        assert!(Version::parse("1073741824.0.0").is_none());
    }

    #[test]
    fn pages() {
        let (p, n) = paginate((0..30).collect(), None, &None).unwrap();
        assert_eq!(p.len(), 25);
        let (p, n) = paginate((0..30).collect::<Vec<i32>>(), None, &n).unwrap();
        assert_eq!((p.len(), n), (5, None));
        assert!(paginate(vec![1], None, &Some("bogus".into())).is_err());
    }
}
