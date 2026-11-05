//! ARNs, errors and package coordinates.

use mws_core::{ErrorValue, ServiceError};

pub const FORMATS: &[&str] = &["npm", "pypi", "maven", "nuget", "generic", "ruby", "swift", "cargo"];

pub fn domain_arn(partition: &str, region: &str, owner: &str, domain: &str) -> String {
    format!("arn:{partition}:codeartifact:{region}:{owner}:domain/{domain}")
}

pub fn repository_arn(partition: &str, region: &str, owner: &str, domain: &str, repo: &str) -> String {
    format!("arn:{partition}:codeartifact:{region}:{owner}:repository/{domain}/{repo}")
}

#[allow(clippy::too_many_arguments)]
pub fn package_arn(
    partition: &str,
    region: &str,
    owner: &str,
    domain: &str,
    repo: &str,
    format: &str,
    namespace: Option<&str>,
    package: &str,
) -> String {
    format!(
        "arn:{partition}:codeartifact:{region}:{owner}:package/{domain}/{repo}/{format}/{}/{package}",
        namespace.unwrap_or("")
    )
}

pub fn package_group_arn(partition: &str, region: &str, owner: &str, domain: &str, pattern: &str) -> String {
    let encoded: String = pattern
        .chars()
        .map(|c| match c {
            '$' => "%24".to_string(),
            '~' => "%7E".to_string(),
            c => c.to_string(),
        })
        .collect();
    format!("arn:{partition}:codeartifact:{region}:{owner}:package-group/{domain}{encoded}")
}

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message).with_field("reason", ErrorValue::String("OTHER".into()))
}

fn with_resource(e: ServiceError, kind: &str, id: &str) -> ServiceError {
    e.with_field("resourceId", ErrorValue::String(id.to_string()))
        .with_field("resourceType", ErrorValue::String(kind.to_string()))
}

pub fn not_found(kind: &str, id: &str, message: impl Into<String>) -> ServiceError {
    with_resource(ServiceError::client("ResourceNotFoundException", 404, message), kind, id)
}

pub fn conflict(kind: &str, id: &str, message: impl Into<String>) -> ServiceError {
    with_resource(ServiceError::client("ConflictException", 409, message), kind, id)
}

pub fn quota(kind: &str, id: &str, message: impl Into<String>) -> ServiceError {
    with_resource(ServiceError::client("ServiceQuotaExceededException", 402, message), kind, id)
}

pub fn domain_not_found(domain: &str) -> ServiceError {
    not_found("domain", domain, format!("Domain not found. Domain name: '{domain}'"))
}

pub fn repository_not_found(repo: &str) -> ServiceError {
    not_found("repository", repo, format!("Repository not found. Repository name: '{repo}'"))
}

pub fn package_not_found(format: &str, namespace: Option<&str>, package: &str) -> ServiceError {
    let what = match namespace {
        Some(ns) => format!("Package not found. Format: '{format}', namespace: '{ns}', package: '{package}'"),
        None => format!("Package not found. Format: '{format}', package: '{package}'"),
    };
    not_found("package", package, what)
}

pub fn version_not_found(package: &str, version: &str) -> ServiceError {
    not_found(
        "package-version",
        version,
        format!("Package version not found. Package: '{package}', version: '{version}'"),
    )
}

pub fn check_format(format: &str) -> Result<(), ServiceError> {
    if FORMATS.contains(&format) {
        Ok(())
    } else {
        Err(validation(format!(
            "1 validation error detected: Value '{format}' at 'format' failed to satisfy constraint: Member must satisfy enum value set: [{}]",
            FORMATS.join(", ")
        )))
    }
}

/// Validate a package's namespace for its format and return it normalized
/// (PyPI and NuGet have none; Maven needs one).
pub fn check_coordinates(format: &str, namespace: Option<&str>, package: &str) -> Result<Coordinates, ServiceError> {
    check_format(format)?;
    let namespace = namespace.filter(|n| !n.is_empty());
    match format {
        "pypi" | "nuget" | "cargo" | "ruby" if namespace.is_some() => {
            return Err(validation(format!("Packages of format '{format}' do not have a namespace.")))
        }
        "maven" | "generic" | "swift" if namespace.is_none() => {
            return Err(validation(format!("Namespace is required for packages of format '{format}'.")))
        }
        _ => {}
    }
    let name = match format {
        "pypi" => normalize_pypi(package),
        "nuget" => package.to_ascii_lowercase(),
        _ => package.to_string(),
    };
    Ok(Coordinates { format: format.to_string(), namespace: namespace.map(str::to_string), name })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinates {
    pub format: String,
    pub namespace: Option<String>,
    pub name: String,
}

impl Coordinates {
    pub fn key(&self) -> String {
        crate::state::package_key(&self.format, self.namespace.as_deref(), &self.name)
    }
}

/// PEP 503 name normalization, which CodeArtifact applies to PyPI names.
pub fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// A pagination token: the index to continue from.
pub fn page<T: Clone>(items: &[T], max_results: Option<i32>, next_token: Option<&str>) -> (Vec<T>, Option<String>) {
    let start = next_token.and_then(|t| t.parse::<usize>().ok()).unwrap_or(0).min(items.len());
    let max = max_results.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(100);
    let end = (start + max).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    (items[start..end].to_vec(), next)
}

/// Order version strings naturally: numeric runs compare as numbers.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> Vec<Result<u64, String>> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut digit = None;
        for c in s.chars() {
            let d = c.is_ascii_digit();
            if digit.is_some_and(|x| x != d) {
                out.push(if digit == Some(true) { Ok(cur.parse().unwrap_or(u64::MAX)) } else { Err(cur.clone()) });
                cur.clear();
            }
            digit = Some(d);
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(if digit == Some(true) { Ok(cur.parse().unwrap_or(u64::MAX)) } else { Err(cur) });
        }
        out
    }
    let (pa, pb) = (parts(a), parts(b));
    for (x, y) in pa.iter().zip(pb.iter()) {
        let o = match (x, y) {
            (Ok(x), Ok(y)) => x.cmp(y),
            (Err(x), Err(y)) => x.cmp(y),
            (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
            (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        };
        if o != std::cmp::Ordering::Equal {
            return o;
        }
    }
    pa.len().cmp(&pb.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_names_normalize() {
        assert_eq!(normalize_pypi("Foo.Bar__baz"), "foo-bar-baz");
    }

    #[test]
    fn versions_order_naturally() {
        assert_eq!(compare_versions("1.10.0", "1.9.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.0-beta"), std::cmp::Ordering::Less);
    }
}
