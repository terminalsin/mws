//! Package group patterns, the package-to-group association and origin
//! controls (`PUBLISH`, `EXTERNAL_UPSTREAM`, `INTERNAL_UPSTREAM`).

use mws_core::ServiceError;

use crate::names::{validation, Coordinates};
use crate::state::{Domain, PackageGroup};

pub const RESTRICTION_TYPES: &[&str] = &["EXTERNAL_UPSTREAM", "INTERNAL_UPSTREAM", "PUBLISH"];
pub const ROOT: &str = "/*";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// `*`: every value of the next components.
    Wildcard,
    /// `~`: the last component starts with this word.
    Prefix,
    /// `$`: the whole coordinate.
    Exact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub parts: Vec<String>,
    pub end: End,
}

impl Pattern {
    pub fn parse(pattern: &str) -> Result<Self, ServiceError> {
        let invalid = || validation(format!("Invalid package group pattern: '{pattern}'"));
        let rest = pattern.strip_prefix('/').ok_or_else(invalid)?;
        let (body, end) = if let Some(b) = rest.strip_suffix('*') {
            (b, End::Wildcard)
        } else if let Some(b) = rest.strip_suffix('~') {
            (b, End::Prefix)
        } else if let Some(b) = rest.strip_suffix('$') {
            (b, End::Exact)
        } else {
            return Err(invalid());
        };
        let parts: Vec<String> = match end {
            End::Wildcard => {
                if body.is_empty() {
                    Vec::new()
                } else {
                    let b = body.strip_suffix('/').ok_or_else(invalid)?;
                    b.split('/').map(str::to_string).collect()
                }
            }
            _ => body.split('/').map(str::to_string).collect(),
        };
        if parts.len() > 3 || (end == End::Exact && parts.len() != 3) || (end == End::Prefix && parts.is_empty()) {
            return Err(invalid());
        }
        if let Some(format) = parts.first() {
            if !crate::names::FORMATS.contains(&format.as_str()) {
                return Err(invalid());
            }
            let namespaced = !matches!(format.as_str(), "pypi" | "nuget" | "cargo" | "ruby");
            if let Some(ns) = parts.get(1) {
                if !namespaced && !ns.is_empty() {
                    return Err(validation(format!(
                        "Invalid package group pattern: '{pattern}'. Packages of format '{format}' do not have a namespace."
                    )));
                }
                if ns.is_empty() && parts.len() == 2 {
                    return Err(invalid());
                }
            }
        }
        if parts.iter().skip(1).take(parts.len().saturating_sub(2)).any(|p| p.contains(['*', '~', '$'])) {
            return Err(invalid());
        }
        if end == End::Prefix {
            let last = parts.last().expect("checked");
            if !last.chars().last().is_some_and(is_word) {
                return Err(invalid());
            }
        }
        if parts.iter().enumerate().any(|(i, p)| p.is_empty() && i != 1) {
            return Err(invalid());
        }
        Ok(Self { parts, end })
    }

    /// Larger is more specific.
    fn specificity(&self) -> (usize, u8, usize) {
        let kind = match self.end {
            End::Wildcard => 0,
            End::Prefix => 1,
            End::Exact => 2,
        };
        (self.parts.len(), kind, self.parts.last().map_or(0, |p| p.len()))
    }

    fn matches_with(&self, path: &[String; 3], norm: fn(&str) -> String) -> bool {
        let n = self.parts.len();
        match self.end {
            End::Wildcard => self.parts.iter().zip(path.iter()).all(|(a, b)| norm(a) == norm(b)),
            End::Exact => self.parts.iter().zip(path.iter()).all(|(a, b)| norm(a) == norm(b)),
            End::Prefix => {
                self.parts[..n - 1].iter().zip(path.iter()).all(|(a, b)| norm(a) == norm(b))
                    && word_prefix(&norm(&self.parts[n - 1]), &norm(&path[n - 1]))
            }
        }
    }

    /// Whether every package this pattern matches is matched by `self`.
    fn contains(&self, other: &Pattern) -> bool {
        if self == other || other.parts.len() < self.parts.len() {
            return false;
        }
        let n = self.parts.len();
        match self.end {
            End::Exact => false,
            End::Wildcard => self.parts.iter().zip(other.parts.iter()).all(|(a, b)| a == b),
            End::Prefix => {
                self.parts[..n - 1].iter().zip(other.parts.iter()).all(|(a, b)| a == b)
                    && word_prefix(&self.parts[n - 1], &other.parts[n - 1])
                    && (other.parts.len() > n || other.end != End::Wildcard)
            }
        }
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric()
}

/// `foo` is a word prefix of `foo` and `foo-bar`, not of `food`.
fn word_prefix(prefix: &str, value: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|rest| rest.chars().next().is_none_or(|c| !is_word(c)))
}

fn exact(s: &str) -> String {
    s.to_string()
}

/// Weak-match normalization: case folded, runs of `-`, `.` and `_` as
/// one `.`.
fn weak(s: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in s.chars() {
        if matches!(c, '-' | '.' | '_') {
            if !sep {
                out.push('.');
            }
            sep = true;
        } else {
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Association {
    Strong,
    Weak,
}

impl Association {
    pub fn as_str(self) -> &'static str {
        match self {
            Association::Strong => "STRONG",
            Association::Weak => "WEAK",
        }
    }
}

fn path(c: &Coordinates) -> [String; 3] {
    [c.format.clone(), c.namespace.clone().unwrap_or_default(), c.name.clone()]
}

/// The group a package is associated with: the most specific match.
pub fn associated<'a>(domain: &'a Domain, c: &Coordinates) -> Option<(&'a PackageGroup, Association)> {
    let p = path(c);
    let mut best: Option<(&PackageGroup, Association, (usize, u8, usize))> = None;
    for g in domain.groups.values() {
        let Ok(pattern) = Pattern::parse(&g.pattern) else { continue };
        let assoc = if pattern.matches_with(&p, exact) {
            Association::Strong
        } else if pattern.matches_with(&p, weak) {
            Association::Weak
        } else {
            continue;
        };
        let s = pattern.specificity();
        if best.as_ref().is_none_or(|(_, _, bs)| s > *bs) {
            best = Some((g, assoc, s));
        }
    }
    best.map(|(g, a, _)| (g, a))
}

/// The most specific group containing `pattern`.
pub fn parent<'a>(domain: &'a Domain, pattern: &str) -> Option<&'a PackageGroup> {
    let me = Pattern::parse(pattern).ok()?;
    domain
        .groups
        .values()
        .filter_map(|g| Pattern::parse(&g.pattern).ok().map(|p| (g, p)))
        .filter(|(_, p)| p.contains(&me))
        .max_by_key(|(_, p)| p.specificity())
        .map(|(g, _)| g)
}

/// A group's effective mode for a restriction type and the group it comes
/// from.
pub fn effective<'a>(domain: &'a Domain, group: &'a PackageGroup, kind: &str) -> (String, &'a PackageGroup) {
    let mut g = group;
    for _ in 0..64 {
        let mode = g.restrictions.get(kind).map(String::as_str).unwrap_or("INHERIT");
        if mode != "INHERIT" {
            return (mode.to_string(), g);
        }
        match parent(domain, &g.pattern) {
            Some(p) => g = p,
            None => break,
        }
    }
    ("ALLOW".to_string(), g)
}

/// Whether the package groups let `repo` do `kind` for this package.
pub fn allows(domain: &Domain, c: &Coordinates, repo: &str, kind: &str) -> bool {
    let Some((group, assoc)) = associated(domain, c) else { return true };
    if assoc == Association::Weak {
        return false;
    }
    let (mode, from) = effective(domain, group, kind);
    match mode.as_str() {
        "ALLOW" => true,
        "ALLOW_SPECIFIC_REPOSITORIES" => from.allowed_repositories.get(kind).is_some_and(|r| r.contains(repo)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(format: &str, ns: Option<&str>, name: &str) -> Coordinates {
        Coordinates { format: format.into(), namespace: ns.map(str::to_string), name: name.into() }
    }

    #[test]
    fn patterns_parse_and_match() {
        let p = Pattern::parse("/npm/space/foo~").unwrap();
        assert!(p.matches_with(&path(&c("npm", Some("space"), "foo-bar")), exact));
        assert!(!p.matches_with(&path(&c("npm", Some("space"), "food")), exact));
        assert!(Pattern::parse("/pypi/ns/x$").is_err());
        assert!(Pattern::parse("/npm//react$").is_ok());
        assert!(Pattern::parse("/npm/*").unwrap().contains(&Pattern::parse("/npm/space/*").unwrap()));
        assert!(Pattern::parse("/*").unwrap().contains(&Pattern::parse("/npm/*").unwrap()));
    }

    #[test]
    fn weak_matches_fold_case_and_separators() {
        let p = Pattern::parse("/npm//anycompany-spicy-client$").unwrap();
        let v = path(&c("npm", None, "AnyCompany_spicy.client"));
        assert!(!p.matches_with(&v, exact));
        assert!(p.matches_with(&v, weak));
    }
}
