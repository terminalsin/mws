//! Where a repository finds package versions: itself, then its upstream
//! repositories in priority order (each searched the same way, depth
//! first), then its external connection. Package origin controls and
//! package groups decide which of these a package may come from.

use std::collections::BTreeSet;

use crate::groups;
use crate::names::Coordinates;
use crate::state::{Domain, Package, Version};

#[derive(Debug, Clone)]
pub enum Source {
    /// A repository. `path` runs from the requested repository to this one.
    Repo { path: Vec<String> },
    /// An external connection of the last repository in `path`.
    External { path: Vec<String>, connection: String },
}

/// Statuses a package manager may download.
pub fn downloadable(v: &Version) -> bool {
    matches!(v.status.as_str(), "Published" | "Unlisted")
}

/// Statuses package managers list.
pub fn listed(v: &Version) -> bool {
    v.status == "Published"
}

pub fn sources(d: &Domain, start: &str, c: &Coordinates) -> Vec<Source> {
    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    walk(d, &[start.to_string()], c, &mut visited, &mut out);
    out
}

fn walk(d: &Domain, path: &[String], c: &Coordinates, visited: &mut BTreeSet<String>, out: &mut Vec<Source>) {
    let repo = path.last().expect("path is never empty");
    if !visited.insert(repo.clone()) {
        return;
    }
    let Some(r) = d.repositories.get(repo) else { return };
    out.push(Source::Repo { path: path.to_vec() });
    let upstream_ok = r.packages.get(&c.key()).is_none_or(|p| p.upstream == "ALLOW");
    if !upstream_ok {
        return;
    }
    if groups::allows(d, c, repo, "INTERNAL_UPSTREAM") {
        for u in &r.upstreams {
            let mut next = path.to_vec();
            next.push(u.clone());
            walk(d, &next, c, visited, out);
        }
    }
    for conn in &r.external_connections {
        if crate::external::format_of(conn) == Some(c.format.as_str())
            && groups::allows(d, c, repo, "EXTERNAL_UPSTREAM")
        {
            out.push(Source::External { path: path.to_vec(), connection: conn.clone() });
        }
    }
}

/// Whether `repo` may take a new version of this package by publishing.
pub fn publish_allowed(d: &Domain, repo: &str, c: &Coordinates) -> bool {
    let local = d.repositories.get(repo).and_then(|r| r.packages.get(&c.key()));
    local.is_none_or(|p| p.publish == "ALLOW") && groups::allows(d, c, repo, "PUBLISH")
}

fn new_package(c: &Coordinates, publish: &str, upstream: &str) -> Package {
    Package {
        format: c.format.clone(),
        namespace: c.namespace.clone(),
        name: c.name.clone(),
        publish: publish.into(),
        upstream: upstream.into(),
        ..Default::default()
    }
}

/// The package in `repo`, created as a published package would be
/// (publish allowed, upstreams blocked) when missing.
pub fn package_for_publish<'a>(d: &'a mut Domain, repo: &str, c: &Coordinates) -> &'a mut Package {
    let r = d.repositories.get_mut(repo).expect("repository exists");
    r.packages.entry(c.key()).or_insert_with(|| new_package(c, "ALLOW", "BLOCK"))
}

/// Keep `version` in every repository of `repos` that lacks it, as AWS
/// retains versions fetched through upstreams. Packages created this way
/// block publishing and allow upstreams.
pub fn retain(d: &mut Domain, repos: &[String], c: &Coordinates, version: &Version) {
    for repo in repos {
        let Some(r) = d.repositories.get_mut(repo) else { continue };
        let p = r.packages.entry(c.key()).or_insert_with(|| new_package(c, "BLOCK", "ALLOW"));
        p.versions.entry(version.version.clone()).or_insert_with(|| version.clone());
    }
}

/// Look `version` up through `start`'s sources. Returns the version and
/// the repositories between `start` and where it was found (exclusive),
/// or the external connections left to try.
pub enum Lookup {
    Found { version: Box<Version>, retain_in: Vec<String> },
    External(Vec<Source>),
}

pub fn lookup(d: &Domain, start: &str, c: &Coordinates, version: &str) -> Lookup {
    let mut externals = Vec::new();
    for s in sources(d, start, c) {
        match &s {
            Source::Repo { path } => {
                let repo = path.last().expect("non-empty");
                let found = d
                    .repositories
                    .get(repo)
                    .and_then(|r| r.packages.get(&c.key()))
                    .and_then(|p| p.versions.get(version));
                if let Some(v) = found.filter(|v| downloadable(v)) {
                    return Lookup::Found { version: Box::new(v.clone()), retain_in: path[..path.len() - 1].to_vec() };
                }
            }
            Source::External { .. } => externals.push(s),
        }
    }
    Lookup::External(externals)
}

/// Every version visible from `start` (first source wins), for package
/// manager metadata (packuments, simple indexes, maven-metadata.xml), with
/// the external connections to merge in.
pub fn visible_versions(d: &Domain, start: &str, c: &Coordinates) -> (Vec<Version>, Vec<Source>) {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut externals = Vec::new();
    for s in sources(d, start, c) {
        match &s {
            Source::Repo { path } => {
                let repo = path.last().expect("non-empty");
                if let Some(p) = d.repositories.get(repo).and_then(|r| r.packages.get(&c.key())) {
                    for v in p.versions.values() {
                        if seen.insert(v.version.clone()) {
                            out.push(v.clone());
                        }
                    }
                }
            }
            Source::External { .. } => externals.push(s),
        }
    }
    (out, externals)
}
