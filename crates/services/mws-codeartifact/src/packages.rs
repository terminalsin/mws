//! Packages, package versions and assets.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};
use sha2::Digest;

use crate::generated::types;
use crate::names::{self, check_coordinates, conflict, package_not_found, validation, version_not_found, Coordinates};
use crate::state::{Asset, Domain, Package, Version};
use crate::{upstream, CodeArtifact};

pub(crate) fn origin(p: &Package) -> types::PackageOriginConfiguration {
    types::PackageOriginConfiguration {
        restrictions: Some(types::PackageOriginRestrictions {
            publish: p.publish.clone(),
            upstream: p.upstream.clone(),
        }),
    }
}

fn version_origin(v: &Version) -> types::PackageVersionOrigin {
    types::PackageVersionOrigin {
        domain_entry_point: Some(types::DomainEntryPoint {
            repository_name: v.entry_repository.clone(),
            external_connection_name: v.entry_external_connection.clone(),
        }),
        origin_type: Some(v.origin_type.clone()),
    }
}

fn asset_summary(a: &Asset) -> types::AssetSummary {
    types::AssetSummary { name: a.name.clone(), size: Some(a.content.len() as i64), hashes: Some(a.hashes()) }
}

/// Which versions a batch operation names: `versions` or the keys of
/// `versionRevisions` (whose revisions must then match).
fn named_versions(versions: &[String], revisions: Option<&BTreeMap<String, String>>) -> Vec<String> {
    let mut out: Vec<String> = versions.to_vec();
    for k in revisions.into_iter().flat_map(|r| r.keys()) {
        if !out.contains(k) {
            out.push(k.clone());
        }
    }
    out
}

fn failure(code: &str, message: impl Into<String>) -> types::PackageVersionError {
    types::PackageVersionError { error_code: Some(code.into()), error_message: Some(message.into()) }
}

/// Check one version for a batch operation.
fn check_version(
    p: &Package,
    version: &str,
    revisions: Option<&BTreeMap<String, String>>,
    expected_status: Option<&str>,
) -> Result<(), types::PackageVersionError> {
    let v =
        p.versions.get(version).ok_or_else(|| failure("NOT_FOUND", format!("Package version not found: {version}")))?;
    if let Some(r) = revisions.and_then(|r| r.get(version)) {
        if r != &v.revision {
            return Err(failure("MISMATCHED_REVISION", "The package version revision does not match."));
        }
    }
    if let Some(s) = expected_status {
        if s != v.status {
            return Err(failure("MISMATCHED_STATUS", format!("The package version status is {}.", v.status)));
        }
    }
    Ok(())
}

pub(crate) fn describe_version(c: &Coordinates, v: &Version) -> types::PackageVersionDescription {
    types::PackageVersionDescription {
        format: Some(c.format.clone()),
        namespace: c.namespace.clone(),
        package_name: Some(c.name.clone()),
        display_name: Some(v.meta.display_name.clone().unwrap_or_else(|| c.name.clone())),
        version: Some(v.version.clone()),
        summary: v.meta.summary.clone(),
        home_page: v.meta.home_page.clone(),
        source_code_repository: v.meta.source_code_repository.clone(),
        published_time: Some(v.published),
        licenses: Some(
            v.meta.licenses.iter().map(|l| types::LicenseInfo { name: l.name.clone(), url: l.url.clone() }).collect(),
        ),
        revision: Some(v.revision.clone()),
        status: Some(v.status.clone()),
        origin: Some(version_origin(v)),
    }
}

/// Add an asset to a version in `repo`, publishing the version unless it
/// is left unfinished. Origin controls must allow publishing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish(
    d: &mut Domain,
    repo: &str,
    c: &Coordinates,
    version: &str,
    asset: Asset,
    meta: Option<crate::state::VersionMeta>,
    finished: bool,
    now: chrono::DateTime<chrono::Utc>,
    overwrite: bool,
) -> Result<Version, ServiceError> {
    if !upstream::publish_allowed(d, repo, c) {
        return Err(ServiceError::client(
            "AccessDeniedException",
            403,
            format!(
                "Publishing package '{}' to repository '{repo}' is blocked by its package origin controls.",
                c.name
            ),
        ));
    }
    let p = upstream::package_for_publish(d, repo, c);
    let existing = p.versions.get(version);
    if let Some(v) = existing {
        if v.status != "Unfinished" && !overwrite {
            return Err(conflict(
                "package-version",
                version,
                format!("Package version {version} of '{}' already exists and cannot be modified.", c.name),
            ));
        }
    }
    let v = p.versions.entry(version.to_string()).or_insert_with(|| Version {
        version: version.to_string(),
        status: "Unfinished".into(),
        published: now,
        origin_type: "INTERNAL".into(),
        entry_repository: Some(repo.to_string()),
        ..Default::default()
    });
    v.put_asset(asset);
    if let Some(m) = meta {
        v.meta = m;
    }
    if finished && v.status == "Unfinished" {
        v.status = "Published".into();
        v.published = now;
    }
    Ok(v.clone())
}

struct PackageRef<'a> {
    owner: String,
    domain: &'a str,
    repo: &'a str,
    coords: Coordinates,
    arn: String,
}

impl CodeArtifact {
    fn package_ref<'a>(
        ctx: &RequestContext,
        domain_owner: Option<&str>,
        domain: &'a str,
        repo: &'a str,
        format: &str,
        namespace: Option<&str>,
        package: &str,
    ) -> Result<PackageRef<'a>, ServiceError> {
        let owner = Self::owner(ctx, domain_owner);
        let coords = check_coordinates(format, namespace, package)?;
        let arn = names::package_arn(
            &ctx.partition,
            &ctx.region,
            &owner,
            domain,
            repo,
            &coords.format,
            coords.namespace.as_deref(),
            &coords.name,
        );
        Ok(PackageRef { owner, domain, repo, coords, arn })
    }

    fn authorize_package(&self, ctx: &RequestContext, p: &PackageRef<'_>, action: &str) -> Result<(), ServiceError> {
        self.authorize_repo(ctx, &p.owner, p.domain, p.repo, action, Some(&p.arn))
    }

    fn with_package<T>(
        &self,
        ctx: &RequestContext,
        p: &PackageRef<'_>,
        f: impl FnOnce(&Package) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let st = self.read();
        let (_, r) = Self::repo(&st, ctx, &p.owner, p.domain, p.repo)?;
        let pkg = r
            .packages
            .get(&p.coords.key())
            .ok_or_else(|| package_not_found(&p.coords.format, p.coords.namespace.as_deref(), &p.coords.name))?;
        f(pkg)
    }

    fn with_package_mut<T>(
        &self,
        ctx: &RequestContext,
        p: &PackageRef<'_>,
        f: impl FnOnce(&mut Package) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &p.owner, p.domain, p.repo)?;
        let r = d.repositories.get_mut(p.repo).expect("checked");
        let pkg = r
            .packages
            .get_mut(&p.coords.key())
            .ok_or_else(|| package_not_found(&p.coords.format, p.coords.namespace.as_deref(), &p.coords.name))?;
        f(pkg)
    }

    pub(crate) fn list_packages(
        &self,
        ctx: &RequestContext,
        input: types::ListPackagesRequest,
    ) -> Result<types::ListPackagesResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_repo(ctx, &owner, &input.domain, &input.repository, "codeartifact:ListPackages", None)?;
        if let Some(f) = &input.format {
            names::check_format(f)?;
        }
        let st = self.read();
        let (_, r) = Self::repo(&st, ctx, &owner, &input.domain, &input.repository)?;
        let prefix = input.package_prefix.unwrap_or_default();
        let all: Vec<_> = r
            .packages
            .values()
            .filter(|p| input.format.as_ref().is_none_or(|f| &p.format == f))
            .filter(|p| {
                input.namespace.as_ref().is_none_or(|n| p.namespace.as_deref().unwrap_or("").starts_with(n.as_str()))
            })
            .filter(|p| p.name.starts_with(&prefix))
            .filter(|p| input.publish.as_ref().is_none_or(|x| &p.publish == x))
            .filter(|p| input.upstream.as_ref().is_none_or(|x| &p.upstream == x))
            .map(|p| types::PackageSummary {
                format: Some(p.format.clone()),
                namespace: p.namespace.clone(),
                package: Some(p.name.clone()),
                origin_configuration: Some(origin(p)),
            })
            .collect();
        let (packages, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListPackagesResult { packages: Some(packages), next_token })
    }

    pub(crate) fn describe_package(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageRequest,
    ) -> Result<types::DescribePackageResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:DescribePackage")?;
        self.with_package(ctx, &p, |pkg| {
            Ok(types::DescribePackageResult {
                package: types::PackageDescription {
                    format: Some(pkg.format.clone()),
                    namespace: pkg.namespace.clone(),
                    name: Some(pkg.name.clone()),
                    origin_configuration: Some(origin(pkg)),
                },
            })
        })
    }

    pub(crate) fn delete_package(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageRequest,
    ) -> Result<types::DeletePackageResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:DeletePackage")?;
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &p.owner, p.domain, p.repo)?;
        let r = d.repositories.get_mut(p.repo).expect("checked");
        let pkg = r
            .packages
            .remove(&p.coords.key())
            .ok_or_else(|| package_not_found(&p.coords.format, p.coords.namespace.as_deref(), &p.coords.name))?;
        Ok(types::DeletePackageResult {
            deleted_package: Some(types::PackageSummary {
                format: Some(pkg.format.clone()),
                namespace: pkg.namespace.clone(),
                package: Some(pkg.name.clone()),
                origin_configuration: Some(origin(&pkg)),
            }),
        })
    }

    pub(crate) fn put_package_origin_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutPackageOriginConfigurationRequest,
    ) -> Result<types::PutPackageOriginConfigurationResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:PutPackageOriginConfiguration")?;
        for v in [&input.restrictions.publish, &input.restrictions.upstream] {
            if !matches!(v.as_str(), "ALLOW" | "BLOCK") {
                return Err(validation(format!("Invalid origin restriction: '{v}'. Must be ALLOW or BLOCK.")));
            }
        }
        // Setting origin controls on a package that does not exist yet
        // creates it, so its controls apply before the first version.
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &p.owner, p.domain, p.repo)?;
        let pkg = upstream::package_for_publish(d, p.repo, &p.coords);
        pkg.publish = input.restrictions.publish.clone();
        pkg.upstream = input.restrictions.upstream.clone();
        Ok(types::PutPackageOriginConfigurationResult { origin_configuration: Some(origin(pkg)) })
    }

    pub(crate) fn list_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionsRequest,
    ) -> Result<types::ListPackageVersionsResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:ListPackageVersions")?;
        self.with_package(ctx, &p, |pkg| {
            let mut versions: Vec<&Version> = pkg
                .versions
                .values()
                .filter(|v| input.status.as_ref().is_none_or(|s| &v.status == s))
                .filter(|v| input.origin_type.as_ref().is_none_or(|o| &v.origin_type == o))
                .collect();
            if input.sort_by.as_deref() == Some("PUBLISHED_TIME") {
                versions.sort_by_key(|v| std::cmp::Reverse(v.published));
            } else {
                versions.sort_by(|a, b| names::compare_versions(&b.version, &a.version));
            }
            let all: Vec<_> = versions
                .iter()
                .map(|v| types::PackageVersionSummary {
                    version: v.version.clone(),
                    revision: Some(v.revision.clone()),
                    status: v.status.clone(),
                    origin: Some(version_origin(v)),
                })
                .collect();
            let (versions_page, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
            Ok(types::ListPackageVersionsResult {
                default_display_version: default_display_version(pkg),
                format: Some(p.coords.format.clone()),
                namespace: p.coords.namespace.clone(),
                package: Some(p.coords.name.clone()),
                versions: Some(versions_page),
                next_token,
            })
        })
    }

    pub(crate) fn describe_package_version(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageVersionRequest,
    ) -> Result<types::DescribePackageVersionResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:DescribePackageVersion")?;
        self.with_package(ctx, &p, |pkg| {
            let v = pkg
                .versions
                .get(&input.package_version)
                .ok_or_else(|| version_not_found(&p.coords.name, &input.package_version))?;
            Ok(types::DescribePackageVersionResult { package_version: describe_version(&p.coords, v) })
        })
    }

    pub(crate) fn update_package_versions_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageVersionsStatusRequest,
    ) -> Result<types::UpdatePackageVersionsStatusResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:UpdatePackageVersionsStatus")?;
        if !matches!(input.target_status.as_str(), "Published" | "Unlisted" | "Archived") {
            return Err(validation(format!(
                "Invalid target status: '{}'. The target status must be Published, Unlisted or Archived.",
                input.target_status
            )));
        }
        let versions = named_versions(&input.versions, input.version_revisions.as_ref());
        self.with_package_mut(ctx, &p, |pkg| {
            let mut ok = BTreeMap::new();
            let mut failed = BTreeMap::new();
            for version in versions {
                match check_version(pkg, &version, input.version_revisions.as_ref(), input.expected_status.as_deref()) {
                    Err(e) => {
                        failed.insert(version, e);
                    }
                    Ok(()) => {
                        let v = pkg.versions.get_mut(&version).expect("checked");
                        if v.status == "Disposed" {
                            failed.insert(
                                version,
                                failure("NOT_ALLOWED", "The status of a disposed package version cannot be changed."),
                            );
                            continue;
                        }
                        v.status = input.target_status.clone();
                        ok.insert(
                            version,
                            types::SuccessfulPackageVersionInfo {
                                revision: Some(v.revision.clone()),
                                status: Some(v.status.clone()),
                            },
                        );
                    }
                }
            }
            Ok(types::UpdatePackageVersionsStatusResult {
                successful_versions: Some(ok),
                failed_versions: Some(failed),
            })
        })
    }

    pub(crate) fn delete_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageVersionsRequest,
    ) -> Result<types::DeletePackageVersionsResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:DeletePackageVersions")?;
        self.with_package_mut(ctx, &p, |pkg| {
            let mut ok = BTreeMap::new();
            let mut failed = BTreeMap::new();
            for version in &input.versions {
                match check_version(pkg, version, None, input.expected_status.as_deref()) {
                    Err(e) => {
                        failed.insert(version.clone(), e);
                    }
                    Ok(()) => {
                        let v = pkg.versions.remove(version).expect("checked");
                        pkg.dist_tags.retain(|_, t| t != version);
                        ok.insert(
                            version.clone(),
                            types::SuccessfulPackageVersionInfo {
                                revision: Some(v.revision),
                                status: Some("Deleted".into()),
                            },
                        );
                    }
                }
            }
            Ok(types::DeletePackageVersionsResult { successful_versions: Some(ok), failed_versions: Some(failed) })
        })
    }

    pub(crate) fn dispose_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::DisposePackageVersionsRequest,
    ) -> Result<types::DisposePackageVersionsResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:DisposePackageVersions")?;
        let versions = named_versions(&input.versions, input.version_revisions.as_ref());
        self.with_package_mut(ctx, &p, |pkg| {
            let mut ok = BTreeMap::new();
            let mut failed = BTreeMap::new();
            for version in versions {
                match check_version(pkg, &version, input.version_revisions.as_ref(), input.expected_status.as_deref()) {
                    Err(e) => {
                        failed.insert(version, e);
                    }
                    Ok(()) => {
                        let v = pkg.versions.get_mut(&version).expect("checked");
                        v.assets.clear();
                        v.status = "Disposed".into();
                        ok.insert(
                            version,
                            types::SuccessfulPackageVersionInfo {
                                revision: Some(v.revision.clone()),
                                status: Some("Disposed".into()),
                            },
                        );
                    }
                }
            }
            Ok(types::DisposePackageVersionsResult { successful_versions: Some(ok), failed_versions: Some(failed) })
        })
    }

    pub(crate) fn copy_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::CopyPackageVersionsRequest,
    ) -> Result<types::CopyPackageVersionsResult, ServiceError> {
        let src = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.source_repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        let dst = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.destination_repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        match (&input.versions, &input.version_revisions) {
            (Some(v), None) if !v.is_empty() => {}
            (None, Some(r)) if !r.is_empty() => {}
            _ => return Err(validation("Exactly one of versions or versionRevisions must be specified.")),
        }
        if input.source_repository == input.destination_repository {
            return Err(validation("The source and destination repositories must be different."));
        }
        self.authorize_package(ctx, &src, "codeartifact:ReadFromRepository")?;
        self.authorize_repo(ctx, &dst.owner, dst.domain, dst.repo, "codeartifact:CopyPackageVersions", None)?;
        let versions = named_versions(input.versions.as_deref().unwrap_or_default(), input.version_revisions.as_ref());
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &dst.owner, dst.domain, dst.repo)?;
        if !d.repositories.contains_key(src.repo) {
            return Err(names::repository_not_found(src.repo));
        }
        let key = src.coords.key();
        let mut ok = BTreeMap::new();
        let mut failed = BTreeMap::new();
        let mut copies = Vec::new();
        for version in versions {
            let found = if input.include_from_upstream == Some(true) {
                match upstream::lookup(d, src.repo, &src.coords, &version) {
                    upstream::Lookup::Found { version, .. } => Some(*version),
                    upstream::Lookup::External(_) => None,
                }
            } else {
                d.repositories[src.repo].packages.get(&key).and_then(|p| p.versions.get(&version)).cloned()
            };
            let Some(v) = found else {
                failed.insert(version.clone(), failure("NOT_FOUND", format!("Package version not found: {version}")));
                continue;
            };
            if let Some(r) = input.version_revisions.as_ref().and_then(|r| r.get(&version)) {
                if r != &v.revision {
                    failed.insert(
                        version,
                        failure("MISMATCHED_REVISION", "The package version revision does not match."),
                    );
                    continue;
                }
            }
            if v.status == "Disposed" {
                failed.insert(version, failure("NOT_ALLOWED", "A disposed package version cannot be copied."));
                continue;
            }
            let exists = d.repositories[dst.repo].packages.get(&key).is_some_and(|p| p.versions.contains_key(&version));
            if exists && input.allow_overwrite != Some(true) {
                failed.insert(
                    version,
                    failure("ALREADY_EXISTS", "The package version already exists in the destination repository."),
                );
                continue;
            }
            ok.insert(
                version.clone(),
                types::SuccessfulPackageVersionInfo {
                    revision: Some(v.revision.clone()),
                    status: Some(v.status.clone()),
                },
            );
            copies.push(v);
        }
        if !copies.is_empty() {
            let pkg = upstream::package_for_publish(d, dst.repo, &dst.coords);
            for v in copies {
                pkg.versions.insert(v.version.clone(), v);
            }
        }
        Ok(types::CopyPackageVersionsResult { successful_versions: Some(ok), failed_versions: Some(failed) })
    }

    pub(crate) fn list_package_version_assets(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionAssetsRequest,
    ) -> Result<types::ListPackageVersionAssetsResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:ListPackageVersionAssets")?;
        self.with_package(ctx, &p, |pkg| {
            let v = pkg
                .versions
                .get(&input.package_version)
                .ok_or_else(|| version_not_found(&p.coords.name, &input.package_version))?;
            let all: Vec<_> = v.assets.iter().map(asset_summary).collect();
            let (assets, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
            Ok(types::ListPackageVersionAssetsResult {
                format: Some(p.coords.format.clone()),
                namespace: p.coords.namespace.clone(),
                package: Some(p.coords.name.clone()),
                version: Some(v.version.clone()),
                version_revision: Some(v.revision.clone()),
                next_token,
                assets: Some(assets),
            })
        })
    }

    pub(crate) fn get_package_version_asset(
        &self,
        ctx: &RequestContext,
        input: types::GetPackageVersionAssetRequest,
    ) -> Result<types::GetPackageVersionAssetResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:ReadFromRepository")?;
        self.with_package(ctx, &p, |pkg| {
            let v = pkg
                .versions
                .get(&input.package_version)
                .ok_or_else(|| version_not_found(&p.coords.name, &input.package_version))?;
            if let Some(r) = &input.package_version_revision {
                if r != &v.revision {
                    return Err(names::not_found(
                        "package-version",
                        &input.package_version,
                        format!("Package version revision not found: {r}"),
                    ));
                }
            }
            if matches!(v.status.as_str(), "Archived" | "Disposed") {
                return Err(conflict(
                    "package-version",
                    &input.package_version,
                    format!("Assets of a package version with status {} cannot be downloaded.", v.status),
                ));
            }
            let a = v.asset(&input.asset).ok_or_else(|| {
                names::not_found("asset", &input.asset, format!("Asset not found. Asset name: '{}'", input.asset))
            })?;
            Ok(types::GetPackageVersionAssetResult {
                asset: a.content.clone(),
                asset_name: Some(a.name.clone()),
                package_version: Some(v.version.clone()),
                package_version_revision: Some(v.revision.clone()),
            })
        })
    }

    pub(crate) fn get_package_version_readme(
        &self,
        ctx: &RequestContext,
        input: types::GetPackageVersionReadmeRequest,
    ) -> Result<types::GetPackageVersionReadmeResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:GetPackageVersionReadme")?;
        self.with_package(ctx, &p, |pkg| {
            let v = pkg
                .versions
                .get(&input.package_version)
                .ok_or_else(|| version_not_found(&p.coords.name, &input.package_version))?;
            Ok(types::GetPackageVersionReadmeResult {
                format: Some(p.coords.format.clone()),
                namespace: p.coords.namespace.clone(),
                package: Some(p.coords.name.clone()),
                version: Some(v.version.clone()),
                version_revision: Some(v.revision.clone()),
                readme: v.meta.readme.clone(),
            })
        })
    }

    pub(crate) fn list_package_version_dependencies(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionDependenciesRequest,
    ) -> Result<types::ListPackageVersionDependenciesResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:ListPackageVersionDependencies")?;
        self.with_package(ctx, &p, |pkg| {
            let v = pkg
                .versions
                .get(&input.package_version)
                .ok_or_else(|| version_not_found(&p.coords.name, &input.package_version))?;
            let all: Vec<_> = v
                .meta
                .dependencies
                .iter()
                .map(|d| types::PackageDependency {
                    namespace: d.namespace.clone(),
                    package: Some(d.package.clone()),
                    dependency_type: Some(d.dependency_type.clone()),
                    version_requirement: d.version_requirement.clone(),
                })
                .collect();
            let (dependencies, next_token) = names::page(&all, Some(100), input.next_token.as_deref());
            Ok(types::ListPackageVersionDependenciesResult {
                format: Some(p.coords.format.clone()),
                namespace: p.coords.namespace.clone(),
                package: Some(p.coords.name.clone()),
                version: Some(v.version.clone()),
                version_revision: Some(v.revision.clone()),
                next_token,
                dependencies: Some(dependencies),
            })
        })
    }

    pub(crate) fn publish_package_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishPackageVersionRequest,
    ) -> Result<types::PublishPackageVersionResult, ServiceError> {
        let p = Self::package_ref(
            ctx,
            input.domain_owner.as_deref(),
            &input.domain,
            &input.repository,
            &input.format,
            input.namespace.as_deref(),
            &input.package,
        )?;
        self.authorize_package(ctx, &p, "codeartifact:PublishPackageVersion")?;
        if p.coords.format != "generic" {
            return Err(validation(format!(
                "PublishPackageVersion does not support packages of format '{}'. Only generic packages can be published with this API.",
                p.coords.format
            )));
        }
        let digest = hex::encode(sha2::Sha256::digest(&input.asset_content));
        if !digest.eq_ignore_ascii_case(&input.asset_sha256) {
            return Err(validation(format!(
                "The provided SHA256 hash '{}' does not match the hash of the asset content '{digest}'.",
                input.asset_sha256
            )));
        }
        let mut st = self.write();
        let d = Self::repo_mut(&mut st, ctx, &p.owner, p.domain, p.repo)?;
        let asset = Asset::new(input.asset_name.clone(), input.asset_content);
        let summary = asset_summary(&asset);
        let finished = input.unfinished != Some(true);
        let v = publish(d, p.repo, &p.coords, &input.package_version, asset, None, finished, ctx.received_at, false)?;
        Ok(types::PublishPackageVersionResult {
            format: Some(p.coords.format.clone()),
            namespace: p.coords.namespace.clone(),
            package: Some(p.coords.name.clone()),
            version: Some(v.version.clone()),
            version_revision: Some(v.revision.clone()),
            status: Some(v.status.clone()),
            asset: Some(summary),
        })
    }
}

/// The version a package manager would show: the npm `latest` tag, or
/// the highest published version.
fn default_display_version(pkg: &Package) -> Option<String> {
    if let Some(latest) = pkg.dist_tags.get("latest") {
        return Some(latest.clone());
    }
    pkg.versions
        .values()
        .filter(|v| v.status == "Published")
        .max_by(|a, b| names::compare_versions(&a.version, &b.version))
        .map(|v| v.version.clone())
}
