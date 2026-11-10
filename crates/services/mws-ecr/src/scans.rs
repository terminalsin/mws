//! Image scanning: basic scans (ECR's own, on push or `StartImageScan`) and
//! enhanced scans (Amazon Inspector, when the registry's scan type is
//! `ENHANCED`). Both run on the emulated clock: a basic scan is
//! `IN_PROGRESS` for a few seconds before it is `COMPLETE`; an enhanced
//! scan is `PENDING` until Inspector's initial scan is done, then `ACTIVE`
//! (continuous scanning) or `COMPLETE` (scan on push). MWS has no
//! vulnerability database, so scans find nothing.

use serde_json::json;

use crate::generated::types;
use crate::names::{self, dt};
use crate::state::{Registry, Repo, Scan};
use crate::EcrEvent;

/// How often an image may be scanned with basic scanning.
pub(crate) const SCAN_INTERVAL_MS: i64 = 24 * 3600 * 1000;
/// How long a basic scan is `IN_PROGRESS`.
pub(crate) const BASIC_SCAN_MS: i64 = 5 * 1000;
/// How long an enhanced scan is `PENDING` before Inspector's initial scan
/// completes.
pub(crate) const ENHANCED_SCAN_MS: i64 = 30 * 1000;

/// Whether the registry scans with Amazon Inspector.
pub(crate) fn enhanced(reg: &Registry) -> bool {
    reg.scanning.as_ref().and_then(|s| s.scan_type.as_deref()) == Some("ENHANCED")
}

/// The scan a push of a new image into `repo` starts, if any. With
/// enhanced scanning only the registry's rules count (the repository's
/// `scanOnPush` is ignored); with basic scanning either does.
pub(crate) fn on_push(reg: &Registry, repo: &Repo, now: i64) -> Option<Scan> {
    let rules = reg.scanning.as_ref().and_then(|s| s.rules.clone()).unwrap_or_default();
    let matching = |frequencies: &[&str]| {
        rules
            .iter()
            .filter(|r| frequencies.contains(&r.scan_frequency.as_str()))
            .find(|r| r.repository_filters.iter().any(|f| names::wildcard(&f.filter, &repo.name)))
            .map(|r| r.scan_frequency.clone())
    };
    if enhanced(reg) {
        // A continuous rule wins over a scan-on-push one.
        let frequency = matching(&["CONTINUOUS_SCAN"]).or_else(|| matching(&["SCAN_ON_PUSH"]))?;
        return Some(Scan { status: "PENDING".into(), started_at: now, completed_at: None, enhanced: true, frequency });
    }
    (repo.scan_on_push || matching(&["SCAN_ON_PUSH"]).is_some()).then(|| Scan {
        status: "IN_PROGRESS".into(),
        started_at: now,
        completed_at: None,
        ..Default::default()
    })
}

/// Move a scan on once its time has come; returns the event its
/// completion emits.
pub(crate) fn settle(
    partition: &str,
    reg: &Registry,
    repo: &Repo,
    digest: &str,
    scan: &mut Scan,
    now: i64,
) -> Option<EcrEvent> {
    let tags = repo.content.tags_of(digest);
    match scan.status.as_str() {
        "IN_PROGRESS" if !scan.enhanced && now >= scan.started_at + BASIC_SCAN_MS => {
            let at = scan.started_at + BASIC_SCAN_MS;
            scan.status = "COMPLETE".into();
            scan.completed_at = Some(at);
            Some(EcrEvent {
                partition: partition.to_string(),
                source: "aws.ecr".into(),
                account: reg.account.clone(),
                region: reg.region.clone(),
                detail_type: "ECR Image Scan".into(),
                resources: vec![repo.arn.clone()],
                detail: json!({
                    "scan-status": "COMPLETE",
                    "repository-name": repo.name,
                    "finding-severity-counts": {},
                    "image-digest": digest,
                    "image-tags": tags,
                }),
                time: dt(at),
            })
        }
        "PENDING" if scan.enhanced && now >= scan.started_at + ENHANCED_SCAN_MS => {
            let at = scan.started_at + ENHANCED_SCAN_MS;
            scan.status = if scan.frequency == "CONTINUOUS_SCAN" { "ACTIVE" } else { "COMPLETE" }.into();
            scan.completed_at = Some(at);
            // Inspector's "initial scan complete" event; with no findings
            // there are no "Inspector2 Finding" events.
            Some(EcrEvent {
                partition: partition.to_string(),
                source: "aws.inspector2".into(),
                account: reg.account.clone(),
                region: reg.region.clone(),
                detail_type: "Inspector2 Scan".into(),
                resources: vec![repo.arn.clone()],
                detail: json!({
                    "scan-status": "INITIAL_SCAN_COMPLETE",
                    "repository-name": repo.arn,
                    "finding-severity-counts": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "TOTAL": 0 },
                    "image-digest": digest,
                    "image-tags": tags,
                }),
                time: dt(at),
            })
        }
        _ => None,
    }
}

/// Whether a scan has findings to show (possibly none).
pub(crate) fn has_findings(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "COMPLETE" | "ACTIVE")
}

/// A scan's findings, as `DescribeImageScanFindings` returns them: basic
/// scans list `findings`, enhanced ones `enhancedFindings`.
pub(crate) fn findings(scan: &Scan) -> Option<types::ImageScanFindings> {
    has_findings(scan).then(|| types::ImageScanFindings {
        image_scan_completed_at: scan.completed_at.map(dt),
        vulnerability_source_updated_at: scan.completed_at.map(dt),
        finding_severity_counts: Some(Default::default()),
        findings: (!scan.enhanced).then(Vec::new),
        enhanced_findings: scan.enhanced.then(Vec::new),
    })
}

pub(crate) fn status(scan: &Scan) -> types::ImageScanStatus {
    let description = match scan.status.as_str() {
        "COMPLETE" => "The scan was completed successfully.",
        "IN_PROGRESS" => "The scan is in progress.",
        "UNSUPPORTED_IMAGE" => "The operation is not supported for this image type.",
        "ACTIVE" => "Continuous scan is selected for image.",
        _ => "",
    };
    types::ImageScanStatus {
        status: Some(scan.status.clone()),
        description: (!description.is_empty()).then(|| description.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(scan_type: &str, frequency: &str) -> Registry {
        Registry {
            account: "123456789012".into(),
            region: "us-east-1".into(),
            scanning: Some(types::RegistryScanningConfiguration {
                scan_type: Some(scan_type.into()),
                rules: Some(vec![types::RegistryScanningRule {
                    scan_frequency: frequency.into(),
                    repository_filters: vec![types::ScanningRepositoryFilter {
                        filter: "app*".into(),
                        filter_type: "WILDCARD".into(),
                    }],
                }]),
            }),
            ..Default::default()
        }
    }

    fn repo(name: &str, scan_on_push: bool) -> Repo {
        Repo {
            name: name.into(),
            arn: format!("arn:aws:ecr:us-east-1:123456789012:repository/{name}"),
            scan_on_push,
            ..Default::default()
        }
    }

    #[test]
    fn basic_scans_finish_after_a_few_seconds() {
        let reg = registry("BASIC", "SCAN_ON_PUSH");
        let r = repo("app", false);
        let mut scan = on_push(&reg, &r, 1000).unwrap();
        assert_eq!((scan.status.as_str(), scan.enhanced), ("IN_PROGRESS", false));
        assert!(settle("aws", &reg, &r, "sha256:x", &mut scan, 1000 + BASIC_SCAN_MS - 1).is_none());
        let e = settle("aws", &reg, &r, "sha256:x", &mut scan, 1000 + BASIC_SCAN_MS).unwrap();
        assert_eq!((e.source.as_str(), e.detail_type.as_str()), ("aws.ecr", "ECR Image Scan"));
        assert_eq!(scan.status, "COMPLETE");
        assert!(findings(&scan).unwrap().findings.is_some());
        assert!(on_push(&reg, &repo("other", true), 0).is_some(), "the repository setting applies");
        assert!(on_push(&reg, &repo("other", false), 0).is_none());
    }

    #[test]
    fn enhanced_scans_go_through_inspector() {
        let reg = registry("ENHANCED", "CONTINUOUS_SCAN");
        let r = repo("app", false);
        let mut scan = on_push(&reg, &r, 0).unwrap();
        assert_eq!((scan.status.as_str(), scan.enhanced), ("PENDING", true));
        assert!(findings(&scan).is_none());
        let e = settle("aws", &reg, &r, "sha256:x", &mut scan, ENHANCED_SCAN_MS).unwrap();
        assert_eq!((e.source.as_str(), e.detail_type.as_str()), ("aws.inspector2", "Inspector2 Scan"));
        assert_eq!(scan.status, "ACTIVE");
        let f = findings(&scan).unwrap();
        assert!(f.findings.is_none() && f.enhanced_findings.is_some());
        assert!(on_push(&reg, &repo("other", true), 0).is_none(), "scanOnPush is ignored");
        let reg = registry("ENHANCED", "SCAN_ON_PUSH");
        let mut scan = on_push(&reg, &r, 0).unwrap();
        settle("aws", &reg, &r, "sha256:x", &mut scan, ENHANCED_SCAN_MS);
        assert_eq!(scan.status, "COMPLETE");
    }
}
