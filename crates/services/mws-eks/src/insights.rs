//! Cluster insights: EKS's upgrade-readiness and misconfiguration checks,
//! computed from the cluster's own node groups and add-ons.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use sha2::{Digest, Sha256};

use crate::catalog;
use crate::generated::{errors, types};
use crate::state::{ClusterRec, InsightsRefresh};
use crate::util::{self, text};
use crate::Eks;

/// A stable id per cluster and check.
fn insight_id(cluster_arn: &str, key: &str) -> String {
    let d = Sha256::digest(format!("{cluster_arn}/{key}"));
    let h = hex::encode(&d[..16]);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn status(s: &str, reason: &str) -> types::InsightStatus {
    types::InsightStatus { status: Some(s.into()), reason: Some(reason.into()) }
}

/// Every insight for the cluster, in full.
fn compute(rec: &ClusterRec) -> Vec<types::Insight> {
    let arn = rec.cluster.arn.clone().unwrap_or_default();
    let version = rec.cluster.version.clone().unwrap_or_default();
    let minor = catalog::minor(&version).unwrap_or_default();
    let next = format!("1.{}", minor + 1);
    let refreshed = rec.insights_refresh.as_ref().and_then(|r| r.ended_at).or(rec.cluster.created_at);
    let mut out = Vec::new();
    let mut push = |key: &str,
                    name: &str,
                    category: &str,
                    description: &str,
                    recommendation: &str,
                    st: types::InsightStatus,
                    resources: Vec<types::InsightResourceDetail>,
                    summary: Option<types::InsightCategorySpecificSummary>| {
        out.push(types::Insight {
            id: Some(insight_id(&arn, key)),
            name: Some(name.into()),
            category: Some(category.into()),
            kubernetes_version: Some(next.clone()),
            last_refresh_time: refreshed,
            last_transition_time: rec.cluster.created_at,
            description: Some(description.into()),
            insight_status: Some(st),
            recommendation: Some(recommendation.into()),
            additional_info: Some(BTreeMap::from([(
                "EKS update cluster documentation".to_string(),
                "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html".to_string(),
            )])),
            resources: Some(resources),
            category_specific_summary: summary,
        });
    };

    // Kubelet version skew: node groups more than two minors behind the
    // next version can't follow the upgrade.
    let skewed: Vec<types::InsightResourceDetail> = rec
        .nodegroups
        .values()
        .filter(|n| n.nodegroup.version.as_deref().and_then(catalog::minor).is_some_and(|m| m + 3 <= minor + 1))
        .map(|n| types::InsightResourceDetail {
            insight_status: Some(status("ERROR", "Node kubelet version is too far behind the target version.")),
            kubernetes_resource_uri: None,
            arn: n.nodegroup.nodegroup_arn.clone(),
        })
        .collect();
    push(
        "kubelet-version-skew",
        "Kubelet version skew",
        "UPGRADE_READINESS",
        "Checks for kubelet versions of worker nodes in the cluster to see if upgrade would cause noncompliance with supported Kubernetes kubelet version skew policy.",
        "Upgrade your worker nodes to match the Kubernetes version of your cluster control plane.",
        if skewed.is_empty() {
            status("PASSING", "Node kubelet versions match the cluster control plane's Kubernetes version.")
        } else {
            status("ERROR", "Some nodes have a kubelet version that would be unsupported after the upgrade.")
        },
        skewed,
        None,
    );

    // Add-on compatibility with the next version.
    let mut incompatible = Vec::new();
    let mut details = Vec::new();
    for a in rec.addons.values() {
        let Some(spec) = a.addon_name.as_deref().and_then(catalog::addon) else { continue };
        let current = a.addon_version.clone().unwrap_or_default();
        let compatible: Vec<String> = spec
            .versions
            .iter()
            .filter(|(_, lo, hi)| (*lo..=*hi).contains(&(minor + 1)))
            .map(|(v, _, _)| v.to_string())
            .collect();
        if !compatible.contains(&current) {
            incompatible.push(types::InsightResourceDetail {
                insight_status: Some(status("ERROR", "The add-on version is not compatible with the next version.")),
                kubernetes_resource_uri: None,
                arn: a.addon_arn.clone(),
            });
        }
        details.push(types::AddonCompatibilityDetail {
            name: Some(spec.name.into()),
            compatible_versions: Some(compatible),
        });
    }
    push(
        "addon-version-compatibility",
        "Amazon EKS add-on version compatibility",
        "UPGRADE_READINESS",
        "Checks version of installed EKS add-ons to ensure they are compatible with the next version of Kubernetes.",
        "Upgrade your EKS add-on to a newer version that is supported by the next Kubernetes version.",
        if incompatible.is_empty() {
            status("PASSING", "All installed add-on versions are compatible with the next Kubernetes version.")
        } else {
            status("ERROR", "Some installed add-ons are not compatible with the next Kubernetes version.")
        },
        incompatible,
        Some(types::InsightCategorySpecificSummary {
            deprecation_details: None,
            addon_compatibility_details: Some(details),
        }),
    );

    // Amazon Linux 2 node groups can't move past 1.32.
    let al2: Vec<types::InsightResourceDetail> = rec
        .nodegroups
        .values()
        .filter(|n| n.nodegroup.ami_type.as_deref().is_some_and(|t| t.starts_with("AL2_")))
        .map(|n| types::InsightResourceDetail {
            insight_status: Some(status("ERROR", "The node group runs Amazon Linux 2.")),
            kubernetes_resource_uri: None,
            arn: n.nodegroup.nodegroup_arn.clone(),
        })
        .collect();
    push(
        "amazon-linux-2-compatibility",
        "Amazon Linux 2 compatibility",
        "UPGRADE_READINESS",
        "Checks if any nodes in the cluster are running Amazon Linux 2, which is not supported for Kubernetes 1.33 and later.",
        "Migrate your node groups to Amazon Linux 2023 or Bottlerocket.",
        if al2.is_empty() || minor + 1 < 33 {
            status("PASSING", "No Amazon Linux 2 nodes are blocking the upgrade.")
        } else {
            status("ERROR", "Amazon Linux 2 nodes are not supported in the next Kubernetes version.")
        },
        al2,
        None,
    );

    // Deprecated APIs: nothing calls the API server here, so nothing uses
    // them.
    push(
        "deprecated-apis",
        &format!("Deprecated APIs removed in Kubernetes v{next}"),
        "UPGRADE_READINESS",
        &format!("Checks for usage of deprecated APIs that are scheduled for removal in Kubernetes v{next}."),
        "Update manifests and API clients to use newer Kubernetes APIs if applicable before upgrading.",
        status("PASSING", "No deprecated API usage detected within the last 30 days."),
        Vec::new(),
        Some(types::InsightCategorySpecificSummary {
            deprecation_details: Some(Vec::new()),
            addon_compatibility_details: None,
        }),
    );

    // Cluster health.
    let issues = rec.cluster.health.as_ref().and_then(|h| h.issues.clone()).unwrap_or_default();
    push(
        "cluster-health-issues",
        "Cluster health issues",
        "UPGRADE_READINESS",
        "Checks for any cluster health issues that prevent successful upgrade to the next Kubernetes version on EKS.",
        "Refer to the resolution recommendation of the cluster health issue.",
        if issues.is_empty() {
            status("PASSING", "No cluster health issues detected.")
        } else {
            status("ERROR", "The cluster has health issues.")
        },
        Vec::new(),
        None,
    );

    // Hybrid nodes misconfiguration only applies to clusters with remote
    // networks.
    if rec.cluster.remote_network_config.is_some() {
        push(
            "hybrid-nodes-configuration",
            "Hybrid nodes configuration",
            "MISCONFIGURATION",
            "Checks for misconfiguration of EKS hybrid nodes.",
            "Review the remote node and pod network configuration.",
            status("PASSING", "No misconfiguration detected."),
            Vec::new(),
            None,
        );
    }
    out
}

fn summary(i: &types::Insight) -> types::InsightSummary {
    types::InsightSummary {
        id: i.id.clone(),
        name: i.name.clone(),
        category: i.category.clone(),
        kubernetes_version: i.kubernetes_version.clone(),
        last_refresh_time: i.last_refresh_time,
        last_transition_time: i.last_transition_time,
        description: i.description.clone(),
        insight_status: i.insight_status.clone(),
    }
}

impl Eks {
    pub(crate) async fn list_insights(
        &self,
        ctx: &RequestContext,
        input: types::ListInsightsRequest,
    ) -> Result<types::ListInsightsResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListInsights", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let f = input.filter.clone().unwrap_or_default();
        let all: Vec<types::InsightSummary> = compute(rec)
            .iter()
            .filter(|i| {
                f.categories.as_ref().is_none_or(|c| c.is_empty() || c.iter().any(|x| Some(x) == i.category.as_ref()))
            })
            .filter(|i| {
                f.kubernetes_versions
                    .as_ref()
                    .is_none_or(|v| v.is_empty() || v.iter().any(|x| Some(x) == i.kubernetes_version.as_ref()))
            })
            .filter(|i| {
                f.statuses.as_ref().is_none_or(|s| {
                    s.is_empty()
                        || s.iter().any(|x| Some(x) == i.insight_status.as_ref().and_then(|st| st.status.as_ref()))
                })
            })
            .map(summary)
            .collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListInsightsResponse { insights: Some(items), next_token: next })
    }

    pub(crate) async fn describe_insight(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInsightRequest,
    ) -> Result<types::DescribeInsightResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "DescribeInsight", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let insight =
            compute(rec).into_iter().find(|i| i.id.as_deref() == Some(input.id.as_str())).ok_or_else(|| {
                errors::resource_not_found(format!("No insight found with id: {}", input.id))
                    .with_field("clusterName", text(&input.cluster_name))
            })?;
        Ok(types::DescribeInsightResponse { insight: Some(insight) })
    }

    pub(crate) async fn start_insights_refresh(
        &self,
        ctx: &RequestContext,
        input: types::StartInsightsRefreshRequest,
    ) -> Result<types::StartInsightsRefreshResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "StartInsightsRefresh", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        if rec.insights_refresh.as_ref().is_some_and(|r| r.status == "IN_PROGRESS") {
            return Err(errors::invalid_request("An insights refresh is already in progress for this cluster.")
                .with_field("clusterName", text(&input.cluster_name)));
        }
        rec.insights_refresh =
            Some(InsightsRefresh { status: "IN_PROGRESS".into(), started_at: Some(ctx.received_at), ended_at: None });
        Ok(types::StartInsightsRefreshResponse {
            message: Some("Insights refresh started.".into()),
            status: Some("IN_PROGRESS".into()),
        })
    }

    pub(crate) async fn describe_insights_refresh(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInsightsRefreshRequest,
    ) -> Result<types::DescribeInsightsRefreshResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "DescribeInsightsRefresh",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let r = rec.insights_refresh.clone().unwrap_or(InsightsRefresh {
            status: "COMPLETED".into(),
            started_at: rec.cluster.created_at,
            ended_at: rec.cluster.created_at,
        });
        let message = match r.status.as_str() {
            "IN_PROGRESS" => "Insights refresh is in progress.",
            "COMPLETED" => "Insights refresh completed.",
            _ => "Insights refresh failed.",
        };
        Ok(types::DescribeInsightsRefreshResponse {
            message: Some(message.into()),
            status: Some(r.status),
            started_at: r.started_at,
            ended_at: r.ended_at,
        })
    }
}
