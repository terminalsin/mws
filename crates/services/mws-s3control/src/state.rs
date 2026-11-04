//! S3 Control state. Saved state from older versions still loads: every
//! field defaults.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Access points by ARN.
    pub access_points: BTreeMap<String, AccessPoint>,
    /// Object Lambda access points by ARN.
    pub object_lambdas: BTreeMap<String, ObjectLambda>,
    /// Account-level Block Public Access, by account.
    pub public_access_blocks: BTreeMap<String, types::PublicAccessBlockConfiguration>,
    /// Batch Operations jobs by id.
    pub jobs: BTreeMap<String, crate::jobs::Job>,
    /// Access Grants instances by "account/region".
    pub access_grants: BTreeMap<String, crate::access_grants::Instance>,
    /// Tags of resources that do not hold their own (Access Grants
    /// resources, Storage Lens groups), by ARN.
    pub resource_tags: BTreeMap<String, BTreeMap<String, String>>,
    /// Multi-Region Access Points by "account/name".
    pub mraps: BTreeMap<String, crate::mrap::Mrap>,
    /// Multi-Region Access Point requests by request token ARN.
    pub mrap_requests: BTreeMap<String, crate::mrap::AsyncRequest>,
    /// Storage Lens dashboards by "account/id".
    pub storage_lens: BTreeMap<String, crate::storage_lens::Dashboard>,
    /// Storage Lens groups by "account/name".
    pub storage_lens_groups: BTreeMap<String, crate::storage_lens::Group>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessPoint {
    pub name: String,
    pub arn: String,
    pub account_id: String,
    pub region: String,
    pub bucket: String,
    pub bucket_account_id: String,
    pub alias: String,
    pub vpc_id: Option<String>,
    pub public_access_block: Option<types::PublicAccessBlockConfiguration>,
    pub policy: Option<String>,
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    pub tags: BTreeMap<String, String>,
    pub scope: Option<types::Scope>,
}

impl AccessPoint {
    /// Whether this access point is attached to a directory bucket.
    pub fn directory(&self) -> bool {
        self.bucket.ends_with("--x-s3")
    }

    pub fn network_origin(&self) -> &'static str {
        if self.vpc_id.is_some() {
            "VPC"
        } else {
            "Internet"
        }
    }

    pub fn pab(&self) -> types::PublicAccessBlockConfiguration {
        self.public_access_block.clone().unwrap_or(types::PublicAccessBlockConfiguration {
            block_public_acls: true,
            ignore_public_acls: true,
            block_public_policy: true,
            restrict_public_buckets: true,
        })
    }

    pub fn public(&self) -> mws_s3::AccessPoint {
        mws_s3::AccessPoint {
            name: self.name.clone(),
            arn: self.arn.clone(),
            account_id: self.account_id.clone(),
            bucket: self.bucket.clone(),
            alias: self.alias.clone(),
            network_origin: self.network_origin().to_string(),
            policy: self.policy.clone(),
            restrict_public_buckets: self.pab().restrict_public_buckets,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ObjectLambda {
    pub name: String,
    pub arn: String,
    pub account_id: String,
    pub region: String,
    pub alias: String,
    pub configuration: Option<types::ObjectLambdaConfiguration>,
    pub policy: Option<String>,
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

impl ObjectLambda {
    pub fn public(&self) -> mws_s3::ObjectLambdaAccessPoint {
        let c = self.configuration.clone();
        mws_s3::ObjectLambdaAccessPoint {
            name: self.name.clone(),
            arn: self.arn.clone(),
            account_id: self.account_id.clone(),
            alias: self.alias.clone(),
            supporting_access_point: c.as_ref().map(|c| c.supporting_access_point.clone()).unwrap_or_default(),
            allowed_features: c.as_ref().and_then(|c| c.allowed_features.clone()).unwrap_or_default(),
            transformations: c
                .map(|c| {
                    c.transformation_configurations
                        .into_iter()
                        .map(|t| {
                            let types::ObjectLambdaContentTransformation::AwsLambda(l) = t.content_transformation;
                            mws_s3::Transformation {
                                actions: t.actions,
                                function_arn: l.function_arn,
                                payload: l.function_payload,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            policy: self.policy.clone(),
        }
    }
}
