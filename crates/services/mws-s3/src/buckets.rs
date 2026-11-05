//! Buckets: create, delete, list, head, location, versioning, policy,
//! tags, ACLs, ownership controls and Block Public Access.

use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::acl::{self, GrantHeaders};
use crate::auth::{self, bucket_arn, Resource};
use crate::errors;
use crate::generated::types;
use crate::state::{Bucket, State};
use crate::Call;

/// Check a bucket name against S3's general purpose bucket naming rules.
pub fn valid_bucket_name(name: &str) -> bool {
    let len_ok = (3..=63).contains(&name.len());
    let chars_ok = name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    let ends_ok = name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && name.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric());
    let ip = name.split('.').count() == 4 && name.split('.').all(|p| p.parse::<u8>().is_ok());
    let reserved_prefix = ["xn--", "sthree-", "amzn-s3-demo-"].iter().any(|p| name.starts_with(p));
    let reserved_suffix = ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"].iter().any(|s| name.ends_with(s));
    len_ok && chars_ok && ends_ok && !ip && !name.contains("..") && !reserved_prefix && !reserved_suffix
}

/// Validate a tag set: unique keys, lengths, no `aws:` keys, and at most
/// `max` tags.
pub fn validate_tags(tags: &[types::Tag], max: usize, object: bool) -> Result<(), ServiceError> {
    if tags.len() > max {
        return Err(if object {
            ServiceError::client("BadRequest", 400, "Object tags cannot be greater than 10")
        } else {
            errors::invalid_tag("Bucket tag count cannot be greater than 50", None)
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for t in tags {
        if t.key.is_empty() || t.key.chars().count() > 128 {
            return Err(errors::invalid_tag("The TagKey you have provided is invalid", Some(&t.key)));
        }
        if t.value.chars().count() > 256 {
            return Err(errors::invalid_tag("The TagValue you have provided is invalid", Some(&t.key)));
        }
        if t.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_tag("System tags cannot be added/updated by requester", Some(&t.key)));
        }
        if !seen.insert(t.key.as_str()) {
            return Err(errors::invalid_tag("Cannot provide multiple Tags with the same key", Some(&t.key)));
        }
    }
    Ok(())
}

/// `ExpectedBucketOwner` must name the owner, or S3 answers 403.
pub fn check_owner(bucket: &Bucket, expected: Option<&str>) -> Result<(), ServiceError> {
    match expected {
        Some(e) if e != bucket.owner => Err(errors::access_denied("Access Denied")),
        _ => Ok(()),
    }
}

impl Call {
    /// Look up `name`, check `ExpectedBucketOwner`, authorize `action` on
    /// the bucket, then run `f`.
    pub fn bucket_read<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        expected_owner: Option<&str>,
        action: &str,
        f: impl FnOnce(&Bucket) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let st = self.read();
        let b = st.buckets.get(name).ok_or_else(|| errors::no_such_bucket(name))?;
        check_owner(b, expected_owner)?;
        self.authorize(ctx, action, b, Resource::Bucket, ConditionContext::new())?;
        f(b)
    }

    /// Like [`Call::bucket_read`], with the bucket mutable.
    pub fn bucket_write<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        expected_owner: Option<&str>,
        action: &str,
        f: impl FnOnce(&mut Bucket) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let mut st = self.write();
        let b = st.buckets.get_mut(name).ok_or_else(|| errors::no_such_bucket(name))?;
        check_owner(b, expected_owner)?;
        self.authorize(ctx, action, b, Resource::Bucket, ConditionContext::new())?;
        f(b)
    }

    pub fn create_bucket(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketRequest,
    ) -> Result<types::CreateBucketOutput, ServiceError> {
        let name = input.bucket.clone();
        let config = input.create_bucket_configuration.clone().unwrap_or_default();
        if let Some(directory) = crate::directory::directory_config(&name, &config)? {
            return self.create_directory_bucket(ctx, &name, directory);
        }
        if !valid_bucket_name(&name) {
            return Err(errors::invalid_bucket_name(&name));
        }
        let region = match config.location_constraint.as_deref() {
            None | Some("") => {
                if ctx.region != "us-east-1" {
                    return Err(ServiceError::client(
                        "IllegalLocationConstraintException",
                        400,
                        "The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.",
                    ));
                }
                "us-east-1".to_string()
            }
            Some("us-east-1") => {
                return Err(ServiceError::client(
                    "InvalidLocationConstraint",
                    400,
                    "The specified location-constraint is not valid",
                )
                .with_field("LocationConstraint", mws_core::ErrorValue::String("us-east-1".into())));
            }
            Some(lc) => {
                let region = if lc == "EU" { "eu-west-1" } else { lc };
                if region != ctx.region {
                    return Err(ServiceError::client(
                        "IllegalLocationConstraintException",
                        400,
                        format!(
                            "The {lc} location constraint is incompatible for the region specific endpoint this request was sent to."
                        ),
                    ));
                }
                region.to_string()
            }
        };
        if let Some(tags) = &config.tags {
            validate_tags(tags, 50, false)?;
        }
        let account = ctx.caller.account_id.clone();
        let mut extra = ConditionContext::new();
        extra.insert("s3:LocationConstraint".into(), vec![region.clone()]);
        if let Some(acl) = &input.acl {
            extra.insert("s3:x-amz-acl".into(), vec![acl.clone()]);
        }
        if let Some(o) = &input.object_ownership {
            extra.insert("s3:x-amz-object-ownership".into(), vec![o.clone()]);
        }
        if let Some(tags) = &config.tags {
            extra.extend(request_tag_context(tags));
        }
        self.authorize_plain(ctx, "s3:CreateBucket", &bucket_arn(ctx, &name), extra)?;
        if input.object_lock_enabled_for_bucket == Some(true) {
            for action in ["s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning"] {
                self.authorize_plain(ctx, action, &bucket_arn(ctx, &name), ConditionContext::new())?;
            }
        }

        let ownership = input.object_ownership.clone().unwrap_or_else(|| "BucketOwnerEnforced".into());
        let headers = GrantHeaders {
            full_control: input.grant_full_control.as_deref(),
            read: input.grant_read.as_deref(),
            read_acp: input.grant_read_acp.as_deref(),
            write: input.grant_write.as_deref(),
            write_acp: input.grant_write_acp.as_deref(),
        };
        if input.acl.is_some() && headers.any() {
            return Err(errors::invalid_request("Specifying both Canned ACLs and Header Grants is not allowed"));
        }
        let grants = if headers.any() {
            let mut g = acl::canned("private", &account, &account)?;
            let extra = headers.grants()?;
            acl::validate_grants(&extra, &account)?;
            g.extend(extra);
            g
        } else {
            acl::canned(input.acl.as_deref().unwrap_or("private"), &account, &account)?
        };
        if ownership == "BucketOwnerEnforced" && !acl::is_owner_only(&grants, &account) {
            return Err(ServiceError::client(
                "InvalidBucketAclWithObjectOwnership",
                400,
                "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
            ));
        }

        let bucket_limit = match self.links.quotas.get() {
            Some(q) => q.applied_value(&account, &ctx.region, "s3", BUCKETS_QUOTA, ctx.received_at),
            None => mws_servicequotas::catalog::quota("s3", BUCKETS_QUOTA).map_or(f64::INFINITY, |d| d.value),
        };
        let mut st = self.write();
        if !st.buckets.contains_key(&name)
            && st.buckets.values().filter(|b| b.owner == account).count() as f64 >= bucket_limit
        {
            return Err(ServiceError::client(
                "TooManyBuckets",
                400,
                "You have attempted to create more buckets than allowed",
            ));
        }
        if let Some(existing) = st.buckets.get(&name) {
            if existing.owner != account {
                return Err(errors::bucket_already_exists(&name));
            }
            // us-east-1 answers success for a bucket you already own there.
            if existing.region == "us-east-1" && region == "us-east-1" {
                return Ok(types::CreateBucketOutput {
                    location: Some(format!("/{name}")),
                    bucket_arn: Some(bucket_arn(ctx, &name)),
                });
            }
            return Err(errors::bucket_already_owned_by_you(&name));
        }
        let lock = input.object_lock_enabled_for_bucket == Some(true);
        let bucket = Bucket {
            name: name.clone(),
            region: region.clone(),
            owner: account,
            created: ctx.received_at,
            versioning: lock.then(|| "Enabled".to_string()),
            ownership: Some(ownership),
            acl: grants,
            object_lock_enabled: lock,
            object_lock: lock
                .then(|| types::ObjectLockConfiguration { object_lock_enabled: Some("Enabled".into()), rule: None }),
            tags: config.tags.clone().filter(|t| !t.is_empty()),
            ..Bucket::default()
        };
        st.buckets.insert(name.clone(), bucket);
        let location =
            if region == "us-east-1" { format!("/{name}") } else { format!("http://{name}.s3.amazonaws.com/") };
        Ok(types::CreateBucketOutput { location: Some(location), bucket_arn: Some(bucket_arn(ctx, &name)) })
    }

    /// Authorize an action that has no bucket to consult (CreateBucket,
    /// ListBuckets), worded as S3 words denials.
    pub fn authorize_plain(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        match ctx.check(action, resource, None, mws_core::ResourcePolicyMode::Optional, extra) {
            mws_core::AuthzDecision::Allow => Ok(()),
            _ if ctx.caller.kind == CallerKind::Anonymous => Err(errors::access_denied("Access Denied")),
            mws_core::AuthzDecision::Deny { reason, .. } => {
                let reason = if reason.is_empty() { String::new() } else { format!(" {reason}") };
                Err(errors::access_denied(format!(
                    "User: {} is not authorized to perform: {action} on resource: \"{resource}\"{reason}",
                    ctx.caller.arn
                )))
            }
        }
    }

    pub fn delete_bucket(&self, ctx: &RequestContext, input: types::DeleteBucketRequest) -> Result<(), ServiceError> {
        let mut st = self.write();
        {
            let b = st.buckets.get(&input.bucket).ok_or_else(|| errors::no_such_bucket(&input.bucket))?;
            check_owner(b, input.expected_bucket_owner.as_deref())?;
            self.authorize(ctx, "s3:DeleteBucket", b, Resource::Bucket, ConditionContext::new())?;
            if !b.is_empty() {
                return Err(errors::bucket_not_empty(&b.name, b.versioning.is_some()));
            }
        }
        st.buckets.remove(&input.bucket);
        Ok(())
    }

    pub fn head_bucket(
        &self,
        ctx: &RequestContext,
        input: types::HeadBucketRequest,
    ) -> Result<types::HeadBucketOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:ListBucket", |b| {
            Ok(types::HeadBucketOutput {
                bucket_arn: Some(bucket_arn(ctx, &b.name)),
                bucket_region: Some(b.region.clone()),
                access_point_alias: Some(false),
                ..Default::default()
            })
        })
    }

    pub fn list_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListBucketsRequest,
    ) -> Result<types::ListBucketsOutput, ServiceError> {
        self.authorize_plain(ctx, "s3:ListAllMyBuckets", "*", ConditionContext::new())?;
        let max = match input.max_buckets {
            Some(n) if !(1..=10000).contains(&n) => {
                return Err(errors::invalid_argument(
                    "Argument max-buckets must be an integer between 1 and 10000",
                    "max-buckets",
                    &n.to_string(),
                ))
            }
            Some(n) => n as usize,
            None => usize::MAX,
        };
        let after = match &input.continuation_token {
            Some(t) => Some(decode_token(t).ok_or_else(|| {
                errors::invalid_argument("The continuation token provided is incorrect", "continuation-token", t)
            })?),
            None => None,
        };
        let st = self.read();
        let mut buckets: Vec<&Bucket> = st
            .buckets
            .values()
            .filter(|b| b.owner == ctx.caller.account_id && b.directory.is_none())
            .filter(|b| input.prefix.as_deref().is_none_or(|p| b.name.starts_with(p)))
            .filter(|b| input.bucket_region.as_deref().is_none_or(|r| b.region == r))
            .filter(|b| after.as_deref().is_none_or(|a| b.name.as_str() > a))
            .collect();
        let truncated = buckets.len() > max;
        buckets.truncate(max);
        let next = truncated.then(|| encode_token(&buckets.last().map(|b| b.name.clone()).unwrap_or_default()));
        Ok(types::ListBucketsOutput {
            buckets: Some(
                buckets
                    .into_iter()
                    .map(|b| types::Bucket {
                        name: Some(b.name.clone()),
                        creation_date: Some(b.created),
                        bucket_region: Some(b.region.clone()),
                        bucket_arn: Some(bucket_arn(ctx, &b.name)),
                    })
                    .collect(),
            ),
            owner: Some(acl::owner(&ctx.caller.account_id)),
            continuation_token: next,
            prefix: input.prefix,
        })
    }

    pub fn get_bucket_location(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLocationRequest,
    ) -> Result<types::GetBucketLocationOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketLocation", |b| {
            Ok(types::GetBucketLocationOutput {
                location_constraint: (b.region != "us-east-1").then(|| b.region.clone()),
            })
        })
    }

    pub fn get_bucket_versioning(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketVersioningRequest,
    ) -> Result<types::GetBucketVersioningOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketVersioning", |b| {
            Ok(types::GetBucketVersioningOutput { status: b.versioning.clone(), mfa_delete: b.mfa_delete.clone() })
        })
    }

    pub fn put_bucket_versioning(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketVersioningRequest,
    ) -> Result<(), ServiceError> {
        let config = input.versioning_configuration;
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketVersioning", |b| {
            if let Some(status) = &config.status {
                if !matches!(status.as_str(), "Enabled" | "Suspended") {
                    return Err(errors::malformed_xml());
                }
                if status == "Suspended" && b.object_lock_enabled {
                    return Err(errors::invalid_bucket_state(
                        "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                    ));
                }
            }
            if let Some(m) = &config.mfa_delete {
                if m == "Enabled" && input.mfa.is_none() {
                    return Err(errors::invalid_request(
                        "DevPay and Mfa are mutually exclusive authorization methods.",
                    ));
                }
                b.mfa_delete = Some(m.clone());
            }
            if let Some(status) = config.status {
                b.versioning = Some(status);
            }
            Ok(())
        })
    }

    pub fn get_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketPolicyRequest,
    ) -> Result<types::GetBucketPolicyOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketPolicy", |b| {
            let policy = b.policy.clone().ok_or_else(|| {
                errors::not_found_config("NoSuchBucketPolicy", "The bucket policy does not exist", &b.name)
            })?;
            Ok(types::GetBucketPolicyOutput { policy: Some(policy) })
        })
    }

    pub fn put_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketPolicyRequest,
    ) -> Result<(), ServiceError> {
        let partition = ctx.partition.clone();
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketPolicy", |b| {
            auth::validate_policy(&input.policy, &partition, &b.name)?;
            if self.pab(b).block_public_policy.unwrap_or(false) && auth::policy_is_public(&input.policy) {
                return Err(errors::access_denied(format!(
                    "User: {} is not authorized to perform: s3:PutBucketPolicy on resource: \"{}\" because public policies are blocked by the BlockPublicPolicy block public access setting.",
                    ctx.caller.arn,
                    bucket_arn(ctx, &b.name)
                )));
            }
            b.policy = Some(input.policy);
            Ok(())
        })
    }

    pub fn delete_bucket_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:DeleteBucketPolicy", |b| {
            b.policy = None;
            Ok(())
        })
    }

    pub fn get_bucket_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketPolicyStatusRequest,
    ) -> Result<types::GetBucketPolicyStatusOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketPolicyStatus", |b| {
            let policy = b.policy.as_deref().ok_or_else(|| {
                errors::not_found_config("NoSuchBucketPolicy", "The bucket policy does not exist", &b.name)
            })?;
            Ok(types::GetBucketPolicyStatusOutput {
                policy_status: Some(types::PolicyStatus { is_public: Some(auth::policy_is_public(policy)) }),
            })
        })
    }

    pub fn get_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketTaggingRequest,
    ) -> Result<types::GetBucketTaggingOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketTagging", |b| {
            let tags = b.tags.clone().ok_or_else(|| errors::no_such_tag_set(&b.name))?;
            Ok(types::GetBucketTaggingOutput { tag_set: tags })
        })
    }

    pub fn put_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketTaggingRequest,
    ) -> Result<(), ServiceError> {
        validate_tags(&input.tagging.tag_set, 50, false)?;
        let mut st = self.write();
        let b = st.buckets.get_mut(&input.bucket).ok_or_else(|| errors::no_such_bucket(&input.bucket))?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        let context = request_tag_context(&input.tagging.tag_set);
        self.authorize(ctx, "s3:PutBucketTagging", b, Resource::Bucket, context)?;
        b.tags = Some(input.tagging.tag_set);
        Ok(())
    }

    pub fn delete_bucket_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketTaggingRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketTagging", |b| {
            b.tags = None;
            Ok(())
        })
    }

    pub fn get_bucket_acl(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAclRequest,
    ) -> Result<types::GetBucketAclOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketAcl", |b| {
            Ok(types::GetBucketAclOutput { owner: Some(acl::owner(&b.owner)), grants: Some(b.acl.clone()) })
        })
    }

    pub fn put_bucket_acl(&self, ctx: &RequestContext, input: types::PutBucketAclRequest) -> Result<(), ServiceError> {
        let headers = GrantHeaders {
            full_control: input.grant_full_control.as_deref(),
            read: input.grant_read.as_deref(),
            read_acp: input.grant_read_acp.as_deref(),
            write: input.grant_write.as_deref(),
            write_acp: input.grant_write_acp.as_deref(),
        };
        let mut extra = ConditionContext::new();
        if let Some(a) = &input.acl {
            extra.insert("s3:x-amz-acl".into(), vec![a.clone()]);
        }
        let mut st = self.write();
        let b = st.buckets.get_mut(&input.bucket).ok_or_else(|| errors::no_such_bucket(&input.bucket))?;
        check_owner(b, input.expected_bucket_owner.as_deref())?;
        self.authorize(ctx, "s3:PutBucketAcl", b, Resource::Bucket, extra)?;
        let grants =
            resolve_acl(input.acl.as_deref(), &headers, input.access_control_policy.as_ref(), &b.owner, &b.owner)?;
        apply_acl_rules(b, &grants)?;
        b.acl = grants;
        Ok(())
    }

    pub fn get_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketOwnershipControlsRequest,
    ) -> Result<types::GetBucketOwnershipControlsOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketOwnershipControls",
            |b| {
                let o = b.ownership.clone().ok_or_else(|| {
                    errors::not_found_config(
                        "OwnershipControlsNotFoundError",
                        "The bucket ownership controls were not found",
                        &b.name,
                    )
                })?;
                Ok(types::GetBucketOwnershipControlsOutput {
                    ownership_controls: Some(types::OwnershipControls {
                        rules: vec![types::OwnershipControlsRule { object_ownership: o }],
                    }),
                })
            },
        )
    }

    pub fn put_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketOwnershipControlsRequest,
    ) -> Result<(), ServiceError> {
        let rules = input.ownership_controls.rules;
        let [rule] = rules.as_slice() else { return Err(errors::malformed_xml()) };
        let ownership = rule.object_ownership.clone();
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketOwnershipControls",
            |b| {
                if ownership == "BucketOwnerEnforced" && !acl::is_owner_only(&b.acl, &b.owner) {
                    return Err(ServiceError::client(
                        "InvalidBucketAclWithObjectOwnership",
                        400,
                        "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
                    ));
                }
                b.ownership = Some(ownership);
                Ok(())
            },
        )
    }

    pub fn delete_bucket_ownership_controls(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketOwnershipControlsRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketOwnershipControls",
            |b| {
                b.ownership = None;
                Ok(())
            },
        )
    }

    pub fn get_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicAccessBlockRequest,
    ) -> Result<types::GetPublicAccessBlockOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketPublicAccessBlock",
            |b| {
                let c = b.public_access_block.clone().ok_or_else(|| {
                    errors::not_found_config(
                        "NoSuchPublicAccessBlockConfiguration",
                        "The public access block configuration was not found",
                        &b.name,
                    )
                })?;
                Ok(types::GetPublicAccessBlockOutput { public_access_block_configuration: Some(c) })
            },
        )
    }

    pub fn put_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::PutPublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        let mut c = input.public_access_block_configuration;
        for f in [
            &mut c.block_public_acls,
            &mut c.ignore_public_acls,
            &mut c.block_public_policy,
            &mut c.restrict_public_buckets,
        ] {
            f.get_or_insert(false);
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketPublicAccessBlock",
            |b| {
                b.public_access_block = Some(c);
                Ok(())
            },
        )
    }

    pub fn delete_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketPublicAccessBlock",
            |b| {
                b.public_access_block = None;
                Ok(())
            },
        )
    }
}

/// Grants from exactly one of: a canned ACL, grant headers, or an
/// `AccessControlPolicy` body.
pub fn resolve_acl(
    canned: Option<&str>,
    headers: &GrantHeaders<'_>,
    body: Option<&types::AccessControlPolicy>,
    owner: &str,
    bucket_owner: &str,
) -> Result<Vec<types::Grant>, ServiceError> {
    let sources = canned.is_some() as u8 + headers.any() as u8 + body.is_some() as u8;
    if sources > 1 {
        return Err(if body.is_some() {
            errors::invalid_request("Specifying both Canned ACLs and Header Grants is not allowed")
                .with_field("ArgumentName", mws_core::ErrorValue::String("x-amz-acl".into()))
        } else {
            errors::invalid_request("Specifying both Canned ACLs and Header Grants is not allowed")
        });
    }
    if let Some(c) = canned {
        return acl::canned(c, owner, bucket_owner);
    }
    if headers.any() {
        let grants = headers.grants()?;
        acl::validate_grants(&grants, owner)?;
        return Ok(grants);
    }
    match body {
        Some(policy) => {
            let grants = policy.grants.clone().unwrap_or_default();
            acl::validate_grants(&grants, owner)?;
            Ok(grants)
        }
        None => Err(errors::malformed_xml()),
    }
}

/// ACL-disabled buckets only accept owner-only ACLs; Block Public Access
/// rejects public ones.
pub fn apply_acl_rules(b: &Bucket, grants: &[types::Grant]) -> Result<(), ServiceError> {
    if !b.acls_enabled() && !acl::is_owner_only(grants, &b.owner) {
        return Err(errors::acls_not_supported());
    }
    if b.pab().block_public_acls.unwrap_or(false) && acl::is_public(grants) {
        return Err(errors::access_denied("Access Denied"));
    }
    Ok(())
}

pub fn encode_token(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

pub fn decode_token(t: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(t).ok().and_then(|b| String::from_utf8(b).ok())
}

impl State {
    /// The bucket, or NoSuchBucket.
    pub fn bucket(&self, name: &str) -> Result<&Bucket, ServiceError> {
        self.buckets.get(name).ok_or_else(|| errors::no_such_bucket(name))
    }

    pub fn bucket_mut(&mut self, name: &str) -> Result<&mut Bucket, ServiceError> {
        self.buckets.get_mut(name).ok_or_else(|| errors::no_such_bucket(name))
    }
}

/// `aws:RequestTag/<key>` and `aws:TagKeys` for tags a request sets.
fn request_tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut c: ConditionContext =
        tags.iter().map(|t| (format!("aws:RequestTag/{}", t.key), vec![t.value.clone()])).collect();
    c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        for ok in ["abc", "my-bucket.example", "a1b2c3", "0bucket"] {
            assert!(valid_bucket_name(ok), "{ok}");
        }
        for bad in ["ab", "Abc", "a..b", "-ab", "ab-", "192.168.1.1", "xn--abc", "abc-s3alias", "a_b", &"a".repeat(64)]
        {
            assert!(!valid_bucket_name(bad), "{bad}");
        }
    }
}

/// Service Quotas' "General purpose buckets" quota.
const BUCKETS_QUOTA: &str = "L-DC2B2D3D";
