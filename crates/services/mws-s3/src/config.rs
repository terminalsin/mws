//! Bucket subresources that S3 stores and returns: CORS, default
//! encryption, lifecycle, website, logging, notifications, accelerate,
//! request payment, replication, object lock, ABAC, and the keyed
//! analytics / metrics / inventory / Intelligent-Tiering configurations.
//! Lifecycle rules run in [`crate::lifecycle`] and replication rules in
//! [`crate::replication`]; MWS does not act on logging, inventory or
//! notifications.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::buckets::{decode_token, encode_token};
use crate::errors;
use crate::generated::types;
use crate::Call;

const CORS_METHODS: &[&str] = &["GET", "PUT", "HEAD", "POST", "DELETE"];

pub fn default_encryption() -> types::ServerSideEncryptionConfiguration {
    types::ServerSideEncryptionConfiguration {
        rules: vec![types::ServerSideEncryptionRule {
            apply_server_side_encryption_by_default: Some(types::ServerSideEncryptionByDefault {
                sse_algorithm: "AES256".into(),
                kms_master_key_id: None,
            }),
            bucket_key_enabled: Some(false),
            blocked_encryption_types: None,
        }],
    }
}

/// Page through a keyed configuration map, 100 at a time like S3.
fn page<T: Clone>(
    map: &BTreeMap<String, T>,
    token: Option<&str>,
) -> Result<(Vec<T>, bool, Option<String>), ServiceError> {
    let after = match token {
        Some(t) => Some(decode_token(t).ok_or_else(|| {
            errors::invalid_argument("The continuation token provided is incorrect", "continuation-token", t)
        })?),
        None => None,
    };
    let items: Vec<(&String, &T)> =
        map.iter().filter(|(k, _)| after.as_deref().is_none_or(|a| k.as_str() > a)).collect();
    let truncated = items.len() > 100;
    let page: Vec<(&String, &T)> = items.into_iter().take(100).collect();
    let next = truncated.then(|| encode_token(page.last().map(|(k, _)| k.as_str()).unwrap_or_default()));
    Ok((page.into_iter().map(|(_, v)| v.clone()).collect(), truncated, next))
}

fn check_id(id: &str) -> Result<(), ServiceError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return Err(errors::invalid_argument("The configuration ID is not valid.", "id", id));
    }
    Ok(())
}

macro_rules! keyed_config {
    ($field:ident, $get_action:literal, $put_action:literal, $max:literal,
     $get:ident, $get_in:ident, $get_out:ident, $out_field:ident,
     $put:ident, $put_in:ident, $in_field:ident,
     $del:ident, $del_in:ident,
     $list:ident, $list_in:ident, $list_out:ident, $list_field:ident) => {
        impl Call {
            pub fn $get(&self, ctx: &RequestContext, input: types::$get_in) -> Result<types::$get_out, ServiceError> {
                self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), $get_action, |b| {
                    let c = b.$field.get(&input.id).cloned().ok_or_else(errors::no_such_configuration)?;
                    Ok(types::$get_out { $out_field: Some(c) })
                })
            }

            pub fn $put(&self, ctx: &RequestContext, input: types::$put_in) -> Result<(), ServiceError> {
                check_id(&input.id)?;
                let mut config = input.$in_field;
                config.id = input.id.clone();
                self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), $put_action, |b| {
                    if !b.$field.contains_key(&input.id) && b.$field.len() >= $max {
                        return Err(ServiceError::client(
                            "TooManyConfigurations",
                            400,
                            "You are attempting to create a new configuration but have already reached the limit.",
                        ));
                    }
                    b.$field.insert(input.id, config);
                    Ok(())
                })
            }

            pub fn $del(&self, ctx: &RequestContext, input: types::$del_in) -> Result<(), ServiceError> {
                self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), $put_action, |b| {
                    b.$field.remove(&input.id).map(|_| ()).ok_or_else(errors::no_such_configuration)
                })
            }

            pub fn $list(
                &self,
                ctx: &RequestContext,
                input: types::$list_in,
            ) -> Result<types::$list_out, ServiceError> {
                self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), $get_action, |b| {
                    let (items, truncated, next) = page(&b.$field, input.continuation_token.as_deref())?;
                    Ok(types::$list_out {
                        is_truncated: Some(truncated),
                        continuation_token: input.continuation_token.clone(),
                        next_continuation_token: next,
                        $list_field: (!items.is_empty()).then_some(items),
                    })
                })
            }
        }
    };
}

keyed_config!(
    analytics,
    "s3:GetAnalyticsConfiguration",
    "s3:PutAnalyticsConfiguration",
    1000,
    get_bucket_analytics_configuration,
    GetBucketAnalyticsConfigurationRequest,
    GetBucketAnalyticsConfigurationOutput,
    analytics_configuration,
    put_bucket_analytics_configuration,
    PutBucketAnalyticsConfigurationRequest,
    analytics_configuration,
    delete_bucket_analytics_configuration,
    DeleteBucketAnalyticsConfigurationRequest,
    list_bucket_analytics_configurations,
    ListBucketAnalyticsConfigurationsRequest,
    ListBucketAnalyticsConfigurationsOutput,
    analytics_configuration_list
);
keyed_config!(
    metrics,
    "s3:GetMetricsConfiguration",
    "s3:PutMetricsConfiguration",
    1000,
    get_bucket_metrics_configuration,
    GetBucketMetricsConfigurationRequest,
    GetBucketMetricsConfigurationOutput,
    metrics_configuration,
    put_bucket_metrics_configuration,
    PutBucketMetricsConfigurationRequest,
    metrics_configuration,
    delete_bucket_metrics_configuration,
    DeleteBucketMetricsConfigurationRequest,
    list_bucket_metrics_configurations,
    ListBucketMetricsConfigurationsRequest,
    ListBucketMetricsConfigurationsOutput,
    metrics_configuration_list
);
keyed_config!(
    inventory,
    "s3:GetInventoryConfiguration",
    "s3:PutInventoryConfiguration",
    1000,
    get_bucket_inventory_configuration,
    GetBucketInventoryConfigurationRequest,
    GetBucketInventoryConfigurationOutput,
    inventory_configuration,
    put_bucket_inventory_configuration,
    PutBucketInventoryConfigurationRequest,
    inventory_configuration,
    delete_bucket_inventory_configuration,
    DeleteBucketInventoryConfigurationRequest,
    list_bucket_inventory_configurations,
    ListBucketInventoryConfigurationsRequest,
    ListBucketInventoryConfigurationsOutput,
    inventory_configuration_list
);
keyed_config!(
    intelligent_tiering,
    "s3:GetIntelligentTieringConfiguration",
    "s3:PutIntelligentTieringConfiguration",
    1000,
    get_bucket_intelligent_tiering_configuration,
    GetBucketIntelligentTieringConfigurationRequest,
    GetBucketIntelligentTieringConfigurationOutput,
    intelligent_tiering_configuration,
    put_bucket_intelligent_tiering_configuration,
    PutBucketIntelligentTieringConfigurationRequest,
    intelligent_tiering_configuration,
    delete_bucket_intelligent_tiering_configuration,
    DeleteBucketIntelligentTieringConfigurationRequest,
    list_bucket_intelligent_tiering_configurations,
    ListBucketIntelligentTieringConfigurationsRequest,
    ListBucketIntelligentTieringConfigurationsOutput,
    intelligent_tiering_configuration_list
);

impl Call {
    pub fn get_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketCorsRequest,
    ) -> Result<types::GetBucketCorsOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketCORS", |b| {
            let c = b.cors.clone().ok_or_else(|| {
                errors::not_found_config("NoSuchCORSConfiguration", "The CORS configuration does not exist", &b.name)
            })?;
            Ok(types::GetBucketCorsOutput { cors_rules: Some(c.cors_rules) })
        })
    }

    pub fn put_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketCorsRequest,
    ) -> Result<(), ServiceError> {
        let config = input.cors_configuration;
        if config.cors_rules.is_empty() || config.cors_rules.len() > 100 {
            return Err(errors::malformed_xml());
        }
        for rule in &config.cors_rules {
            if rule.allowed_methods.is_empty() || rule.allowed_origins.is_empty() {
                return Err(errors::malformed_xml());
            }
            for m in &rule.allowed_methods {
                if !CORS_METHODS.contains(&m.as_str()) {
                    return Err(errors::invalid_request(format!(
                        "Found unsupported HTTP method in CORS config. Unsupported method is {m}"
                    )));
                }
            }
            for o in &rule.allowed_origins {
                if o.matches('*').count() > 1 {
                    return Err(errors::invalid_request(format!(
                        "AllowedOrigin \"{o}\" can not have more than one wildcard."
                    )));
                }
            }
            for h in rule.allowed_headers.iter().flatten() {
                if h.matches('*').count() > 1 {
                    return Err(errors::invalid_request(format!(
                        "AllowedHeader \"{h}\" can not have more than one wildcard."
                    )));
                }
            }
        }
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketCORS", |b| {
            b.cors = Some(config);
            Ok(())
        })
    }

    pub fn delete_bucket_cors(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketCorsRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketCORS", |b| {
            b.cors = None;
            Ok(())
        })
    }

    pub fn get_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketEncryptionRequest,
    ) -> Result<types::GetBucketEncryptionOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetEncryptionConfiguration",
            |b| {
                Ok(types::GetBucketEncryptionOutput {
                    server_side_encryption_configuration: Some(b.encryption.clone().unwrap_or_else(default_encryption)),
                })
            },
        )
    }

    pub fn put_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketEncryptionRequest,
    ) -> Result<(), ServiceError> {
        let config = input.server_side_encryption_configuration;
        if config.rules.len() != 1 {
            return Err(errors::malformed_xml());
        }
        for rule in &config.rules {
            if let Some(d) = &rule.apply_server_side_encryption_by_default {
                match d.sse_algorithm.as_str() {
                    "AES256" => {
                        if d.kms_master_key_id.is_some() {
                            return Err(errors::invalid_argument(
                                "a KMSMasterKeyID is not applicable if the default sse algorithm is not aws:kms or aws:kms:dsse",
                                "ApplyServerSideEncryptionByDefault",
                                "null",
                            ));
                        }
                    }
                    "aws:kms" | "aws:kms:dsse" => {}
                    other => {
                        return Err(errors::malformed_xml()
                            .with_field("SSEAlgorithm", mws_core::ErrorValue::String(other.to_string())))
                    }
                }
            }
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutEncryptionConfiguration",
            |b| {
                b.encryption = Some(config);
                Ok(())
            },
        )
    }

    pub fn delete_bucket_encryption(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketEncryptionRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutEncryptionConfiguration",
            |b| {
                b.encryption = None;
                Ok(())
            },
        )
    }

    pub fn get_bucket_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLifecycleConfigurationRequest,
    ) -> Result<types::GetBucketLifecycleConfigurationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetLifecycleConfiguration",
            |b| {
                let c = b.lifecycle.clone().ok_or_else(|| {
                    errors::not_found_config(
                        "NoSuchLifecycleConfiguration",
                        "The lifecycle configuration does not exist",
                        &b.name,
                    )
                })?;
                Ok(types::GetBucketLifecycleConfigurationOutput {
                    rules: Some(c.rules),
                    transition_default_minimum_object_size: Some("all_storage_classes_128K".into()),
                })
            },
        )
    }

    pub fn put_bucket_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketLifecycleConfigurationRequest,
    ) -> Result<types::PutBucketLifecycleConfigurationOutput, ServiceError> {
        let config = input.lifecycle_configuration.ok_or_else(errors::malformed_xml)?;
        if config.rules.is_empty() || config.rules.len() > 1000 {
            return Err(errors::malformed_xml());
        }
        let mut ids = std::collections::BTreeSet::new();
        for rule in &config.rules {
            if let Some(id) = &rule.id {
                if id.len() > 255 {
                    return Err(errors::invalid_argument("ID length should not exceed allowed limit of 255", "ID", id));
                }
                if !ids.insert(id.clone()) {
                    return Err(errors::invalid_argument(
                        "Rule ID must be unique. Found same ID for more than one rule",
                        "ID",
                        id,
                    ));
                }
            }
            if !matches!(rule.status.as_str(), "Enabled" | "Disabled") {
                return Err(errors::malformed_xml());
            }
            if rule.filter.is_some() && rule.prefix.is_some() {
                return Err(errors::malformed_xml());
            }
            let has_action = rule.expiration.is_some()
                || rule.transitions.as_ref().is_some_and(|t| !t.is_empty())
                || rule.noncurrent_version_transitions.as_ref().is_some_and(|t| !t.is_empty())
                || rule.noncurrent_version_expiration.is_some()
                || rule.abort_incomplete_multipart_upload.is_some();
            if !has_action {
                return Err(errors::invalid_request("At least one action needs to be specified in a rule"));
            }
            if let Some(e) = &rule.expiration {
                let set =
                    e.date.is_some() as u8 + e.days.is_some() as u8 + e.expired_object_delete_marker.is_some() as u8;
                if set != 1 {
                    return Err(errors::malformed_xml());
                }
                if e.days.is_some_and(|d| d <= 0) {
                    return Err(errors::invalid_argument(
                        "'Days' for Expiration action must be a positive integer",
                        "Days",
                        &e.days.unwrap_or_default().to_string(),
                    ));
                }
            }
        }
        let min_size =
            input.transition_default_minimum_object_size.clone().unwrap_or_else(|| "all_storage_classes_128K".into());
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutLifecycleConfiguration",
            |b| {
                b.lifecycle = Some(config);
                Ok(types::PutBucketLifecycleConfigurationOutput {
                    transition_default_minimum_object_size: Some(min_size),
                })
            },
        )
    }

    pub fn delete_bucket_lifecycle(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketLifecycleRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutLifecycleConfiguration",
            |b| {
                b.lifecycle = None;
                Ok(())
            },
        )
    }

    pub fn get_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketWebsiteRequest,
    ) -> Result<types::GetBucketWebsiteOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketWebsite", |b| {
            let c = b.website.clone().ok_or_else(|| {
                errors::not_found_config(
                    "NoSuchWebsiteConfiguration",
                    "The specified bucket does not have a website configuration",
                    &b.name,
                )
            })?;
            Ok(types::GetBucketWebsiteOutput {
                redirect_all_requests_to: c.redirect_all_requests_to,
                index_document: c.index_document,
                error_document: c.error_document,
                routing_rules: c.routing_rules,
            })
        })
    }

    pub fn put_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketWebsiteRequest,
    ) -> Result<(), ServiceError> {
        let c = input.website_configuration;
        if c.redirect_all_requests_to.is_some()
            && (c.index_document.is_some() || c.error_document.is_some() || c.routing_rules.is_some())
        {
            return Err(errors::invalid_argument(
                "RedirectAllRequestsTo cannot be provided in conjunction with other Routing/Redirect configurations.",
                "RedirectAllRequestsTo",
                "not null",
            ));
        }
        if c.redirect_all_requests_to.is_none() && c.index_document.is_none() {
            return Err(errors::invalid_argument(
                "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty",
                "IndexDocument",
                "null",
            ));
        }
        if let Some(i) = &c.index_document {
            if i.suffix.is_empty() || i.suffix.contains('/') {
                return Err(errors::invalid_argument(
                    "The IndexDocument Suffix is not well formed",
                    "IndexDocument",
                    &i.suffix,
                ));
            }
        }
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketWebsite", |b| {
            b.website = Some(c);
            Ok(())
        })
    }

    pub fn delete_bucket_website(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketWebsiteRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:DeleteBucketWebsite", |b| {
            b.website = None;
            Ok(())
        })
    }

    pub fn get_bucket_logging(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketLoggingRequest,
    ) -> Result<types::GetBucketLoggingOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketLogging", |b| {
            Ok(types::GetBucketLoggingOutput { logging_enabled: b.logging.clone() })
        })
    }

    pub fn put_bucket_logging(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketLoggingRequest,
    ) -> Result<(), ServiceError> {
        let logging = input.bucket_logging_status.logging_enabled;
        if let Some(l) = &logging {
            let st = self.read();
            let target = st.buckets.get(&l.target_bucket);
            let source_region = st.buckets.get(&input.bucket).map(|b| b.region.clone());
            match target {
                None => {
                    return Err(ServiceError::client(
                        "InvalidTargetBucketForLogging",
                        400,
                        "The target bucket for logging does not exist",
                    )
                    .with_field("TargetBucket", mws_core::ErrorValue::String(l.target_bucket.clone())))
                }
                Some(t) if Some(&t.region) != source_region.as_ref() && source_region.is_some() => {
                    return Err(ServiceError::client(
                        "CrossLocationLoggingProhibitted",
                        403,
                        "Cross S3 location logging not allowed. ",
                    ))
                }
                Some(_) => {}
            }
        }
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketLogging", |b| {
            b.logging = logging;
            Ok(())
        })
    }

    pub fn get_bucket_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketNotificationConfigurationRequest,
    ) -> Result<types::NotificationConfiguration, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketNotification", |b| {
            Ok(b.notification.clone())
        })
    }

    pub fn put_bucket_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketNotificationConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let mut config = input.notification_configuration;
        let arn_ok = |arn: &str, service: &str| {
            let parts: Vec<&str> = arn.split(':').collect();
            parts.len() >= 6 && parts[0] == "arn" && parts[2] == service
        };
        let invalid = || {
            errors::invalid_argument("Unable to validate the following destination configurations", "Destination", "")
        };
        for t in config.topic_configurations.iter_mut().flatten() {
            if !arn_ok(&t.topic_arn, "sns") || t.events.is_empty() {
                return Err(invalid());
            }
            t.id.get_or_insert_with(|| uuid::Uuid::new_v4().to_string());
        }
        for q in config.queue_configurations.iter_mut().flatten() {
            if !arn_ok(&q.queue_arn, "sqs") || q.events.is_empty() {
                return Err(invalid());
            }
            q.id.get_or_insert_with(|| uuid::Uuid::new_v4().to_string());
        }
        for l in config.lambda_function_configurations.iter_mut().flatten() {
            if !arn_ok(&l.lambda_function_arn, "lambda") || l.events.is_empty() {
                return Err(invalid());
            }
            l.id.get_or_insert_with(|| uuid::Uuid::new_v4().to_string());
        }
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketNotification", |b| {
            b.notification = config;
            Ok(())
        })
    }

    pub fn get_bucket_accelerate_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAccelerateConfigurationRequest,
    ) -> Result<types::GetBucketAccelerateConfigurationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetAccelerateConfiguration",
            |b| {
                Ok(types::GetBucketAccelerateConfigurationOutput {
                    status: b.accelerate.clone(),
                    request_charged: None,
                })
            },
        )
    }

    pub fn put_bucket_accelerate_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAccelerateConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let status = input.accelerate_configuration.status.ok_or_else(errors::malformed_xml)?;
        if input.bucket.contains('.') {
            return Err(errors::invalid_request(
                "S3 Transfer Acceleration is not supported for buckets with periods (.) in their names",
            ));
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutAccelerateConfiguration",
            |b| {
                b.accelerate = Some(status);
                Ok(())
            },
        )
    }

    pub fn get_bucket_request_payment(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketRequestPaymentRequest,
    ) -> Result<types::GetBucketRequestPaymentOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketRequestPayment",
            |b| Ok(types::GetBucketRequestPaymentOutput { payer: Some(b.request_payer.clone()) }),
        )
    }

    pub fn put_bucket_request_payment(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketRequestPaymentRequest,
    ) -> Result<(), ServiceError> {
        let payer = input.request_payment_configuration.payer;
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketRequestPayment",
            |b| {
                b.request_payer = payer;
                Ok(())
            },
        )
    }

    pub fn get_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketReplicationRequest,
    ) -> Result<types::GetBucketReplicationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetReplicationConfiguration",
            |b| {
                let c = b.replication.clone().ok_or_else(|| {
                    errors::not_found_config(
                        "ReplicationConfigurationNotFoundError",
                        "The replication configuration was not found",
                        &b.name,
                    )
                })?;
                Ok(types::GetBucketReplicationOutput { replication_configuration: Some(c) })
            },
        )
    }

    pub fn put_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketReplicationRequest,
    ) -> Result<(), ServiceError> {
        let config = input.replication_configuration;
        if config.rules.is_empty() || config.rules.len() > 1000 {
            return Err(errors::malformed_xml());
        }
        let destinations: Vec<String> = config.rules.iter().map(|r| r.destination.bucket.clone()).collect();
        {
            let st = self.read();
            for d in &destinations {
                let name = d.rsplit(":::").next().unwrap_or(d);
                match st.buckets.get(name) {
                    None => {
                        return Err(errors::invalid_request("Destination bucket must exist."));
                    }
                    Some(b) if !b.versioning_enabled() => {
                        return Err(errors::invalid_request("Destination bucket must have versioning enabled."));
                    }
                    Some(_) => {}
                }
            }
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutReplicationConfiguration",
            |b| {
                if !b.versioning_enabled() {
                    return Err(errors::invalid_request(
                        "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
                    ));
                }
                b.replication = Some(config);
                Ok(())
            },
        )
    }

    pub fn delete_bucket_replication(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketReplicationRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutReplicationConfiguration",
            |b| {
                b.replication = None;
                Ok(())
            },
        )
    }

    pub fn get_object_lock_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetObjectLockConfigurationRequest,
    ) -> Result<types::GetObjectLockConfigurationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketObjectLockConfiguration",
            |b| {
                let c = b.object_lock.clone().ok_or_else(|| {
                    errors::not_found_config(
                        "ObjectLockConfigurationNotFoundError",
                        "Object Lock configuration does not exist for this bucket",
                        &b.name,
                    )
                })?;
                Ok(types::GetObjectLockConfigurationOutput { object_lock_configuration: Some(c) })
            },
        )
    }

    pub fn put_object_lock_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutObjectLockConfigurationRequest,
    ) -> Result<types::PutObjectLockConfigurationOutput, ServiceError> {
        let config = input.object_lock_configuration.ok_or_else(errors::malformed_xml)?;
        if config.object_lock_enabled.as_deref() != Some("Enabled") {
            return Err(errors::malformed_xml());
        }
        if let Some(r) = config.rule.as_ref().and_then(|r| r.default_retention.as_ref()) {
            if r.days.is_some() == r.years.is_some() || r.mode.is_none() {
                return Err(errors::malformed_xml());
            }
            if r.days.is_some_and(|d| d <= 0) || r.years.is_some_and(|y| y <= 0) {
                return Err(errors::invalid_argument(
                    "Default retention period must be a positive integer value.",
                    "Days",
                    &r.days.or(r.years).unwrap_or_default().to_string(),
                ));
            }
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:PutBucketObjectLockConfiguration",
            |b| {
                if !b.versioning_enabled() {
                    return Err(errors::invalid_bucket_state(
                        "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
                    ));
                }
                b.object_lock_enabled = true;
                b.object_lock = Some(config);
                Ok(types::PutObjectLockConfigurationOutput { request_charged: None })
            },
        )
    }

    pub fn get_bucket_abac(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketAbacRequest,
    ) -> Result<types::GetBucketAbacOutput, ServiceError> {
        self.bucket_read(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:GetBucketAbac", |b| {
            Ok(types::GetBucketAbacOutput {
                abac_status: Some(types::AbacStatus {
                    status: Some(b.abac.clone().unwrap_or_else(|| "Disabled".into())),
                }),
            })
        })
    }

    pub fn put_bucket_abac(
        &self,
        ctx: &RequestContext,
        input: types::PutBucketAbacRequest,
    ) -> Result<(), ServiceError> {
        let status = input.abac_status.status.ok_or_else(errors::malformed_xml)?;
        self.bucket_write(ctx, &input.bucket, input.expected_bucket_owner.as_deref(), "s3:PutBucketAbac", |b| {
            b.abac = Some(status);
            Ok(())
        })
    }
}
