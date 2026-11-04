//! Delivery stream lifecycle, description, listing, tags, server-side
//! encryption and destination updates.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::config::{self, destination_of, merge, strip_nulls, update_of};
use crate::generated::{errors, types};
use crate::names::{authorize, invalid_argument, now_ms, request_tag_context, StreamRef};
use crate::state::{DeliveryStream, Destination, Encryption, TRANSITION_MS};
use crate::Firehose;

const TAG_LIMIT: usize = 50;

fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

fn tag_map(tags: &[types::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone(), t.value.clone().unwrap_or_default())).collect()
}

fn check_tags(tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if tags.len() > TAG_LIMIT {
        return Err(errors::limit_exceeded(format!("A delivery stream cannot have more than {TAG_LIMIT} tags.")));
    }
    Ok(())
}

/// Checks on a destination configuration that the model cannot express.
fn validate_destination(kind: &str, config: &Value) -> Result<(), ServiceError> {
    let effective = config::effective(kind, config);
    let s3 = if kind == "extended_s3" { Some(&effective) } else { effective.get("s3_configuration") };
    if let Some(s3) = s3 {
        if let Some(bucket) = s3.get("bucket_arn").and_then(Value::as_str) {
            if !bucket.starts_with("arn:") || !bucket.contains(":s3:::") {
                return Err(invalid_argument(format!("BucketARN {bucket} is not a valid S3 bucket ARN.")));
            }
        }
    }
    if kind == "extended_s3" {
        let prefix = effective.get("prefix").and_then(Value::as_str).unwrap_or_default();
        let error_prefix = effective.get("error_output_prefix").and_then(Value::as_str).unwrap_or_default();
        let dynamic = config::dynamic_partitioning(&effective);
        let conversion = config::format_conversion(&effective);
        if (prefix.contains("!{") || dynamic) && error_prefix.is_empty() {
            return Err(invalid_argument(
                "ErrorOutputPrefix cannot be null or empty when Prefix contains expressions or dynamic partitioning is enabled.",
            ));
        }
        let size = effective.pointer("/buffering_hints/size_in_m_bs").and_then(Value::as_i64).unwrap_or(5);
        if conversion {
            if size < 64 {
                return Err(invalid_argument(
                    "BufferingHints.SizeInMBs must be at least 64 when data format conversion is enabled.",
                ));
            }
            let compression = effective.get("compression_format").and_then(Value::as_str).unwrap_or("UNCOMPRESSED");
            if compression != "UNCOMPRESSED" {
                return Err(invalid_argument(
                    "CompressionFormat must be UNCOMPRESSED when data format conversion is enabled.",
                ));
            }
        }
        if dynamic {
            if size < 64 {
                return Err(invalid_argument(
                    "BufferingHints.SizeInMBs must be at least 64 when Dynamic Partitioning is enabled.",
                ));
            }
            if !prefix.contains("!{partitionKeyFrom") {
                return Err(invalid_argument(
                    "When dynamic partitioning is enabled, the Prefix must contain at least one partitionKeyFromQuery or partitionKeyFromLambda expression.",
                ));
            }
        }
    }
    Ok(())
}

impl Firehose {
    pub fn create_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::CreateDeliveryStreamInput,
    ) -> Result<types::CreateDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let tags = tag_map(input.tags.as_deref().unwrap_or_default());
        {
            let st = self.settled(ctx);
            authorize(ctx, &st, "CreateDeliveryStream", &r, request_tag_context(&tags))?;
            if !tags.is_empty() {
                authorize(ctx, &st, "TagDeliveryStream", &r, request_tag_context(&tags))?;
            }
        }
        check_tags(&tags)?;
        let kind = input.delivery_stream_type.clone().unwrap_or_else(|| "DirectPut".into());
        let source = match kind.as_str() {
            "DirectPut" => {
                if input.kinesis_stream_source_configuration.is_some() || input.msk_source_configuration.is_some() {
                    return Err(invalid_argument(
                        "KinesisSourceStreamConfig or MSKSourceConfig is only supported for the KinesisStreamAsSource or MSKAsSource delivery stream types.",
                    ));
                }
                serde_json::json!({"direct_put": input.direct_put_source_configuration})
            }
            "KinesisStreamAsSource" => match &input.kinesis_stream_source_configuration {
                Some(k) => serde_json::json!({"kinesis": k}),
                None => {
                    return Err(invalid_argument(
                        "KinesisSourceStreamConfig is required for the KinesisStreamAsSource delivery stream type.",
                    ))
                }
            },
            "MSKAsSource" => match &input.msk_source_configuration {
                Some(m) => serde_json::json!({"msk": m}),
                None => {
                    return Err(invalid_argument(
                        "MSKSourceConfiguration is required for the MSKAsSource delivery stream type.",
                    ))
                }
            },
            _ => match &input.database_source_configuration {
                Some(d) => serde_json::json!({"database": d}),
                None => {
                    return Err(invalid_argument(
                        "DatabaseSourceConfiguration is required for the DatabaseAsSource delivery stream type.",
                    ))
                }
            },
        };
        if input.delivery_stream_encryption_configuration_input.is_some() && kind != "DirectPut" {
            return Err(invalid_argument(format!(
                "Server-side encryption is not supported for the {kind} delivery stream type; it uses the source's encryption."
            )));
        }
        let encryption = match &input.delivery_stream_encryption_configuration_input {
            Some(e) => Some(self.encryption_for(ctx, e)?),
            None => None,
        };
        let whole = serde_json::to_value(&input).map_err(|e| invalid_argument(e.to_string()))?;
        let (dest_kind, dest_config, plain_s3) = destination_of(&whole)?;
        let dest_config = strip_nulls(dest_config);
        validate_destination(&dest_kind, &dest_config)?;
        if let Some(k) = &input.kinesis_stream_source_configuration {
            self.check_kinesis_source(ctx, &r.arn, &k.kinesis_stream_arn, &k.role_arn)?;
        }
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        if st.streams.contains_key(&r.arn) {
            return Err(errors::resource_in_use(format!(
                "Firehose {} under accountId {} already exists",
                r.name, r.account
            )));
        }
        st.streams.insert(
            r.arn.clone(),
            DeliveryStream {
                name: r.name.clone(),
                arn: r.arn.clone(),
                account: r.account.clone(),
                region: ctx.region.clone(),
                partition: ctx.partition.clone(),
                kind: kind.clone(),
                status: "CREATING".into(),
                settles_at: now + TRANSITION_MS,
                version: 1,
                created_at: now,
                updated_at: now,
                source,
                destinations: vec![Destination {
                    id: "destinationId-000000000001".into(),
                    kind: dest_kind,
                    plain_s3,
                    config: dest_config,
                    ..Default::default()
                }],
                encryption,
                tags,
                kinesis_positions: BTreeMap::new(),
                delivery_start: (kind == "KinesisStreamAsSource").then_some(now),
            },
        );
        Ok(types::CreateDeliveryStreamOutput { delivery_stream_arn: Some(r.arn) })
    }

    /// The encryption a `DeliveryStreamEncryptionConfigurationInput` asks
    /// for; a customer managed key must exist and be usable by the caller.
    fn encryption_for(
        &self,
        ctx: &RequestContext,
        e: &types::DeliveryStreamEncryptionConfigurationInput,
    ) -> Result<Encryption, ServiceError> {
        let key_arn = match e.key_type.as_str() {
            "CUSTOMER_MANAGED_CMK" => {
                let Some(key) = &e.key_arn else {
                    return Err(invalid_argument("KeyARN is required when KeyType is CUSTOMER_MANAGED_CMK."));
                };
                if let Some(kms) = self.inner.kms.get() {
                    kms.encrypt_via(ctx, "firehose", key, b"firehose", &BTreeMap::new()).map_err(|err| {
                        errors::invalid_kms_resource(format!(
                            "Firehose is unable to use the KMS key {key}: {}",
                            err.message
                        ))
                    })?;
                }
                Some(key.clone())
            }
            _ => {
                if e.key_arn.is_some() {
                    return Err(invalid_argument("KeyARN is not allowed when KeyType is AWS_OWNED_CMK."));
                }
                None
            }
        };
        Ok(Encryption {
            key_type: Some(e.key_type.clone()),
            key_arn,
            status: "ENABLING".into(),
            settles_at: now_ms(ctx) + TRANSITION_MS,
        })
    }

    pub fn delete_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDeliveryStreamInput,
    ) -> Result<types::DeleteDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "DeleteDeliveryStream", &r, ConditionContext::new())?;
        let s = r.get_mut(&mut st)?;
        if s.status == "DELETING" {
            return Err(errors::resource_in_use(format!(
                "Firehose {} under account {} is already being deleted.",
                s.name, s.account
            )));
        }
        s.status = "DELETING".into();
        s.settles_at = now_ms(ctx) + TRANSITION_MS;
        Ok(types::DeleteDeliveryStreamOutput {})
    }

    pub fn describe_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDeliveryStreamInput,
    ) -> Result<types::DescribeDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let st = self.settled(ctx);
        authorize(ctx, &st, "DescribeDeliveryStream", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let after = input.exclusive_start_destination_id.as_deref();
        let limit = input.limit.unwrap_or(10).clamp(1, 10_000) as usize;
        let all: Vec<&Destination> =
            s.destinations.iter().filter(|d| after.is_none_or(|a| d.id.as_str() > a)).collect();
        let destinations: Vec<types::DestinationDescription> =
            all.iter().take(limit).map(|d| config::describe(&d.id, &d.kind, &d.config, d.plain_s3)).collect();
        Ok(types::DescribeDeliveryStreamOutput {
            delivery_stream_description: types::DeliveryStreamDescription {
                delivery_stream_name: s.name.clone(),
                delivery_stream_arn: s.arn.clone(),
                delivery_stream_status: s.status.clone(),
                failure_description: None,
                delivery_stream_encryption_configuration: Some(match &s.encryption {
                    Some(e) => types::DeliveryStreamEncryptionConfiguration {
                        key_arn: e.key_arn.clone(),
                        key_type: e.key_type.clone(),
                        status: Some(e.status.clone()),
                        failure_description: None,
                    },
                    None => types::DeliveryStreamEncryptionConfiguration {
                        status: Some("DISABLED".into()),
                        ..Default::default()
                    },
                }),
                delivery_stream_type: s.kind.clone(),
                version_id: s.version.to_string(),
                create_timestamp: Some(time(s.created_at)),
                last_update_timestamp: (s.version > 1).then(|| time(s.updated_at)),
                source: source_description(s),
                has_more_destinations: all.len() > destinations.len(),
                destinations,
            },
        })
    }

    pub fn list_delivery_streams(
        &self,
        ctx: &RequestContext,
        input: types::ListDeliveryStreamsInput,
    ) -> Result<types::ListDeliveryStreamsOutput, ServiceError> {
        let any = StreamRef::new(ctx, "*");
        let st = self.settled(ctx);
        authorize(ctx, &st, "ListDeliveryStreams", &any, ConditionContext::new())?;
        let after = input.exclusive_start_delivery_stream_name.as_deref();
        let mut names: Vec<&str> = st
            .streams
            .values()
            .filter(|s| s.account == any.account && s.region == ctx.region)
            .filter(|s| input.delivery_stream_type.as_ref().is_none_or(|t| &s.kind == t))
            .filter(|s| after.is_none_or(|a| s.name.as_str() > a))
            .map(|s| s.name.as_str())
            .collect();
        names.sort_unstable();
        let limit = input.limit.unwrap_or(10).clamp(1, 10_000) as usize;
        let more = names.len() > limit;
        Ok(types::ListDeliveryStreamsOutput {
            delivery_stream_names: names.into_iter().take(limit).map(str::to_string).collect(),
            has_more_delivery_streams: more,
        })
    }

    pub fn tag_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::TagDeliveryStreamInput,
    ) -> Result<types::TagDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let tags = tag_map(&input.tags);
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "TagDeliveryStream", &r, request_tag_context(&tags))?;
        let s = r.get_mut(&mut st)?;
        let mut merged = s.tags.clone();
        merged.extend(tags);
        check_tags(&merged)?;
        s.tags = merged;
        Ok(types::TagDeliveryStreamOutput {})
    }

    pub fn untag_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::UntagDeliveryStreamInput,
    ) -> Result<types::UntagDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let mut st = self.settled(ctx);
        let mut extra = ConditionContext::new();
        extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize(ctx, &st, "UntagDeliveryStream", &r, extra)?;
        let s = r.get_mut(&mut st)?;
        for k in &input.tag_keys {
            s.tags.remove(k);
        }
        Ok(types::UntagDeliveryStreamOutput {})
    }

    pub fn list_tags_for_delivery_stream(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForDeliveryStreamInput,
    ) -> Result<types::ListTagsForDeliveryStreamOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let st = self.settled(ctx);
        authorize(ctx, &st, "ListTagsForDeliveryStream", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let after = input.exclusive_start_tag_key.as_deref();
        let all: Vec<types::Tag> = s
            .tags
            .iter()
            .filter(|(k, _)| after.is_none_or(|a| k.as_str() > a))
            .map(|(k, v)| types::Tag { key: k.clone(), value: Some(v.clone()) })
            .collect();
        let limit = input.limit.unwrap_or(50).clamp(1, 50) as usize;
        let more = all.len() > limit;
        Ok(types::ListTagsForDeliveryStreamOutput { tags: all.into_iter().take(limit).collect(), has_more_tags: more })
    }

    pub fn start_delivery_stream_encryption(
        &self,
        ctx: &RequestContext,
        input: types::StartDeliveryStreamEncryptionInput,
    ) -> Result<types::StartDeliveryStreamEncryptionOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        {
            let st = self.settled(ctx);
            authorize(ctx, &st, "StartDeliveryStreamEncryption", &r, ConditionContext::new())?;
            let s = r.get(&st)?;
            if s.kind != "DirectPut" {
                return Err(invalid_argument(format!(
                    "Server-side encryption is not supported for the {} delivery stream type.",
                    s.kind
                )));
            }
            if !s.active() {
                return Err(errors::resource_in_use(format!(
                    "Firehose {} under account {} is not ACTIVE, instead in state {}.",
                    s.name, s.account, s.status
                )));
            }
        }
        let wanted = input.delivery_stream_encryption_configuration_input.unwrap_or(
            types::DeliveryStreamEncryptionConfigurationInput { key_arn: None, key_type: "AWS_OWNED_CMK".into() },
        );
        let e = self.encryption_for(ctx, &wanted)?;
        let mut st = self.settled(ctx);
        let s = r.get_mut(&mut st)?;
        let same = s
            .encryption
            .as_ref()
            .is_some_and(|c| c.status == "ENABLED" && c.key_type == e.key_type && c.key_arn == e.key_arn);
        if !same {
            s.encryption = Some(e);
        }
        Ok(types::StartDeliveryStreamEncryptionOutput {})
    }

    pub fn stop_delivery_stream_encryption(
        &self,
        ctx: &RequestContext,
        input: types::StopDeliveryStreamEncryptionInput,
    ) -> Result<types::StopDeliveryStreamEncryptionOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "StopDeliveryStreamEncryption", &r, ConditionContext::new())?;
        let s = r.get_mut(&mut st)?;
        if s.kind != "DirectPut" {
            return Err(invalid_argument(format!(
                "Server-side encryption is not supported for the {} delivery stream type.",
                s.kind
            )));
        }
        if let Some(e) = &mut s.encryption {
            if e.status != "DISABLED" {
                e.status = "DISABLING".into();
                e.settles_at = now_ms(ctx) + TRANSITION_MS;
            }
        }
        Ok(types::StopDeliveryStreamEncryptionOutput {})
    }

    pub fn update_destination(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDestinationInput,
    ) -> Result<types::UpdateDestinationOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let whole = serde_json::to_value(&input).map_err(|e| invalid_argument(e.to_string()))?;
        let (kind, update, plain_s3) = update_of(&whole)?;
        let update = strip_nulls(update);
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "UpdateDestination", &r, ConditionContext::new())?;
        let s = r.get_mut(&mut st)?;
        if s.version.to_string() != input.current_delivery_stream_version_id {
            return Err(errors::concurrent_modification(format!(
                "Cannot update firehose: {} since the current version id: {} and specified version id: {} do not match",
                s.name, s.version, input.current_delivery_stream_version_id
            )));
        }
        if !s.active() {
            return Err(errors::resource_in_use(format!(
                "Firehose {} under account {} is not ACTIVE, instead in state {}.",
                s.name, s.account, s.status
            )));
        }
        let Some(d) = s.destinations.iter_mut().find(|d| d.id == input.destination_id) else {
            return Err(invalid_argument(format!("Destination Id {} not found.", input.destination_id)));
        };
        let mut config = if d.kind == kind { d.config.clone() } else { Value::Object(Default::default()) };
        merge(&mut config, update);
        validate_destination(&kind, &config)?;
        d.kind = kind;
        d.plain_s3 = plain_s3 && d.plain_s3;
        d.config = config;
        s.version += 1;
        s.updated_at = now_ms(ctx);
        Ok(types::UpdateDestinationOutput {})
    }
}

fn source_description(s: &DeliveryStream) -> Option<types::SourceDescription> {
    let mut d = types::SourceDescription::default();
    if let Some(k) = s.source.get("kinesis").filter(|v| !v.is_null()) {
        let k: types::KinesisStreamSourceConfiguration = serde_json::from_value(k.clone()).ok()?;
        d.kinesis_stream_source_description = Some(types::KinesisStreamSourceDescription {
            kinesis_stream_arn: Some(k.kinesis_stream_arn),
            role_arn: Some(k.role_arn),
            delivery_start_timestamp: s.delivery_start.map(time),
        });
    } else if let Some(m) = s.source.get("msk").filter(|v| !v.is_null()) {
        let m: types::MSKSourceConfiguration = serde_json::from_value(m.clone()).ok()?;
        d.msk_source_description = Some(types::MSKSourceDescription {
            msk_cluster_arn: Some(m.msk_cluster_arn),
            topic_name: Some(m.topic_name),
            authentication_configuration: Some(m.authentication_configuration),
            delivery_start_timestamp: Some(time(s.created_at)),
            read_from_timestamp: m.read_from_timestamp,
        });
    } else if let Some(db) = s.source.get("database").filter(|v| !v.is_null()) {
        d.database_source_description = serde_json::from_value(db.clone()).ok();
    } else {
        let p = s.source.get("direct_put").filter(|v| !v.is_null())?;
        let p: types::DirectPutSourceConfiguration = serde_json::from_value(p.clone()).ok()?;
        d.direct_put_source_description =
            Some(types::DirectPutSourceDescription { throughput_hint_in_m_bs: Some(p.throughput_hint_in_m_bs) });
    }
    Some(d)
}
