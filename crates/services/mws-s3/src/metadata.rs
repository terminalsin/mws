//! S3 Metadata configurations: the V2 configuration (journal, inventory
//! and annotation tables in the AWS managed table bucket `aws-s3`) and the
//! legacy V1 metadata table configuration (a table in a customer table
//! bucket). MWS has no S3 Tables, so the tables are described exactly as
//! S3 reports them (status `ACTIVE`, stable table ARNs) but cannot be
//! queried.

use mws_core::{RequestContext, ServiceError};
use sha2::Digest;

use crate::errors;
use crate::generated::types;
use crate::state::Bucket;
use crate::Call;

fn managed_table_bucket_arn(ctx: &RequestContext, b: &Bucket) -> String {
    format!("arn:{}:s3tables:{}:{}:bucket/aws-s3", ctx.partition, b.region, b.owner)
}

/// The namespace S3 creates for a bucket's metadata tables.
fn namespace(bucket: &str) -> String {
    format!("b_{}", bucket.replace(['-', '.'], "_"))
}

/// A stable table id for `(bucket, table)`, shaped like the UUIDs S3 Tables
/// uses.
fn table_id(bucket: &str, table: &str) -> String {
    let h = hex::encode(sha2::Sha256::digest(format!("{bucket}/{table}").as_bytes()));
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn table_arn(table_bucket_arn: &str, bucket: &str, table: &str) -> String {
    format!("{table_bucket_arn}/table/{}", table_id(bucket, table))
}

fn validate_expiration(r: &types::RecordExpiration) -> Result<(), ServiceError> {
    match (r.expiration.as_str(), r.days) {
        ("ENABLED", Some(d)) if (7..=2_147_483_647).contains(&d) => Ok(()),
        ("ENABLED", _) => {
            Err(errors::invalid_request("When record expiration is ENABLED, Days must be specified and be at least 7."))
        }
        ("DISABLED", None) => Ok(()),
        ("DISABLED", Some(_)) => {
            Err(errors::invalid_request("Days must not be specified when record expiration is DISABLED."))
        }
        _ => Err(errors::malformed_xml()),
    }
}

fn validate_encryption(e: Option<&types::MetadataTableEncryptionConfiguration>) -> Result<(), ServiceError> {
    match e {
        None => Ok(()),
        Some(e) => match (e.sse_algorithm.as_str(), &e.kms_key_arn) {
            ("AES256", None) | ("aws:kms", Some(_)) => Ok(()),
            ("aws:kms", None) => Err(errors::invalid_request("A KMS key ARN is required for aws:kms encryption.")),
            ("AES256", Some(_)) => {
                Err(errors::invalid_request("A KMS key ARN can only be specified with aws:kms encryption."))
            }
            _ => Err(errors::malformed_xml()),
        },
    }
}

fn validate_state(state: &str) -> Result<(), ServiceError> {
    if matches!(state, "ENABLED" | "DISABLED") {
        Ok(())
    } else {
        Err(errors::malformed_xml())
    }
}

fn result(ctx: &RequestContext, b: &Bucket, c: &types::MetadataConfiguration) -> types::MetadataConfigurationResult {
    let tb = managed_table_bucket_arn(ctx, b);
    let enabled_table = |state: &str, name: &str| {
        (state == "ENABLED")
            .then(|| (Some("ACTIVE".to_string()), Some(name.to_string()), Some(table_arn(&tb, &b.name, name))))
    };
    types::MetadataConfigurationResult {
        destination_result: types::DestinationResult {
            table_bucket_type: Some("aws".into()),
            table_bucket_arn: Some(tb.clone()),
            table_namespace: Some(namespace(&b.name)),
        },
        journal_table_configuration_result: Some(types::JournalTableConfigurationResult {
            table_status: "ACTIVE".into(),
            error: None,
            table_name: "journal".into(),
            table_arn: Some(table_arn(&tb, &b.name, "journal")),
            record_expiration: c.journal_table_configuration.record_expiration.clone(),
        }),
        inventory_table_configuration_result: c.inventory_table_configuration.as_ref().map(|i| {
            let (status, name, arn) = enabled_table(&i.configuration_state, "inventory").unwrap_or_default();
            types::InventoryTableConfigurationResult {
                configuration_state: i.configuration_state.clone(),
                table_status: status,
                error: None,
                table_name: name,
                table_arn: arn,
            }
        }),
        annotation_table_configuration_result: c.annotation_table_configuration.as_ref().map(|a| {
            let (status, name, arn) = enabled_table(&a.configuration_state, "annotation").unwrap_or_default();
            types::AnnotationTableConfigurationResult {
                configuration_state: a.configuration_state.clone(),
                table_status: status,
                error: None,
                table_name: name,
                table_arn: arn,
                role: a.role.clone(),
            }
        }),
    }
}

fn not_found() -> ServiceError {
    errors::no_such_configuration()
}

impl Call {
    pub fn create_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketMetadataConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let c = input.metadata_configuration;
        validate_expiration(&c.journal_table_configuration.record_expiration)?;
        validate_encryption(c.journal_table_configuration.encryption_configuration.as_ref())?;
        if let Some(i) = &c.inventory_table_configuration {
            validate_state(&i.configuration_state)?;
            validate_encryption(i.encryption_configuration.as_ref())?;
        }
        if let Some(a) = &c.annotation_table_configuration {
            validate_state(&a.configuration_state)?;
            validate_encryption(a.encryption_configuration.as_ref())?;
        }
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:CreateBucketMetadataTableConfiguration",
            |b| {
                if b.metadata.is_some() || b.metadata_v1.is_some() {
                    return Err(ServiceError::client(
                        "Conflict",
                        409,
                        "A metadata configuration already exists for this bucket.",
                    ));
                }
                b.metadata = Some(c);
                Ok(())
            },
        )
    }

    pub fn get_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketMetadataConfigurationRequest,
    ) -> Result<types::GetBucketMetadataConfigurationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketMetadataTableConfiguration",
            |b| {
                let c = b.metadata.as_ref().ok_or_else(not_found)?;
                Ok(types::GetBucketMetadataConfigurationOutput {
                    get_bucket_metadata_configuration_result: Some(types::GetBucketMetadataConfigurationResult {
                        metadata_configuration_result: result(ctx, b, c),
                    }),
                })
            },
        )
    }

    pub fn delete_bucket_metadata_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketMetadataConfigurationRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:DeleteBucketMetadataTableConfiguration",
            |b| {
                b.metadata.take().ok_or_else(not_found)?;
                Ok(())
            },
        )
    }

    pub fn update_bucket_metadata_journal_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataJournalTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let update = input.journal_table_configuration;
        validate_expiration(&update.record_expiration)?;
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:UpdateBucketMetadataJournalTableConfiguration",
            |b| {
                let c = b.metadata.as_mut().ok_or_else(not_found)?;
                c.journal_table_configuration.record_expiration = update.record_expiration;
                Ok(())
            },
        )
    }

    pub fn update_bucket_metadata_inventory_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataInventoryTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let update = input.inventory_table_configuration;
        validate_state(&update.configuration_state)?;
        validate_encryption(update.encryption_configuration.as_ref())?;
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:UpdateBucketMetadataInventoryTableConfiguration",
            |b| {
                let c = b.metadata.as_mut().ok_or_else(not_found)?;
                c.inventory_table_configuration = Some(types::InventoryTableConfiguration {
                    configuration_state: update.configuration_state,
                    encryption_configuration: update.encryption_configuration,
                });
                Ok(())
            },
        )
    }

    pub fn update_bucket_metadata_annotation_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBucketMetadataAnnotationTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let update = input.annotation_table_configuration;
        validate_state(&update.configuration_state)?;
        validate_encryption(update.encryption_configuration.as_ref())?;
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:UpdateBucketMetadataAnnotationTableConfiguration",
            |b| {
                let c = b.metadata.as_mut().ok_or_else(not_found)?;
                c.annotation_table_configuration = Some(types::AnnotationTableConfiguration {
                    configuration_state: update.configuration_state,
                    encryption_configuration: update.encryption_configuration,
                    role: update.role,
                });
                Ok(())
            },
        )
    }

    // ---- V1: a metadata table in a customer table bucket ----------------------

    pub fn create_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateBucketMetadataTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let dest = &input.metadata_table_configuration.s3_tables_destination;
        let parts: Vec<&str> = dest.table_bucket_arn.split(':').collect();
        let valid_arn = parts.len() == 6
            && parts[0] == "arn"
            && parts[2] == "s3tables"
            && parts[5].strip_prefix("bucket/").is_some_and(|n| !n.is_empty() && !n.contains('/'));
        if !valid_arn {
            return Err(errors::invalid_request(format!(
                "The table bucket ARN {} is not valid.",
                dest.table_bucket_arn
            )));
        }
        let name_ok = !dest.table_name.is_empty()
            && dest.table_name.len() <= 255
            && dest.table_name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
        if !name_ok {
            return Err(errors::invalid_request(format!("The table name {} is not valid.", dest.table_name)));
        }
        let config = input.metadata_table_configuration;
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:CreateBucketMetadataTableConfiguration",
            |b| {
                if b.metadata.is_some() || b.metadata_v1.is_some() {
                    return Err(ServiceError::client(
                        "Conflict",
                        409,
                        "A metadata table configuration already exists for this bucket.",
                    ));
                }
                b.metadata_v1 = Some(config);
                Ok(())
            },
        )
    }

    pub fn get_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetBucketMetadataTableConfigurationRequest,
    ) -> Result<types::GetBucketMetadataTableConfigurationOutput, ServiceError> {
        self.bucket_read(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:GetBucketMetadataTableConfiguration",
            |b| {
                let c = b.metadata_v1.as_ref().ok_or_else(not_found)?;
                let dest = &c.s3_tables_destination;
                Ok(types::GetBucketMetadataTableConfigurationOutput {
                    get_bucket_metadata_table_configuration_result: Some(
                        types::GetBucketMetadataTableConfigurationResult {
                            metadata_table_configuration_result: types::MetadataTableConfigurationResult {
                                s3_tables_destination_result: types::S3TablesDestinationResult {
                                    table_bucket_arn: dest.table_bucket_arn.clone(),
                                    table_name: dest.table_name.clone(),
                                    table_arn: table_arn(&dest.table_bucket_arn, &b.name, &dest.table_name),
                                    table_namespace: "aws_s3_metadata".into(),
                                },
                            },
                            status: "ACTIVE".into(),
                            error: None,
                        },
                    ),
                })
            },
        )
    }

    pub fn delete_bucket_metadata_table_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBucketMetadataTableConfigurationRequest,
    ) -> Result<(), ServiceError> {
        self.bucket_write(
            ctx,
            &input.bucket,
            input.expected_bucket_owner.as_deref(),
            "s3:DeleteBucketMetadataTableConfiguration",
            |b| {
                b.metadata_v1.take().ok_or_else(not_found)?;
                Ok(())
            },
        )
    }
}
