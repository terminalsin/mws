//! End-to-end tests: real AWS SDK clients against a running MWS.
//!
//! One test binary for every service: each extra binary would link all the
//! AWS SDKs again, which costs minutes of build time and gigabytes of disk.

mod acm;
mod acmpca;
mod acmpca_parity;
mod cloudwatch;
mod cloudwatch_parity;
mod ec2;
mod ec2_docker;
mod events;
mod firehose;
mod firehose_monitoring;
mod iam;
mod iam_advanced;
mod iam_parity;
mod identity_center;
mod identity_center_apps;
mod identitystore;
mod kinesis;
mod kinesis_parity;
mod kinesis_targets;
mod kms;
mod lambda;
mod lambda_destinations;
mod lambda_sqs;
mod lambda_urls;
mod logs;
mod logs_queries;
mod logs_subscriptions;
mod object_lambda;
mod organizations;
mod parity;
mod policies;
mod route53;
mod route53_advanced;
mod route53_parity;
mod s3;
mod s3_access_logs;
mod s3_batch;
mod s3_control_parity;
mod s3_inventory;
mod s3_parity;
mod secretsmanager;
mod sns;
mod sns_archive;
mod sns_encryption;
mod sns_parity;
mod sns_status_logs;
mod sqs;
mod ssm;
mod state;
mod sts;
