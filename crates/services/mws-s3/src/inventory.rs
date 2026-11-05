//! S3 Inventory: enabled inventory configurations deliver reports to their
//! destination bucket on schedule, as `s3.amazonaws.com`.
//!
//! A report is what AWS writes: gzipped CSV data files under
//! `<prefix>/<source bucket>/<config id>/data/`, a `manifest.json` and
//! `manifest.checksum` (MD5 of the manifest) under
//! `<prefix>/<source bucket>/<config id>/<YYYY-MM-DDTHH-MMZ>/`, and a Hive
//! `symlink.txt` under `.../hive/dt=<YYYY-MM-DD-HH-MM>/`. Parquet reports
//! are real Parquet files (see [`crate::parquet`]). ORC reports are not
//! written yet: ORC configurations are stored but deliver nothing.
//!
//! As in AWS, the destination bucket policy must let `s3.amazonaws.com`
//! `s3:PutObject` (`aws:SourceArn` = the source bucket, `aws:SourceAccount`
//! = its owner, `s3:x-amz-acl` = `bucket-owner-full-control`); an
//! SSE-KMS report also needs the key policy to let the service principal
//! `kms:GenerateDataKey`. A report that cannot be written is lost silently.
//!
//! Schedule: AWS delivers the first report within 48 hours and then daily
//! or weekly. MWS delivers at 00:00 UTC on the emulated clock
//! (`/_mws/clock`): the first midnight after the configuration is put, then
//! every day or seven days. Moving the clock past a due time makes the next
//! S3 request deliver the report (one report however many periods passed).

use std::io::Write;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use md5::Digest;
use mws_core::RequestContext;

use crate::generated::types;
use crate::public::ServicePutObject;
use crate::state::{Bucket, ObjectVersion, Sse};
use crate::{lifecycle, S3};

const PRINCIPAL: &str = "s3.amazonaws.com";

/// Optional fields in the order AWS writes them, whatever order the
/// configuration lists them in.
const FIELD_ORDER: &[&str] = &[
    "Size",
    "LastModifiedDate",
    "ETag",
    "StorageClass",
    "IsMultipartUploaded",
    "ReplicationStatus",
    "EncryptionStatus",
    "ObjectLockRetainUntilDate",
    "ObjectLockMode",
    "ObjectLockLegalHoldStatus",
    "IntelligentTieringAccessTier",
    "BucketKeyStatus",
    "ChecksumAlgorithm",
    "ObjectAccessControlList",
    "ObjectOwner",
    "LifecycleExpirationDate",
    "IntelligentTieringReferenceDate",
    "ObjectLockEventHoldStatus",
    "ObjectLockEventHoldDuration",
];

fn next_midnight(after: DateTime<Utc>) -> DateTime<Utc> {
    (after.date_naive() + Duration::days(1)).and_hms_opt(0, 0, 0).expect("midnight exists").and_utc()
}

fn period(config: &types::InventoryConfiguration) -> Duration {
    if config.schedule.frequency == "Weekly" {
        Duration::days(7)
    } else {
        Duration::days(1)
    }
}

impl Bucket {
    /// A keyed configuration was put: inventory configurations start their
    /// schedule.
    pub fn configuration_put(&mut self, kind: &str, id: &str, now: DateTime<Utc>) {
        if kind == "inventory" {
            self.inventory_due.entry(id.to_string()).or_insert_with(|| next_midnight(now));
        }
    }

    pub fn configuration_deleted(&mut self, kind: &str, id: &str) {
        if kind == "inventory" {
            self.inventory_due.remove(id);
        }
    }
}

/// One column value of one inventory row.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Cell {
    Str(String),
    Int(i64),
    Bool(bool),
    Time(DateTime<Utc>),
    /// No value (CSV writes an empty string).
    Null,
}

impl Cell {
    fn csv(&self) -> String {
        match self {
            Cell::Str(s) => s.clone(),
            Cell::Int(i) => i.to_string(),
            Cell::Bool(b) => b.to_string(),
            Cell::Time(t) => t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            Cell::Null => String::new(),
        }
    }
}

/// A report waiting to be written.
struct Job {
    source: String,
    owner: String,
    partition: String,
    config: types::InventoryConfiguration,
    at: DateTime<Utc>,
    schema: Vec<&'static str>,
    rows: Vec<Vec<Cell>>,
}

fn optional_fields(config: &types::InventoryConfiguration) -> Vec<&'static str> {
    let wanted = config.optional_fields.clone().unwrap_or_default();
    FIELD_ORDER.iter().copied().filter(|f| wanted.iter().any(|w| w == f)).collect()
}

fn schema(config: &types::InventoryConfiguration) -> Vec<&'static str> {
    let mut s = vec!["Bucket", "Key"];
    if config.included_object_versions == "All" {
        s.extend(["VersionId", "IsLatest", "IsDeleteMarker"]);
    }
    s.extend(optional_fields(config));
    s
}

fn encryption_status(v: &ObjectVersion) -> &'static str {
    match v.sse.algorithm.as_deref() {
        Some("AES256") => "SSE-S3",
        Some("aws:kms") => "SSE-KMS",
        Some("aws:kms:dsse") => "DSSE-KMS",
        Some(_) => "NOT-SSE",
        None if v.sse.customer_key_md5.is_some() => "SSE-C",
        None => "NOT-SSE",
    }
}

/// `ObjectAccessControlList`: the grants as base64-encoded JSON.
fn acl_field(v: &ObjectVersion) -> String {
    let grants: Vec<serde_json::Value> = v
        .acl
        .iter()
        .filter_map(|g| {
            let grantee = g.grantee.as_ref()?;
            let mut o = serde_json::Map::new();
            o.insert("permission".into(), g.permission.clone().unwrap_or_default().into());
            o.insert("type".into(), grantee.r#type.clone().into());
            if let Some(id) = &grantee.id {
                o.insert("canonicalId".into(), id.clone().into());
            }
            if let Some(uri) = &grantee.uri {
                o.insert("uri".into(), uri.clone().into());
            }
            Some(serde_json::Value::Object(o))
        })
        .collect();
    let doc = serde_json::json!({"version": "2022-11-10", "status": "AVAILABLE", "grants": grants});
    base64::engine::general_purpose::STANDARD.encode(doc.to_string())
}

fn field(name: &str, b: &Bucket, key: &str, v: &ObjectVersion, latest: bool) -> Cell {
    let marker = v.delete_marker;
    let opt = |s: Option<String>| s.map_or(Cell::Null, Cell::Str);
    match name {
        _ if marker && name != "LastModifiedDate" && name != "ObjectOwner" => Cell::Null,
        "Size" => Cell::Int(v.size()),
        "LastModifiedDate" => Cell::Time(v.last_modified),
        "ETag" => Cell::Str(v.etag.trim_matches('"').to_string()),
        "StorageClass" => Cell::Str(v.storage_class.clone()),
        "IsMultipartUploaded" => Cell::Bool(!v.parts.is_empty()),
        "ReplicationStatus" => opt(v.replication_status.clone()),
        "EncryptionStatus" => Cell::Str(encryption_status(v).into()),
        "ObjectLockRetainUntilDate" => v.lock_until.map_or(Cell::Null, Cell::Time),
        "ObjectLockMode" => opt(v.lock_mode.clone()),
        "ObjectLockLegalHoldStatus" => Cell::Str(v.legal_hold.clone().unwrap_or_else(|| "OFF".into())),
        "IntelligentTieringAccessTier" => {
            if v.storage_class == "INTELLIGENT_TIERING" {
                Cell::Str("FREQUENT".into())
            } else {
                Cell::Null
            }
        }
        "BucketKeyStatus" => Cell::Str(if v.sse.bucket_key { "ENABLED" } else { "DISABLED" }.into()),
        "ChecksumAlgorithm" => opt(v.checksum.as_ref().map(|c| c.algorithm.clone())),
        "ObjectAccessControlList" => Cell::Str(acl_field(v)),
        "ObjectOwner" => Cell::Str(crate::auth::canonical_id(&v.owner)),
        "LifecycleExpirationDate" => {
            if latest {
                lifecycle::expiry(b, key, v).map_or(Cell::Null, Cell::Time)
            } else {
                Cell::Null
            }
        }
        _ => Cell::Null,
    }
}

/// Every row of a report on `b`.
fn rows(b: &Bucket, config: &types::InventoryConfiguration, schema: &[&'static str]) -> Vec<Vec<Cell>> {
    let all = config.included_object_versions == "All";
    let prefix = config.filter.as_ref().map(|f| f.prefix.as_str()).unwrap_or("");
    let mut out = Vec::new();
    for (key, versions) in b.objects.range(prefix.to_string()..) {
        if !key.starts_with(prefix) {
            break;
        }
        let n = versions.len();
        // Newest first, as ListObjectVersions orders them.
        for (i, v) in versions.iter().enumerate().rev() {
            let latest = i + 1 == n;
            if !all && (!latest || v.delete_marker) {
                continue;
            }
            let row = schema
                .iter()
                .map(|name| match *name {
                    "Bucket" => Cell::Str(b.name.clone()),
                    "Key" => Cell::Str(key.clone()),
                    "VersionId" => Cell::Str(v.version_id.clone()),
                    "IsLatest" => Cell::Bool(latest),
                    "IsDeleteMarker" => Cell::Bool(v.delete_marker),
                    f => field(f, b, key, v, latest),
                })
                .collect();
            out.push(row);
        }
    }
    out
}

/// CSV as S3 Inventory writes it: every field quoted, keys URL-encoded.
fn csv(schema: &[&str], rows: &[Vec<Cell>]) -> Vec<u8> {
    let mut out = String::new();
    for row in rows {
        let fields: Vec<String> = row
            .iter()
            .zip(schema)
            .map(|(c, name)| {
                let v = c.csv();
                let v = if *name == "Key" { form_urlencoded::byte_serialize(v.as_bytes()).collect() } else { v };
                format!("\"{}\"", v.replace('"', "\"\""))
            })
            .collect();
        out.push_str(&fields.join(","));
        out.push('\n');
    }
    out.into_bytes()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("writing to memory");
    e.finish().expect("writing to memory")
}

fn md5_hex(data: &[u8]) -> String {
    hex::encode(md5::Md5::digest(data))
}

impl S3 {
    /// Deliver every inventory report that has come due.
    pub(crate) fn run_inventory(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let due = |st: &crate::state::State| st.buckets.values().any(|b| b.inventory_due.values().any(|at| *at <= now));
        if !due(&self.read()) {
            return;
        }
        let jobs = {
            let mut st = self.write();
            let mut jobs = Vec::new();
            for b in st.buckets.values_mut() {
                let ready: Vec<(String, DateTime<Utc>)> =
                    b.inventory_due.iter().filter(|(_, at)| **at <= now).map(|(k, v)| (k.clone(), *v)).collect();
                for (id, at) in ready {
                    let Some(config) = b.inventory.get(&id).cloned() else {
                        b.inventory_due.remove(&id);
                        continue;
                    };
                    let mut next = at;
                    while next <= now {
                        next += period(&config);
                    }
                    b.inventory_due.insert(id, next);
                    if !config.is_enabled {
                        continue;
                    }
                    let schema = schema(&config);
                    jobs.push(Job {
                        source: b.name.clone(),
                        owner: b.owner.clone(),
                        partition: ctx.partition.clone(),
                        rows: rows(b, &config, &schema),
                        schema,
                        config,
                        at,
                    });
                }
            }
            jobs
        };
        for job in jobs {
            // Like AWS, a destination that refuses the report loses it.
            let _ = self.deliver_inventory(&job);
        }
    }

    fn deliver_inventory(&self, job: &Job) -> Result<(), String> {
        let dest = &job.config.destination.s3_bucket_destination;
        let bucket = dest.bucket.rsplit(":::").next().unwrap_or(&dest.bucket).to_string();
        let dest_owner = self.bucket_owner(&bucket).ok_or("no destination bucket")?;
        if dest.account_id.as_deref().is_some_and(|a| a != dest_owner) {
            return Err("destination account mismatch".into());
        }
        let (body, extension) = match dest.format.as_str() {
            "CSV" => (gzip(&csv(&job.schema, &job.rows)), "csv.gz"),
            "Parquet" => (crate::parquet::write(&job.schema, &job.rows), "parquet"),
            other => return Err(format!("{other} inventory is not supported")),
        };
        let base = match dest.prefix.as_deref().map(|p| p.trim_end_matches('/')).filter(|p| !p.is_empty()) {
            Some(p) => format!("{p}/{}/{}", job.source, job.config.id),
            None => format!("{}/{}", job.source, job.config.id),
        };
        let source_arn = format!("arn:{}:s3:::{}", job.partition, job.source);
        let data_key = format!("{base}/data/{}.{extension}", uuid::Uuid::new_v4());
        let put = |key: &str, body: Vec<u8>, content_type: &'static str| -> Result<(), String> {
            let put = ServicePutObject {
                bucket: &bucket,
                key,
                body,
                content_type,
                service_principal: PRINCIPAL,
                source_account: &job.owner,
                source_arn: &source_arn,
                acl: Some("bucket-owner-full-control"),
                partition: &job.partition,
            };
            let sse = self.inventory_sse(job, &put)?;
            self.put_object_as_service_with(put, sse).map(|_| ()).map_err(|e| e.to_string())
        };
        let size = body.len();
        let checksum = md5_hex(&body);
        put(&data_key, body, "application/octet-stream")?;
        let manifest = serde_json::json!({
            "sourceBucket": job.source,
            "destinationBucket": format!("arn:{}:s3:::{bucket}", job.partition),
            "version": "2016-11-30",
            "creationTimestamp": job.at.timestamp_millis().to_string(),
            "fileFormat": dest.format,
            "fileSchema": if dest.format == "CSV" {
                job.schema.join(", ")
            } else {
                crate::parquet::schema_text(&job.schema)
            },
            "files": [{"key": data_key, "size": size, "MD5checksum": checksum}],
        });
        let manifest = serde_json::to_vec_pretty(&manifest).expect("JSON serializes");
        let folder = format!("{base}/{}", job.at.format("%Y-%m-%dT%H-%MZ"));
        let manifest_checksum = md5_hex(&manifest);
        put(&format!("{folder}/manifest.json"), manifest, "application/json")?;
        put(&format!("{folder}/manifest.checksum"), manifest_checksum.into_bytes(), "text/plain")?;
        let symlink = format!("s3://{bucket}/{data_key}\n");
        put(
            &format!("{base}/hive/dt={}/symlink.txt", job.at.format("%Y-%m-%d-%H-%M")),
            symlink.into_bytes(),
            "text/plain",
        )?;
        Ok(())
    }

    /// The encryption of a report object: SSE-S3, or SSE-KMS with a data
    /// key the service principal generates under the configured key.
    fn inventory_sse(&self, job: &Job, put: &ServicePutObject<'_>) -> Result<Sse, String> {
        let dest = &job.config.destination.s3_bucket_destination;
        match dest.encryption.as_ref().and_then(|e| e.ssekms.as_ref()) {
            Some(k) => self.service_kms_sse(put, &k.key_id),
            None => Ok(Sse::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight() {
        let t = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 11, 3, 7, 8, 9).unwrap();
        assert_eq!(next_midnight(t).to_rfc3339(), "2026-11-04T00:00:00+00:00");
    }

    #[test]
    fn csv_quotes_and_encodes() {
        let rows = vec![vec![Cell::Str("b".into()), Cell::Str("a dir/k\"1".into()), Cell::Int(3), Cell::Null]];
        let out = String::from_utf8(csv(&["Bucket", "Key", "Size", "ReplicationStatus"], &rows)).unwrap();
        assert_eq!(out, "\"b\",\"a+dir%2Fk%221\",\"3\",\"\"\n");
    }
}
