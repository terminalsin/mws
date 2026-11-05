//! Where recorded events go: the event history, trails (log files in S3,
//! digests, SNS, CloudWatch Logs), event data stores and EventBridge.

use std::collections::BTreeMap;
use std::io::Write;

/// A trail's owner, the trail, and the events waiting for it.
type Delivery = (String, Trail, Vec<(String, Value)>, Vec<Value>);

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use crate::generated::types;
use crate::record::{time_string, Recorded};
use crate::selectors;
use crate::state::{DeliveredFile, HistoryEvent, Trail, EDS_EVENT_LIMIT, HISTORY_LIMIT};
use crate::CloudTrail;

const PRINCIPAL: &str = "cloudtrail.amazonaws.com";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The RSA key pairs digest files are signed with, by Region.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningKeys {
    pub regions: BTreeMap<String, Vec<SigningKey>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningKey {
    /// PKCS#8 private key, base64.
    pub private_key: String,
    /// PKCS#1 public key (DER), base64.
    pub public_key: String,
    /// Hex MD5 of the public key.
    pub fingerprint: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
}

impl SigningKeys {
    /// The Region's current key, made on first use.
    fn current(&mut self, region: &str, now: DateTime<Utc>) -> Option<SigningKey> {
        let keys = self.regions.entry(region.to_string()).or_default();
        if keys.is_empty() {
            let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).ok()?;
            let private = pair.as_der().ok()?;
            let public = pair.public_key().as_ref().to_vec();
            let fingerprint = hex::encode(<md5::Md5 as md5::Digest>::digest(&public));
            keys.push(SigningKey {
                private_key: b64().encode(private.as_ref()),
                public_key: b64().encode(&public),
                fingerprint,
                valid_from: now - Duration::hours(1),
                valid_to: None,
            });
        }
        keys.last().cloned()
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

fn random_suffix() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::thread_rng();
    (0..16).map(|_| CHARS[r.gen_range(0..CHARS.len())] as char).collect()
}

/// Whether a trail takes an event.
fn trail_takes(t: &Trail, e: &Recorded) -> bool {
    if !(t.is_multi_region_trail || t.home_region == e.region) {
        return false;
    }
    if e.global && !t.include_global_service_events {
        return false;
    }
    match (&t.advanced_event_selectors, &t.event_selectors) {
        (Some(a), _) => selectors::advanced_matches(a, e),
        (None, Some(b)) => selectors::basic_matches(b, e),
        (None, None) => e.management,
    }
}

impl CloudTrail {
    /// Record an event wherever it belongs.
    pub(crate) fn ingest(&self, ctx: &RequestContext, e: Recorded) {
        let org = self.organization(&e.account).map(|o| o.organization_id);
        let mut st = self.lock();
        if e.management {
            let history = st.account(&e.account).history.entry(e.region.clone()).or_default();
            history.push(HistoryEvent {
                event_id: e.event_id.clone(),
                event_name: e.event_name.clone(),
                event_source: e.event_source.clone(),
                event_time: e.time,
                read_only: e.read_only,
                access_key_id: e.access_key_id.clone(),
                username: e.username.clone(),
                resources: e.resources.clone(),
                record: e.record.to_string(),
            });
            let cutoff = e.time - Duration::days(90);
            let expired = history.iter().take_while(|h| h.event_time < cutoff).count();
            let excess = history.len().saturating_sub(HISTORY_LIMIT);
            history.drain(..expired.max(excess));
        }
        crate::insights::count(&mut st, &e);
        let mut logged_by_trail = false;
        // EventBridge sees API calls only while a trail is logging.
        let mut covered = false;
        for (owner, account) in st.accounts.iter_mut() {
            let mine = *owner == e.account;
            for t in account.trails.values_mut() {
                let applies = mine || (t.is_organization_trail && org.is_some() && t.organization_id == org);
                if applies && t.is_logging && (t.is_multi_region_trail || t.home_region == e.region) {
                    covered = true;
                }
                if applies && t.is_logging && trail_takes(t, &e) {
                    t.pending.push((e.account.clone(), e.record.clone()));
                    logged_by_trail = true;
                }
            }
            for eds in account.event_data_stores.values_mut() {
                let applies = mine || (eds.organization_enabled && org.is_some() && eds.organization_id == org);
                let region = eds.multi_region_enabled || eds.home_region == e.region;
                if applies
                    && region
                    && eds.ingesting()
                    && matches!(eds.category().as_deref(), Some("Management") | Some("Data"))
                    && selectors::advanced_matches(&eds.advanced_event_selectors, &e)
                {
                    eds.events.push(e.record.clone());
                    let excess = eds.events.len().saturating_sub(EDS_EVENT_LIMIT);
                    eds.events.drain(..excess);
                }
            }
        }
        drop(st);
        // EventBridge receives write management events while a trail is
        // logging, and the data events a trail logs.
        if ((e.management && !e.read_only && covered) || (!e.management && logged_by_trail))
            && self.inner.events.get().is_some()
        {
            let source = e.event_source.trim_end_matches(".amazonaws.com");
            let source = match source {
                "monitoring" => "cloudwatch",
                other => other,
            };
            let event = mws_events::ServiceEvent {
                partition: ctx.partition.clone(),
                account: e.account.clone(),
                region: e.region.clone(),
                source: format!("aws.{source}"),
                detail_type: "AWS API Call via CloudTrail".into(),
                resources: Vec::new(),
                detail: e.record.clone(),
                time: e.time,
            };
            let ctx = RequestContext { region: e.region.clone(), ..ctx.clone() };
            self.inner.bus.lock().expect("bus lock poisoned").push((ctx, event));
        }
    }

    /// Write every trail's pending events out.
    pub(crate) fn deliver_trails(&self, ctx: &RequestContext) {
        let work: Vec<Delivery> = {
            let mut st = self.lock();
            let mut work = Vec::new();
            for (owner, account) in st.accounts.iter_mut() {
                for t in account.trails.values_mut() {
                    if !t.pending.is_empty() || !t.insight_pending.is_empty() {
                        let pending = std::mem::take(&mut t.pending);
                        let insights = std::mem::take(&mut t.insight_pending);
                        work.push((owner.clone(), t.clone(), pending, insights));
                    }
                }
            }
            work
        };
        for (owner, trail, pending, insights) in work {
            let mut outcome = self.deliver_trail(ctx, &trail, pending);
            if !insights.is_empty() {
                if let Err(e) = self.deliver_insights(ctx, &trail, insights) {
                    outcome.s3_error = Some(e);
                }
            }
            let mut st = self.lock();
            let Some(t) = st.accounts.get_mut(&owner).and_then(|a| a.trails.get_mut(&trail.arn)) else { continue };
            let s = &mut t.status;
            let now = ctx.received_at;
            s.latest_delivery_attempt_time = Some(now);
            match &outcome.s3_error {
                None if !outcome.files.is_empty() => {
                    s.latest_delivery_time = Some(now);
                    s.latest_delivery_attempt_succeeded = Some(now);
                    s.latest_delivery_error = None;
                }
                None => {}
                Some(e) => s.latest_delivery_error = Some(e.clone()),
            }
            if let Some(n) = outcome.notification {
                s.latest_notification_attempt_time = Some(now);
                match n {
                    Ok(()) => {
                        s.latest_notification_time = Some(now);
                        s.latest_notification_attempt_succeeded = Some(now);
                        s.latest_notification_error = None;
                    }
                    Err(e) => s.latest_notification_error = Some(e),
                }
            }
            if let Some(c) = outcome.cloudwatch {
                match c {
                    Ok(()) => {
                        s.latest_cloud_watch_logs_delivery_time = Some(now);
                        s.latest_cloud_watch_logs_delivery_error = None;
                    }
                    Err(e) => s.latest_cloud_watch_logs_delivery_error = Some(e),
                }
            }
            if t.log_file_validation_enabled {
                t.digest.files.extend(outcome.files);
            }
        }
        self.deliver_digests(ctx);
    }

    fn deliver_trail(&self, ctx: &RequestContext, t: &Trail, pending: Vec<(String, Value)>) -> Outcome {
        let mut out = Outcome::default();
        // One log file per account and Region the events came from.
        let mut groups: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
        for (account, record) in pending {
            let region = record.get("awsRegion").and_then(Value::as_str).unwrap_or(&t.home_region).to_string();
            groups.entry((account, region)).or_default().push(record);
        }
        let now = ctx.received_at;
        let mut keys = Vec::new();
        for ((account, region), records) in &groups {
            let body = json!({ "Records": records }).to_string();
            let key = format!(
                "{}{}/CloudTrail/{region}/{}/{account}_CloudTrail_{region}_{}_{}.json.gz",
                self.log_prefix(t),
                account,
                now.format("%Y/%m/%d"),
                now.format("%Y%m%dT%H%MZ"),
                random_suffix()
            );
            let times: Vec<DateTime<Utc>> = records
                .iter()
                .filter_map(|r| r.get("eventTime").and_then(Value::as_str))
                .filter_map(|s| DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)))
                .collect();
            match self.put(ctx, t, &key, gzip(body.as_bytes()), BTreeMap::new()) {
                Ok(()) => {
                    keys.push(key.clone());
                    out.files.push(DeliveredFile {
                        bucket: t.s3_bucket_name.clone(),
                        key,
                        hash: hex::encode(sha2::Sha256::digest(body.as_bytes())),
                        newest: times.iter().max().copied(),
                        oldest: times.iter().min().copied(),
                    });
                }
                Err(e) => out.s3_error = Some(e),
            }
        }
        if let (Some(topic), false) = (&t.sns_topic_arn, keys.is_empty()) {
            out.notification = Some(self.notify(ctx, t, topic, &keys));
        }
        if let (Some(group), Some(role)) = (&t.cloud_watch_logs_log_group_arn, &t.cloud_watch_logs_role_arn) {
            out.cloudwatch = Some(self.to_cloudwatch(ctx, t, group, role, &groups));
        }
        out
    }

    /// Insights events go to their own log files, one per Region.
    fn deliver_insights(&self, ctx: &RequestContext, t: &Trail, records: Vec<Value>) -> Result<(), String> {
        let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for r in records {
            let region = r.get("awsRegion").and_then(Value::as_str).unwrap_or(&t.home_region).to_string();
            groups.entry(region).or_default().push(r);
        }
        let now = ctx.received_at;
        for (region, records) in groups {
            let account = &t.account;
            let key = format!(
                "{}{account}/CloudTrail-Insight/{region}/{}/{account}_CloudTrail-Insight_{region}_{}_{}.json.gz",
                self.log_prefix(t),
                now.format("%Y/%m/%d"),
                now.format("%Y%m%dT%H%MZ"),
                random_suffix()
            );
            let body = json!({ "Records": records }).to_string();
            self.put(ctx, t, &key, gzip(body.as_bytes()), BTreeMap::new())?;
        }
        Ok(())
    }

    /// `<prefix>/AWSLogs/[<org id>/]`.
    fn log_prefix(&self, t: &Trail) -> String {
        let mut p = match t.s3_key_prefix.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => format!("{p}/AWSLogs/"),
            None => "AWSLogs/".to_string(),
        };
        if let Some(o) = &t.organization_id {
            p.push_str(o);
            p.push('/');
        }
        p
    }

    fn put(
        &self,
        ctx: &RequestContext,
        t: &Trail,
        key: &str,
        body: Vec<u8>,
        metadata: BTreeMap<String, String>,
    ) -> Result<(), String> {
        let Some(s3) = self.inner.s3.get() else { return Err("S3 is not available".into()) };
        let put = mws_s3::ServicePutObject {
            bucket: &t.s3_bucket_name,
            key,
            body,
            content_type: "application/json",
            service_principal: PRINCIPAL,
            source_account: &t.account,
            source_arn: &t.arn,
            acl: Some("bucket-owner-full-control"),
            partition: &ctx.partition,
        };
        let options = mws_s3::ServicePutOptions { kms_key_arn: t.kms_key_id.clone(), metadata };
        s3.put_object_as_service_with_options(put, options).map(|_| ()).map_err(|e| match e {
            mws_s3::ServicePutError::NoSuchBucket => "NoSuchBucket".to_string(),
            _ => "AccessDenied".to_string(),
        })
    }

    fn notify(&self, ctx: &RequestContext, t: &Trail, topic: &str, keys: &[String]) -> Result<(), String> {
        let Some(sns) = self.inner.sns.get() else { return Err("SNS is not available".into()) };
        let message = json!({ "s3Bucket": t.s3_bucket_name, "s3ObjectKey": keys }).to_string();
        let p = mws_sns::ServicePublish {
            topic_arn: topic,
            service_principal: PRINCIPAL,
            source_arn: &t.arn,
            source_account: &t.account,
            message,
            subject: None,
            attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
        };
        sns.publish_as_service(ctx, &p).map(|_| ()).map_err(|e| match e {
            mws_sns::ServicePublishError::NoSuchTopic => "NotFound".to_string(),
            mws_sns::ServicePublishError::AccessDenied => "AuthorizationError".to_string(),
            mws_sns::ServicePublishError::Rejected(m) => m,
        })
    }

    fn to_cloudwatch(
        &self,
        ctx: &RequestContext,
        t: &Trail,
        group: &str,
        role: &str,
        groups: &BTreeMap<(String, String), Vec<Value>>,
    ) -> Result<(), String> {
        let (Some(logs), Some(sts)) = (self.inner.logs.get(), self.inner.sts.get()) else {
            return Err("CloudWatch Logs is not available".into());
        };
        let parts: Vec<&str> = group.splitn(7, ':').collect();
        if parts.len() < 7 {
            return Err("InvalidLogGroupArn".into());
        }
        let name = parts[6].trim_end_matches(":*");
        let role_ctx = self.role_context(sts, ctx, role, &t.arn)?;
        let role_ctx = RequestContext { region: parts[3].to_string(), ..role_ctx };
        for ((account, region), records) in groups {
            let events = records
                .iter()
                .map(|r| {
                    let ts = r
                        .get("eventTime")
                        .and_then(Value::as_str)
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.timestamp_millis())
                        .unwrap_or_else(|| ctx.received_at.timestamp_millis());
                    mws_logs::ServiceLogEvent { timestamp: ts, message: r.to_string() }
                })
                .collect();
            let stream = format!("{account}_CloudTrail_{region}");
            logs.put_log_events_as_caller(&role_ctx, name, &stream, events).map_err(|e| e.code.to_string())?;
        }
        Ok(())
    }

    /// Write a digest for each trail with validation on that delivered log
    /// files since its last digest (or every hour, as AWS does, when it
    /// delivered none).
    fn deliver_digests(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let due: Vec<(String, Trail)> = {
            let st = self.lock();
            st.accounts
                .iter()
                .flat_map(|(o, a)| a.trails.values().map(move |t| (o.clone(), t)))
                .filter(|(_, t)| t.log_file_validation_enabled && t.is_logging)
                .filter(|(_, t)| {
                    !t.digest.files.is_empty()
                        || t.digest.last_digest_end.is_none_or(|end| now - end >= Duration::hours(1))
                })
                .map(|(o, t)| (o, t.clone()))
                .collect()
        };
        for (owner, t) in due {
            let result = self.write_digest(ctx, &t);
            let mut st = self.lock();
            let Some(trail) = st.accounts.get_mut(&owner).and_then(|a| a.trails.get_mut(&t.arn)) else { continue };
            match result {
                Ok((key, signature)) => {
                    let delivered = t.digest.files.len();
                    trail.digest.files.drain(..delivered.min(trail.digest.files.len()));
                    trail.digest.previous_key = Some(key);
                    trail.digest.previous_signature = Some(signature);
                    trail.digest.last_digest_end = Some(now);
                    trail.status.latest_digest_delivery_time = Some(now);
                    trail.status.latest_digest_delivery_error = None;
                }
                Err(e) => {
                    trail.status.latest_digest_delivery_error = Some(e);
                    trail.digest.last_digest_end = Some(now);
                }
            }
        }
    }

    fn write_digest(&self, ctx: &RequestContext, t: &Trail) -> Result<(String, String), String> {
        let now = ctx.received_at;
        let region = &t.home_region;
        let key = self.inner.keys.lock().expect("keys lock poisoned").current(region, now).ok_or("no signing key")?;
        let start = t.digest.last_digest_end.unwrap_or(t.start_logging_time.unwrap_or(now));
        let digest_key = format!(
            "{}{}/CloudTrail-Digest/{region}/{}/{}_CloudTrail-Digest_{region}_{}_{region}_{}.json.gz",
            self.log_prefix(t),
            t.account,
            now.format("%Y/%m/%d"),
            t.account,
            t.name,
            now.format("%Y%m%dT%H%M%SZ")
        );
        let files: Vec<Value> = t
            .digest
            .files
            .iter()
            .map(|f| {
                json!({
                    "s3Bucket": f.bucket,
                    "s3Object": f.key,
                    "hashValue": f.hash,
                    "hashAlgorithm": "SHA-256",
                    "newestEventTime": f.newest.map(time_string),
                    "oldestEventTime": f.oldest.map(time_string),
                })
            })
            .collect();
        let previous_hash = t.digest.previous_key.as_ref().and_then(|k| {
            let bytes = self.inner.s3.get()?.object_bytes(&t.s3_bucket_name, k)?;
            let mut d = flate2::read::GzDecoder::new(&bytes[..]);
            let mut plain = Vec::new();
            std::io::Read::read_to_end(&mut d, &mut plain).ok()?;
            Some(hex::encode(sha2::Sha256::digest(&plain)))
        });
        let digest = json!({
            "awsAccountId": t.account,
            "digestStartTime": time_string(start),
            "digestEndTime": time_string(now),
            "digestS3Bucket": t.s3_bucket_name,
            "digestS3Object": digest_key,
            "digestPublicKeyFingerprint": key.fingerprint,
            "digestSignatureAlgorithm": "SHA256withRSA",
            "newestEventTime": t.digest.files.iter().filter_map(|f| f.newest).max().map(time_string),
            "oldestEventTime": t.digest.files.iter().filter_map(|f| f.oldest).min().map(time_string),
            "previousDigestS3Bucket": t.digest.previous_key.as_ref().map(|_| t.s3_bucket_name.clone()),
            "previousDigestS3Object": t.digest.previous_key,
            "previousDigestHashValue": previous_hash,
            "previousDigestHashAlgorithm": t.digest.previous_key.as_ref().map(|_| "SHA-256"),
            "previousDigestSignature": t.digest.previous_signature,
            "logFiles": files,
        })
        .to_string();
        let to_sign = format!(
            "{}\n{}/{}\n{}\n{}",
            time_string(now),
            t.s3_bucket_name,
            digest_key,
            hex::encode(sha2::Sha256::digest(digest.as_bytes())),
            t.digest.previous_signature.as_deref().unwrap_or("null")
        );
        let pkcs8 = b64().decode(&key.private_key).map_err(|e| e.to_string())?;
        let pair = aws_lc_rs::rsa::KeyPair::from_pkcs8(&pkcs8).map_err(|e| e.to_string())?;
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            to_sign.as_bytes(),
            &mut signature,
        )
        .map_err(|e| e.to_string())?;
        let signature = hex::encode(signature);
        let metadata = BTreeMap::from([
            ("signature".to_string(), signature.clone()),
            ("signature-algorithm".to_string(), "SHA256withRSA".to_string()),
        ]);
        self.put(ctx, t, &digest_key, gzip(digest.as_bytes()), metadata)?;
        Ok((digest_key, signature))
    }

    pub(crate) fn list_public_keys(
        &self,
        ctx: &RequestContext,
        input: types::ListPublicKeysRequest,
    ) -> Result<types::ListPublicKeysResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListPublicKeys", "*", mws_core::ConditionContext::new())?;
        let now = ctx.received_at;
        let start = input.start_time.unwrap_or(now);
        let end = input.end_time.unwrap_or(now);
        if start > end {
            return Err(crate::generated::errors::invalid_time_range("Start time must be before end time."));
        }
        let mut keys = self.inner.keys.lock().expect("keys lock poisoned");
        let _ = keys.current(&ctx.region, now);
        let list = keys
            .regions
            .get(&ctx.region)
            .into_iter()
            .flatten()
            .filter(|k| k.valid_from <= end && k.valid_to.is_none_or(|to| to >= start))
            .map(|k| types::PublicKey {
                value: b64().decode(&k.public_key).ok(),
                validity_start_time: Some(k.valid_from),
                validity_end_time: Some(k.valid_to.unwrap_or(k.valid_from + Duration::days(365 * 10))),
                fingerprint: Some(k.fingerprint.clone()),
            })
            .collect();
        Ok(types::ListPublicKeysResponse { public_key_list: Some(list), next_token: None })
    }
}

#[derive(Default)]
struct Outcome {
    files: Vec<DeliveredFile>,
    s3_error: Option<String>,
    notification: Option<Result<(), String>>,
    cloudwatch: Option<Result<(), String>>,
}
