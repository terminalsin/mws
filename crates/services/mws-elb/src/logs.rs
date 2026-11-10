//! Access logs, connection logs and health check logs delivered to S3.
//!
//! Load balancers buffer one line per request (Application and Classic
//! Load Balancers), per TLS connection (Network Load Balancer TLS
//! listeners, Classic TCP/SSL listeners) or per TLS handshake (Application
//! Load Balancer connection logs) or per health check (Application Load
//! Balancer health check logs). Each buffer closes at the end of its
//! interval on the emulated clock (5 minutes; 5 or 60 for Classic) and is
//! written to the bucket as ELB names it:
//! `{prefix/}AWSLogs/{account}/elasticloadbalancing/{region}/yyyy/mm/dd/...`.
//!
//! Delivery is authorized the way AWS authorizes it: the bucket policy must
//! let the service principal `logdelivery.elasticloadbalancing.amazonaws.com`
//! (or, in older setups, the Region's Elastic Load Balancing account) call
//! `s3:PutObject`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Timelike, Utc};
use mws_s3::{ServicePutError, ServicePutObject};

use crate::data::FrontSpec;
use crate::Elb;

pub(crate) const SERVICE_PRINCIPAL: &str = "logdelivery.elasticloadbalancing.amazonaws.com";

/// The AWS account that delivers ELB logs in each Region, for bucket
/// policies that grant it instead of the service principal.
pub(crate) fn regional_account(region: &str) -> Option<&'static str> {
    Some(match region {
        "us-east-1" => "127311923021",
        "us-east-2" => "033677994240",
        "us-west-1" => "027434742980",
        "us-west-2" => "797873946194",
        "af-south-1" => "098369216593",
        "ca-central-1" => "985666609251",
        "eu-central-1" => "054676820928",
        "eu-west-1" => "156460612806",
        "eu-west-2" => "652711504416",
        "eu-south-1" => "635631232127",
        "eu-west-3" => "009996457667",
        "eu-north-1" => "897822967062",
        "ap-east-1" => "754344448648",
        "ap-northeast-1" => "582318560864",
        "ap-northeast-2" => "600734575887",
        "ap-northeast-3" => "383597477331",
        "ap-southeast-1" => "114774131450",
        "ap-southeast-2" => "783225319266",
        "ap-south-1" => "718504428378",
        "me-south-1" => "076674570225",
        "sa-east-1" => "507241528517",
        "us-gov-west-1" => "048591011584",
        "us-gov-east-1" => "190560391635",
        "cn-north-1" => "638102146993",
        "cn-northwest-1" => "037604701340",
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Stream {
    Access,
    Connection,
    Health,
}

/// Where a load balancer's log stream goes.
#[derive(Debug, Clone)]
pub(crate) struct Destination {
    bucket: String,
    prefix: String,
    /// Minutes per file.
    interval: i64,
}

struct Pending {
    account: String,
    region: String,
    partition: String,
    lb_arn: String,
    /// `app.name.id`, `net.name.id`, or a Classic load balancer's name.
    file_id: String,
    stream: Stream,
    classic: bool,
    destination: Destination,
    end: DateTime<Utc>,
    lines: Vec<String>,
}

/// Load balancer ARN, stream, bucket, prefix and interval end.
type FileKey = (String, Stream, String, String, DateTime<Utc>);

/// Log lines waiting for their interval to end.
#[derive(Default)]
pub(crate) struct Logs {
    pending: Mutex<BTreeMap<FileKey, Pending>>,
}

impl Logs {
    pub(crate) fn clear(&self) {
        self.pending.lock().expect("ELB log lock poisoned").clear();
    }
}

/// `2018-07-02T22:23:00.186641Z`, the timestamp ALB and Classic logs use.
pub(crate) fn micros(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// `2018-12-20T02:59:40`, the timestamp NLB logs use.
pub(crate) fn seconds(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// Quote a field the way ELB does: `"value"`, or `"-"` when empty.
pub(crate) fn quoted(v: &str) -> String {
    if v.is_empty() {
        "\"-\"".into()
    } else {
        format!("\"{}\"", v.replace('"', "\\\""))
    }
}

/// `value`, or `-` when empty.
pub(crate) fn dash(v: &str) -> &str {
    if v.is_empty() {
        "-"
    } else {
        v
    }
}

impl Elb {
    /// Where `spec`'s load balancer sends `stream`, when logging is on.
    pub(crate) fn log_destination(&self, spec: &FrontSpec, stream: Stream) -> Option<Destination> {
        let st = self.lock();
        let r = st.regions.get(&spec.region_key)?;
        if let Some(name) = &spec.classic {
            if stream != Stream::Access {
                return None;
            }
            let l = r.classic.get(name)?.attributes.access_log.clone()?;
            if !l.enabled {
                return None;
            }
            return Some(Destination {
                bucket: l.s3_bucket_name.filter(|b| !b.is_empty())?,
                prefix: l.s3_bucket_prefix.unwrap_or_default(),
                interval: i64::from(l.emit_interval.unwrap_or(60)),
            });
        }
        let lb = r.load_balancers.get(&spec.lb_arn)?;
        let kind = match stream {
            Stream::Access => "access_logs",
            Stream::Connection => "connection_logs",
            Stream::Health => "health_check_logs",
        };
        if lb.attributes.get(&format!("{kind}.s3.enabled")).map(String::as_str) != Some("true") {
            return None;
        }
        Some(Destination {
            bucket: lb.attributes.get(&format!("{kind}.s3.bucket")).filter(|b| !b.is_empty())?.clone(),
            prefix: lb.attributes.get(&format!("{kind}.s3.prefix")).cloned().unwrap_or_default(),
            interval: 5,
        })
    }

    /// Buffer one log line for `spec`'s load balancer.
    pub(crate) fn record_log(&self, spec: &FrontSpec, stream: Stream, destination: Destination, line: String) {
        let now = self.now();
        let minutes = destination.interval.max(1);
        let start = now.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(now);
        let start = start - Duration::minutes(i64::from(start.minute()) % minutes);
        let end = start + Duration::minutes(minutes);
        let classic = spec.classic.is_some();
        let file_id = match &spec.classic {
            Some(name) => name.clone(),
            None => crate::names::lb_dimension(&spec.lb_arn).replace('/', "."),
        };
        let key = (spec.lb_arn.clone(), stream, destination.bucket.clone(), destination.prefix.clone(), end);
        let mut pending = self.inner.logs.pending.lock().expect("ELB log lock poisoned");
        pending
            .entry(key)
            .or_insert_with(|| Pending {
                account: spec.account().to_string(),
                region: spec.region().to_string(),
                partition: spec.lb_arn.split(':').nth(1).unwrap_or("aws").to_string(),
                lb_arn: spec.lb_arn.clone(),
                file_id,
                stream,
                classic,
                destination,
                end,
                lines: Vec::new(),
            })
            .lines
            .push(line);
    }

    /// Write every log file whose interval has ended.
    pub(crate) fn flush_logs(&self) {
        let now = self.now();
        let due: Vec<Pending> = {
            let mut pending = self.inner.logs.pending.lock().expect("ELB log lock poisoned");
            let keys: Vec<_> = pending.iter().filter(|(_, p)| p.end <= now).map(|(k, _)| k.clone()).collect();
            keys.into_iter().filter_map(|k| pending.remove(&k)).collect()
        };
        let Some(s3) = self.s3() else { return };
        for p in due {
            let mut body = p.lines.join("\n");
            body.push('\n');
            let (body, suffix) = if p.classic {
                (body.into_bytes(), "log")
            } else {
                let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                let _ = gz.write_all(body.as_bytes());
                (gz.finish().unwrap_or_default(), "log.gz")
            };
            let mut key = prefix_path(&p.destination.prefix);
            let stream = match p.stream {
                Stream::Access => "",
                Stream::Connection => "conn_log.",
                Stream::Health => "health_log.",
            };
            key.push_str(&format!(
                "AWSLogs/{acct}/elasticloadbalancing/{region}/{date}/{stream}{acct}_elasticloadbalancing_{region}_{id}_{end}_{ip}_{random}.{suffix}",
                acct = p.account,
                region = p.region,
                date = p.end.format("%Y/%m/%d"),
                id = p.file_id,
                end = p.end.format("%Y%m%dT%H%MZ"),
                ip = node_ip(&self.inner.config.bind_host),
                random = crate::names::hex_id(8),
            ));
            let content_type = if p.classic { "text/plain" } else { "application/x-gzip" };
            if let Err(e) = deliver(
                s3,
                &p.partition,
                &p.account,
                &p.region,
                &p.lb_arn,
                &p.destination.bucket,
                &key,
                body,
                content_type,
            ) {
                tracing::warn!(lb = %p.lb_arn, bucket = %p.destination.bucket, "ELB log delivery failed: {e}");
            }
        }
    }

    /// The test file ELB writes when logging is turned on, failing the
    /// call (with this message, as `InvalidConfigurationRequest`) when the
    /// bucket does not let ELB write.
    pub(crate) fn check_log_bucket(
        &self,
        lb_arn: &str,
        account: &str,
        region: &str,
        bucket: &str,
        prefix: &str,
    ) -> Result<(), String> {
        let Some(s3) = self.s3() else { return Ok(()) };
        let partition = lb_arn.split(':').nth(1).unwrap_or("aws");
        let key = format!("{}AWSLogs/{account}/ELBAccessLogTestFile", prefix_path(prefix));
        let body = b"Enable AccessLog for ELB: ".to_vec();
        match deliver(s3, partition, account, region, lb_arn, bucket, &key, body, "text/plain") {
            Ok(()) => Ok(()),
            Err(ServicePutError::NoSuchBucket) => Err(format!("The specified bucket does not exist: {bucket}")),
            Err(_) => Err(format!("Access Denied for bucket: {bucket}. Please check S3bucket permission")),
        }
    }
}

fn prefix_path(prefix: &str) -> String {
    let p = prefix.trim_matches('/');
    if p.is_empty() {
        String::new()
    } else {
        format!("{p}/")
    }
}

/// The address a load balancer node writes into log file names.
fn node_ip(bind: &str) -> String {
    match bind {
        "" | "0.0.0.0" | "::" => "127.0.0.1".into(),
        other => other.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn deliver(
    s3: &mws_s3::S3,
    partition: &str,
    account: &str,
    region: &str,
    lb_arn: &str,
    bucket: &str,
    key: &str,
    body: Vec<u8>,
    content_type: &str,
) -> Result<(), ServicePutError> {
    let put = |body: Vec<u8>| ServicePutObject {
        bucket,
        key,
        body,
        content_type,
        service_principal: SERVICE_PRINCIPAL,
        source_account: account,
        source_arn: lb_arn,
        acl: None,
        partition,
    };
    match s3.put_object_as_service(put(body.clone())) {
        Ok(_) => Ok(()),
        Err(ServicePutError::AccessDenied { action }) => match regional_account(region) {
            Some(elb_account) => s3.put_object_as_service_account(put(body), elb_account).map(|_| ()),
            None => Err(ServicePutError::AccessDenied { action }),
        },
        Err(e) => Err(e),
    }
}

impl Elb {
    /// Log one health check of an Application Load Balancer target to each
    /// load balancer routing to its group that has health check logs on:
    /// `type time latency target_addr target_group_id status status_code
    /// reason_code`.
    pub(crate) fn record_health_log(
        &self,
        p: &crate::health::Probe,
        outcome: &Result<(), (String, String)>,
        code: Option<u16>,
        latency: std::time::Duration,
    ) {
        let region_key = format!("{}|{}", p.account, p.region);
        let (lbs, kind) = {
            let st = self.lock();
            let Some(r) = st.regions.get(&region_key) else { return };
            let Some(tg) = r.target_groups.get(&p.key.group) else { return };
            let kind = match (tg.target_type(), tg.tg.health_check_protocol.as_deref()) {
                ("lambda", _) => "lambda",
                (_, Some("HTTPS")) => "https",
                (_, Some("HTTP")) => "http",
                _ => "tcp",
            };
            let lbs: Vec<String> = crate::ops::tg_load_balancers(r, &p.key.group)
                .into_iter()
                .filter(|a| r.load_balancers.get(a).and_then(|l| l.lb.r#type.as_deref()) == Some("application"))
                .collect();
            (lbs, kind)
        };
        let target = match p.address {
            Some(a) => a.to_string(),
            None => p.key.id.clone(),
        };
        let (status, reason) = match outcome {
            Ok(()) => ("PASS", "-".to_string()),
            Err((reason, _)) => ("FAIL", reason.clone()),
        };
        let line = format!(
            "{kind} {} {:.3} {target} {} {status} {} {reason}",
            micros(self.now()),
            latency.as_secs_f64(),
            crate::names::tg_dimension(&p.key.group),
            code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
        );
        for lb_arn in lbs {
            let spec = FrontSpec {
                key: String::new(),
                region_key: region_key.clone(),
                lb_arn,
                lb_type: "application".into(),
                dns: String::new(),
                protocol: String::new(),
                port: 0,
                classic: None,
            };
            if let Some(dest) = self.log_destination(&spec, Stream::Health) {
                self.record_log(&spec, Stream::Health, dest, line.clone());
            }
        }
    }
}
