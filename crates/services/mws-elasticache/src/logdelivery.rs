//! Log delivery: each node's slow log (`SLOWLOG GET`) and engine log (the
//! server's own output) delivered to the CloudWatch Logs log group or
//! Firehose stream a cluster's `LogDeliveryConfigurations` name, in the
//! `text` or `json` format ElastiCache uses.
//!
//! MWS reads the logs every few seconds (Docker backend only). A
//! destination that refuses the events marks its configuration `error`
//! with the reason, as ElastiCache does; the next successful delivery
//! makes it `active` again.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::json;

use crate::generated::types as t;
use crate::resp::{Auth, Resp};
use crate::ElastiCache;

/// Events for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogBatch {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// `cloudwatch-logs` or `kinesis-firehose`.
    pub destination_type: String,
    /// The log group or delivery stream name.
    pub destination: String,
    /// The log stream (`<cluster>-<node>-<slow-log|engine-log>`).
    pub log_stream: String,
    /// The cluster's ARN (`aws:SourceArn`).
    pub source_arn: String,
    /// (epoch milliseconds, message).
    pub events: Vec<(i64, String)>,
}

/// Where ElastiCache delivers logs (CloudWatch Logs and Firehose, in MWS).
#[async_trait::async_trait]
pub trait LogDelivery: Send + Sync {
    async fn deliver(&self, batch: LogBatch) -> Result<(), String>;
}

/// How far each node's logs have been read.
#[derive(Default)]
pub(crate) struct Cursors {
    /// The last slow log entry id delivered, by node.
    slow: Mutex<HashMap<String, i64>>,
    /// Engine log lines delivered, by container handle.
    engine: Mutex<HashMap<String, usize>>,
}

/// One node whose logs go somewhere.
struct LoggedNode {
    key: String,
    partition: String,
    cluster: String,
    node: String,
    rg: Option<String>,
    arn: String,
    port: u16,
    auth: Auth,
    handle: String,
    configs: Vec<t::LogDeliveryConfiguration>,
}

fn destination(c: &t::LogDeliveryConfiguration) -> Option<String> {
    let d = c.destination_details.as_ref()?;
    match c.destination_type.as_deref()? {
        "cloudwatch-logs" => d.cloud_watch_logs_details.as_ref()?.log_group.clone(),
        "kinesis-firehose" => d.kinesis_firehose_details.as_ref()?.delivery_stream.clone(),
        _ => None,
    }
}

/// A command the way the slow log shows it: the name, with the arguments
/// counted rather than shown.
pub(crate) fn slow_command(args: &[String]) -> String {
    match args {
        [] => String::new(),
        [cmd] => cmd.clone(),
        [cmd, rest @ ..] => format!("{cmd} ... ({} more arguments)", rest.len()),
    }
}

/// One `SLOWLOG GET` entry: (id, unix seconds, microseconds, arguments,
/// client address, client name).
pub(crate) type SlowEntry = (i64, i64, i64, Vec<String>, String, String);

pub(crate) fn parse_slowlog(r: &Resp) -> Vec<SlowEntry> {
    let mut out = Vec::new();
    for e in r.items() {
        let f = e.items();
        let (Some(id), Some(ts), Some(us)) =
            (f.first().and_then(Resp::as_int), f.get(1).and_then(Resp::as_int), f.get(2).and_then(Resp::as_int))
        else {
            continue;
        };
        let args = f.get(3).map(|a| a.items().iter().filter_map(Resp::as_text).collect()).unwrap_or_default();
        let addr = f.get(4).and_then(Resp::as_text).unwrap_or_default();
        let name = f.get(5).and_then(Resp::as_text).unwrap_or_default();
        out.push((id, ts, us, args, addr, name));
    }
    out.sort_by_key(|e| e.0);
    out
}

pub(crate) fn slow_message(format: &str, cluster: &str, node: &str, e: &SlowEntry) -> String {
    let (id, ts, us, args, addr, name) = e;
    let command = slow_command(args);
    if format == "json" {
        json!({
            "CacheClusterId": cluster,
            "CacheNodeId": node,
            "Id": id,
            "Timestamp": ts,
            "Duration (us)": us,
            "Command": command,
            "ClientAddress": addr,
            "ClientName": name,
        })
        .to_string()
    } else {
        format!("{cluster},{node},{id},{ts},{us},{command},{addr},{name}")
    }
}

/// An engine log line (`1:M 05 Nov 2026 06:16:27.168 * Ready to accept
/// connections`): (role, timestamp, level, message).
pub(crate) fn parse_engine_line(line: &str) -> Option<(String, String, String, String)> {
    let (pid_role, rest) = line.split_once(' ')?;
    let role = pid_role.split_once(':')?.1.to_string();
    // `05 Nov 2026 06:16:27.168` is four words.
    let mut words = rest.splitn(6, ' ');
    let stamp: Vec<&str> = (0..4).filter_map(|_| words.next()).collect();
    if stamp.len() != 4 {
        return None;
    }
    let level = match words.next()? {
        "." => "DEBUG",
        "-" => "VERBOSE",
        "*" => "NOTICE",
        "#" => "WARNING",
        _ => return None,
    };
    Some((role, format!("{} UTC", stamp.join(" ")), level.to_string(), words.next().unwrap_or_default().to_string()))
}

pub(crate) fn engine_message(format: &str, cluster: &str, node: &str, line: &str) -> Option<String> {
    let (role, stamp, level, message) = parse_engine_line(line)?;
    Some(if format == "json" {
        json!({
            "CacheClusterId": cluster,
            "CacheNodeId": node,
            "LogLevel": level,
            "Role": role,
            "Timestamp": stamp,
            "Message": message,
        })
        .to_string()
    } else {
        format!("{cluster}-{node} {line}")
    })
}

impl ElastiCache {
    /// Deliver logs through `delivery`.
    pub fn set_log_delivery(&self, delivery: std::sync::Arc<dyn LogDelivery>) {
        let _ = self.inner.log_delivery.set(delivery);
    }

    fn logged_nodes(&self) -> Vec<LoggedNode> {
        let st = self.lock();
        let mut out = Vec::new();
        for (key, r) in &st.regions {
            for c in r.clusters.values() {
                if !c.engine().is_redis_like() {
                    continue;
                }
                let rg = c.info.replication_group_id.as_deref().and_then(|g| r.replication_groups.get(g));
                let configs = match rg {
                    Some(g) => g.info.log_delivery_configurations.clone(),
                    None => c.info.log_delivery_configurations.clone(),
                }
                .unwrap_or_default()
                .into_iter()
                .filter(|l| !matches!(l.status.as_deref(), Some("disabling" | "disabled")))
                .collect::<Vec<_>>();
                if configs.is_empty() {
                    continue;
                }
                let auth = match rg {
                    Some(g) => crate::engine::admin_auth(
                        g.engine(),
                        &g.engine_version,
                        g.internal_password.as_deref(),
                        &g.auth,
                    ),
                    None => crate::engine::cluster_auth(c),
                };
                let partition = c.info.arn.as_deref().and_then(|a| a.split(':').nth(1)).unwrap_or("aws").to_string();
                for (node, rt) in &c.nodes {
                    let Some(handle) = rt.handle.clone() else { continue };
                    out.push(LoggedNode {
                        key: key.clone(),
                        partition: partition.clone(),
                        cluster: c.id().to_string(),
                        node: node.clone(),
                        rg: c.info.replication_group_id.clone(),
                        arn: c.info.arn.clone().unwrap_or_default(),
                        port: rt.port,
                        auth: auth.clone(),
                        handle,
                        configs: configs.clone(),
                    });
                }
            }
        }
        out
    }

    /// Read new log entries from every node with log delivery, and
    /// deliver them.
    pub(crate) async fn deliver_logs(&self) {
        let Some(delivery) = self.inner.log_delivery.get().cloned() else { return };
        let now = chrono::Utc::now().timestamp_millis() + self.meter().offset_ms();
        let offset = self.meter().offset_ms();
        for n in self.logged_nodes() {
            let node_key = format!("{}/{}/{}", n.key, n.cluster, n.node);
            let wants = |kind: &str| n.configs.iter().any(|c| c.log_type.as_deref() == Some(kind));
            let mut slow = Vec::new();
            if wants("slow-log") {
                if let Some(r) = crate::engine::slowlog(self, n.port, &n.auth).await {
                    let entries = parse_slowlog(&r);
                    let mut cursors = self.inner.log_cursors.slow.lock().expect("ElastiCache log lock poisoned");
                    let last = cursors.get(&node_key).copied().unwrap_or(-1);
                    slow = entries.into_iter().filter(|e| e.0 > last && e.5 != crate::engine::CLIENT_NAME).collect();
                    if let Some(max) = slow.iter().map(|e| e.0).max() {
                        cursors.insert(node_key.clone(), max);
                    }
                }
            }
            let mut engine_lines = Vec::new();
            if wants("engine-log") {
                if let Ok(text) = self.backend().logs(&n.handle).await {
                    let lines: Vec<String> = text.lines().map(str::to_string).collect();
                    let mut cursors = self.inner.log_cursors.engine.lock().expect("ElastiCache log lock poisoned");
                    let seen = cursors.get(&n.handle).copied().unwrap_or(0).min(lines.len());
                    engine_lines = lines[seen..].to_vec();
                    cursors.insert(n.handle.clone(), lines.len());
                }
            }
            for config in &n.configs {
                let (Some(kind), Some(dest)) = (config.log_type.as_deref(), destination(config)) else { continue };
                let format = config.log_format.as_deref().unwrap_or("text");
                let events: Vec<(i64, String)> = match kind {
                    "slow-log" => slow
                        .iter()
                        .map(|e| (e.1 * 1000 + offset, slow_message(format, &n.cluster, &n.node, e)))
                        .collect(),
                    _ => engine_lines
                        .iter()
                        .filter_map(|l| engine_message(format, &n.cluster, &n.node, l))
                        .map(|m| (now, m))
                        .collect(),
                };
                if events.is_empty() {
                    continue;
                }
                let (account, region) = n.key.split_once('/').unwrap_or((&n.key, ""));
                let result = delivery
                    .deliver(LogBatch {
                        partition: n.partition.clone(),
                        account: account.to_string(),
                        region: region.to_string(),
                        destination_type: config.destination_type.clone().unwrap_or_default(),
                        destination: dest,
                        log_stream: format!("{}-{}-{kind}", n.cluster, n.node),
                        source_arn: n.arn.clone(),
                        events,
                    })
                    .await;
                self.set_log_status(&n.key, n.rg.as_deref(), &n.cluster, kind, result.err());
            }
        }
    }

    /// Record whether delivering `kind` logs worked.
    fn set_log_status(&self, key: &str, rg: Option<&str>, cluster: &str, kind: &str, error: Option<String>) {
        let (status, message) = match &error {
            None => ("active", None),
            Some(e) => ("error", Some(e.clone())),
        };
        let update = |configs: &mut Option<Vec<t::LogDeliveryConfiguration>>| {
            for c in configs.iter_mut().flatten().filter(|c| c.log_type.as_deref() == Some(kind)) {
                c.status = Some(status.into());
                c.message = message.clone();
            }
        };
        self.with_existing(key, |r| {
            match rg.and_then(|g| r.replication_groups.get_mut(g)) {
                Some(g) => update(&mut g.info.log_delivery_configurations),
                None => {
                    if let Some(c) = r.clusters.get_mut(cluster) {
                        update(&mut c.info.log_delivery_configurations);
                    }
                }
            }
            if let Some(g) = rg {
                for c in r.clusters.values_mut().filter(|c| c.info.replication_group_id.as_deref() == Some(g)) {
                    update(&mut c.info.log_delivery_configurations);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_engine_lines() {
        let line = "1:M 05 Nov 2026 06:16:27.168 * Ready to accept connections tcp";
        let (role, stamp, level, message) = parse_engine_line(line).unwrap();
        assert_eq!((role.as_str(), level.as_str()), ("M", "NOTICE"));
        assert_eq!(stamp, "05 Nov 2026 06:16:27.168 UTC");
        assert_eq!(message, "Ready to accept connections tcp");
        assert!(parse_engine_line("random output").is_none());
        let json: serde_json::Value =
            serde_json::from_str(&engine_message("json", "c", "0001", line).unwrap()).unwrap();
        assert_eq!(json["LogLevel"], "NOTICE");
    }

    #[test]
    fn formats_slow_entries() {
        assert_eq!(slow_command(&["SET".into(), "k".into(), "v".into()]), "SET ... (2 more arguments)");
        let e = (7, 1_700_000_000, 12, vec!["GET".into(), "k".into()], "1.2.3.4:5".into(), String::new());
        assert_eq!(
            slow_message("text", "c", "0001", &e),
            "c,0001,7,1700000000,12,GET ... (1 more arguments),1.2.3.4:5,"
        );
        let json: serde_json::Value = serde_json::from_str(&slow_message("json", "c", "0001", &e)).unwrap();
        assert_eq!(json["Duration (us)"], 12);
    }
}
