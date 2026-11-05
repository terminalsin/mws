//! Work ElastiCache does on a schedule: daily automatic snapshots in each
//! cluster's snapshot window (`SnapshotRetentionLimit` > 0), and pruning
//! the ones older than the retention limit. Time is the emulated clock,
//! so advancing it past a window takes the snapshot.

use chrono::{DateTime, Duration, NaiveTime, TimeZone, Utc};
use mws_core::RequestContext;

use crate::engine;
use crate::generated::types as t;
use crate::state::{RegionState, ServerlessSnapshot};
use crate::ElastiCache;

/// The start of the latest window (`hh24:mi-hh24:mi`, or a bare `hh24:mi`
/// for serverless caches) that began at or before `now`.
pub(crate) fn last_window_start(window: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let start = window.split('-').next()?;
    let time = NaiveTime::parse_from_str(start, "%H:%M").ok()?;
    let today = Utc.from_utc_datetime(&now.date_naive().and_time(time));
    Some(if today <= now { today } else { today - Duration::days(1) })
}

/// The name AWS gives an automatic snapshot.
pub(crate) fn automatic_name(source: &str, at: DateTime<Utc>) -> String {
    format!("automatic.{source}-{}", at.format("%Y-%m-%d-%H-%M"))
}

/// A source of automatic snapshots: id, retention limit, window and
/// creation time.
type Candidate = (String, i32, Option<String>, Option<DateTime<Utc>>);

/// What is due in one Region.
#[derive(Default)]
struct Due {
    /// (snapshot name, where its data comes from).
    snapshots: Vec<(String, engine::Sources)>,
    serverless: Vec<String>,
}

impl ElastiCache {
    /// Take the automatic snapshots that are due at `now_ms` (emulated
    /// epoch milliseconds) and prune expired ones.
    pub(crate) fn run_schedules(&self, now_ms: i64) {
        let Some(template) = self.meter().template.lock().expect("ElastiCache meter lock poisoned").clone() else {
            return;
        };
        let Some(now) = DateTime::<Utc>::from_timestamp_millis(now_ms) else { return };
        let keys: Vec<String> = self.lock().regions.keys().cloned().collect();
        for key in keys {
            let (account, region) = key.split_once('/').unwrap_or((&key, ""));
            let mut ctx = RequestContext { region: region.to_string(), received_at: now, ..template.clone() };
            ctx.caller.account_id = account.to_string();
            let due = self.with_existing(&key, |r| due(self, &ctx, r, now)).unwrap_or_default();
            for (name, sources) in due.snapshots {
                engine::snapshot(self, &ctx, &key, &name, sources, vec![]);
            }
            for name in due.serverless {
                engine::serverless_snapshot(self, &ctx, &key, &name);
            }
        }
    }
}

fn due(svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, now: DateTime<Utc>) -> Due {
    let mut out = Due::default();
    prune(r, now);
    // Replication groups.
    let groups: Vec<Candidate> = r
        .replication_groups
        .values()
        .filter(|g| g.status() == "available" && g.engine().is_redis_like())
        .map(|g| {
            (
                g.info.replication_group_id.clone().unwrap_or_default(),
                g.info.snapshot_retention_limit.unwrap_or(0),
                g.info.snapshot_window.clone(),
                g.info.replication_group_create_time,
            )
        })
        .collect();
    for (id, limit, window, created) in groups {
        let Some(at) = is_due(r, &format!("rg/{id}"), limit, window.as_deref(), created, now) else { continue };
        let name = automatic_name(&id, at);
        let sources = engine::snapshot_sources(r, Some(&id), None);
        if crate::ops::snapshots::start(svc, ctx, r, &name, Some(&id), None, "automated", None).is_ok() {
            r.automatic_snapshots.insert(format!("rg/{id}"), now);
            out.snapshots.push((name, sources));
        }
    }
    // Clusters outside replication groups.
    let clusters: Vec<Candidate> = r
        .clusters
        .values()
        .filter(|c| c.info.replication_group_id.is_none() && c.status() == "available" && c.engine().is_redis_like())
        .map(|c| {
            (
                c.id().to_string(),
                c.info.snapshot_retention_limit.unwrap_or(0),
                c.info.snapshot_window.clone(),
                c.info.cache_cluster_create_time,
            )
        })
        .collect();
    for (id, limit, window, created) in clusters {
        let Some(at) = is_due(r, &format!("cluster/{id}"), limit, window.as_deref(), created, now) else { continue };
        let name = automatic_name(&id, at);
        let sources = engine::snapshot_sources(r, None, Some(&id));
        if crate::ops::snapshots::start(svc, ctx, r, &name, None, Some(&id), "automated", None).is_ok() {
            r.automatic_snapshots.insert(format!("cluster/{id}"), now);
            out.snapshots.push((name, sources));
        }
    }
    // Serverless caches.
    let caches: Vec<t::ServerlessCache> = r
        .serverless
        .values()
        .filter(|c| c.info.status.as_deref() == Some("available") && c.info.engine.as_deref() != Some("memcached"))
        .map(|c| c.info.clone())
        .collect();
    for c in caches {
        let id = c.serverless_cache_name.clone().unwrap_or_default();
        let limit = c.snapshot_retention_limit.unwrap_or(0);
        let Some(at) =
            is_due(r, &format!("serverless/{id}"), limit, c.daily_snapshot_time.as_deref(), c.create_time, now)
        else {
            continue;
        };
        let name = automatic_name(&id, at);
        if r.serverless_snapshots.contains_key(&name) {
            continue;
        }
        let info = t::ServerlessCacheSnapshot {
            serverless_cache_snapshot_name: Some(name.clone()),
            arn: Some(crate::ops::arn(ctx, "serverlesscachesnapshot", &name)),
            kms_key_id: c.kms_key_id.clone(),
            snapshot_type: Some("automated".into()),
            status: Some("creating".into()),
            create_time: Some(now),
            expiry_time: Some(now + Duration::days(limit as i64)),
            bytes_used_for_cache: Some("0".into()),
            serverless_cache_configuration: Some(t::ServerlessCacheConfiguration {
                serverless_cache_name: Some(id.clone()),
                engine: c.engine.clone(),
                major_engine_version: c.major_engine_version.clone(),
            }),
        };
        r.serverless_snapshots.insert(name.clone(), ServerlessSnapshot { info, data: Default::default() });
        r.automatic_snapshots.insert(format!("serverless/{id}"), now);
        out.serverless.push(name);
    }
    out
}

/// When `source`'s next automatic snapshot is due: the start of the window
/// it belongs to.
fn is_due(
    r: &RegionState,
    source: &str,
    limit: i32,
    window: Option<&str>,
    created: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if limit <= 0 {
        return None;
    }
    let start = last_window_start(window?, now)?;
    // The first automatic snapshot is taken in the first window after the
    // cluster was created.
    if created.is_some_and(|c| c > start) {
        return None;
    }
    if r.automatic_snapshots.get(source).is_some_and(|last| *last >= start) {
        return None;
    }
    Some(start)
}

/// Delete automatic snapshots older than their source's retention limit,
/// and those of sources that no longer exist.
fn prune(r: &mut RegionState, now: DateTime<Utc>) {
    let mut expired = Vec::new();
    for (name, s) in &r.snapshots {
        if s.info.snapshot_source.as_deref() != Some("automated")
            || s.info.snapshot_status.as_deref() == Some("creating")
        {
            continue;
        }
        let limit = match (&s.info.replication_group_id, &s.info.cache_cluster_id) {
            (_, Some(c)) => r.clusters.get(c).and_then(|c| c.info.snapshot_retention_limit),
            (Some(g), None) => r.replication_groups.get(g).and_then(|g| g.info.snapshot_retention_limit),
            _ => None,
        };
        let created = s.info.node_snapshots.iter().flatten().filter_map(|n| n.snapshot_create_time).min();
        let keep = match (limit, created) {
            (Some(l), Some(c)) if l > 0 => now - c < Duration::days(l as i64),
            _ => false,
        };
        if !keep {
            expired.push(name.clone());
        }
    }
    for name in expired {
        if let Some(s) = r.snapshots.remove(&name) {
            r.tags.remove(s.info.arn.as_deref().unwrap_or_default());
        }
    }
    let mut expired = Vec::new();
    for (name, s) in &r.serverless_snapshots {
        if s.info.snapshot_type.as_deref() != Some("automated") || s.info.status.as_deref() == Some("creating") {
            continue;
        }
        let cache = s.info.serverless_cache_configuration.as_ref().and_then(|c| c.serverless_cache_name.clone());
        let alive = cache.is_some_and(|c| r.serverless.contains_key(&c));
        if !alive || s.info.expiry_time.is_some_and(|e| e <= now) {
            expired.push(name.clone());
        }
    }
    for name in expired {
        if let Some(s) = r.serverless_snapshots.remove(&name) {
            r.tags.remove(s.info.arn.as_deref().unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        let now = Utc.with_ymd_and_hms(2026, 11, 5, 3, 0, 0).unwrap();
        assert_eq!(last_window_start("05:30-06:30", now), Some(Utc.with_ymd_and_hms(2026, 11, 4, 5, 30, 0).unwrap()));
        assert_eq!(last_window_start("02:00", now), Some(Utc.with_ymd_and_hms(2026, 11, 5, 2, 0, 0).unwrap()));
        assert_eq!(
            automatic_name("g", Utc.with_ymd_and_hms(2026, 11, 5, 2, 0, 0).unwrap()),
            "automatic.g-2026-11-05-02-00"
        );
    }
}
