//! Lifecycle rules, acted on.
//!
//! AWS evaluates lifecycle rules asynchronously, about once a day. MWS
//! evaluates them before every S3 request, against the request's time
//! (`RequestContext::received_at`, which follows the `/_mws/clock`), so
//! a test can move the clock forward and see objects expire, transition
//! and uploads get aborted exactly when S3 would have done it.
//!
//! As in S3, a rule's "N days after" is the object's time plus N days,
//! rounded up to the next midnight UTC. Versions under Object Lock are
//! never removed.

use chrono::{DateTime, Duration, NaiveTime, Utc};

use crate::generated::types;
use crate::state::{new_version_id, Bucket, ObjectVersion, State};

/// `t + days`, rounded up to the next midnight UTC.
pub fn due(t: DateTime<Utc>, days: i32) -> DateTime<Utc> {
    let at = t + Duration::days(i64::from(days));
    let midnight = at.date_naive().and_time(NaiveTime::MIN).and_utc();
    if midnight == at {
        at
    } else {
        midnight + Duration::days(1)
    }
}

fn enabled(rule: &types::LifecycleRule) -> bool {
    rule.status == "Enabled"
}

/// The key prefix a rule's filter (or legacy `Prefix`) requires.
fn rule_prefix(rule: &types::LifecycleRule) -> &str {
    if let Some(f) = &rule.filter {
        if let Some(and) = &f.and {
            return and.prefix.as_deref().unwrap_or_default();
        }
        return f.prefix.as_deref().unwrap_or_default();
    }
    rule.prefix.as_deref().unwrap_or_default()
}

/// Whether `rule`'s filter selects this object version.
pub fn matches(rule: &types::LifecycleRule, key: &str, v: &ObjectVersion) -> bool {
    if !key.starts_with(rule_prefix(rule)) {
        return false;
    }
    let Some(f) = &rule.filter else { return true };
    let has_tag = |t: &types::Tag| v.tags.iter().any(|x| x.key == t.key && x.value == t.value);
    let size_ok = |gt: Option<i64>, lt: Option<i64>| {
        // Delete markers have no size and only match prefix filters.
        (gt.is_none() && lt.is_none())
            || (!v.delete_marker && gt.is_none_or(|g| v.size() > g) && lt.is_none_or(|l| v.size() < l))
    };
    if let Some(and) = &f.and {
        return and.tags.iter().flatten().all(has_tag)
            && size_ok(and.object_size_greater_than, and.object_size_less_than);
    }
    f.tag.as_ref().is_none_or(has_tag) && size_ok(f.object_size_greater_than, f.object_size_less_than)
}

/// When `rule` expires the current version `v` (if it does).
fn current_expiry(rule: &types::LifecycleRule, v: &ObjectVersion) -> Option<DateTime<Utc>> {
    let e = rule.expiration.as_ref()?;
    match (e.days, e.date) {
        (Some(days), _) => Some(due(v.last_modified, days)),
        (None, Some(date)) => Some(date.max(v.last_modified)),
        _ => None,
    }
}

/// When lifecycle rules will expire the current version `v` of `key`.
pub fn expiry(b: &Bucket, key: &str, v: &ObjectVersion) -> Option<DateTime<Utc>> {
    let config = b.lifecycle.as_ref()?;
    config.rules.iter().filter(|r| enabled(r) && matches(r, key, v)).filter_map(|r| current_expiry(r, v)).min()
}

/// The `x-amz-expiration` header value for the current version of `key`:
/// the earliest expiration any enabled rule schedules.
pub fn expiration_header(b: &Bucket, key: &str, v: &ObjectVersion) -> Option<String> {
    let config = b.lifecycle.as_ref()?;
    let (at, id) = config
        .rules
        .iter()
        .filter(|r| enabled(r) && matches(r, key, v))
        .filter_map(|r| Some((current_expiry(r, v)?, r.id.clone().unwrap_or_default())))
        .min_by_key(|(at, _)| *at)?;
    Some(format!("expiry-date=\"{}\", rule-id=\"{id}\"", at.format("%a, %d %b %Y %H:%M:%S GMT")))
}

impl State {
    /// Apply every bucket's lifecycle rules as of `now`.
    pub fn run_lifecycle(&mut self, now: DateTime<Utc>) {
        for b in self.buckets.values_mut() {
            if let Some(config) = b.lifecycle.clone() {
                let rules: Vec<_> = config.rules.into_iter().filter(enabled).collect();
                if !rules.is_empty() {
                    run_bucket(b, &rules, now);
                }
            }
        }
    }

    /// Whether any bucket has lifecycle rules to run.
    pub fn has_lifecycle(&self) -> bool {
        self.buckets.values().any(|b| b.lifecycle.as_ref().is_some_and(|c| c.rules.iter().any(enabled)))
    }
}

fn run_bucket(b: &mut Bucket, rules: &[types::LifecycleRule], now: DateTime<Utc>) {
    // Incomplete multipart uploads.
    b.uploads.retain(|_, up| {
        !rules.iter().any(|r| {
            let Some(days) = r.abort_incomplete_multipart_upload.as_ref().and_then(|a| a.days_after_initiation) else {
                return false;
            };
            up.key.starts_with(rule_prefix(r)) && due(up.initiated, days) <= now
        })
    });

    let versioning = b.versioning.clone();
    let keys: Vec<String> = b.objects.keys().cloned().collect();
    for key in keys {
        let Some(mut versions) = b.objects.remove(&key) else { continue };
        apply_noncurrent(&key, &mut versions, rules, now);
        apply_current(&key, &mut versions, rules, versioning.as_deref(), now);
        if !versions.is_empty() {
            b.objects.insert(key, versions);
        }
    }
}

fn apply_current(
    key: &str,
    versions: &mut Vec<ObjectVersion>,
    rules: &[types::LifecycleRule],
    versioning: Option<&str>,
    now: DateTime<Utc>,
) {
    let Some(current) = versions.last().cloned() else { return };
    if current.delete_marker {
        // An expired object delete marker: a marker with no versions left.
        let removable = versions.len() == 1
            && rules.iter().any(|r| {
                matches(r, key, &current)
                    && r.expiration
                        .as_ref()
                        .is_some_and(|e| e.expired_object_delete_marker == Some(true) || e.days.is_some())
            });
        if removable {
            versions.clear();
        }
        return;
    }
    let matching = || rules.iter().filter(|r| matches(r, key, &current));
    if matching().filter_map(|r| current_expiry(r, &current)).any(|at| at <= now) {
        match versioning {
            None => {
                if current.locked(now).is_none() {
                    versions.pop();
                }
            }
            Some(state) => {
                let marker = ObjectVersion {
                    version_id: if state == "Enabled" { new_version_id() } else { "null".into() },
                    delete_marker: true,
                    last_modified: now,
                    owner: current.owner.clone(),
                    ..ObjectVersion::default()
                };
                if state != "Enabled" {
                    versions.retain(|v| v.version_id != "null" || v.locked(now).is_some());
                }
                versions.push(marker);
            }
        }
        return;
    }
    // Transitions: the coldest class whose time has come.
    let target = matching()
        .flat_map(|r| r.transitions.iter().flatten())
        .filter_map(|t| {
            let at = match (t.days, t.date) {
                (Some(days), _) => due(current.last_modified, days),
                (None, Some(date)) => date,
                _ => return None,
            };
            let class = t.storage_class.clone()?;
            (at <= now).then_some((at, class))
        })
        .max_by_key(|(at, _)| *at)
        .map(|(_, class)| class);
    if let (Some(class), Some(v)) = (target, versions.last_mut()) {
        transition(v, &class);
    }
}

/// Move a version to a colder storage class (never back to a warmer one).
fn transition(v: &mut ObjectVersion, class: &str) {
    const ORDER: [&str; 8] =
        ["STANDARD", "INTELLIGENT_TIERING", "STANDARD_IA", "ONEZONE_IA", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE", ""];
    let rank = |c: &str| ORDER.iter().position(|o| *o == c).unwrap_or(0);
    if rank(class) > rank(&v.storage_class) {
        v.storage_class = class.to_string();
        v.restored_until = None;
    }
}

fn apply_noncurrent(key: &str, versions: &mut Vec<ObjectVersion>, rules: &[types::LifecycleRule], now: DateTime<Utc>) {
    if versions.len() < 2 {
        return;
    }
    // Noncurrent versions, newest first, with the time each became noncurrent.
    let n = versions.len();
    let mut remove = vec![false; n];
    let mut new_class: Vec<Option<String>> = vec![None; n];
    for (rank, i) in (0..n - 1).rev().enumerate() {
        let v = &versions[i];
        let since = versions[i + 1].last_modified;
        for r in rules.iter().filter(|r| matches(r, key, v)) {
            if let Some(e) = &r.noncurrent_version_expiration {
                let keep = e.newer_noncurrent_versions.map(|k| rank < k.max(0) as usize).unwrap_or(false);
                let old_enough = match e.noncurrent_days {
                    Some(days) => due(since, days) <= now,
                    None => true,
                };
                if !keep && old_enough && v.locked(now).is_none() {
                    remove[i] = true;
                }
            }
            for t in r.noncurrent_version_transitions.iter().flatten() {
                let keep = t.newer_noncurrent_versions.map(|k| rank < k.max(0) as usize).unwrap_or(false);
                if let (false, Some(days), Some(class)) = (keep, t.noncurrent_days, &t.storage_class) {
                    if due(since, days) <= now && !v.delete_marker {
                        new_class[i] = Some(class.clone());
                    }
                }
            }
        }
    }
    let mut i = 0;
    versions.retain_mut(|v| {
        let idx = i;
        i += 1;
        if remove[idx] {
            return false;
        }
        if let Some(class) = &new_class[idx] {
            transition(v, class);
        }
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn days_round_up_to_midnight() {
        assert_eq!(due(at("2026-01-01T10:30:00Z"), 1), at("2026-01-03T00:00:00Z"));
        assert_eq!(due(at("2026-01-01T00:00:00Z"), 1), at("2026-01-02T00:00:00Z"));
        assert_eq!(due(at("2026-01-31T23:59:59Z"), 0), at("2026-02-01T00:00:00Z"));
    }

    #[test]
    fn filters() {
        let v = ObjectVersion {
            data: bytes::Bytes::from_static(b"12345"),
            tags: vec![types::Tag { key: "a".into(), value: "1".into() }],
            ..ObjectVersion::default()
        };
        let rule =
            |filter| types::LifecycleRule { status: "Enabled".into(), filter: Some(filter), ..Default::default() };
        assert!(matches(
            &rule(types::LifecycleRuleFilter { prefix: Some("logs/".into()), ..Default::default() }),
            "logs/x",
            &v
        ));
        assert!(!matches(
            &rule(types::LifecycleRuleFilter { prefix: Some("logs/".into()), ..Default::default() }),
            "x",
            &v
        ));
        assert!(matches(
            &rule(types::LifecycleRuleFilter { object_size_greater_than: Some(4), ..Default::default() }),
            "x",
            &v
        ));
        assert!(!matches(
            &rule(types::LifecycleRuleFilter { object_size_less_than: Some(5), ..Default::default() }),
            "x",
            &v
        ));
        let and = types::LifecycleRuleAndOperator {
            prefix: Some("x".into()),
            tags: Some(vec![types::Tag { key: "a".into(), value: "1".into() }]),
            ..Default::default()
        };
        assert!(matches(&rule(types::LifecycleRuleFilter { and: Some(and), ..Default::default() }), "xy", &v));
    }
}
