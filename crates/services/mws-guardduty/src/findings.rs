//! Findings: querying with finding criteria, archiving, feedback,
//! statistics, and the pipeline new findings go through (suppression
//! rules, EventBridge, publishing destinations).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Write;

use chrono::{DateTime, NaiveDate, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::common::*;
use crate::generated::{json_ser, types};
use crate::state::State;
use crate::{FindingExport, GuardDuty, GuardDutyEvent};

/// A finding as JSON, with GuardDuty's wire names.
pub fn finding_json(f: &types::Finding) -> Value {
    json_ser::ser_finding(f)
}

/// The finding as EventBridge, S3 exports and finding criteria see it:
/// the wire JSON with `service.additionalInfo` flattened into its fields.
pub fn event_detail(f: &types::Finding) -> Value {
    let mut v = finding_json(f);
    if let Some(info) = v.pointer_mut("/service/additionalInfo") {
        let parsed = info.get("value").and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok());
        if let Some(Value::Object(mut fields)) = parsed {
            if let Some(t) = info.get("type").cloned() {
                fields.entry("type".to_string()).or_insert(t);
            }
            *info = Value::Object(fields);
        }
    }
    v
}

/// Every value at dotted `path` in `v`, looking through arrays.
fn values_at<'v>(v: &'v Value, path: &str) -> Vec<&'v Value> {
    let mut current = vec![v];
    for part in path.split('.') {
        let mut next = Vec::new();
        for c in current {
            let c = match c {
                Value::Array(items) => items.iter().filter_map(|i| i.get(part)).collect::<Vec<_>>(),
                other => other.get(part).into_iter().collect(),
            };
            for x in c {
                match x {
                    Value::Array(items) => next.extend(items.iter()),
                    other => next.push(other),
                }
            }
        }
        current = next;
    }
    current
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A value as a number: numbers, numeric strings and ISO 8601 timestamps
/// (epoch milliseconds).
fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => {
            s.parse::<f64>().ok().or_else(|| DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp_millis() as f64))
        }
        _ => None,
    }
}

fn equal(v: &Value, wanted: &str) -> bool {
    if as_text(v) == wanted {
        return true;
    }
    match (as_number(v), wanted.parse::<f64>().ok()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// `*` and `?` wildcards.
fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The JSON path a criterion key names. Most keys are paths already; a few
/// console names are shorthands.
fn criterion_path(key: &str) -> &str {
    match key {
        "sample" => "service.additionalInfo.sample",
        "archived" => "service.archived",
        other => other,
    }
}

fn condition_matches(values: &[&Value], c: &types::Condition) -> bool {
    let any = |f: &dyn Fn(&Value) -> bool| values.iter().any(|v| f(v));
    let eq = c.equals.as_ref().or(c.eq.as_ref());
    if let Some(list) = eq {
        if !any(&|v| list.iter().any(|w| equal(v, w))) {
            return false;
        }
    }
    let neq = c.not_equals.as_ref().or(c.neq.as_ref());
    if let Some(list) = neq {
        if values.iter().any(|v| list.iter().any(|w| equal(v, w))) {
            return false;
        }
    }
    let num = |bound: Option<f64>, cmp: fn(f64, f64) -> bool| match bound {
        None => true,
        Some(b) => any(&|v| as_number(v).is_some_and(|n| cmp(n, b))),
    };
    let gt = c.greater_than.map(|x| x as f64).or(c.gt.map(f64::from));
    let gte = c.greater_than_or_equal.map(|x| x as f64).or(c.gte.map(f64::from));
    let lt = c.less_than.map(|x| x as f64).or(c.lt.map(f64::from));
    let lte = c.less_than_or_equal.map(|x| x as f64).or(c.lte.map(f64::from));
    if !(num(gt, |n, b| n > b) && num(gte, |n, b| n >= b) && num(lt, |n, b| n < b) && num(lte, |n, b| n <= b)) {
        return false;
    }
    if let Some(list) = &c.matches {
        if !any(&|v| list.iter().any(|p| wildcard(p, &as_text(v)))) {
            return false;
        }
    }
    if let Some(list) = &c.not_matches {
        if values.iter().any(|v| list.iter().any(|p| wildcard(p, &as_text(v)))) {
            return false;
        }
    }
    true
}

/// Whether finding `detail` (see [`event_detail`]) meets `criteria`.
pub fn criteria_match(criteria: &types::FindingCriteria, detail: &Value) -> bool {
    criteria.criterion.iter().flatten().all(|(key, c)| condition_matches(&values_at(detail, criterion_path(key)), c))
}

fn compare_values(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => match (as_number(a), as_number(b)) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            _ => as_text(a).cmp(&as_text(b)),
        },
    }
}

pub fn sort_findings(items: &mut [(types::Finding, Value)], sort: Option<&types::SortCriteria>) {
    let Some(sort) = sort else { return };
    let Some(attr) = sort.attribute_name.as_deref() else { return };
    let desc = sort.order_by.as_deref() == Some("DESC");
    items.sort_by(|(_, a), (_, b)| {
        let o = compare_values(values_at(a, attr).first().copied(), values_at(b, attr).first().copied());
        if desc {
            o.reverse()
        } else {
            o
        }
    });
}

impl GuardDuty {
    /// The accounts whose findings the caller's detector shows: its own
    /// and its enabled members'.
    pub(crate) fn finding_accounts(state: &State, ctx: &RequestContext, detector_id: &str) -> Vec<String> {
        let mut out = vec![ctx.caller.account_id.clone()];
        if let Ok(d) = Self::owned(state, ctx, detector_id) {
            out.extend(d.members.values().filter(|m| m.status == "Enabled").map(|m| m.account.clone()));
        }
        out
    }

    /// Every finding the caller's detector shows, with its detail JSON.
    fn visible_findings(state: &State, ctx: &RequestContext, detector_id: &str) -> Vec<(types::Finding, Value)> {
        Self::finding_accounts(state, ctx, detector_id)
            .iter()
            .filter_map(|a| state.detector(a, &ctx.region))
            .flat_map(|d| d.findings.values())
            .map(|f| (f.clone(), event_detail(f)))
            .collect()
    }

    /// Apply `edit` to the findings named by `ids` that the caller sees.
    fn edit_findings(
        &self,
        ctx: &RequestContext,
        detector_id: &str,
        ids: &[String],
        edit: impl Fn(&mut types::Finding),
    ) -> Result<(), ServiceError> {
        let mut state = self.lock();
        let accounts = Self::finding_accounts(&state, ctx, detector_id);
        for account in accounts {
            if let Some(d) = state.detector_mut(&account, &ctx.region) {
                for id in ids {
                    if let Some(f) = d.findings.get_mut(id) {
                        edit(f);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn list_findings(
        &self,
        ctx: &RequestContext,
        input: types::ListFindingsRequest,
    ) -> Result<types::ListFindingsResponse, ServiceError> {
        self.authorize_detector(ctx, "ListFindings", &input.detector_id)?;
        let state = self.lock();
        let mut items = Self::visible_findings(&state, ctx, &input.detector_id);
        if let Some(c) = &input.finding_criteria {
            items.retain(|(_, d)| criteria_match(c, d));
        }
        sort_findings(&mut items, input.sort_criteria.as_ref());
        let ids: Vec<String> = items.into_iter().map(|(f, _)| f.id).collect();
        let (finding_ids, next_token) = paginate(ids, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListFindingsResponse { finding_ids, next_token })
    }

    pub(crate) fn get_findings(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsRequest,
    ) -> Result<types::GetFindingsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetFindings", &input.detector_id)?;
        let state = self.lock();
        let mut items: Vec<(types::Finding, Value)> = Self::visible_findings(&state, ctx, &input.detector_id)
            .into_iter()
            .filter(|(f, _)| input.finding_ids.contains(&f.id))
            .collect();
        if input.sort_criteria.is_some() {
            sort_findings(&mut items, input.sort_criteria.as_ref());
        } else {
            items.sort_by_key(|(f, _)| input.finding_ids.iter().position(|i| *i == f.id));
        }
        Ok(types::GetFindingsResponse { findings: items.into_iter().map(|(f, _)| f).collect() })
    }

    pub(crate) fn archive_findings(
        &self,
        ctx: &RequestContext,
        input: types::ArchiveFindingsRequest,
    ) -> Result<types::ArchiveFindingsResponse, ServiceError> {
        self.authorize_detector(ctx, "ArchiveFindings", &input.detector_id)?;
        self.check_not_managed_member(ctx)?;
        let now = iso(ctx.received_at);
        self.edit_findings(ctx, &input.detector_id, &input.finding_ids, |f| {
            if let Some(s) = f.service.as_mut() {
                if s.archived != Some(true) {
                    s.archived = Some(true);
                    f.updated_at = now.clone();
                }
            }
        })?;
        Ok(Default::default())
    }

    pub(crate) fn unarchive_findings(
        &self,
        ctx: &RequestContext,
        input: types::UnarchiveFindingsRequest,
    ) -> Result<types::UnarchiveFindingsResponse, ServiceError> {
        self.authorize_detector(ctx, "UnarchiveFindings", &input.detector_id)?;
        self.check_not_managed_member(ctx)?;
        let now = iso(ctx.received_at);
        self.edit_findings(ctx, &input.detector_id, &input.finding_ids, |f| {
            if let Some(s) = f.service.as_mut() {
                if s.archived == Some(true) {
                    s.archived = Some(false);
                    f.updated_at = now.clone();
                }
            }
        })?;
        Ok(Default::default())
    }

    /// Members of an administrator cannot archive findings; their
    /// administrator does.
    fn check_not_managed_member(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        if Self::managed_by_admin(&self.lock(), ctx) {
            return Err(invalid_input(
                "The request is rejected because the current account is a member account and cannot archive or unarchive findings. Contact your administrator account.",
            ));
        }
        Ok(())
    }

    pub(crate) fn update_findings_feedback(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingsFeedbackRequest,
    ) -> Result<types::UpdateFindingsFeedbackResponse, ServiceError> {
        self.authorize_detector(ctx, "UpdateFindingsFeedback", &input.detector_id)?;
        let feedback = input.feedback.clone();
        self.edit_findings(ctx, &input.detector_id, &input.finding_ids, |f| {
            if let Some(s) = f.service.as_mut() {
                s.user_feedback = Some(feedback.clone());
            }
        })?;
        Ok(Default::default())
    }

    pub(crate) fn get_findings_statistics(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsStatisticsRequest,
    ) -> Result<types::GetFindingsStatisticsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetFindingsStatistics", &input.detector_id)?;
        if input.finding_statistic_types.is_none() && input.group_by.is_none() {
            return Err(invalid_input(
                "The request is rejected because either findingStatisticTypes or groupBy must be specified.",
            ));
        }
        let state = self.lock();
        let mut items = Self::visible_findings(&state, ctx, &input.detector_id);
        if let Some(c) = &input.finding_criteria {
            items.retain(|(_, d)| criteria_match(c, d));
        }
        let mut stats = types::FindingStatistics::default();
        if input.finding_statistic_types.as_ref().is_some_and(|t| t.iter().any(|t| t == "COUNT_BY_SEVERITY")) {
            let mut by: BTreeMap<String, i32> = BTreeMap::new();
            for (f, _) in &items {
                *by.entry(format!("{:.1}", f.severity)).or_default() += 1;
            }
            stats.count_by_severity = Some(by);
        }
        let desc = input.order_by.as_deref() != Some("ASC");
        let limit = input.max_results.filter(|m| *m > 0).unwrap_or(25) as usize;
        if let Some(group) = input.group_by.as_deref() {
            // (key, extra, count, last generated, severity)
            let mut groups: BTreeMap<String, (String, i32, DateTime<Utc>, f64)> = BTreeMap::new();
            for (f, _) in &items {
                let updated = DateTime::parse_from_rfc3339(&f.updated_at)
                    .map(|t| t.with_timezone(&Utc))
                    .unwrap_or(ctx.received_at);
                let (key, extra) = match group {
                    "ACCOUNT" => (f.account_id.clone(), String::new()),
                    "DATE" => (updated.format("%Y-%m-%d").to_string(), String::new()),
                    "FINDING_TYPE" => (f.r#type.clone(), String::new()),
                    "SEVERITY" => (format!("{:.1}", f.severity), String::new()),
                    _ => resource_key(f),
                };
                let e = groups.entry(key).or_insert((extra, 0, updated, f.severity));
                e.1 += 1;
                if updated > e.2 {
                    e.2 = updated;
                }
                if f.severity > e.3 {
                    e.3 = f.severity;
                }
            }
            #[allow(clippy::type_complexity)]
            let mut rows: Vec<(String, (String, i32, DateTime<Utc>, f64))> = groups.into_iter().collect();
            rows.sort_by(|a, b| if desc { b.1 .1.cmp(&a.1 .1) } else { a.1 .1.cmp(&b.1 .1) });
            rows.truncate(limit);
            match group {
                "ACCOUNT" => {
                    stats.grouped_by_account = Some(
                        rows.into_iter()
                            .map(|(k, (_, n, at, _))| types::AccountStatistics {
                                account_id: Some(k),
                                last_generated_at: Some(at),
                                total_findings: Some(n),
                            })
                            .collect(),
                    )
                }
                "DATE" => {
                    stats.grouped_by_date = Some(
                        rows.into_iter()
                            .map(|(k, (_, n, at, sev))| types::DateStatistics {
                                date: NaiveDate::parse_from_str(&k, "%Y-%m-%d")
                                    .ok()
                                    .and_then(|d| d.and_hms_opt(0, 0, 0))
                                    .map(|d| d.and_utc()),
                                last_generated_at: Some(at),
                                severity: Some(sev),
                                total_findings: Some(n),
                            })
                            .collect(),
                    )
                }
                "FINDING_TYPE" => {
                    stats.grouped_by_finding_type = Some(
                        rows.into_iter()
                            .map(|(k, (_, n, at, _))| types::FindingTypeStatistics {
                                finding_type: Some(k),
                                last_generated_at: Some(at),
                                total_findings: Some(n),
                            })
                            .collect(),
                    )
                }
                "SEVERITY" => {
                    stats.grouped_by_severity = Some(
                        rows.into_iter()
                            .map(|(k, (_, n, at, _))| types::SeverityStatistics {
                                last_generated_at: Some(at),
                                severity: k.parse().ok(),
                                total_findings: Some(n),
                            })
                            .collect(),
                    )
                }
                _ => {
                    stats.grouped_by_resource = Some(
                        rows.into_iter()
                            .map(|(k, (extra, n, at, _))| {
                                let (account, rtype) = extra.split_once('|').unwrap_or(("", ""));
                                types::ResourceStatistics {
                                    account_id: Some(account.to_string()),
                                    last_generated_at: Some(at),
                                    resource_id: Some(k),
                                    resource_type: Some(rtype.to_string()),
                                    total_findings: Some(n),
                                }
                            })
                            .collect(),
                    )
                }
            }
        }
        Ok(types::GetFindingsStatisticsResponse { finding_statistics: stats, next_token: None })
    }

    /// `account`'s administrator, while it is an enabled member of one.
    pub(crate) fn admin_of(state: &State, account: &str, region: &str) -> Option<String> {
        state.account(account, region).and_then(|a| a.administrator.as_ref()).map(|l| l.account.clone()).filter(
            |admin| {
                state
                    .detector(admin, region)
                    .and_then(|d| d.members.get(account))
                    .is_some_and(|m| m.status == "Enabled")
            },
        )
    }

    /// The suppression rules (archive filters) of `account` and its
    /// administrator, by rank.
    fn suppression_rules(
        state: &State,
        account: &str,
        admin: Option<&str>,
        region: &str,
    ) -> Vec<types::FindingCriteria> {
        let mut rules: Vec<types::FindingCriteria> = Vec::new();
        for a in std::iter::once(account).chain(admin) {
            if let Some(d) = state.detector(a, region) {
                let mut filters: Vec<_> = d.filters.values().filter(|f| f.action == "ARCHIVE").collect();
                filters.sort_by_key(|f| f.rank);
                rules.extend(filters.into_iter().map(|f| f.criteria.clone()));
            }
        }
        rules
    }

    /// Store `findings` in `account`'s detector: new ones that a
    /// suppression rule matches are archived. Returns the findings stored,
    /// each with whether it is new and whether it is suppressed.
    fn store_findings(
        state: &mut State,
        account: &str,
        region: &str,
        findings: Vec<types::Finding>,
    ) -> Option<(Option<String>, Vec<Stored>)> {
        let admin = Self::admin_of(state, account, region);
        let rules = Self::suppression_rules(state, account, admin.as_deref(), region);
        let det = state.detector_mut(account, region)?;
        let mut out = Vec::new();
        for mut f in findings {
            let new = !det.findings.contains_key(&f.id);
            let detail = event_detail(&f);
            if new && rules.iter().any(|r| criteria_match(r, &detail)) {
                if let Some(s) = f.service.as_mut() {
                    s.archived = Some(true);
                }
            }
            let suppressed = f.service.as_ref().and_then(|s| s.archived) == Some(true);
            det.findings.insert(f.id.clone(), f.clone());
            out.push((f, new, suppressed));
        }
        Some((admin, out))
    }

    /// Record findings generated in `account` (new ones, or updates of
    /// existing ones), then publish them at once: suppression rules of the
    /// account and its administrator archive matches, which are then not
    /// sent; the rest go to EventBridge in the account and its
    /// administrator account, and to the detector's publishing
    /// destinations.
    pub(crate) fn record_findings(&self, ctx: &RequestContext, account: &str, findings: Vec<types::Finding>) {
        let stored = Self::store_findings(&mut self.lock(), account, &ctx.region, findings);
        let Some((admin, stored)) = stored else { return };
        let publish: Vec<types::Finding> = stored.into_iter().filter(|(_, _, s)| !s).map(|(f, _, _)| f).collect();
        self.publish(ctx, account, admin.as_deref(), &publish);
    }

    /// Record findings that threat detection generated in `account`. As
    /// in AWS, a new finding is published within five minutes of being
    /// first seen, and updates of a recurring finding on the detector's
    /// `FindingPublishingFrequency` (see [`GuardDuty::flush_due`]).
    pub(crate) fn record_detected(&self, ctx: &RequestContext, account: &str, findings: Vec<types::Finding>) {
        let now = ctx.received_at;
        {
            let mut state = self.lock();
            let Some((_, stored)) = Self::store_findings(&mut state, account, &ctx.region, findings) else { return };
            let Some(det) = state.detector_mut(account, &ctx.region) else { return };
            let every = crate::detection::frequency(&det.frequency);
            for (f, new, suppressed) in stored {
                if suppressed || det.publish_due.contains_key(&f.id) {
                    continue;
                }
                let due = match det.published_at.get(&f.id) {
                    Some(last) if !new => *last + every,
                    _ => now + chrono::Duration::seconds(crate::detection::NEW_FINDING_DELAY_SECONDS),
                };
                det.publish_due.insert(f.id.clone(), due);
            }
        }
        self.flush_due(ctx);
    }

    /// Publish the detected findings (and updates) that are due by
    /// `ctx.received_at`, in every account and Region.
    pub(crate) fn flush_due(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let batches: Vec<(String, String, Option<String>, Vec<types::Finding>)> = {
            let mut state = self.lock();
            let keys: Vec<String> = state
                .accounts
                .iter()
                .filter(|(_, a)| a.detector.as_ref().is_some_and(|d| d.publish_due.values().any(|t| *t <= now)))
                .map(|(k, _)| k.clone())
                .collect();
            let mut out = Vec::new();
            for key in keys {
                let (account, region) = key.split_once('/').unwrap_or((&key, ""));
                let (account, region) = (account.to_string(), region.to_string());
                let admin = Self::admin_of(&state, &account, &region);
                let Some(det) = state.detector_mut(&account, &region) else { continue };
                let due: Vec<String> =
                    det.publish_due.iter().filter(|(_, t)| **t <= now).map(|(k, _)| k.clone()).collect();
                let mut batch = Vec::new();
                for id in due {
                    det.publish_due.remove(&id);
                    let Some(f) = det.findings.get(&id) else { continue };
                    if f.service.as_ref().and_then(|s| s.archived) == Some(true) || !det.enabled {
                        continue;
                    }
                    det.published_at.insert(id.clone(), now);
                    batch.push(f.clone());
                }
                if !batch.is_empty() {
                    out.push((account, region, admin, batch));
                }
            }
            out
        };
        for (account, region, admin, batch) in batches {
            let rctx = RequestContext { region, ..ctx.clone() };
            self.publish(&rctx, &account, admin.as_deref(), &batch);
        }
    }

    /// Send `publish` (findings of `account`) to EventBridge in the account
    /// and its administrator, to Security Hub and to publishing
    /// destinations.
    fn publish(&self, ctx: &RequestContext, account: &str, admin: Option<&str>, publish: &[types::Finding]) {
        if publish.is_empty() {
            return;
        }
        if let Some(sink) = self.events() {
            for f in publish {
                let detail = event_detail(f);
                for target in std::iter::once(account).chain(admin) {
                    sink.put_event(
                        ctx,
                        GuardDutyEvent {
                            partition: ctx.partition.clone(),
                            account: target.to_string(),
                            region: ctx.region.clone(),
                            detail_type: "GuardDuty Finding".into(),
                            detail: detail.clone(),
                            time: ctx.received_at,
                        },
                    );
                }
            }
        }
        if let Some(hub) = self.security_hub() {
            // Security Hub aggregates members' findings into its own
            // administrator, so only the finding's account imports them.
            hub.import_findings(ctx, account, &ctx.region, publish.iter().map(crate::asff::to_asff).collect());
        }
        for target in std::iter::once(account).chain(admin) {
            self.export_findings(ctx, target, publish);
        }
    }

    /// Export `findings` to the S3 publishing destinations of `account`'s
    /// detector.
    pub(crate) fn export_findings(&self, ctx: &RequestContext, account: &str, findings: &[types::Finding]) {
        let Some(exporter) = self.exporter() else { return };
        let (detector, destinations) = {
            let state = self.lock();
            let Some(d) = state.detector(account, &ctx.region) else { return };
            let dests: Vec<_> = d.destinations.values().filter(|x| x.status != "STOPPED").cloned().collect();
            (d.id.clone(), dests)
        };
        if destinations.is_empty() {
            return;
        }
        let mut lines = Vec::new();
        for f in findings {
            let _ = serde_json::to_writer(&mut lines, &event_detail(f));
            lines.push(b'\n');
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = gz.write_all(&lines);
        let body = gz.finish().unwrap_or_default();
        let date = ctx.received_at.format("%Y/%m/%d");
        for dest in destinations {
            let arn = dest.properties.destination_arn.clone().unwrap_or_default();
            let key = format!("AWSLogs/{account}/GuardDuty/{}/{date}/{}.jsonl.gz", ctx.region, uuid::Uuid::new_v4());
            let result = exporter.export(
                ctx,
                FindingExport {
                    partition: ctx.partition.clone(),
                    account: account.to_string(),
                    region: ctx.region.clone(),
                    destination_arn: arn,
                    kms_key_arn: dest.properties.kms_key_arn.clone().unwrap_or_default(),
                    detector_arn: detector_arn(ctx, account, &detector),
                    key,
                    body: body.clone(),
                },
            );
            let mut state = self.lock();
            if let Some(d) = state.detector_mut(account, &ctx.region).and_then(|d| d.destinations.get_mut(&dest.id)) {
                match result {
                    Ok(()) => {
                        d.status = "PUBLISHING".into();
                        d.failure_since = 0;
                        d.exported_through = Some(ctx.received_at);
                    }
                    Err(e) => {
                        tracing::warn!(destination = %dest.id, "GuardDuty export failed: {e}");
                        if d.failure_since == 0 {
                            d.failure_since = ctx.received_at.timestamp_millis();
                        }
                        d.status = "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY".into();
                    }
                }
            }
        }
    }
}

/// A finding as stored: with whether it is new and whether a suppression
/// rule archived it.
type Stored = (types::Finding, bool, bool);

/// The resource a finding is about: (resource id, `account|type`).
fn resource_key(f: &types::Finding) -> (String, String) {
    let r = &f.resource;
    let id = r
        .instance_details
        .as_ref()
        .and_then(|i| i.instance_id.clone())
        .or_else(|| r.access_key_details.as_ref().and_then(|a| a.access_key_id.clone()))
        .or_else(|| r.s3_bucket_details.as_ref().and_then(|b| b.first()).and_then(|b| b.name.clone()))
        .or_else(|| r.eks_cluster_details.as_ref().and_then(|e| e.name.clone()))
        .or_else(|| r.ecs_cluster_details.as_ref().and_then(|e| e.name.clone()))
        .or_else(|| r.lambda_details.as_ref().and_then(|l| l.function_name.clone()))
        .or_else(|| r.rds_db_instance_details.as_ref().and_then(|d| d.db_instance_identifier.clone()))
        .unwrap_or_default();
    (id, format!("{}|{}", f.account_id, r.resource_type.clone().unwrap_or_default()))
}
