//! Anomaly detection models, as `ANOMALY_DETECTION_BAND` uses them.
//!
//! A model trains on the metric's history before the query: up to two
//! weeks of it (fewer points for high-resolution periods), less the
//! detector's `ExcludedTimeRanges`. It learns an expected value and a
//! spread, with hourly, daily or weekly seasonality (in the detector's
//! `MetricTimezone`) when the history covers at least two cycles and the
//! seasonal model explains the data clearly better than a flat one. The
//! band is the expected value ± `k` standard deviations. With too little
//! history there is no model, and the band has no datapoints.
//!
//! Everything is deterministic: the same history gives the same band.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};

use crate::generated::types;

/// How far back a model looks.
pub const TRAINING_DAYS: i64 = 14;
/// At most this many periods of history (two weeks of minutes).
const MAX_TRAINING_POINTS: i64 = 20_160;
/// The fewest datapoints a model trains on.
pub const MIN_TRAINING_POINTS: usize = 10;
/// A seasonal model must at least halve the residual variance.
const SEASONAL_GAIN: f64 = 0.5;
/// The band never gets narrower than this fraction of the expected value.
const MIN_RELATIVE_SPREAD: f64 = 0.01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seasonality {
    None,
    Hourly,
    Daily,
    Weekly,
}

impl Seasonality {
    fn cycle(self) -> i64 {
        match self {
            Seasonality::None => 0,
            Seasonality::Hourly => 3600,
            Seasonality::Daily => 86_400,
            Seasonality::Weekly => 604_800,
        }
    }
}

/// What a detector's configuration changes about training.
#[derive(Debug, Clone, Default)]
pub struct Training {
    pub excluded: Vec<(i64, i64)>,
    pub timezone: Option<chrono_tz::Tz>,
}

impl Training {
    pub fn from_config(config: Option<&types::AnomalyDetectorConfiguration>) -> Self {
        let Some(c) = config else { return Self::default() };
        Self {
            excluded: c
                .excluded_time_ranges
                .iter()
                .flatten()
                .map(|r| (r.start_time.timestamp(), r.end_time.timestamp()))
                .collect(),
            timezone: c.metric_timezone.as_deref().and_then(|tz| tz.parse().ok()),
        }
    }

    fn excluded(&self, t: i64, period: i64) -> bool {
        self.excluded.iter().any(|(s, e)| t < *e && t + period > *s)
    }
}

/// The history window a band for a query starting at `start` trains on.
pub fn training_window(start: DateTime<Utc>, period: i64) -> (DateTime<Utc>, DateTime<Utc>) {
    let span = (TRAINING_DAYS * 86_400).min(period.max(1) * MAX_TRAINING_POINTS);
    (start - Duration::seconds(span), start)
}

#[derive(Debug, Clone)]
pub struct Model {
    pub seasonality: Seasonality,
    period: i64,
    timezone: Option<chrono_tz::Tz>,
    /// Expected value by phase of the cycle.
    phases: BTreeMap<i64, f64>,
    mean: f64,
    sd: f64,
}

fn phase(t: i64, season: Seasonality, period: i64, tz: Option<chrono_tz::Tz>) -> i64 {
    if season == Seasonality::None {
        return 0;
    }
    let utc = DateTime::from_timestamp(t, 0).unwrap_or_default();
    let local = match tz {
        Some(tz) => tz.from_utc_datetime(&utc.naive_utc()).naive_local(),
        None => utc.naive_utc(),
    };
    let of_day = i64::from(local.num_seconds_from_midnight());
    let secs = match season {
        Seasonality::None => 0,
        Seasonality::Hourly => i64::from(local.minute() * 60 + local.second()),
        Seasonality::Daily => of_day,
        Seasonality::Weekly => i64::from(local.weekday().num_days_from_monday()) * 86_400 + of_day,
    };
    secs / period.max(1)
}

/// Group means and the pooled within-group variance (`None` without the
/// degrees of freedom to estimate it).
fn fit(
    points: &[(i64, f64)],
    season: Seasonality,
    period: i64,
    tz: Option<chrono_tz::Tz>,
) -> Option<(BTreeMap<i64, f64>, f64)> {
    let mut groups: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    for (t, v) in points {
        groups.entry(phase(*t, season, period, tz)).or_default().push(*v);
    }
    let dof = points.len() as i64 - groups.len() as i64;
    if dof <= 0 {
        return None;
    }
    let mut means = BTreeMap::new();
    let mut ss = 0.0;
    for (p, vals) in groups {
        let m = vals.iter().sum::<f64>() / vals.len() as f64;
        ss += vals.iter().map(|v| (v - m).powi(2)).sum::<f64>();
        means.insert(p, m);
    }
    Some((means, ss / dof as f64))
}

/// Train on `history` (values by period start). `None` with too little.
pub fn train(history: &BTreeMap<i64, f64>, period: i64, training: &Training) -> Option<Model> {
    let points: Vec<(i64, f64)> = history
        .iter()
        .filter(|(t, v)| v.is_finite() && !training.excluded(**t, period))
        .map(|(t, v)| (*t, *v))
        .collect();
    if points.len() < MIN_TRAINING_POINTS {
        return None;
    }
    let span = points.last()?.0 - points.first()?.0 + period;
    let tz = training.timezone;
    let (flat, flat_var) = fit(&points, Seasonality::None, period, tz)?;
    let mean = flat.get(&0).copied().unwrap_or_default();
    let mut best = (Seasonality::None, flat, flat_var);
    for season in [Seasonality::Hourly, Seasonality::Daily, Seasonality::Weekly] {
        if period >= season.cycle() || span < 2 * season.cycle() {
            continue;
        }
        if let Some((phases, var)) = fit(&points, season, period, tz) {
            if var < best.2 * SEASONAL_GAIN {
                best = (season, phases, var);
            }
        }
    }
    let (seasonality, phases, var) = best;
    Some(Model { seasonality, period, timezone: tz, phases, mean, sd: var.max(0.0).sqrt() })
}

impl Model {
    /// The band at period start `t`: `(lower, upper)`.
    pub fn band(&self, t: i64, k: f64) -> (f64, f64) {
        let expected =
            self.phases.get(&phase(t, self.seasonality, self.period, self.timezone)).copied().unwrap_or(self.mean);
        let spread = self.sd.max(expected.abs() * MIN_RELATIVE_SPREAD) * k.abs();
        (expected - spread, expected + spread)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_little_history_gives_no_model() {
        let h: BTreeMap<i64, f64> = (0..5).map(|i| (i * 60, 1.0)).collect();
        assert!(train(&h, 60, &Training::default()).is_none());
    }

    #[test]
    fn flat_noise_gives_a_band_around_the_mean() {
        // 7, 8, ... 13 repeating: no hourly pattern, a spread of 2.
        let h: BTreeMap<i64, f64> = (0..120).map(|i| (i * 60, 7.0 + (i % 7) as f64)).collect();
        let m = train(&h, 60, &Training::default()).unwrap();
        assert_eq!(m.seasonality, Seasonality::None);
        let (lo, hi) = m.band(120 * 60, 2.0);
        assert!(lo > 4.0 && lo < 8.0 && hi > 12.0 && hi < 16.0, "{lo} {hi}");
    }

    #[test]
    fn learns_hourly_seasonality_and_skips_excluded_ranges() {
        // Every hour: 100 in the first half, 10 in the second.
        let h: BTreeMap<i64, f64> =
            (0..360).map(|i| (i * 60, if (i % 60) < 30 { 100.0 } else { 10.0 } + (i % 3) as f64)).collect();
        let m = train(&h, 60, &Training::default()).unwrap();
        assert_eq!(m.seasonality, Seasonality::Hourly);
        let (lo, hi) = m.band(6 * 3600 + 60, 2.0);
        assert!(lo > 90.0 && hi < 110.0, "{lo} {hi}");
        let (lo, hi) = m.band(6 * 3600 + 40 * 60, 2.0);
        assert!(lo > 0.0 && hi < 20.0, "{lo} {hi}");

        // A spike inside an excluded range is left out of training.
        let mut spiky: BTreeMap<i64, f64> = (0..120).map(|i| (i * 60, 10.0)).collect();
        spiky.insert(60 * 60, 1e6);
        let t = Training { excluded: vec![(3600, 3660)], timezone: None };
        let (_, hi) = train(&spiky, 60, &t).unwrap().band(130 * 60, 2.0);
        assert!(hi < 11.0, "{hi}");
    }

    #[test]
    fn daily_seasonality_follows_the_metric_timezone() {
        let tz: chrono_tz::Tz = "America/New_York".parse().unwrap();
        // Busy from 09:00 to 17:00 New York time, for three days, hourly.
        let base = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap().timestamp();
        let h: BTreeMap<i64, f64> = (0..72)
            .map(|i| {
                let t = base + i * 3600;
                let hour = tz.from_utc_datetime(&DateTime::from_timestamp(t, 0).unwrap().naive_utc()).hour();
                (t, if (9..17).contains(&hour) { 500.0 } else { 50.0 } + (i % 2) as f64)
            })
            .collect();
        let m = train(&h, 3600, &Training { excluded: vec![], timezone: Some(tz) }).unwrap();
        assert_eq!(m.seasonality, Seasonality::Daily);
        // 15:00 UTC is 10:00 in New York (EST).
        let (lo, _) = m.band(base + 3 * 86_400 + 15 * 3600, 2.0);
        assert!(lo > 400.0, "{lo}");
    }
}
