//! Statistics over stored samples: the five basic statistics, percentiles
//! (`p99`, `p99.9`), trimmed and winsorized means (`tm90`, `wm(10%:90%)`),
//! trimmed counts and sums (`tc`, `ts`), percentile ranks (`PR(:300)`) and
//! `IQM`, computed from the values and counts each datum carried.

use crate::state::Sample;

/// The samples of one period, combined.
#[derive(Debug, Clone, Default)]
pub struct Agg {
    pub count: f64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    /// `(value, count)` pairs, sorted by value. Incomplete when some
    /// samples were statistic sets.
    pub values: Vec<(f64, f64)>,
    /// Whether every sample carried values (so percentiles are exact).
    pub has_values: bool,
    pub unit: Option<String>,
}

impl Agg {
    pub fn of<'a>(samples: impl IntoIterator<Item = &'a Sample>) -> Option<Agg> {
        let mut a = Agg { min: f64::INFINITY, max: f64::NEG_INFINITY, has_values: true, ..Agg::default() };
        let mut any = false;
        for s in samples {
            any = true;
            if a.unit.is_none() {
                a.unit = Some(s.unit.clone());
            }
            match &s.stats {
                Some(st) => {
                    a.count += st.count;
                    a.sum += st.sum;
                    a.min = a.min.min(st.min);
                    a.max = a.max.max(st.max);
                    a.has_values = false;
                }
                None => {
                    for &(v, c) in &s.values {
                        a.count += c;
                        a.sum += v * c;
                        a.min = a.min.min(v);
                        a.max = a.max.max(v);
                        a.values.push((v, c));
                    }
                }
            }
        }
        if !any {
            return None;
        }
        a.values.sort_by(|x, y| x.0.total_cmp(&y.0));
        Some(a)
    }

    pub fn average(&self) -> Option<f64> {
        (self.count > 0.0).then(|| self.sum / self.count)
    }

    /// The value `stat` names, `None` when it cannot be computed (no data,
    /// a percentile of statistic sets, an empty trimmed range).
    pub fn stat(&self, stat: &str) -> Option<f64> {
        let s = Stat::parse(stat)?;
        if self.count <= 0.0 && !matches!(s, Stat::SampleCount | Stat::Sum) {
            return None;
        }
        match s {
            Stat::SampleCount => Some(self.count),
            Stat::Sum => Some(self.sum),
            Stat::Average => self.average(),
            Stat::Minimum => Some(self.min),
            Stat::Maximum => Some(self.max),
            other => {
                if !self.has_values || self.values.is_empty() {
                    return None;
                }
                self.extended(&other)
            }
        }
    }

    fn total(&self) -> f64 {
        self.values.iter().map(|(_, c)| c).sum()
    }

    /// The smallest value with at least `p` percent of the samples at or
    /// below it.
    fn percentile(&self, p: f64) -> f64 {
        let total = self.total();
        let target = (p / 100.0 * total).max(f64::MIN_POSITIVE);
        let mut acc = 0.0;
        for &(v, c) in &self.values {
            acc += c;
            if acc + 1e-9 >= target {
                return v;
            }
        }
        self.values.last().map(|(v, _)| *v).unwrap_or(f64::NAN)
    }

    fn bounds(&self, b: &Bounds) -> (f64, f64) {
        match b {
            Bounds::Percent(lo, hi) => (
                lo.map(|p| self.percentile(p)).unwrap_or(f64::NEG_INFINITY),
                hi.map(|p| self.percentile(p)).unwrap_or(f64::INFINITY),
            ),
            Bounds::Absolute(lo, hi) => (lo.unwrap_or(f64::NEG_INFINITY), hi.unwrap_or(f64::INFINITY)),
        }
    }

    /// Values within `b`: lower bound exclusive for percentages (as
    /// CloudWatch trims), inclusive upper bound.
    fn within(&self, b: &Bounds) -> Vec<(f64, f64)> {
        let (lo, hi) = self.bounds(b);
        let lower_inclusive = matches!(b, Bounds::Absolute(..)) || matches!(b, Bounds::Percent(None, _));
        self.values
            .iter()
            .copied()
            .filter(|(v, _)| (if lower_inclusive { *v >= lo } else { *v > lo }) && *v <= hi)
            .collect()
    }

    fn extended(&self, s: &Stat) -> Option<f64> {
        match s {
            Stat::Percentile(p) => Some(self.percentile(*p)),
            Stat::TrimmedMean(b) => {
                let w = self.within(b);
                let c: f64 = w.iter().map(|(_, c)| c).sum();
                (c > 0.0).then(|| w.iter().map(|(v, c)| v * c).sum::<f64>() / c)
            }
            Stat::TrimmedCount(b) => Some(self.within(b).iter().map(|(_, c)| c).sum()),
            Stat::TrimmedSum(b) => Some(self.within(b).iter().map(|(v, c)| v * c).sum()),
            Stat::WinsorizedMean(b) => {
                let (lo, hi) = self.bounds(b);
                let total = self.total();
                (total > 0.0).then(|| self.values.iter().map(|(v, c)| v.clamp(lo, hi) * c).sum::<f64>() / total)
            }
            Stat::PercentileRank(lo, hi) => {
                let total = self.total();
                let n: f64 = self
                    .values
                    .iter()
                    .filter(|(v, _)| lo.is_none_or(|l| *v > l) && hi.is_none_or(|h| *v <= h))
                    .map(|(_, c)| c)
                    .sum();
                (total > 0.0).then(|| n / total * 100.0)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bounds {
    Percent(Option<f64>, Option<f64>),
    Absolute(Option<f64>, Option<f64>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stat {
    SampleCount,
    Sum,
    Average,
    Minimum,
    Maximum,
    Percentile(f64),
    TrimmedMean(Bounds),
    WinsorizedMean(Bounds),
    TrimmedCount(Bounds),
    TrimmedSum(Bounds),
    PercentileRank(Option<f64>, Option<f64>),
}

fn pct(s: &str) -> Option<f64> {
    let v: f64 = s.parse().ok()?;
    (0.0..=100.0).contains(&v).then_some(v)
}

fn opt(s: &str, f: impl Fn(&str) -> Option<f64>) -> Option<Option<f64>> {
    if s.trim().is_empty() {
        Some(None)
    } else {
        f(s.trim()).map(Some)
    }
}

fn parse_bounds(inner: &str) -> Option<Bounds> {
    let (lo, hi) = inner.split_once(':')?;
    if lo.trim().ends_with('%') || hi.trim().ends_with('%') {
        let p = |s: &str| pct(s.strip_suffix('%')?);
        let b = Bounds::Percent(opt(lo, p)?, opt(hi, p)?);
        if let Bounds::Percent(Some(l), Some(h)) = b {
            if l >= h {
                return None;
            }
        }
        Some(b)
    } else {
        let n = |s: &str| s.parse::<f64>().ok();
        Some(Bounds::Absolute(opt(lo, n)?, opt(hi, n)?))
    }
}

impl Stat {
    pub fn parse(s: &str) -> Option<Stat> {
        Some(match s {
            "SampleCount" => Stat::SampleCount,
            "Sum" => Stat::Sum,
            "Average" => Stat::Average,
            "Minimum" => Stat::Minimum,
            "Maximum" => Stat::Maximum,
            "IQM" => Stat::TrimmedMean(Bounds::Percent(Some(25.0), Some(75.0))),
            _ => {
                let lower = s.to_ascii_lowercase();
                let (prefix, rest) =
                    lower.split_at(lower.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(lower.len()));
                let wrapped = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')'));
                let short = |n: &str| -> Option<Bounds> { Some(Bounds::Percent(None, Some(pct(n)?))) };
                let bounds = |r: &str| -> Option<Bounds> {
                    match wrapped {
                        Some(inner) => parse_bounds(inner),
                        None => short(r),
                    }
                };
                match prefix {
                    "p" if wrapped.is_none() => Stat::Percentile(pct(rest)?),
                    "tm" => Stat::TrimmedMean(bounds(rest)?),
                    "wm" => Stat::WinsorizedMean(bounds(rest)?),
                    "tc" => Stat::TrimmedCount(bounds(rest)?),
                    "ts" => Stat::TrimmedSum(bounds(rest)?),
                    "pr" => {
                        let (lo, hi) = wrapped?.split_once(':')?;
                        let n = |s: &str| s.parse::<f64>().ok();
                        Stat::PercentileRank(opt(lo, n)?, opt(hi, n)?)
                    }
                    _ => return None,
                }
            }
        })
    }

    pub fn is_basic(s: &str) -> bool {
        matches!(s, "SampleCount" | "Sum" | "Average" | "Minimum" | "Maximum")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(values: &[f64]) -> Agg {
        let s = Sample { values: values.iter().map(|v| (*v, 1.0)).collect(), ..Sample::default() };
        Agg::of([&s]).unwrap()
    }

    #[test]
    fn computes_extended_statistics() {
        let a = agg(&(1..=100).map(f64::from).collect::<Vec<_>>());
        assert_eq!(a.stat("p50"), Some(50.0));
        assert_eq!(a.stat("p99"), Some(99.0));
        assert_eq!(a.stat("p100"), Some(100.0));
        assert_eq!(a.stat("tc90"), Some(90.0));
        assert_eq!(a.stat("ts(:10%)"), Some(55.0));
        assert_eq!(a.stat("tm(10%:20%)"), Some(15.5));
        assert_eq!(a.stat("PR(:50)"), Some(50.0));
        assert_eq!(a.stat("IQM"), Some(50.5));
        assert_eq!(a.stat("Average"), Some(50.5));
        assert!(Stat::parse("p101").is_none());
        assert!(Stat::parse("Median").is_none());
    }
}
