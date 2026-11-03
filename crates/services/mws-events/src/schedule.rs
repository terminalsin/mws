//! Schedule expressions: `rate(5 minutes)` and six-field
//! `cron(minutes hours day-of-month month day-of-week year)`, in UTC.

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Timelike, Utc, Weekday};

#[derive(Debug, Clone, PartialEq)]
pub enum Schedule {
    Rate(Duration),
    Cron(Box<Cron>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cron {
    minutes: Vec<bool>,
    hours: Vec<bool>,
    dom: DayOfMonth,
    months: Vec<bool>,
    dow: DayOfWeek,
    years: Option<Vec<i32>>,
}

#[derive(Debug, Clone, PartialEq)]
enum DayOfMonth {
    Any,
    Days(Vec<bool>),
    Last { offset: u32 },
    LastWeekday,
    NearestWeekday(u32),
}

#[derive(Debug, Clone, PartialEq)]
enum DayOfWeek {
    Any,
    /// Index 1..=7, Sunday is 1.
    Days(Vec<bool>),
    Last(u32),
    Nth(u32, u32),
}

impl Schedule {
    pub fn parse(expr: &str) -> Option<Self> {
        let expr = expr.trim();
        if let Some(inner) = expr.strip_prefix("rate(").and_then(|s| s.strip_suffix(')')) {
            let mut parts = inner.split_whitespace();
            let n: i64 = parts.next()?.parse().ok()?;
            let unit = parts.next()?;
            if parts.next().is_some() || n <= 0 {
                return None;
            }
            let singular = matches!(unit, "minute" | "hour" | "day");
            if (n == 1) != singular {
                return None;
            }
            let d = match unit.trim_end_matches('s') {
                "minute" => Duration::minutes(n),
                "hour" => Duration::hours(n),
                "day" => Duration::days(n),
                _ => return None,
            };
            return Some(Schedule::Rate(d));
        }
        let inner = expr.strip_prefix("cron(").and_then(|s| s.strip_suffix(')'))?;
        let f: Vec<&str> = inner.split_whitespace().collect();
        if f.len() != 6 {
            return None;
        }
        // One of day-of-month and day-of-week must be `?`.
        if (f[2] == "?") == (f[4] == "?") {
            return None;
        }
        Some(Schedule::Cron(Box::new(Cron {
            minutes: set(f[0], 0, 59, &[])?,
            hours: set(f[1], 0, 23, &[])?,
            dom: parse_dom(f[2])?,
            months: set(f[3], 1, 12, &MONTHS)?,
            dow: parse_dow(f[4])?,
            years: if f[5] == "*" {
                None
            } else {
                let s = set(f[5], 1970, 2199, &[])?;
                Some(s.iter().enumerate().filter(|(_, b)| **b).map(|(i, _)| i as i32).collect())
            },
        })))
    }

    /// The times in `(after, until]` this schedule fires at, for a rule
    /// created at `anchor`, capped at `limit` firings.
    pub fn fires_between(
        &self,
        anchor: DateTime<Utc>,
        after: DateTime<Utc>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Vec<DateTime<Utc>> {
        let mut out = Vec::new();
        match self {
            Schedule::Rate(period) => {
                let p = period.num_milliseconds().max(1);
                let since = (after - anchor).num_milliseconds();
                let mut k = if since < 0 { 1 } else { since / p + 1 };
                loop {
                    let t = anchor + Duration::milliseconds(k * p);
                    if t > until || out.len() >= limit {
                        break;
                    }
                    if t > after {
                        out.push(t);
                    }
                    k += 1;
                }
            }
            Schedule::Cron(c) => {
                let mut t =
                    after.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(after) + Duration::minutes(1);
                // Look at most a year of minutes ahead per call.
                let mut steps = 0;
                while t <= until && out.len() < limit && steps < 60 * 24 * 366 {
                    if c.matches(t) {
                        out.push(t);
                    }
                    t += Duration::minutes(1);
                    steps += 1;
                }
            }
        }
        out
    }
}

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

fn value(s: &str, min: u32, names: &[&str]) -> Option<u32> {
    if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(s)) {
        return Some(i as u32 + min);
    }
    s.parse().ok()
}

/// A field as a bitmap indexed by value (`0..=max`).
fn set(field: &str, min: u32, max: u32, names: &[&str]) -> Option<Vec<bool>> {
    let mut bits = vec![false; max as usize + 1];
    for part in field.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a, min, names)?, value(b, min, names)?)
        } else {
            let v = value(range, min, names)?;
            (v, if part.contains('/') { max } else { v })
        };
        if lo < min || hi > max || lo > hi {
            return None;
        }
        let mut v = lo;
        while v <= hi {
            bits[v as usize] = true;
            v += step;
        }
    }
    Some(bits)
}

fn parse_dom(f: &str) -> Option<DayOfMonth> {
    Some(match f {
        "?" => DayOfMonth::Any,
        "L" => DayOfMonth::Last { offset: 0 },
        "LW" => DayOfMonth::LastWeekday,
        _ if f.starts_with("L-") => DayOfMonth::Last { offset: f[2..].parse().ok().filter(|n| *n <= 30)? },
        _ if f.ends_with('W') => {
            DayOfMonth::NearestWeekday(f[..f.len() - 1].parse().ok().filter(|d| (1..=31).contains(d))?)
        }
        _ => DayOfMonth::Days(set(f, 1, 31, &[])?),
    })
}

fn parse_dow(f: &str) -> Option<DayOfWeek> {
    Some(match f {
        "?" => DayOfWeek::Any,
        _ if f.ends_with('L') && f.len() > 1 => {
            DayOfWeek::Last(value(&f[..f.len() - 1], 1, &DAYS).filter(|d| (1..=7).contains(d))?)
        }
        _ if f.contains('#') => {
            let (d, n) = f.split_once('#')?;
            DayOfWeek::Nth(
                value(d, 1, &DAYS).filter(|d| (1..=7).contains(d))?,
                n.parse().ok().filter(|n| (1..=5).contains(n))?,
            )
        }
        "L" => DayOfWeek::Last(7),
        _ => DayOfWeek::Days(set(f, 1, 7, &DAYS)?),
    })
}

fn days_in_month(y: i32, m: u32) -> u32 {
    let next = if m == 12 { NaiveDate::from_ymd_opt(y + 1, 1, 1) } else { NaiveDate::from_ymd_opt(y, m + 1, 1) };
    next.and_then(|n| n.pred_opt()).map(|d| d.day()).unwrap_or(28)
}

fn dow_index(w: Weekday) -> u32 {
    w.num_days_from_sunday() + 1
}

impl Cron {
    fn matches(&self, t: DateTime<Utc>) -> bool {
        if !self.minutes[t.minute() as usize] || !self.hours[t.hour() as usize] || !self.months[t.month() as usize] {
            return false;
        }
        if let Some(years) = &self.years {
            if !years.contains(&t.year()) {
                return false;
            }
        }
        let last = days_in_month(t.year(), t.month());
        let day = t.day();
        let weekday = |d: u32| {
            Utc.with_ymd_and_hms(t.year(), t.month(), d, 0, 0, 0).single().map(|x| x.weekday()).unwrap_or(Weekday::Mon)
        };
        let is_weekday = |d: u32| !matches!(weekday(d), Weekday::Sat | Weekday::Sun);
        let dom_ok = match &self.dom {
            DayOfMonth::Any => true,
            DayOfMonth::Days(bits) => bits[day as usize],
            DayOfMonth::Last { offset } => day == last.saturating_sub(*offset),
            DayOfMonth::LastWeekday => {
                let mut d = last;
                while !is_weekday(d) {
                    d -= 1;
                }
                day == d
            }
            DayOfMonth::NearestWeekday(n) => {
                let n = (*n).min(last);
                let target = match weekday(n) {
                    Weekday::Sat => {
                        if n == 1 {
                            3
                        } else {
                            n - 1
                        }
                    }
                    Weekday::Sun => {
                        if n == last {
                            n - 2
                        } else {
                            n + 1
                        }
                    }
                    _ => n,
                };
                day == target
            }
        };
        let dow = dow_index(t.weekday());
        let dow_ok = match &self.dow {
            DayOfWeek::Any => true,
            DayOfWeek::Days(bits) => bits[dow as usize],
            DayOfWeek::Last(d) => dow == *d && day + 7 > last,
            DayOfWeek::Nth(d, n) => dow == *d && (day - 1) / 7 + 1 == *n,
        };
        dom_ok && dow_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        assert!(Schedule::parse("rate(5 minutes)").is_some());
        assert!(Schedule::parse("rate(1 minute)").is_some());
        assert!(Schedule::parse("rate(1 minutes)").is_none());
        assert!(Schedule::parse("rate(0 minutes)").is_none());
        assert!(Schedule::parse("cron(0 12 * * ? *)").is_some());
        assert!(Schedule::parse("cron(0 12 * * * *)").is_none());
        assert!(Schedule::parse("cron(15 10 ? * MON-FRI *)").is_some());
        assert!(Schedule::parse("cron(0 8 1W * ? 2026)").is_some());
        assert!(Schedule::parse("cron(0 8 ? * 6L *)").is_some());
        assert!(Schedule::parse("cron(0/15 * * * ? *)").is_some());
        assert!(Schedule::parse("nope").is_none());
    }

    #[test]
    fn fires() {
        let anchor = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let s = Schedule::parse("rate(5 minutes)").unwrap();
        let f = s.fires_between(anchor, anchor, anchor + Duration::minutes(16), 10);
        assert_eq!(f.len(), 3);
        let c = Schedule::parse("cron(0/15 * * * ? *)").unwrap();
        let f = c.fires_between(anchor, anchor, anchor + Duration::hours(1), 10);
        assert_eq!(f.len(), 4);
        // 2026-01-02 is a Friday.
        let c = Schedule::parse("cron(30 9 ? * FRI *)").unwrap();
        let f = c.fires_between(anchor, anchor, anchor + Duration::days(7), 10);
        assert_eq!(f, vec![Utc.with_ymd_and_hms(2026, 1, 2, 9, 30, 0).unwrap()]);
    }
}
