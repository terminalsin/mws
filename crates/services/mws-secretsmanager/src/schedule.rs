//! Rotation schedules: `AutomaticallyAfterDays`, `rate()` and `cron()`
//! expressions, and the rotation windows they open (see "Schedule
//! expressions in Secrets Manager rotation" in the user guide). All times
//! are UTC.

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};

/// A parsed rotation schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// Every N days; the window opens at midnight.
    Days(i64),
    /// Every N hours, counted from midnight.
    Hours(i64),
    Cron(Box<Cron>),
}

/// A rotation window: when it opens and when it closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Window {
    /// `NextRotationDate`: the last second of the window.
    pub fn next_rotation_date(&self) -> DateTime<Utc> {
        self.end - Duration::seconds(1)
    }
}

fn midnight(t: DateTime<Utc>) -> DateTime<Utc> {
    t.date_naive().and_hms_opt(0, 0, 0).expect("midnight exists").and_utc()
}

/// Parse a `rate()` or `cron()` expression.
pub fn parse(expression: &str) -> Result<Schedule, String> {
    let e = expression.trim();
    if let Some(inner) = e.strip_prefix("rate(").and_then(|r| r.strip_suffix(')')) {
        let mut parts = inner.split_whitespace();
        let (Some(n), Some(unit), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!("Invalid rate expression: {expression}"));
        };
        let n: i64 = n.parse().map_err(|_| format!("Invalid rate expression: {expression}"))?;
        return match unit {
            "day" | "days" if (1..=1000).contains(&n) => Ok(Schedule::Days(n)),
            "hour" | "hours" if (4..=23).contains(&n) => Ok(Schedule::Hours(n)),
            "hour" | "hours" => Err("A rate in hours must be between 4 and 23 hours.".into()),
            _ => Err(format!("Invalid rate expression: {expression}")),
        };
    }
    if let Some(inner) = e.strip_prefix("cron(").and_then(|r| r.strip_suffix(')')) {
        return Cron::parse(inner).map(|c| Schedule::Cron(Box::new(c)));
    }
    Err(format!("Invalid schedule expression: {expression}"))
}

/// Parse a `Duration` such as `3h`.
pub fn parse_duration(d: &str) -> Result<Duration, String> {
    let hours: i64 =
        d.strip_suffix('h').and_then(|h| h.parse().ok()).ok_or_else(|| format!("Invalid Duration: {d}"))?;
    if !(1..=24).contains(&hours) {
        return Err("The rotation window Duration must be between 1h and 24h.".into());
    }
    Ok(Duration::hours(hours))
}

impl Schedule {
    /// The default window length when no `Duration` is given: an hour for
    /// schedules in hours, the rest of the UTC day otherwise.
    fn in_hours(&self) -> bool {
        match self {
            Schedule::Hours(_) => true,
            Schedule::Days(_) => false,
            Schedule::Cron(c) => c.hours.iter().filter(|h| **h).count() > 1,
        }
    }

    /// The first window opening strictly after `after`. For day rates,
    /// `after` is the last rotation and the window opens N days later.
    pub fn next_window(&self, after: DateTime<Utc>, duration: Option<Duration>) -> Option<Window> {
        let start = match self {
            Schedule::Days(n) => midnight(after) + Duration::days(*n),
            Schedule::Hours(n) => {
                let mut t = midnight(after);
                while t <= after {
                    t += Duration::hours(*n);
                }
                t
            }
            Schedule::Cron(c) => c.next_after(after)?,
        };
        let end = match duration {
            Some(d) => start + d,
            None if self.in_hours() => start + Duration::hours(1),
            None => midnight(start) + Duration::days(1),
        };
        Some(Window { start, end })
    }

    /// Whether a `Duration` fits: the window may not run into the next UTC
    /// day or the next window.
    pub fn check_duration(&self, duration: Duration, from: DateTime<Utc>) -> Result<(), String> {
        let Some(w) = self.next_window(from, Some(duration)) else { return Ok(()) };
        if w.end > midnight(w.start) + Duration::days(1) {
            return Err("The rotation window can't extend into the next UTC day.".into());
        }
        if let Some(next) = self.next_window(w.start, None) {
            if w.end > next.start {
                return Err("The rotation window can't extend into the next rotation window.".into());
            }
        }
        Ok(())
    }
}

/// Day-of-month field.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dom {
    Any,
    Days([bool; 32]),
    Last,
}

/// Day-of-week field (1 = Sunday ... 7 = Saturday, as in AWS cron).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dow {
    Any,
    Days([bool; 8]),
    /// `5L`: the last such weekday of the month.
    Last(u32),
    /// `2#1`: the nth such weekday of the month.
    Nth(u32, u32),
}

/// A six-field AWS cron expression: minutes hours day-of-month month
/// day-of-week year.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cron {
    minutes: [bool; 60],
    hours: [bool; 24],
    dom: Dom,
    months: [bool; 13],
    dow: Dow,
    years: Option<Vec<i32>>,
}

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

fn value(s: &str, names: &[&str], offset: u32) -> Option<u32> {
    if let Ok(n) = s.parse() {
        return Some(n);
    }
    names.iter().position(|n| n.eq_ignore_ascii_case(s)).map(|i| i as u32 + offset)
}

/// Expand a field of numbers (lists, ranges, steps, `*`) into a set.
fn field(spec: &str, min: u32, max: u32, names: &[&str], offset: u32) -> Result<Vec<u32>, String> {
    let bad = || format!("Invalid cron field: {spec}");
    let mut out = Vec::new();
    for part in spec.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok().filter(|s| *s > 0).ok_or_else(bad)?),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a, names, offset).ok_or_else(bad)?, value(b, names, offset).ok_or_else(bad)?)
        } else {
            let v = value(range, names, offset).ok_or_else(bad)?;
            (v, if part.contains('/') { max } else { v })
        };
        if lo < min || hi > max || lo > hi {
            return Err(bad());
        }
        out.extend((lo..=hi).step_by(step as usize));
    }
    Ok(out)
}

impl Cron {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let f: Vec<&str> = spec.split_whitespace().collect();
        if f.len() != 6 {
            return Err(format!("Invalid cron expression: cron({spec}). It must have six fields."));
        }
        let mut minutes = [false; 60];
        for m in field(f[0], 0, 59, &[], 0)? {
            minutes[m as usize] = true;
        }
        let mut hours = [false; 24];
        for h in field(f[1], 0, 23, &[], 0)? {
            hours[h as usize] = true;
        }
        let dom = match f[2] {
            "?" => Dom::Any,
            "*" => Dom::Days([true; 32]),
            "L" => Dom::Last,
            s => {
                let mut d = [false; 32];
                for x in field(s, 1, 31, &[], 0)? {
                    d[x as usize] = true;
                }
                Dom::Days(d)
            }
        };
        let mut months = [false; 13];
        for m in field(f[3], 1, 12, &MONTHS, 1)? {
            months[m as usize] = true;
        }
        let dow = match f[4] {
            "?" => Dow::Any,
            "*" => Dow::Days([true; 8]),
            s if s.ends_with('L') && s.len() > 1 => Dow::Last(
                value(&s[..s.len() - 1], &DAYS, 1).filter(|d| (1..=7).contains(d)).ok_or("Invalid cron day-of-week")?,
            ),
            s if s.contains('#') => {
                let (d, n) = s.split_once('#').expect("contains #");
                let d = value(d, &DAYS, 1).filter(|d| (1..=7).contains(d)).ok_or("Invalid cron day-of-week")?;
                let n: u32 = n.parse().ok().filter(|n| (1..=5).contains(n)).ok_or("Invalid cron day-of-week")?;
                Dow::Nth(d, n)
            }
            s => {
                let mut d = [false; 8];
                for x in field(s, 1, 7, &DAYS, 1)? {
                    d[x as usize] = true;
                }
                Dow::Days(d)
            }
        };
        if (dom == Dom::Any) == (dow == Dow::Any) {
            return Err("In a cron expression, exactly one of day-of-month and day-of-week must be '?'.".into());
        }
        let years = match f[5] {
            "*" => None,
            s => Some(field(s, 1970, 2199, &[], 0)?.into_iter().map(|y| y as i32).collect()),
        };
        Ok(Self { minutes, hours, dom, months, dow, years })
    }

    fn day_matches(&self, d: NaiveDate) -> bool {
        if !self.months[d.month() as usize] {
            return false;
        }
        if let Some(y) = &self.years {
            if !y.contains(&d.year()) {
                return false;
            }
        }
        let last_day = {
            let (y, m) = if d.month() == 12 { (d.year() + 1, 1) } else { (d.year(), d.month() + 1) };
            NaiveDate::from_ymd_opt(y, m, 1).expect("valid date").pred_opt().expect("valid date").day()
        };
        let weekday = d.weekday().num_days_from_sunday() + 1;
        let dom = match &self.dom {
            Dom::Any => true,
            Dom::Days(set) => set[d.day() as usize],
            Dom::Last => d.day() == last_day,
        };
        let dow = match &self.dow {
            Dow::Any => true,
            Dow::Days(set) => set[weekday as usize],
            Dow::Last(w) => weekday == *w && d.day() + 7 > last_day,
            Dow::Nth(w, n) => weekday == *w && (d.day() - 1) / 7 + 1 == *n,
        };
        dom && dow
    }

    /// The first matching minute strictly after `after`.
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let mut day = after.date_naive();
        for _ in 0..(366 * 6) {
            if self.day_matches(day) {
                for h in (0..24).filter(|h| self.hours[*h as usize]) {
                    for m in (0..60).filter(|m| self.minutes[*m as usize]) {
                        let t = Utc.from_utc_datetime(&day.and_hms_opt(h, m, 0)?);
                        if t > after {
                            return Some(t);
                        }
                    }
                }
            }
            day = day.succ_opt()?;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn day_rates_open_at_midnight_and_close_at_end_of_day() {
        let w = parse("rate(10 days)").unwrap().next_window(t("2026-01-05T13:00:00Z"), None).unwrap();
        assert_eq!(w.start, t("2026-01-15T00:00:00Z"));
        assert_eq!(w.next_rotation_date(), t("2026-01-15T23:59:59Z"));
    }

    #[test]
    fn hour_rates_default_to_an_hour() {
        let w = parse("rate(6 hours)").unwrap().next_window(t("2026-01-05T13:00:00Z"), None).unwrap();
        assert_eq!(w.start, t("2026-01-05T18:00:00Z"));
        assert_eq!(w.end, t("2026-01-05T19:00:00Z"));
    }

    #[test]
    fn cron_expressions() {
        // 8 AM UTC on the first Sunday of each month.
        let s = parse("cron(0 8 ? * 1#1 *)").unwrap();
        let w = s.next_window(t("2026-01-05T00:00:00Z"), Some(Duration::hours(2))).unwrap();
        assert_eq!(w.start, t("2026-02-01T08:00:00Z"));
        assert_eq!(w.end, t("2026-02-01T10:00:00Z"));
        // Every day at 16:00, last day of the month.
        let s = parse("cron(0 16 L * ? *)").unwrap();
        assert_eq!(s.next_window(t("2026-02-03T00:00:00Z"), None).unwrap().start, t("2026-02-28T16:00:00Z"));
        // Last Friday.
        let s = parse("cron(0 0 ? * 6L *)").unwrap();
        assert_eq!(s.next_window(t("2026-01-01T00:00:00Z"), None).unwrap().start, t("2026-01-30T00:00:00Z"));
        assert!(parse("cron(0 8 * * 1 *)").is_err());
        assert!(parse("rate(2 hours)").is_err());
    }

    #[test]
    fn durations_stay_in_the_day() {
        let s = parse("cron(0 20 * * ? *)").unwrap();
        assert!(s.check_duration(Duration::hours(4), t("2026-01-01T00:00:00Z")).is_ok());
        assert!(s.check_duration(Duration::hours(5), t("2026-01-01T00:00:00Z")).is_err());
    }
}
