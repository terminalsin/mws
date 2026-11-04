//! `GetMetricData`: metric queries and metric math.
//!
//! Each query is a metric (`MetricStat`) or an expression over the other
//! queries. Expressions support arithmetic (`+ - * / ^`), comparison and
//! logical operators, `IF`, and the common functions: `ABS`, `AVG`,
//! `CEIL`, `DATAPOINT_COUNT`, `DIFF`, `DIFF_TIME`, `FILL`, `FIRST`,
//! `FLOOR`, `LAST`, `LOG`, `LOG10`, `MAX`, `METRICS`, `METRIC_COUNT`,
//! `MIN`, `PERIOD`, `RATE`, `REMOVE_EMPTY`, `RUNNING_SUM`, `SEARCH`,
//! `SLICE`, `SORT`, `STDDEV`, `SUM`, `TIME_SERIES`, the time functions
//! (`EPOCH`, `MINUTE`, `HOUR`, `DAY`, `DATE`, `MONTH`, `YEAR`) and
//! `ANOMALY_DETECTION_BAND`. Labels may use `${PROP('...')}` and the
//! summary-statistic placeholders.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::metrics::{aggregates, buckets, valid_period};
use crate::names::{self, now};
use crate::state::{MetricKey, Region};
use crate::CloudWatch;

/// One time series: values by epoch second.
#[derive(Debug, Clone, Default)]
pub struct Ts {
    pub label: String,
    pub period: i64,
    pub points: BTreeMap<i64, f64>,
    /// The metric and statistic a `MetricStat` series came from.
    pub metric: Option<(MetricKey, String)>,
}

#[derive(Debug, Clone)]
pub enum Val {
    Scalar(f64),
    Series(Ts),
    Array(Vec<Ts>),
    Str(String),
}

fn err(id: &str, m: impl std::fmt::Display) -> ServiceError {
    errors::validation(format!("Error in expression {id}: {m}"))
}

// ---- parsing ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Ident(String),
    Str(String),
    Op(&'static str),
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_digit() || (ch == '.' && c.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let st = i;
            while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
                i += 1;
            }
            if i < c.len() && (c[i] == 'e' || c[i] == 'E') {
                i += 1;
                if i < c.len() && (c[i] == '+' || c[i] == '-') {
                    i += 1;
                }
                while i < c.len() && c[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let t: String = c[st..i].iter().collect();
            out.push(Tok::Num(t.parse().map_err(|_| format!("Invalid number '{t}'"))?));
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(c[st..i].iter().collect()));
        } else if ch == '\'' || ch == '"' {
            let q = ch;
            i += 1;
            let mut t = String::new();
            while i < c.len() && c[i] != q {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                }
                t.push(c[i]);
                i += 1;
            }
            if i >= c.len() {
                return Err("Unterminated string".into());
            }
            i += 1;
            out.push(Tok::Str(t));
        } else {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            let op = match two.as_str() {
                ">=" => Some(">="),
                "<=" => Some("<="),
                "==" => Some("=="),
                "!=" => Some("!="),
                "&&" => Some("&&"),
                "||" => Some("||"),
                _ => None,
            };
            if let Some(op) = op {
                out.push(Tok::Op(op));
                i += 2;
                continue;
            }
            let op = match ch {
                '+' => "+",
                '-' => "-",
                '*' => "*",
                '/' => "/",
                '^' => "^",
                '(' => "(",
                ')' => ")",
                ',' => ",",
                '>' => ">",
                '<' => "<",
                '!' => "!",
                _ => return Err(format!("Unrecognized character '{ch}'")),
            };
            out.push(Tok::Op(op));
            i += 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
enum Expr {
    Num(f64),
    Str(String),
    Ident(String),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }

    fn eat_op(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Op(o)) if *o == op) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, w: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(o)) if o.eq_ignore_ascii_case(w)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.eat_op("||") || self.eat_word("OR") {
            l = Expr::Bin("||", Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.cmp()?;
        while self.eat_op("&&") || self.eat_word("AND") {
            l = Expr::Bin("&&", Box::new(l), Box::new(self.cmp()?));
        }
        Ok(l)
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let mut l = self.add()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op(o)) if matches!(*o, ">" | "<" | ">=" | "<=" | "==" | "!=") => *o,
                _ => return Ok(l),
            };
            self.i += 1;
            l = Expr::Bin(op, Box::new(l), Box::new(self.add()?));
        }
    }

    fn add(&mut self) -> Result<Expr, String> {
        let mut l = self.mul()?;
        loop {
            let op = if self.eat_op("+") {
                "+"
            } else if self.eat_op("-") {
                "-"
            } else {
                return Ok(l);
            };
            l = Expr::Bin(op, Box::new(l), Box::new(self.mul()?));
        }
    }

    fn mul(&mut self) -> Result<Expr, String> {
        let mut l = self.unary()?;
        loop {
            let op = if self.eat_op("*") {
                "*"
            } else if self.eat_op("/") {
                "/"
            } else {
                return Ok(l);
            };
            l = Expr::Bin(op, Box::new(l), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat_op("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat_op("!") || self.eat_word("NOT") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        let base = self.atom()?;
        if self.eat_op("^") {
            return Ok(Expr::Bin("^", Box::new(base), Box::new(self.unary()?)));
        }
        Ok(base)
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.toks.get(self.i).cloned() {
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(Expr::Num(n))
            }
            Some(Tok::Str(s)) => {
                self.i += 1;
                Ok(Expr::Str(s))
            }
            Some(Tok::Ident(name)) => {
                self.i += 1;
                if self.eat_op("(") {
                    let mut args = Vec::new();
                    if !self.eat_op(")") {
                        loop {
                            args.push(self.expr()?);
                            if self.eat_op(")") {
                                break;
                            }
                            if !self.eat_op(",") {
                                return Err(format!("Expected ',' or ')' in call to {name}"));
                            }
                        }
                    }
                    Ok(Expr::Call(name.to_ascii_uppercase(), args))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            Some(Tok::Op("(")) => {
                self.i += 1;
                let e = self.expr()?;
                if !self.eat_op(")") {
                    return Err("Unbalanced parentheses".into());
                }
                Ok(e)
            }
            Some(t) => Err(format!("Unexpected token {t:?}")),
            None => Err("Unexpected end of expression".into()),
        }
    }
}

fn parse(s: &str) -> Result<Expr, String> {
    let mut p = Parser { toks: lex(s)?, i: 0 };
    let e = p.expr()?;
    if p.i != p.toks.len() {
        return Err(format!("Unexpected token {:?}", p.toks[p.i]));
    }
    Ok(e)
}

/// The query ids an expression references.
fn references(e: &Expr, out: &mut BTreeSet<String>) {
    match e {
        Expr::Ident(i) => {
            out.insert(i.clone());
        }
        Expr::Neg(x) | Expr::Not(x) => references(x, out),
        Expr::Bin(_, a, b) => {
            references(a, out);
            references(b, out);
        }
        Expr::Call(_, args) => args.iter().for_each(|a| references(a, out)),
        _ => {}
    }
}

// ---- evaluation ----------------------------------------------------------------

pub struct Engine<'a> {
    pub region: Option<&'a Region>,
    /// CloudWatch Logs and the account and Region, for
    /// `INSIGHT_RULE_METRIC`.
    pub logs: Option<(&'a mws_logs::Logs, &'a str, &'a str)>,
    pub queries: &'a [types::MetricDataQuery],
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Periods must be multiples of this to get data (see
    /// [`crate::metrics::retained_resolution`]).
    pub retained: i64,
    cache: RefCell<BTreeMap<String, Val>>,
    visiting: RefCell<BTreeSet<String>>,
}

impl<'a> Engine<'a> {
    pub fn new(
        region: Option<&'a Region>,
        queries: &'a [types::MetricDataQuery],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Self {
        Self {
            region,
            logs: None,
            queries,
            start,
            end,
            retained: 1,
            cache: RefCell::default(),
            visiting: RefCell::default(),
        }
    }

    pub fn with_logs(mut self, logs: Option<&'a mws_logs::Logs>, account: &'a str, region: &'a str) -> Self {
        self.logs = logs.map(|l| (l, account, region));
        self
    }

    fn query(&self, id: &str) -> Option<&'a types::MetricDataQuery> {
        self.queries.iter().find(|q| q.id == id)
    }

    fn default_period(&self) -> i64 {
        self.queries
            .iter()
            .find_map(|q| q.metric_stat.as_ref().map(|m| m.period as i64))
            .or_else(|| self.queries.iter().find_map(|q| q.period.map(i64::from)))
            .unwrap_or(60)
    }

    /// A metric's statistic per period.
    pub fn metric_series(&self, key: &MetricKey, stat: &str, period: i64, unit: Option<&str>) -> Ts {
        let mut ts = Ts {
            label: key.name.clone(),
            period,
            points: BTreeMap::new(),
            metric: Some((key.clone(), stat.to_string())),
        };
        let series = self.region.and_then(|r| r.metrics.get(&key.key())).filter(|_| period % self.retained == 0);
        if let Some(series) = series {
            let starts = buckets(self.start, self.end, period);
            for (t, agg) in aggregates(series, &starts, period, unit) {
                if let Some(v) = agg.stat(stat) {
                    ts.points.insert(t.timestamp(), v);
                }
            }
        }
        ts
    }

    /// Evaluate query `id`.
    pub fn eval(&self, id: &str) -> Result<Val, ServiceError> {
        if let Some(v) = self.cache.borrow().get(id) {
            return Ok(v.clone());
        }
        let q = self.query(id).ok_or_else(|| err(id, format!("Unrecognized id '{id}'")))?;
        if !self.visiting.borrow_mut().insert(id.to_string()) {
            return Err(err(id, "Circular dependency between expressions"));
        }
        let v = match (&q.metric_stat, &q.expression) {
            (Some(ms), _) => {
                let key = MetricKey::new(
                    ms.metric.namespace.as_deref().unwrap_or_default(),
                    ms.metric.metric_name.as_deref().unwrap_or_default(),
                    ms.metric.dimensions.as_deref(),
                );
                Val::Series(self.metric_series(&key, &ms.stat, ms.period as i64, ms.unit.as_deref()))
            }
            (None, Some(expr)) => {
                let e = parse(expr).map_err(|m| err(id, m))?;
                let period = q.period.map(i64::from).unwrap_or_else(|| self.default_period());
                let v = self.eval_expr(id, &e, period)?;
                match v {
                    Val::Str(_) => return Err(err(id, "The expression must return a time series or a scalar")),
                    Val::Series(mut ts) => {
                        ts.label = String::new();
                        Val::Series(ts)
                    }
                    other => other,
                }
            }
            (None, None) => return Err(err(id, "Either MetricStat or Expression must be specified")),
        };
        self.visiting.borrow_mut().remove(id);
        self.cache.borrow_mut().insert(id.to_string(), v.clone());
        Ok(v)
    }

    fn grid(&self, period: i64) -> Vec<i64> {
        buckets(self.start, self.end, period).iter().map(|t| t.timestamp()).collect()
    }

    fn eval_expr(&self, id: &str, e: &Expr, period: i64) -> Result<Val, ServiceError> {
        Ok(match e {
            Expr::Num(n) => Val::Scalar(*n),
            Expr::Str(s) => Val::Str(s.clone()),
            Expr::Ident(name) => {
                if self.query(name).is_some() {
                    if name == id {
                        return Err(err(id, "An expression cannot reference itself"));
                    }
                    self.eval(name)?
                } else if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                    Val::Str(name.clone())
                } else {
                    return Err(err(id, format!("Unrecognized id '{name}'")));
                }
            }
            Expr::Neg(x) => unary(self.eval_expr(id, x, period)?, |v| Some(-v)),
            Expr::Not(x) => unary(self.eval_expr(id, x, period)?, |v| Some(if v == 0.0 { 1.0 } else { 0.0 })),
            Expr::Bin(op, a, b) => {
                let a = self.eval_expr(id, a, period)?;
                let b = self.eval_expr(id, b, period)?;
                binary(id, op, a, b)?
            }
            Expr::Call(name, args) => self.call(id, name, args, period)?,
        })
    }

    fn arg(&self, id: &str, args: &[Expr], i: usize, period: i64) -> Result<Val, ServiceError> {
        let e = args.get(i).ok_or_else(|| err(id, "Missing function argument"))?;
        self.eval_expr(id, e, period)
    }

    fn call(&self, id: &str, name: &str, args: &[Expr], period: i64) -> Result<Val, ServiceError> {
        let one = |f: fn(f64) -> f64| -> Result<Val, ServiceError> {
            Ok(unary(self.arg(id, args, 0, period)?, |v| {
                let r = f(v);
                r.is_finite().then_some(r)
            }))
        };
        Ok(match name {
            "ABS" => one(f64::abs)?,
            "CEIL" => one(f64::ceil)?,
            "FLOOR" => one(f64::floor)?,
            "LOG" => one(f64::ln)?,
            "LOG10" => one(f64::log10)?,
            "SQRT" => one(f64::sqrt)?,
            "SUM" | "AVG" | "MIN" | "MAX" | "STDDEV" => {
                let agg = |vals: &[f64]| aggregate(name, vals);
                match self.arg(id, args, 0, period)? {
                    Val::Scalar(v) => Val::Scalar(v),
                    Val::Series(ts) => {
                        let vals: Vec<f64> = ts.points.values().copied().collect();
                        match agg(&vals) {
                            Some(v) => Val::Scalar(v),
                            None => Val::Series(Ts { points: BTreeMap::new(), ..ts }),
                        }
                    }
                    Val::Array(arr) => Val::Series(pointwise(&arr, period, agg)),
                    Val::Str(_) => return Err(err(id, format!("{name} expects a time series"))),
                }
            }
            "METRIC_COUNT" => match self.arg(id, args, 0, period)? {
                Val::Array(a) => Val::Scalar(a.len() as f64),
                Val::Series(_) => Val::Scalar(1.0),
                _ => Val::Scalar(0.0),
            },
            "DATAPOINT_COUNT" => match self.arg(id, args, 0, period)? {
                Val::Series(ts) => Val::Scalar(ts.points.len() as f64),
                Val::Array(arr) => Val::Array(
                    arr.into_iter().map(|t| Ts { points: map_const(&t, t.points.len() as f64), ..t }).collect(),
                ),
                _ => return Err(err(id, "DATAPOINT_COUNT expects a time series")),
            },
            "METRICS" => {
                let filter = match args.first() {
                    Some(_) => match self.arg(id, args, 0, period)? {
                        Val::Str(s) => Some(s),
                        _ => return Err(err(id, "METRICS expects a string")),
                    },
                    None => None,
                };
                let mut out = Vec::new();
                for q in self.queries {
                    if q.id == id || q.metric_stat.is_none() {
                        continue;
                    }
                    if filter.as_ref().is_some_and(|f| !q.id.contains(f.as_str())) {
                        continue;
                    }
                    if let Val::Series(mut ts) = self.eval(&q.id)? {
                        ts.label = q.label.clone().unwrap_or(ts.label);
                        out.push(ts);
                    }
                }
                Val::Array(out)
            }
            "FILL" => {
                let v = self.arg(id, args, 0, period)?;
                let how = self.arg(id, args, 1, period)?;
                each_series(v, |ts| fill(self, ts, &how))?
            }
            "RATE" | "DIFF" | "DIFF_TIME" | "RUNNING_SUM" => {
                let v = self.arg(id, args, 0, period)?;
                each_series(v, |ts| Ok(sequential(name, ts)))?
            }
            "PERIOD" | "EPOCH" | "MINUTE" | "HOUR" | "DAY" | "DATE" | "MONTH" | "YEAR" => {
                let v = self.arg(id, args, 0, period)?;
                each_series(v, |ts| {
                    let points = ts
                        .points
                        .keys()
                        .map(|t| {
                            let d = DateTime::from_timestamp(*t, 0).unwrap_or_default();
                            let v = match name {
                                "PERIOD" => ts.period as f64,
                                "EPOCH" => *t as f64,
                                "MINUTE" => d.minute() as f64,
                                "HOUR" => d.hour() as f64,
                                "DAY" => d.weekday().number_from_monday() as f64,
                                "DATE" => d.day() as f64,
                                "MONTH" => d.month() as f64,
                                _ => d.year() as f64,
                            };
                            (*t, v)
                        })
                        .collect();
                    Ok(Ts { points, ..ts })
                })?
            }
            "TIME_SERIES" => match self.arg(id, args, 0, period)? {
                Val::Scalar(v) => Val::Series(Ts {
                    period,
                    points: self.grid(period).into_iter().map(|t| (t, v)).collect(),
                    ..Ts::default()
                }),
                other => other,
            },
            "IF" => {
                let c = self.arg(id, args, 0, period)?;
                let a = self.arg(id, args, 1, period)?;
                let b = if args.len() > 2 { Some(self.arg(id, args, 2, period)?) } else { None };
                if_(id, c, a, b, &self.grid(period))?
            }
            "REMOVE_EMPTY" => match self.arg(id, args, 0, period)? {
                Val::Array(a) => Val::Array(a.into_iter().filter(|t| !t.points.is_empty()).collect()),
                other => other,
            },
            "FIRST" | "LAST" => match self.arg(id, args, 0, period)? {
                Val::Array(a) => {
                    let pick = if name == "FIRST" { a.into_iter().next() } else { a.into_iter().last() };
                    Val::Series(pick.unwrap_or_default())
                }
                other => other,
            },
            "SORT" => {
                let Val::Array(mut a) = self.arg(id, args, 0, period)? else {
                    return Err(err(id, "SORT expects an array of time series"));
                };
                let by = match self.arg(id, args, 1, period)? {
                    Val::Str(s) => s.to_ascii_uppercase(),
                    _ => return Err(err(id, "SORT expects SUM, AVG, MIN or MAX")),
                };
                let desc = match args.get(2) {
                    Some(_) => match self.arg(id, args, 2, period)? {
                        Val::Str(s) => s.eq_ignore_ascii_case("DESC"),
                        _ => return Err(err(id, "SORT expects ASC or DESC")),
                    },
                    None => false,
                };
                let key = |t: &Ts| aggregate(&by, &t.points.values().copied().collect::<Vec<_>>()).unwrap_or(f64::NAN);
                a.sort_by(|x, y| key(x).total_cmp(&key(y)));
                if desc {
                    a.reverse();
                }
                if args.len() > 3 {
                    if let Val::Scalar(n) = self.arg(id, args, 3, period)? {
                        a.truncate(n.max(0.0) as usize);
                    }
                }
                Val::Array(a)
            }
            "SLICE" => {
                let Val::Array(a) = self.arg(id, args, 0, period)? else {
                    return Err(err(id, "SLICE expects an array of time series"));
                };
                let (Val::Scalar(s), Val::Scalar(e)) = (self.arg(id, args, 1, period)?, self.arg(id, args, 2, period)?)
                else {
                    return Err(err(id, "SLICE expects numeric bounds"));
                };
                let s = (s.max(0.0) as usize).min(a.len());
                let e = (e.max(0.0) as usize).clamp(s, a.len());
                Val::Array(a[s..e].to_vec())
            }
            "SEARCH" => {
                let (Val::Str(q), Val::Str(stat)) = (self.arg(id, args, 0, period)?, self.arg(id, args, 1, period)?)
                else {
                    return Err(err(id, "SEARCH expects a search string and a statistic"));
                };
                let p = match args.get(2) {
                    Some(_) => match self.arg(id, args, 2, period)? {
                        Val::Scalar(p) => p as i64,
                        _ => period,
                    },
                    None => period,
                };
                if !valid_period(p) {
                    return Err(err(id, "The period of a SEARCH must be 1, 5, 10, 20, 30 or a multiple of 60"));
                }
                let filter = crate::search::parse(&q).map_err(|m| err(id, m))?;
                let mut out = Vec::new();
                if let Some(r) = self.region {
                    for s in r.metrics.values() {
                        if s.samples.last().is_none_or(|x| x.t < self.start - Duration::days(14)) {
                            continue;
                        }
                        if filter.matches(&s.key) {
                            let mut ts = self.metric_series(&s.key, &stat, p, None);
                            ts.label = search_label(&s.key, &filter);
                            out.push(ts);
                        }
                    }
                }
                Val::Array(out)
            }
            "ANOMALY_DETECTION_BAND" => {
                let v = self.arg(id, args, 0, period)?;
                let k = match args.get(1) {
                    Some(_) => match self.arg(id, args, 1, period)? {
                        Val::Scalar(k) => k,
                        _ => 2.0,
                    },
                    None => 2.0,
                };
                let Val::Series(ts) = v else { return Err(err(id, "ANOMALY_DETECTION_BAND expects one time series")) };
                let (lower, upper) = band(&ts, k);
                Val::Array(vec![lower, upper])
            }
            "INSIGHT_RULE_METRIC" => {
                let (Val::Str(rule), Val::Str(metric)) =
                    (self.arg(id, args, 0, period)?, self.arg(id, args, 1, period)?)
                else {
                    return Err(err(id, "INSIGHT_RULE_METRIC expects a rule name and a metric name"));
                };
                let points = crate::insights::rule_metric(self, &rule, &metric, period);
                Val::Series(Ts { label: format!("{rule} {metric}"), period, points, metric: None })
            }
            "SERVICE_QUOTA" => return Err(err(id, "SERVICE_QUOTA is not supported for this metric")),
            other => return Err(err(id, format!("Unknown function {other}"))),
        })
    }
}

fn aggregate(name: &str, vals: &[f64]) -> Option<f64> {
    if vals.is_empty() {
        return None;
    }
    let n = vals.len() as f64;
    Some(match name {
        "SUM" => vals.iter().sum(),
        "AVG" => vals.iter().sum::<f64>() / n,
        "MIN" => vals.iter().copied().fold(f64::INFINITY, f64::min),
        "MAX" => vals.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        _ => {
            let mean = vals.iter().sum::<f64>() / n;
            (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n).sqrt()
        }
    })
}

fn map_const(ts: &Ts, v: f64) -> BTreeMap<i64, f64> {
    ts.points.keys().map(|t| (*t, v)).collect()
}

fn pointwise(arr: &[Ts], period: i64, f: impl Fn(&[f64]) -> Option<f64>) -> Ts {
    let mut by_t: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    for t in arr {
        for (k, v) in &t.points {
            by_t.entry(*k).or_default().push(*v);
        }
    }
    let period = arr.first().map(|t| t.period).unwrap_or(period);
    Ts { period, points: by_t.into_iter().filter_map(|(k, v)| f(&v).map(|r| (k, r))).collect(), ..Ts::default() }
}

fn unary(v: Val, f: impl Fn(f64) -> Option<f64>) -> Val {
    let map = |ts: Ts| Ts { points: ts.points.iter().filter_map(|(k, v)| f(*v).map(|r| (*k, r))).collect(), ..ts };
    match v {
        Val::Scalar(x) => f(x).map(Val::Scalar).unwrap_or(Val::Scalar(f64::NAN)),
        Val::Series(ts) => Val::Series(map(ts)),
        Val::Array(a) => Val::Array(a.into_iter().map(map).collect()),
        s => s,
    }
}

fn op(op: &str, a: f64, b: f64) -> Option<f64> {
    let t = |c: bool| if c { 1.0 } else { 0.0 };
    let r = match op {
        "+" => a + b,
        "-" => a - b,
        "*" => a * b,
        "/" => {
            if b == 0.0 {
                return None;
            }
            a / b
        }
        "^" => a.powf(b),
        ">" => t(a > b),
        "<" => t(a < b),
        ">=" => t(a >= b),
        "<=" => t(a <= b),
        "==" => t(a == b),
        "!=" => t(a != b),
        "&&" => t(a != 0.0 && b != 0.0),
        "||" => t(a != 0.0 || b != 0.0),
        _ => return None,
    };
    r.is_finite().then_some(r)
}

fn series_op(o: &str, a: &Ts, b: &Ts) -> Ts {
    let points =
        a.points.iter().filter_map(|(k, x)| b.points.get(k).and_then(|y| op(o, *x, *y)).map(|r| (*k, r))).collect();
    Ts { label: String::new(), period: a.period, points, metric: None }
}

fn binary(id: &str, o: &'static str, a: Val, b: Val) -> Result<Val, ServiceError> {
    let scal = |ts: &Ts, s: f64, left: bool| Ts {
        points: ts
            .points
            .iter()
            .filter_map(|(k, v)| (if left { op(o, *v, s) } else { op(o, s, *v) }).map(|r| (*k, r)))
            .collect(),
        label: String::new(),
        period: ts.period,
        metric: None,
    };
    Ok(match (a, b) {
        (Val::Scalar(x), Val::Scalar(y)) => Val::Scalar(op(o, x, y).unwrap_or(f64::NAN)),
        (Val::Series(t), Val::Scalar(s)) => Val::Series(scal(&t, s, true)),
        (Val::Scalar(s), Val::Series(t)) => Val::Series(scal(&t, s, false)),
        (Val::Series(x), Val::Series(y)) => Val::Series(series_op(o, &x, &y)),
        (Val::Array(a), Val::Scalar(s)) => {
            Val::Array(a.iter().map(|t| Ts { label: t.label.clone(), ..scal(t, s, true) }).collect())
        }
        (Val::Scalar(s), Val::Array(a)) => {
            Val::Array(a.iter().map(|t| Ts { label: t.label.clone(), ..scal(t, s, false) }).collect())
        }
        (Val::Array(a), Val::Series(y)) => {
            Val::Array(a.iter().map(|t| Ts { label: t.label.clone(), ..series_op(o, t, &y) }).collect())
        }
        (Val::Series(x), Val::Array(a)) => {
            Val::Array(a.iter().map(|t| Ts { label: t.label.clone(), ..series_op(o, &x, t) }).collect())
        }
        (Val::Array(_), Val::Array(_)) => {
            return Err(err(id, "Operations between two arrays of time series are not supported"));
        }
        _ => return Err(err(id, format!("Operator {o} cannot be applied to a string"))),
    })
}

fn each_series(v: Val, mut f: impl FnMut(Ts) -> Result<Ts, ServiceError>) -> Result<Val, ServiceError> {
    Ok(match v {
        Val::Series(ts) => Val::Series(f(ts)?),
        Val::Array(a) => Val::Array(a.into_iter().map(f).collect::<Result<_, _>>()?),
        other => other,
    })
}

fn fill(e: &Engine<'_>, ts: Ts, how: &Val) -> Result<Ts, ServiceError> {
    let grid = e.grid(ts.period.max(1));
    let mut points = BTreeMap::new();
    match how {
        Val::Scalar(v) => {
            for t in &grid {
                points.insert(*t, ts.points.get(t).copied().unwrap_or(*v));
            }
        }
        Val::Str(s) if s.eq_ignore_ascii_case("REPEAT") => {
            let mut last = ts.points.values().next().copied();
            for t in &grid {
                if let Some(v) = ts.points.get(t) {
                    last = Some(*v);
                }
                if let Some(v) = last {
                    points.insert(*t, v);
                }
            }
        }
        Val::Str(s) if s.eq_ignore_ascii_case("LINEAR") => {
            for t in &grid {
                if let Some(v) = ts.points.get(t) {
                    points.insert(*t, *v);
                    continue;
                }
                let before = ts.points.range(..*t).next_back();
                let after = ts.points.range(*t..).next();
                if let (Some((t0, v0)), Some((t1, v1))) = (before, after) {
                    let f = (*t - t0) as f64 / (t1 - t0) as f64;
                    points.insert(*t, v0 + (v1 - v0) * f);
                }
            }
        }
        Val::Series(other) => {
            for t in &grid {
                if let Some(v) = ts.points.get(t).or_else(|| other.points.get(t)) {
                    points.insert(*t, *v);
                }
            }
        }
        _ => return Err(err("", "FILL expects a number, a time series, REPEAT or LINEAR")),
    }
    Ok(Ts { points, ..ts })
}

fn sequential(name: &str, ts: Ts) -> Ts {
    let mut points = BTreeMap::new();
    let mut prev: Option<(i64, f64)> = None;
    let mut running = 0.0;
    for (t, v) in &ts.points {
        match name {
            "RUNNING_SUM" => {
                running += v;
                points.insert(*t, running);
            }
            _ => {
                if let Some((pt, pv)) = prev {
                    let dt = (t - pt) as f64;
                    let r = match name {
                        "RATE" => (v - pv) / dt,
                        "DIFF" => v - pv,
                        _ => dt,
                    };
                    points.insert(*t, r);
                }
            }
        }
        prev = Some((*t, *v));
    }
    Ts { points, ..ts }
}

fn if_(id: &str, c: Val, a: Val, b: Option<Val>, grid: &[i64]) -> Result<Val, ServiceError> {
    let at = |v: &Val, t: i64| -> Option<f64> {
        match v {
            Val::Scalar(s) => Some(*s),
            Val::Series(ts) => ts.points.get(&t).copied(),
            _ => None,
        }
    };
    let cond = match &c {
        Val::Series(ts) => ts.clone(),
        Val::Scalar(s) => Ts { points: grid.iter().map(|t| (*t, *s)).collect(), ..Ts::default() },
        _ => return Err(err(id, "IF expects a condition time series")),
    };
    if matches!(a, Val::Array(_)) || matches!(b, Some(Val::Array(_))) {
        return Err(err(id, "IF does not accept arrays"));
    }
    let points = cond
        .points
        .iter()
        .filter_map(|(t, cv)| {
            let v = if *cv != 0.0 { at(&a, *t) } else { b.as_ref().and_then(|b| at(b, *t)) };
            v.map(|v| (*t, v))
        })
        .collect();
    Ok(Val::Series(Ts { points, period: cond.period, label: String::new(), metric: None }))
}

fn band(ts: &Ts, k: f64) -> (Ts, Ts) {
    let vals: Vec<f64> = ts.points.values().copied().collect();
    let mean = aggregate("AVG", &vals).unwrap_or(0.0);
    let sd = aggregate("STDDEV", &vals).unwrap_or(0.0);
    let mk = |off: f64, suffix: &str| Ts {
        label: format!("{} ({suffix})", ts.label),
        period: ts.period,
        points: ts.points.keys().map(|t| (*t, mean + off)).collect(),
        metric: None,
    };
    (mk(-k * sd, "lower"), mk(k * sd, "upper"))
}

fn search_label(key: &MetricKey, _f: &crate::search::Filter) -> String {
    let dims: Vec<&str> = key.dimensions.iter().map(|(_, v)| v.as_str()).collect();
    if dims.is_empty() {
        key.name.clone()
    } else {
        format!("{} {}", dims.join(" "), key.name)
    }
}

// ---- labels -------------------------------------------------------------------

/// Expand `${...}` placeholders in a label.
fn expand_label(label: &str, ts: &Ts, stat: Option<&str>) -> String {
    let mut out = String::new();
    let mut rest = label;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let token = &rest[i + 2..i + j];
        out.push_str(&placeholder(token, ts, stat).unwrap_or_else(|| format!("${{{token}}}")));
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    out
}

fn placeholder(token: &str, ts: &Ts, stat: Option<&str>) -> Option<String> {
    let vals: Vec<f64> = ts.points.values().copied().collect();
    let num = |v: Option<f64>| v.map(|v| format!("{v}")).unwrap_or_default();
    Some(match token {
        "LABEL" => ts.label.clone(),
        "SUM" | "AVG" | "MIN" | "MAX" => num(aggregate(token, &vals)),
        "FIRST" => num(vals.first().copied()),
        "LAST" => num(vals.last().copied()),
        "DATAPOINT_COUNT" => vals.len().to_string(),
        _ => {
            let prop = token.strip_prefix("PROP(")?.strip_suffix(')')?.trim_matches(|c| c == '\'' || c == '"');
            let (key, s) = ts.metric.as_ref()?;
            match prop {
                "MetricName" => key.name.clone(),
                "Namespace" => key.namespace.clone(),
                "Period" => ts.period.to_string(),
                "Stat" => stat.map(str::to_string).unwrap_or_else(|| s.clone()),
                p => {
                    let dim = p.strip_prefix("Dim.")?;
                    key.dimensions.iter().find(|(n, _)| n == dim).map(|(_, v)| v.clone())?
                }
            }
        }
    })
}

// ---- the operation ------------------------------------------------------------

const MAX_QUERIES: usize = 500;

fn valid_id(id: &str) -> bool {
    let mut c = id.chars();
    c.next().is_some_and(|f| f.is_ascii_lowercase()) && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// Validate a set of metric data queries (`GetMetricData`, alarms,
/// anomaly detectors).
pub fn validate_queries(queries: &[types::MetricDataQuery], field: &str) -> Result<(), ServiceError> {
    if queries.len() > MAX_QUERIES {
        return Err(errors::validation(format!(
            "The collection {field} must not have a size greater than {MAX_QUERIES}."
        )));
    }
    let mut seen = BTreeSet::new();
    for (i, q) in queries.iter().enumerate() {
        let at = format!("{field}.member.{}", i + 1);
        if !valid_id(&q.id) {
            return Err(errors::validation(format!(
                "Invalid metric data query id '{}' at {at}.Id. The id must start with a lowercase letter and contain only letters, numbers and underscores.",
                q.id
            )));
        }
        if !seen.insert(q.id.clone()) {
            return Err(errors::validation(format!("The value {} for parameter {at}.Id is not unique.", q.id)));
        }
        match (&q.metric_stat, &q.expression) {
            (Some(_), Some(_)) => {
                return Err(errors::validation(format!(
                    "The parameters {at}.MetricStat and {at}.Expression are mutually exclusive and you have specified both."
                )))
            }
            (None, None) => {
                return Err(errors::validation(format!(
                    "One of the parameters {at}.MetricStat or {at}.Expression must be specified."
                )))
            }
            (Some(ms), None) => {
                if !valid_period(ms.period as i64) {
                    return Err(errors::validation(format!(
                        "The value {} for parameter {at}.MetricStat.Period is not valid. The period must be 1, 5, 10, 20, 30, 60 or any multiple of 60.",
                        ms.period
                    )));
                }
                if crate::stats::Stat::parse(&ms.stat).is_none() {
                    return Err(errors::validation(format!(
                        "The value {} for parameter {at}.MetricStat.Stat is not a valid statistic.",
                        ms.stat
                    )));
                }
                if ms.metric.metric_name.is_none() || ms.metric.namespace.is_none() {
                    return Err(errors::validation(format!(
                        "The parameters {at}.MetricStat.Metric.Namespace and {at}.MetricStat.Metric.MetricName are required."
                    )));
                }
            }
            (None, Some(e)) => {
                let parsed = parse(e).map_err(|m| err(&q.id, m))?;
                let mut refs = BTreeSet::new();
                references(&parsed, &mut refs);
                for r in refs {
                    let is_symbol = r.chars().next().is_some_and(|c| c.is_ascii_uppercase());
                    if !is_symbol && !queries.iter().any(|x| x.id == r) {
                        return Err(err(&q.id, format!("Unrecognized id '{r}'")));
                    }
                }
            }
        }
    }
    Ok(())
}

/// The series each returned query produced, as `(id, label, points)`.
/// One returned series: id, label and points.
pub type SeriesResult = (String, String, BTreeMap<i64, f64>);

pub fn results(engine: &Engine<'_>) -> Result<Vec<SeriesResult>, ServiceError> {
    let mut out = Vec::new();
    for q in engine.queries {
        let v = engine.eval(&q.id)?;
        if q.return_data == Some(false) {
            continue;
        }
        let stat = q.metric_stat.as_ref().map(|m| m.stat.as_str());
        let label_for = |ts: &Ts| -> String {
            match &q.label {
                Some(l) => expand_label(l, ts, stat),
                None if !ts.label.is_empty() => ts.label.clone(),
                None => q.id.clone(),
            }
        };
        match v {
            Val::Series(ts) => out.push((q.id.clone(), label_for(&ts), ts.points)),
            Val::Array(a) => {
                for ts in a {
                    let label = match &q.label {
                        Some(l) => format!("{} {}", expand_label(l, &ts, stat), ts.label).trim().to_string(),
                        None => ts.label.clone(),
                    };
                    out.push((q.id.clone(), label, ts.points));
                }
            }
            Val::Scalar(s) => {
                let period = q.period.map(i64::from).unwrap_or_else(|| engine.default_period());
                let points = engine.grid(period).into_iter().map(|t| (t, s)).collect();
                out.push((q.id.clone(), q.label.clone().unwrap_or_else(|| q.id.clone()), points));
            }
            Val::Str(_) => {}
        }
    }
    Ok(out)
}

impl CloudWatch {
    pub(crate) fn get_metric_data(
        &self,
        ctx: &RequestContext,
        input: types::GetMetricDataInput,
    ) -> Result<types::GetMetricDataOutput, ServiceError> {
        ctx.authorize("cloudwatch:GetMetricData", &names::any(ctx), ConditionContext::new())?;
        self.observe(ctx);
        let now = now(ctx);
        validate_queries(&input.metric_data_queries, "MetricDataQueries")?;
        if !input.metric_data_queries.iter().any(|q| q.return_data != Some(false)) {
            return Err(errors::validation("At least one MetricDataQuery must have ReturnData set to true."));
        }
        if input.start_time >= input.end_time {
            return Err(errors::validation("The parameter StartTime must be less than the parameter EndTime."));
        }
        let st = self.lock();
        let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
        let start = crate::metrics::round_start(input.start_time, now, 60);
        let mut engine = Engine::new(region, &input.metric_data_queries, start, input.end_time).with_logs(
            self.inner.logs.get(),
            &ctx.caller.account_id,
            &ctx.region,
        );
        engine.retained = crate::metrics::retained_resolution(start, now);
        let series = results(&engine)?;
        drop(st);
        let ascending = input.scan_by.as_deref() == Some("TimestampAscending");
        // Page through the datapoints of all results in order.
        let offset = match input.next_token.as_deref() {
            None => 0,
            Some(t) => decode_offset(t)
                .ok_or_else(|| errors::invalid_next_token("The service returned an invalid next token."))?,
        };
        let max = input.max_datapoints.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(100_800);
        let mut seen = 0usize;
        let mut taken = 0usize;
        let mut out = Vec::new();
        let mut next = None;
        for (id, label, points) in series {
            let mut pts: Vec<(i64, f64)> = points.into_iter().collect();
            if !ascending {
                pts.reverse();
            }
            let mut timestamps = Vec::new();
            let mut values = Vec::new();
            for (t, v) in pts {
                if seen < offset {
                    seen += 1;
                    continue;
                }
                if taken >= max {
                    next = Some(encode_offset(seen));
                    break;
                }
                timestamps.push(DateTime::from_timestamp(t, 0).unwrap_or_default());
                values.push(v);
                seen += 1;
                taken += 1;
            }
            let partial = next.is_some();
            out.push(types::MetricDataResult {
                id: Some(id),
                label: Some(label),
                timestamps: Some(timestamps),
                values: Some(values),
                status_code: Some(if partial { "PartialData" } else { "Complete" }.into()),
                messages: Some(Vec::new()),
            });
            if partial {
                break;
            }
        }
        Ok(types::GetMetricDataOutput { metric_data_results: Some(out), next_token: next, messages: Some(Vec::new()) })
    }
}

fn encode_offset(n: usize) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("mws-cloudwatch-gmd:{n}"))
}

fn decode_offset(t: &str) -> Option<usize> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(t).ok()?;
    String::from_utf8(raw).ok()?.strip_prefix("mws-cloudwatch-gmd:")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_precedence() {
        let e = parse("m1 + m2 * 2 ^ 2 > 10 AND NOT m3").unwrap();
        assert!(matches!(e, Expr::Bin("&&", _, _)));
        assert!(parse("SUM(METRICS())").is_ok());
        assert!(parse("FILL(m1, REPEAT)").is_ok());
        assert!(parse("SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', 300)").is_ok());
        assert!(parse("m1 +").is_err());
        assert!(parse("(m1").is_err());
    }

    #[test]
    fn sequential_functions() {
        let ts = Ts { period: 60, points: [(0, 1.0), (60, 4.0), (120, 10.0)].into_iter().collect(), ..Ts::default() };
        let rate = sequential("RATE", ts.clone());
        assert_eq!(rate.points.get(&60), Some(&0.05));
        let diff = sequential("DIFF", ts.clone());
        assert_eq!(diff.points.get(&120), Some(&6.0));
        let rs = sequential("RUNNING_SUM", ts);
        assert_eq!(rs.points.get(&120), Some(&15.0));
    }
}
