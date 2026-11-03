//! CloudWatch Logs Insights query language: parsing and execution over a
//! set of records.
//!
//! Supported commands: `fields`, `display`, `filter`, `parse` (glob and
//! regex with named groups), `stats` (with `by`, several in sequence),
//! `sort`, `limit`, `dedup` and `unmask`. Expressions cover arithmetic,
//! comparisons, `like`/`not like` (strings and `/regex/`), `=~`, `in`,
//! `and`/`or`/`not`, and the common functions (string, numeric, datetime,
//! `ispresent`, `coalesce`, `bin`, ...). Aggregations: `count`,
//! `count_distinct`, `sum`, `avg`, `min`, `max`, `earliest`, `latest`,
//! `pct`, `stddev`, `sortsFirst`, `sortsLast`.
//!
//! Spec: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html>

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use regex::Regex;

/// A field value.
#[derive(Debug, Clone, PartialEq)]
pub enum V {
    Null,
    Num(f64),
    Str(String),
    Bool(bool),
    /// Epoch milliseconds, displayed as `YYYY-MM-DD HH:MM:SS.mmm`.
    Time(i64),
}

impl V {
    pub fn display(&self) -> Option<String> {
        match self {
            V::Null => None,
            V::Num(n) => Some(fmt_num(*n)),
            V::Str(s) => Some(s.clone()),
            V::Bool(b) => Some(b.to_string()),
            V::Time(t) => Some(fmt_time(*t)),
        }
    }

    fn num(&self) -> Option<f64> {
        match self {
            V::Num(n) => Some(*n),
            V::Time(t) => Some(*t as f64),
            V::Str(s) => s.trim().parse().ok(),
            V::Bool(b) => Some(f64::from(u8::from(*b))),
            V::Null => None,
        }
    }

    fn text(&self) -> String {
        self.display().unwrap_or_default()
    }

    fn truthy(&self) -> bool {
        match self {
            V::Null => false,
            V::Bool(b) => *b,
            V::Num(n) => *n != 0.0,
            V::Str(s) => !s.is_empty(),
            V::Time(_) => true,
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, V::Null)
    }
}

pub fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        let s = format!("{n:.4}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

pub fn fmt_time(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_default()
}

pub type Record = BTreeMap<String, V>;

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(V),
    Field(String),
    Regex(Regex),
    Duration(i64),
    Unary(char, Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    In(Box<Expr>, Vec<Expr>, bool),
    Like(Box<Expr>, Box<Expr>, bool),
    Call(String, Vec<Expr>),
    Star,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone)]
pub struct Named {
    pub expr: Expr,
    pub name: String,
}

#[derive(Debug, Clone)]
pub enum Command {
    Fields(Vec<Named>),
    Display(Vec<String>),
    Filter(Expr),
    ParseGlob { field: Expr, pattern: Regex, names: Vec<String> },
    ParseRegex { field: Expr, pattern: Regex },
    Stats { aggs: Vec<Named>, by: Vec<Named> },
    Sort(Vec<(Expr, bool)>),
    Limit(usize),
    Dedup(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Query {
    pub commands: Vec<Command>,
}

const AGGREGATES: &[&str] = &[
    "count",
    "count_distinct",
    "sum",
    "avg",
    "min",
    "max",
    "earliest",
    "latest",
    "pct",
    "stddev",
    "sortsfirst",
    "sortslast",
];

// ---- tokenizer ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(f64),
    Str(String),
    Regex(String),
    Duration(i64),
    Op(String),
    Comma,
    LParen,
    RParen,
    LBracket,
    RBracket,
}

fn duration_ms(n: f64, unit: &str) -> Option<i64> {
    let ms = match unit {
        "ms" => 1.0,
        "s" | "sec" | "second" | "seconds" => 1000.0,
        "m" | "min" | "minute" | "minutes" => 60_000.0,
        "h" | "hr" | "hour" | "hours" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "week" | "weeks" => 604_800_000.0,
        "mo" | "month" | "months" => 2_592_000_000.0,
        "q" | "quarter" | "quarters" => 7_776_000_000.0,
        "y" | "year" | "years" => 31_536_000_000.0,
        _ => return None,
    };
    Some((n * ms) as i64)
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    // A `/` starts a regex where an operand is expected.
    let operand_expected = |out: &Vec<Tok>| {
        matches!(out.last(), None | Some(Tok::Op(_)) | Some(Tok::Comma) | Some(Tok::LParen) | Some(Tok::LBracket))
            || matches!(out.last(), Some(Tok::Ident(w)) if ["like", "as", "by"].contains(&w.to_lowercase().as_str()))
            // `parse <field> /regex/`
            || (out.len() == 2 && matches!(&out[0], Tok::Ident(w) if w.eq_ignore_ascii_case("parse")))
    };
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if ch == '#' {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            let q = ch;
            let mut t = String::new();
            i += 1;
            while i < c.len() && c[i] != q {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                    t.push(match c[i] {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    t.push(c[i]);
                }
                i += 1;
            }
            if i >= c.len() {
                return Err("unterminated string literal".into());
            }
            i += 1;
            out.push(Tok::Str(t));
            continue;
        }
        if ch == '/' && operand_expected(&out) {
            let mut t = String::new();
            i += 1;
            while i < c.len() && c[i] != '/' {
                if c[i] == '\\' && i + 1 < c.len() && c[i + 1] == '/' {
                    i += 1;
                }
                t.push(c[i]);
                i += 1;
            }
            if i >= c.len() {
                return Err("unterminated regular expression".into());
            }
            i += 1;
            // Flags such as `/abc/i`.
            if i < c.len() && c[i] == 'i' {
                t = format!("(?i){t}");
                i += 1;
            }
            out.push(Tok::Regex(t));
            continue;
        }
        if ch == '`' {
            let end = c[i + 1..].iter().position(|x| *x == '`').ok_or("unterminated backtick")? + i + 1;
            out.push(Tok::Ident(c[i + 1..end].iter().collect()));
            i = end + 1;
            continue;
        }
        if ch.is_ascii_digit() || (ch == '.' && c.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let start = i;
            while i < c.len()
                && (c[i].is_ascii_digit()
                    || c[i] == '.'
                    || c[i] == 'e' && c.get(i + 1).is_some_and(|d| d.is_ascii_digit() || *d == '-'))
            {
                if c[i] == 'e' {
                    i += 1;
                }
                i += 1;
            }
            let n: f64 = c[start..i].iter().collect::<String>().parse().map_err(|_| "invalid number")?;
            let ustart = i;
            while i < c.len() && c[i].is_ascii_alphabetic() {
                i += 1;
            }
            if ustart < i {
                let unit: String = c[ustart..i].iter().collect();
                out.push(Tok::Duration(duration_ms(n, &unit).ok_or(format!("unknown time unit '{unit}'"))?));
            } else {
                out.push(Tok::Num(n));
            }
            continue;
        }
        if ch.is_alphanumeric() || ch == '@' || ch == '_' || ch == '$' {
            let start = i;
            while i < c.len() && (c[i].is_alphanumeric() || "@_.$-".contains(c[i])) {
                // A `-` only continues a name when followed by a letter.
                if c[i] == '-' && !c.get(i + 1).is_some_and(|x| x.is_alphabetic()) {
                    break;
                }
                i += 1;
            }
            out.push(Tok::Ident(c[start..i].iter().collect()));
            continue;
        }
        let two: String = c[i..(i + 2).min(c.len())].iter().collect();
        if ["!=", "<=", ">=", "=~", "==", "&&", "||"].contains(&two.as_str()) {
            out.push(Tok::Op(two));
            i += 2;
            continue;
        }
        match ch {
            ',' => out.push(Tok::Comma),
            '(' => out.push(Tok::LParen),
            ')' => out.push(Tok::RParen),
            '[' => out.push(Tok::LBracket),
            ']' => out.push(Tok::RBracket),
            '=' | '<' | '>' | '+' | '-' | '*' | '/' | '%' | '^' | '!' => out.push(Tok::Op(ch.to_string())),
            other => return Err(format!("unexpected symbol found {other}")),
        }
        i += 1;
    }
    Ok(out)
}

/// Split a query into commands on `|` outside strings and regexes.
fn split_commands(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut in_regex = false;
    let mut prev_sig = ' ';
    for ch in q.chars() {
        match quote {
            Some(qc) => {
                if ch == qc {
                    quote = None;
                }
            }
            None if in_regex => {
                if ch == '/' {
                    in_regex = false;
                }
            }
            None => match ch {
                '"' | '\'' | '`' => quote = Some(ch),
                '/' if matches!(prev_sig, ' ' | ',' | '(' | '=' | '~' | 'e') => in_regex = true,
                '|' => {
                    out.push(std::mem::take(&mut cur));
                    prev_sig = ' ';
                    continue;
                }
                _ => {}
            },
        }
        cur.push(ch);
        if !ch.is_whitespace() {
            prev_sig = ch;
        } else if quote.is_none() && !in_regex {
            prev_sig = ' ';
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

// ---- parser ----------------------------------------------------------------------

struct P {
    toks: Vec<Tok>,
    pos: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn at_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(w)) if w.eq_ignore_ascii_case(kw))
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.at_kw(kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn at_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(o)) if o == op)
    }

    fn done(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.eat_kw("or") || self.at_op("||") && self.next().is_some() {
            let r = self.and()?;
            l = Expr::Bin(BinOp::Or, Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.not()?;
        while self.eat_kw("and") || self.at_op("&&") && self.next().is_some() {
            let r = self.not()?;
            l = Expr::Bin(BinOp::And, Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.eat_kw("not") || self.at_op("!") && self.next().is_some() {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let l = self.add()?;
        let negated = if self.at_kw("not")
            && matches!(self.toks.get(self.pos + 1), Some(Tok::Ident(w)) if w.eq_ignore_ascii_case("like") || w.eq_ignore_ascii_case("in"))
        {
            self.pos += 1;
            true
        } else {
            false
        };
        if self.eat_kw("like") {
            let r = self.add()?;
            return Ok(Expr::Like(Box::new(l), Box::new(r), negated));
        }
        if self.eat_kw("in") {
            if self.next() != Some(Tok::LBracket) {
                return Err("expected '[' after in".into());
            }
            let mut items = Vec::new();
            while self.peek() != Some(&Tok::RBracket) {
                items.push(self.add()?);
                if self.peek() == Some(&Tok::Comma) {
                    self.pos += 1;
                }
                if self.done() {
                    return Err("expected ']'".into());
                }
            }
            self.pos += 1;
            return Ok(Expr::In(Box::new(l), items, negated));
        }
        let op = match self.peek() {
            Some(Tok::Op(o)) => match o.as_str() {
                "=" | "==" => Some(BinOp::Eq),
                "!=" => Some(BinOp::Ne),
                "<" => Some(BinOp::Lt),
                "<=" => Some(BinOp::Le),
                ">" => Some(BinOp::Gt),
                ">=" => Some(BinOp::Ge),
                "=~" => {
                    self.pos += 1;
                    let r = self.add()?;
                    return Ok(Expr::Like(Box::new(l), Box::new(r), false));
                }
                _ => None,
            },
            _ => None,
        };
        match op {
            Some(op) => {
                self.pos += 1;
                let r = self.add()?;
                Ok(Expr::Bin(op, Box::new(l), Box::new(r)))
            }
            None => Ok(l),
        }
    }

    fn add(&mut self) -> Result<Expr, String> {
        let mut l = self.mul()?;
        loop {
            let op = if self.at_op("+") {
                BinOp::Add
            } else if self.at_op("-") {
                BinOp::Sub
            } else {
                break;
            };
            self.pos += 1;
            let r = self.mul()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn mul(&mut self) -> Result<Expr, String> {
        let mut l = self.unary()?;
        loop {
            let op = if self.at_op("*") {
                BinOp::Mul
            } else if self.at_op("/") {
                BinOp::Div
            } else if self.at_op("%") {
                BinOp::Mod
            } else if self.at_op("^") {
                BinOp::Pow
            } else {
                break;
            };
            self.pos += 1;
            let r = self.unary()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.at_op("-") {
            self.pos += 1;
            return Ok(Expr::Unary('-', Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(Expr::Lit(V::Num(n))),
            Some(Tok::Str(s)) => Ok(Expr::Lit(V::Str(s))),
            Some(Tok::Regex(r)) => Regex::new(&r).map(Expr::Regex).map_err(|e| format!("invalid regex: {e}")),
            Some(Tok::Duration(d)) => Ok(Expr::Duration(d)),
            Some(Tok::Op(o)) if o == "*" => Ok(Expr::Star),
            Some(Tok::LParen) => {
                let e = self.expr()?;
                if self.next() != Some(Tok::RParen) {
                    return Err("expected ')'".into());
                }
                Ok(e)
            }
            Some(Tok::Ident(name)) => {
                if self.peek() == Some(&Tok::LParen) {
                    self.pos += 1;
                    let mut args = Vec::new();
                    while self.peek() != Some(&Tok::RParen) {
                        args.push(self.expr()?);
                        if self.peek() == Some(&Tok::Comma) {
                            self.pos += 1;
                        } else if self.peek() != Some(&Tok::RParen) {
                            return Err(format!("expected ',' or ')' in call to {name}"));
                        }
                    }
                    self.pos += 1;
                    return Ok(Expr::Call(name.to_lowercase(), args));
                }
                match name.to_lowercase().as_str() {
                    "true" => Ok(Expr::Lit(V::Bool(true))),
                    "false" => Ok(Expr::Lit(V::Bool(false))),
                    _ => Ok(Expr::Field(name)),
                }
            }
            other => Err(format!("unexpected symbol found {}", describe(other.as_ref()))),
        }
    }

    /// `expr [as name]` items separated by commas, up to `stop` keyword.
    fn named_list(&mut self, stop: Option<&str>) -> Result<Vec<Named>, String> {
        let mut out = Vec::new();
        loop {
            let start = self.pos;
            let expr = self.expr()?;
            let name = if self.eat_kw("as") {
                match self.next() {
                    Some(Tok::Ident(n)) => n,
                    other => return Err(format!("expected a name after as, found {}", describe(other.as_ref()))),
                }
            } else {
                self.source_text(start)
            };
            out.push(Named { expr, name });
            if self.peek() == Some(&Tok::Comma) {
                self.pos += 1;
                continue;
            }
            if self.done() || stop.is_some_and(|s| self.at_kw(s)) {
                return Ok(out);
            }
            return Err(format!("unexpected symbol found {}", describe(self.peek())));
        }
    }

    /// The default column name for an unnamed expression: its text.
    fn source_text(&self, start: usize) -> String {
        let mut s = String::new();
        for t in &self.toks[start..self.pos] {
            let piece = match t {
                Tok::Ident(i) => i.clone(),
                Tok::Num(n) => fmt_num(*n),
                Tok::Str(x) => format!("\"{x}\""),
                Tok::Regex(r) => format!("/{r}/"),
                Tok::Duration(d) => format_duration(*d),
                Tok::Op(o) => o.clone(),
                Tok::Comma => ",".into(),
                Tok::LParen => "(".into(),
                Tok::RParen => ")".into(),
                Tok::LBracket => "[".into(),
                Tok::RBracket => "]".into(),
            };
            if !s.is_empty() && !matches!(t, Tok::LParen | Tok::RParen | Tok::Comma) && !s.ends_with('(') {
                s.push(' ');
            }
            s.push_str(&piece);
        }
        s
    }
}

fn format_duration(ms: i64) -> String {
    for (unit, n) in [("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000)] {
        if ms % n == 0 {
            return format!("{}{unit}", ms / n);
        }
    }
    format!("{ms}ms")
}

fn describe(t: Option<&Tok>) -> String {
    match t {
        None => "end of query".into(),
        Some(Tok::Ident(i)) => i.clone(),
        Some(Tok::Num(n)) => fmt_num(*n),
        Some(Tok::Str(s)) => format!("'{s}'"),
        Some(Tok::Op(o)) => o.clone(),
        Some(other) => format!("{other:?}"),
    }
}

fn glob_to_regex(pattern: &str) -> Result<(Regex, usize), String> {
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut re = parts.iter().map(|p| regex::escape(p)).collect::<Vec<_>>().join("(.*?)");
    // A trailing wildcard takes the rest of the text, not nothing.
    if parts.len() > 1 && parts.last() == Some(&"") {
        re.truncate(re.len() - "(.*?)".len());
        re.push_str("(.*)");
    }
    let re = Regex::new(&format!("(?s){re}")).map_err(|e| e.to_string())?;
    Ok((re, parts.len() - 1))
}

pub fn parse(query: &str) -> Result<Query, String> {
    let mut commands = Vec::new();
    for text in split_commands(query) {
        let toks = tokenize(&text)?;
        let mut p = P { toks, pos: 0 };
        let Some(Tok::Ident(cmd)) = p.next() else {
            return Err(format!("unexpected symbol found {}", text.split_whitespace().next().unwrap_or("")));
        };
        let c = match cmd.to_lowercase().as_str() {
            "fields" => Command::Fields(p.named_list(None)?),
            "display" => Command::Display(p.named_list(None)?.into_iter().map(|n| n.name).collect()),
            "filter" => {
                let e = p.expr()?;
                if !p.done() {
                    return Err(format!("unexpected symbol found {}", describe(p.peek())));
                }
                Command::Filter(e)
            }
            "parse" => {
                let field = p.unary()?;
                match p.next() {
                    Some(Tok::Str(glob)) => {
                        if !p.eat_kw("as") {
                            return Err("expected 'as' in parse".into());
                        }
                        let names = p.named_list(None)?.into_iter().map(|n| n.name).collect::<Vec<_>>();
                        let (pattern, n) = glob_to_regex(&glob)?;
                        if n != names.len() {
                            return Err(
                                "Number of fields in parse expression does not match number of wildcards".into()
                            );
                        }
                        Command::ParseGlob { field, pattern, names }
                    }
                    Some(Tok::Regex(r)) => Command::ParseRegex {
                        field,
                        pattern: Regex::new(&r).map_err(|e| format!("invalid regex: {e}"))?,
                    },
                    other => return Err(format!("unexpected symbol found {}", describe(other.as_ref()))),
                }
            }
            "stats" => {
                let aggs = p.named_list(Some("by"))?;
                let by = if p.eat_kw("by") { p.named_list(None)? } else { Vec::new() };
                for a in &aggs {
                    if !contains_aggregate(&a.expr) {
                        return Err(format!("stats requires an aggregate function, found {}", a.name));
                    }
                }
                Command::Stats { aggs, by }
            }
            "sort" => {
                let mut keys = Vec::new();
                loop {
                    let e = p.expr()?;
                    let desc = if p.eat_kw("desc") {
                        true
                    } else {
                        p.eat_kw("asc");
                        false
                    };
                    keys.push((e, desc));
                    if p.peek() == Some(&Tok::Comma) {
                        p.pos += 1;
                        continue;
                    }
                    break;
                }
                Command::Sort(keys)
            }
            "limit" => match p.next() {
                Some(Tok::Num(n)) if (1.0..=10_000.0).contains(&n) => Command::Limit(n as usize),
                _ => return Err("limit must be a number between 1 and 10000".into()),
            },
            "dedup" => Command::Dedup(p.named_list(None)?.into_iter().map(|n| n.name).collect()),
            "unmask" => continue,
            other => return Err(format!("unexpected symbol found {other}")),
        };
        if !p.done() {
            return Err(format!("unexpected symbol found {}", describe(p.peek())));
        }
        commands.push(c);
    }
    Ok(Query { commands })
}

fn contains_aggregate(e: &Expr) -> bool {
    match e {
        Expr::Call(name, args) => AGGREGATES.contains(&name.as_str()) || args.iter().any(contains_aggregate),
        Expr::Bin(_, a, b) | Expr::Like(a, b, _) => contains_aggregate(a) || contains_aggregate(b),
        Expr::Unary(_, a) | Expr::Not(a) => contains_aggregate(a),
        _ => false,
    }
}

// ---- evaluation ----------------------------------------------------------------

fn cmp_values(a: &V, b: &V) -> Option<Ordering> {
    match (a, b) {
        (V::Null, _) | (_, V::Null) => None,
        (V::Str(x), V::Str(y)) => match (x.parse::<f64>(), y.parse::<f64>()) {
            (Ok(p), Ok(q)) => p.partial_cmp(&q),
            _ => Some(x.cmp(y)),
        },
        _ => match (a.num(), b.num()) {
            (Some(x), Some(y)) => x.partial_cmp(&y),
            _ => Some(a.text().cmp(&b.text())),
        },
    }
}

fn eval(e: &Expr, r: &Record) -> V {
    match e {
        Expr::Lit(v) => v.clone(),
        Expr::Field(f) => r.get(f).cloned().unwrap_or(V::Null),
        Expr::Regex(re) => V::Str(re.as_str().to_string()),
        Expr::Duration(d) => V::Num(*d as f64),
        Expr::Star => V::Null,
        Expr::Unary(_, a) => eval(a, r).num().map(|n| V::Num(-n)).unwrap_or(V::Null),
        Expr::Not(a) => V::Bool(!eval(a, r).truthy()),
        Expr::In(a, items, neg) => {
            let v = eval(a, r);
            if v.is_null() {
                return V::Bool(false);
            }
            let hit = items.iter().any(|i| cmp_values(&v, &eval(i, r)) == Some(Ordering::Equal));
            V::Bool(hit != *neg)
        }
        Expr::Like(a, pat, neg) => {
            let v = eval(a, r);
            if v.is_null() {
                return V::Bool(false);
            }
            let text = v.text();
            let hit = match pat.as_ref() {
                Expr::Regex(re) => re.is_match(&text),
                other => text.contains(&eval(other, r).text()),
            };
            V::Bool(hit != *neg)
        }
        Expr::Bin(op, a, b) => {
            let (x, y) = (eval(a, r), eval(b, r));
            match op {
                BinOp::And => V::Bool(x.truthy() && y.truthy()),
                BinOp::Or => V::Bool(x.truthy() || y.truthy()),
                BinOp::Eq => V::Bool(cmp_values(&x, &y) == Some(Ordering::Equal)),
                BinOp::Ne => V::Bool(!x.is_null() && !y.is_null() && cmp_values(&x, &y) != Some(Ordering::Equal)),
                BinOp::Lt => V::Bool(cmp_values(&x, &y) == Some(Ordering::Less)),
                BinOp::Le => V::Bool(matches!(cmp_values(&x, &y), Some(Ordering::Less | Ordering::Equal))),
                BinOp::Gt => V::Bool(cmp_values(&x, &y) == Some(Ordering::Greater)),
                BinOp::Ge => V::Bool(matches!(cmp_values(&x, &y), Some(Ordering::Greater | Ordering::Equal))),
                _ => {
                    let (Some(p), Some(q)) = (x.num(), y.num()) else { return V::Null };
                    let n = match op {
                        BinOp::Add => p + q,
                        BinOp::Sub => p - q,
                        BinOp::Mul => p * q,
                        BinOp::Div if q != 0.0 => p / q,
                        BinOp::Mod if q != 0.0 => p % q,
                        BinOp::Pow => p.powf(q),
                        _ => return V::Null,
                    };
                    match (&x, op) {
                        (V::Time(_), BinOp::Add | BinOp::Sub) if !matches!(y, V::Time(_)) => V::Time(n as i64),
                        _ => V::Num(n),
                    }
                }
            }
        }
        Expr::Call(name, args) => call(name, args, r),
    }
}

fn call(name: &str, args: &[Expr], r: &Record) -> V {
    let a: Vec<V> = args.iter().map(|x| eval(x, r)).collect();
    let s = |i: usize| a.get(i).map(V::text).unwrap_or_default();
    let n = |i: usize| a.get(i).and_then(V::num);
    let num = |f: fn(f64) -> f64| n(0).map(|x| V::Num(f(x))).unwrap_or(V::Null);
    match name {
        "abs" => num(f64::abs),
        "ceil" => num(f64::ceil),
        "floor" => num(f64::floor),
        "sqrt" => num(f64::sqrt),
        "log" => num(f64::ln),
        "round" => match (n(0), n(1)) {
            (Some(x), Some(d)) => {
                let m = 10f64.powi(d as i32);
                V::Num((x * m).round() / m)
            }
            (Some(x), None) => V::Num(x.round()),
            _ => V::Null,
        },
        "greatest" => a.iter().filter_map(V::num).reduce(f64::max).map(V::Num).unwrap_or(V::Null),
        "least" => a.iter().filter_map(V::num).reduce(f64::min).map(V::Num).unwrap_or(V::Null),
        "strlen" => {
            a.first().filter(|v| !v.is_null()).map(|v| V::Num(v.text().chars().count() as f64)).unwrap_or(V::Null)
        }
        "toupper" => V::Str(s(0).to_uppercase()),
        "tolower" => V::Str(s(0).to_lowercase()),
        "trim" => V::Str(s(0).trim().to_string()),
        "ltrim" => V::Str(s(0).trim_start().to_string()),
        "rtrim" => V::Str(s(0).trim_end().to_string()),
        "concat" => V::Str(a.iter().map(V::text).collect()),
        "substr" => {
            let text: Vec<char> = s(0).chars().collect();
            let start = n(1).unwrap_or(0.0).max(0.0) as usize;
            let len = n(2).map(|l| l.max(0.0) as usize).unwrap_or(text.len());
            V::Str(text.iter().skip(start).take(len).collect())
        }
        "replace" => V::Str(s(0).replace(&s(1), &s(2))),
        "strcontains" => V::Num(f64::from(u8::from(s(0).contains(&s(1))))),
        "ispresent" => V::Bool(a.first().is_some_and(|v| !v.is_null())),
        "isempty" => V::Bool(a.first().is_none_or(|v| v.is_null() || v.text().is_empty())),
        "isblank" => V::Bool(a.first().is_none_or(|v| v.is_null() || v.text().trim().is_empty())),
        "coalesce" => a.iter().find(|v| !v.is_null()).cloned().unwrap_or(V::Null),
        "isvalidip" => V::Bool(s(0).parse::<std::net::IpAddr>().is_ok()),
        "isvalidipv4" => V::Bool(s(0).parse::<std::net::Ipv4Addr>().is_ok()),
        "isvalidipv6" => V::Bool(s(0).parse::<std::net::Ipv6Addr>().is_ok()),
        "bin" => {
            let period = n(0).unwrap_or(0.0) as i64;
            match r.get("@timestamp") {
                Some(V::Time(t)) if period > 0 => V::Time(t.div_euclid(period) * period),
                _ => V::Null,
            }
        }
        "datefloor" | "dateceil" => {
            let (Some(t), Some(p)) = (n(0), n(1)) else { return V::Null };
            let (t, p) = (t as i64, p as i64);
            if p <= 0 {
                return V::Null;
            }
            let floor = t.div_euclid(p) * p;
            V::Time(if name == "dateceil" && floor != t { floor + p } else { floor })
        }
        "frommillis" => n(0).map(|x| V::Time(x as i64)).unwrap_or(V::Null),
        "tomillis" => n(0).map(V::Num).unwrap_or(V::Null),
        "now" => V::Time(Utc::now().timestamp_millis()),
        _ => V::Null,
    }
}

// ---- aggregation ---------------------------------------------------------------

fn aggregate(e: &Expr, rows: &[&Record]) -> V {
    match e {
        Expr::Call(name, args) if AGGREGATES.contains(&name.as_str()) => {
            let values = || -> Vec<V> {
                match args.first() {
                    None | Some(Expr::Star) => Vec::new(),
                    Some(x) => rows.iter().map(|r| eval(x, r)).filter(|v| !v.is_null()).collect(),
                }
            };
            let nums = || values().iter().filter_map(V::num).collect::<Vec<_>>();
            match name.as_str() {
                "count" => match args.first() {
                    None | Some(Expr::Star) => V::Num(rows.len() as f64),
                    Some(_) => V::Num(values().len() as f64),
                },
                "count_distinct" => V::Num(values().iter().map(V::text).collect::<BTreeSet<_>>().len() as f64),
                "sum" => V::Num(nums().iter().sum()),
                "avg" => {
                    let v = nums();
                    if v.is_empty() {
                        V::Null
                    } else {
                        V::Num(v.iter().sum::<f64>() / v.len() as f64)
                    }
                }
                "min" | "max" => {
                    let v = values();
                    let pick = v.into_iter().reduce(|x, y| {
                        let o = cmp_values(&x, &y).unwrap_or(Ordering::Equal);
                        if (name == "min") == (o == Ordering::Greater) {
                            y
                        } else {
                            x
                        }
                    });
                    pick.unwrap_or(V::Null)
                }
                "earliest" | "latest" | "sortsfirst" | "sortslast" => {
                    let Some(x) = args.first() else { return V::Null };
                    let mut with_ts: Vec<(i64, V)> = rows
                        .iter()
                        .filter_map(|r| {
                            let v = eval(x, r);
                            let ts = match r.get("@timestamp") {
                                Some(V::Time(t)) => *t,
                                _ => 0,
                            };
                            (!v.is_null()).then_some((ts, v))
                        })
                        .collect();
                    match name.as_str() {
                        "sortsfirst" | "sortslast" => {
                            with_ts.sort_by(|a, b| cmp_values(&a.1, &b.1).unwrap_or(Ordering::Equal));
                        }
                        _ => with_ts.sort_by_key(|(t, _)| *t),
                    }
                    let pick = if matches!(name.as_str(), "earliest" | "sortsfirst") {
                        with_ts.into_iter().next()
                    } else {
                        with_ts.pop()
                    };
                    pick.map(|(_, v)| v).unwrap_or(V::Null)
                }
                "pct" => {
                    let mut v = nums();
                    let p = args.get(1).and_then(|e| eval(e, &Record::new()).num()).unwrap_or(50.0);
                    if v.is_empty() {
                        return V::Null;
                    }
                    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
                    let rank = ((p / 100.0) * v.len() as f64).ceil().max(1.0) as usize;
                    V::Num(v[rank.min(v.len()) - 1])
                }
                "stddev" => {
                    let v = nums();
                    if v.len() < 2 {
                        return V::Num(0.0);
                    }
                    let mean = v.iter().sum::<f64>() / v.len() as f64;
                    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
                    V::Num(var.sqrt())
                }
                _ => V::Null,
            }
        }
        Expr::Bin(op, a, b) => {
            let x = Expr::Lit(aggregate(a, rows));
            let y = Expr::Lit(aggregate(b, rows));
            eval(&Expr::Bin(*op, Box::new(x), Box::new(y)), &Record::new())
        }
        Expr::Call(name, args) => {
            let lits: Vec<Expr> = args.iter().map(|x| Expr::Lit(aggregate(x, rows))).collect();
            call(name, &lits, &Record::new())
        }
        other => rows.first().map(|r| eval(other, r)).unwrap_or(V::Null),
    }
}

/// The result of running a query.
#[derive(Debug, Default)]
pub struct Output {
    /// Rows of `(field, value)` in display order.
    pub rows: Vec<Vec<(String, String)>>,
    pub records_matched: usize,
}

/// Run `q` over `records`, returning at most `limit` rows.
pub fn execute(q: &Query, mut records: Vec<Record>, limit: usize) -> Output {
    let mut display: Option<Vec<String>> = None;
    let mut fields: Vec<String> = Vec::new();
    let mut aggregated = false;
    // Records that reached the first `stats`, which is what AWS reports as
    // matched for an aggregating query.
    let mut matched_before_stats = None;
    let mut sorted = false;
    let mut row_limit = limit;
    for c in &q.commands {
        match c {
            Command::Fields(items) => {
                for r in &mut records {
                    for item in items {
                        if !matches!(&item.expr, Expr::Field(f) if *f == item.name) {
                            let v = eval(&item.expr, r);
                            r.insert(item.name.clone(), v);
                        }
                    }
                }
                for item in items {
                    if !fields.contains(&item.name) {
                        fields.push(item.name.clone());
                    }
                }
            }
            Command::Display(names) => display = Some(names.clone()),
            Command::Filter(e) => records.retain(|r| eval(e, r).truthy()),
            Command::ParseGlob { field, pattern, names } => {
                for r in &mut records {
                    let text = eval(field, r).text();
                    if let Some(caps) = pattern.captures(&text) {
                        for (i, n) in names.iter().enumerate() {
                            if let Some(m) = caps.get(i + 1) {
                                r.insert(n.clone(), V::Str(m.as_str().to_string()));
                            }
                        }
                    }
                }
            }
            Command::ParseRegex { field, pattern } => {
                let names: Vec<String> = pattern.capture_names().flatten().map(str::to_string).collect();
                for r in &mut records {
                    let text = eval(field, r).text();
                    if let Some(caps) = pattern.captures(&text) {
                        for n in &names {
                            if let Some(m) = caps.name(n) {
                                r.insert(n.clone(), V::Str(m.as_str().to_string()));
                            }
                        }
                    }
                }
            }
            Command::Stats { aggs, by } => {
                let mut groups: Vec<(Vec<V>, Vec<usize>)> = Vec::new();
                let mut index: BTreeMap<Vec<String>, usize> = BTreeMap::new();
                for (i, r) in records.iter().enumerate() {
                    let key: Vec<V> = by.iter().map(|b| eval(&b.expr, r)).collect();
                    if !by.is_empty() && key.iter().any(V::is_null) {
                        continue;
                    }
                    let k: Vec<String> = key.iter().map(|v| format!("{v:?}")).collect();
                    let gi = *index.entry(k).or_insert_with(|| {
                        groups.push((key.clone(), Vec::new()));
                        groups.len() - 1
                    });
                    groups[gi].1.push(i);
                }
                if by.is_empty() && groups.is_empty() {
                    groups.push((Vec::new(), Vec::new()));
                }
                let mut out = Vec::new();
                for (key, members) in groups {
                    let rows: Vec<&Record> = members.iter().map(|i| &records[*i]).collect();
                    let mut rec = Record::new();
                    for (b, v) in by.iter().zip(key) {
                        rec.insert(b.name.clone(), v);
                    }
                    for a in aggs {
                        rec.insert(a.name.clone(), aggregate(&a.expr, &rows));
                    }
                    out.push(rec);
                }
                if !aggregated {
                    matched_before_stats = Some(records.len());
                }
                records = out;
                fields = by.iter().chain(aggs.iter()).map(|n| n.name.clone()).collect();
                aggregated = true;
            }
            Command::Sort(keys) => {
                records.sort_by(|a, b| {
                    for (k, desc) in keys {
                        let (x, y) = (eval(k, a), eval(k, b));
                        let o = match (x.is_null(), y.is_null()) {
                            (true, true) => Ordering::Equal,
                            (true, false) => Ordering::Greater,
                            (false, true) => Ordering::Less,
                            _ => {
                                let o = cmp_values(&x, &y).unwrap_or(Ordering::Equal);
                                if *desc {
                                    o.reverse()
                                } else {
                                    o
                                }
                            }
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    Ordering::Equal
                });
                sorted = true;
            }
            Command::Limit(n) => {
                row_limit = row_limit.min(*n);
                records.truncate(*n);
            }
            Command::Dedup(names) => {
                let mut seen = BTreeSet::new();
                records.retain(|r| {
                    let k: Vec<String> =
                        names.iter().map(|n| r.get(n).and_then(V::display).unwrap_or_default()).collect();
                    seen.insert(k)
                });
            }
        }
    }
    let matched = matched_before_stats.unwrap_or(records.len());
    if !aggregated && !sorted {
        records.sort_by(|a, b| {
            let t = |r: &Record| match r.get("@timestamp") {
                Some(V::Time(t)) => *t,
                _ => 0,
            };
            t(b).cmp(&t(a))
        });
    }
    records.truncate(row_limit);
    let columns: Vec<String> = match display {
        Some(d) => d,
        None if !fields.is_empty() => fields,
        None => vec!["@timestamp".into(), "@message".into(), "@logStream".into(), "@log".into()],
    };
    let rows = records
        .iter()
        .map(|r| {
            let mut row: Vec<(String, String)> =
                columns.iter().filter_map(|c| r.get(c).and_then(V::display).map(|v| (c.clone(), v))).collect();
            if !aggregated {
                if let Some(p) = r.get("@ptr").and_then(V::display) {
                    row.push(("@ptr".into(), p));
                }
            }
            row
        })
        .collect();
    Output { rows, records_matched: matched }
}

/// Fields discovered in a JSON message, flattened with `.` (arrays by
/// index), as Logs Insights discovers them.
pub fn discover_json(message: &str, out: &mut Record) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(message.trim()) else { return };
    if !v.is_object() {
        return;
    }
    fn walk(prefix: &str, v: &serde_json::Value, out: &mut Record) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    walk(&key, x, out);
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(&format!("{prefix}.{i}"), x, out);
                }
            }
            serde_json::Value::Number(n) => {
                out.insert(prefix.to_string(), n.as_f64().map(V::Num).unwrap_or(V::Null));
            }
            serde_json::Value::String(s) => {
                out.insert(prefix.to_string(), V::Str(s.clone()));
            }
            serde_json::Value::Bool(b) => {
                out.insert(prefix.to_string(), V::Bool(*b));
            }
            serde_json::Value::Null => {}
        }
    }
    walk("", &v, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: i64, msg: &str) -> Record {
        let mut r = Record::new();
        r.insert("@timestamp".into(), V::Time(ts));
        r.insert("@message".into(), V::Str(msg.into()));
        discover_json(msg, &mut r);
        r
    }

    fn run(q: &str, recs: Vec<Record>) -> Vec<Vec<(String, String)>> {
        execute(&parse(q).unwrap(), recs, 10_000).rows
    }

    #[test]
    fn fields_filter_sort_limit() {
        let recs = vec![rec(1000, "a ERROR one"), rec(2000, "b INFO two"), rec(3000, "c ERROR three")];
        let rows =
            run("fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp asc | limit 1", recs);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][1], ("@message".into(), "a ERROR one".into()));
        assert_eq!(rows[0][0].1, "1970-01-01 00:00:01.000");
    }

    #[test]
    fn stats_by() {
        let recs = vec![
            rec(1000, r#"{"level":"ERROR","ms":10}"#),
            rec(2000, r#"{"level":"INFO","ms":20}"#),
            rec(3000, r#"{"level":"ERROR","ms":30}"#),
        ];
        let rows = run("stats count(*) as n, avg(ms) as avg_ms, max(ms) by level | sort n desc", recs.clone());
        assert_eq!(
            rows[0],
            vec![
                ("level".into(), "ERROR".into()),
                ("n".into(), "2".into()),
                ("avg_ms".into(), "20".into()),
                ("max(ms)".into(), "30".into())
            ]
        );
        let rows = run("stats count(*) by bin(1s)", recs);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn parse_glob_and_regex() {
        let recs = vec![rec(1, "user=alice action=login"), rec(2, "user=bob action=logout")];
        let rows = run(
            "parse @message \"user=* action=*\" as user, action | filter action = \"login\" | display user",
            recs.clone(),
        );
        assert_eq!(rows, vec![vec![("user".to_string(), "alice".to_string())]]);
        let rows = run("parse @message /user=(?<u>\\w+)/ | stats count_distinct(u) as users", recs);
        assert_eq!(rows, vec![vec![("users".to_string(), "2".to_string())]]);
    }

    #[test]
    fn malformed() {
        assert!(parse("fields @message | bogus x").is_err());
        assert!(parse("stats @message").is_err());
        assert!(parse("filter (a = 1").is_err());
    }
}
