//! The SQL CloudTrail Lake queries are written in (a Trino dialect), over
//! the events an event data store holds.
//!
//! Supported: `SELECT [DISTINCT] expr [AS alias], ... | *`, `FROM` one or
//! more event data stores (by id or ARN; `UNION ALL` of several selects is
//! not), `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY ... [ASC|DESC]`, `LIMIT`.
//! Expressions: dotted column paths (`userIdentity.arn`), string, number
//! and boolean literals, `= != <> < <= > >=`, `AND OR NOT`, `[NOT] LIKE`,
//! `[NOT] IN (...)`, `[NOT] BETWEEN`, `IS [NOT] NULL`, `+ - * /`, `||`,
//! `CAST(x AS type)`, and the functions `count`, `sum`, `avg`, `min`,
//! `max`, `lower`, `upper`, `length`, `coalesce`, `concat`, `substr`,
//! `element_at`, `json_extract_scalar`, `from_iso8601_timestamp`, `now`,
//! `date_add` and `date_trunc`.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

/// A parsed query.
#[derive(Debug, Clone)]
pub struct Select {
    distinct: bool,
    /// `None` for `*`.
    items: Option<Vec<(Expr, Option<String>)>>,
    /// Event data store ids or ARNs.
    pub from: Vec<String>,
    filter: Option<Expr>,
    group_by: Vec<Expr>,
    having: Option<Expr>,
    order_by: Vec<(Expr, bool)>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Col(Vec<String>),
    Lit(V),
    Star,
    Bin(Box<Expr>, String, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Like(Box<Expr>, Box<Expr>, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    IsNull(Box<Expr>, bool),
    Func(String, Vec<Expr>, bool),
    Cast(Box<Expr>, String),
}

/// A SQL value.
#[derive(Debug, Clone, PartialEq)]
enum V {
    Null,
    Str(String),
    Num(f64),
    Bool(bool),
    Json(Value),
}

impl V {
    fn from_json(v: &Value) -> V {
        match v {
            Value::Null => V::Null,
            Value::String(s) => V::Str(s.clone()),
            Value::Number(n) => V::Num(n.as_f64().unwrap_or(0.0)),
            Value::Bool(b) => V::Bool(*b),
            other => V::Json(other.clone()),
        }
    }

    /// As Lake prints it.
    pub fn render(&self) -> Option<String> {
        match self {
            V::Null => None,
            V::Str(s) => Some(s.clone()),
            V::Num(n) if n.fract() == 0.0 && n.abs() < 1e15 => Some(format!("{}", *n as i64)),
            V::Num(n) => Some(n.to_string()),
            V::Bool(b) => Some(b.to_string()),
            V::Json(v) => Some(v.to_string()),
        }
    }

    fn truthy(&self) -> bool {
        matches!(self, V::Bool(true))
    }

    fn num(&self) -> Option<f64> {
        match self {
            V::Num(n) => Some(*n),
            V::Str(s) => s.trim().parse().ok(),
            V::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    }

    fn text(&self) -> Option<String> {
        self.render()
    }
}

fn compare(a: &V, b: &V) -> Option<Ordering> {
    match (a, b) {
        (V::Null, _) | (_, V::Null) => None,
        (V::Num(x), y) | (y, V::Num(x)) if y.num().is_some() => {
            let y = y.num()?;
            let o = x.partial_cmp(&y)?;
            Some(if matches!(a, V::Num(_)) { o } else { o.reverse() })
        }
        (V::Bool(x), V::Bool(y)) => Some(x.cmp(y)),
        _ => Some(a.text()?.cmp(&b.text()?)),
    }
}

// ---- lexing ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Str(String),
    Num(f64),
    Sym(String),
}

fn lex(sql: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ';' {
            i += 1;
            continue;
        }
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // The event data store after FROM (or a comma in its list): ids
        // contain dashes and ARNs colons and slashes.
        let after_from = matches!(out.last(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("from"))
            || (matches!(out.last(), Some(Tok::Sym(s)) if s == ",") && in_from_list(&out));
        if after_from && c != '(' && c != '"' {
            let start = i;
            while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], ',' | ')' | ';') {
                i += 1;
            }
            out.push(Tok::Word(chars[start..i].iter().collect()));
            continue;
        }
        if c == '\'' {
            let mut s = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("unterminated string literal".into()),
                    Some('\'') if chars.get(i + 1) == Some(&'\'') => {
                        s.push('\'');
                        i += 2;
                    }
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some(c) => {
                        s.push(*c);
                        i += 1;
                    }
                }
            }
            out.push(Tok::Str(s));
            continue;
        }
        if c == '"' {
            let start = i + 1;
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated quoted identifier".into());
            }
            out.push(Tok::Quoted(chars[start..i].iter().collect()));
            i += 1;
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && chars.get(i + 1).is_some_and(char::is_ascii_digit)) {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            out.push(Tok::Num(s.parse().map_err(|_| format!("invalid number {s}"))?));
            continue;
        }
        if c.is_alphanumeric() || c == '_' || c == '$' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '$')) {
                i += 1;
            }
            out.push(Tok::Word(chars[start..i].iter().collect()));
            continue;
        }
        let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        if ["<=", ">=", "<>", "!=", "||"].contains(&two.as_str()) {
            out.push(Tok::Sym(two));
            i += 2;
            continue;
        }
        if "=<>(),.*+-/%".contains(c) {
            out.push(Tok::Sym(c.to_string()));
            i += 1;
            continue;
        }
        return Err(format!("unexpected character '{c}'"));
    }
    Ok(out)
}

/// Whether the tokens so far end inside a `FROM a, b` list.
fn in_from_list(toks: &[Tok]) -> bool {
    for t in toks.iter().rev() {
        match t {
            Tok::Word(w) if w.eq_ignore_ascii_case("from") => return true,
            Tok::Word(w) if is_keyword(w) => return false,
            Tok::Sym(s) if s != "," => return false,
            _ => {}
        }
    }
    false
}

const KEYWORDS: &[&str] = &[
    "select", "distinct", "from", "where", "group", "by", "having", "order", "limit", "as", "and", "or", "not", "like",
    "in", "between", "is", "null", "asc", "desc", "true", "false", "cast", "union", "join", "on",
];

fn is_keyword(w: &str) -> bool {
    KEYWORDS.iter().any(|k| k.eq_ignore_ascii_case(w))
}

// ---- parsing --------------------------------------------------------------

struct P {
    toks: Vec<Tok>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }

    fn kw(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(k))
    }

    fn eat_kw(&mut self, k: &str) -> bool {
        if self.kw(k) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect_kw(&mut self, k: &str) -> Result<(), String> {
        if self.eat_kw(k) {
            Ok(())
        } else {
            Err(format!("expected {} near {}", k.to_uppercase(), self.near()))
        }
    }

    fn sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if x == s)
    }

    fn eat_sym(&mut self, s: &str) -> bool {
        if self.sym(s) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect_sym(&mut self, s: &str) -> Result<(), String> {
        if self.eat_sym(s) {
            Ok(())
        } else {
            Err(format!("expected '{s}' near {}", self.near()))
        }
    }

    fn near(&self) -> String {
        match self.peek() {
            None => "end of query".into(),
            Some(Tok::Word(w)) | Some(Tok::Quoted(w)) | Some(Tok::Sym(w)) => format!("'{w}'"),
            Some(Tok::Str(s)) => format!("'{s}'"),
            Some(Tok::Num(n)) => n.to_string(),
        }
    }

    fn select(&mut self) -> Result<Select, String> {
        self.expect_kw("select")?;
        let distinct = self.eat_kw("distinct");
        let items = if self.eat_sym("*") {
            None
        } else {
            let mut items = Vec::new();
            loop {
                let e = self.expr()?;
                let alias = if self.eat_kw("as") {
                    Some(self.ident()?)
                } else {
                    match self.peek() {
                        Some(Tok::Word(w)) if !is_keyword(w) => Some(self.ident()?),
                        Some(Tok::Quoted(_)) => Some(self.ident()?),
                        _ => None,
                    }
                };
                items.push((e, alias));
                if !self.eat_sym(",") {
                    break;
                }
            }
            Some(items)
        };
        self.expect_kw("from")?;
        let mut from = Vec::new();
        loop {
            match self.peek().cloned() {
                Some(Tok::Word(w)) | Some(Tok::Quoted(w)) => {
                    self.i += 1;
                    from.push(w);
                }
                _ => return Err(format!("expected an event data store near {}", self.near())),
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        let filter = if self.eat_kw("where") { Some(self.expr()?) } else { None };
        let mut group_by = Vec::new();
        if self.eat_kw("group") {
            self.expect_kw("by")?;
            loop {
                group_by.push(self.expr()?);
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let having = if self.eat_kw("having") { Some(self.expr()?) } else { None };
        let mut order_by = Vec::new();
        if self.eat_kw("order") {
            self.expect_kw("by")?;
            loop {
                let e = self.expr()?;
                let desc = if self.eat_kw("desc") {
                    true
                } else {
                    self.eat_kw("asc");
                    false
                };
                order_by.push((e, desc));
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let limit = if self.eat_kw("limit") {
            match self.peek() {
                Some(Tok::Num(n)) if *n >= 0.0 => {
                    let n = *n as usize;
                    self.i += 1;
                    Some(n)
                }
                _ => return Err(format!("expected a number after LIMIT near {}", self.near())),
            }
        } else {
            None
        };
        if self.peek().is_some() {
            return Err(format!("unexpected {}", self.near()));
        }
        Ok(Select { distinct, items, from, filter, group_by, having, order_by, limit })
    }

    fn ident(&mut self) -> Result<String, String> {
        match self.peek().cloned() {
            Some(Tok::Word(w)) | Some(Tok::Quoted(w)) => {
                self.i += 1;
                Ok(w)
            }
            Some(Tok::Str(s)) => {
                self.i += 1;
                Ok(s)
            }
            _ => Err(format!("expected an identifier near {}", self.near())),
        }
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut left = self.and()?;
        while self.eat_kw("or") {
            left = Expr::Bin(Box::new(left), "or".into(), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut left = self.not()?;
        while self.eat_kw("and") {
            left = Expr::Bin(Box::new(left), "and".into(), Box::new(self.not()?));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.eat_kw("not") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Expr, String> {
        let left = self.additive()?;
        if self.eat_kw("is") {
            let neg = self.eat_kw("not");
            self.expect_kw("null")?;
            return Ok(Expr::IsNull(Box::new(left), neg));
        }
        let neg = self.eat_kw("not");
        if self.eat_kw("like") {
            return Ok(Expr::Like(Box::new(left), Box::new(self.additive()?), neg));
        }
        if self.eat_kw("in") {
            self.expect_sym("(")?;
            let mut list = Vec::new();
            loop {
                list.push(self.expr()?);
                if !self.eat_sym(",") {
                    break;
                }
            }
            self.expect_sym(")")?;
            return Ok(Expr::In(Box::new(left), list, neg));
        }
        if self.eat_kw("between") {
            let lo = self.additive()?;
            self.expect_kw("and")?;
            let hi = self.additive()?;
            return Ok(Expr::Between(Box::new(left), Box::new(lo), Box::new(hi), neg));
        }
        if neg {
            return Err(format!("expected LIKE, IN or BETWEEN after NOT near {}", self.near()));
        }
        for op in ["=", "!=", "<>", "<=", ">=", "<", ">"] {
            if self.eat_sym(op) {
                let op = if op == "<>" { "!=" } else { op };
                return Ok(Expr::Bin(Box::new(left), op.into(), Box::new(self.additive()?)));
            }
        }
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr, String> {
        let mut left = self.multiplicative()?;
        loop {
            let op = ["+", "-", "||"].into_iter().find(|o| self.sym(o));
            let Some(op) = op else { return Ok(left) };
            self.i += 1;
            left = Expr::Bin(Box::new(left), op.into(), Box::new(self.multiplicative()?));
        }
    }

    fn multiplicative(&mut self) -> Result<Expr, String> {
        let mut left = self.unary()?;
        loop {
            let op = ["*", "/", "%"].into_iter().find(|o| self.sym(o));
            let Some(op) = op else { return Ok(left) };
            self.i += 1;
            left = Expr::Bin(Box::new(left), op.into(), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat_sym("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let Some(t) = self.peek().cloned() else { return Err("unexpected end of query".into()) };
        self.i += 1;
        match t {
            Tok::Str(s) => Ok(Expr::Lit(V::Str(s))),
            Tok::Num(n) => Ok(Expr::Lit(V::Num(n))),
            Tok::Sym(s) if s == "(" => {
                let e = self.expr()?;
                self.expect_sym(")")?;
                Ok(e)
            }
            Tok::Sym(s) if s == "*" => Ok(Expr::Star),
            Tok::Word(w) if w.eq_ignore_ascii_case("null") => Ok(Expr::Lit(V::Null)),
            Tok::Word(w) if w.eq_ignore_ascii_case("true") => Ok(Expr::Lit(V::Bool(true))),
            Tok::Word(w) if w.eq_ignore_ascii_case("false") => Ok(Expr::Lit(V::Bool(false))),
            Tok::Word(w) if w.eq_ignore_ascii_case("timestamp") && matches!(self.peek(), Some(Tok::Str(_))) => {
                let Some(Tok::Str(s)) = self.peek().cloned() else { unreachable!() };
                self.i += 1;
                Ok(Expr::Lit(V::Str(s)))
            }
            Tok::Word(w) if w.eq_ignore_ascii_case("cast") => {
                self.expect_sym("(")?;
                let e = self.expr()?;
                self.expect_kw("as")?;
                let ty = self.ident()?;
                if self.eat_sym("(") {
                    while !self.eat_sym(")") {
                        if self.peek().is_none() {
                            return Err("unterminated CAST".into());
                        }
                        self.i += 1;
                    }
                }
                self.expect_sym(")")?;
                Ok(Expr::Cast(Box::new(e), ty.to_ascii_lowercase()))
            }
            Tok::Word(w) | Tok::Quoted(w) if !is_keyword(&w) || matches!(t, Tok::Quoted(_)) => {
                if self.eat_sym("(") {
                    let name = w.to_ascii_lowercase();
                    let distinct = self.eat_kw("distinct");
                    let mut args = Vec::new();
                    if !self.eat_sym(")") {
                        loop {
                            args.push(self.expr()?);
                            if !self.eat_sym(",") {
                                break;
                            }
                        }
                        self.expect_sym(")")?;
                    }
                    return Ok(Expr::Func(name, args, distinct));
                }
                let mut path = vec![w];
                while self.eat_sym(".") {
                    path.push(self.ident()?);
                }
                Ok(Expr::Col(path))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

/// Parse a query statement.
pub fn parse(sql: &str) -> Result<Select, String> {
    let toks = lex(sql)?;
    if toks
        .iter()
        .any(|t| matches!(t, Tok::Word(w) if w.eq_ignore_ascii_case("union") || w.eq_ignore_ascii_case("join")))
    {
        return Err("UNION and JOIN are not supported by MWS".into());
    }
    P { toks, i: 0 }.select()
}

// ---- evaluation -----------------------------------------------------------

/// Lake shows `eventTime` as `YYYY-MM-DD HH:MM:SS.000`.
fn lake_time(s: &str) -> String {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc).format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_else(|_| s.to_string())
}

fn lookup<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    let m = v.as_object()?;
    m.get(key).or_else(|| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v))
}

fn column(record: &Value, path: &[String]) -> V {
    let mut cur = record;
    for (i, seg) in path.iter().enumerate() {
        match lookup(cur, seg) {
            Some(v) => cur = v,
            None => {
                // `requestParameters.bucketName` style access into a map.
                let _ = i;
                return V::Null;
            }
        }
    }
    if path.len() == 1 && path[0].eq_ignore_ascii_case("eventTime") {
        if let Value::String(s) = cur {
            return V::Str(lake_time(s));
        }
    }
    V::from_json(cur)
}

fn is_aggregate(name: &str) -> bool {
    matches!(name, "count" | "sum" | "avg" | "min" | "max" | "approx_distinct" | "array_agg")
}

fn has_aggregate(e: &Expr) -> bool {
    match e {
        Expr::Func(n, args, _) => is_aggregate(n) || args.iter().any(has_aggregate),
        Expr::Bin(a, _, b) | Expr::Like(a, b, _) => has_aggregate(a) || has_aggregate(b),
        Expr::Not(a) | Expr::Neg(a) | Expr::IsNull(a, _) | Expr::Cast(a, _) => has_aggregate(a),
        Expr::In(a, l, _) => has_aggregate(a) || l.iter().any(has_aggregate),
        Expr::Between(a, b, c, _) => has_aggregate(a) || has_aggregate(b) || has_aggregate(c),
        _ => false,
    }
}

fn like(text: &str, pattern: &str) -> bool {
    let mut re = String::from("^");
    for c in pattern.chars() {
        match c {
            '%' => re.push_str(".*"),
            '_' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    regex::RegexBuilder::new(&re).dot_matches_new_line(true).build().is_ok_and(|r| r.is_match(text))
}

struct Ctx<'a> {
    now: DateTime<Utc>,
    /// The rows of the current group (one row outside aggregation).
    rows: &'a [&'a Value],
}

fn eval(e: &Expr, c: &Ctx<'_>) -> Result<V, String> {
    let row = c.rows.first().copied();
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Star => V::Null,
        Expr::Col(path) => match row {
            Some(r) => column(r, path),
            None => V::Null,
        },
        Expr::Not(a) => match eval(a, c)? {
            V::Null => V::Null,
            v => V::Bool(!v.truthy()),
        },
        Expr::Neg(a) => match eval(a, c)?.num() {
            Some(n) => V::Num(-n),
            None => V::Null,
        },
        Expr::Bin(a, op, b) => {
            let (x, y) = (eval(a, c)?, eval(b, c)?);
            match op.as_str() {
                "and" => match (&x, &y) {
                    (V::Bool(false), _) | (_, V::Bool(false)) => V::Bool(false),
                    (V::Bool(true), V::Bool(true)) => V::Bool(true),
                    _ => V::Null,
                },
                "or" => match (&x, &y) {
                    (V::Bool(true), _) | (_, V::Bool(true)) => V::Bool(true),
                    (V::Bool(false), V::Bool(false)) => V::Bool(false),
                    _ => V::Null,
                },
                "||" => match (x.text(), y.text()) {
                    (Some(p), Some(q)) => V::Str(p + &q),
                    _ => V::Null,
                },
                "+" | "-" | "*" | "/" | "%" => match (x.num(), y.num()) {
                    (Some(p), Some(q)) => V::Num(match op.as_str() {
                        "+" => p + q,
                        "-" => p - q,
                        "*" => p * q,
                        "/" if q == 0.0 => return Err("division by zero".into()),
                        "/" => p / q,
                        _ => p % q,
                    }),
                    _ => V::Null,
                },
                cmp => match compare(&x, &y) {
                    None => V::Null,
                    Some(o) => V::Bool(match cmp {
                        "=" => o == Ordering::Equal,
                        "!=" => o != Ordering::Equal,
                        "<" => o == Ordering::Less,
                        "<=" => o != Ordering::Greater,
                        ">" => o == Ordering::Greater,
                        _ => o != Ordering::Less,
                    }),
                },
            }
        }
        Expr::Like(a, p, neg) => match (eval(a, c)?.text(), eval(p, c)?.text()) {
            (Some(t), Some(p)) => V::Bool(like(&t, &p) != *neg),
            _ => V::Null,
        },
        Expr::In(a, list, neg) => {
            let x = eval(a, c)?;
            if x == V::Null {
                V::Null
            } else {
                let mut found = false;
                for item in list {
                    if compare(&x, &eval(item, c)?) == Some(Ordering::Equal) {
                        found = true;
                        break;
                    }
                }
                V::Bool(found != *neg)
            }
        }
        Expr::Between(a, lo, hi, neg) => {
            let x = eval(a, c)?;
            match (compare(&x, &eval(lo, c)?), compare(&x, &eval(hi, c)?)) {
                (Some(l), Some(h)) => V::Bool((l != Ordering::Less && h != Ordering::Greater) != *neg),
                _ => V::Null,
            }
        }
        Expr::IsNull(a, neg) => V::Bool((eval(a, c)? == V::Null) != *neg),
        Expr::Cast(a, ty) => {
            let v = eval(a, c)?;
            match ty.as_str() {
                "varchar" | "string" | "char" => v.text().map(V::Str).unwrap_or(V::Null),
                "integer" | "int" | "bigint" | "smallint" | "tinyint" => {
                    v.num().map(|n| V::Num(n.trunc())).unwrap_or(V::Null)
                }
                "double" | "real" | "decimal" => v.num().map(V::Num).unwrap_or(V::Null),
                "boolean" => match v.text().as_deref() {
                    Some("true") => V::Bool(true),
                    Some("false") => V::Bool(false),
                    _ => V::Null,
                },
                "timestamp" | "date" => v.text().map(|t| V::Str(lake_time(&t))).unwrap_or(V::Null),
                other => return Err(format!("unknown type {other}")),
            }
        }
        Expr::Func(name, args, distinct) => func(name, args, *distinct, c)?,
    })
}

fn func(name: &str, args: &[Expr], distinct: bool, c: &Ctx<'_>) -> Result<V, String> {
    let arg = |i: usize| -> Result<V, String> {
        match args.get(i) {
            Some(e) => eval(e, c),
            None => Err(format!("{name}() is missing an argument")),
        }
    };
    if is_aggregate(name) {
        let values: Vec<V> = if matches!(args.first(), None | Some(Expr::Star)) {
            c.rows.iter().map(|_| V::Bool(true)).collect()
        } else {
            let mut vals = Vec::new();
            for r in c.rows {
                let one = [*r];
                let v = eval(&args[0], &Ctx { now: c.now, rows: &one })?;
                if v != V::Null {
                    vals.push(v);
                }
            }
            vals
        };
        let values = if distinct {
            let mut seen: Vec<V> = Vec::new();
            for v in values {
                if !seen.contains(&v) {
                    seen.push(v);
                }
            }
            seen
        } else {
            values
        };
        return Ok(match name {
            "count" | "approx_distinct" => V::Num(values.len() as f64),
            "sum" => V::Num(values.iter().filter_map(V::num).sum()),
            "avg" => {
                let nums: Vec<f64> = values.iter().filter_map(V::num).collect();
                if nums.is_empty() {
                    V::Null
                } else {
                    V::Num(nums.iter().sum::<f64>() / nums.len() as f64)
                }
            }
            "min" => values.into_iter().min_by(|a, b| compare(a, b).unwrap_or(Ordering::Equal)).unwrap_or(V::Null),
            "max" => values.into_iter().max_by(|a, b| compare(a, b).unwrap_or(Ordering::Equal)).unwrap_or(V::Null),
            _ => V::Json(Value::Array(values.iter().filter_map(V::render).map(Value::String).collect())),
        });
    }
    Ok(match name {
        "lower" => arg(0)?.text().map(|s| V::Str(s.to_lowercase())).unwrap_or(V::Null),
        "upper" => arg(0)?.text().map(|s| V::Str(s.to_uppercase())).unwrap_or(V::Null),
        "length" => arg(0)?.text().map(|s| V::Num(s.chars().count() as f64)).unwrap_or(V::Null),
        "coalesce" => {
            for a in args {
                let v = eval(a, c)?;
                if v != V::Null {
                    return Ok(v);
                }
            }
            V::Null
        }
        "concat" => {
            let mut s = String::new();
            for a in args {
                match eval(a, c)?.text() {
                    Some(t) => s.push_str(&t),
                    None => return Ok(V::Null),
                }
            }
            V::Str(s)
        }
        "substr" | "substring" => {
            let Some(s) = arg(0)?.text() else { return Ok(V::Null) };
            let start = arg(1)?.num().unwrap_or(1.0).max(1.0) as usize - 1;
            let chars: Vec<char> = s.chars().collect();
            let len = match args.get(2) {
                Some(e) => eval(e, c)?.num().unwrap_or(0.0).max(0.0) as usize,
                None => chars.len(),
            };
            V::Str(chars.iter().skip(start).take(len).collect())
        }
        "element_at" => {
            let container = arg(0)?;
            let key = arg(1)?;
            match container {
                V::Json(Value::Object(m)) => {
                    let k = key.text().unwrap_or_default();
                    match m.get(&k) {
                        Some(Value::String(s)) => V::Str(s.clone()),
                        Some(Value::Null) | None => V::Null,
                        Some(other) => V::Str(other.to_string()),
                    }
                }
                V::Json(Value::Array(a)) => {
                    let i = key.num().unwrap_or(0.0) as usize;
                    a.get(i.wrapping_sub(1)).map(V::from_json).unwrap_or(V::Null)
                }
                _ => V::Null,
            }
        }
        "json_extract_scalar" | "json_extract" => {
            let doc = match arg(0)? {
                V::Json(v) => v,
                V::Str(s) => serde_json::from_str(&s).unwrap_or(Value::Null),
                _ => return Ok(V::Null),
            };
            let path = arg(1)?.text().unwrap_or_default();
            let pointer: String =
                path.trim_start_matches('$').split('.').filter(|p| !p.is_empty()).map(|p| format!("/{p}")).collect();
            match doc.pointer(&pointer) {
                Some(Value::String(s)) => V::Str(s.clone()),
                Some(Value::Null) | None => V::Null,
                Some(v) if name == "json_extract" => V::Str(v.to_string()),
                Some(v @ (Value::Number(_) | Value::Bool(_))) => V::Str(v.to_string()),
                Some(_) => V::Null,
            }
        }
        "from_iso8601_timestamp" | "date_parse" | "parse_datetime" => {
            arg(0)?.text().map(|t| V::Str(lake_time(&t))).unwrap_or(V::Null)
        }
        "now" | "current_timestamp" => V::Str(c.now.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
        "date_add" => {
            let unit = arg(0)?.text().unwrap_or_default().to_lowercase();
            let n = arg(1)?.num().unwrap_or(0.0) as i64;
            let Some(t) = arg(2)?.text().and_then(|t| parse_lake_time(&t)) else { return Ok(V::Null) };
            let d = match unit.as_str() {
                "second" => chrono::Duration::seconds(n),
                "minute" => chrono::Duration::minutes(n),
                "hour" => chrono::Duration::hours(n),
                "day" => chrono::Duration::days(n),
                "week" => chrono::Duration::weeks(n),
                other => return Err(format!("unsupported date_add unit {other}")),
            };
            V::Str((t + d).format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        }
        "date_trunc" => {
            let unit = arg(0)?.text().unwrap_or_default().to_lowercase();
            let Some(t) = arg(1)?.text().and_then(|t| parse_lake_time(&t)) else { return Ok(V::Null) };
            let f = match unit.as_str() {
                "minute" => "%Y-%m-%d %H:%M:00.000",
                "hour" => "%Y-%m-%d %H:00:00.000",
                "day" => "%Y-%m-%d 00:00:00.000",
                "month" => "%Y-%m-01 00:00:00.000",
                "year" => "%Y-01-01 00:00:00.000",
                other => return Err(format!("unsupported date_trunc unit {other}")),
            };
            V::Str(t.format(f).to_string())
        }
        other => return Err(format!("Function {other} not registered")),
    })
}

fn parse_lake_time(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    for f in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"] {
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, f) {
            return Some(d.and_utc());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, f) {
            return d.and_hms_opt(0, 0, 0).map(|d| d.and_utc());
        }
    }
    None
}

/// The columns `SELECT *` returns, in the Lake schema's order.
const STAR_COLUMNS: &[&str] = &[
    "eventVersion",
    "userIdentity",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "errorCode",
    "errorMessage",
    "requestParameters",
    "responseElements",
    "additionalEventData",
    "requestID",
    "eventID",
    "readOnly",
    "resources",
    "eventType",
    "apiVersion",
    "managementEvent",
    "recipientAccountId",
    "sharedEventID",
    "annotation",
    "vpcEndpointId",
    "serviceEventDetails",
    "addendum",
    "edgeDeviceDetails",
    "insightDetails",
    "eventCategory",
    "tlsDetails",
    "sessionCredentialFromConsole",
];

fn column_name(e: &Expr, alias: &Option<String>, index: usize) -> String {
    if let Some(a) = alias {
        return a.clone();
    }
    match e {
        Expr::Col(p) => p.last().cloned().unwrap_or_default(),
        _ => format!("_col{index}"),
    }
}

/// What a query produced.
#[derive(Debug, Clone, Default)]
pub struct Output {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub scanned: usize,
    pub matched: usize,
    pub bytes: usize,
}

/// Run `q` over `events`.
pub fn run(q: &Select, events: &[&Value], now: DateTime<Utc>) -> Result<Output, String> {
    let mut matched: Vec<&Value> = Vec::new();
    let mut bytes = 0;
    for e in events {
        bytes += e.to_string().len();
        let keep = match &q.filter {
            Some(f) => {
                let one = [*e];
                eval(f, &Ctx { now, rows: &one })?.truthy()
            }
            None => true,
        };
        if keep {
            matched.push(e);
        }
    }
    let items: Vec<(Expr, Option<String>)> = match &q.items {
        Some(i) => i.clone(),
        None => STAR_COLUMNS.iter().map(|c| (Expr::Col(vec![c.to_string()]), None)).collect(),
    };
    let columns: Vec<String> = items.iter().enumerate().map(|(i, (e, a))| column_name(e, a, i)).collect();
    let aggregate = !q.group_by.is_empty() || items.iter().any(|(e, _)| has_aggregate(e));
    // Each output row: (values, the rows it came from).
    let groups: Vec<Vec<&Value>> = if aggregate {
        let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for e in &matched {
            let one = [*e];
            let mut key = Vec::new();
            for g in &q.group_by {
                key.push(eval(g, &Ctx { now, rows: &one })?.render());
            }
            let key = serde_json::to_string(&key).unwrap_or_default();
            if !groups.contains_key(&key) {
                order.push(key.clone());
            }
            groups.entry(key).or_default().push(e);
        }
        if q.group_by.is_empty() && groups.is_empty() {
            vec![Vec::new()]
        } else {
            order.into_iter().filter_map(|k| groups.remove(&k)).collect()
        }
    } else {
        matched.iter().map(|e| vec![*e]).collect()
    };
    let mut out: Vec<(Vec<V>, Vec<V>)> = Vec::new();
    for g in &groups {
        let c = Ctx { now, rows: g };
        if let Some(h) = &q.having {
            if !eval(h, &c)?.truthy() {
                continue;
            }
        }
        let mut values = Vec::new();
        for (e, _) in &items {
            values.push(eval(e, &c)?);
        }
        let mut keys = Vec::new();
        for (e, _) in &q.order_by {
            // ORDER BY an output column (by alias or position) or an
            // expression.
            let by_name = match e {
                Expr::Col(p) if p.len() == 1 => columns.iter().position(|c| c.eq_ignore_ascii_case(&p[0])),
                Expr::Lit(V::Num(n)) if *n >= 1.0 => Some(*n as usize - 1).filter(|i| *i < values.len()),
                _ => None,
            };
            keys.push(match by_name {
                Some(i) => values[i].clone(),
                None => eval(e, &c)?,
            });
        }
        out.push((values, keys));
    }
    if q.distinct {
        let mut seen: Vec<Vec<V>> = Vec::new();
        out.retain(|(v, _)| {
            if seen.contains(v) {
                false
            } else {
                seen.push(v.clone());
                true
            }
        });
    }
    if !q.order_by.is_empty() {
        out.sort_by(|(_, a), (_, b)| {
            for (i, (_, desc)) in q.order_by.iter().enumerate() {
                // NULLs sort last.
                let o = match (&a[i], &b[i]) {
                    (V::Null, V::Null) => Ordering::Equal,
                    (V::Null, _) => return Ordering::Greater,
                    (_, V::Null) => return Ordering::Less,
                    (x, y) => compare(x, y).unwrap_or(Ordering::Equal),
                };
                let o = if *desc { o.reverse() } else { o };
                if o != Ordering::Equal {
                    return o;
                }
            }
            Ordering::Equal
        });
    }
    if let Some(n) = q.limit {
        out.truncate(n);
    }
    Ok(Output {
        columns,
        rows: out.into_iter().map(|(v, _)| v.iter().map(V::render).collect()).collect(),
        scanned: events.len(),
        matched: matched.len(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn events() -> Vec<Value> {
        vec![
            json!({"eventName": "CreateUser", "eventSource": "iam.amazonaws.com", "eventTime": "2026-11-05T01:00:00Z",
                   "userIdentity": {"arn": "arn:aws:iam::1:root"}, "requestParameters": {"userName": "a"}, "readOnly": false}),
            json!({"eventName": "CreateUser", "eventSource": "iam.amazonaws.com", "eventTime": "2026-11-05T02:00:00Z",
                   "userIdentity": {"arn": "arn:aws:iam::1:user/x"}, "requestParameters": {"userName": "b"}, "readOnly": false}),
            json!({"eventName": "GetUser", "eventSource": "iam.amazonaws.com", "eventTime": "2026-11-05T03:00:00Z",
                   "userIdentity": {"arn": "arn:aws:iam::1:root"}, "readOnly": true}),
        ]
    }

    fn query(sql: &str) -> Output {
        let e = events();
        let refs: Vec<&Value> = e.iter().collect();
        run(&parse(sql).unwrap(), &refs, Utc::now()).unwrap()
    }

    #[test]
    fn filters_groups_and_orders() {
        let q = parse("SELECT eventName, count(*) AS n FROM abcd-1234 WHERE eventSource = 'iam.amazonaws.com' GROUP BY eventName ORDER BY n DESC").unwrap();
        assert_eq!(q.from, vec!["abcd-1234"]);
        let o = query("SELECT eventName, count(*) AS n FROM abcd-1234 WHERE eventSource = 'iam.amazonaws.com' GROUP BY eventName ORDER BY n DESC");
        assert_eq!(o.columns, vec!["eventName", "n"]);
        assert_eq!(
            o.rows,
            vec![vec![Some("CreateUser".into()), Some("2".into())], vec![Some("GetUser".into()), Some("1".into())]]
        );
    }

    #[test]
    fn paths_functions_and_times() {
        let o = query(
            "SELECT element_at(requestParameters, 'userName') AS u, userIdentity.arn FROM x \
             WHERE eventTime > '2026-11-05 01:30:00' AND readOnly = false AND eventName LIKE 'Create%'",
        );
        assert_eq!(o.rows, vec![vec![Some("b".into()), Some("arn:aws:iam::1:user/x".into())]]);
        let o = query("SELECT count(*) FROM x WHERE eventName IN ('GetUser', 'Nope')");
        assert_eq!(o.columns, vec!["_col0"]);
        assert_eq!(o.rows, vec![vec![Some("1".into())]]);
        let o = query("SELECT DISTINCT eventName FROM arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/abc ORDER BY 1 LIMIT 1");
        assert_eq!(o.rows, vec![vec![Some("CreateUser".into())]]);
        assert!(parse("SELEC x FROM y").is_err());
        assert!(parse("SELECT FROM").is_err());
    }
}
