//! Filter pattern syntax, as `FilterLogEvents`, metric filters,
//! subscription filters and live tail use it.
//!
//! * Terms: `ERROR`, `"phrase with spaces"`, `?ERROR ?WARN` (any of),
//!   `ERROR -Exiting` (exclusion) and `%regex%`. Terms are case sensitive
//!   and match anywhere in the message.
//! * JSON: `{ $.level = "ERROR" && ($.latency > 100 || $.user.id IS NULL) }`
//!   with `=`, `!=`, `<`, `<=`, `>`, `>=`, `IS NULL`, `NOT EXISTS`,
//!   `IS TRUE`, `IS FALSE`, `*` wildcards and `%regex%` values.
//! * Space-delimited: `[ip, user, ..., status = 4*, bytes > 1000]` over
//!   space-separated fields, where `"..."` and `[...]` group one field.
//!
//! Spec: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone)]
pub enum Pattern {
    /// The empty pattern matches every event.
    All,
    Terms(Vec<Term>),
    Json(Expr),
    Delimited(Delimited),
}

#[derive(Debug, Clone)]
pub enum Matcher {
    Text(String),
    Regex(Regex),
}

impl Matcher {
    fn find(&self, s: &str) -> bool {
        match self {
            Matcher::Text(t) => s.contains(t.as_str()),
            Matcher::Regex(r) => r.is_match(s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Term {
    pub matcher: Matcher,
    pub kind: TermKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermKind {
    Required,
    Optional,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Number(f64),
    Text(String),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Compare { selector: String, op: Op, value: Operand },
    IsNull(String),
    NotExists(String),
    IsBool(String, bool),
}

#[derive(Debug, Clone)]
pub struct Delimited {
    /// Field names in order; `None` for `...`.
    pub fields: Vec<Option<String>>,
    pub conditions: Option<Expr>,
}

pub type ParseError = String;

pub fn parse(pattern: &str) -> Result<Pattern, ParseError> {
    let p = pattern.trim();
    if p.is_empty() || p == "\"\"" {
        return Ok(Pattern::All);
    }
    if p.starts_with('{') {
        let inner = p.strip_prefix('{').and_then(|s| s.strip_suffix('}')).ok_or("Unbalanced braces")?;
        let mut parser = ExprParser::new(inner, true)?;
        let e = parser.expr()?;
        parser.end()?;
        return Ok(Pattern::Json(e));
    }
    if p.starts_with('[') {
        let inner = p.strip_prefix('[').and_then(|s| s.strip_suffix(']')).ok_or("Unbalanced brackets")?;
        return parse_delimited(inner).map(Pattern::Delimited);
    }
    parse_terms(p).map(Pattern::Terms)
}

impl Pattern {
    pub fn matches(&self, message: &str) -> bool {
        self.extract(message).is_some()
    }

    /// The values a match extracts (`$field` for space-delimited
    /// patterns, `$.selector` for JSON ones), or `None` when the message
    /// does not match.
    pub fn extract(&self, message: &str) -> Option<BTreeMap<String, String>> {
        match self {
            Pattern::All => Some(BTreeMap::new()),
            Pattern::Terms(terms) => {
                let mut any_optional = false;
                let mut optional_hit = false;
                for t in terms {
                    let hit = t.matcher.find(message);
                    match t.kind {
                        TermKind::Required if !hit => return None,
                        TermKind::Excluded if hit => return None,
                        TermKind::Optional => {
                            any_optional = true;
                            optional_hit |= hit;
                        }
                        _ => {}
                    }
                }
                (!any_optional || optional_hit).then(BTreeMap::new)
            }
            Pattern::Json(e) => {
                let doc: Value = serde_json::from_str(message.trim()).ok()?;
                if !doc.is_object() && !doc.is_array() {
                    return None;
                }
                let lookup = |sel: &str| select(&doc, sel);
                if !eval(e, &lookup) {
                    return None;
                }
                let mut out = BTreeMap::new();
                collect_selectors(e, &mut |s| {
                    if let Some(v) = select(&doc, s) {
                        out.insert(s.to_string(), scalar_text(&v));
                    }
                });
                Some(out)
            }
            Pattern::Delimited(d) => {
                let values = split_fields(message);
                let bound = bind_fields(&d.fields, &values)?;
                if let Some(c) = &d.conditions {
                    let lookup = |name: &str| bound.get(name).map(|v| Value::String(v.clone()));
                    if !eval(c, &lookup) {
                        return None;
                    }
                }
                Some(bound.into_iter().map(|(k, v)| (format!("${k}"), v)).collect())
            }
        }
    }
}

// ---- terms ------------------------------------------------------------------

fn parse_terms(p: &str) -> Result<Vec<Term>, ParseError> {
    let mut out = Vec::new();
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let kind = match chars[i] {
            '?' => {
                i += 1;
                TermKind::Optional
            }
            '-' if i + 1 < chars.len() && !chars[i + 1].is_whitespace() => {
                i += 1;
                TermKind::Excluded
            }
            _ => TermKind::Required,
        };
        let matcher = match chars.get(i) {
            Some('"') => {
                let end = chars[i + 1..].iter().position(|c| *c == '"').ok_or("Unterminated quoted term")? + i + 1;
                let text: String = chars[i + 1..end].iter().collect();
                i = end + 1;
                Matcher::Text(text)
            }
            Some('%') => {
                let end = chars[i + 1..].iter().position(|c| *c == '%').ok_or("Unterminated regex")? + i + 1;
                let re: String = chars[i + 1..end].iter().collect();
                i = end + 1;
                Matcher::Regex(Regex::new(&re).map_err(|e| format!("Invalid regex: {e}"))?)
            }
            Some(_) => {
                let start = i;
                while i < chars.len() && !chars[i].is_whitespace() {
                    i += 1;
                }
                Matcher::Text(chars[start..i].iter().collect())
            }
            None => return Err("Dangling operator".into()),
        };
        out.push(Term { matcher, kind });
    }
    Ok(out)
}

// ---- space-delimited ----------------------------------------------------------

/// Split a message into fields on spaces; `"..."` and `[...]` group one
/// field each (without the quotes or brackets).
pub fn split_fields(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = message.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let close = match c {
            '"' => Some('"'),
            '[' => Some(']'),
            _ => None,
        };
        let mut field = String::new();
        if let Some(close) = close {
            chars.next();
            for c in chars.by_ref() {
                if c == close {
                    break;
                }
                field.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                field.push(c);
                chars.next();
            }
        }
        out.push(field);
    }
    out
}

fn bind_fields(fields: &[Option<String>], values: &[String]) -> Option<BTreeMap<String, String>> {
    fn go(fields: &[Option<String>], values: &[String], out: &mut BTreeMap<String, String>) -> bool {
        match fields.split_first() {
            None => values.is_empty(),
            Some((None, rest)) => (0..=values.len()).any(|skip| {
                let mut trial = out.clone();
                if go(rest, &values[skip..], &mut trial) {
                    *out = trial;
                    true
                } else {
                    false
                }
            }),
            Some((Some(name), rest)) => {
                let Some((v, vs)) = values.split_first() else { return false };
                out.insert(name.clone(), v.clone());
                go(rest, vs, out)
            }
        }
    }
    let mut out = BTreeMap::new();
    go(fields, values, &mut out).then_some(out)
}

fn parse_delimited(inner: &str) -> Result<Delimited, ParseError> {
    let mut fields = Vec::new();
    let mut conditions: Option<Expr> = None;
    for (i, part) in split_top_level(inner, ',').into_iter().enumerate() {
        let part = part.trim();
        if part == "..." {
            fields.push(None);
            continue;
        }
        if part.is_empty() {
            return Err("Empty field in space-delimited pattern".into());
        }
        let name_end = part.find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$')).unwrap_or(part.len());
        let name = part[..name_end].trim_start_matches('$').to_string();
        let name = if name.is_empty() { format!("{}", i + 1) } else { name };
        if name_end < part.len() {
            let mut parser = ExprParser::new(part, false)?;
            let e = parser.expr()?;
            parser.end()?;
            conditions = Some(match conditions {
                Some(c) => Expr::And(Box::new(c), Box::new(e)),
                None => e,
            });
        }
        fields.push(Some(name));
    }
    Ok(Delimited { fields, conditions })
}

fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut quote = false;
    for c in s.chars() {
        match c {
            '"' => quote = !quote,
            '(' if !quote => depth += 1,
            ')' if !quote => depth -= 1,
            c if c == sep && depth == 0 && !quote => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur);
    out
}

// ---- expressions (JSON and field conditions) ---------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Selector(String),
    Op(Op),
    And,
    Or,
    Not,
    LParen,
    RParen,
    Str(String),
    Bare(String),
    Regex(String),
    Is,
    NotKw,
    Exists,
    Null,
    True,
    False,
}

fn tokenize(s: &str, json: bool) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        match two.as_str() {
            "&&" => {
                out.push(Tok::And);
                i += 2;
                continue;
            }
            "||" => {
                out.push(Tok::Or);
                i += 2;
                continue;
            }
            "!=" => {
                out.push(Tok::Op(Op::Ne));
                i += 2;
                continue;
            }
            "<=" => {
                out.push(Tok::Op(Op::Le));
                i += 2;
                continue;
            }
            ">=" => {
                out.push(Tok::Op(Op::Ge));
                i += 2;
                continue;
            }
            _ => {}
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '=' => {
                out.push(Tok::Op(Op::Eq));
                i += 1;
            }
            '<' => {
                out.push(Tok::Op(Op::Lt));
                i += 1;
            }
            '>' => {
                out.push(Tok::Op(Op::Gt));
                i += 1;
            }
            '!' => {
                out.push(Tok::Not);
                i += 1;
            }
            '"' => {
                let mut text = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    text.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("Unterminated string".into());
                }
                i += 1;
                out.push(Tok::Str(text));
            }
            '%' => {
                let end = chars[i + 1..].iter().position(|c| *c == '%').ok_or("Unterminated regex")? + i + 1;
                out.push(Tok::Regex(chars[i + 1..end].iter().collect()));
                i = end + 1;
            }
            _ => {
                let start = i;
                while i < chars.len() && !chars[i].is_whitespace() && !"()=<>!&|\"".contains(chars[i]) {
                    i += 1;
                }
                if start == i {
                    return Err(format!("Unexpected character '{c}'"));
                }
                let word: String = chars[start..i].iter().collect();
                out.push(match word.to_ascii_uppercase().as_str() {
                    "IS" => Tok::Is,
                    "NOT" => Tok::NotKw,
                    "EXISTS" => Tok::Exists,
                    "NULL" => Tok::Null,
                    "TRUE" => Tok::True,
                    "FALSE" => Tok::False,
                    _ if json && word.starts_with('$') => Tok::Selector(word),
                    _ => Tok::Bare(word),
                });
            }
        }
    }
    Ok(out)
}

struct ExprParser {
    toks: Vec<Tok>,
    pos: usize,
    json: bool,
}

impl ExprParser {
    fn new(s: &str, json: bool) -> Result<Self, ParseError> {
        Ok(Self { toks: tokenize(s, json)?, pos: 0, json })
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn end(&self) -> Result<(), ParseError> {
        match self.peek() {
            None => Ok(()),
            Some(t) => Err(format!("Unexpected token {t:?}")),
        }
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.next();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Tok::And) {
            self.next();
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Tok::Not) => {
                self.next();
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some(Tok::LParen) => {
                self.next();
                let e = self.expr()?;
                if self.next() != Some(Tok::RParen) {
                    return Err("Expected ')'".into());
                }
                Ok(e)
            }
            _ => self.comparison(),
        }
    }

    fn comparison(&mut self) -> Result<Expr, ParseError> {
        let selector = match self.next() {
            Some(Tok::Selector(s)) if self.json => s,
            Some(Tok::Bare(s)) if !self.json => s.trim_start_matches('$').to_string(),
            other => return Err(format!("Expected a selector, found {other:?}")),
        };
        match self.next() {
            Some(Tok::Op(op)) => {
                let value = match self.next() {
                    Some(Tok::Str(s)) => Operand::Text(s),
                    Some(Tok::Bare(s)) => match s.parse::<f64>() {
                        Ok(n) => Operand::Number(n),
                        Err(_) => Operand::Text(s),
                    },
                    Some(Tok::Regex(r)) => Operand::Regex(Regex::new(&r).map_err(|e| format!("Invalid regex: {e}"))?),
                    Some(Tok::True) => Operand::Text("true".into()),
                    Some(Tok::False) => Operand::Text("false".into()),
                    Some(Tok::Null) => Operand::Text("null".into()),
                    other => return Err(format!("Expected a value, found {other:?}")),
                };
                Ok(Expr::Compare { selector, op, value })
            }
            Some(Tok::Is) => match self.next() {
                Some(Tok::Null) => Ok(Expr::IsNull(selector)),
                Some(Tok::True) => Ok(Expr::IsBool(selector, true)),
                Some(Tok::False) => Ok(Expr::IsBool(selector, false)),
                other => Err(format!("Expected NULL, TRUE or FALSE, found {other:?}")),
            },
            Some(Tok::NotKw) => match self.next() {
                Some(Tok::Exists) => Ok(Expr::NotExists(selector)),
                other => Err(format!("Expected EXISTS, found {other:?}")),
            },
            other => Err(format!("Expected an operator, found {other:?}")),
        }
    }
}

fn glob(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let re = format!("^{}$", pattern.split('*').map(regex::escape).collect::<Vec<_>>().join(".*"));
    Regex::new(&re).is_ok_and(|r| r.is_match(text))
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn eval(e: &Expr, lookup: &dyn Fn(&str) -> Option<Value>) -> bool {
    match e {
        Expr::And(a, b) => eval(a, lookup) && eval(b, lookup),
        Expr::Or(a, b) => eval(a, lookup) || eval(b, lookup),
        Expr::Not(a) => !eval(a, lookup),
        Expr::IsNull(s) => matches!(lookup(s), Some(Value::Null)),
        Expr::NotExists(s) => lookup(s).is_none(),
        Expr::IsBool(s, b) => lookup(s) == Some(Value::Bool(*b)),
        Expr::Compare { selector, op, value } => {
            let Some(v) = lookup(selector) else { return false };
            let candidates: Vec<Value> = match v {
                Value::Array(a) => a,
                other => vec![other],
            };
            candidates.iter().any(|v| compare(v, *op, value))
        }
    }
}

fn compare(v: &Value, op: Op, value: &Operand) -> bool {
    let text = scalar_text(v);
    match value {
        Operand::Regex(r) => {
            let m = r.is_match(&text);
            match op {
                Op::Eq => m,
                Op::Ne => !m,
                _ => false,
            }
        }
        Operand::Number(n) => {
            let x = match v {
                Value::Number(x) => x.as_f64(),
                Value::String(s) => s.parse::<f64>().ok(),
                _ => None,
            };
            let Some(x) = x else { return op == Op::Ne };
            match op {
                Op::Eq => x == *n,
                Op::Ne => x != *n,
                Op::Lt => x < *n,
                Op::Le => x <= *n,
                Op::Gt => x > *n,
                Op::Ge => x >= *n,
            }
        }
        Operand::Text(t) => {
            if matches!(v, Value::Object(_) | Value::Array(_)) {
                return op == Op::Ne;
            }
            match op {
                Op::Eq => glob(t, &text),
                Op::Ne => !glob(t, &text),
                Op::Lt => text.as_str() < t.as_str(),
                Op::Le => text.as_str() <= t.as_str(),
                Op::Gt => text.as_str() > t.as_str(),
                Op::Ge => text.as_str() >= t.as_str(),
            }
        }
    }
}

fn collect_selectors(e: &Expr, f: &mut dyn FnMut(&str)) {
    match e {
        Expr::And(a, b) | Expr::Or(a, b) => {
            collect_selectors(a, f);
            collect_selectors(b, f);
        }
        Expr::Not(a) => collect_selectors(a, f),
        Expr::Compare { selector, .. }
        | Expr::IsNull(selector)
        | Expr::NotExists(selector)
        | Expr::IsBool(selector, _) => f(selector),
    }
}

/// Resolve a `$.a.b[0].c` selector. `$.a.*` style wildcards are not
/// supported in values but `[*]`/`.*` on arrays fan out.
pub fn select(doc: &Value, selector: &str) -> Option<Value> {
    let path = selector.strip_prefix('$')?;
    let mut cur = vec![doc.clone()];
    let mut rest = path;
    while !rest.is_empty() {
        let mut next = Vec::new();
        if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['.', '[']).unwrap_or(r.len());
            let key = &r[..end];
            rest = &r[end..];
            for v in &cur {
                if key == "*" {
                    match v {
                        Value::Object(m) => next.extend(m.values().cloned()),
                        Value::Array(a) => next.extend(a.iter().cloned()),
                        _ => {}
                    }
                } else if let Some(x) = v.get(key) {
                    next.push(x.clone());
                }
            }
        } else {
            let r = rest.strip_prefix('[')?;
            let end = r.find(']')?;
            let idx = &r[..end];
            rest = &r[end + 1..];
            for v in &cur {
                if idx == "*" {
                    if let Value::Array(a) = v {
                        next.extend(a.iter().cloned());
                    }
                } else if let Ok(i) = idx.parse::<usize>() {
                    if let Some(x) = v.get(i) {
                        next.push(x.clone());
                    }
                } else if let Some(x) = v.get(idx.trim_matches(['\'', '"'])) {
                    next.push(x.clone());
                }
            }
        }
        cur = next;
        if cur.is_empty() {
            return None;
        }
    }
    match cur.len() {
        1 => cur.pop(),
        _ => Some(Value::Array(cur)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, msg: &str) -> bool {
        parse(p).unwrap().matches(msg)
    }

    #[test]
    fn terms() {
        assert!(m("", "anything"));
        assert!(m("ERROR", "[ERROR] boom"));
        assert!(!m("ERROR", "error boom"));
        assert!(m("ERROR Exception", "ERROR: Exception thrown"));
        assert!(!m("ERROR Exception", "ERROR only"));
        assert!(m("?ERROR ?WARN", "WARN low disk"));
        assert!(!m("?ERROR ?WARN", "INFO ok"));
        assert!(m("ERROR -Exiting", "ERROR boom"));
        assert!(!m("ERROR -Exiting", "ERROR Exiting now"));
        assert!(m("\"user signed in\"", "x user signed in y"));
        assert!(m("%[0-9]{3} ms%", "took 123 ms"));
    }

    #[test]
    fn json() {
        let doc = r#"{"level":"ERROR","latency":250,"user":{"id":null,"name":"bob"},"tags":["a","b"],"ok":false}"#;
        assert!(m(r#"{ $.level = "ERROR" }"#, doc));
        assert!(m("{ $.level = ERR* }", doc));
        assert!(m("{ $.latency > 200 && $.latency <= 250 }", doc));
        assert!(!m("{ $.latency < 200 }", doc));
        assert!(m("{ $.user.id IS NULL }", doc));
        assert!(m("{ $.missing NOT EXISTS }", doc));
        assert!(m("{ $.ok IS FALSE }", doc));
        assert!(m("{ $.tags[1] = \"b\" }", doc));
        assert!(m("{ ($.level = \"INFO\") || ($.user.name = \"bob\") }", doc));
        assert!(m("{ $.level != \"INFO\" }", doc));
        assert!(m("{ $.level = %ERR|WARN% }", doc));
        assert!(!m("{ $.level = \"ERROR\" }", "not json"));
    }

    #[test]
    fn delimited() {
        let line = r#"127.0.0.1 - frank [10/Oct/2000:13:25:15 -0700] "GET /index.html HTTP/1.0" 404 1534"#;
        let p = parse("[ip, user, username, timestamp, request, status_code = 4*, bytes]").unwrap();
        let x = p.extract(line).unwrap();
        assert_eq!(x["$status_code"], "404");
        assert_eq!(x["$request"], "GET /index.html HTTP/1.0");
        assert!(m("[..., status_code = 404, bytes > 1000]", line));
        assert!(!m("[..., status_code = 200, bytes]", line));
        assert!(m("[ip, ...]", line));
        assert!(!m("[ip, user]", line));
        assert!(m("[ip, user, ..., status = 4* || status = 5*, bytes]", line));
    }
}
