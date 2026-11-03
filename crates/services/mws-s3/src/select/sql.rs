//! The S3 Select SQL dialect: `SELECT ... FROM S3Object [alias] [WHERE ...]
//! [LIMIT n]` with S3 Select's operators, conditional and string
//! functions, `CAST`, and the aggregates `COUNT`, `SUM`, `AVG`, `MIN` and
//! `MAX`.

use std::cmp::Ordering;

use serde_json::{Map, Value as Json};

/// A value during evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Missing,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// A JSON object or array from JSON input.
    Json(Json),
}

impl Val {
    pub fn from_json(v: &Json) -> Val {
        match v {
            Json::Null => Val::Null,
            Json::Bool(b) => Val::Bool(*b),
            Json::Number(n) => n.as_i64().map(Val::Int).unwrap_or_else(|| Val::Float(n.as_f64().unwrap_or(0.0))),
            Json::String(s) => Val::Str(s.clone()),
            other => Val::Json(other.clone()),
        }
    }

    pub fn to_json(&self) -> Json {
        match self {
            Val::Missing | Val::Null => Json::Null,
            Val::Bool(b) => Json::Bool(*b),
            Val::Int(i) => Json::from(*i),
            Val::Float(f) => serde_json::Number::from_f64(*f).map(Json::Number).unwrap_or(Json::Null),
            Val::Str(s) => Json::String(s.clone()),
            Val::Json(j) => j.clone(),
        }
    }

    /// Text for CSV output.
    pub fn to_text(&self) -> String {
        match self {
            Val::Missing | Val::Null => String::new(),
            Val::Bool(b) => b.to_string(),
            Val::Int(i) => i.to_string(),
            Val::Float(f) => format_float(*f),
            Val::Str(s) => s.clone(),
            Val::Json(j) => j.to_string(),
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Val::Null | Val::Missing)
    }

    fn number(&self) -> Option<f64> {
        match self {
            Val::Int(i) => Some(*i as f64),
            Val::Float(f) => Some(*f),
            Val::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    fn truthy(&self) -> Option<bool> {
        match self {
            Val::Bool(b) => Some(*b),
            Val::Str(s) if s.eq_ignore_ascii_case("true") => Some(true),
            Val::Str(s) if s.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        }
    }
}

fn format_float(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{f:.1}")
    } else {
        f.to_string()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(Val),
    /// A path from the record: `_1`, `name`, `s.name`, `s.a.b[0]`.
    Path(Vec<Step>),
    /// `*` or `s.*` in a projection.
    Star,
    Unary(String, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
    Like {
        value: Box<Expr>,
        pattern: Box<Expr>,
        escape: Option<Box<Expr>>,
        negated: bool,
    },
    In {
        value: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    Between {
        value: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    IsNull {
        value: Box<Expr>,
        negated: bool,
        missing: bool,
    },
    Cast(Box<Expr>, String),
    Func(String, Vec<Expr>),
    Agg {
        func: String,
        arg: Option<Box<Expr>>,
    },
    Case {
        operand: Option<Box<Expr>>,
        whens: Vec<(Expr, Expr)>,
        otherwise: Option<Box<Expr>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone)]
pub struct Projection {
    pub expr: Expr,
    pub alias: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub projections: Vec<Projection>,
    /// The `FROM` alias (`s` in `FROM S3Object s`), if any.
    pub alias: Option<String>,
    /// A path inside the record set (`FROM S3Object[*].items[*]`).
    pub from_path: Vec<Step>,
    pub filter: Option<Expr>,
    pub limit: Option<u64>,
}

impl Query {
    pub fn is_aggregate(&self) -> bool {
        self.projections.iter().any(|p| contains_agg(&p.expr))
    }
}

fn contains_agg(e: &Expr) -> bool {
    match e {
        Expr::Agg { .. } => true,
        Expr::Unary(_, a) | Expr::Cast(a, _) => contains_agg(a),
        Expr::Binary(_, a, b) => contains_agg(a) || contains_agg(b),
        Expr::Func(_, args) => args.iter().any(contains_agg),
        _ => false,
    }
}

// ---- lexer --------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Quoted(String),
    Str(String),
    Num(String),
    Sym(String),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' {
            let mut s = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("Unterminated string literal".into()),
                    Some('\'') if chars.get(i + 1) == Some(&'\'') => {
                        s.push('\'');
                        i += 2;
                    }
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some(ch) => {
                        s.push(*ch);
                        i += 1;
                    }
                }
            }
            out.push(Tok::Str(s));
        } else if c == '"' {
            let mut s = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err("Unterminated quoted identifier".into()),
                    Some('"') if chars.get(i + 1) == Some(&'"') => {
                        s.push('"');
                        i += 2;
                    }
                    Some('"') => {
                        i += 1;
                        break;
                    }
                    Some(ch) => {
                        s.push(*ch);
                        i += 1;
                    }
                }
            }
            out.push(Tok::Quoted(s));
        } else if c.is_ascii_digit() || (c == '.' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_digit() || chars[i] == '.' || chars[i] == 'e' || chars[i] == 'E')
            {
                i += 1;
            }
            out.push(Tok::Num(chars[start..i].iter().collect()));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(chars[start..i].iter().collect()));
        } else {
            let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            if ["<=", ">=", "<>", "!=", "||"].contains(&two.as_str()) {
                out.push(Tok::Sym(two));
                i += 2;
            } else if "=<>+-*/%(),.[]".contains(c) {
                out.push(Tok::Sym(c.to_string()));
                i += 1;
            } else {
                return Err(format!("Unexpected character '{c}'"));
            }
        }
    }
    Ok(out)
}

// ---- parser -------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

const RESERVED: &[&str] = &[
    "SELECT", "FROM", "WHERE", "LIMIT", "AS", "AND", "OR", "NOT", "LIKE", "IN", "BETWEEN", "IS", "NULL", "MISSING",
    "TRUE", "FALSE", "CASE", "WHEN", "THEN", "ELSE", "END", "ESCAPE",
];

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn kw(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(w)) if w.eq_ignore_ascii_case(word))
    }

    fn eat_kw(&mut self, word: &str) -> bool {
        if self.kw(word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_kw(&mut self, word: &str) -> Result<(), String> {
        if self.eat_kw(word) {
            Ok(())
        } else {
            Err(format!("Expected {word}"))
        }
    }

    fn sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if x == s)
    }

    fn eat_sym(&mut self, s: &str) -> bool {
        if self.sym(s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_sym(&mut self, s: &str) -> Result<(), String> {
        if self.eat_sym(s) {
            Ok(())
        } else {
            Err(format!("Expected '{s}'"))
        }
    }

    fn query(&mut self) -> Result<Query, String> {
        self.expect_kw("SELECT")?;
        let mut projections = Vec::new();
        loop {
            let expr = if self.eat_sym("*") { Expr::Star } else { self.expr()? };
            let alias = if self.eat_kw("AS") {
                Some(self.name()?)
            } else {
                match self.peek() {
                    Some(Tok::Ident(w)) if !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(w)) => Some(self.name()?),
                    Some(Tok::Quoted(_)) => Some(self.name()?),
                    _ => None,
                }
            };
            projections.push(Projection { expr, alias });
            if !self.eat_sym(",") {
                break;
            }
        }
        self.expect_kw("FROM")?;
        match self.next() {
            Some(Tok::Ident(w)) if w.eq_ignore_ascii_case("S3Object") => {}
            _ => return Err("Expected S3Object after FROM".into()),
        }
        let mut from_path = Vec::new();
        loop {
            if self.eat_sym("[") {
                if self.eat_sym("*") {
                    // `[*]` iterates the current value.
                } else {
                    return Err("Only [*] is supported after S3Object".into());
                }
                self.expect_sym("]")?;
            } else if self.eat_sym(".") {
                from_path.push(Step::Key(self.name()?));
            } else {
                break;
            }
        }
        self.eat_kw("AS");
        let alias = match self.peek() {
            Some(Tok::Ident(w)) if !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(w)) => Some(self.name()?),
            _ => None,
        };
        let filter = if self.eat_kw("WHERE") { Some(self.expr()?) } else { None };
        let limit = if self.eat_kw("LIMIT") {
            match self.next() {
                Some(Tok::Num(n)) => Some(n.parse().map_err(|_| "Invalid LIMIT".to_string())?),
                _ => return Err("Expected a number after LIMIT".into()),
            }
        } else {
            None
        };
        if let Some(t) = self.peek() {
            return Err(format!("Unexpected token {t:?}"));
        }
        Ok(Query { projections, alias, from_path, filter, limit })
    }

    fn name(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Ident(w)) | Some(Tok::Quoted(w)) => Ok(w),
            other => Err(format!("Expected a name, found {other:?}")),
        }
    }

    fn expr(&mut self) -> Result<Expr, String> {
        self.or()
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut l = self.and()?;
        while self.eat_kw("OR") {
            l = Expr::Binary("OR".into(), Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.not()?;
        while self.eat_kw("AND") {
            l = Expr::Binary("AND".into(), Box::new(l), Box::new(self.not()?));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.eat_kw("NOT") {
            return Ok(Expr::Unary("NOT".into(), Box::new(self.not()?)));
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Expr, String> {
        let l = self.additive()?;
        for op in ["=", "!=", "<>", "<=", ">=", "<", ">"] {
            if self.eat_sym(op) {
                let op = if op == "<>" { "!=" } else { op };
                return Ok(Expr::Binary(op.into(), Box::new(l), Box::new(self.additive()?)));
            }
        }
        if self.eat_kw("IS") {
            let negated = self.eat_kw("NOT");
            let missing = if self.eat_kw("NULL") {
                false
            } else if self.eat_kw("MISSING") {
                true
            } else {
                return Err("Expected NULL or MISSING after IS".into());
            };
            return Ok(Expr::IsNull { value: Box::new(l), negated, missing });
        }
        let negated = self.eat_kw("NOT");
        if self.eat_kw("LIKE") {
            let pattern = self.additive()?;
            let escape = if self.eat_kw("ESCAPE") { Some(Box::new(self.additive()?)) } else { None };
            return Ok(Expr::Like { value: Box::new(l), pattern: Box::new(pattern), escape, negated });
        }
        if self.eat_kw("IN") {
            self.expect_sym("(")?;
            let mut list = vec![self.expr()?];
            while self.eat_sym(",") {
                list.push(self.expr()?);
            }
            self.expect_sym(")")?;
            return Ok(Expr::In { value: Box::new(l), list, negated });
        }
        if self.eat_kw("BETWEEN") {
            let low = self.additive()?;
            self.expect_kw("AND")?;
            let high = self.additive()?;
            return Ok(Expr::Between { value: Box::new(l), low: Box::new(low), high: Box::new(high), negated });
        }
        if negated {
            return Err("Expected LIKE, IN or BETWEEN after NOT".into());
        }
        Ok(l)
    }

    fn additive(&mut self) -> Result<Expr, String> {
        let mut l = self.multiplicative()?;
        loop {
            let op = if self.eat_sym("+") {
                "+"
            } else if self.eat_sym("-") {
                "-"
            } else if self.eat_sym("||") {
                "||"
            } else {
                return Ok(l);
            };
            l = Expr::Binary(op.into(), Box::new(l), Box::new(self.multiplicative()?));
        }
    }

    fn multiplicative(&mut self) -> Result<Expr, String> {
        let mut l = self.unary()?;
        loop {
            let op = if self.eat_sym("*") {
                "*"
            } else if self.eat_sym("/") {
                "/"
            } else if self.eat_sym("%") {
                "%"
            } else {
                return Ok(l);
            };
            l = Expr::Binary(op.into(), Box::new(l), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat_sym("-") {
            return Ok(Expr::Unary("-".into(), Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Num(n)) => {
                if let Ok(i) = n.parse::<i64>() {
                    Ok(Expr::Lit(Val::Int(i)))
                } else {
                    n.parse::<f64>().map(|f| Expr::Lit(Val::Float(f))).map_err(|_| format!("Invalid number {n}"))
                }
            }
            Some(Tok::Str(s)) => Ok(Expr::Lit(Val::Str(s))),
            Some(Tok::Sym(s)) if s == "(" => {
                let e = self.expr()?;
                self.expect_sym(")")?;
                Ok(e)
            }
            Some(Tok::Quoted(name)) => self.path(name),
            Some(Tok::Ident(w)) => {
                let upper = w.to_ascii_uppercase();
                match upper.as_str() {
                    "NULL" => return Ok(Expr::Lit(Val::Null)),
                    "MISSING" => return Ok(Expr::Lit(Val::Missing)),
                    "TRUE" => return Ok(Expr::Lit(Val::Bool(true))),
                    "FALSE" => return Ok(Expr::Lit(Val::Bool(false))),
                    "CASE" => return self.case(),
                    _ => {}
                }
                if self.sym("(") {
                    self.pos += 1;
                    return self.call(&upper);
                }
                self.path(w)
            }
            other => Err(format!("Unexpected token {other:?}")),
        }
    }

    fn case(&mut self) -> Result<Expr, String> {
        let operand = if self.kw("WHEN") { None } else { Some(Box::new(self.expr()?)) };
        let mut whens = Vec::new();
        while self.eat_kw("WHEN") {
            let w = self.expr()?;
            self.expect_kw("THEN")?;
            whens.push((w, self.expr()?));
        }
        let otherwise = if self.eat_kw("ELSE") { Some(Box::new(self.expr()?)) } else { None };
        self.expect_kw("END")?;
        Ok(Expr::Case { operand, whens, otherwise })
    }

    fn call(&mut self, name: &str) -> Result<Expr, String> {
        match name {
            "CAST" => {
                let e = self.expr()?;
                self.expect_kw("AS")?;
                let ty = self.name()?.to_ascii_uppercase();
                self.expect_sym(")")?;
                Ok(Expr::Cast(Box::new(e), ty))
            }
            "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" => {
                let arg = if self.eat_sym("*") { None } else { Some(Box::new(self.expr()?)) };
                self.expect_sym(")")?;
                Ok(Expr::Agg { func: name.into(), arg })
            }
            "SUBSTRING" => {
                let s = self.expr()?;
                let mut args = vec![s];
                if self.eat_kw("FROM") || self.eat_sym(",") {
                    args.push(self.expr()?);
                    if self.eat_kw("FOR") || self.eat_sym(",") {
                        args.push(self.expr()?);
                    }
                }
                self.expect_sym(")")?;
                Ok(Expr::Func(name.into(), args))
            }
            "TRIM" => {
                let mut mode = "BOTH".to_string();
                for m in ["LEADING", "TRAILING", "BOTH"] {
                    if self.eat_kw(m) {
                        mode = m.into();
                    }
                }
                let mut chars = None;
                let first = if self.kw("FROM") { None } else { Some(self.expr()?) };
                let value = if self.eat_kw("FROM") {
                    chars = first;
                    self.expr()?
                } else {
                    first.ok_or("TRIM needs a value")?
                };
                self.expect_sym(")")?;
                let mut args = vec![value, Expr::Lit(Val::Str(mode))];
                if let Some(c) = chars {
                    args.push(c);
                }
                Ok(Expr::Func("TRIM".into(), args))
            }
            _ => {
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
                Ok(Expr::Func(name.into(), args))
            }
        }
    }

    fn path(&mut self, first: String) -> Result<Expr, String> {
        let mut steps = vec![Step::Key(first)];
        loop {
            if self.eat_sym(".") {
                if self.eat_sym("*") {
                    steps.push(Step::Key("*".into()));
                    continue;
                }
                steps.push(Step::Key(self.name()?));
            } else if self.eat_sym("[") {
                match self.next() {
                    Some(Tok::Num(n)) => steps.push(Step::Index(n.parse().map_err(|_| "Invalid index")?)),
                    Some(Tok::Str(s)) => steps.push(Step::Key(s)),
                    _ => return Err("Expected an index".into()),
                }
                self.expect_sym("]")?;
            } else {
                break;
            }
        }
        if steps.last() == Some(&Step::Key("*".into())) {
            return Ok(Expr::Star);
        }
        Ok(Expr::Path(steps))
    }
}

pub fn parse(sql: &str) -> Result<Query, String> {
    let toks = lex(sql)?;
    Parser { toks, pos: 0 }.query()
}

// ---- evaluation ---------------------------------------------------------------

/// One input record: CSV fields (with optional header names) or a JSON value.
pub enum Record<'a> {
    Csv { fields: &'a [String], header: Option<&'a [String]> },
    Json(&'a Json),
}

impl Record<'_> {
    fn lookup(&self, steps: &[Step], alias: Option<&str>) -> Val {
        let mut steps = steps;
        // Drop the FROM alias: `s._1`, `s.name`.
        if let (Some(Step::Key(first)), true) = (steps.first(), steps.len() > 1) {
            if alias.is_some_and(|a| a.eq_ignore_ascii_case(first)) || first.eq_ignore_ascii_case("S3Object") {
                steps = &steps[1..];
            }
        }
        match self {
            Record::Csv { fields, header } => {
                let [Step::Key(name)] = steps else { return Val::Missing };
                if let Some(n) = name.strip_prefix('_').and_then(|n| n.parse::<usize>().ok()) {
                    return fields.get(n.wrapping_sub(1)).map(|f| Val::Str(f.clone())).unwrap_or(Val::Missing);
                }
                if let Some(h) = header {
                    let pos = h
                        .iter()
                        .position(|c| c == name)
                        .or_else(|| h.iter().position(|c| c.eq_ignore_ascii_case(name)));
                    if let Some(i) = pos {
                        return fields.get(i).map(|f| Val::Str(f.clone())).unwrap_or(Val::Missing);
                    }
                }
                Val::Missing
            }
            Record::Json(v) => {
                let mut cur: &Json = v;
                for step in steps {
                    let next = match (step, cur) {
                        (Step::Key(k), Json::Object(m)) => {
                            m.get(k).or_else(|| m.iter().find(|(x, _)| x.eq_ignore_ascii_case(k)).map(|(_, v)| v))
                        }
                        (Step::Index(i), Json::Array(a)) => a.get(*i),
                        _ => None,
                    };
                    match next {
                        Some(n) => cur = n,
                        None => return Val::Missing,
                    }
                }
                Val::from_json(cur)
            }
        }
    }
}

pub struct Ctx<'a> {
    pub record: Record<'a>,
    pub alias: Option<&'a str>,
}

fn cmp(a: &Val, b: &Val) -> Option<Ordering> {
    match (a, b) {
        (Val::Str(x), Val::Str(y)) => Some(x.cmp(y)),
        (Val::Bool(x), Val::Bool(y)) => Some(x.cmp(y)),
        _ => {
            let (x, y) = (a.number()?, b.number()?);
            x.partial_cmp(&y)
        }
    }
}

fn like(value: &str, pattern: &str, escape: Option<char>) -> bool {
    fn go(v: &[char], p: &[char], esc: Option<char>) -> bool {
        match p.first() {
            None => v.is_empty(),
            Some(c) if Some(*c) == esc && p.len() > 1 => v.first() == Some(&p[1]) && go(&v[1..], &p[2..], esc),
            Some('%') => (0..=v.len()).any(|i| go(&v[i..], &p[1..], esc)),
            Some('_') => !v.is_empty() && go(&v[1..], &p[1..], esc),
            Some(c) => v.first() == Some(c) && go(&v[1..], &p[1..], esc),
        }
    }
    let v: Vec<char> = value.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    go(&v, &p, escape)
}

fn arith(op: &str, a: &Val, b: &Val) -> Result<Val, String> {
    if a.is_null() || b.is_null() {
        return Ok(Val::Null);
    }
    if let (Val::Int(x), Val::Int(y)) = (a, b) {
        return Ok(match op {
            "+" => Val::Int(x.wrapping_add(*y)),
            "-" => Val::Int(x.wrapping_sub(*y)),
            "*" => Val::Int(x.wrapping_mul(*y)),
            "/" if *y == 0 => return Err("Division by zero".into()),
            "/" => Val::Int(x / y),
            "%" if *y == 0 => return Err("Division by zero".into()),
            _ => Val::Int(x % y),
        });
    }
    let (x, y) = (
        a.number().ok_or_else(|| format!("Cannot use {a:?} in arithmetic"))?,
        b.number().ok_or_else(|| format!("Cannot use {b:?} in arithmetic"))?,
    );
    Ok(Val::Float(match op {
        "+" => x + y,
        "-" => x - y,
        "*" => x * y,
        "/" => x / y,
        _ => x % y,
    }))
}

pub fn cast(v: Val, ty: &str) -> Result<Val, String> {
    if v.is_null() {
        return Ok(v);
    }
    let fail = |v: &Val| format!("Cannot cast {} to {ty}", v.to_text());
    Ok(match ty {
        "INT" | "INTEGER" | "BIGINT" | "SMALLINT" => match &v {
            Val::Int(_) => v,
            Val::Float(f) => Val::Int(*f as i64),
            Val::Bool(b) => Val::Int(i64::from(*b)),
            Val::Str(s) => {
                let t = s.trim();
                t.parse::<i64>()
                    .map(Val::Int)
                    .or_else(|_| t.parse::<f64>().map(|f| Val::Int(f as i64)))
                    .map_err(|_| fail(&v))?
            }
            _ => return Err(fail(&v)),
        },
        "FLOAT" | "DOUBLE" | "REAL" | "DECIMAL" | "NUMERIC" => match &v {
            Val::Int(i) => Val::Float(*i as f64),
            Val::Float(_) => v,
            Val::Str(s) => Val::Float(s.trim().parse().map_err(|_| fail(&v))?),
            _ => return Err(fail(&v)),
        },
        "STRING" | "VARCHAR" | "CHAR" => Val::Str(v.to_text()),
        "BOOL" | "BOOLEAN" => Val::Bool(v.truthy().ok_or_else(|| fail(&v))?),
        "TIMESTAMP" => {
            let s = v.to_text();
            chrono::DateTime::parse_from_rfc3339(s.trim()).map_err(|_| fail(&v))?;
            Val::Str(s)
        }
        other => return Err(format!("Unsupported CAST type {other}")),
    })
}

impl Ctx<'_> {
    pub fn eval(&self, e: &Expr) -> Result<Val, String> {
        Ok(match e {
            Expr::Lit(v) => v.clone(),
            Expr::Path(steps) => self.record.lookup(steps, self.alias),
            Expr::Star => match &self.record {
                Record::Json(v) => Val::from_json(v),
                Record::Csv { .. } => return Err("* is only allowed in the projection".into()),
            },
            Expr::Unary(op, a) => {
                let v = self.eval(a)?;
                match op.as_str() {
                    "NOT" => match v.truthy() {
                        Some(b) => Val::Bool(!b),
                        None => Val::Null,
                    },
                    _ => arith("-", &Val::Int(0), &v)?,
                }
            }
            Expr::Binary(op, a, b) => match op.as_str() {
                "AND" => {
                    let (x, y) = (self.eval(a)?.truthy(), self.eval(b)?.truthy());
                    match (x, y) {
                        (Some(false), _) | (_, Some(false)) => Val::Bool(false),
                        (Some(true), Some(true)) => Val::Bool(true),
                        _ => Val::Null,
                    }
                }
                "OR" => {
                    let (x, y) = (self.eval(a)?.truthy(), self.eval(b)?.truthy());
                    match (x, y) {
                        (Some(true), _) | (_, Some(true)) => Val::Bool(true),
                        (Some(false), Some(false)) => Val::Bool(false),
                        _ => Val::Null,
                    }
                }
                "||" => {
                    let (x, y) = (self.eval(a)?, self.eval(b)?);
                    if x.is_null() || y.is_null() {
                        Val::Null
                    } else {
                        Val::Str(x.to_text() + &y.to_text())
                    }
                }
                "+" | "-" | "*" | "/" | "%" => arith(op, &self.eval(a)?, &self.eval(b)?)?,
                _ => {
                    let (x, y) = (self.eval(a)?, self.eval(b)?);
                    if x.is_null() || y.is_null() {
                        return Ok(Val::Null);
                    }
                    let Some(o) = cmp(&x, &y) else { return Ok(Val::Bool(op == "!=")) };
                    Val::Bool(match op.as_str() {
                        "=" => o == Ordering::Equal,
                        "!=" => o != Ordering::Equal,
                        "<" => o == Ordering::Less,
                        ">" => o == Ordering::Greater,
                        "<=" => o != Ordering::Greater,
                        _ => o != Ordering::Less,
                    })
                }
            },
            Expr::Like { value, pattern, escape, negated } => {
                let (v, p) = (self.eval(value)?, self.eval(pattern)?);
                if v.is_null() || p.is_null() {
                    return Ok(Val::Null);
                }
                let esc = match escape {
                    Some(e) => self.eval(e)?.to_text().chars().next(),
                    None => None,
                };
                Val::Bool(like(&v.to_text(), &p.to_text(), esc) != *negated)
            }
            Expr::In { value, list, negated } => {
                let v = self.eval(value)?;
                if v.is_null() {
                    return Ok(Val::Null);
                }
                let mut found = false;
                for item in list {
                    if cmp(&v, &self.eval(item)?) == Some(Ordering::Equal) {
                        found = true;
                        break;
                    }
                }
                Val::Bool(found != *negated)
            }
            Expr::Between { value, low, high, negated } => {
                let (v, l, h) = (self.eval(value)?, self.eval(low)?, self.eval(high)?);
                if v.is_null() {
                    return Ok(Val::Null);
                }
                let inside = cmp(&v, &l).is_some_and(|o| o != Ordering::Less)
                    && cmp(&v, &h).is_some_and(|o| o != Ordering::Greater);
                Val::Bool(inside != *negated)
            }
            Expr::IsNull { value, negated, missing } => {
                let v = self.eval(value)?;
                let is = if *missing { v == Val::Missing } else { v.is_null() };
                Val::Bool(is != *negated)
            }
            Expr::Cast(a, ty) => cast(self.eval(a)?, ty)?,
            Expr::Case { operand, whens, otherwise } => {
                let base = match operand {
                    Some(o) => Some(self.eval(o)?),
                    None => None,
                };
                for (w, then) in whens {
                    let hit = match &base {
                        Some(b) => cmp(b, &self.eval(w)?) == Some(Ordering::Equal),
                        None => self.eval(w)?.truthy() == Some(true),
                    };
                    if hit {
                        return self.eval(then);
                    }
                }
                match otherwise {
                    Some(e) => self.eval(e)?,
                    None => Val::Null,
                }
            }
            Expr::Func(name, args) => self.func(name, args)?,
            Expr::Agg { .. } => return Err("Aggregate functions are not allowed here".into()),
        })
    }

    fn func(&self, name: &str, args: &[Expr]) -> Result<Val, String> {
        let vals: Vec<Val> = args.iter().map(|a| self.eval(a)).collect::<Result<_, _>>()?;
        let text = |i: usize| vals.get(i).map(Val::to_text).unwrap_or_default();
        let null_arg = vals.first().is_some_and(Val::is_null);
        Ok(match name {
            "LOWER" if null_arg => Val::Null,
            "LOWER" => Val::Str(text(0).to_lowercase()),
            "UPPER" if null_arg => Val::Null,
            "UPPER" => Val::Str(text(0).to_uppercase()),
            "CHAR_LENGTH" | "CHARACTER_LENGTH" if null_arg => Val::Null,
            "CHAR_LENGTH" | "CHARACTER_LENGTH" => Val::Int(text(0).chars().count() as i64),
            "COALESCE" => vals.into_iter().find(|v| !v.is_null()).unwrap_or(Val::Null),
            "NULLIF" => {
                if vals.len() == 2 && cmp(&vals[0], &vals[1]) == Some(Ordering::Equal) {
                    Val::Null
                } else {
                    vals.into_iter().next().unwrap_or(Val::Null)
                }
            }
            "SUBSTRING" if null_arg => Val::Null,
            "SUBSTRING" => {
                let s: Vec<char> = text(0).chars().collect();
                let start = vals.get(1).and_then(Val::number).unwrap_or(1.0) as i64;
                let len = vals.get(2).and_then(Val::number).map(|l| l as i64);
                // SQL positions start at 1; a start below 1 eats into the length.
                let from = (start - 1).max(0) as usize;
                let end = match len {
                    Some(l) => ((start - 1 + l).max(0) as usize).min(s.len()),
                    None => s.len(),
                };
                Val::Str(if from < end { s[from..end].iter().collect() } else { String::new() })
            }
            "TRIM" if null_arg => Val::Null,
            "TRIM" => {
                let chars: Vec<char> = vals.get(2).map(|c| c.to_text().chars().collect()).unwrap_or_else(|| vec![' ']);
                let s = text(0);
                let s = match text(1).as_str() {
                    "LEADING" => s.trim_start_matches(chars.as_slice()).to_string(),
                    "TRAILING" => s.trim_end_matches(chars.as_slice()).to_string(),
                    _ => s.trim_matches(chars.as_slice()).to_string(),
                };
                Val::Str(s)
            }
            "UTCNOW" => Val::Str(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            other => return Err(format!("Unsupported function {other}")),
        })
    }
}

/// The column name for a projection without an alias, as S3 Select names it.
pub fn column_name(p: &Projection, index: usize) -> String {
    if let Some(a) = &p.alias {
        return a.clone();
    }
    match &p.expr {
        Expr::Path(steps) => match steps.last() {
            Some(Step::Key(k)) => k.clone(),
            _ => format!("_{}", index + 1),
        },
        _ => format!("_{}", index + 1),
    }
}

/// Running state of one aggregate.
#[derive(Debug, Clone)]
pub struct Agg {
    count: i64,
    sum: f64,
    int_sum: Option<i64>,
    min: Option<Val>,
    max: Option<Val>,
}

pub fn collect_aggs(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Agg { .. } => out.push(e.clone()),
        Expr::Unary(_, a) | Expr::Cast(a, _) => collect_aggs(a, out),
        Expr::Binary(_, a, b) => {
            collect_aggs(a, out);
            collect_aggs(b, out);
        }
        Expr::Func(_, args) => args.iter().for_each(|a| collect_aggs(a, out)),
        _ => {}
    }
}

impl Default for Agg {
    fn default() -> Self {
        // An integer sum until a non-integer (or an overflow) turns up.
        Agg { count: 0, sum: 0.0, int_sum: Some(0), min: None, max: None }
    }
}

impl Agg {
    pub fn add(&mut self, func: &str, v: Option<Val>) -> Result<(), String> {
        let Some(v) = v else {
            self.count += 1;
            return Ok(());
        };
        if v.is_null() {
            return Ok(());
        }
        self.count += 1;
        match func {
            "SUM" | "AVG" => {
                let n = v.number().ok_or_else(|| format!("Cannot aggregate {}", v.to_text()))?;
                self.sum += n;
                self.int_sum = match (&v, self.int_sum) {
                    (Val::Int(i), Some(s)) => s.checked_add(*i),
                    _ => None,
                };
            }
            "MIN" if self.min.as_ref().is_none_or(|m| cmp(&v, m) == Some(Ordering::Less)) => self.min = Some(v),
            "MAX" if self.max.as_ref().is_none_or(|m| cmp(&v, m) == Some(Ordering::Greater)) => self.max = Some(v),
            _ => {}
        }
        Ok(())
    }

    pub fn result(&self, func: &str) -> Val {
        match func {
            "COUNT" => Val::Int(self.count),
            "SUM" if self.count == 0 => Val::Null,
            "SUM" => self.int_sum.map(Val::Int).unwrap_or(Val::Float(self.sum)),
            "AVG" if self.count == 0 => Val::Null,
            "AVG" => Val::Float(self.sum / self.count as f64),
            "MIN" => self.min.clone().unwrap_or(Val::Null),
            _ => self.max.clone().unwrap_or(Val::Null),
        }
    }
}

/// Replace aggregates in `e` by their results.
pub fn substitute(e: &Expr, results: &[(Expr, Val)]) -> Expr {
    match e {
        Expr::Agg { .. } => {
            Expr::Lit(results.iter().find(|(x, _)| x == e).map(|(_, v)| v.clone()).unwrap_or(Val::Null))
        }
        Expr::Unary(op, a) => Expr::Unary(op.clone(), Box::new(substitute(a, results))),
        Expr::Cast(a, t) => Expr::Cast(Box::new(substitute(a, results)), t.clone()),
        Expr::Binary(op, a, b) => {
            Expr::Binary(op.clone(), Box::new(substitute(a, results)), Box::new(substitute(b, results)))
        }
        Expr::Func(n, args) => Expr::Func(n.clone(), args.iter().map(|a| substitute(a, results)).collect()),
        other => other.clone(),
    }
}

/// A JSON object for a projected row.
pub fn json_row(names: &[String], vals: Vec<Val>) -> Json {
    let mut m = Map::new();
    for (n, v) in names.iter().zip(vals) {
        if v != Val::Missing {
            m.insert(n.clone(), v.to_json());
        }
    }
    Json::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval_csv(sql: &str, fields: &[&str], header: Option<&[&str]>) -> Vec<Val> {
        let q = parse(sql).unwrap();
        let fields: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        let header: Option<Vec<String>> = header.map(|h| h.iter().map(|s| s.to_string()).collect());
        let ctx = Ctx { record: Record::Csv { fields: &fields, header: header.as_deref() }, alias: q.alias.as_deref() };
        if let Some(f) = &q.filter {
            if ctx.eval(f).unwrap().truthy() != Some(true) {
                return vec![];
            }
        }
        q.projections.iter().map(|p| ctx.eval(&p.expr).unwrap()).collect()
    }

    #[test]
    fn csv_queries() {
        assert_eq!(eval_csv("select s._2 from S3Object s", &["a", "b"], None), vec![Val::Str("b".into())]);
        assert_eq!(
            eval_csv("SELECT name FROM S3Object WHERE CAST(age AS INT) > 30", &["bob", "41"], Some(&["name", "age"])),
            vec![Val::Str("bob".into())]
        );
        assert!(eval_csv(
            "SELECT name FROM S3Object WHERE CAST(age AS INT) > 50",
            &["bob", "41"],
            Some(&["name", "age"])
        )
        .is_empty());
        assert_eq!(
            eval_csv("SELECT UPPER(s.name) || '!' FROM S3Object s WHERE s.name LIKE 'b%'", &["bob"], Some(&["name"])),
            vec![Val::Str("BOB!".into())]
        );
        assert_eq!(
            eval_csv("SELECT SUBSTRING(_1 FROM 2 FOR 3) FROM S3Object", &["abcdef"], None),
            vec![Val::Str("bcd".into())]
        );
        assert_eq!(
            eval_csv("SELECT _1 FROM S3Object WHERE _1 IN ('x', 'y')", &["y"], None),
            vec![Val::Str("y".into())]
        );
        assert_eq!(
            eval_csv(
                "SELECT CASE WHEN CAST(_1 AS INT) BETWEEN 1 AND 3 THEN 'low' ELSE 'high' END FROM S3Object",
                &["2"],
                None
            ),
            vec![Val::Str("low".into())]
        );
    }

    #[test]
    fn json_paths() {
        let q = parse("SELECT s.a.b[1] AS x FROM S3Object[*] s WHERE s.a.c IS MISSING").unwrap();
        let rec = serde_json::json!({"a": {"b": [1, 2]}});
        let ctx = Ctx { record: Record::Json(&rec), alias: q.alias.as_deref() };
        assert_eq!(ctx.eval(q.filter.as_ref().unwrap()).unwrap(), Val::Bool(true));
        assert_eq!(ctx.eval(&q.projections[0].expr).unwrap(), Val::Int(2));
        assert_eq!(column_name(&q.projections[0], 0), "x");
    }

    #[test]
    fn aggregates() {
        let q = parse("SELECT COUNT(*), SUM(CAST(_1 AS INT)), AVG(CAST(_1 AS FLOAT)), MAX(_1) FROM S3Object").unwrap();
        assert!(q.is_aggregate());
        let mut aggs = Vec::new();
        for p in &q.projections {
            collect_aggs(&p.expr, &mut aggs);
        }
        assert_eq!(aggs.len(), 4);
        let mut state = vec![Agg::default(); 4];
        for row in ["1", "2", "3"] {
            let fields = vec![row.to_string()];
            let ctx = Ctx { record: Record::Csv { fields: &fields, header: None }, alias: None };
            for (i, a) in aggs.iter().enumerate() {
                let Expr::Agg { func, arg } = a else { unreachable!() };
                let v = arg.as_ref().map(|e| ctx.eval(e).unwrap());
                state[i].add(func, v).unwrap();
            }
        }
        let results: Vec<Val> = aggs
            .iter()
            .zip(&state)
            .map(|(a, s)| match a {
                Expr::Agg { func, .. } => s.result(func),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(results, vec![Val::Int(3), Val::Int(6), Val::Float(2.0), Val::Str("3".into())]);
    }
}
