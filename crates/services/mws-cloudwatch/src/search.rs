//! The search expressions of metric math `SEARCH()`:
//! `{Namespace,DimName,...} MetricName="CPUUtilization" OR prod`.
//!
//! A schema in braces keeps metrics of that namespace with exactly those
//! dimension names. Terms are `Key=value` (`MetricName`, `Namespace` or a
//! dimension name; quoted values match exactly, bare ones as a token) or
//! free text (a token of the namespace, name or a dimension), combined
//! with `AND` (the default), `OR`, `NOT` and parentheses.

use crate::state::MetricKey;

#[derive(Debug, Clone)]
pub struct Filter {
    schema: Option<(String, Vec<String>)>,
    term: Option<Term>,
}

#[derive(Debug, Clone)]
enum Term {
    Field { key: String, value: String, exact: bool },
    Text { value: String, exact: bool },
    And(Box<Term>, Box<Term>),
    Or(Box<Term>, Box<Term>),
    Not(Box<Term>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Eq,
    Open,
    Close,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        match c[i] {
            ' ' | '\t' | '\n' => i += 1,
            '=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            '(' => {
                out.push(Tok::Open);
                i += 1;
            }
            ')' => {
                out.push(Tok::Close);
                i += 1;
            }
            '"' => {
                i += 1;
                let mut t = String::new();
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        i += 1;
                    }
                    t.push(c[i]);
                    i += 1;
                }
                if i >= c.len() {
                    return Err("Unterminated quoted term in search expression".into());
                }
                i += 1;
                out.push(Tok::Quoted(t));
            }
            _ => {
                let st = i;
                while i < c.len() && !matches!(c[i], ' ' | '\t' | '\n' | '=' | '(' | ')' | '"') {
                    i += 1;
                }
                out.push(Tok::Word(c[st..i].iter().collect()));
            }
        }
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn word(&self, w: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Word(x)) if x == w)
    }

    fn or(&mut self) -> Result<Term, String> {
        let mut l = self.and()?;
        while self.word("OR") {
            self.i += 1;
            l = Term::Or(Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Term, String> {
        let mut l = self.not()?;
        loop {
            if self.word("AND") {
                self.i += 1;
            } else if self.i >= self.t.len() || self.word("OR") || self.t[self.i] == Tok::Close {
                return Ok(l);
            }
            l = Term::And(Box::new(l), Box::new(self.not()?));
        }
    }

    fn not(&mut self) -> Result<Term, String> {
        if self.word("NOT") {
            self.i += 1;
            return Ok(Term::Not(Box::new(self.not()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Term, String> {
        let t = self.t.get(self.i).cloned().ok_or("Unexpected end of search expression")?;
        self.i += 1;
        match t {
            Tok::Open => {
                let e = self.or()?;
                if self.t.get(self.i) != Some(&Tok::Close) {
                    return Err("Unbalanced parentheses in search expression".into());
                }
                self.i += 1;
                Ok(e)
            }
            Tok::Word(w) | Tok::Quoted(w) if self.t.get(self.i) == Some(&Tok::Eq) => {
                self.i += 1;
                match self.t.get(self.i).cloned() {
                    Some(Tok::Quoted(v)) => {
                        self.i += 1;
                        Ok(Term::Field { key: w, value: v, exact: true })
                    }
                    Some(Tok::Word(v)) => {
                        self.i += 1;
                        Ok(Term::Field { key: w, value: v, exact: false })
                    }
                    _ => Err(format!("Expected a value after {w}=")),
                }
            }
            Tok::Quoted(v) => Ok(Term::Text { value: v, exact: true }),
            Tok::Word(v) => Ok(Term::Text { value: v, exact: false }),
            Tok::Close | Tok::Eq => Err("Unexpected token in search expression".into()),
        }
    }
}

pub fn parse(s: &str) -> Result<Filter, String> {
    let s = s.trim();
    let (schema, rest) = match s.strip_prefix('{') {
        Some(r) => {
            let (inner, rest) = r.split_once('}').ok_or("Unterminated schema in search expression")?;
            let parts: Vec<String> =
                inner.split(',').map(|p| p.trim().trim_matches('"').to_string()).filter(|p| !p.is_empty()).collect();
            let ns = parts.first().cloned().ok_or("The schema must name a namespace")?;
            (Some((ns, parts[1..].to_vec())), rest)
        }
        None => (None, s),
    };
    let toks = lex(rest)?;
    let term = if toks.is_empty() {
        None
    } else {
        let mut p = P { t: toks, i: 0 };
        let t = p.or()?;
        if p.i != p.t.len() {
            return Err("Unexpected token in search expression".into());
        }
        Some(t)
    };
    if schema.is_none() && term.is_none() {
        return Err("The search expression is empty".into());
    }
    Ok(Filter { schema, term })
}

fn tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty())
}

fn partial(hay: &str, needle: &str) -> bool {
    let n = needle.to_ascii_lowercase();
    hay == needle || tokens(hay).any(|t| t.to_ascii_lowercase() == n) || hay.to_ascii_lowercase().contains(&n)
}

impl Term {
    fn matches(&self, k: &MetricKey) -> bool {
        match self {
            Term::And(a, b) => a.matches(k) && b.matches(k),
            Term::Or(a, b) => a.matches(k) || b.matches(k),
            Term::Not(a) => !a.matches(k),
            Term::Field { key, value, exact } => {
                let test = |v: &str| if *exact { v == value } else { partial(v, value) };
                match key.as_str() {
                    "MetricName" => test(&k.name),
                    "Namespace" => test(&k.namespace),
                    d => k.dimensions.iter().any(|(n, v)| n == d && test(v)),
                }
            }
            Term::Text { value, exact } => {
                let test = |v: &str| if *exact { v == value } else { partial(v, value) };
                test(&k.namespace) || test(&k.name) || k.dimensions.iter().any(|(n, v)| test(n) || test(v))
            }
        }
    }
}

impl Filter {
    pub fn matches(&self, k: &MetricKey) -> bool {
        if let Some((ns, dims)) = &self.schema {
            if &k.namespace != ns {
                return false;
            }
            let mut want: Vec<&str> = dims.iter().map(String::as_str).collect();
            let mut have: Vec<&str> = k.dimensions.iter().map(|(n, _)| n.as_str()).collect();
            want.sort_unstable();
            have.sort_unstable();
            if want != have {
                return false;
            }
        }
        self.term.as_ref().is_none_or(|t| t.matches(k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ns: &str, name: &str, dims: &[(&str, &str)]) -> MetricKey {
        MetricKey {
            namespace: ns.into(),
            name: name.into(),
            dimensions: dims.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        }
    }

    #[test]
    fn matches_schema_and_terms() {
        let f = parse("{App,Host} MetricName=\"Latency\"").unwrap();
        assert!(f.matches(&key("App", "Latency", &[("Host", "a")])));
        assert!(!f.matches(&key("App", "Latency", &[("Host", "a"), ("Az", "b")])));
        assert!(!f.matches(&key("App", "Errors", &[("Host", "a")])));
        let f = parse("Latency OR Errors NOT prod").unwrap();
        assert!(f.matches(&key("App", "Errors", &[("Stage", "dev")])));
        let f = parse("Host=web").unwrap();
        assert!(f.matches(&key("App", "X", &[("Host", "web-1")])));
    }
}
