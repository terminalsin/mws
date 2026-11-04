//! Composite alarm rules: `ALARM("a") AND NOT (OK(b) OR TRUE)`,
//! `AT_LEAST(2, ALARM, ("a", "b", "c"))`. Alarms are named by name or ARN.

use std::collections::BTreeSet;

use crate::state::Region;

#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    Const(bool),
    State(String, String),
    Not(Box<Rule>),
    And(Box<Rule>, Box<Rule>),
    Or(Box<Rule>, Box<Rule>),
    AtLeast { count: Option<u32>, percent: Option<f64>, state: String, alarms: Vec<String> },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Open,
    Close,
    Comma,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        match c[i] {
            ch if ch.is_whitespace() => i += 1,
            '(' => {
                out.push(Tok::Open);
                i += 1;
            }
            ')' => {
                out.push(Tok::Close);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '"' => {
                i += 1;
                let st = i;
                while i < c.len() && c[i] != '"' {
                    i += 1;
                }
                if i >= c.len() {
                    return Err("Error in alarm rule: unterminated quoted alarm name".into());
                }
                out.push(Tok::Quoted(c[st..i].iter().collect()));
                i += 1;
            }
            _ => {
                let st = i;
                while i < c.len() && !c[i].is_whitespace() && !matches!(c[i], '(' | ')' | ',' | '"') {
                    i += 1;
                }
                out.push(Tok::Word(c[st..i].iter().collect()));
            }
        }
    }
    Ok(out)
}

fn alarm_name(r: &str) -> String {
    match r.split_once(":alarm:") {
        Some((_, n)) => n.to_string(),
        None => r.to_string(),
    }
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn kw(&self, w: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Word(x)) if x.eq_ignore_ascii_case(w))
    }

    fn expect(&mut self, t: Tok) -> Result<(), String> {
        if self.t.get(self.i) == Some(&t) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("Error in alarm rule: expected {t:?}"))
        }
    }

    fn or(&mut self) -> Result<Rule, String> {
        let mut l = self.and()?;
        while self.kw("OR") {
            self.i += 1;
            l = Rule::Or(Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }

    fn and(&mut self) -> Result<Rule, String> {
        let mut l = self.not()?;
        while self.kw("AND") {
            self.i += 1;
            l = Rule::And(Box::new(l), Box::new(self.not()?));
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Rule, String> {
        if self.kw("NOT") {
            self.i += 1;
            return Ok(Rule::Not(Box::new(self.not()?)));
        }
        self.atom()
    }

    fn reference(&mut self) -> Result<String, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Quoted(s)) | Some(Tok::Word(s)) => {
                self.i += 1;
                Ok(alarm_name(&s))
            }
            _ => Err("Error in alarm rule: expected an alarm name or ARN".into()),
        }
    }

    fn atom(&mut self) -> Result<Rule, String> {
        let tok = self.t.get(self.i).cloned().ok_or("Error in alarm rule: unexpected end of rule")?;
        self.i += 1;
        match tok {
            Tok::Open => {
                let r = self.or()?;
                self.expect(Tok::Close)?;
                Ok(r)
            }
            Tok::Word(w) => match w.to_ascii_uppercase().as_str() {
                "TRUE" => Ok(Rule::Const(true)),
                "FALSE" => Ok(Rule::Const(false)),
                s @ ("ALARM" | "OK" | "INSUFFICIENT_DATA") => {
                    let s = s.to_string();
                    self.expect(Tok::Open)?;
                    let name = self.reference()?;
                    self.expect(Tok::Close)?;
                    Ok(Rule::State(s, name))
                }
                "AT_LEAST" => {
                    self.expect(Tok::Open)?;
                    let n = match self.t.get(self.i).cloned() {
                        Some(Tok::Word(n)) => n,
                        _ => return Err("Error in alarm rule: AT_LEAST expects a threshold".into()),
                    };
                    self.i += 1;
                    let (count, percent) = match n.strip_suffix('%') {
                        Some(p) => (
                            None,
                            Some(p.parse::<f64>().map_err(|_| "Error in alarm rule: invalid AT_LEAST percentage")?),
                        ),
                        None => {
                            (Some(n.parse::<u32>().map_err(|_| "Error in alarm rule: invalid AT_LEAST count")?), None)
                        }
                    };
                    self.expect(Tok::Comma)?;
                    let state = match self.t.get(self.i).cloned() {
                        Some(Tok::Word(s))
                            if matches!(
                                s.as_str(),
                                "ALARM" | "OK" | "INSUFFICIENT_DATA" | "NOT_ALARM" | "NOT_OK" | "NOT_INSUFFICIENT_DATA"
                            ) =>
                        {
                            s
                        }
                        _ => return Err("Error in alarm rule: AT_LEAST expects an alarm state".into()),
                    };
                    self.i += 1;
                    self.expect(Tok::Comma)?;
                    self.expect(Tok::Open)?;
                    let mut alarms = vec![self.reference()?];
                    while self.t.get(self.i) == Some(&Tok::Comma) {
                        self.i += 1;
                        alarms.push(self.reference()?);
                    }
                    self.expect(Tok::Close)?;
                    self.expect(Tok::Close)?;
                    Ok(Rule::AtLeast { count, percent, state, alarms })
                }
                other => Err(format!("Error in alarm rule: unexpected token {other}")),
            },
            _ => Err("Error in alarm rule: unexpected token".into()),
        }
    }
}

impl Rule {
    pub fn parse(s: &str) -> Result<Rule, String> {
        let mut p = P { t: lex(s)?, i: 0 };
        let r = p.or()?;
        if p.i != p.t.len() {
            return Err("Error in alarm rule: unexpected trailing tokens".into());
        }
        Ok(r)
    }

    /// The alarms the rule names.
    pub fn alarms(&self) -> Vec<String> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out.into_iter().collect()
    }

    fn collect(&self, out: &mut BTreeSet<String>) {
        match self {
            Rule::State(_, n) => {
                out.insert(n.clone());
            }
            Rule::Not(r) => r.collect(out),
            Rule::And(a, b) | Rule::Or(a, b) => {
                a.collect(out);
                b.collect(out);
            }
            Rule::AtLeast { alarms, .. } => out.extend(alarms.iter().cloned()),
            Rule::Const(_) => {}
        }
    }

    /// Whether the rule holds, given each alarm's state.
    pub fn eval(&self, state: &dyn Fn(&str) -> Option<String>) -> bool {
        match self {
            Rule::Const(b) => *b,
            Rule::State(s, n) => state(n).as_deref() == Some(s.as_str()),
            Rule::Not(r) => !r.eval(state),
            Rule::And(a, b) => a.eval(state) && b.eval(state),
            Rule::Or(a, b) => a.eval(state) || b.eval(state),
            Rule::AtLeast { count, percent, state: want, alarms } => {
                let hits = alarms
                    .iter()
                    .filter(|n| {
                        let s = state(n).unwrap_or_default();
                        match want.strip_prefix("NOT_") {
                            Some(w) => s != w,
                            None => &s == want,
                        }
                    })
                    .count();
                match (count, percent) {
                    (Some(c), _) => hits as u32 >= *c,
                    (_, Some(p)) => hits as f64 * 100.0 >= p * alarms.len() as f64,
                    _ => false,
                }
            }
        }
    }
}

/// Whether making `name`'s rule `rule` would create a cycle of composite
/// alarms.
pub fn creates_cycle(region: &Region, name: &str, rule: &Rule) -> bool {
    let mut stack = rule.alarms();
    let mut seen = BTreeSet::new();
    while let Some(n) = stack.pop() {
        if n == name {
            return true;
        }
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(c) = region.alarms.get(&n).and_then(|a| a.composite.as_ref()) {
            if let Ok(r) = Rule::parse(&c.alarm_rule) {
                stack.extend(r.alarms());
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_evaluates() {
        let r = Rule::parse("ALARM(\"cpu\") AND NOT OK(arn:aws:cloudwatch:us-east-1:1:alarm:mem) OR FALSE").unwrap();
        assert_eq!(r.alarms(), vec!["cpu".to_string(), "mem".to_string()]);
        let st = |_: &str| Some("ALARM".to_string());
        assert!(r.eval(&st));
        let r = Rule::parse("AT_LEAST(2, ALARM, (a, \"b\", c))").unwrap();
        let st = |n: &str| Some(if n == "c" { "OK".to_string() } else { "ALARM".to_string() });
        assert!(r.eval(&st));
        assert!(Rule::parse("ALARM(a) AND").is_err());
        assert!(Rule::parse("BOGUS(a)").is_err());
    }
}
