//! The other two Logs Insights query languages, OpenSearch SQL and
//! OpenSearch PPL, compiled into the same commands the Logs Insights
//! language runs as ([`insights::Command`]).
//!
//! * SQL: `SELECT [DISTINCT] items | * FROM <log group> [WHERE ...]
//!   [GROUP BY ...] [HAVING ...] [ORDER BY ... [ASC|DESC]] [LIMIT n]`,
//!   where the log group is `` `name` `` or
//!   `` `logGroups(logGroupIdentifier: ['a', 'b'])` ``.
//! * PPL: `fields [-]`, `where`, `eval`, `stats ... by`, `sort [-]`,
//!   `head`, `rename`, `dedup`, `top`, `rare`, `parse` and `fillnull`,
//!   on the log groups the request names.
//!
//! Expressions take the SQL forms (`IS NULL`, `BETWEEN`, `IN (...)`,
//! `LIKE '%x_'`) and OpenSearch function names (`lower`, `length`,
//! `substring`, `dc`, `percentile`, `span`, ...).
//!
//! Specs: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_SQL.html>
//! and <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData_PPL.html>.

use regex::Regex;

use crate::insights::{self, contains_aggregate, tokenize, Command, Expr, Named, Query, Tok, AGGREGATES, P};

/// A query ready to run, and the log groups it names itself (SQL `FROM`,
/// PPL `source`).
#[derive(Debug)]
pub struct Compiled {
    pub query: Query,
    pub log_groups: Vec<String>,
}

/// Compile a query in `language` (`CWLI`, `SQL` or `PPL`).
pub fn compile(language: &str, text: &str) -> Result<Compiled, String> {
    match language {
        "SQL" => sql(text),
        "PPL" => ppl(text),
        _ => Ok(Compiled { query: insights::parse(text)?, log_groups: Vec::new() }),
    }
}

fn parser(toks: Vec<Tok>) -> P {
    P { toks, pos: 0, sql: true }
}

fn finish<T>(p: &P, value: T) -> Result<T, String> {
    if p.done() {
        Ok(value)
    } else {
        Err(format!("Syntax error: unexpected token {:?}", p.peek().expect("not done")))
    }
}

fn ident(t: Option<Tok>) -> Result<String, String> {
    match t {
        Some(Tok::Ident(n)) | Some(Tok::Str(n)) => Ok(n),
        other => Err(format!("Syntax error: expected a field name, found {other:?}")),
    }
}

/// Aggregate calls inside `e` become references to (possibly hidden)
/// columns that the `stats` computes.
fn hoist_aggregates(e: Expr, aggs: &mut Vec<Named>) -> Expr {
    match e {
        Expr::Call(name, args) if AGGREGATES.contains(&name.as_str()) => {
            let call = Expr::Call(name, args);
            let key = format!("{call:?}");
            if let Some(existing) = aggs.iter().find(|a| format!("{:?}", a.expr) == key) {
                return Expr::Field(existing.name.clone());
            }
            let name = format!("__agg{}", aggs.len());
            aggs.push(Named { expr: call, name: name.clone() });
            Expr::Field(name)
        }
        Expr::Call(name, args) => Expr::Call(name, args.into_iter().map(|a| hoist_aggregates(a, aggs)).collect()),
        Expr::Bin(op, a, b) => {
            Expr::Bin(op, Box::new(hoist_aggregates(*a, aggs)), Box::new(hoist_aggregates(*b, aggs)))
        }
        Expr::Not(a) => Expr::Not(Box::new(hoist_aggregates(*a, aggs))),
        Expr::Unary(c, a) => Expr::Unary(c, Box::new(hoist_aggregates(*a, aggs))),
        Expr::Like(a, b, n) => Expr::Like(Box::new(hoist_aggregates(*a, aggs)), b, n),
        Expr::In(a, items, n) => Expr::In(Box::new(hoist_aggregates(*a, aggs)), items, n),
        other => other,
    }
}

// ---- SQL ---------------------------------------------------------------------------

const CLAUSES: &[&str] = &["select", "from", "where", "group", "having", "order", "limit", "offset"];
const UNSUPPORTED: &[&str] = &["join", "union", "intersect", "except"];

/// `` logGroups(logGroupIdentifier: ['a', 'b']) `` or a plain name.
fn from_groups(text: &str) -> Result<Vec<String>, String> {
    let t = text.trim();
    if t.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("loggroups(")) {
        let re = Regex::new(r#"'([^']*)'|"([^"]*)""#).expect("valid regex");
        let groups: Vec<String> = re
            .captures_iter(t)
            .filter_map(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_string()))
            .filter(|g| !g.is_empty())
            .collect();
        if groups.is_empty() {
            return Err("logGroups() needs at least one logGroupIdentifier".into());
        }
        return Ok(groups);
    }
    Ok(vec![t.to_string()])
}

fn sql(text: &str) -> Result<Compiled, String> {
    let toks = tokenize(text.trim().trim_end_matches(';'))?;
    // Split into clauses at parenthesis depth 0.
    let mut clauses: Vec<(String, Vec<Tok>)> = Vec::new();
    let mut depth = 0i32;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        match t {
            Tok::LParen => depth += 1,
            Tok::RParen => depth -= 1,
            Tok::Ident(w) if depth == 0 => {
                let lw = w.to_lowercase();
                if UNSUPPORTED.contains(&lw.as_str()) || (lw == "select" && !clauses.is_empty()) {
                    return Err(format!("Unsupported SQL: {} is not supported", w.to_uppercase()));
                }
                if CLAUSES.contains(&lw.as_str()) {
                    if matches!(lw.as_str(), "group" | "order") {
                        match toks.get(i + 1) {
                            Some(Tok::Ident(b)) if b.eq_ignore_ascii_case("by") => i += 1,
                            _ => return Err(format!("Syntax error: expected BY after {}", w.to_uppercase())),
                        }
                    }
                    if clauses.iter().any(|(c, _)| *c == lw) {
                        return Err(format!("Syntax error: duplicate {} clause", w.to_uppercase()));
                    }
                    clauses.push((lw, Vec::new()));
                    i += 1;
                    continue;
                }
            }
            _ => {}
        }
        match clauses.last_mut() {
            Some((_, body)) => body.push(t.clone()),
            None => return Err("Syntax error: a SQL query starts with SELECT".into()),
        }
        i += 1;
    }
    let clause = |name: &str| clauses.iter().find(|(c, _)| c == name).map(|(_, b)| b.clone());
    let select = clause("select").ok_or("Syntax error: a SQL query starts with SELECT")?;
    let from = clause("from").ok_or("Syntax error: missing FROM clause; name the log group to query in FROM")?;

    let log_groups = match from.as_slice() {
        [Tok::Ident(t)] | [Tok::Str(t)] => from_groups(t)?,
        [Tok::Ident(t), Tok::Ident(_)] => from_groups(t)?,
        [Tok::Ident(t), Tok::Ident(a), Tok::Ident(_)] if a.eq_ignore_ascii_case("as") => from_groups(t)?,
        _ => return Err("Syntax error: FROM takes one log group, or `logGroups(logGroupIdentifier: [...])`".into()),
    };

    let mut p = parser(select);
    let distinct = p.eat_kw("distinct");
    let star = p.toks.len() == p.pos + 1 && p.at_op("*");
    let items = if star {
        Vec::new()
    } else {
        let l = p.named_list(None)?;
        finish(&p, l)?
    };

    let where_ = clause("where").map(parse_expr).transpose()?;
    let group_by = match clause("group") {
        Some(t) => {
            let mut p = parser(t);
            let l = p.named_list(None)?;
            finish(&p, l)?
        }
        None => Vec::new(),
    };
    let having = clause("having").map(parse_expr).transpose()?;
    let order = clause("order").map(sort_keys).transpose()?.unwrap_or_default();
    let limit = match clause("limit").as_deref() {
        None => None,
        Some([Tok::Num(n)]) if *n >= 1.0 => Some(*n as usize),
        Some(_) => return Err("Syntax error: LIMIT takes a positive number".into()),
    };

    let mut commands = Vec::new();
    if let Some(w) = where_ {
        commands.push(Command::Filter(w));
    }
    let aggregating = !group_by.is_empty() || items.iter().any(|i| contains_aggregate(&i.expr));
    if aggregating {
        if star {
            return Err("Syntax error: SELECT * cannot be used with GROUP BY or aggregate functions".into());
        }
        let mut by = group_by;
        let mut aggs = Vec::new();
        for item in &items {
            if contains_aggregate(&item.expr) {
                aggs.push(item.clone());
            } else if !by.iter().any(|b| b.name == item.name || format!("{:?}", b.expr) == format!("{:?}", item.expr)) {
                by.push(item.clone());
            }
        }
        let having = having.map(|h| hoist_aggregates(h, &mut aggs));
        let order: Vec<(Expr, bool)> = order.into_iter().map(|(e, d)| (hoist_aggregates(e, &mut aggs), d)).collect();
        // Group keys named like a select item take its alias.
        for b in &mut by {
            if let Some(item) = items.iter().find(|i| format!("{:?}", i.expr) == format!("{:?}", b.expr)) {
                b.name = item.name.clone();
            }
        }
        commands.push(Command::Stats { aggs, by });
        if let Some(h) = having {
            commands.push(Command::Filter(h));
        }
        if !order.is_empty() {
            commands.push(Command::Sort(order));
        }
        commands.push(Command::Display(items.iter().map(|i| i.name.clone()).collect()));
    } else {
        if having.is_some() {
            return Err("Syntax error: HAVING needs GROUP BY or an aggregate function".into());
        }
        if star {
            commands.push(Command::AllFields);
        } else {
            commands.push(Command::Fields(items.clone()));
        }
        if distinct && !star {
            commands.push(Command::Dedup(items.iter().map(|i| i.name.clone()).collect()));
        }
        if !order.is_empty() {
            commands.push(Command::Sort(order));
        }
    }
    if let Some(n) = limit {
        commands.push(Command::Limit(n.min(10_000)));
    }
    Ok(Compiled { query: Query { commands }, log_groups })
}

fn parse_expr(toks: Vec<Tok>) -> Result<Expr, String> {
    let mut p = parser(toks);
    let e = p.expr()?;
    finish(&p, e)
}

/// `a [ASC|DESC], b ...` (SQL) or `- a, + b, c desc` (PPL).
fn sort_keys(toks: Vec<Tok>) -> Result<Vec<(Expr, bool)>, String> {
    let mut p = parser(toks);
    let mut keys = Vec::new();
    loop {
        let mut desc = if p.at_op("-") {
            p.pos += 1;
            true
        } else {
            if p.at_op("+") {
                p.pos += 1;
            }
            false
        };
        let e = p.expr()?;
        if p.eat_kw("desc") {
            desc = true;
        } else {
            p.eat_kw("asc");
        }
        keys.push((e, desc));
        if p.peek() == Some(&Tok::Comma) {
            p.pos += 1;
            continue;
        }
        return finish(&p, keys);
    }
}

// ---- PPL ---------------------------------------------------------------------------

fn names(p: &mut P) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    loop {
        out.push(ident(p.next())?);
        if p.peek() == Some(&Tok::Comma) {
            p.pos += 1;
            continue;
        }
        return Ok(out);
    }
}

fn ppl(text: &str) -> Result<Compiled, String> {
    let mut commands = vec![Command::AllFields];
    let mut log_groups = Vec::new();
    for (n, part) in insights::split_commands(text).into_iter().enumerate() {
        let mut p = parser(tokenize(&part)?);
        let cmd = ident(p.next())?.to_lowercase();
        match cmd.as_str() {
            "source" | "search" if n == 0 => {
                // `source=lg` or `search source=lg`.
                if (cmd == "search" && !p.eat_kw("source")) || !p.at_op("=") {
                    return Err("Syntax error: expected source=<log group>".into());
                }
                p.pos += 1;
                log_groups = names(&mut p)?;
            }
            "fields" => {
                if p.at_op("-") {
                    p.pos += 1;
                    commands.push(Command::Remove(names(&mut p)?));
                } else {
                    if p.at_op("+") {
                        p.pos += 1;
                    }
                    let items = p.named_list(None)?;
                    commands.push(Command::Fields(items));
                }
            }
            "where" => commands.push(Command::Filter(p.expr()?)),
            "eval" => {
                let mut items = Vec::new();
                loop {
                    let name = ident(p.next())?;
                    if !p.at_op("=") {
                        return Err(format!("Syntax error: expected '=' after {name} in eval"));
                    }
                    p.pos += 1;
                    items.push(Named { expr: p.expr()?, name });
                    if p.peek() == Some(&Tok::Comma) {
                        p.pos += 1;
                        continue;
                    }
                    break;
                }
                commands.push(Command::Eval(items));
            }
            "stats" => {
                let aggs = p.named_list(Some("by"))?;
                let by = if p.eat_kw("by") { p.named_list(None)? } else { Vec::new() };
                if let Some(a) = aggs.iter().find(|a| !contains_aggregate(&a.expr)) {
                    return Err(format!("stats requires an aggregate function, found {}", a.name));
                }
                commands.push(Command::Stats { aggs, by });
            }
            "sort" => {
                let rest = p.toks[p.pos..].to_vec();
                p.pos = p.toks.len();
                commands.push(Command::Sort(sort_keys(rest)?));
            }
            "head" => {
                let n = match p.next() {
                    None => 10,
                    Some(Tok::Num(n)) if n >= 1.0 => n as usize,
                    other => return Err(format!("Syntax error: head takes a positive number, found {other:?}")),
                };
                commands.push(Command::Limit(n.min(10_000)));
            }
            "rename" => {
                let mut pairs = Vec::new();
                loop {
                    let from = ident(p.next())?;
                    if !p.eat_kw("as") {
                        return Err("Syntax error: expected AS in rename".into());
                    }
                    pairs.push((from, ident(p.next())?));
                    if p.peek() == Some(&Tok::Comma) {
                        p.pos += 1;
                        continue;
                    }
                    break;
                }
                commands.push(Command::Rename(pairs));
            }
            "dedup" => {
                if matches!(p.peek(), Some(Tok::Num(_))) {
                    p.pos += 1;
                }
                commands.push(Command::Dedup(names(&mut p)?));
            }
            "top" | "rare" => {
                let n = match p.peek() {
                    Some(Tok::Num(n)) => {
                        let n = *n as usize;
                        p.pos += 1;
                        n
                    }
                    _ => 10,
                };
                let fields = names(&mut p)?;
                let by = if p.eat_kw("by") { names(&mut p)? } else { Vec::new() };
                let named = |n: &String| Named { expr: Expr::Field(n.clone()), name: n.clone() };
                let mut columns: Vec<String> = by.clone();
                columns.extend(fields.iter().cloned());
                commands.push(Command::Stats {
                    aggs: vec![Named { expr: Expr::Call("count".into(), Vec::new()), name: "count".into() }],
                    by: columns.iter().map(named).collect(),
                });
                commands.push(Command::Sort(vec![(Expr::Field("count".into()), cmd == "top")]));
                commands.push(Command::Limit(n.clamp(1, 10_000)));
                columns.push("count".into());
                commands.push(Command::Display(columns));
            }
            "parse" => {
                let field = p.unary()?;
                let pattern = match p.next() {
                    Some(Tok::Str(s)) => Regex::new(&s).map_err(|e| format!("invalid regex: {e}"))?,
                    other => return Err(format!("Syntax error: parse takes a regular expression, found {other:?}")),
                };
                commands.push(Command::ParseRegex { field, pattern });
            }
            "fillnull" => {
                let mut items = Vec::new();
                if p.eat_kw("with") {
                    let value = p.expr()?;
                    if !p.eat_kw("in") {
                        return Err("Syntax error: expected IN in fillnull".into());
                    }
                    for n in names(&mut p)? {
                        let e = Expr::Call("coalesce".into(), vec![Expr::Field(n.clone()), value.clone()]);
                        items.push(Named { expr: e, name: n });
                    }
                } else if p.eat_kw("using") {
                    loop {
                        let name = ident(p.next())?;
                        if !p.at_op("=") {
                            return Err("Syntax error: expected '=' in fillnull".into());
                        }
                        p.pos += 1;
                        let value = p.expr()?;
                        let e = Expr::Call("coalesce".into(), vec![Expr::Field(name.clone()), value]);
                        items.push(Named { expr: e, name });
                        if p.peek() == Some(&Tok::Comma) {
                            p.pos += 1;
                            continue;
                        }
                        break;
                    }
                } else {
                    return Err(
                        "Syntax error: fillnull takes `with <value> in <fields>` or `using <field> = <value>`".into()
                    );
                }
                commands.push(Command::Eval(items));
            }
            other => return Err(format!("Unsupported PPL command: {other}")),
        }
        finish(&p, ())?;
    }
    Ok(Compiled { query: Query { commands }, log_groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insights::{execute, Record, V};

    fn rec(ts: i64, status: f64, path: &str) -> Record {
        let mut r = Record::new();
        r.insert("@timestamp".into(), V::Time(ts));
        r.insert("@message".into(), V::Str(format!("{path} {status}")));
        r.insert("status".into(), V::Num(status));
        r.insert("path".into(), V::Str(path.into()));
        r.insert("@ptr".into(), V::Str("p".into()));
        r
    }

    fn data() -> Vec<Record> {
        vec![rec(1, 200.0, "/a"), rec(2, 500.0, "/b"), rec(3, 200.0, "/b"), rec(4, 404.0, "/A")]
    }

    #[test]
    fn sql_group_by() {
        let c = compile(
            "SQL",
            "SELECT path, COUNT(*) AS hits FROM `logGroups(logGroupIdentifier: ['/x', '/y'])` \
             WHERE status >= 200 GROUP BY path HAVING COUNT(*) > 1 ORDER BY hits DESC LIMIT 5",
        )
        .unwrap();
        assert_eq!(c.log_groups, vec!["/x", "/y"]);
        let out = execute(&c.query, data(), 100);
        assert_eq!(out.rows, vec![vec![("path".into(), "/b".into()), ("hits".into(), "2".into())]]);
    }

    #[test]
    fn sql_where_forms() {
        let c = compile(
            "SQL",
            "SELECT path FROM `/x` WHERE path LIKE '/a%' AND status NOT IN (500) AND status BETWEEN 100 AND 450 \
             AND missing IS NULL ORDER BY path",
        )
        .unwrap();
        assert_eq!(c.log_groups, vec!["/x"]);
        let out = execute(&c.query, data(), 100);
        let paths: Vec<_> = out.rows.iter().map(|r| r[0].1.clone()).collect();
        assert_eq!(paths, vec!["/A", "/a"]);
    }

    #[test]
    fn sql_star_and_errors() {
        let c = compile("SQL", "SELECT * FROM `/x` LIMIT 1").unwrap();
        let out = execute(&c.query, data(), 100);
        assert_eq!(out.rows.len(), 1);
        assert!(out.rows[0].iter().any(|(k, _)| k == "status"));
        assert!(compile("SQL", "SELECT a FROM `x` JOIN `y` ON a = b").is_err());
        assert!(compile("SQL", "SELECT a").is_err());
        assert!(compile("SQL", "fields @message").is_err());
    }

    #[test]
    fn ppl_pipeline() {
        let c = compile("PPL", "where status = 200 or status = 500 | stats count() as n by path | sort - n | head 1")
            .unwrap();
        let out = execute(&c.query, data(), 100);
        assert_eq!(out.rows, vec![vec![("path".into(), "/b".into()), ("n".into(), "2".into())]]);
        let c = compile("PPL", "eval double = status * 2 | fields path, double | where like(path, '/a') | sort path")
            .unwrap();
        let out = execute(&c.query, data(), 100);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(out.rows[0][..2], [("path".into(), "/A".into()), ("double".into(), "808".into())]);
        let c = compile("PPL", "top 1 path").unwrap();
        let out = execute(&c.query, data(), 100);
        assert_eq!(out.rows, vec![vec![("path".into(), "/b".into()), ("count".into(), "2".into())]]);
        let c = compile("PPL", "fields - @message, @ptr | rename status as code | head 1").unwrap();
        let out = execute(&c.query, data(), 100);
        assert!(out.rows[0].iter().any(|(k, _)| k == "code"));
        assert!(!out.rows[0].iter().any(|(k, _)| k == "@message"));
        assert!(compile("PPL", "bogus x").is_err());
    }
}
