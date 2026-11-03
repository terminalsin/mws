//! Log transformers: the processors `PutTransformer` accepts and
//! `TestTransformer` runs.
//!
//! A log event starts as `{"@message": <text>}`; parsers turn the text (or
//! another string field) into fields, and the other processors edit them.
//! Keys are dotted paths into nested objects.
//!
//! Spec: <https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation-Processors.html>

use regex::Regex;
use serde_json::{Map, Value};

use crate::generated::types::{self, Processor};

pub const MAX_PROCESSORS: usize = 20;

/// The name of the one processor a `Processor` sets, or an error when it
/// sets none or several.
pub fn kind(p: &Processor) -> Result<&'static str, String> {
    let set: Vec<&'static str> = [
        ("addKeys", p.add_keys.is_some()),
        ("copyValue", p.copy_value.is_some()),
        ("csv", p.csv.is_some()),
        ("dateTimeConverter", p.date_time_converter.is_some()),
        ("deleteKeys", p.delete_keys.is_some()),
        ("grok", p.grok.is_some()),
        ("listToMap", p.list_to_map.is_some()),
        ("lowerCaseString", p.lower_case_string.is_some()),
        ("moveKeys", p.move_keys.is_some()),
        ("parseCloudfront", p.parse_cloudfront.is_some()),
        ("parseJSON", p.parse_json.is_some()),
        ("parseKeyValue", p.parse_key_value.is_some()),
        ("parseRoute53", p.parse_route53.is_some()),
        ("parseToOCSF", p.parse_to_ocsf.is_some()),
        ("parsePostgres", p.parse_postgres.is_some()),
        ("parseVPC", p.parse_vpc.is_some()),
        ("parseWAF", p.parse_waf.is_some()),
        ("renameKeys", p.rename_keys.is_some()),
        ("splitString", p.split_string.is_some()),
        ("substituteString", p.substitute_string.is_some()),
        ("trimString", p.trim_string.is_some()),
        ("typeConverter", p.type_converter.is_some()),
        ("upperCaseString", p.upper_case_string.is_some()),
    ]
    .into_iter()
    .filter_map(|(n, s)| s.then_some(n))
    .collect();
    match set.as_slice() {
        [one] => Ok(one),
        [] => Err("Each processor must specify exactly one processor type.".into()),
        _ => Err("Each processor must specify exactly one processor type, found several.".into()),
    }
}

const VENDED: &[&str] = &["parseCloudfront", "parseRoute53", "parseToOCSF", "parsePostgres", "parseVPC", "parseWAF"];
const PARSERS: &[&str] = &[
    "parseJSON",
    "grok",
    "csv",
    "parseKeyValue",
    "parseCloudfront",
    "parseRoute53",
    "parseToOCSF",
    "parsePostgres",
    "parseVPC",
    "parseWAF",
];

/// Validate a transformer configuration as `PutTransformer` does.
pub fn validate(processors: &[Processor]) -> Result<(), String> {
    if processors.is_empty() || processors.len() > MAX_PROCESSORS {
        return Err(format!("A transformer must have between 1 and {MAX_PROCESSORS} processors."));
    }
    let kinds: Vec<&str> = processors.iter().map(kind).collect::<Result<_, _>>()?;
    if !PARSERS.contains(&kinds[0]) {
        return Err("The first processor in a transformer must be a parser.".into());
    }
    for (i, k) in kinds.iter().enumerate() {
        if VENDED.contains(k) && i != 0 {
            return Err(format!("{k} must be the first processor in the transformer."));
        }
    }
    if kinds.iter().filter(|k| **k == "grok").count() > 5 {
        return Err("A transformer can contain at most 5 grok processors.".into());
    }
    for p in processors {
        if let Some(g) = &p.grok {
            grok_regex(&g.r#match)?;
        }
        if let Some(s) = &p.substitute_string {
            for e in &s.entries {
                Regex::new(&e.from).map_err(|e| format!("Invalid regex in substituteString: {e}"))?;
            }
        }
        if p.parse_to_ocsf.is_some() {
            return Err("parseToOCSF is not supported by MWS.".into());
        }
    }
    Ok(())
}

// ---- dotted paths ------------------------------------------------------------

fn get<'a>(doc: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(v) = doc.get(path) {
        return Some(v);
    }
    let (head, rest) = path.split_once('.')?;
    match doc.get(head)? {
        Value::Object(m) => get(m, rest),
        _ => None,
    }
}

fn set(doc: &mut Map<String, Value>, path: &str, v: Value, overwrite: bool) {
    match path.split_once('.') {
        Some((head, rest)) if !doc.contains_key(path) => {
            let child = doc.entry(head.to_string()).or_insert_with(|| Value::Object(Map::new()));
            if !child.is_object() {
                if !overwrite {
                    return;
                }
                *child = Value::Object(Map::new());
            }
            if let Value::Object(m) = child {
                set(m, rest, v, overwrite);
            }
        }
        _ => {
            if overwrite || !doc.contains_key(path) {
                doc.insert(path.to_string(), v);
            }
        }
    }
}

fn remove(doc: &mut Map<String, Value>, path: &str) -> Option<Value> {
    if let Some(v) = doc.remove(path) {
        return Some(v);
    }
    let (head, rest) = path.split_once('.')?;
    match doc.get_mut(head)? {
        Value::Object(m) => remove(m, rest),
        _ => None,
    }
}

fn text_of(doc: &Map<String, Value>, source: Option<&str>) -> Option<String> {
    match get(doc, source.unwrap_or("@message"))? {
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Put parsed fields at `destination`, or at the top level.
fn merge(doc: &mut Map<String, Value>, destination: Option<&str>, fields: Map<String, Value>, overwrite: bool) {
    match destination {
        Some(d) if !d.is_empty() => set(doc, d, Value::Object(fields), true),
        _ => {
            for (k, v) in fields {
                if overwrite || !doc.contains_key(&k) {
                    doc.insert(k, v);
                }
            }
        }
    }
}

// ---- grok ---------------------------------------------------------------------

fn grok_pattern(name: &str) -> Option<&'static str> {
    Some(match name {
        "WORD" => r"\b\w+\b",
        "NOTSPACE" => r"\S+",
        "SPACE" => r"\s*",
        "DATA" => r".*?",
        "GREEDYDATA" => r".*",
        "INT" => r"[+-]?\d+",
        "POSINT" => r"\b[1-9]\d*\b",
        "NONNEGINT" => r"\b\d+\b",
        "NUMBER" | "BASE10NUM" => r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)",
        "IPV4" => r"(?:\d{1,3}\.){3}\d{1,3}",
        "IPV6" => r"[0-9A-Fa-f:]+:[0-9A-Fa-f:.]+",
        "IP" => r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+:[0-9A-Fa-f:.]+)",
        "HOSTNAME" => r"\b[0-9A-Za-z][0-9A-Za-z-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*\.?\b",
        "IPORHOST" => r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Za-z.-]+)",
        "USERNAME" | "USER" => r"[a-zA-Z0-9._-]+",
        "EMAILADDRESS" => r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+",
        "LOGLEVEL" => {
            r"(?i:trace|debug|info|notice|warn(?:ing)?|err(?:or)?|crit(?:ical)?|fatal|severe|emerg(?:ency)?|alert)"
        }
        "UUID" => r"[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}",
        "TIMESTAMP_ISO8601" => r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?",
        "HTTPDATE" => r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}",
        "QUOTEDSTRING" | "QS" => r#""(?:[^"\\]|\\.)*""#,
        "URIPATH" => r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+",
        "URIPATHPARAM" => r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+(?:\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*)?",
        "WORDS" => r"[\w ]+",
        _ => return None,
    })
}

/// A grok expression as a regex with named groups (dots in names become
/// `__`, typed captures `%{INT:x:int}` keep their type for later).
/// A grok capture: field name, pattern name and optional type conversion.
type GrokField = (String, String, Option<String>);

fn grok_regex(expr: &str) -> Result<(Regex, Vec<GrokField>), String> {
    let token = Regex::new(r"%\{(\w+)(?::([\w.@\[\]-]+))?(?::(\w+))?\}").expect("static regex");
    let mut out = String::new();
    let mut names = Vec::new();
    let mut last = 0;
    for c in token.captures_iter(expr) {
        let m = c.get(0).expect("whole match");
        out.push_str(&expr[last..m.start()]);
        last = m.end();
        let pattern = grok_pattern(&c[1]).ok_or_else(|| format!("Unknown grok pattern %{{{}}}", &c[1]))?;
        match c.get(2) {
            Some(name) => {
                let group = format!("g{}", names.len());
                names.push((group.clone(), name.as_str().to_string(), c.get(3).map(|t| t.as_str().to_string())));
                out.push_str(&format!("(?P<{group}>{pattern})"));
            }
            None => out.push_str(&format!("(?:{pattern})")),
        }
    }
    out.push_str(&expr[last..]);
    let re = Regex::new(&out).map_err(|e| format!("Invalid grok pattern: {e}"))?;
    Ok((re, names))
}

// ---- date conversion ------------------------------------------------------------

/// Java `DateTimeFormatter` pattern to a chrono format string.
fn java_to_chrono(p: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
            continue;
        }
        let mut n = 1;
        while i + n < chars.len() && chars[i + n] == c {
            n += 1;
        }
        let piece = match (c, n) {
            ('y', 2) => "%y",
            ('y', _) | ('u', _) => "%Y",
            ('M', 1) | ('M', 2) => "%m",
            ('M', 3) => "%b",
            ('M', _) => "%B",
            ('d', _) => "%d",
            ('H', _) => "%H",
            ('h', _) => "%I",
            ('m', _) => "%M",
            ('s', _) => "%S",
            ('S', _) => "%3f",
            ('a', _) => "%p",
            ('E', 1..=3) => "%a",
            ('E', _) => "%A",
            ('X', _) | ('x', _) => "%:z",
            ('Z', _) => "%z",
            _ => {
                for _ in 0..n {
                    out.push(c);
                }
                i += n;
                continue;
            }
        };
        out.push_str(piece);
        i += n;
    }
    out
}

fn convert_date(text: &str, d: &types::DateTimeConverter) -> Option<String> {
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    let parsed: DateTime<Utc> = d.match_patterns.iter().find_map(|p| {
        if p == "epoch" || p == "epoch_millis" {
            let n: f64 = text.parse().ok()?;
            let ms = if p == "epoch" { n * 1000.0 } else { n };
            return Utc.timestamp_millis_opt(ms as i64).single();
        }
        let f = java_to_chrono(p);
        DateTime::parse_from_str(text, &f)
            .map(|t| t.with_timezone(&Utc))
            .ok()
            .or_else(|| NaiveDateTime::parse_from_str(text, &f).ok().map(|n| n.and_utc()))
    })?;
    let target = d.target_format.as_deref().unwrap_or("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    Some(parsed.format(&java_to_chrono(target)).to_string())
}

// ---- vended formats ---------------------------------------------------------------

fn positional(text: &str, names: &[&str], sep: Option<char>) -> Map<String, Value> {
    let parts: Vec<&str> = match sep {
        Some(c) => text.split(c).collect(),
        None => text.split_whitespace().collect(),
    };
    names.iter().zip(parts).map(|(n, v)| (n.to_string(), Value::String(v.to_string()))).collect()
}

const VPC_FIELDS: &[&str] = &[
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
];
const ROUTE53_FIELDS: &[&str] = &[
    "version",
    "query_timestamp",
    "hosted_zone_id",
    "query_name",
    "query_type",
    "response_code",
    "protocol",
    "edge_location",
    "resolver_ip",
    "edns_client_subnet",
];
const CLOUDFRONT_FIELDS: &[&str] = &[
    "date",
    "time",
    "x-edge-location",
    "sc-bytes",
    "c-ip",
    "cs-method",
    "cs(Host)",
    "cs-uri-stem",
    "sc-status",
    "cs(Referer)",
    "cs(User-Agent)",
    "cs-uri-query",
    "cs(Cookie)",
    "x-edge-result-type",
    "x-edge-request-id",
    "x-host-header",
    "cs-protocol",
    "cs-bytes",
    "time-taken",
];

// ---- running --------------------------------------------------------------------

/// Run `processors` over one log event; the transformed event as JSON.
pub fn run(processors: &[Processor], message: &str) -> Result<String, String> {
    let mut doc = Map::new();
    doc.insert("@message".into(), Value::String(message.to_string()));
    for p in processors {
        apply(p, &mut doc)?;
    }
    doc.remove("@message");
    Ok(Value::Object(doc).to_string())
}

fn apply(p: &Processor, doc: &mut Map<String, Value>) -> Result<(), String> {
    if let Some(x) = &p.parse_json {
        let src = x.source.as_deref().unwrap_or("@message");
        if let Some(Value::Object(fields)) = text_of(doc, Some(src)).and_then(|t| serde_json::from_str(&t).ok()) {
            if src == "@message" {
                doc.remove("@message");
            }
            merge(doc, x.destination.as_deref(), fields, true);
        }
    } else if let Some(x) = &p.grok {
        let (re, names) = grok_regex(&x.r#match)?;
        if let Some(text) = text_of(doc, x.source.as_deref()) {
            if let Some(c) = re.captures(&text) {
                for (group, name, ty) in names {
                    if let Some(m) = c.name(&group) {
                        let v = match ty.as_deref() {
                            Some("int") => m.as_str().parse::<i64>().map(Value::from).unwrap_or(Value::Null),
                            Some("float") => m.as_str().parse::<f64>().map(Value::from).unwrap_or(Value::Null),
                            _ => Value::String(m.as_str().to_string()),
                        };
                        set(doc, &name, v, true);
                    }
                }
            }
        }
    } else if let Some(x) = &p.csv {
        let delim = x.delimiter.as_deref().and_then(|d| d.chars().next()).unwrap_or(',');
        let quote = x.quote_character.as_deref().and_then(|d| d.chars().next()).unwrap_or('"');
        if let Some(text) = text_of(doc, x.source.as_deref()) {
            let mut values = Vec::new();
            let mut cur = String::new();
            let mut quoted = false;
            for c in text.chars() {
                if c == quote {
                    quoted = !quoted;
                } else if c == delim && !quoted {
                    values.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            }
            values.push(cur);
            let mut fields = Map::new();
            for (i, v) in values.into_iter().enumerate() {
                let name =
                    x.columns.as_ref().and_then(|c| c.get(i).cloned()).unwrap_or_else(|| format!("column_{}", i + 1));
                fields.insert(name, Value::String(v));
            }
            merge(doc, x.destination.as_deref(), fields, true);
        }
    } else if let Some(x) = &p.parse_key_value {
        let fd = x.field_delimiter.as_deref().unwrap_or("&");
        let kvd = x.key_value_delimiter.as_deref().unwrap_or("=");
        if let Some(text) = text_of(doc, x.source.as_deref()) {
            let mut fields = Map::new();
            for pair in text.split(fd).filter(|p| !p.is_empty()) {
                let (k, v) = match pair.split_once(kvd) {
                    Some((k, v)) => (k, Value::String(v.to_string())),
                    None => match &x.non_match_value {
                        Some(n) => (pair, Value::String(n.clone())),
                        None => continue,
                    },
                };
                fields.insert(format!("{}{}", x.key_prefix.as_deref().unwrap_or(""), k.trim()), v);
            }
            merge(doc, x.destination.as_deref(), fields, x.overwrite_if_exists);
        }
    } else if let Some(x) = &p.parse_vpc {
        if let Some(t) = text_of(doc, x.source.as_deref()) {
            merge(doc, None, positional(&t, VPC_FIELDS, None), true);
        }
    } else if let Some(x) = &p.parse_route53 {
        if let Some(t) = text_of(doc, x.source.as_deref()) {
            merge(doc, None, positional(&t, ROUTE53_FIELDS, None), true);
        }
    } else if let Some(x) = &p.parse_cloudfront {
        if let Some(t) = text_of(doc, x.source.as_deref()) {
            merge(doc, None, positional(&t, CLOUDFRONT_FIELDS, Some('\t')), true);
        }
    } else if let Some(x) = &p.parse_waf {
        if let Some(Value::Object(fields)) =
            text_of(doc, x.source.as_deref()).and_then(|t| serde_json::from_str(&t).ok())
        {
            merge(doc, None, fields, true);
        }
    } else if let Some(x) = &p.parse_postgres {
        let re = Regex::new(r"^(?P<timestamp>\S+ \S+(?: \S+)?)(?::(?P<host>[^:(]*)(?:\((?P<port>\d+)\))?)?:(?P<user>[^@]*)@(?P<database>[^:]*):\[(?P<pid>\d+)\]:(?P<level>[A-Z]+):\s*(?P<message>.*)$").expect("static regex");
        if let Some(t) = text_of(doc, x.source.as_deref()) {
            if let Some(c) = re.captures(&t) {
                for n in ["timestamp", "host", "port", "user", "database", "pid", "level", "message"] {
                    if let Some(m) = c.name(n) {
                        doc.insert(n.to_string(), Value::String(m.as_str().to_string()));
                    }
                }
            }
        }
    } else if p.parse_to_ocsf.is_some() {
        return Err("parseToOCSF is not supported by MWS.".into());
    } else if let Some(x) = &p.add_keys {
        for e in &x.entries {
            set(doc, &e.key, Value::String(e.value.clone()), e.overwrite_if_exists);
        }
    } else if let Some(x) = &p.delete_keys {
        for k in &x.with_keys {
            remove(doc, k);
        }
    } else if let Some(x) = &p.move_keys {
        for e in &x.entries {
            if let Some(v) = remove(doc, &e.source) {
                set(doc, &e.target, v, e.overwrite_if_exists);
            }
        }
    } else if let Some(x) = &p.rename_keys {
        for e in &x.entries {
            if get(doc, &e.rename_to).is_some() && !e.overwrite_if_exists {
                continue;
            }
            if let Some(v) = remove(doc, &e.key) {
                set(doc, &e.rename_to, v, true);
            }
        }
    } else if let Some(x) = &p.copy_value {
        for e in &x.entries {
            if let Some(v) = get(doc, &e.source).cloned() {
                set(doc, &e.target, v, e.overwrite_if_exists);
            }
        }
    } else if let Some(x) = &p.lower_case_string {
        map_strings(doc, &x.with_keys, |s| s.to_lowercase());
    } else if let Some(x) = &p.upper_case_string {
        map_strings(doc, &x.with_keys, |s| s.to_uppercase());
    } else if let Some(x) = &p.trim_string {
        map_strings(doc, &x.with_keys, |s| s.trim().to_string());
    } else if let Some(x) = &p.split_string {
        for e in &x.entries {
            if let Some(Value::String(s)) = get(doc, &e.source).cloned() {
                let parts = s.split(e.delimiter.as_str()).map(|p| Value::String(p.to_string())).collect();
                set(doc, &e.source, Value::Array(parts), true);
            }
        }
    } else if let Some(x) = &p.substitute_string {
        for e in &x.entries {
            let re = Regex::new(&e.from).map_err(|e| e.to_string())?;
            if let Some(Value::String(s)) = get(doc, &e.source).cloned() {
                set(doc, &e.source, Value::String(re.replace_all(&s, e.to.as_str()).into_owned()), true);
            }
        }
    } else if let Some(x) = &p.type_converter {
        for e in &x.entries {
            let Some(v) = get(doc, &e.key).cloned() else { continue };
            let text = match &v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let converted = match e.r#type.as_str() {
                "integer" => text.trim().parse::<i64>().map(Value::from).ok(),
                "double" => text.trim().parse::<f64>().map(Value::from).ok(),
                "boolean" => match text.trim().to_lowercase().as_str() {
                    "true" => Some(Value::Bool(true)),
                    "false" => Some(Value::Bool(false)),
                    _ => None,
                },
                "string" => Some(Value::String(text)),
                _ => None,
            };
            if let Some(c) = converted {
                set(doc, &e.key, c, true);
            }
        }
    } else if let Some(x) = &p.list_to_map {
        if let Some(Value::Array(items)) = get(doc, &x.source).cloned() {
            let mut out = Map::new();
            for item in items {
                let Value::Object(o) = item else { continue };
                let Some(k) = o.get(&x.key).map(|k| match k {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                }) else {
                    continue;
                };
                let v = match &x.value_key {
                    Some(vk) => o.get(vk).cloned().unwrap_or(Value::Null),
                    None => Value::Object(o.clone()),
                };
                if x.flatten {
                    let v = match (&v, x.flattened_element.as_deref()) {
                        (Value::Array(a), Some("last")) => a.last().cloned().unwrap_or(Value::Null),
                        (Value::Array(a), _) => a.first().cloned().unwrap_or(Value::Null),
                        _ => v,
                    };
                    out.insert(k, v);
                } else {
                    match out.entry(k).or_insert_with(|| Value::Array(Vec::new())) {
                        Value::Array(a) => a.push(v),
                        _ => unreachable!(),
                    }
                }
            }
            match &x.target {
                Some(t) => set(doc, t, Value::Object(out), true),
                None => merge(doc, None, out, true),
            }
        }
    } else if let Some(x) = &p.date_time_converter {
        if let Some(Value::String(s)) = get(doc, &x.source).cloned() {
            if let Some(converted) = convert_date(&s, x) {
                set(doc, &x.target, Value::String(converted), true);
            }
        }
    }
    Ok(())
}

fn map_strings(doc: &mut Map<String, Value>, keys: &[String], f: impl Fn(&str) -> String) {
    for k in keys {
        if let Some(Value::String(s)) = get(doc, k).cloned() {
            set(doc, k, Value::String(f(&s)), true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(json: &str) -> Processor {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn json_then_edits() {
        let ps = vec![
            proc(r#"{"parse_json": {}}"#),
            proc(r#"{"add_keys": {"entries": [{"key": "env", "value": "prod", "overwrite_if_exists": false}]}}"#),
            proc(
                r#"{"rename_keys": {"entries": [{"key": "lvl", "rename_to": "level", "overwrite_if_exists": false}]}}"#,
            ),
            proc(r#"{"upper_case_string": {"with_keys": ["level"]}}"#),
            proc(r#"{"type_converter": {"entries": [{"key": "ms", "type": "integer"}]}}"#),
        ];
        validate(&ps).unwrap();
        let out: Value = serde_json::from_str(&run(&ps, r#"{"lvl":"info","ms":"12"}"#).unwrap()).unwrap();
        assert_eq!(out, serde_json::json!({"env": "prod", "level": "INFO", "ms": 12}));
    }

    #[test]
    fn grok_and_kv() {
        let ps = vec![proc(r#"{"grok": {"match": "%{IP:client} %{WORD:method} %{NUMBER:ms:int}"}}"#)];
        let out: Value = serde_json::from_str(&run(&ps, "10.0.0.1 GET 42").unwrap()).unwrap();
        assert_eq!(out, serde_json::json!({"client": "10.0.0.1", "method": "GET", "ms": 42}));
        let ps = vec![proc(r#"{"parse_key_value": {"field_delimiter": " ", "overwrite_if_exists": false}}"#)];
        let out: Value = serde_json::from_str(&run(&ps, "a=1 b=2").unwrap()).unwrap();
        assert_eq!(out, serde_json::json!({"a": "1", "b": "2"}));
    }

    #[test]
    fn rules() {
        assert!(validate(&[proc(r#"{"add_keys": {"entries": []}}"#)]).is_err());
        assert!(validate(&[proc(r#"{"parse_json": {}}"#), proc(r#"{"parse_vpc": {}}"#)]).is_err());
        assert!(validate(&[proc("{}")]).is_err());
    }
}
