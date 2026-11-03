//! S3 Select: `SelectObjectContent` runs a SQL expression over a CSV or
//! JSON object (optionally GZIP or BZIP2 compressed) and streams the result
//! back as `Records` events, followed by `Progress` (when requested),
//! `Stats` and `End`.

mod sql;

use std::io::Read;

use mws_core::{RequestContext, ServiceError};
use serde_json::Value as Json;

use crate::errors;
use crate::generated::types;
use crate::objects::check_customer_key;
use crate::Call;
use sql::{Agg, Ctx, Expr, Query, Record, Val};

/// The size of the `Records` events S3 sends.
const CHUNK: usize = 64 * 1024;

fn select_error(code: &'static str, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, 400, message)
}

/// The S3 Select error code for an engine message.
fn engine_error(message: String) -> ServiceError {
    let code = if message.starts_with("Unexpected character") || message.starts_with("Unterminated") {
        "LexerInvalidChar"
    } else if message.starts_with("Expected") || message.starts_with("Unexpected token") {
        "ParseUnexpectedToken"
    } else if message.starts_with("Only [*]") {
        "ParseUnsupportedSyntax"
    } else if message.starts_with("Cannot cast") || message.starts_with("Unsupported CAST") {
        "CastFailed"
    } else if message.starts_with("Division by zero") {
        "DivisionByZero"
    } else if message.starts_with("Unsupported function") {
        "UnsupportedFunction"
    } else if message.starts_with("Aggregate") || message.starts_with("* is only") {
        "UnsupportedSqlOperation"
    } else {
        "EvaluatorInvalidArguments"
    };
    select_error(code, message)
}

fn one_char(value: Option<&str>, default: char, name: &'static str) -> Result<char, ServiceError> {
    match value {
        None | Some("") => Ok(default),
        Some(s) if s.chars().count() == 1 => Ok(s.chars().next().unwrap_or(default)),
        Some(s) => Err(errors::invalid_argument(format!("{name} must be a single character."), name, s)),
    }
}

/// CSV input or output settings.
struct CsvFormat {
    field: char,
    record: String,
    quote: char,
    escape: char,
}

/// One input record and where it starts in the object.
struct RawRecord {
    offset: usize,
    fields: Vec<String>,
}

/// Split CSV text into records, honouring quotes.
fn parse_csv(text: &str, f: &CsvFormat, comment: Option<char>) -> Result<Vec<RawRecord>, ServiceError> {
    let mut out = Vec::new();
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut record_start = 0;
    let bytes = text.as_bytes();
    let mut iter = text.char_indices().peekable();
    let flush = |out: &mut Vec<RawRecord>, fields: &mut Vec<String>, cur: &mut String, start: usize| {
        fields.push(std::mem::take(cur));
        let fs = std::mem::take(fields);
        let is_comment = comment.is_some_and(|c| fs.first().is_some_and(|x| x.starts_with(c)));
        if !is_comment {
            out.push(RawRecord { offset: start, fields: fs });
        }
    };
    while let Some((i, c)) = iter.next() {
        if in_quotes {
            if c == f.escape && f.escape != f.quote && iter.peek().is_some_and(|(_, n)| *n == f.quote) {
                cur.push(f.quote);
                iter.next();
            } else if c == f.quote {
                if iter.peek().is_some_and(|(_, n)| *n == f.quote) {
                    cur.push(f.quote);
                    iter.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
            continue;
        }
        if c == f.quote && at_field_start {
            in_quotes = true;
            at_field_start = false;
            continue;
        }
        if bytes[i..].starts_with(f.record.as_bytes()) {
            for _ in 1..f.record.chars().count() {
                iter.next();
            }
            flush(&mut out, &mut fields, &mut cur, record_start);
            record_start = i + f.record.len();
            at_field_start = true;
            continue;
        }
        if c == f.field {
            fields.push(std::mem::take(&mut cur));
            at_field_start = true;
            continue;
        }
        // A "\r\n" file read with the default "\n" delimiter.
        if c == '\r' && f.record == "\n" && iter.peek().is_some_and(|(_, n)| *n == '\n') {
            continue;
        }
        cur.push(c);
        at_field_start = false;
    }
    if in_quotes {
        return Err(select_error("CSVUnescapedQuote", "A quote character in the CSV input is not closed."));
    }
    if !cur.is_empty() || !fields.is_empty() {
        flush(&mut out, &mut fields, &mut cur, record_start);
    }
    Ok(out)
}

fn write_csv_row(out: &mut Vec<u8>, vals: &[String], f: &CsvFormat, always: bool) {
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            let mut b = [0; 4];
            out.extend_from_slice(f.field.encode_utf8(&mut b).as_bytes());
        }
        let needs = always || v.contains(f.field) || v.contains(f.quote) || v.contains(&f.record) || v.contains('\n');
        if needs {
            out.extend_from_slice(f.quote.to_string().as_bytes());
            for c in v.chars() {
                if c == f.quote {
                    out.extend_from_slice(f.escape.to_string().as_bytes());
                }
                out.extend_from_slice(c.to_string().as_bytes());
            }
            out.extend_from_slice(f.quote.to_string().as_bytes());
        } else {
            out.extend_from_slice(v.as_bytes());
        }
    }
    out.extend_from_slice(f.record.as_bytes());
}

enum Output {
    Csv { format: CsvFormat, always: bool },
    Json { delimiter: String },
}

impl Output {
    fn from(o: &types::OutputSerialization) -> Result<Output, ServiceError> {
        match (&o.csv, &o.json) {
            (Some(c), None) => {
                let always = match c.quote_fields.as_deref() {
                    None | Some("ASNEEDED") => false,
                    Some("ALWAYS") => true,
                    Some(other) => {
                        return Err(select_error("InvalidQuoteFields", format!("Invalid QuoteFields value: {other}")))
                    }
                };
                let quote = one_char(c.quote_character.as_deref(), '"', "QuoteCharacter")?;
                Ok(Output::Csv {
                    format: CsvFormat {
                        field: one_char(c.field_delimiter.as_deref(), ',', "FieldDelimiter")?,
                        record: c.record_delimiter.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "\n".into()),
                        quote,
                        escape: one_char(c.quote_escape_character.as_deref(), quote, "QuoteEscapeCharacter")?,
                    },
                    always,
                })
            }
            (None, Some(j)) => Ok(Output::Json {
                delimiter: j.record_delimiter.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "\n".into()),
            }),
            _ => Err(select_error(
                "MissingRequiredParameter",
                "OutputSerialization must specify exactly one of CSV or JSON.",
            )),
        }
    }

    /// Write one result row.
    fn row(&self, out: &mut Vec<u8>, names: &[String], vals: Vec<Val>) {
        match self {
            Output::Csv { format, always } => {
                let texts: Vec<String> = vals
                    .into_iter()
                    .flat_map(|v| match v {
                        // `SELECT *` over JSON: the object's values.
                        Val::Json(Json::Object(m)) if names.len() == 1 && names[0] == "*" => {
                            m.values().map(|x| Val::from_json(x).to_text()).collect()
                        }
                        other => vec![other.to_text()],
                    })
                    .collect();
                write_csv_row(out, &texts, format, *always);
            }
            Output::Json { delimiter } => {
                let value = if names.len() == 1 && names[0] == "*" {
                    vals.into_iter().next().map(|v| v.to_json()).unwrap_or(Json::Null)
                } else {
                    sql::json_row(names, vals)
                };
                out.extend_from_slice(value.to_string().as_bytes());
                out.extend_from_slice(delimiter.as_bytes());
            }
        }
    }
}

/// Input records, ready for evaluation.
enum Input {
    Csv { header: Option<Vec<String>>, records: Vec<RawRecord> },
    Json(Vec<(usize, Json)>),
}

fn decompress(data: &[u8], compression: Option<&str>) -> Result<Vec<u8>, ServiceError> {
    let mut out = Vec::new();
    let bad =
        |what: &str| select_error("InvalidCompressionFormat", format!("The file is not in a supported {what} format."));
    match compression.unwrap_or("NONE") {
        "NONE" => return Ok(data.to_vec()),
        "GZIP" => {
            flate2::read::MultiGzDecoder::new(data).read_to_end(&mut out).map_err(|_| bad("GZIP"))?;
        }
        "BZIP2" => {
            bzip2::read::MultiBzDecoder::new(data).read_to_end(&mut out).map_err(|_| bad("BZIP2"))?;
        }
        other => {
            return Err(select_error("InvalidCompressionFormat", format!("Invalid CompressionType: {other}")));
        }
    }
    Ok(out)
}

/// Split a JSON document into its top-level values (with their offsets).
fn json_values(text: &str) -> Result<Vec<(usize, Json)>, ServiceError> {
    let mut out = Vec::new();
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Json>();
    loop {
        let start = stream.byte_offset();
        match stream.next() {
            None => break,
            Some(Ok(v)) => {
                // Skip the whitespace before the value.
                let skipped = text[start..].len() - text[start..].trim_start().len();
                out.push((start + skipped, v));
            }
            Some(Err(e)) => return Err(select_error("JSONParsingError", format!("Error parsing JSON file: {e}"))),
        }
    }
    Ok(out)
}

fn read_input(s: &types::InputSerialization, text: &str) -> Result<Input, ServiceError> {
    match (&s.csv, &s.json, &s.parquet) {
        (Some(c), None, None) => {
            let quote = one_char(c.quote_character.as_deref(), '"', "QuoteCharacter")?;
            let format = CsvFormat {
                field: one_char(c.field_delimiter.as_deref(), ',', "FieldDelimiter")?,
                record: c.record_delimiter.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "\n".into()),
                quote,
                escape: one_char(c.quote_escape_character.as_deref(), quote, "QuoteEscapeCharacter")?,
            };
            let comment = match c.comments.as_deref() {
                None | Some("") => None,
                Some(x) => Some(one_char(Some(x), '#', "Comments")?),
            };
            let mut records = parse_csv(text, &format, comment)?;
            let header = match c.file_header_info.as_deref().unwrap_or("NONE") {
                "NONE" => None,
                "IGNORE" => {
                    if !records.is_empty() {
                        records.remove(0);
                    }
                    None
                }
                "USE" => {
                    if records.is_empty() {
                        None
                    } else {
                        Some(records.remove(0).fields)
                    }
                }
                other => {
                    return Err(select_error("InvalidFileHeaderInfo", format!("Invalid FileHeaderInfo value: {other}")))
                }
            };
            Ok(Input::Csv { header, records })
        }
        (None, Some(j), None) => match j.r#type.as_deref() {
            Some("DOCUMENT") => Ok(Input::Json(json_values(text)?)),
            Some("LINES") => {
                let mut out = Vec::new();
                let mut offset = 0;
                for line in text.split_inclusive('\n') {
                    let t = line.trim();
                    if !t.is_empty() {
                        let v = serde_json::from_str(t)
                            .map_err(|e| select_error("JSONParsingError", format!("Error parsing JSON file: {e}")))?;
                        out.push((offset, v));
                    }
                    offset += line.len();
                }
                Ok(Input::Json(out))
            }
            other => Err(select_error(
                "InvalidJsonType",
                format!("The JsonType is invalid. Only DOCUMENT and LINES are supported: {}", other.unwrap_or("")),
            )),
        },
        (None, None, Some(_)) => Err(ServiceError::client(
            "NotImplemented",
            501,
            "Parquet input is not supported by this S3 Select implementation.",
        )),
        _ => Err(select_error(
            "MissingRequiredParameter",
            "InputSerialization must specify exactly one of CSV, JSON or Parquet.",
        )),
    }
}

/// Expand JSON records through the `FROM S3Object[*].path` of the query.
fn json_records(values: Vec<(usize, Json)>, q: &Query) -> Vec<(usize, Json)> {
    let mut out = Vec::new();
    for (offset, v) in values {
        let mut cur = vec![v];
        // `S3Object[*]` over an array document iterates its elements.
        if !q.from_path.is_empty() || matches!(cur.first(), Some(Json::Array(_))) {
            cur = cur.into_iter().flat_map(expand).collect();
        }
        for step in &q.from_path {
            let sql::Step::Key(k) = step else { continue };
            cur = cur
                .into_iter()
                .filter_map(|x| match x {
                    Json::Object(mut m) => m.remove(k),
                    _ => None,
                })
                .flat_map(expand)
                .collect();
        }
        out.extend(cur.into_iter().map(|x| (offset, x)));
    }
    out
}

fn expand(v: Json) -> Vec<Json> {
    match v {
        Json::Array(a) => a,
        other => vec![other],
    }
}

pub struct Selected {
    pub records: Vec<u8>,
    pub bytes_scanned: i64,
    pub bytes_processed: i64,
}

/// Run `expression` over an object's bytes.
pub fn run(
    expression: &str,
    input: &types::InputSerialization,
    output: &types::OutputSerialization,
    scan_range: Option<&types::ScanRange>,
    data: &[u8],
) -> Result<Selected, ServiceError> {
    let q = sql::parse(expression).map_err(engine_error)?;
    let out_format = Output::from(output)?;
    let compression = input.compression_type.as_deref().filter(|c| *c != "NONE");
    let lines = input.json.as_ref().is_some_and(|j| j.r#type.as_deref() == Some("LINES"));
    let range = match scan_range {
        Some(r) if r.start.is_some() || r.end.is_some() => {
            if compression.is_some() || input.parquet.is_some() || (input.json.is_some() && !lines) {
                return Err(errors::invalid_request(
                    "Scan range is only supported for uncompressed CSV and JSON LINES objects.",
                ));
            }
            if input.csv.as_ref().is_some_and(|c| c.allow_quoted_record_delimiter == Some(true)) {
                return Err(errors::invalid_request(
                    "Scan range is not supported with AllowQuotedRecordDelimiter set to TRUE.",
                ));
            }
            let len = data.len() as i64;
            let (start, end) = match (r.start, r.end) {
                (Some(s), Some(e)) => (s, e.min(len - 1)),
                (Some(s), None) => (s, len - 1),
                // Only `End`: the last `End` bytes.
                (None, Some(e)) => ((len - e).max(0), len - 1),
                (None, None) => (0, len - 1),
            };
            if start < 0 || start > end.max(0) && len > 0 {
                return Err(errors::invalid_request("The scan range start must not be greater than its end."));
            }
            Some((start as usize, end.max(0) as usize))
        }
        _ => None,
    };
    let plain = decompress(data, compression)?;
    let text = std::str::from_utf8(&plain)
        .map_err(|_| select_error("InvalidTextEncoding", "Invalid encoding type. Input data is not UTF-8."))?;
    let in_range = |offset: usize| range.is_none_or(|(s, e)| offset >= s && offset <= e);

    let parsed = read_input(input, text)?;
    let (header, rows): (Option<Vec<String>>, Vec<Row>) = match parsed {
        Input::Csv { header, records } => {
            (header, records.into_iter().filter(|r| in_range(r.offset)).map(|r| Row::Csv(r.fields)).collect())
        }
        Input::Json(values) => {
            let values = values.into_iter().filter(|(o, _)| in_range(*o)).collect();
            (None, json_records(values, &q).into_iter().map(|(_, v)| Row::Json(v)).collect())
        }
    };

    let star = q.projections.len() == 1 && q.projections[0].expr == Expr::Star;
    let names: Vec<String> = if star {
        vec!["*".into()]
    } else {
        q.projections.iter().enumerate().map(|(i, p)| sql::column_name(p, i)).collect()
    };

    let mut out = Vec::new();
    let alias = q.alias.as_deref();
    if q.is_aggregate() {
        let mut aggs = Vec::new();
        for p in &q.projections {
            if p.expr == Expr::Star {
                return Err(engine_error("* is only allowed without aggregates".into()));
            }
            sql::collect_aggs(&p.expr, &mut aggs);
        }
        let mut state = vec![Agg::default(); aggs.len()];
        for row in &rows {
            let ctx = row.ctx(header.as_deref(), alias);
            if !passes(&ctx, &q)? {
                continue;
            }
            for (a, s) in aggs.iter().zip(state.iter_mut()) {
                let Expr::Agg { func, arg } = a else { continue };
                let v = match arg {
                    Some(e) => Some(ctx.eval(e).map_err(engine_error)?),
                    None => None,
                };
                s.add(func, v).map_err(engine_error)?;
            }
        }
        let results: Vec<(Expr, Val)> = aggs
            .iter()
            .zip(&state)
            .map(|(a, s)| match a {
                Expr::Agg { func, .. } => (a.clone(), s.result(func)),
                _ => (a.clone(), Val::Null),
            })
            .collect();
        let empty = Json::Null;
        let ctx = Ctx { record: Record::Json(&empty), alias };
        let vals = q
            .projections
            .iter()
            .map(|p| ctx.eval(&sql::substitute(&p.expr, &results)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(engine_error)?;
        if q.limit != Some(0) {
            out_format.row(&mut out, &names, vals);
        }
    } else {
        let mut emitted = 0u64;
        for row in &rows {
            if q.limit.is_some_and(|l| emitted >= l) {
                break;
            }
            let ctx = row.ctx(header.as_deref(), alias);
            if !passes(&ctx, &q)? {
                continue;
            }
            let vals: Vec<Val> = if star {
                match row {
                    Row::Json(v) => vec![Val::Json(v.clone())],
                    Row::Csv(fields) => match &out_format {
                        Output::Csv { .. } => fields.iter().cloned().map(Val::Str).collect(),
                        Output::Json { .. } => {
                            let keys: Vec<String> = (0..fields.len())
                                .map(|i| {
                                    header
                                        .as_ref()
                                        .and_then(|h| h.get(i).cloned())
                                        .unwrap_or_else(|| format!("_{}", i + 1))
                                })
                                .collect();
                            vec![Val::Json(sql::json_row(&keys, fields.iter().cloned().map(Val::Str).collect()))]
                        }
                    },
                }
            } else {
                q.projections.iter().map(|p| ctx.eval(&p.expr)).collect::<Result<_, _>>().map_err(engine_error)?
            };
            out_format.row(&mut out, &names, vals);
            emitted += 1;
        }
    }
    let scanned = match range {
        Some((s, e)) => (e.min(data.len().saturating_sub(1)) + 1).saturating_sub(s),
        None => data.len(),
    };
    Ok(Selected { records: out, bytes_scanned: scanned as i64, bytes_processed: plain.len() as i64 })
}

enum Row {
    Csv(Vec<String>),
    Json(Json),
}

impl Row {
    fn ctx<'a>(&'a self, header: Option<&'a [String]>, alias: Option<&'a str>) -> Ctx<'a> {
        let record = match self {
            Row::Csv(fields) => Record::Csv { fields, header },
            Row::Json(v) => Record::Json(v),
        };
        Ctx { record, alias }
    }
}

fn passes(ctx: &Ctx, q: &Query) -> Result<bool, ServiceError> {
    match &q.filter {
        None => Ok(true),
        Some(f) => Ok(matches!(ctx.eval(f).map_err(engine_error)?, Val::Bool(true))),
    }
}

impl Call {
    pub fn select_object_content(
        &self,
        ctx: &RequestContext,
        input: types::SelectObjectContentRequest,
    ) -> Result<types::SelectObjectContentOutput, ServiceError> {
        let data = self.object_read(
            ctx,
            &input.bucket,
            &input.key,
            None,
            input.expected_bucket_owner.as_deref(),
            "s3:GetObject",
            |_, v| {
                if v.is_archived() && v.restored_until.is_none_or(|t| t < ctx.received_at) {
                    return Err(errors::invalid_object_state(&v.storage_class));
                }
                check_customer_key(
                    v,
                    input.sse_customer_algorithm.as_deref(),
                    input.sse_customer_key.as_deref(),
                    input.sse_customer_key_md5.as_deref(),
                )?;
                Ok(v.clone())
            },
        )?;
        self.open_kms(ctx, &data, &input.bucket, &input.key)?;
        if !input.expression_type.eq_ignore_ascii_case("SQL") {
            return Err(select_error(
                "InvalidExpressionType",
                "The ExpressionType is invalid. Only SQL expressions are supported.",
            ));
        }
        let selected = run(
            &input.expression,
            &input.input_serialization,
            &input.output_serialization,
            input.scan_range.as_ref(),
            &data.data,
        )?;
        let returned = selected.records.len() as i64;
        let mut payload: Vec<types::SelectObjectContentEventStream> = selected
            .records
            .chunks(CHUNK)
            .map(|c| types::SelectObjectContentEventStream::Records(types::RecordsEvent { payload: Some(c.to_vec()) }))
            .collect();
        if input.request_progress.as_ref().and_then(|p| p.enabled) == Some(true) {
            payload.push(types::SelectObjectContentEventStream::Progress(types::ProgressEvent {
                details: Some(types::Progress {
                    bytes_scanned: Some(selected.bytes_scanned),
                    bytes_processed: Some(selected.bytes_processed),
                    bytes_returned: Some(returned),
                }),
            }));
        }
        payload.push(types::SelectObjectContentEventStream::Stats(types::StatsEvent {
            details: Some(types::Stats {
                bytes_scanned: Some(selected.bytes_scanned),
                bytes_processed: Some(selected.bytes_processed),
                bytes_returned: Some(returned),
            }),
        }));
        payload.push(types::SelectObjectContentEventStream::End(types::EndEvent {}));
        Ok(types::SelectObjectContentOutput { payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csv_in(header: &str) -> types::InputSerialization {
        types::InputSerialization {
            csv: Some(types::CSVInput { file_header_info: Some(header.into()), ..Default::default() }),
            ..Default::default()
        }
    }

    fn csv_out() -> types::OutputSerialization {
        types::OutputSerialization { csv: Some(types::CSVOutput::default()), ..Default::default() }
    }

    fn json_out() -> types::OutputSerialization {
        types::OutputSerialization { json: Some(types::JSONOutput::default()), ..Default::default() }
    }

    fn text(r: Result<Selected, ServiceError>) -> String {
        String::from_utf8(r.unwrap().records).unwrap()
    }

    const PEOPLE: &str = "name,age,city\nalice,34,\"Paris, FR\"\nbob,27,Berlin\ncarol,41,Oslo\n";

    #[test]
    fn csv_to_csv_and_json() {
        let r = run("SELECT * FROM S3Object", &csv_in("NONE"), &csv_out(), None, PEOPLE.as_bytes());
        assert_eq!(text(r), PEOPLE);
        let r = run(
            "SELECT s.name, s.city FROM S3Object s WHERE CAST(s.age AS INT) > 30",
            &csv_in("USE"),
            &csv_out(),
            None,
            PEOPLE.as_bytes(),
        );
        assert_eq!(text(r), "alice,\"Paris, FR\"\ncarol,Oslo\n");
        let r = run("SELECT name FROM S3Object LIMIT 1", &csv_in("USE"), &json_out(), None, PEOPLE.as_bytes());
        assert_eq!(text(r), "{\"name\":\"alice\"}\n");
        let r = run("SELECT * FROM S3Object s LIMIT 1", &csv_in("IGNORE"), &json_out(), None, PEOPLE.as_bytes());
        assert_eq!(text(r), "{\"_1\":\"alice\",\"_2\":\"34\",\"_3\":\"Paris, FR\"}\n");
    }

    #[test]
    fn aggregates_and_compression() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, PEOPLE.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let mut input = csv_in("USE");
        input.compression_type = Some("GZIP".into());
        let r = run("SELECT COUNT(*), SUM(CAST(age AS INT)), MIN(name) FROM S3Object", &input, &csv_out(), None, &gz)
            .unwrap();
        assert_eq!(String::from_utf8(r.records).unwrap(), "3,102,alice\n");
        assert_eq!(r.bytes_scanned, gz.len() as i64);
        assert_eq!(r.bytes_processed, PEOPLE.len() as i64);
    }

    #[test]
    fn json_lines_and_documents() {
        let lines = "{\"a\":1,\"b\":{\"c\":\"x\"}}\n{\"a\":2}\n";
        let input = types::InputSerialization {
            json: Some(types::JSONInput { r#type: Some("LINES".into()) }),
            ..Default::default()
        };
        let r = run("SELECT s.a, s.b.c FROM S3Object s WHERE s.a > 1", &input, &json_out(), None, lines.as_bytes());
        assert_eq!(text(r), "{\"a\":2}\n");
        let r = run("SELECT s.b.c FROM S3Object s", &input, &csv_out(), None, lines.as_bytes());
        assert_eq!(text(r), "x\n\n");
        let doc = "{\"items\":[{\"id\":1},{\"id\":2}]}";
        let input = types::InputSerialization {
            json: Some(types::JSONInput { r#type: Some("DOCUMENT".into()) }),
            ..Default::default()
        };
        let r = run("SELECT i.id FROM S3Object[*].items[*] i", &input, &csv_out(), None, doc.as_bytes());
        assert_eq!(text(r), "1\n2\n");
    }

    #[test]
    fn scan_ranges_select_records_that_start_inside() {
        let data = "a\nbb\nccc\n";
        let range = types::ScanRange { start: Some(1), end: Some(5) };
        let r = run("SELECT * FROM S3Object", &csv_in("NONE"), &csv_out(), Some(&range), data.as_bytes());
        assert_eq!(text(r), "bb\nccc\n");
    }

    #[test]
    fn errors_have_s3_select_codes() {
        let e = run("SELEC * FROM S3Object", &csv_in("NONE"), &csv_out(), None, b"a").err().unwrap();
        assert_eq!(e.code, "ParseUnexpectedToken");
        let e = run("SELECT CAST(_1 AS INT) FROM S3Object", &csv_in("NONE"), &csv_out(), None, b"x").err().unwrap();
        assert_eq!(e.code, "CastFailed");
    }
}
