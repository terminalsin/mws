//! What Firehose writes to S3: object keys from prefixes (with
//! `!{timestamp:...}`, `!{firehose:...}` and partition key expressions),
//! compression, and the JSON lines of the error output.

use std::collections::BTreeMap;
use std::io::Write;

use base64::Engine;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde_json::json;

use crate::processing::Failed;

/// Keys a prefix expression can name.
pub struct PrefixInputs<'a> {
    pub at: DateTime<Utc>,
    pub error_output_type: Option<&'a str>,
    pub query_keys: &'a BTreeMap<String, String>,
    pub lambda_keys: &'a BTreeMap<String, String>,
}

/// A Java `DateTimeFormatter` pattern (`yyyy/MM/dd`) as chrono formats it.
fn java_format(pattern: &str, at: DateTime<Utc>) -> String {
    let mut out = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let mut n = 1;
        while i + n < chars.len() && chars[i + n] == c {
            n += 1;
        }
        let piece = match (c, n) {
            ('y', 2) => at.format("%y").to_string(),
            ('y', _) => at.format("%Y").to_string(),
            ('M', _) => at.format("%m").to_string(),
            ('d', _) => at.format("%d").to_string(),
            ('H', _) => at.format("%H").to_string(),
            ('m', _) => at.format("%M").to_string(),
            ('s', _) => at.format("%S").to_string(),
            ('S', _) => at.format("%3f").to_string(),
            _ => std::iter::repeat_n(c, n).collect(),
        };
        out.push_str(&piece);
        i += n;
    }
    out
}

fn random_string() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..11).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// Evaluate a prefix. Without a `!{timestamp:...}` expression (and outside
/// dynamic partitioning) Firehose adds the default `YYYY/MM/DD/HH/`.
pub fn evaluate_prefix(prefix: &str, inputs: &PrefixInputs<'_>, dynamic: bool) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = prefix;
    let mut timestamped = false;
    while let Some(start) = rest.find("!{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| format!("Unterminated expression in prefix {prefix}"))?;
        let expr = &after[..end];
        let (ns, arg) = expr.split_once(':').unwrap_or((expr, ""));
        let value = match ns {
            "timestamp" => {
                timestamped = true;
                java_format(arg, inputs.at)
            }
            "firehose" => match arg {
                "random-string" => random_string(),
                "error-output-type" => inputs.error_output_type.unwrap_or_default().to_string(),
                other => return Err(format!("Unknown firehose expression {other}")),
            },
            "partitionKeyFromQuery" => {
                inputs.query_keys.get(arg).cloned().ok_or_else(|| format!("The partition key {arg} has no value"))?
            }
            "partitionKeyFromLambda" => {
                inputs.lambda_keys.get(arg).cloned().ok_or_else(|| format!("The partition key {arg} has no value"))?
            }
            other => return Err(format!("Unknown namespace {other}")),
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    if !timestamped && !dynamic {
        out.push_str(&inputs.at.format("%Y/%m/%d/%H/").to_string());
    }
    Ok(out)
}

/// The key prefix error output goes under.
pub fn error_prefix(configured: Option<&str>, output_type: &str, at: DateTime<Utc>) -> String {
    let empty = BTreeMap::new();
    let inputs = PrefixInputs { at, error_output_type: Some(output_type), query_keys: &empty, lambda_keys: &empty };
    match configured.filter(|p| !p.is_empty()) {
        Some(p) => evaluate_prefix(p, &inputs, false).unwrap_or_else(|_| format!("{output_type}/")),
        None => format!("{output_type}/{}", at.format("%Y/%m/%d/%H/")),
    }
}

/// The object name Firehose gives a delivery:
/// `<stream>-<version>-<yyyy-MM-dd-HH-mm-ss>-<uuid>` and the extension.
pub fn object_name(stream: &str, version: u64, at: DateTime<Utc>, extension: &str) -> String {
    format!("{stream}-{version}-{}-{}{extension}", at.format("%Y-%m-%d-%H-%M-%S"), uuid::Uuid::new_v4())
}

/// The extension for a compression format, unless one is configured.
pub fn extension(configured: Option<&str>, compression: &str) -> String {
    if let Some(e) = configured.filter(|e| !e.is_empty()) {
        return e.to_string();
    }
    match compression {
        "GZIP" => ".gz",
        "ZIP" => ".zip",
        "Snappy" => ".snappy",
        "HADOOP_SNAPPY" => ".hsnappy",
        _ => "",
    }
    .to_string()
}

/// Compress a delivery's bytes.
pub fn compress(format: &str, data: &[u8], entry_name: &str) -> Vec<u8> {
    match format {
        "GZIP" => {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(data).expect("writing to memory");
            gz.finish().expect("writing to memory")
        }
        "ZIP" => {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut z = zip::ZipWriter::new(&mut buf);
                z.start_file(entry_name, zip::write::SimpleFileOptions::default()).expect("writing to memory");
                z.write_all(data).expect("writing to memory");
                z.finish().expect("writing to memory");
            }
            buf.into_inner()
        }
        "Snappy" => {
            let mut w = snap::write::FrameEncoder::new(Vec::new());
            w.write_all(data).expect("writing to memory");
            w.into_inner().unwrap_or_default()
        }
        "HADOOP_SNAPPY" => {
            // Hadoop's block format: uncompressed length, then chunks of
            // compressed length + raw Snappy data.
            let mut out = Vec::new();
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let block = snap::raw::Encoder::new().compress_vec(data).unwrap_or_default();
            out.extend_from_slice(&(block.len() as u32).to_be_bytes());
            out.extend_from_slice(&block);
            out
        }
        _ => data.to_vec(),
    }
}

/// The error output for failed records: one JSON document per line.
pub fn error_lines(failed: &[Failed], attempt_end: i64) -> Vec<u8> {
    let mut out = Vec::new();
    for f in failed {
        let mut v = json!({
            "attemptsMade": 1,
            "arrivalTimestamp": f.source.arrival,
            "errorCode": f.error_code,
            "errorMessage": f.error_message,
            "attemptEndingTimestamp": attempt_end,
            "rawData": base64::engine::general_purpose::STANDARD.encode(&f.data),
        });
        if let Some(arn) = &f.lambda_arn {
            v["lambdaArn"] = json!(arn);
        }
        out.extend_from_slice(v.to_string().as_bytes());
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-03-04T05:06:07Z").unwrap().with_timezone(&Utc)
    }

    #[test]
    fn prefixes() {
        let empty = BTreeMap::new();
        let mut q = BTreeMap::new();
        q.insert("customer".to_string(), "42".to_string());
        let i = PrefixInputs { at: at(), error_output_type: None, query_keys: &q, lambda_keys: &empty };
        assert_eq!(evaluate_prefix("", &i, false).unwrap(), "2026/03/04/05/");
        assert_eq!(evaluate_prefix("logs/", &i, false).unwrap(), "logs/2026/03/04/05/");
        assert_eq!(evaluate_prefix("y=!{timestamp:yyyy}/m=!{timestamp:MM}/", &i, false).unwrap(), "y=2026/m=03/");
        assert_eq!(evaluate_prefix("c=!{partitionKeyFromQuery:customer}/", &i, true).unwrap(), "c=42/");
        assert!(evaluate_prefix("!{partitionKeyFromLambda:x}/", &i, true).is_err());
        assert_eq!(error_prefix(None, "processing-failed", at()), "processing-failed/2026/03/04/05/");
        assert_eq!(
            error_prefix(Some("err/!{firehose:error-output-type}/"), "processing-failed", at()),
            "err/processing-failed/2026/03/04/05/"
        );
        let name = object_name("s", 1, at(), ".gz");
        assert!(name.starts_with("s-1-2026-03-04-05-06-07-") && name.ends_with(".gz"));
    }

    #[test]
    fn compression_round_trips() {
        use std::io::Read;
        let gz = compress("GZIP", b"hello", "x");
        let mut out = String::new();
        flate2::read::GzDecoder::new(gz.as_slice()).read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello");
        let sn = compress("Snappy", b"hello", "x");
        let mut out = Vec::new();
        snap::read::FrameDecoder::new(sn.as_slice()).read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(compress("UNCOMPRESSED", b"hi", "x"), b"hi");
    }
}
