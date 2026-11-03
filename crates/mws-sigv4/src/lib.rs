//! Server-side verification of AWS Signature Version 4.
//!
//! Verification is split in two so the caller can look up the secret key in
//! between: [`parse`] extracts the claimed credential from the request, then
//! [`verify`] recomputes the signature with the secret and compares.
//!
//! Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>

use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const AMZ_DATE_FORMAT: &str = "%Y%m%dT%H%M%SZ";
/// AWS rejects requests whose timestamp is more than 15 minutes off.
pub const MAX_CLOCK_SKEW: TimeDelta = TimeDelta::minutes(15);
/// Presigned URLs may be valid for at most 7 days.
const MAX_PRESIGN_EXPIRES: i64 = 604_800;

/// Characters SigV4 leaves unencoded: `A-Z a-z 0-9 - _ . ~`.
const SIGV4_ENCODE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigV4Error {
    /// The request carries no SigV4 authentication at all.
    #[error("request is not signed")]
    Missing,
    /// Authentication is present but malformed (AWS: `IncompleteSignature`).
    #[error("{0}")]
    Incomplete(String),
    /// The algorithm is not one MWS supports.
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The request date is outside the allowed skew.
    #[error("Signature expired: {request} is now earlier than {earliest} ({now} - 15 min.)")]
    Expired { request: String, earliest: String, now: String },
    /// A presigned URL whose `X-Amz-Expires` has passed.
    #[error("Request has expired")]
    PresignExpired,
    /// The recomputed signature differs.
    #[error("signature does not match")]
    Mismatch,
    /// The body's SHA-256 is not the one `x-amz-content-sha256` claims.
    #[error("The provided 'x-amz-content-sha256' header does not match what was computed.")]
    ContentSha256Mismatch,
    /// An `aws-chunked` body that cannot be decoded.
    #[error("{0}")]
    MalformedChunks(String),
}

/// The payload claim of a signed request (`x-amz-content-sha256`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// The SHA-256 of the body, hex encoded.
    Hash(String),
    /// `UNSIGNED-PAYLOAD`.
    Unsigned,
    /// An `aws-chunked` body: `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
    /// (`signed`) or `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, optionally with a
    /// trailer (`-TRAILER`).
    Streaming { signed: bool, trailer: bool },
}

impl Payload {
    /// What `request` claims about its payload. Requests without the header
    /// sign the SHA-256 of their body.
    pub fn of<B>(request: &http::Request<B>) -> Result<Option<Self>, SigV4Error> {
        let Some(v) = request.headers().get("x-amz-content-sha256") else { return Ok(None) };
        let v = v.to_str().unwrap_or_default();
        Ok(Some(match v {
            "UNSIGNED-PAYLOAD" => Payload::Unsigned,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => Payload::Streaming { signed: true, trailer: false },
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => Payload::Streaming { signed: true, trailer: true },
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Payload::Streaming { signed: false, trailer: true },
            h if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => Payload::Hash(h.to_ascii_lowercase()),
            other => {
                return Err(SigV4Error::Incomplete(format!(
                    "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, or a valid sha256 value. Got: {other}"
                )))
            }
        }))
    }
}

/// A decoded `aws-chunked` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedChunks {
    pub body: Vec<u8>,
    /// Trailing headers (e.g. `x-amz-checksum-crc32`), lowercase names.
    pub trailers: Vec<(String, String)>,
}

/// Check the body against the request's payload claim, decoding an
/// `aws-chunked` body (and verifying its chunk signatures against
/// `parsed.signature`, the seed). Returns `None` when the body is used as is.
pub fn check_payload(
    request: &http::Request<impl AsRef<[u8]>>,
    parsed: &ParsedSignature,
    secret_access_key: &str,
) -> Result<Option<DecodedChunks>, SigV4Error> {
    match Payload::of(request)? {
        None | Some(Payload::Unsigned) => Ok(None),
        Some(Payload::Hash(h)) => {
            if hex::encode(Sha256::digest(request.body().as_ref())) == h {
                Ok(None)
            } else {
                Err(SigV4Error::ContentSha256Mismatch)
            }
        }
        Some(Payload::Streaming { signed, trailer }) => {
            let key = signing_key(secret_access_key, &parsed.scope);
            let signer = signed.then(|| ChunkSigner {
                key,
                prefix: format!("{}\n{}", parsed.amz_date, parsed.scope.scope_string()),
                previous: parsed.signature.clone(),
            });
            decode_chunks(request.body().as_ref(), signer, trailer).map(Some)
        }
    }
}

struct ChunkSigner {
    key: Vec<u8>,
    /// `{amz-date}\n{scope}`.
    prefix: String,
    previous: String,
}

impl ChunkSigner {
    fn check(&mut self, algorithm: &str, hash: &str, claimed: Option<&str>) -> Result<(), SigV4Error> {
        let empty = hex::encode(Sha256::digest(b""));
        let to_sign = if algorithm == "AWS4-HMAC-SHA256-PAYLOAD" {
            format!("{algorithm}\n{}\n{}\n{empty}\n{hash}", self.prefix, self.previous)
        } else {
            format!("{algorithm}\n{}\n{}\n{hash}", self.prefix, self.previous)
        };
        let expected = hex::encode(hmac(&self.key, to_sign.as_bytes()));
        match claimed {
            Some(c) if bool::from(expected.as_bytes().ct_eq(c.as_bytes())) => {
                self.previous = expected;
                Ok(())
            }
            _ => Err(SigV4Error::Mismatch),
        }
    }
}

fn malformed(msg: &str) -> SigV4Error {
    SigV4Error::MalformedChunks(msg.to_string())
}

/// Decode `size[;chunk-signature=sig]\r\ndata\r\n ... 0[;...]\r\n[trailers]\r\n`.
fn decode_chunks(raw: &[u8], mut signer: Option<ChunkSigner>, trailer: bool) -> Result<DecodedChunks, SigV4Error> {
    let line = |pos: usize| -> Result<(&[u8], usize), SigV4Error> {
        let rest = raw.get(pos..).ok_or_else(|| malformed("Incomplete aws-chunked body."))?;
        let end =
            rest.windows(2).position(|w| w == b"\r\n").ok_or_else(|| malformed("Incomplete aws-chunked body."))?;
        Ok((&rest[..end], pos + end + 2))
    };
    let mut body = Vec::new();
    let mut pos = 0;
    loop {
        let (header, next) = line(pos)?;
        let header = std::str::from_utf8(header).map_err(|_| malformed("Invalid chunk header."))?;
        let (size, ext) = header.split_once(';').unwrap_or((header, ""));
        let size = usize::from_str_radix(size.trim(), 16).map_err(|_| malformed("Invalid chunk size."))?;
        let claimed = ext.trim().strip_prefix("chunk-signature=");
        let data = raw.get(next..next + size).ok_or_else(|| malformed("Incomplete aws-chunked body."))?;
        if let Some(s) = signer.as_mut() {
            s.check("AWS4-HMAC-SHA256-PAYLOAD", &hex::encode(Sha256::digest(data)), claimed)?;
        }
        body.extend_from_slice(data);
        pos = next + size;
        if size == 0 {
            break;
        }
        if raw.get(pos..pos + 2) != Some(b"\r\n") {
            return Err(malformed("Chunk data is not followed by CRLF."));
        }
        pos += 2;
    }
    let mut trailers = Vec::new();
    let mut trailer_text = String::new();
    let mut trailer_signature = None;
    // After the final chunk: trailer lines, then an empty line. Tolerate a
    // missing final CRLF.
    while pos < raw.len() {
        let (l, next) = match line(pos) {
            Ok(x) => x,
            Err(_) => (&raw[pos..], raw.len()),
        };
        pos = next;
        if l.is_empty() {
            continue;
        }
        let l = std::str::from_utf8(l).map_err(|_| malformed("Invalid trailer."))?;
        let (k, v) = l.split_once(':').ok_or_else(|| malformed("Invalid trailer."))?;
        let k = k.trim().to_ascii_lowercase();
        if k == "x-amz-trailer-signature" {
            trailer_signature = Some(v.trim().to_string());
            continue;
        }
        trailer_text.push_str(&format!("{k}:{}\n", v.trim()));
        trailers.push((k, v.trim().to_string()));
    }
    if let (Some(s), true) = (signer.as_mut(), trailer) {
        s.check(
            "AWS4-HMAC-SHA256-TRAILER",
            &hex::encode(Sha256::digest(trailer_text.as_bytes())),
            trailer_signature.as_deref(),
        )?;
    }
    Ok(DecodedChunks { body, trailers })
}

/// Where the signature came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureLocation {
    Header,
    Query,
}

/// The credential scope: `AKID/date/region/service/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    pub access_key_id: String,
    pub date: String,
    pub region: String,
    pub service: String,
}

impl CredentialScope {
    fn scope_string(&self) -> String {
        format!("{}/{}/{}/aws4_request", self.date, self.region, self.service)
    }
}

/// The signature claims extracted from a request, before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignature {
    pub location: SignatureLocation,
    pub scope: CredentialScope,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub amz_date: String,
    pub timestamp: DateTime<Utc>,
    pub session_token: Option<String>,
    /// Presigned URLs only.
    pub expires_in: Option<i64>,
}

/// Extract the SigV4 claims from a request's headers or query string.
pub fn parse<B>(request: &http::Request<B>) -> Result<ParsedSignature, SigV4Error> {
    if let Some(auth) = request.headers().get(http::header::AUTHORIZATION) {
        let auth =
            auth.to_str().map_err(|_| SigV4Error::Incomplete("Authorization header is not valid ASCII".into()))?;
        return parse_header(request, auth);
    }
    let query = request.uri().query().unwrap_or("");
    let params = decode_query(query);
    if params.iter().any(|(k, _)| k == "X-Amz-Algorithm" || k == "X-Amz-Signature") {
        return parse_query(&params);
    }
    Err(SigV4Error::Missing)
}

fn parse_header<B>(request: &http::Request<B>, auth: &str) -> Result<ParsedSignature, SigV4Error> {
    let (algorithm, rest) = auth.trim().split_once(' ').ok_or_else(|| {
        SigV4Error::Incomplete(format!("Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization={auth}"))
    })?;
    if algorithm != ALGORITHM {
        return Err(SigV4Error::UnsupportedAlgorithm(algorithm.to_string()));
    }
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else { continue };
        match k.trim() {
            "Credential" => credential = Some(v.trim().to_string()),
            "SignedHeaders" => signed_headers = Some(v.trim().to_string()),
            "Signature" => signature = Some(v.trim().to_string()),
            _ => {}
        }
    }
    let mut missing = Vec::new();
    if credential.is_none() {
        missing.push("Authorization header requires 'Credential' parameter.");
    }
    if signature.is_none() {
        missing.push("Authorization header requires 'Signature' parameter.");
    }
    if signed_headers.is_none() {
        missing.push("Authorization header requires 'SignedHeaders' parameter.");
    }
    if !missing.is_empty() {
        return Err(SigV4Error::Incomplete(format!("{} Authorization={auth}", missing.join(" "))));
    }
    let scope = parse_scope(&credential.unwrap())?;
    let headers = request.headers();
    let amz_date = header_str(headers, "x-amz-date").or_else(|| header_str(headers, "date")).ok_or_else(|| {
        SigV4Error::Incomplete(
            "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.".into(),
        )
    })?;
    let timestamp = parse_amz_date(&amz_date)?;
    Ok(ParsedSignature {
        location: SignatureLocation::Header,
        scope,
        signed_headers: split_signed_headers(&signed_headers.unwrap()),
        signature: signature.unwrap(),
        amz_date,
        timestamp,
        session_token: header_str(headers, "x-amz-security-token"),
        expires_in: None,
    })
}

fn parse_query(params: &[(String, String)]) -> Result<ParsedSignature, SigV4Error> {
    let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let algorithm = get("X-Amz-Algorithm").unwrap_or_default();
    if algorithm != ALGORITHM {
        return Err(SigV4Error::UnsupportedAlgorithm(algorithm));
    }
    let required = ["X-Amz-Credential", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Signature"];
    let missing: Vec<_> = required.iter().filter(|n| get(n).is_none()).collect();
    if !missing.is_empty() {
        return Err(SigV4Error::Incomplete(format!(
            "AWS query-string parameters must include {}. Re-examine the query-string parameters.",
            missing.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ")
        )));
    }
    let amz_date = get("X-Amz-Date").unwrap();
    let expires_in = match get("X-Amz-Expires") {
        Some(v) => Some(v.parse::<i64>().map_err(|_| SigV4Error::Incomplete("X-Amz-Expires must be a number".into()))?),
        None => None,
    };
    if let Some(e) = expires_in {
        if !(0..=MAX_PRESIGN_EXPIRES).contains(&e) {
            return Err(SigV4Error::Incomplete(
                "X-Amz-Expires must be less than a week (in seconds) that is 604800".into(),
            ));
        }
    }
    Ok(ParsedSignature {
        location: SignatureLocation::Query,
        scope: parse_scope(&get("X-Amz-Credential").unwrap())?,
        signed_headers: split_signed_headers(&get("X-Amz-SignedHeaders").unwrap()),
        signature: get("X-Amz-Signature").unwrap(),
        timestamp: parse_amz_date(&amz_date)?,
        amz_date,
        session_token: get("X-Amz-Security-Token"),
        expires_in,
    })
}

fn parse_scope(credential: &str) -> Result<CredentialScope, SigV4Error> {
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(SigV4Error::Incomplete(format!(
            "Credential should be scoped to a valid region. Credential={credential}"
        )));
    }
    Ok(CredentialScope {
        access_key_id: parts[0].to_string(),
        date: parts[1].to_string(),
        region: parts[2].to_string(),
        service: parts[3].to_string(),
    })
}

fn split_signed_headers(s: &str) -> Vec<String> {
    s.split(';').filter(|h| !h.is_empty()).map(|h| h.to_ascii_lowercase()).collect()
}

fn parse_amz_date(s: &str) -> Result<DateTime<Utc>, SigV4Error> {
    if let Ok(t) = NaiveDateTime::parse_from_str(s, AMZ_DATE_FORMAT) {
        return Ok(t.and_utc());
    }
    // `Date` header fallback (RFC 1123).
    DateTime::parse_from_rfc2822(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| SigV4Error::Incomplete(format!("Invalid date format: {s}")))
}

fn header_str(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Options that differ between services.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// S3 does not normalize or double-encode the path; every other service
    /// does.
    pub double_encode_path: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { double_encode_path: true }
    }
}

/// Recompute the signature with `secret_access_key` and compare it with the
/// one in `parsed`. Also enforces clock skew and presigned expiry against
/// `now`.
pub fn verify(
    request: &http::Request<impl AsRef<[u8]>>,
    parsed: &ParsedSignature,
    secret_access_key: &str,
    now: DateTime<Utc>,
    options: VerifyOptions,
) -> Result<(), SigV4Error> {
    check_time(parsed, now)?;
    let expected = compute_signature(request, parsed, secret_access_key, options);
    if bool::from(expected.as_bytes().ct_eq(parsed.signature.as_bytes())) {
        Ok(())
    } else {
        Err(SigV4Error::Mismatch)
    }
}

fn check_time(parsed: &ParsedSignature, now: DateTime<Utc>) -> Result<(), SigV4Error> {
    match parsed.expires_in {
        Some(expires) => {
            if now > parsed.timestamp + TimeDelta::seconds(expires) {
                return Err(SigV4Error::PresignExpired);
            }
            if parsed.timestamp > now + MAX_CLOCK_SKEW {
                return Err(SigV4Error::PresignExpired);
            }
        }
        None => {
            if parsed.timestamp < now - MAX_CLOCK_SKEW {
                return Err(SigV4Error::Expired {
                    request: parsed.amz_date.clone(),
                    earliest: (now - MAX_CLOCK_SKEW).format(AMZ_DATE_FORMAT).to_string(),
                    now: now.format(AMZ_DATE_FORMAT).to_string(),
                });
            }
            if parsed.timestamp > now + MAX_CLOCK_SKEW {
                return Err(SigV4Error::Expired {
                    request: parsed.amz_date.clone(),
                    earliest: (now + MAX_CLOCK_SKEW).format(AMZ_DATE_FORMAT).to_string(),
                    now: now.format(AMZ_DATE_FORMAT).to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Compute the hex signature the client should have sent.
pub fn compute_signature(
    request: &http::Request<impl AsRef<[u8]>>,
    parsed: &ParsedSignature,
    secret_access_key: &str,
    options: VerifyOptions,
) -> String {
    let canonical = canonical_request(request, parsed, options);
    let string_to_sign = format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        parsed.amz_date,
        parsed.scope.scope_string(),
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let key = signing_key(secret_access_key, &parsed.scope);
    hex::encode(hmac(&key, string_to_sign.as_bytes()))
}

/// Build the canonical request string (exposed for debugging and tests).
pub fn canonical_request(
    request: &http::Request<impl AsRef<[u8]>>,
    parsed: &ParsedSignature,
    options: VerifyOptions,
) -> String {
    let method = request.method().as_str();
    let uri = canonical_uri(request.uri().path(), options);
    let query = canonical_query(request.uri().query().unwrap_or(""), parsed.location);
    let headers = request.headers();
    let mut canonical_headers = String::new();
    for name in &parsed.signed_headers {
        let values: Vec<String> = if name == "host" && headers.get("host").is_none() {
            request.uri().authority().map(|a| vec![a.to_string()]).unwrap_or_default()
        } else {
            headers
                .get_all(name.as_str())
                .iter()
                .map(|v| normalize_header_value(&String::from_utf8_lossy(v.as_bytes())))
                .collect()
        };
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&values.join(","));
        canonical_headers.push('\n');
    }
    let payload_hash = payload_hash(request, parsed);
    format!("{method}\n{uri}\n{query}\n{canonical_headers}\n{}\n{payload_hash}", parsed.signed_headers.join(";"))
}

fn payload_hash(request: &http::Request<impl AsRef<[u8]>>, parsed: &ParsedSignature) -> String {
    if let Some(v) = request.headers().get("x-amz-content-sha256").and_then(|v| v.to_str().ok()) {
        return v.to_string();
    }
    if parsed.location == SignatureLocation::Query && parsed.scope.service == "s3" {
        return "UNSIGNED-PAYLOAD".into();
    }
    hex::encode(Sha256::digest(request.body().as_ref()))
}

fn normalize_header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_uri(path: &str, options: VerifyOptions) -> String {
    if path.is_empty() {
        return "/".into();
    }
    if !options.double_encode_path {
        return path.to_string();
    }
    // Normalize dot segments and repeated slashes the way the SDKs do, then
    // encode each (already encoded) segment a second time.
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(
        &segments.iter().map(|s| utf8_percent_encode(s, SIGV4_ENCODE).to_string()).collect::<Vec<_>>().join("/"),
    );
    if path.ends_with('/') && out.len() > 1 {
        out.push('/');
    }
    out
}

fn canonical_query(query: &str, location: SignatureLocation) -> String {
    let mut pairs: Vec<(String, String)> = decode_query(query)
        .into_iter()
        .filter(|(k, _)| !(location == SignatureLocation::Query && k == "X-Amz-Signature"))
        .map(|(k, v)| (sigv4_encode(&k), sigv4_encode(&v)))
        .collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

fn decode_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            // `+` is a literal plus in SigV4 canonicalization, not a space.
            (
                percent_decode_str(k).decode_utf8_lossy().into_owned(),
                percent_decode_str(v).decode_utf8_lossy().into_owned(),
            )
        })
        .collect()
}

/// What [`presign_url`] signs with.
#[derive(Debug, Clone)]
pub struct PresignParams<'a> {
    pub method: &'a str,
    /// `http://host:port/path?query`, path already URI-encoded.
    pub url: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: Option<&'a str>,
    pub now: DateTime<Utc>,
    pub expires_in: i64,
}

/// Presign `url` with query-string SigV4, as SDKs do for S3: only `host` is
/// signed and the payload is `UNSIGNED-PAYLOAD`.
pub fn presign_url(p: &PresignParams<'_>) -> Result<String, SigV4Error> {
    let bad = |m: &str| SigV4Error::Incomplete(m.to_string());
    let uri: http::Uri = p.url.parse().map_err(|_| bad("invalid URL"))?;
    let authority = uri.authority().ok_or_else(|| bad("URL has no host"))?.to_string();
    let amz_date = p.now.format(AMZ_DATE_FORMAT).to_string();
    let scope = CredentialScope {
        access_key_id: p.access_key_id.to_string(),
        date: p.now.format("%Y%m%d").to_string(),
        region: p.region.to_string(),
        service: p.service.to_string(),
    };
    let mut query = uri.query().map(str::to_string).unwrap_or_default();
    let mut add = |k: &str, v: &str| {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(k);
        query.push('=');
        query.push_str(&sigv4_encode(v));
    };
    add("X-Amz-Algorithm", ALGORITHM);
    add("X-Amz-Credential", &format!("{}/{}", p.access_key_id, scope.scope_string()));
    add("X-Amz-Date", &amz_date);
    add("X-Amz-Expires", &p.expires_in.to_string());
    if let Some(t) = p.session_token {
        add("X-Amz-Security-Token", t);
    }
    add("X-Amz-SignedHeaders", "host");
    let path_and_query = format!("{}?{query}", uri.path());
    let request = http::Request::builder()
        .method(p.method)
        .uri(&path_and_query)
        .header(http::header::HOST, &authority)
        .body(Vec::<u8>::new())
        .map_err(|_| bad("invalid request"))?;
    let parsed = ParsedSignature {
        location: SignatureLocation::Query,
        scope,
        signed_headers: vec!["host".into()],
        signature: String::new(),
        amz_date,
        timestamp: p.now,
        session_token: p.session_token.map(str::to_string),
        expires_in: Some(p.expires_in),
    };
    let options = VerifyOptions { double_encode_path: p.service != "s3" };
    let signature = compute_signature(&request, &parsed, p.secret_access_key, options);
    let scheme = uri.scheme_str().unwrap_or("http");
    Ok(format!("{scheme}://{authority}{path_and_query}&X-Amz-Signature={signature}"))
}

fn sigv4_encode(s: &str) -> String {
    utf8_percent_encode(s, SIGV4_ENCODE).to_string()
}

fn signing_key(secret: &str, scope: &CredentialScope) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), scope.date.as_bytes());
    let k_region = hmac(&k_date, scope.region.as_bytes());
    let k_service = hmac(&k_region, scope.service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests;
