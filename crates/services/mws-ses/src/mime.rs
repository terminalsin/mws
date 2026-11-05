//! Building the MIME messages SES sends, and reading the ones callers
//! (`SendRawEmail`) and SMTP clients hand over.

use base64::Engine;
use mws_core::RequestContext;

use crate::templates::Rendered;

pub const CRLF: &str = "\r\n";

/// Headers SES does not let callers set on a `Simple` v2 message.
const RESERVED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "message-id",
    "date",
    "return-path",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "reply-to",
    "sender",
    "dkim-signature",
    "received",
];

pub fn is_reserved_header(name: &str) -> bool {
    RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

/// A message SES composes from parts.
#[derive(Debug, Clone, Default)]
pub struct Compose<'a> {
    pub message_id: &'a str,
    pub from: &'a str,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub reply_to: &'a [String],
    pub subject: &'a str,
    pub text: Option<&'a str>,
    pub html: Option<&'a str>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, Default)]
pub struct Attachment {
    pub file_name: String,
    pub content_type: String,
    pub disposition: String,
    pub content_id: Option<String>,
    pub description: Option<String>,
    pub data: Vec<u8>,
}

/// RFC 2047-encode a header value if it is not plain ASCII.
pub fn encode_header(value: &str) -> String {
    if value.is_ascii() {
        value.to_string()
    } else {
        format!("=?UTF-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(value.as_bytes()))
    }
}

fn boundary() -> String {
    format!("----=_Part_{}", uuid::Uuid::new_v4().simple())
}

fn body_part(content_type: &str, body: &str) -> String {
    if body.is_ascii() && body.lines().all(|l| l.len() < 990) {
        format!(
            "Content-Type: {content_type}; charset=UTF-8{CRLF}Content-Transfer-Encoding: 7bit{CRLF}{CRLF}{}{CRLF}",
            body.replace("\r\n", "\n").replace('\n', CRLF)
        )
    } else {
        format!(
            "Content-Type: {content_type}; charset=UTF-8{CRLF}Content-Transfer-Encoding: base64{CRLF}{CRLF}{}{CRLF}",
            wrap_base64(body.as_bytes())
        )
    }
}

fn wrap_base64(data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    b64.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(CRLF)
}

fn alternative(text: Option<&str>, html: Option<&str>) -> String {
    match (text, html) {
        (Some(t), Some(h)) => {
            let b = boundary();
            format!(
                "Content-Type: multipart/alternative; {CRLF} boundary=\"{b}\"{CRLF}{CRLF}--{b}{CRLF}{}{CRLF}--{b}{CRLF}{}{CRLF}--{b}--{CRLF}",
                body_part("text/plain", t),
                body_part("text/html", h)
            )
        }
        (None, Some(h)) => body_part("text/html", h),
        (Some(t), None) => body_part("text/plain", t),
        (None, None) => body_part("text/plain", ""),
    }
}

/// The whole message, as SES would put it on the wire.
pub fn compose(ctx: &RequestContext, m: &Compose<'_>) -> String {
    let mut out = String::new();
    let mut header = |name: &str, value: &str| {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str(CRLF);
    };
    header("From", &encode_header(m.from));
    if !m.reply_to.is_empty() {
        header("Reply-To", &m.reply_to.join(", "));
    }
    if !m.to.is_empty() {
        header("To", &m.to.join(", "));
    }
    if !m.cc.is_empty() {
        header("Cc", &m.cc.join(", "));
    }
    header("Subject", &encode_header(m.subject));
    header("Message-ID", &format!("<{}@email.amazonses.com>", m.message_id));
    header("Date", &ctx.received_at.format("%a, %d %b %Y %H:%M:%S +0000").to_string());
    header("MIME-Version", "1.0");
    for (k, v) in &m.headers {
        header(k, v);
    }
    let body = alternative(m.text, m.html);
    if m.attachments.is_empty() {
        out.push_str(&body);
        return out;
    }
    let b = boundary();
    out.push_str(&format!("Content-Type: multipart/mixed; {CRLF} boundary=\"{b}\"{CRLF}{CRLF}--{b}{CRLF}{body}{CRLF}"));
    for a in &m.attachments {
        out.push_str(&format!("--{b}{CRLF}"));
        out.push_str(&format!("Content-Type: {}; name=\"{}\"{CRLF}", a.content_type, a.file_name));
        out.push_str(&format!(
            "Content-Disposition: {}; filename=\"{}\"{CRLF}",
            a.disposition.to_ascii_lowercase(),
            a.file_name
        ));
        if let Some(id) = &a.content_id {
            out.push_str(&format!("Content-ID: <{}>{CRLF}", id.trim_matches(|c| c == '<' || c == '>')));
        }
        if let Some(d) = &a.description {
            out.push_str(&format!("Content-Description: {d}{CRLF}"));
        }
        out.push_str(&format!("Content-Transfer-Encoding: base64{CRLF}{CRLF}{}{CRLF}", wrap_base64(&a.data)));
    }
    out.push_str(&format!("--{b}--{CRLF}"));
    out
}

/// What `TestRenderTemplate` returns: the rendered parts as a MIME
/// message without addresses.
pub fn render_preview(ctx: &RequestContext, r: &Rendered) -> String {
    let mut out = String::new();
    out.push_str(&format!("Date: {}{CRLF}", ctx.received_at.format("%a, %d %b %Y %H:%M:%S +0000")));
    out.push_str(&format!("Message-ID: <{}@email.amazonses.com>{CRLF}", uuid::Uuid::new_v4()));
    out.push_str(&format!("Subject: {}{CRLF}", encode_header(&r.subject)));
    out.push_str(&format!("MIME-Version: 1.0{CRLF}"));
    out.push_str(&alternative(r.text.as_deref(), r.html.as_deref()));
    out
}

/// A message read back from its MIME text.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    /// Header names and (unfolded) values, in order.
    pub headers: Vec<(String, String)>,
    pub text: Option<String>,
    pub html: Option<String>,
}

impl Parsed {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Addresses in an address-list header (`To`, `Cc`, ...).
    pub fn addresses(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| split_addresses(v))
            .collect()
    }

    pub fn subject(&self) -> String {
        self.header("Subject").map(decode_header).unwrap_or_default()
    }
}

/// Split `a@x, "B, C" <b@y>` into its addresses (with display names).
pub fn split_addresses(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut angle = false;
    for c in v.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            '<' => {
                angle = true;
                cur.push(c);
            }
            '>' => {
                angle = false;
                cur.push(c);
            }
            ',' if !quoted && !angle => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Decode RFC 2047 encoded words (`=?UTF-8?B?...?=`, `=?...?Q?...?=`).
pub fn decode_header(v: &str) -> String {
    let mut out = String::new();
    let mut rest = v;
    while let Some(start) = rest.find("=?") {
        let Some(rel_end) = rest[start + 2..].find("?=") else { break };
        let word = &rest[start + 2..start + 2 + rel_end];
        let parts: Vec<&str> = word.splitn(3, '?').collect();
        if parts.len() != 3 {
            break;
        }
        let between = &rest[..start];
        if !(between.trim().is_empty() && !out.is_empty()) {
            out.push_str(between);
        }
        let bytes = match parts[1].to_ascii_uppercase().as_str() {
            "B" => base64::engine::general_purpose::STANDARD.decode(parts[2]).unwrap_or_default(),
            _ => decode_qp(&parts[2].replace('_', " ")),
        };
        out.push_str(&String::from_utf8_lossy(&bytes));
        rest = &rest[start + 2 + rel_end + 2..];
    }
    out.push_str(rest);
    out
}

fn decode_qp(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            if i + 2 < b.len() + 1 && b.get(i + 1) == Some(&b'\r') && b.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if b.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if let (Some(h), Some(l)) = (b.get(i + 1), b.get(i + 2)) {
                if let Ok(v) = u8::from_str_radix(&format!("{}{}", *h as char, *l as char), 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Split raw bytes into header block and body.
fn split_head(raw: &str) -> (&str, &str) {
    if let Some(i) = raw.find("\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = raw.find("\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, "")
    }
}

pub fn parse_headers(block: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in block.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    headers
}

fn param(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn decode_body(body: &str, encoding: Option<&str>) -> String {
    match encoding.map(|e| e.to_ascii_lowercase()) {
        Some(e) if e == "base64" => {
            let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(clean).unwrap_or_default())
                .into_owned()
        }
        Some(e) if e == "quoted-printable" => String::from_utf8_lossy(&decode_qp(body)).into_owned(),
        _ => body.to_string(),
    }
}

/// Parse a message far enough to know its headers and text/HTML bodies.
pub fn parse(raw: &[u8]) -> Parsed {
    let raw = String::from_utf8_lossy(raw);
    let (head, body) = split_head(&raw);
    let headers = parse_headers(head);
    let mut p = Parsed { headers, text: None, html: None };
    let ct = p.header("Content-Type").unwrap_or("text/plain").to_string();
    let enc = p.header("Content-Transfer-Encoding").map(str::to_string);
    walk(&ct, enc.as_deref(), body, &mut p, 0);
    p
}

fn walk(content_type: &str, encoding: Option<&str>, body: &str, p: &mut Parsed, depth: usize) {
    let lower = content_type.to_ascii_lowercase();
    if lower.starts_with("multipart/") && depth < 8 {
        let Some(b) = param(content_type, "boundary") else { return };
        let delim = format!("--{b}");
        for part in body.split(delim.as_str()).skip(1) {
            if part.starts_with("--") {
                break;
            }
            let part = part.trim_start_matches(['\r', '\n']);
            let (head, pbody) = split_head(part);
            let headers = parse_headers(head);
            let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
            let ct = get("Content-Type").unwrap_or_else(|| "text/plain".into());
            if get("Content-Disposition").is_some_and(|d| d.to_ascii_lowercase().starts_with("attachment")) {
                continue;
            }
            let enc = get("Content-Transfer-Encoding");
            walk(&ct, enc.as_deref(), pbody.trim_end_matches(['\r', '\n']), p, depth + 1);
        }
    } else if lower.starts_with("text/html") {
        if p.html.is_none() {
            p.html = Some(decode_body(body, encoding));
        }
    } else if lower.starts_with("text/") && p.text.is_none() {
        p.text = Some(decode_body(body, encoding));
    }
}

/// Insert headers at the top of a raw message.
pub fn prepend_headers(raw: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 128);
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}{CRLF}").as_bytes());
    }
    out.extend_from_slice(raw);
    out
}

/// Remove the `Bcc` header from a raw message, as SES does before sending.
pub fn strip_bcc(raw: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(raw);
    let (head, body) = split_head(&s);
    let sep = if s.contains("\r\n") { CRLF } else { "\n" };
    let mut lines = Vec::new();
    let mut skipping = false;
    for line in head.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            if !skipping {
                lines.push(line);
            }
            continue;
        }
        skipping = line.to_ascii_lowercase().starts_with("bcc:");
        if !skipping {
            lines.push(line);
        }
    }
    let mut out = lines.join(sep);
    out.push_str(sep);
    out.push_str(sep);
    out.push_str(body);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multipart_and_encoded_headers() {
        let raw = "From: =?UTF-8?B?w4FuYQ==?= <ana@example.com>\r\nTo: a@x.com, \"B, C\" <b@y.com>\r\nSubject: =?utf-8?Q?Ol=C3=A1?= there\r\nContent-Type: multipart/alternative; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XX\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+aGk8L2I+\r\n--XX--\r\n";
        let p = parse(raw.as_bytes());
        assert_eq!(p.addresses("To"), vec!["a@x.com", "\"B, C\" <b@y.com>"]);
        assert_eq!(p.subject(), "Olá there");
        assert_eq!(decode_header(p.header("From").unwrap()), "Ána <ana@example.com>");
        assert_eq!(p.text.as_deref(), Some("hello"));
        assert_eq!(p.html.as_deref(), Some("<b>hi</b>"));
        let stripped = strip_bcc(b"From: a@b.c\r\nBcc: x@y.z,\r\n  w@v.u\r\nTo: q@r.s\r\n\r\nbody");
        assert_eq!(String::from_utf8(stripped).unwrap(), "From: a@b.c\r\nTo: q@r.s\r\n\r\nbody");
    }
}
