use std::fmt::Write;

/// A minimal streaming XML writer. Elements are written without
/// indentation, which every AWS SDK accepts.
#[derive(Debug, Default)]
pub struct XmlWriter {
    buf: String,
}

impl XmlWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self, name: &str) {
        let _ = write!(self.buf, "<{name}>");
    }

    pub fn open_with_ns(&mut self, name: &str, ns: &str) {
        let _ = write!(self.buf, "<{name} xmlns=\"{}\">", escape(ns));
    }

    /// `<name a="v" ...>`, with attribute values escaped.
    pub fn open_attrs(&mut self, name: &str, attrs: &[(&str, String)]) {
        let _ = write!(self.buf, "<{name}");
        for (k, v) in attrs {
            let _ = write!(self.buf, " {k}=\"{}\"", escape(v));
        }
        self.buf.push('>');
    }

    pub fn close(&mut self, name: &str) {
        let _ = write!(self.buf, "</{name}>");
    }

    /// `<name>text</name>`, with `text` escaped.
    pub fn leaf(&mut self, name: &str, text: &str) {
        let _ = write!(self.buf, "<{name}>{}</{name}>", escape(text));
    }

    /// Escaped character data inside the current element.
    pub fn text(&mut self, text: &str) {
        self.buf.push_str(&escape(text));
    }

    pub fn finish(self) -> String {
        self.buf
    }

    // ---- scalar formatting used by generated serializers --------------------

    pub fn leaf_bool(&mut self, name: &str, v: bool) {
        self.leaf(name, if v { "true" } else { "false" });
    }

    pub fn leaf_num(&mut self, name: &str, v: impl std::fmt::Display) {
        self.leaf(name, &v.to_string());
    }

    pub fn leaf_timestamp(&mut self, name: &str, v: &chrono::DateTime<chrono::Utc>) {
        self.leaf(name, &format_timestamp(v));
    }

    pub fn leaf_blob(&mut self, name: &str, v: &[u8]) {
        use base64::Engine;
        self.leaf(name, &base64::engine::general_purpose::STANDARD.encode(v));
    }
}

/// awsQuery timestamps are ISO 8601 in UTC. AWS omits fractional seconds when
/// they are zero.
pub fn format_timestamp(v: &chrono::DateTime<chrono::Utc>) -> String {
    if v.timestamp_subsec_millis() == 0 {
        v.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        v.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_text_and_attributes() {
        let mut w = XmlWriter::new();
        w.open_with_ns("R", "a\"b");
        w.leaf("Doc", "{\"a\":\"<b>&\"}");
        w.close("R");
        assert_eq!(w.finish(), "<R xmlns=\"a&quot;b\"><Doc>{&quot;a&quot;:&quot;&lt;b&gt;&amp;&quot;}</Doc></R>");
    }
}
