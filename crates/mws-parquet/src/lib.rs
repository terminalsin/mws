//! A small Apache Parquet writer: one row group, one uncompressed PLAIN
//! data page (v1) per column, metadata in Thrift's compact protocol.
//! Readers such as pyarrow, Spark and Athena read it.
//!
//! Spec: <https://parquet.apache.org/docs/file-format/>

use chrono::{DateTime, Utc};

/// Parquet physical types.
const BOOLEAN: i32 = 0;
const INT64: i32 = 2;
const DOUBLE: i32 = 5;
const BYTE_ARRAY: i32 = 6;
/// Converted types.
const UTF8: i32 = 0;
const TIMESTAMP_MILLIS: i32 = 9;

/// A column's logical type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// UTF-8 string (`binary (STRING)`).
    Str,
    Bool,
    /// 64-bit integer.
    Int,
    /// 64-bit float.
    Double,
    /// UTC timestamp in milliseconds.
    Time,
}

/// A column of the file's (flat) schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: Kind,
    /// Required columns have no nulls.
    pub required: bool,
}

impl Column {
    pub fn new(name: impl Into<String>, kind: Kind, required: bool) -> Self {
        Column { name: name.into(), kind, required }
    }

    fn physical(&self) -> i32 {
        match self.kind {
            Kind::Str => BYTE_ARRAY,
            Kind::Bool => BOOLEAN,
            Kind::Int | Kind::Time => INT64,
            Kind::Double => DOUBLE,
        }
    }
}

/// One cell.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Double(f64),
    Time(DateTime<Utc>),
    Null,
}

/// The schema in Parquet's message syntax, as some manifests give it.
pub fn schema_text(message: &str, columns: &[Column]) -> String {
    let cols: Vec<String> = columns
        .iter()
        .map(|c| {
            let rep = if c.required { "required" } else { "optional" };
            let name = &c.name;
            match c.kind {
                Kind::Str => format!("{rep} binary {name} (STRING)"),
                Kind::Bool => format!("{rep} boolean {name}"),
                Kind::Int => format!("{rep} int64 {name}"),
                Kind::Double => format!("{rep} double {name}"),
                Kind::Time => format!("{rep} int64 {name} (TIMESTAMP(MILLIS,true))"),
            }
        })
        .collect();
    format!("message {message} {{ {}; }}", cols.join("; "))
}

// ---- Thrift compact protocol ---------------------------------------------------

const T_I32: u8 = 5;
const T_I64: u8 = 6;
const T_BINARY: u8 = 8;
const T_LIST: u8 = 9;
const T_STRUCT: u8 = 12;

#[derive(Default)]
struct Thrift {
    out: Vec<u8>,
    last: Vec<i16>,
}

impl Thrift {
    fn varint(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.out.push(b);
                return;
            }
            self.out.push(b | 0x80);
        }
    }

    fn zigzag(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }

    fn field(&mut self, id: i16, ty: u8) {
        let last = self.last.last().copied().unwrap_or(0);
        let delta = id - last;
        if (1..=15).contains(&delta) {
            self.out.push(((delta as u8) << 4) | ty);
        } else {
            self.out.push(ty);
            self.zigzag(i64::from(id));
        }
        if let Some(l) = self.last.last_mut() {
            *l = id;
        }
    }

    fn begin(&mut self) {
        self.last.push(0);
    }

    fn end(&mut self) {
        self.out.push(0);
        self.last.pop();
    }

    fn i32(&mut self, id: i16, v: i32) {
        self.field(id, T_I32);
        self.zigzag(i64::from(v));
    }

    fn i64(&mut self, id: i16, v: i64) {
        self.field(id, T_I64);
        self.zigzag(v);
    }

    fn string(&mut self, id: i16, v: &str) {
        self.field(id, T_BINARY);
        self.varint(v.len() as u64);
        self.out.extend_from_slice(v.as_bytes());
    }

    fn list(&mut self, id: i16, elem: u8, len: usize) {
        self.field(id, T_LIST);
        if len < 15 {
            self.out.push(((len as u8) << 4) | elem);
        } else {
            self.out.push(0xf0 | elem);
            self.varint(len as u64);
        }
    }

    fn struct_field(&mut self, id: i16) {
        self.field(id, T_STRUCT);
        self.begin();
    }
}

// ---- encodings ------------------------------------------------------------------

/// Bits, least significant first, padded to whole bytes.
fn bit_pack(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Definition levels (bit width 1) as one bit-packed run of the
/// RLE/bit-packing hybrid, with the v1 page's length prefix.
fn definition_levels(defined: &[bool]) -> Vec<u8> {
    let mut run = Vec::new();
    let groups = defined.len().div_ceil(8);
    let mut t = Thrift::default();
    t.varint(((groups as u64) << 1) | 1);
    run.extend(t.out);
    run.extend(bit_pack(defined));
    let mut out = (run.len() as u32).to_le_bytes().to_vec();
    out.extend(run);
    out
}

fn plain(kind: Kind, cells: &[&Value]) -> Vec<u8> {
    let mut out = Vec::new();
    match kind {
        Kind::Bool => {
            let bits: Vec<bool> = cells.iter().map(|c| matches!(c, Value::Bool(true))).collect();
            out.extend(bit_pack(&bits));
        }
        Kind::Int | Kind::Time => {
            for c in cells {
                let v = match c {
                    Value::Int(i) => *i,
                    Value::Time(t) => t.timestamp_millis(),
                    Value::Double(d) => *d as i64,
                    Value::Bool(b) => i64::from(*b),
                    _ => 0,
                };
                out.extend(v.to_le_bytes());
            }
        }
        Kind::Double => {
            for c in cells {
                let v = match c {
                    Value::Double(d) => *d,
                    Value::Int(i) => *i as f64,
                    _ => 0.0,
                };
                out.extend(v.to_le_bytes());
            }
        }
        Kind::Str => {
            for c in cells {
                let s = match c {
                    Value::Str(s) => s.clone(),
                    Value::Int(i) => i.to_string(),
                    Value::Double(d) => d.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Time(t) => t.to_rfc3339(),
                    Value::Null => String::new(),
                };
                out.extend((s.len() as u32).to_le_bytes());
                out.extend(s.as_bytes());
            }
        }
    }
    out
}

struct Chunk {
    physical: i32,
    name: String,
    offset: usize,
    size: usize,
    values: usize,
}

/// Write `rows` (cells in `columns` order) as a Parquet file. `created_by`
/// names the writer in the footer.
pub fn write(columns: &[Column], rows: &[Vec<Value>], created_by: &str) -> Vec<u8> {
    let mut out = b"PAR1".to_vec();
    let mut chunks = Vec::new();
    if !rows.is_empty() {
        for (i, col) in columns.iter().enumerate() {
            let cells: Vec<&Value> = rows.iter().map(|r| r.get(i).unwrap_or(&Value::Null)).collect();
            let defined: Vec<bool> = cells.iter().map(|c| !matches!(c, Value::Null)).collect();
            let present: Vec<&Value> = cells.iter().copied().filter(|c| !matches!(c, Value::Null)).collect();
            let mut page = Vec::new();
            if !col.required {
                page.extend(definition_levels(&defined));
            }
            page.extend(plain(col.kind, &present));
            let mut h = Thrift::default();
            h.begin();
            h.i32(1, 0); // DATA_PAGE
            h.i32(2, page.len() as i32);
            h.i32(3, page.len() as i32);
            h.struct_field(5);
            h.i32(1, rows.len() as i32);
            h.i32(2, 0); // PLAIN
            h.i32(3, 3); // RLE
            h.i32(4, 3); // RLE
            h.end();
            h.end();
            let offset = out.len();
            out.extend(&h.out);
            out.extend(&page);
            chunks.push(Chunk {
                physical: col.physical(),
                name: col.name.clone(),
                offset,
                size: h.out.len() + page.len(),
                values: rows.len(),
            });
        }
    }
    let mut m = Thrift::default();
    m.begin();
    m.i32(1, 1);
    m.list(2, T_STRUCT, columns.len() + 1);
    m.begin();
    m.string(4, "schema");
    m.i32(5, columns.len() as i32);
    m.end();
    for col in columns {
        m.begin();
        m.i32(1, col.physical());
        m.i32(3, if col.required { 0 } else { 1 });
        m.string(4, &col.name);
        match col.kind {
            Kind::Str => m.i32(6, UTF8),
            Kind::Time => m.i32(6, TIMESTAMP_MILLIS),
            _ => {}
        }
        m.end();
    }
    m.i64(3, rows.len() as i64);
    if chunks.is_empty() {
        m.list(4, T_STRUCT, 0);
    } else {
        m.list(4, T_STRUCT, 1);
        m.begin();
        m.list(1, T_STRUCT, chunks.len());
        for c in &chunks {
            m.begin();
            m.i64(2, c.offset as i64);
            m.struct_field(3);
            m.i32(1, c.physical);
            m.list(2, T_I32, 2);
            m.zigzag(0); // PLAIN
            m.zigzag(3); // RLE
            m.list(3, T_BINARY, 1);
            m.varint(c.name.len() as u64);
            m.out.extend(c.name.as_bytes());
            m.i32(4, 0); // UNCOMPRESSED
            m.i64(5, c.values as i64);
            m.i64(6, c.size as i64);
            m.i64(7, c.size as i64);
            m.i64(9, c.offset as i64);
            m.end();
            m.end();
        }
        m.i64(2, chunks.iter().map(|c| c.size as i64).sum());
        m.i64(3, rows.len() as i64);
        m.end();
    }
    m.string(6, created_by);
    m.end();
    out.extend(&m.out);
    out.extend((m.out.len() as u32).to_le_bytes());
    out.extend(b"PAR1");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        let cols = vec![
            Column::new("bucket", Kind::Str, true),
            Column::new("size", Kind::Int, false),
            Column::new("ratio", Kind::Double, false),
        ];
        let rows = vec![vec![Value::Str("b".into()), Value::Int(5), Value::Null]];
        let f = write(&cols, &rows, "test");
        assert!(f.starts_with(b"PAR1") && f.ends_with(b"PAR1"));
        let len = u32::from_le_bytes(f[f.len() - 8..f.len() - 4].try_into().unwrap()) as usize;
        assert!(len < f.len());
    }
}
