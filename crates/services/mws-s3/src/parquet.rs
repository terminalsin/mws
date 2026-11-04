//! A small Apache Parquet writer for S3 Inventory reports: one row group,
//! one uncompressed PLAIN data page (v1) per column, metadata in Thrift's
//! compact protocol. Readers such as pyarrow, Spark and Athena read it.
//!
//! The schema is AWS's: `bucket` and `key` are required UTF-8 strings,
//! everything else optional, with booleans, `int64` sizes and
//! `TIMESTAMP_MILLIS` dates.
//!
//! Spec: <https://parquet.apache.org/docs/file-format/>

use crate::inventory::Cell;

/// Parquet physical types.
const BOOLEAN: i32 = 0;
const INT64: i32 = 2;
const BYTE_ARRAY: i32 = 6;
/// Converted types.
const UTF8: i32 = 0;
const TIMESTAMP_MILLIS: i32 = 9;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Str,
    Bool,
    Int,
    Time,
}

/// The Parquet column for an inventory field.
fn column(field: &str) -> (String, Kind) {
    let kind = match field {
        "IsLatest" | "IsDeleteMarker" | "IsMultipartUploaded" => Kind::Bool,
        "Size" => Kind::Int,
        "LastModifiedDate"
        | "ObjectLockRetainUntilDate"
        | "LifecycleExpirationDate"
        | "IntelligentTieringReferenceDate" => Kind::Time,
        _ => Kind::Str,
    };
    let name = match field {
        "ETag" => "e_tag".to_string(),
        f => {
            let mut s = String::new();
            for (i, c) in f.chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    s.push('_');
                }
                s.push(c.to_ascii_lowercase());
            }
            s
        }
    };
    (name, kind)
}

fn required(field: &str) -> bool {
    matches!(field, "Bucket" | "Key")
}

/// The schema as the manifest's `fileSchema` gives it.
pub(crate) fn schema_text(fields: &[&str]) -> String {
    let cols: Vec<String> = fields
        .iter()
        .map(|f| {
            let (name, kind) = column(f);
            let rep = if required(f) { "required" } else { "optional" };
            match kind {
                Kind::Str => format!("{rep} binary {name} (STRING)"),
                Kind::Bool => format!("{rep} boolean {name}"),
                Kind::Int => format!("{rep} int64 {name}"),
                Kind::Time => format!("{rep} int64 {name} (TIMESTAMP(MILLIS,true))"),
            }
        })
        .collect();
    format!("message s3.inventory {{ {}; }}", cols.join("; "))
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

fn plain(kind: Kind, cells: &[&Cell]) -> Vec<u8> {
    let mut out = Vec::new();
    match kind {
        Kind::Bool => {
            let bits: Vec<bool> = cells.iter().map(|c| matches!(c, Cell::Bool(true))).collect();
            out.extend(bit_pack(&bits));
        }
        Kind::Int | Kind::Time => {
            for c in cells {
                let v = match c {
                    Cell::Int(i) => *i,
                    Cell::Time(t) => t.timestamp_millis(),
                    _ => 0,
                };
                out.extend(v.to_le_bytes());
            }
        }
        Kind::Str => {
            for c in cells {
                let s = match c {
                    Cell::Str(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                out.extend((s.len() as u32).to_le_bytes());
                out.extend(s.as_bytes());
            }
        }
    }
    out
}

struct Chunk {
    kind: Kind,
    name: String,
    offset: usize,
    size: usize,
    values: usize,
}

/// Write `rows` (columns in `fields` order) as a Parquet file.
pub(crate) fn write(fields: &[&str], rows: &[Vec<Cell>]) -> Vec<u8> {
    let mut out = b"PAR1".to_vec();
    let mut chunks = Vec::new();
    if !rows.is_empty() {
        for (i, f) in fields.iter().enumerate() {
            let (name, kind) = column(f);
            let cells: Vec<&Cell> = rows.iter().map(|r| &r[i]).collect();
            let defined: Vec<bool> = cells.iter().map(|c| !matches!(c, Cell::Null)).collect();
            let present: Vec<&Cell> = cells.iter().copied().filter(|c| !matches!(c, Cell::Null)).collect();
            let mut page = Vec::new();
            if !required(f) {
                page.extend(definition_levels(&defined));
            }
            page.extend(plain(kind, &present));
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
            chunks.push(Chunk { kind, name, offset, size: h.out.len() + page.len(), values: rows.len() });
        }
    }
    let mut m = Thrift::default();
    m.begin();
    m.i32(1, 1);
    m.list(2, T_STRUCT, fields.len() + 1);
    m.begin();
    m.string(4, "schema");
    m.i32(5, fields.len() as i32);
    m.end();
    for f in fields {
        let (name, kind) = column(f);
        m.begin();
        m.i32(
            1,
            match kind {
                Kind::Str => BYTE_ARRAY,
                Kind::Bool => BOOLEAN,
                Kind::Int | Kind::Time => INT64,
            },
        );
        m.i32(3, if required(f) { 0 } else { 1 });
        m.string(4, &name);
        match kind {
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
            m.i32(
                1,
                match c.kind {
                    Kind::Str => BYTE_ARRAY,
                    Kind::Bool => BOOLEAN,
                    Kind::Int | Kind::Time => INT64,
                },
            );
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
    m.string(6, "MWS S3 Inventory");
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
    fn names() {
        assert_eq!(column("ETag").0, "e_tag");
        assert_eq!(column("LastModifiedDate").0, "last_modified_date");
        assert_eq!(column("IsDeleteMarker").0, "is_delete_marker");
    }

    #[test]
    fn framing() {
        let rows = vec![vec![Cell::Str("b".into()), Cell::Str("k".into()), Cell::Int(5), Cell::Null]];
        let f = write(&["Bucket", "Key", "Size", "ReplicationStatus"], &rows);
        assert!(f.starts_with(b"PAR1") && f.ends_with(b"PAR1"));
        let len = u32::from_le_bytes(f[f.len() - 8..f.len() - 4].try_into().unwrap()) as usize;
        assert!(len < f.len());
    }
}
