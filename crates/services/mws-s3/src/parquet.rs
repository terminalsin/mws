//! S3 Inventory's Parquet schema, written with `mws-parquet`: `bucket` and
//! `key` are required UTF-8 strings, everything else optional, with
//! booleans, `int64` sizes and `TIMESTAMP_MILLIS` dates.

use mws_parquet::{Column, Kind, Value};

use crate::inventory::Cell;

/// The Parquet column for an inventory field.
fn column(field: &str) -> Column {
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
    Column::new(name, kind, matches!(field, "Bucket" | "Key"))
}

/// The schema as the manifest's `fileSchema` gives it.
pub(crate) fn schema_text(fields: &[&str]) -> String {
    let cols: Vec<Column> = fields.iter().map(|f| column(f)).collect();
    mws_parquet::schema_text("s3.inventory", &cols)
}

/// Write `rows` (columns in `fields` order) as a Parquet file.
pub(crate) fn write(fields: &[&str], rows: &[Vec<Cell>]) -> Vec<u8> {
    let cols: Vec<Column> = fields.iter().map(|f| column(f)).collect();
    let rows: Vec<Vec<Value>> = rows
        .iter()
        .map(|r| {
            r.iter()
                .map(|c| match c {
                    Cell::Str(s) => Value::Str(s.clone()),
                    Cell::Int(i) => Value::Int(*i),
                    Cell::Bool(b) => Value::Bool(*b),
                    Cell::Time(t) => Value::Time(*t),
                    Cell::Null => Value::Null,
                })
                .collect()
        })
        .collect();
    mws_parquet::write(&cols, &rows, "MWS S3 Inventory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(column("ETag").name, "e_tag");
        assert_eq!(column("LastModifiedDate").name, "last_modified_date");
        assert_eq!(column("IsDeleteMarker").name, "is_delete_marker");
    }

    #[test]
    fn framing() {
        let rows = vec![vec![Cell::Str("b".into()), Cell::Str("k".into()), Cell::Int(5), Cell::Null]];
        let f = write(&["Bucket", "Key", "Size", "ReplicationStatus"], &rows);
        assert!(f.starts_with(b"PAR1") && f.ends_with(b"PAR1"));
    }
}
