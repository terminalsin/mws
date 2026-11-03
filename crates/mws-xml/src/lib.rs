//! XML helpers shared by the awsQuery and restXml runtimes: a small writer
//! and a re-export of the reader (`roxmltree`).

mod writer;

pub use roxmltree;
pub use writer::{format_timestamp, XmlWriter};

use mws_core::{ErrorValue, ServiceError};

/// Extra modeled error members, written inside `<Error>` as the SDKs expect.
pub fn write_error_fields(w: &mut XmlWriter, error: &ServiceError) {
    for f in &error.fields {
        match &f.value {
            ErrorValue::String(s) => w.leaf(&f.name, s),
            ErrorValue::List { item, values } => {
                w.open(&f.name);
                for v in values {
                    w.leaf(item, v);
                }
                w.close(&f.name);
            }
        }
    }
}
