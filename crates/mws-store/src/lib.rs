//! On-disk persistence for MWS.
//!
//! A [`Store`] is one SQLite file. It holds an opaque JSON document per
//! service (whatever the service's `export_state` produced), named snapshots of
//! the whole emulator, and a few metadata values. It never looks inside the
//! documents, so it knows nothing about any service.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

/// Bumped when the table layout changes.
const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("state database uses schema version {found}, this build of MWS understands {SCHEMA_VERSION}")]
    Schema { found: i64 },
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A named snapshot's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A SQLite-backed store. Cheap operations; callers may share it behind an
/// `Arc`.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (or create) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Self::init(conn)
    }

    /// A private in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS service_state (
                 service TEXT PRIMARY KEY,
                 document TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS snapshot (
                 name TEXT PRIMARY KEY,
                 document TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );",
        )?;
        let store = Self { conn: Mutex::new(conn) };
        match store.meta("schema_version")? {
            None => store.set_meta("schema_version", &SCHEMA_VERSION.to_string())?,
            Some(v) => {
                let found = v.parse().unwrap_or(-1);
                if found != SCHEMA_VERSION {
                    return Err(StoreError::Schema { found });
                }
            }
        }
        Ok(store)
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the connection cannot leave SQLite in a
        // half-written state (statements are atomic), so ignore poisoning.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn().query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Every saved service document, by service name.
    pub fn service_states(&self) -> Result<BTreeMap<String, String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT service, document FROM service_state")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Write the given service documents and delete the `removed` ones, in
    /// one transaction.
    pub fn save_service_states(&self, changed: &[(&str, &str)], removed: &[&str]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        for (service, document) in changed {
            tx.execute(
                "INSERT INTO service_state (service, document, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(service) DO UPDATE SET document = excluded.document, updated_at = excluded.updated_at",
                params![service, document, now],
            )?;
        }
        for service in removed {
            tx.execute("DELETE FROM service_state WHERE service = ?1", [service])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Save (or replace) a named snapshot.
    pub fn put_snapshot(&self, name: &str, document: &str) -> Result<SnapshotInfo> {
        let created_at = Utc::now();
        self.conn().execute(
            "INSERT INTO snapshot (name, document, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET document = excluded.document, created_at = excluded.created_at",
            params![name, document, created_at.to_rfc3339()],
        )?;
        Ok(SnapshotInfo { name: name.to_string(), created_at })
    }

    pub fn snapshot(&self, name: &str) -> Result<Option<String>> {
        Ok(self.conn().query_row("SELECT document FROM snapshot WHERE name = ?1", [name], |r| r.get(0)).optional()?)
    }

    /// Snapshots in name order.
    pub fn snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT name, created_at FROM snapshot ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            let created: String = r.get(1)?;
            Ok(SnapshotInfo {
                name: r.get(0)?,
                created_at: DateTime::parse_from_rfc3339(&created).map(|t| t.with_timezone(&Utc)).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Delete a snapshot; `false` if there was none by that name.
    pub fn delete_snapshot(&self, name: &str) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM snapshot WHERE name = ?1", [name])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_states_round_trip() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.service_states().unwrap().is_empty());
        store.save_service_states(&[("a", "{\"x\":1}"), ("b", "{}")], &[]).unwrap();
        store.save_service_states(&[("a", "{\"x\":2}")], &["b"]).unwrap();
        let states = store.service_states().unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states["a"], "{\"x\":2}");
    }

    #[test]
    fn snapshots() {
        let store = Store::open_in_memory().unwrap();
        store.put_snapshot("two", "2").unwrap();
        store.put_snapshot("one", "1").unwrap();
        store.put_snapshot("one", "1b").unwrap();
        let names: Vec<_> = store.snapshots().unwrap().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["one", "two"]);
        assert_eq!(store.snapshot("one").unwrap().as_deref(), Some("1b"));
        assert!(store.delete_snapshot("one").unwrap());
        assert!(!store.delete_snapshot("one").unwrap());
        assert_eq!(store.snapshot("one").unwrap(), None);
    }

    #[test]
    fn reopens_file() {
        let dir = std::env::temp_dir().join(format!("mws-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        let _ = std::fs::remove_file(&path);
        {
            let store = Store::open(&path).unwrap();
            store.save_service_states(&[("svc", "{}")], &[]).unwrap();
            store.set_meta("k", "v").unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.service_states().unwrap()["svc"], "{}");
        assert_eq!(store.meta("k").unwrap().as_deref(), Some("v"));
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
