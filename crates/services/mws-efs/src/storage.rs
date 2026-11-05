//! Where file system data lives: one real directory per file system under
//! a root directory on the host (`MWS_EFS_DIR`). Instances mount it, MWS
//! measures it for `SizeInBytes` and copies it for replication.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
}

impl Storage {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory holding `fs_id`'s data.
    pub fn dir(&self, fs_id: &str) -> PathBuf {
        self.root.join(fs_id)
    }

    pub fn create(&self, fs_id: &str) {
        let dir = self.dir(fs_id);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!("EFS: creating {}: {e}", dir.display());
            return;
        }
        // Instances write as any user; the root of a new EFS file system is
        // owned by root with mode 0755, which a container's root can work
        // with, and MWS (maybe not root) must still be able to read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777));
        }
    }

    /// Remove a deleted file system's data. Files instances wrote as root
    /// may not be removable by MWS; those are moved aside instead.
    pub fn delete(&self, fs_id: &str) {
        let dir = self.dir(fs_id);
        if !dir.exists() {
            return;
        }
        if std::fs::remove_dir_all(&dir).is_err() && dir.exists() {
            let trash = self.root.join(".deleted");
            let _ = std::fs::create_dir_all(&trash);
            let target = trash.join(format!("{fs_id}-{}", uuid::Uuid::new_v4()));
            if let Err(e) = std::fs::rename(&dir, &target) {
                tracing::warn!("EFS: removing {}: {e}", dir.display());
            }
        }
    }

    /// Bytes stored, as EFS meters them: file sizes rounded up to 4 KiB
    /// blocks, plus the 6 KiB an empty file system reports.
    pub fn size(&self, fs_id: &str) -> i64 {
        fn walk(dir: &Path, total: &mut i64, depth: usize) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for e in entries.flatten() {
                let Ok(meta) = e.metadata() else { continue };
                if meta.is_dir() {
                    *total += 4096;
                    if depth < 64 {
                        walk(&e.path(), total, depth + 1);
                    }
                } else {
                    *total += (meta.len() as i64 + 4095) / 4096 * 4096;
                }
            }
        }
        let mut total = 6144;
        walk(&self.dir(fs_id), &mut total, 0);
        total
    }

    /// Copy everything from `from` to `to` (replication), replacing what
    /// `to` held.
    pub fn replicate(&self, from: &str, to: &str) {
        fn copy(src: &Path, dst: &Path) -> std::io::Result<()> {
            std::fs::create_dir_all(dst)?;
            for e in std::fs::read_dir(src)? {
                let e = e?;
                let target = dst.join(e.file_name());
                let kind = e.file_type()?;
                if kind.is_dir() {
                    copy(&e.path(), &target)?;
                } else if kind.is_symlink() {
                    #[cfg(unix)]
                    {
                        let link = std::fs::read_link(e.path())?;
                        let _ = std::fs::remove_file(&target);
                        std::os::unix::fs::symlink(link, &target)?;
                    }
                } else {
                    std::fs::copy(e.path(), &target)?;
                }
            }
            Ok(())
        }
        let src = self.dir(from);
        let dst = self.dir(to);
        if let Ok(entries) = std::fs::read_dir(&dst) {
            for e in entries.flatten() {
                let p = e.path();
                let _ = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
            }
        }
        if let Err(e) = copy(&src, &dst) {
            tracing::warn!("EFS: replicating {from} to {to}: {e}");
        }
    }
}

/// `path` (absolute, as in an access point's root directory or a mount
/// source) as a relative path with no `..`, or `None` if it would escape.
pub fn relative(path: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in Path::new(path).components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(p) => out.push(p),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths() {
        assert_eq!(relative("/"), Some(PathBuf::new()));
        assert_eq!(relative("/a/b/"), Some(PathBuf::from("a/b")));
        assert_eq!(relative("/a/../b"), Some(PathBuf::from("b")));
        assert_eq!(relative("/../x"), None);
    }
}
