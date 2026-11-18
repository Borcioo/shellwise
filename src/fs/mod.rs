//! File-system access for the rules. Every call goes through `Fs` so tests can stub it and the
//! caller can bound it by the deadline.

use std::io;
use std::path::{Path, PathBuf};

/// What `lstat` reports about a path, without following a final link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

pub trait Fs: Send + Sync {
    fn lstat(&self, p: &Path) -> io::Result<Meta>;
    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>>;
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>>;
}

/// The real file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl Fs for RealFs {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        let m = std::fs::symlink_metadata(p)?;
        let t = m.file_type();
        Ok(Meta {
            is_dir: t.is_dir(),
            is_file: t.is_file(),
            is_symlink: t.is_symlink(),
        })
    }

    // Not implemented yet: an error makes the caller treat the target as unknown (fail closed).
    fn read_dir(&self, _p: &Path) -> io::Result<Vec<PathBuf>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn link_target(&self, _p: &Path) -> io::Result<Option<PathBuf>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
