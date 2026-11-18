//! File-system access for the rules. Every call goes through `Fs` so tests can stub it, and
//! through `bounded` so a call that never returns cannot hold the check past its deadline.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};

use crate::Deadline;

pub mod resolve;
pub mod walk;
#[cfg(windows)]
mod windows;

/// What `lstat` reports about a path, without following a final link.
///
/// `is_symlink` is true for every name-surrogate reparse point on Windows (symbolic link,
/// junction, volume mount point); such a path is neither `is_dir` nor `is_file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

pub trait Fs: Send + Sync {
    fn lstat(&self, p: &Path) -> io::Result<Meta>;
    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>>;
    /// The absolute target of a link; `None` when `p` is no link. A target the walk cannot
    /// place on a drive (`\\?\Volume{…}\`) is returned as read.
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>>;
    /// `p` with Windows 8.3 short names expanded; an error when it does not exist.
    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        Ok(p.to_path_buf())
    }
    /// What kind of link `p` is (called only on paths `lstat` reports as links).
    fn link_kind(&self, _p: &Path) -> io::Result<LinkKind> {
        Ok(LinkKind::Unknown)
    }
    /// The identity of the file `p` names after every link (volume serial and file ID on
    /// Windows, device and inode elsewhere); `None` when the file system cannot tell.
    fn file_id(&self, _p: &Path) -> io::Result<Option<FileId>> {
        Ok(None)
    }
}

/// One file's identity: two paths with equal ids name the same file or folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub volume: u64,
    pub index: u64,
}

/// The kind of a link: rules differ on which ones a delete follows (`git worktree remove`
/// empties junctions and mount points but unlinks a symbolic link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Junction,
    MountPoint,
    Symlink,
    /// A link whose kind could not be read.
    Unknown,
}

/// An `Fs` a worker thread can own.
pub type SharedFs = Arc<dyn Fs>;

/// The deadline passed (or the call panicked) before a bounded call returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOut;

/// Run `f` on a worker thread and wait for it only until the deadline. A worker that never
/// returns is left behind; the process exit ends it.
pub fn bounded<T: Send + 'static>(
    deadline: &Deadline,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TimedOut> {
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Err(TimedOut);
    }
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("shellwise-fs".to_string())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|_| TimedOut)?;
    rx.recv_timeout(remaining).map_err(|_| TimedOut)
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

    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
        std::fs::read_dir(p)?.map(|e| e.map(|e| e.path())).collect()
    }

    #[cfg(windows)]
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        windows::link_target(p)
    }

    #[cfg(not(windows))]
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        match std::fs::read_link(p) {
            Ok(t) => {
                let parent = p.parent().unwrap_or(Path::new("/"));
                let joined = parent.join(t);
                Ok(Some(PathBuf::from(resolve::canonical(
                    &joined.to_string_lossy(),
                    crate::Os::Posix,
                ))))
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(None),
            Err(e) => Err(e),
        }
    }

    #[cfg(windows)]
    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        windows::long_path(p)
    }

    #[cfg(windows)]
    fn link_kind(&self, p: &Path) -> io::Result<LinkKind> {
        windows::link_kind(p)
    }

    #[cfg(windows)]
    fn file_id(&self, p: &Path) -> io::Result<Option<FileId>> {
        windows::file_id(p).map(Some)
    }

    #[cfg(not(windows))]
    fn file_id(&self, p: &Path) -> io::Result<Option<FileId>> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p)?;
        Ok(Some(FileId {
            volume: m.dev(),
            index: m.ino(),
        }))
    }

    #[cfg(not(windows))]
    fn link_kind(&self, p: &Path) -> io::Result<LinkKind> {
        Ok(if self.lstat(p)?.is_symlink {
            LinkKind::Symlink
        } else {
            LinkKind::Unknown
        })
    }
}
