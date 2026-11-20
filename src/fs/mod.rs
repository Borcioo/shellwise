//! File-system access for the rules. Every call goes through `Fs` so tests can stub it, and
//! through `bounded` so a call that never returns cannot hold the check past its deadline.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};

use crate::Deadline;

pub mod assigned;
mod cmdlet_table;
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
    /// The device `p` itself is on (`st_dev`, not following a final link); `None` when the
    /// file system cannot tell. The walk counts a folder on another device than its root as a
    /// mount point (a Windows mount point is a link, `lstat` already reports it).
    fn device(&self, _p: &Path) -> io::Result<Option<u64>> {
        Ok(None)
    }
    /// Every mount point on this system (`/proc/self/mountinfo` on Linux), so the walk sees a
    /// bind mount that keeps the device; `None` where the system cannot list them.
    fn mount_points(&self) -> io::Result<Option<Vec<PathBuf>>> {
        Ok(None)
    }
    /// Whether a PowerShell wildcard without -Force skips `p`: on Windows its Hidden attribute,
    /// elsewhere a name that starts with a dot (the default, which the fakes keep).
    fn is_hidden(&self, p: &Path) -> io::Result<bool> {
        Ok(p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.')))
    }
    /// The Windows drive `letter` (`C`) exists now: its root can be read. A drive a command
    /// makes later does not.
    fn drive_exists(&self, letter: char) -> io::Result<bool> {
        match self.lstat(Path::new(&format!("{}:\\", letter.to_ascii_uppercase()))) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The mount points in the text of a `/proc/self/mountinfo` file (field 5, octal escapes such
/// as `\040` decoded).
pub fn parse_mountinfo(text: &str) -> Vec<PathBuf> {
    text.lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|field| PathBuf::from(unescape_mount(field)))
        .collect()
}

/// `\NNN` (three octal digits) as the byte it names: the kernel writes space, tab, newline and
/// backslash this way.
fn unescape_mount(field: &str) -> String {
    let b = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match (b[i], octal) {
            (b'\\', Some(d)) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    fn is_hidden(&self, p: &Path) -> io::Result<bool> {
        use std::os::windows::fs::MetadataExt;
        /// `FILE_ATTRIBUTE_HIDDEN`.
        const HIDDEN: u32 = 0x2;
        Ok(std::fs::symlink_metadata(p)?.file_attributes() & HIDDEN != 0)
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

    #[cfg(target_os = "linux")]
    fn mount_points(&self) -> io::Result<Option<Vec<PathBuf>>> {
        let text = std::fs::read_to_string("/proc/self/mountinfo")?;
        Ok(Some(parse_mountinfo(&text)))
    }

    #[cfg(not(windows))]
    fn device(&self, p: &Path) -> io::Result<Option<u64>> {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(std::fs::symlink_metadata(p)?.dev()))
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
