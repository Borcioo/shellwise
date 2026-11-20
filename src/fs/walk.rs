//! The folder walk behind a recursive delete: does the tree hold a link whose target lies
//! outside it, so the delete would empty that target?

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use super::LinkKind;
use super::resolve::path_key;
use super::{Fs, SharedFs, bounded};
use crate::{Deadline, Os};

/// A link the walk found, with its kind so each rule can decide which kinds it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub path: PathBuf,
    pub kind: LinkKind,
}

fn link(fs: &dyn Fs, p: &Path) -> Link {
    Link {
        path: p.to_path_buf(),
        kind: fs.link_kind(p).unwrap_or(LinkKind::Unknown),
    }
}

/// At most this many outside links are reported.
const MAX_REPORTED: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkResult {
    /// No link leads out of the tree (or the tree does not exist).
    Clean,
    /// Links whose target is outside the tree, unreadable, or on a volume with no drive path;
    /// also the root itself or one of its ancestors when that is a link.
    Outside(Vec<Link>),
    /// A folder or entry the walk could not read.
    Unreadable(PathBuf),
    /// The deadline passed first.
    Timeout,
}

/// Walk `root` breadth first without following any link, on a worker bounded by `deadline`.
pub fn outside_links(root: &Path, fs: &SharedFs, deadline: &Deadline, os: Os) -> WalkResult {
    let root = root.to_path_buf();
    let fs = Arc::clone(fs);
    let d = *deadline;
    bounded(deadline, move || walk(&root, fs.as_ref(), &d, os)).unwrap_or(WalkResult::Timeout)
}

fn not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

fn walk(root: &Path, fs: &dyn Fs, deadline: &Deadline, os: Os) -> WalkResult {
    let mut ancestors: Vec<&Path> = root.ancestors().skip(1).collect();
    ancestors.reverse();
    for a in ancestors {
        if deadline.expired() {
            return WalkResult::Timeout;
        }
        match fs.lstat(a) {
            Ok(m) if m.is_symlink => return WalkResult::Outside(vec![link(fs, a)]),
            Ok(_) => {}
            Err(e) if not_found(&e) => return WalkResult::Clean,
            Err(_) => return WalkResult::Unreadable(a.to_path_buf()),
        }
    }
    let meta = match fs.lstat(root) {
        Ok(m) => m,
        Err(e) if not_found(&e) => return WalkResult::Clean,
        Err(_) => return WalkResult::Unreadable(root.to_path_buf()),
    };
    if meta.is_symlink {
        return WalkResult::Outside(vec![link(fs, root)]);
    }
    if !meta.is_dir {
        return WalkResult::Clean;
    }
    // A folder on another device is a mount point: `rm -rf` crosses it.
    let root_dev = match fs.device(root) {
        Ok(d) => d,
        Err(e) if not_found(&e) => return WalkResult::Clean,
        Err(_) => return WalkResult::Unreadable(root.to_path_buf()),
    };
    let inside = path_key(&root.to_string_lossy(), os);
    // The mount table: a folder in the tree that is a mount point leads out of it even when a
    // bind mount keeps the device. Without a table the device check alone decides.
    let mounts: Vec<String> = match fs.mount_points() {
        Ok(Some(list)) => list
            .iter()
            .map(|m| path_key(&m.to_string_lossy(), os))
            .collect(),
        _ => Vec::new(),
    };
    let mut found = Vec::new();
    let done = |found: Vec<Link>, otherwise: WalkResult| {
        if found.is_empty() {
            otherwise
        } else {
            WalkResult::Outside(found)
        }
    };
    let mut todo = VecDeque::from([root.to_path_buf()]);
    while let Some(dir) = todo.pop_front() {
        if deadline.expired() {
            return done(found, WalkResult::Timeout);
        }
        let entries = match fs.read_dir(&dir) {
            Ok(v) => v,
            Err(e) if not_found(&e) => continue,
            Err(_) => return done(found, WalkResult::Unreadable(dir)),
        };
        for e in entries {
            let m = match fs.lstat(&e) {
                Ok(m) => m,
                Err(err) if not_found(&err) => continue,
                Err(_) => return done(found, WalkResult::Unreadable(e)),
            };
            if m.is_symlink {
                let within = match fs.link_target(&e) {
                    Ok(Some(t)) => is_within(&path_key(&t.to_string_lossy(), os), &inside, os),
                    _ => false,
                };
                if !within {
                    found.push(link(fs, &e));
                    if found.len() >= MAX_REPORTED {
                        return WalkResult::Outside(found);
                    }
                }
            } else if m.is_dir {
                let listed = mounts.contains(&path_key(&e.to_string_lossy(), os));
                let same_device = !listed
                    && match (root_dev, fs.device(&e)) {
                        (None, _) => true,
                        (Some(r), Ok(d)) => d == Some(r),
                        (Some(_), Err(err)) if not_found(&err) => continue,
                        (Some(_), Err(_)) => return done(found, WalkResult::Unreadable(e)),
                    };
                if same_device {
                    todo.push_back(e);
                } else {
                    // Another device, or one that cannot be read.
                    found.push(Link {
                        path: e,
                        kind: LinkKind::MountPoint,
                    });
                    if found.len() >= MAX_REPORTED {
                        return WalkResult::Outside(found);
                    }
                }
            }
        }
    }
    done(found, WalkResult::Clean)
}

/// `key` is `root` or lies under it (both keys from `path_key`).
pub(crate) fn is_within(key: &str, root: &str, os: Os) -> bool {
    let sep = if os == Os::Windows { '\\' } else { '/' };
    if key == root {
        return true;
    }
    let mut prefix = root.to_string();
    if !prefix.ends_with(sep) {
        prefix.push(sep);
    }
    key.starts_with(&prefix)
}
