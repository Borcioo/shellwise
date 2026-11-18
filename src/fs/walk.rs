//! The folder walk behind a recursive delete: does the tree hold a link whose target lies
//! outside it, so the delete would empty that target?

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::resolve::path_key;
use super::{Fs, SharedFs, bounded};
use crate::{Deadline, Os};

/// At most this many outside links are reported.
const MAX_REPORTED: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkResult {
    /// No link leads out of the tree (or the tree does not exist).
    Clean,
    /// Links whose target is outside the tree, unreadable, or on a volume with no drive path;
    /// also the root itself or one of its ancestors when that is a link.
    Outside(Vec<PathBuf>),
    /// A folder or entry the walk could not read.
    Unreadable(PathBuf),
    /// The deadline passed first.
    Timeout,
}

/// Walk `root` breadth first without following any link, on a worker bounded by `deadline`.
pub fn outside_links(root: &Path, fs: &SharedFs, deadline: &Deadline) -> WalkResult {
    let root = root.to_path_buf();
    let fs = Arc::clone(fs);
    let d = *deadline;
    bounded(deadline, move || walk(&root, fs.as_ref(), &d)).unwrap_or(WalkResult::Timeout)
}

fn not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

fn walk(root: &Path, fs: &dyn Fs, deadline: &Deadline) -> WalkResult {
    let os = Os::host();
    let mut ancestors: Vec<&Path> = root.ancestors().skip(1).collect();
    ancestors.reverse();
    for a in ancestors {
        if deadline.expired() {
            return WalkResult::Timeout;
        }
        match fs.lstat(a) {
            Ok(m) if m.is_symlink => return WalkResult::Outside(vec![a.to_path_buf()]),
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
        return WalkResult::Outside(vec![root.to_path_buf()]);
    }
    if !meta.is_dir {
        return WalkResult::Clean;
    }
    let inside = path_key(&root.to_string_lossy(), os);
    let mut found = Vec::new();
    let done = |found: Vec<PathBuf>, otherwise: WalkResult| {
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
                    found.push(e);
                    if found.len() >= MAX_REPORTED {
                        return WalkResult::Outside(found);
                    }
                }
            } else if m.is_dir {
                todo.push_back(e);
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
