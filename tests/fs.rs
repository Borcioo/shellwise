//! Delete-target resolution, the folder walk and the bounded file-system calls.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use shellwise::fs::resolve::{
    DeleteBy, Location, ParamMatch, Target, UnknownKind, critical_by_identity, critical_reason,
    delete_by, env_view, mark_assigned, pwsh_param, repo_root, shipped_command, target,
};
use shellwise::fs::walk::{Link, LinkKind, WalkResult, outside_links};
use shellwise::fs::{FileId, Fs, Meta, RealFs, SharedFs};
use shellwise::ir::{
    ChainOp, Elem, EnvView, MethodCall, Pipeline, Quote, Script, SimpleCommand, Stmt, Word,
    WordPart,
};
use shellwise::level::Span;
use shellwise::{BashProfile, Deadline, Os, Shell};

// ---------------------------------------------------------------- IR builders

fn word_at(parts: Vec<WordPart>, start: usize) -> Word {
    Word {
        parts,
        span: Span {
            start,
            end: start + 1,
        },
        quote: Quote::None,
    }
}

fn lit(s: &str) -> Word {
    word_at(vec![WordPart::Literal(s.to_string())], 0)
}

fn var(name: &str) -> Word {
    word_at(vec![WordPart::Var(name.to_string())], 7)
}

fn cmd(name: &str, args: Vec<Word>) -> SimpleCommand {
    SimpleCommand {
        name: lit(name),
        typed: name.to_string(),
        canonical: Some(name.to_string()),
        args,
        redirects: Vec::new(),
        assigns: Vec::new(),
        span: Span::default(),
        in_loop: false,
        opaque: false,
    }
}

fn lits(name: &str, args: &[&str]) -> SimpleCommand {
    cmd(name, args.iter().map(|a| lit(a)).collect())
}

/// The command as text, for a failure message.
fn show(c: &SimpleCommand) -> String {
    let word = |w: &Word| -> String {
        w.parts
            .iter()
            .map(|p| match p {
                WordPart::Literal(s) => s.clone(),
                other => format!("{other:?}"),
            })
            .collect()
    };
    std::iter::once(c.typed.clone())
        .chain(c.args.iter().map(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn stmt(c: SimpleCommand, chain: Option<ChainOp>) -> Stmt {
    Stmt::Pipeline(Pipeline {
        elems: vec![Elem::Cmd(c)],
        chain,
    })
}

fn script(stmts: Vec<Stmt>) -> Script {
    Script {
        stmts,
        comments: Vec::new(),
    }
}

/// An assignment-only statement, `NAME=value` / `$NAME = value`.
fn assign(name: &str, value: &str) -> SimpleCommand {
    let mut c = cmd("", Vec::new());
    c.typed = String::new();
    c.canonical = None;
    c.assigns = vec![(name.to_string(), lit(value))];
    c
}

fn far() -> Deadline {
    Deadline::new(Instant::now(), 60_000)
}

/// The real file system, except that the drives that exist are declared (C:, D: and X:), so a
/// row reads the same on every machine and on the WSL leg, which has no letter drives.
fn real() -> SharedFs {
    Arc::new(Declared("CDX"))
}

/// `RealFs` with `drive_exists` answered from a declared set of letters.
struct Declared(&'static str);

impl Fs for Declared {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        RealFs.lstat(p)
    }
    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
        RealFs.read_dir(p)
    }
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        RealFs.link_target(p)
    }
    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        RealFs.long_path(p)
    }
    fn link_kind(&self, p: &Path) -> io::Result<LinkKind> {
        RealFs.link_kind(p)
    }
    fn file_id(&self, p: &Path) -> io::Result<Option<FileId>> {
        RealFs.file_id(p)
    }
    fn device(&self, p: &Path) -> io::Result<Option<u64>> {
        RealFs.device(p)
    }
    fn mount_points(&self) -> io::Result<Option<Vec<PathBuf>>> {
        RealFs.mount_points()
    }
    fn drive_exists(&self, letter: char) -> io::Result<bool> {
        Ok(self.0.contains(letter.to_ascii_uppercase()))
    }
}

/// A target the hook cannot place that may be a critical folder under another name.
const MAY_BE_CRITICAL: Target = Target::UnknownLocation(UnknownKind::MayBeCritical);
/// A relative target in a folder a variable or substitution chose.
const DYNAMIC_LOCATION: Target = Target::UnknownLocation(UnknownKind::Dynamic);

fn paths(v: &[&str]) -> Target {
    Target::Paths(v.iter().map(PathBuf::from).collect())
}

fn sorted(t: Target) -> Target {
    match t {
        Target::Paths(mut v) => {
            v.sort();
            Target::Paths(v)
        }
        other => other,
    }
}

// ---------------------------------------------------------------- fakes

#[derive(Debug, Clone)]
enum Node {
    Dir,
    File,
    Link(String, LinkKind),
    /// A link whose target cannot be read.
    BrokenLink,
    /// An entry `lstat` is refused on.
    Denied,
}

/// A device id `FakeFs::device` refuses to read.
const DEVICE_ERROR: u64 = u64::MAX;

/// An in-memory tree; every ancestor of an added node is a folder.
#[derive(Default)]
struct FakeFs {
    nodes: BTreeMap<PathBuf, Node>,
    long: BTreeMap<PathBuf, PathBuf>,
    ids: BTreeMap<PathBuf, u64>,
    /// Devices; when any is set, a node without one is on device 1, and `DEVICE_ERROR` cannot
    /// be read.
    devs: BTreeMap<PathBuf, Option<u64>>,
    /// What `mount_points` answers; `Err` when `None`.
    mounts: Option<Vec<PathBuf>>,
}

impl FakeFs {
    fn add(mut self, p: &str, node: Node) -> FakeFs {
        let p = PathBuf::from(p);
        for a in p.ancestors().skip(1) {
            self.nodes.entry(a.to_path_buf()).or_insert(Node::Dir);
        }
        self.nodes.insert(p, node);
        self
    }

    fn dir(self, p: &str) -> FakeFs {
        self.add(p, Node::Dir)
    }

    fn file(self, p: &str) -> FakeFs {
        self.add(p, Node::File)
    }

    fn link(self, p: &str, t: &str) -> FakeFs {
        self.add(p, Node::Link(t.to_string(), LinkKind::Junction))
    }

    fn shared(self) -> SharedFs {
        Arc::new(self)
    }
}

impl Fs for FakeFs {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        match self.nodes.get(p) {
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
            Some(Node::Denied) => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Some(n) => Ok(Meta {
                is_dir: matches!(n, Node::Dir),
                is_file: matches!(n, Node::File),
                is_symlink: matches!(n, Node::Link(..) | Node::BrokenLink),
            }),
        }
    }

    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
        match self.nodes.get(p) {
            Some(Node::Dir) => Ok(self
                .nodes
                .keys()
                .filter(|k| k.parent() == Some(p))
                .cloned()
                .collect()),
            Some(_) => Err(io::Error::other("not a folder")),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }

    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        match self.nodes.get(p) {
            Some(Node::Link(t, _)) => Ok(Some(PathBuf::from(t))),
            Some(Node::BrokenLink) => Err(io::Error::other("unreadable link kind")),
            Some(_) => Ok(None),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }

    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        Ok(self.long.get(p).cloned().unwrap_or_else(|| p.to_path_buf()))
    }

    fn file_id(&self, p: &Path) -> io::Result<Option<FileId>> {
        Ok(self.ids.get(p).map(|&index| FileId { volume: 1, index }))
    }

    fn link_kind(&self, p: &Path) -> io::Result<LinkKind> {
        match self.nodes.get(p) {
            Some(Node::Link(_, k)) => Ok(*k),
            _ => Err(io::Error::other("no readable link")),
        }
    }

    fn mount_points(&self) -> io::Result<Option<Vec<PathBuf>>> {
        match &self.mounts {
            Some(m) => Ok(Some(m.clone())),
            None => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        }
    }

    /// A drive exists when the tree holds a path on it.
    fn drive_exists(&self, letter: char) -> io::Result<bool> {
        let want = format!("{}:", letter.to_ascii_uppercase());
        Ok(self
            .nodes
            .keys()
            .any(|k| k.to_string_lossy().to_ascii_uppercase().starts_with(&want)))
    }

    fn device(&self, p: &Path) -> io::Result<Option<u64>> {
        match self.nodes.get(p) {
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
            Some(Node::Denied) => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Some(_) if self.devs.is_empty() => Ok(None),
            Some(_) => match self.devs.get(p).copied().unwrap_or(Some(1)) {
                Some(DEVICE_ERROR) => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                d => Ok(d),
            },
        }
    }
}

/// The kind a folder link made by `Tree::dir_link` has.
#[cfg(windows)]
const DIR_LINK: LinkKind = LinkKind::Junction;
#[cfg(not(windows))]
const DIR_LINK: LinkKind = LinkKind::Symlink;

fn lk(p: impl Into<PathBuf>, kind: LinkKind) -> Link {
    Link {
        path: p.into(),
        kind,
    }
}

/// Answers every folder as empty, except that the named call never returns.
struct Hang(&'static str);

impl Hang {
    fn block(&self, call: &str) {
        if self.0 == call {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }
}

impl Fs for Hang {
    fn lstat(&self, _p: &Path) -> io::Result<Meta> {
        self.block("lstat");
        Ok(Meta {
            is_dir: true,
            is_file: false,
            is_symlink: false,
        })
    }

    fn read_dir(&self, _p: &Path) -> io::Result<Vec<PathBuf>> {
        self.block("read_dir");
        Ok(Vec::new())
    }

    fn link_target(&self, _p: &Path) -> io::Result<Option<PathBuf>> {
        self.block("link_target");
        Ok(None)
    }

    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        self.block("long_path");
        Ok(p.to_path_buf())
    }

    fn file_id(&self, _p: &Path) -> io::Result<Option<FileId>> {
        self.block("file_id");
        Ok(None)
    }
}

#[cfg(windows)]
const BASE: &str = r"C:\w";
#[cfg(not(windows))]
const BASE: &str = "/w";

fn at(rel: &str) -> String {
    Path::new(BASE).join(rel).to_string_lossy().into_owned()
}

// ---------------------------------------------------------------- real trees

static TREE_ID: AtomicUsize = AtomicUsize::new(0);

/// A fresh folder under the system temp dir. Drop unlinks every link it made before removing
/// the folder, so a cleanup never deletes through a junction.
struct Tree {
    root: PathBuf,
    links: Vec<PathBuf>,
    denied: Vec<PathBuf>,
}

impl Tree {
    fn new() -> Tree {
        let n = TREE_ID.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("shellwise-fs-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Tree {
            root,
            links: Vec::new(),
            denied: Vec::new(),
        }
    }

    fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self
            .root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A folder link: a junction on Windows, a symlink elsewhere.
    fn dir_link(&mut self, rel: &str, target: &Path) -> Link {
        let p = self
            .root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        #[cfg(windows)]
        {
            let out = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&p)
                .arg(target.to_string_lossy().replace('/', "\\"))
                .output()
                .unwrap();
            assert!(out.status.success(), "mklink /J: {out:?}");
        }
        #[cfg(not(windows))]
        std::os::unix::fs::symlink(target, &p).unwrap();
        self.links.push(p.clone());
        lk(p, DIR_LINK)
    }

    /// A symbolic link to a folder.
    fn sym_link(&mut self, rel: &str, target: &Path) -> Link {
        let p = self
            .root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, &p).unwrap();
        #[cfg(not(windows))]
        std::os::unix::fs::symlink(target, &p).unwrap();
        self.links.push(p.clone());
        lk(p, LinkKind::Symlink)
    }

    /// A folder nobody may list.
    fn deny_list(&mut self, rel: &str) -> PathBuf {
        let p = self.mkdir(rel);
        #[cfg(windows)]
        {
            let out = std::process::Command::new("icacls")
                .arg(&p)
                .args(["/deny", "*S-1-1-0:(RD)"])
                .output()
                .unwrap();
            assert!(out.status.success(), "icacls: {out:?}");
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        self.denied.push(p.clone());
        p
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        for p in &self.denied {
            #[cfg(windows)]
            let _ = std::process::Command::new("icacls")
                .arg(p)
                .args(["/remove:d", "*S-1-1-0"])
                .output();
            #[cfg(not(windows))]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
            }
        }
        for l in &self.links {
            #[cfg(windows)]
            let _ = std::fs::remove_dir(l);
            #[cfg(not(windows))]
            let _ = std::fs::remove_file(l);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------- walk

#[test]
fn walk_finds_a_folder_link_whose_target_is_outside_the_tree() {
    let mut t = Tree::new();
    let outside = t.mkdir("outside");
    std::fs::write(outside.join("keep.txt"), "x").unwrap();
    let root = t.mkdir("root/a");
    let root = root.parent().unwrap().to_path_buf();
    let link = t.dir_link("root/a/j", &outside);
    assert_eq!(
        outside_links(&root, &real(), &far()),
        WalkResult::Outside(vec![link])
    );
}

#[test]
fn walk_is_clean_when_every_link_points_inside_the_tree() {
    let mut t = Tree::new();
    let inner = t.mkdir("root/data/deep");
    std::fs::write(inner.join("f.txt"), "x").unwrap();
    t.dir_link("root/j", &t.root.join("root/data"));
    t.dir_link("root/data/k", &inner);
    assert_eq!(
        outside_links(&t.root.join("root"), &real(), &far()),
        WalkResult::Clean
    );
}

#[test]
fn walk_counts_a_link_into_a_sibling_with_a_longer_name_as_outside() {
    let mut t = Tree::new();
    t.mkdir("root");
    let data = t.mkdir("root2/data");
    let link = t.dir_link("root/j", &data);
    assert_eq!(
        outside_links(&t.root.join("root"), &real(), &far()),
        WalkResult::Outside(vec![link])
    );
}

#[test]
fn walk_finds_a_symlink_whose_target_is_outside_the_tree() {
    let mut t = Tree::new();
    let outside = t.mkdir("outside");
    t.mkdir("root");
    let link = t.sym_link("root/s", &outside);
    assert_eq!(
        outside_links(&t.root.join("root"), &real(), &far()),
        WalkResult::Outside(vec![link])
    );
}

#[test]
fn walk_counts_a_volume_target_and_an_unreadable_target_as_outside() {
    let fs = FakeFs::default()
        .dir(&at("root/a"))
        .add(
            &at("root/a/m"),
            Node::Link(
                r"\\?\Volume{0b1c2d3e-0000-4000-8000-000000000001}\".to_string(),
                LinkKind::MountPoint,
            ),
        )
        .file(&at("root/f"))
        .add(&at("root/b/broken"), Node::BrokenLink)
        .shared();
    assert_eq!(
        outside_links(Path::new(&at("root")), &fs, &far()),
        WalkResult::Outside(vec![
            lk(at("root/a/m"), LinkKind::MountPoint),
            lk(at("root/b/broken"), LinkKind::Unknown)
        ])
    );
}

#[test]
fn walk_reports_an_entry_it_cannot_stat() {
    let fs = FakeFs::default()
        .dir(&at("root/a"))
        .add(&at("root/a/x"), Node::Denied)
        .shared();
    assert_eq!(
        outside_links(Path::new(&at("root")), &fs, &far()),
        WalkResult::Unreadable(PathBuf::from(at("root/a/x")))
    );
}

#[test]
fn walk_reports_a_folder_it_cannot_list() {
    let mut t = Tree::new();
    t.mkdir("root/ok");
    let denied = t.deny_list("root/ok/locked");
    assert_eq!(
        outside_links(&t.root.join("root"), &real(), &far()),
        WalkResult::Unreadable(denied)
    );
}

#[test]
fn walk_checks_the_root_and_its_ancestors_for_a_link() {
    let fs = FakeFs::default()
        .dir(&at("real/sub/x"))
        .link(&at("wt/j"), &at("real"))
        .link(&at("wt/k"), &at("real/sub"))
        .shared();
    // An ancestor of the root is a link: the tree lives elsewhere.
    let deep = Path::new(&at("wt/j")).join("sub");
    assert_eq!(
        outside_links(&deep, &fs, &far()),
        WalkResult::Outside(vec![lk(at("wt/j"), LinkKind::Junction)])
    );
    // The root itself is a link.
    assert_eq!(
        outside_links(Path::new(&at("wt/k")), &fs, &far()),
        WalkResult::Outside(vec![lk(at("wt/k"), LinkKind::Junction)])
    );
    // A missing root has nothing to delete.
    assert_eq!(
        outside_links(Path::new(&at("real/nope")), &fs, &far()),
        WalkResult::Clean
    );
}

#[test]
fn walk_breadth_first_reports_the_link_nearest_the_root_first() {
    // Depth first from the last folder would reach `deep` first.
    let fs = FakeFs::default()
        .link(&at("root/a/near"), &at("elsewhere"))
        .link(&at("root/z/b/c/deep"), &at("elsewhere"))
        .dir(&at("elsewhere"))
        .shared();
    assert_eq!(
        outside_links(Path::new(&at("root")), &fs, &far()),
        WalkResult::Outside(vec![
            lk(at("root/a/near"), LinkKind::Junction),
            lk(at("root/z/b/c/deep"), LinkKind::Junction)
        ])
    );
}

#[test]
fn walk_times_out_within_the_remaining_time_when_a_call_never_returns() {
    for call in ["lstat", "read_dir"] {
        let fs: SharedFs = Arc::new(Hang(call));
        let start = Instant::now();
        let deadline = Deadline::new(start, 200);
        let r = outside_links(Path::new(&at("root")), &fs, &deadline);
        let took = start.elapsed();
        assert_eq!(r, WalkResult::Timeout, "{call}");
        assert!(took < Duration::from_millis(250), "{call}: {took:?}");
    }
}

/// `rm -rf ./data` where `data/vol` is a bind mount: GNU rm crosses mount points.
#[cfg(unix)]
#[test]
fn walk_counts_a_folder_on_another_device_as_a_mount_point() {
    let mut fake = FakeFs::default()
        .dir(&at("data/sub/deep"))
        .dir(&at("data/vol/x"))
        .dir(&at("data/unread"));
    fake.devs.insert(PathBuf::from(at("data/vol")), Some(2));
    fake.devs.insert(PathBuf::from(at("data/vol/x")), Some(2));
    // A folder whose device cannot be read counts too.
    fake.devs.insert(PathBuf::from(at("data/unread")), None);
    let fs = fake.shared();
    assert_eq!(
        outside_links(Path::new(&at("data")), &fs, &far()),
        WalkResult::Outside(vec![
            lk(at("data/unread"), LinkKind::MountPoint),
            lk(at("data/vol"), LinkKind::MountPoint),
        ])
    );
    // The same tree on one device is clean.
    let one = FakeFs::default()
        .dir(&at("data/sub/deep"))
        .dir(&at("data/vol/x"))
        .shared();
    assert_eq!(
        outside_links(Path::new(&at("data")), &one, &far()),
        WalkResult::Clean
    );
    // A device the walk cannot read, on the root or a folder in it.
    for (refused, want) in [
        ("data", WalkResult::Unreadable(PathBuf::from(at("data")))),
        (
            "data/sub",
            WalkResult::Unreadable(PathBuf::from(at("data/sub"))),
        ),
    ] {
        let mut fake = FakeFs::default().dir(&at("data/sub/deep"));
        fake.devs
            .insert(PathBuf::from(at(refused)), Some(DEVICE_ERROR));
        let fs = fake.shared();
        assert_eq!(
            outside_links(Path::new(&at("data")), &fs, &far()),
            want,
            "{refused}"
        );
    }
}

/// `mount --bind` on the same file system keeps the device: the mount table names it.
#[cfg(unix)]
#[test]
fn walk_counts_a_listed_mount_point_inside_the_tree_on_the_same_device() {
    let tree = || {
        FakeFs::default()
            .dir(&at("data/sub/deep"))
            .dir(&at("data/bind/x"))
    };
    let mut fake = tree();
    fake.mounts = Some(vec![
        PathBuf::from("/"),
        // The root itself, and a mount outside it, are not links out of the tree.
        PathBuf::from(at("data")),
        PathBuf::from(at("elsewhere")),
        PathBuf::from(at("data/bind")),
    ]);
    let fs = fake.shared();
    assert_eq!(
        outside_links(Path::new(&at("data")), &fs, &far()),
        WalkResult::Outside(vec![lk(at("data/bind"), LinkKind::MountPoint)])
    );
    // A mount table that cannot be read leaves the device check.
    let unread = tree().shared();
    assert_eq!(
        outside_links(Path::new(&at("data")), &unread, &far()),
        WalkResult::Clean
    );
}

#[test]
fn mountinfo_lists_every_mount_point_with_its_escapes_decoded() {
    let text = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                61 22 0:5 / /dev rw,nosuid - devtmpfs udev rw\n\
                90 22 8:1 /srv/src /w/my\\040data/bind rw - ext4 /dev/sda1 rw\n\
                91 22 0:44 / /w/tab\\011and\\134back rw - tmpfs none rw\n";
    assert_eq!(
        shellwise::fs::parse_mountinfo(text),
        vec![
            PathBuf::from("/"),
            PathBuf::from("/dev"),
            PathBuf::from("/w/my data/bind"),
            PathBuf::from("/w/tab\tand\\back"),
        ]
    );
}

/// The real mount table is read.
#[cfg(target_os = "linux")]
#[test]
fn real_fs_reads_the_mount_table() {
    let mounts = real().mount_points().unwrap().unwrap();
    assert!(mounts.iter().any(|m| m == Path::new("/proc")), "{mounts:?}");
}

/// The real file system reports the device: `/dev/shm` and `/dev/pts` are mounts under `/dev`.
#[cfg(target_os = "linux")]
#[test]
fn real_fs_walk_reports_a_mount_inside_the_tree() {
    let fs = real();
    let dev = fs.device(Path::new("/dev")).unwrap();
    let shm = fs.device(Path::new("/dev/shm")).unwrap();
    assert!(
        dev.is_some() && shm.is_some() && dev != shm,
        "{dev:?} {shm:?}"
    );
    match outside_links(Path::new("/dev"), &fs, &far()) {
        WalkResult::Outside(links) => assert!(
            links.iter().any(|l| l.kind == LinkKind::MountPoint
                && [Path::new("/dev/shm"), Path::new("/dev/pts")].contains(&l.path.as_path())),
            "{links:?}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn walk_on_an_expired_deadline_is_a_timeout() {
    let fs = FakeFs::default().dir(&at("root")).shared();
    let deadline = Deadline::new(Instant::now() - Duration::from_millis(5), 1);
    assert_eq!(
        outside_links(Path::new(&at("root")), &fs, &deadline),
        WalkResult::Timeout
    );
}

// ---------------------------------------------------------------- path forms

fn win(shell: Shell) -> (Location, EnvView) {
    let loc = Location::new(shell, Os::Windows, Some(Path::new(r"C:\w\repo")));
    let env = env_view(
        shell,
        Os::Windows,
        [
            ("USERPROFILE".to_string(), r"C:\Profiles\u".to_string()),
            (
                "TEMP".to_string(),
                r"C:\Profiles\u\AppData\Local\Temp".to_string(),
            ),
        ],
    );
    (loc, env)
}

/// A delete that reads its path as a file-system path (a native program, a .NET call).
const NATIVE: DeleteBy = DeleteBy::Native;

fn resolve(w: &Word, loc: &Location, env: &EnvView) -> Target {
    sorted(target(w, loc, env, NATIVE, &real(), &far()))
}

#[test]
fn windows_path_forms_resolve_as_the_shell_would() {
    let (loc, env) = win(Shell::Pwsh);
    let cases: &[(&str, Target)] = &[
        (r"C:\x", paths(&[r"C:\x"])),
        ("C:/x/", paths(&[r"C:\x"])),
        (r"c:\x\.\y\..\z", paths(&[r"c:\x\z"])),
        ("C:x", MAY_BE_CRITICAL),
        ("C:", MAY_BE_CRITICAL),
        (r"\\?\C:\x", paths(&[r"C:\x"])),
        (r"\\.\C:\x", paths(&[r"C:\x"])),
        (r"\\?\UNC\srv\share\x", MAY_BE_CRITICAL),
        (r"\\srv\share\x", MAY_BE_CRITICAL),
        ("//srv/share/x", MAY_BE_CRITICAL),
        (r"sub\x", paths(&[r"C:\w\repo\sub\x"])),
        (r"..\..\..\..", paths(&[r"C:\"])),
        (r"\x", paths(&[r"C:\x"])),
        ("/x", paths(&[r"C:\x"])),
        (r"C:\Profiles\u.\ ", paths(&[r"C:\Profiles\u"])),
        ("~", paths(&[r"C:\Profiles\u"])),
        (r"~\x", paths(&[r"C:\Profiles\u\x"])),
        (r"FileSystem::C:\x", paths(&[r"C:\x"])),
        (
            r"Microsoft.PowerShell.Core\FileSystem::C:\x",
            paths(&[r"C:\x"]),
        ),
        (r"Temp:\x", paths(&[r"C:\Profiles\u\AppData\Local\Temp\x"])),
        (r"HKCU:\Software\x", MAY_BE_CRITICAL),
        // NTFS stream forms name the folder itself (`rd /s` deletes it).
        (r"C:\w\repo::$INDEX_ALLOCATION", MAY_BE_CRITICAL),
        (r"C:\w\repo:$I30:$INDEX_ALLOCATION", MAY_BE_CRITICAL),
        (r"~::$INDEX_ALLOCATION", MAY_BE_CRITICAL),
        (r"sub\f:stream", MAY_BE_CRITICAL),
        (r"f::$DATA", MAY_BE_CRITICAL),
        (r"C:\w\*::$INDEX_ALLOCATION", MAY_BE_CRITICAL),
        // Aliases of local folders the critical check could not recognise.
        (r"\\localhost\share\x", MAY_BE_CRITICAL),
        (r"\\127.0.0.1\share\x", MAY_BE_CRITICAL),
        (r"\\srv\C$\x", MAY_BE_CRITICAL),
        (r"\\srv", MAY_BE_CRITICAL),
        (
            r"\\?\Volume{0b1c2d3e-0000-4000-8000-000000000001}\x",
            MAY_BE_CRITICAL,
        ),
        (r"\\?\GLOBALROOT\Device\HarddiskVolume1\x", MAY_BE_CRITICAL),
        ("", paths(&[])),
    ];
    for (text, want) in cases {
        assert_eq!(&resolve(&lit(text), &loc, &env), want, "{text:?}");
    }
}

#[test]
fn git_bash_path_forms_map_msys_paths_to_windows_ones() {
    let shell = Shell::Bash(BashProfile::GitBash);
    let (loc, env) = win(shell);
    let cases: &[(&str, Target)] = &[
        ("/c/x", paths(&[r"C:\x"])),
        ("/C/x/../y", paths(&[r"C:\y"])),
        ("/c", paths(&[r"C:\"])),
        ("/c/", paths(&[r"C:\"])),
        ("/", paths(&["/"])),
        ("/tmp/x", paths(&[r"C:\Profiles\u\AppData\Local\Temp\x"])),
        ("/usr/bin", MAY_BE_CRITICAL),
        ("C:/x", paths(&[r"C:\x"])),
        ("//srv/share/x", MAY_BE_CRITICAL),
        ("sub/x", paths(&[r"C:\w\repo\sub\x"])),
    ];
    for (text, want) in cases {
        assert_eq!(&resolve(&lit(text), &loc, &env), want, "{text:?}");
    }
    let tilde = word_at(
        vec![WordPart::Tilde, WordPart::Literal("/x".to_string())],
        0,
    );
    assert_eq!(resolve(&tilde, &loc, &env), paths(&[r"C:\Profiles\u\x"]));
    // In bash a literal `~` (quoted) is a folder of that name.
    assert_eq!(resolve(&lit("~"), &loc, &env), paths(&[r"C:\w\repo\~"]));
}

#[test]
fn posix_path_forms_resolve_lexically() {
    let shell = Shell::Bash(BashProfile::Posix);
    let loc = Location::new(shell, Os::Posix, Some(Path::new("/w/repo")));
    let env = env_view(shell, Os::Posix, [("HOME".to_string(), "/h".to_string())]);
    let cases: &[(&str, Target)] = &[
        ("/x/../y", paths(&["/y"])),
        ("//x///y/", paths(&["/x/y"])),
        ("rel", paths(&["/w/repo/rel"])),
        ("../../..", paths(&["/"])),
        (r"a\b", paths(&[r"/w/repo/a\b"])),
    ];
    for (text, want) in cases {
        assert_eq!(&resolve(&lit(text), &loc, &env), want, "{text:?}");
    }
    let tilde = word_at(vec![WordPart::Tilde], 0);
    assert_eq!(resolve(&tilde, &loc, &env), paths(&["/h"]));
}

#[test]
fn a_relative_path_without_a_location_is_unknown() {
    let shell = Shell::Pwsh;
    let loc = Location::new(shell, Os::Windows, None);
    let env = EnvView::new();
    assert_eq!(resolve(&lit("x"), &loc, &env), MAY_BE_CRITICAL);
    assert_eq!(resolve(&lit(r"\x"), &loc, &env), MAY_BE_CRITICAL);
    assert_eq!(resolve(&lit(r"C:\x"), &loc, &env), paths(&[r"C:\x"]));
}

#[test]
fn dynamic_words_resolve_only_from_the_env_view() {
    let (loc, env) = win(Shell::Pwsh);
    let unknown = var("x");
    assert_eq!(resolve(&unknown, &loc, &env), Target::Dynamic(unknown.span));
    let subst = word_at(vec![WordPart::Subst(Box::default())], 3);
    assert_eq!(resolve(&subst, &loc, &env), Target::Dynamic(subst.span));
    let block = word_at(vec![WordPart::Block(Box::default())], 4);
    assert_eq!(resolve(&block, &loc, &env), Target::Dynamic(block.span));
    let temp = word_at(
        vec![
            WordPart::Var("env:TEMP".to_string()),
            WordPart::Literal(r"\x".to_string()),
        ],
        0,
    );
    assert_eq!(
        resolve(&temp, &loc, &env),
        paths(&[r"C:\Profiles\u\AppData\Local\Temp\x"])
    );
    let home = word_at(vec![WordPart::Var("HOME".to_string())], 0);
    assert_eq!(resolve(&home, &loc, &env), paths(&[r"C:\Profiles\u"]));
    let pwd = word_at(
        vec![
            WordPart::Var("PWD".to_string()),
            WordPart::Literal(r"\x".to_string()),
        ],
        0,
    );
    assert_eq!(resolve(&pwd, &loc, &env), paths(&[r"C:\w\repo\x"]));
    // `$PWD` where the location is unknown.
    let nowhere = Location::new(Shell::Pwsh, Os::Windows, None);
    assert_eq!(resolve(&pwd, &nowhere, &env), MAY_BE_CRITICAL);
    // PowerShell's `~` without a known profile.
    assert_eq!(
        resolve(&lit(r"~\x"), &loc, &EnvView::new()),
        Target::Dynamic(lit("").span)
    );
}

#[test]
fn short_names_are_expanded_before_comparison() {
    let shell = Shell::Pwsh;
    let loc = Location::new(shell, Os::Windows, Some(Path::new(r"C:\w")));
    let mut fake = FakeFs::default().dir(r"C:\w");
    fake.long.insert(
        PathBuf::from(r"C:\PROFILES\U~1"),
        PathBuf::from(r"C:\Profiles\u.name"),
    );
    let fs = fake.shared();
    let t = target(
        &lit(r"C:\PROFILES\U~1"),
        &loc,
        &EnvView::new(),
        NATIVE,
        &fs,
        &far(),
    );
    assert_eq!(t, paths(&[r"C:\Profiles\u.name"]));
    let hang: SharedFs = Arc::new(Hang("long_path"));
    let start = Instant::now();
    let t = target(
        &lit(r"C:\PROFILES\U~1"),
        &loc,
        &EnvView::new(),
        NATIVE,
        &hang,
        &Deadline::new(start, 100),
    );
    assert_eq!(t, Target::Timeout);
    assert!(start.elapsed() < Duration::from_millis(150));
}

#[cfg(windows)]
#[test]
fn real_fs_expands_a_short_name() {
    let long = real().long_path(Path::new(r"C:\PROGRA~1")).unwrap();
    assert_eq!(long, PathBuf::from(r"C:\Program Files"));
}

#[test]
fn globs_expand_against_the_folder_and_time_out_with_it() {
    let t = Tree::new();
    for f in ["a1", "a2", "b1"] {
        std::fs::write(t.root.join(f), "x").unwrap();
    }
    let shell = if cfg!(windows) {
        Shell::Pwsh
    } else {
        Shell::Bash(BashProfile::Posix)
    };
    let loc = Location::new(shell, Os::host(), Some(&t.root));
    let env = EnvView::new();
    let glob = |pat: &str| word_at(vec![WordPart::Glob(pat.to_string())], 0);
    let s = |names: &[&str]| Target::Paths(names.iter().map(|n| t.root.join(n)).collect());
    assert_eq!(resolve(&glob("*"), &loc, &env), s(&["a1", "a2", "b1"]));
    assert_eq!(resolve(&glob("a*"), &loc, &env), s(&["a1", "a2"]));
    assert_eq!(resolve(&glob("nope*"), &loc, &env), s(&[]));
    if cfg!(windows) {
        assert_eq!(resolve(&glob("A?"), &loc, &env), s(&["a1", "a2"]));
        // PowerShell's -Path reads a quoted `*` as a wildcard too.
        let quoted = lit(&format!(r"{}\a*", t.root.display()));
        let elsewhere = Location::new(shell, Os::Windows, Some(Path::new(r"C:\w")));
        assert_eq!(resolve(&quoted, &elsewhere, &env), s(&["a1", "a2"]));
        // A bracket expression is a wildcard too; an unclosed one cannot be read.
        let bracket = lit(&format!(r"{}\[a]1", t.root.display()));
        assert_eq!(resolve(&bracket, &elsewhere, &env), s(&["a1"]));
        let open = lit(&format!(r"{}\[a1", t.root.display()));
        assert_eq!(resolve(&open, &elsewhere, &env), MAY_BE_CRITICAL);
    }
    // A glob in the middle of the path, the literal part around it kept as written.
    std::fs::create_dir(t.root.join("d1")).unwrap();
    let mid = word_at(
        vec![
            WordPart::Glob("d?".to_string()),
            WordPart::Literal(format!("{}f", std::path::MAIN_SEPARATOR)),
        ],
        0,
    );
    assert_eq!(
        resolve(&mid, &loc, &env),
        Target::Paths(vec![t.root.join("d1").join("f")])
    );
    let hang: SharedFs = Arc::new(Hang("read_dir"));
    let start = Instant::now();
    let r = target(
        &glob("*"),
        &loc,
        &env,
        NATIVE,
        &hang,
        &Deadline::new(start, 100),
    );
    assert_eq!(r, Target::Timeout);
    assert!(start.elapsed() < Duration::from_millis(150));
}

fn host_bash() -> Shell {
    if cfg!(windows) {
        Shell::Bash(BashProfile::GitBash)
    } else {
        Shell::Bash(BashProfile::Posix)
    }
}

#[test]
fn a_glob_over_a_folder_the_hook_cannot_list_is_unknown() {
    let fs = FakeFs::default()
        .dir(&at("repo"))
        .add(&at("repo/locked"), Node::Denied)
        .shared();
    let loc = Location::new(host_bash(), Os::host(), Some(Path::new(&at("repo"))));
    let w = word_at(
        vec![
            WordPart::Literal(format!("locked{}", std::path::MAIN_SEPARATOR)),
            WordPart::Glob("*".to_string()),
        ],
        0,
    );
    assert_eq!(
        target(&w, &loc, &EnvView::new(), NATIVE, &fs, &far()),
        MAY_BE_CRITICAL
    );
}

#[test]
fn a_bash_dotdot_out_of_a_link_is_unknown() {
    let fs = FakeFs::default()
        .dir(&at("repo/sub"))
        .link(&at("repo/l"), &at("elsewhere/deep"))
        .shared();
    let sep = std::path::MAIN_SEPARATOR;
    let r = |shell: Shell, text: &str| {
        let loc = Location::new(shell, Os::host(), Some(Path::new(&at("repo"))));
        target(&lit(text), &loc, &EnvView::new(), NATIVE, &fs, &far())
    };
    let out_of_link = format!("l{sep}..{sep}x");
    let out_of_dir = format!("sub{sep}..{sep}x");
    assert_eq!(r(host_bash(), &out_of_link), MAY_BE_CRITICAL);
    assert_eq!(r(host_bash(), &out_of_dir), paths(&[&at("repo/x")]));
    if cfg!(windows) {
        // PowerShell and Win32 resolve `..` lexically.
        assert_eq!(r(Shell::Pwsh, &out_of_link), paths(&[&at("repo/x")]));
    }
}

#[test]
fn a_remapped_drive_letter_is_unknown_after_the_mapping() {
    let (base, env) = win(Shell::Pwsh);
    let x = lit(r"X:\sub");
    assert_eq!(resolve(&x, &base, &env), paths(&[r"X:\sub"]));
    for mapping in [
        lits("subst", &["X:", r"C:\Profiles\u"]),
        lits("New-PSDrive", &["-Name", "X", "-Root", r"C:\Profiles\u"]),
        lits("net", &["use", "X:", r"\\srv\share"]),
        lits(r"C:\Windows\System32\SUBST.EXE", &["X:", r"C:\Profiles\u"]),
        lits(
            "mountvol",
            &["X:", r"\\?\Volume{0b1c2d3e-0000-4000-8000-000000000001}\"],
        ),
        lits(
            "New-SmbMapping",
            &["-LocalPath", "X:", "-RemotePath", r"\\srv\share"],
        ),
        lits("net1", &["use", "X:", r"\\srv\share"]),
        lits("ndr", &["-Name", "X", "-Root", r"C:\Profiles\u"]),
        lits("mount", &["-o", "bind", r"C:\Profiles\u", "/c/x"]),
        // diskpart reads its script from stdin: `assign letter=X` is not in the words.
        lits("diskpart", &["/s", "script.txt"]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(mapping.clone(), Some(ChainOp::Seq)), &env);
        assert_eq!(
            resolve(&x, &loc, &env),
            MAY_BE_CRITICAL,
            "{}",
            mapping.typed
        );
        let glob = word_at(
            vec![
                WordPart::Literal(r"X:\".to_string()),
                WordPart::Glob("*".to_string()),
            ],
            0,
        );
        assert_eq!(resolve(&glob, &loc, &env), MAY_BE_CRITICAL);
    }
    for net in ["net", "net1"] {
        let mut loc = base.clone();
        loc.after(&stmt(lits(net, &["view"]), Some(ChainOp::Seq)), &env);
        assert_eq!(resolve(&x, &loc, &env), paths(&[r"X:\sub"]), "{net} view");
    }
}

#[test]
fn a_link_an_earlier_statement_creates_makes_its_tree_unknown() {
    let seq = Some(ChainOp::Seq);
    let ps = Shell::Pwsh;
    let bash = Shell::Bash(BashProfile::GitBash);
    let rows: Vec<(&str, Shell, SimpleCommand)> = vec![
        (
            "mklink /J t\\j $HOME",
            ps,
            cmd("mklink", vec![lit("/J"), lit(r"t\j"), var("HOME")]),
        ),
        (
            "cmd /c mklink /D",
            ps,
            cmd("MKLINK", vec![lit("/d"), lit(r"t\j"), lit(r"C:\x")]),
        ),
        (
            "New-Item -ItemType Junction -Path t\\j",
            ps,
            lits(
                "New-Item",
                &["-ItemType", "Junction", "-Path", r"t\j", "-Target", r"C:\x"],
            ),
        ),
        (
            "ni t\\j -ItemType:SymbolicLink",
            ps,
            lits("ni", &[r"t\j", "-ItemType:SymbolicLink", "-Value", r"C:\x"]),
        ),
        (
            "ln -s ~ t/j",
            bash,
            cmd(
                "ln",
                vec![lit("-sfn"), word_at(vec![WordPart::Tilde], 0), lit("t/j")],
            ),
        ),
        (
            "ln --symbolic",
            bash,
            lits("ln", &["--symbolic", r"C:\x", "t/j"]),
        ),
        // The provider accepts a prefix or a wildcard of the item type.
        (
            "New-Item -ItemType junc",
            ps,
            lits("New-Item", &["-ItemType", "junc", "-Path", r"t\j"]),
        ),
        (
            "New-Item -ItemType sym*",
            ps,
            lits("New-Item", &["-ItemType", "sym*", r"t\j"]),
        ),
        ("ln --sym", bash, lits("ln", &["--sym", r"C:\x", "t/j"])),
        // An empty item type is no proven folder or file.
        (
            "New-Item -ItemType ''",
            ps,
            lits("New-Item", &["-ItemType", "", r"t\j"]),
        ),
        // Parameter names as PowerShell binds them (pwsh 7.7 StaticParameterBinder: each binds
        // ItemType): any unambiguous prefix of the name or its alias `Type`, in any case, also
        // where only common parameters share the prefix (`-i`), with `-Name:value`, `-Name:
        // value` and any dash PowerShell accepts.
        (
            "New-Item -Ty Junction",
            ps,
            lits("New-Item", &["-Ty", "Junction", r"t\j"]),
        ),
        (
            "New-Item -Typ Junction",
            ps,
            lits("New-Item", &["-Typ", "Junction", r"t\j"]),
        ),
        (
            "New-Item -it Junction",
            ps,
            lits("New-Item", &["-it", "Junction", r"t\j"]),
        ),
        (
            "New-Item -ItemType:Junction",
            ps,
            lits("New-Item", &["-ItemType:Junction", r"t\j"]),
        ),
        (
            "New-Item -type Junction",
            ps,
            lits("New-Item", &["-type", "Junction", r"t\j"]),
        ),
        (
            "New-Item -i Junction",
            ps,
            lits("New-Item", &["-i", "Junction", r"t\j"]),
        ),
        (
            "New-Item -TY:Junction",
            ps,
            lits("New-Item", &["-TY:Junction", "-Path", r"t\j"]),
        ),
        (
            "New-Item -ItemType: Junction",
            ps,
            lits("New-Item", &["-ItemType:", "Junction", "-Path", r"t\j"]),
        ),
        (
            "New-Item <en dash>ItemType Junction",
            ps,
            lits("New-Item", &["\u{2013}ItemType", "Junction", r"t\j"]),
        ),
        (
            "New-Item -Path:t\\j -ItemType Junction",
            ps,
            lits("New-Item", &[r"-Path:t\j", "-ItemType", "Junction"]),
        ),
        (
            "New-Item -ItemType: Junction t\\j",
            ps,
            lits("New-Item", &["-ItemType:", "Junction", r"t\j"]),
        ),
        // A switch takes no value.
        (
            "New-Item -Force -ItemType Junction",
            ps,
            lits("New-Item", &["-Force", "-ItemType", "Junction", r"t\j"]),
        ),
    ];
    // Every row is checked; the failures are listed together.
    let mut bad: Vec<String> = Vec::new();
    let mut expect = |got: Target, want: &Target, label: String| {
        if &got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    };
    for (name, shell, link) in rows {
        let (base, env) = win(shell);
        let mut loc = base.clone();
        expect(
            resolve(&lit("t"), &loc, &env),
            &paths(&[r"C:\w\repo\t"]),
            format!("{name}: before"),
        );
        loc.after(&stmt(link, seq), &env);
        for gone in ["t", r"t\j", r"t\other", "."] {
            expect(
                resolve(&lit(gone), &loc, &env),
                &MAY_BE_CRITICAL,
                format!("{name}: {gone}"),
            );
        }
        expect(
            resolve(&lit("u"), &loc, &env),
            &paths(&[r"C:\w\repo\u"]),
            format!("{name}: unrelated"),
        );
    }
    // Not a link: a plain folder, a hard link left out on purpose.
    let (base, env) = win(ps);
    for plain in [
        lits("New-Item", &["-ItemType", "Directory", "-Path", r"t\j"]),
        lits("ln", &[r"C:\x", "t/j"]),
        // Provably a folder or a file.
        lits("New-Item", &["-ItemType", "dir", "-Path", r"t\j"]),
        lits("New-Item", &["-ItemType", "F", r"t\j"]),
        cmd(
            "New-Item",
            vec![lit("-ItemType"), lit("Directory"), var("p")],
        ),
        lits("New-Item", &[r"t\j"]),
        // Common parameters bind and take their value.
        lits(
            "New-Item",
            &["-ItemType", "Directory", "-ea", "Stop", "-Verbose", r"t\j"],
        ),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(plain.clone(), seq), &env);
        expect(
            resolve(&lit("t"), &loc, &env),
            &paths(&[r"C:\w\repo\t"]),
            format!("plain {}", show(&plain)),
        );
    }
    // A link at a place the hook cannot tell: every later target is unknown.
    for vague in [
        lits(
            "New-Item",
            &["-ItemType", "Junction", "-Name", "j", "-Path", "t"],
        ),
        cmd(
            "New-Item",
            vec![lit("-ItemType"), lit("Junction"), var("p")],
        ),
        lits("ln", &["-s", r"C:\x"]),
        cmd("mklink", vec![lit("/J"), var("x"), lit(r"C:\x")]),
        // `-t`/`--target-directory` and options the hook does not model place it elsewhere.
        lits("ln", &["-s", "-t", "d", r"C:\x"]),
        lits("ln", &["-st", "d", r"C:\x"]),
        lits("ln", &["--target-directory=d", "-s", r"C:\x"]),
        lits("ln", &["-s", "--suffix=~", r"C:\x", "t/j"]),
        // A splat or a variable may carry `-ItemType Junction`.
        cmd("New-Item", vec![var("p")]),
        cmd("New-Item", vec![lit(r"t\j"), var("opts")]),
        // A non-literal `ln` argument may carry `-s` and `-t`.
        cmd("ln", vec![var("opts"), lit(r"C:\x"), lit("t/j")]),
        // A prefix PowerShell finds ambiguous (`-t`: ItemType's alias Type, Value's alias
        // Target), or one no parameter has: the hook cannot tell what binds.
        lits("New-Item", &["-t", "Junction", r"t\j"]),
        lits("New-Item", &["-ItemType", "Directory", "-o", "x", r"t\j"]),
        lits("New-Item", &["-Bogus", "Junction", r"t\j"]),
        // A splat.
        lits("New-Item", &["@p"]),
        // A second positional value: PowerShell refuses it.
        lits("New-Item", &["-ItemType", "Junction", r"t\j", "x"]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(vague.clone(), seq), &env);
        // A folder outside the repo: only "a link somewhere unknown" makes it unknown.
        expect(
            resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
            &MAY_BE_CRITICAL,
            format!("vague {}", show(&vague)),
        );
    }
    // PowerShell reads an unquoted `a\j,t\k` as a list: every element is a link.
    for list in [
        lits(
            "New-Item",
            &["-ItemType", "Junction", r"a\j,t\k", "-Value", r"C:\x"],
        ),
        lits("New-Item", &["-ItemType", "Junction", "-Path", r"a\j,t\k"]),
        lits("New-Item", &["-ItemType", "Junction", r"-Path:a\j,t\k"]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(list.clone(), seq), &env);
        for gone in ["a", "t", r"C:\w\repo\t"] {
            expect(
                resolve(&lit(gone), &loc, &env),
                &MAY_BE_CRITICAL,
                format!("list {}: {gone}", show(&list)),
            );
        }
        expect(
            resolve(&lit("u"), &loc, &env),
            &paths(&[r"C:\w\repo\u"]),
            format!("list {}: unrelated", show(&list)),
        );
    }
    // Any other comma shape (quoted, an empty element) is a link at a place the hook cannot
    // tell.
    let mut quoted = lit(r"a\j,t\k");
    quoted.quote = Quote::Single;
    for odd in [
        cmd(
            "New-Item",
            vec![lit("-ItemType"), lit("Junction"), quoted.clone()],
        ),
        lits("New-Item", &["-ItemType", "Junction", r"a\j,"]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(odd.clone(), seq), &env);
        expect(
            resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
            &MAY_BE_CRITICAL,
            format!("comma {}", show(&odd)),
        );
    }
    // `-1` is a value, not a parameter: the link is `-1`.
    let mut loc = base.clone();
    let numeric = lits("New-Item", &["-1", "-ItemType", "Junction"]);
    loc.after(&stmt(numeric, seq), &env);
    expect(
        resolve(&lit("-1"), &loc, &env),
        &MAY_BE_CRITICAL,
        "New-Item -1: -1".to_string(),
    );
    expect(
        resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
        &paths(&[r"D:\elsewhere\u"]),
        "New-Item -1: unrelated".to_string(),
    );
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
    let mut loc = base.clone();
    loc.after(
        &method(
            "IO.Directory",
            "CreateSymbolicLink",
            vec![lit(r"t\j"), lit(r"C:\x")],
        ),
        &env,
    );
    assert_eq!(
        resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
        MAY_BE_CRITICAL
    );
    // An item type the hook cannot read counts as a link.
    let mut loc = base.clone();
    let dyn_kind = cmd("New-Item", vec![lit("-ItemType"), var("k"), lit(r"t\j")]);
    loc.after(&stmt(dyn_kind, seq), &env);
    assert_eq!(resolve(&lit("t"), &loc, &env), MAY_BE_CRITICAL);
}

#[test]
fn an_unknown_target_that_may_name_a_critical_folder_says_so() {
    let seq = Some(ChainOp::Seq);
    let (base, env) = win(Shell::Pwsh);
    // A share root may be this machine's drive root under another name.
    assert_eq!(resolve(&lit(r"\\srv\share\"), &base, &env), MAY_BE_CRITICAL);
    // `New-Item $f -Force; Remove-Item -Recurse -Force C:\`: the link may be anywhere.
    let mut loc = base.clone();
    loc.after(
        &stmt(cmd("New-Item", vec![var("f"), lit("-Force")]), seq),
        &env,
    );
    assert_eq!(resolve(&lit(r"C:\"), &loc, &env), MAY_BE_CRITICAL);
    // A drive letter mapped earlier in the command.
    let mut loc = base.clone();
    loc.after(&stmt(lits("subst", &["X:", r"C:\Profiles\u"]), seq), &env);
    assert_eq!(resolve(&lit(r"X:\"), &loc, &env), MAY_BE_CRITICAL);
    // `rm -rf "$d"` stays a dynamic word.
    let bash = Shell::Bash(BashProfile::GitBash);
    let (bash_loc, bash_env) = win(bash);
    let mut d = var("d");
    d.quote = Quote::Double;
    assert_eq!(resolve(&d, &bash_loc, &bash_env), Target::Dynamic(d.span));
    // `cd $x; rm -rf ..`: the cd may fail, and then `..` is C:\w, above the repo root.
    let mut loc = base.clone();
    loc.after(&stmt(cmd("cd", vec![var("x")]), seq), &env);
    assert_eq!(resolve(&lit(".."), &loc, &env), MAY_BE_CRITICAL);
    // A relative target in a folder a variable chose: `cd $x && rm -rf ..`, `$PWD\x`.
    let mut loc = base.clone();
    loc.after(&stmt(cmd("cd", vec![var("x")]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit(".."), &loc, &env), DYNAMIC_LOCATION);
    let pwd = word_at(
        vec![
            WordPart::Var("PWD".to_string()),
            WordPart::Literal(r"\x".to_string()),
        ],
        0,
    );
    assert_eq!(resolve(&pwd, &loc, &env), DYNAMIC_LOCATION);
}

#[test]
fn a_path_on_a_powershell_drive_that_is_no_file_system_is_not_a_file() {
    let seq = Some(ChainOp::Seq);
    let (base, env) = win(Shell::Pwsh);
    let mut bad: Vec<String> = Vec::new();
    let mut expect = |got: Target, want: &Target, label: String| {
        if &got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    };
    // `<before>; Remove-Item <text>; <later>`, the whole command read first, the delete's own
    // reader taken from the command.
    let judge = |before: Vec<Stmt>, delete: SimpleCommand, later: Vec<Stmt>| {
        let shell = Shell::Pwsh;
        let by = delete_by(&delete, shell, Os::Windows);
        let text = delete.args[0].clone();
        let mut all = before.clone();
        all.push(stmt(delete, seq));
        all.extend(later);
        let mut loc = base.clone();
        loc.read_script(&script(all));
        after_all(&mut loc, &script(before), &env);
        sorted(target(&text, &loc, &env, by, &real(), &far()))
    };
    let ri = |text: &str| lits("Remove-Item", &[text]);
    // Every built-in drive whose provider is no file system, in any case and path form.
    for text in [
        "Env:FOO",
        "env:foo",
        r"Env:\FOO",
        "Env:/FOO",
        "Env:FOO*",
        "Env:",
        "Variable:x",
        r"Cert:\CurrentUser\My\x",
        r"HKCU:\Software\x",
        r"hklm:\SOFTWARE\x",
        r"WSMan:\localhost\x",
    ] {
        expect(
            judge(Vec::new(), ri(text), Vec::new()),
            &Target::NotAFile,
            text.to_string(),
        );
    }
    // Each alias of Remove-Item.
    for alias in ["remove-item", "ri", "rm", "rmdir", "rd", "del", "erase"] {
        expect(
            judge(Vec::new(), lits(alias, &["Env:FOO"]), Vec::new()),
            &Target::NotAFile,
            format!("{alias} Env:FOO"),
        );
    }
    // Only a command whose every part is in a small harmless set proves the drive (Ruling 30):
    // the Remove-Item family, Get-*, Write-*, echo, Test-Path, a cd to a literal path, a plain,
    // `env:` or `variable:` assignment.
    let set = |name: &str, value: &str| stmt(assign(name, value), seq);
    for (label, before) in [
        ("cd literal;", stmt(lits("cd", &[r"C:\x"]), seq)),
        (
            "Set-Location literal &&",
            stmt(lits("Set-Location", &[r"C:\x"]), Some(ChainOp::And)),
        ),
        ("chdir literal", stmt(lits("chdir", &[r"C:\x"]), seq)),
        ("sl literal", stmt(lits("sl", &[r"C:\x"]), seq)),
        ("Get-ChildItem", stmt(lits("Get-ChildItem", &["Env:"]), seq)),
        ("Write-Host", stmt(lits("Write-Host", &["x"]), seq)),
        ("echo", stmt(cmd("echo", vec![var("x")]), seq)),
        ("Test-Path", stmt(lits("Test-Path", &["Env:FOO"]), seq)),
        ("$x =", set("x", "1")),
        ("$env:X =", set("env:X", "1")),
        ("$variable:y =", set("variable:y", "1")),
        ("another delete", stmt(ri("Env:BAR"), seq)),
    ] {
        expect(
            judge(vec![before], ri("Env:FOO"), Vec::new()),
            &Target::NotAFile,
            format!("harmless {label}"),
        );
    }
    // Anything else, the location commands the hook follows included.
    let block = |stmts: Vec<Stmt>| word_at(vec![WordPart::Block(Box::new(script(stmts)))], 0);
    for (label, other) in [
        ("Pop-Location;", stmt(lits("Pop-Location", &[]), seq)),
        ("cd $x;", stmt(cmd("cd", vec![var("x")]), seq)),
        (
            "cd $x &&",
            stmt(cmd("cd", vec![var("x")]), Some(ChainOp::And)),
        ),
        ("git status", stmt(lits("git", &["status"]), seq)),
        // The three notes: `${function:Remove-Item} = {…}`, `[scriptblock]::Create(…)`,
        // `Invoke-Command $sb`, `% { … }`.
        (
            "function: assignment",
            stmt(
                {
                    let mut c = assign("function:Remove-Item", "");
                    c.assigns[0].1 = block(Vec::new());
                    c
                },
                seq,
            ),
        ),
        (
            "scriptblock::Create",
            method("scriptblock", "Create", vec![lit("x")]),
        ),
        (
            "Invoke-Command $sb",
            stmt(cmd("Invoke-Command", vec![var("sb")]), seq),
        ),
        (
            "% { echo }",
            stmt(
                cmd(
                    "ForEach-Object",
                    vec![block(vec![stmt(lits("echo", &["x"]), None)])],
                ),
                seq,
            ),
        ),
        // A harmless name with a script block, or written by a variable.
        (
            "Write-Host { echo }",
            stmt(
                cmd(
                    "Write-Host",
                    vec![block(vec![stmt(lits("echo", &["x"]), None)])],
                ),
                seq,
            ),
        ),
        (
            "opaque echo",
            stmt(
                {
                    let mut c = lits("echo", &["x"]);
                    c.opaque = true;
                    c
                },
                seq,
            ),
        ),
        ("$global:x =", set("global:x", "1")),
        ("$x.y =", set("x.y", "1")),
        (
            "Remove-Item $p",
            stmt(cmd("Remove-Item", vec![var("p")]), seq),
        ),
        ("Remove-Item Function:f", stmt(ri("Function:f"), seq)),
        (
            "path-qualified Get-",
            stmt(lits(r"C:\x\Get-Thing.exe", &[]), seq),
        ),
        (
            "wrapped Get-",
            stmt(lits("command", &["Get-ChildItem"]), seq),
        ),
    ] {
        // Ruling 33: not proven, but no remap in sight; Ruling 40: a part not read as written is
        // a fact on the target.
        let unread = [
            "function: assignment",
            "Invoke-Command $sb",
            "opaque echo",
            "scriptblock::Create",
            "path-qualified Get-",
        ];
        let want = if unread.contains(&label) {
            unproven_unread("Env")
        } else {
            unproven("Env")
        };
        expect(
            judge(vec![other], ri("Env:FOO"), Vec::new()),
            &want,
            format!("not harmless {label}"),
        );
    }
    // A path list (`Env:FOO,bar` deletes the file `bar` too) or a `;` in the path word.
    for text in ["Env:FOO,bar", "Env:FOO;bar"] {
        expect(
            judge(Vec::new(), ri(text), Vec::new()),
            &MAY_BE_CRITICAL,
            format!("list {text}"),
        );
    }
    // A drive name PowerShell does not build in may be a profile's file-system drive (Ruling
    // 33). Removing an alias or a function may make the delete another command, and with
    // `-Include __sw*` a `Variable:` wildcard may remove the shim's variables (Ruling 35).
    for (text, want) in [
        (r"Proj:\x", unproven("Proj")),
        (r"Environment:\x", unproven("Environment")),
        (r"HKCC:\x", unproven("HKCC")),
        ("Function:f", Target::SessionCommand),
        ("Alias:a", Target::SessionCommand),
        (r"variable:\x*", Target::SessionCommand),
    ] {
        expect(
            judge(Vec::new(), ri(text), Vec::new()),
            &want,
            text.to_string(),
        );
    }
    // Note 1: only a provider cmdlet reads the drive; a native program or a .NET call reads a
    // file-system path, and a `.`/`..` step or a stream suffix leaves the drive's path form.
    for (label, delete) in [
        ("rm.exe", lits("rm.exe", &["Env:FOO"])),
        ("cmd", lits("cmd", &["Env:FOO"])),
        (
            "module-qualified",
            lits(r"Microsoft.PowerShell.Management\Remove-Item", &["Env:FOO"]),
        ),
        ("dotdot", ri(r"Env:..\x")),
        ("dot", ri(r"Env:.\x")),
        ("deeper dotdot", ri(r"HKCU:\a\..\..\x")),
        ("stream", ri("Env:FOO:bar")),
    ] {
        expect(
            judge(Vec::new(), delete, Vec::new()),
            &MAY_BE_CRITICAL,
            format!("note 1 {label}"),
        );
    }
    let mut opaque = ri("Env:FOO");
    opaque.opaque = true;
    expect(
        judge(Vec::new(), opaque, Vec::new()),
        &MAY_BE_CRITICAL,
        "note 1 opaque delete".to_string(),
    );
    // The reader decides on its own: a .NET call (`[IO.Directory]::Delete('Env:FOO')`) in a
    // command whose other parts are harmless.
    let mut harmless_loc = base.clone();
    harmless_loc.read_script(&script(vec![stmt(ri("Env:BAR"), seq)]));
    expect(
        sorted(target(
            &lit("Env:FOO"),
            &harmless_loc,
            &env,
            NATIVE,
            &real(),
            &far(),
        )),
        &MAY_BE_CRITICAL,
        "note 1 native reader".to_string(),
    );
    // Note 2: anything anywhere in the command that may define or redefine a drive or a command,
    // before the delete or after it.
    let nested = word_at(
        vec![WordPart::Block(Box::new(script(vec![stmt(
            lits("New-PSDrive", &["Env", "-PSProvider", "FileSystem"]),
            None,
        )])))],
        0,
    );
    let mut opaque = lits("x", &[]);
    opaque.opaque = true;
    let redefiners: Vec<(&str, Stmt)> = vec![
        (
            "New-PSDrive",
            stmt(
                lits(
                    "New-PSDrive",
                    &["Env", "-PSProvider", "FileSystem", "-Root", r"C:\"],
                ),
                seq,
            ),
        ),
        ("ndr", stmt(lits("ndr", &["Env"]), seq)),
        ("mount", stmt(lits("mount", &["Env"]), seq)),
        ("rdr", stmt(lits("rdr", &["Env"]), seq)),
        ("nal", stmt(lits("nal", &["rm", "x"]), seq)),
        ("Import-Alias", stmt(lits("Import-Alias", &["a.csv"]), seq)),
        ("ipal", stmt(lits("ipal", &["a.csv"]), seq)),
        ("New-Module", stmt(lits("New-Module", &["x"]), seq)),
        ("nmo", stmt(lits("nmo", &["x"]), seq)),
        (
            "Import-PSSession",
            stmt(lits("Import-PSSession", &["s"]), seq),
        ),
        ("ipsn", stmt(lits("ipsn", &["s"]), seq)),
        (
            "Invoke-Expression",
            stmt(lits("Invoke-Expression", &["x"]), seq),
        ),
        ("source", stmt(lits("source", &["x"]), seq)),
        ("psm1", stmt(lits("m.psm1", &[]), seq)),
        ("bare ps1", stmt(lits("setup.ps1", &[]), seq)),
        (
            "Remove-PSDrive",
            stmt(lits("Remove-PSDrive", &["Env"]), seq),
        ),
        ("Set-Alias", stmt(lits("Set-Alias", &["rm", "x"]), seq)),
        ("sal", stmt(lits("sal", &["rm", "x"]), seq)),
        ("New-Alias", stmt(lits("New-Alias", &["rm", "x"]), seq)),
        ("Remove-Alias", stmt(lits("Remove-Alias", &["rm"]), seq)),
        ("Remove-Item Alias:rm", stmt(ri("Alias:rm"), seq)),
        (
            "Set-Item Function:",
            stmt(lits("Set-Item", &["Function:Remove-Item", "x"]), seq),
        ),
        (
            "Set-Item $p",
            stmt(cmd("Set-Item", vec![var("p"), lit("x")]), seq),
        ),
        (
            "function",
            Stmt::Func {
                name: "Remove-Item".to_string(),
                body: script(Vec::new()),
            },
        ),
        ("Import-Module", stmt(lits("Import-Module", &["m"]), seq)),
        ("ipmo", stmt(lits("ipmo", &["m"]), seq)),
        ("dot-source", stmt(lits(".", &[r".\x.ps1"]), seq)),
        ("script call", stmt(lits(r".\x.ps1", &[]), seq)),
        ("iex", stmt(lits("iex", &["x"]), seq)),
        (
            "module-qualified",
            stmt(
                lits(r"Microsoft.PowerShell.Management\New-PSDrive", &["Env"]),
                seq,
            ),
        ),
        ("opaque", stmt(opaque, seq)),
        ("Start-Process", stmt(lits("Start-Process", &["pwsh"]), seq)),
        (
            "Drive method",
            method("ExecutionContext.Drive", "New", Vec::new()),
        ),
        (
            "SessionState method",
            method("ExecutionContext.SessionState", "Get", Vec::new()),
        ),
        ("slash path", stmt(lits("./x", &[]), seq)),
        (
            "expression",
            Stmt::Pipeline(Pipeline {
                elems: vec![Elem::Expr(lit("$ExecutionContext.SessionState"))],
                chain: seq,
            }),
        ),
        (
            "nested New-PSDrive",
            stmt(cmd("ForEach-Object", vec![nested]), seq),
        ),
    ];
    // Ruling 33 + I1: only a drive mapping before the delete (or a command that may be one,
    // `Start-Process`) keeps MayBeCritical; any other part, or one after it, leaves the drive
    // unproven.
    // Ruling 36: so does any command not read as written (opaque, unread, code from text, a call
    // to a function or alias the command defines, or a definition whose names the hook cannot
    // read), wherever it stands.
    let remaps = [
        "New-PSDrive",
        "ndr",
        "mount",
        "rdr",
        "Remove-PSDrive",
        "module-qualified",
        "nested New-PSDrive",
    ];
    // Ruling 40: a script run before the delete counts as a remap in sight; any other part not
    // read as written is a fact on the target (`unread_before`), before or after the delete.
    let scripts = [
        "psm1",
        "bare ps1",
        "dot-source",
        "script call",
        "Invoke-Expression",
        "iex",
        "Import-Module",
        "ipmo",
    ];
    let unread = [
        "module-qualified",
        "Drive method",
        "SessionState method",
        "slash path",
        "expression",
        "Start-Process",
        "opaque",
        "function",
        "Set-Item Function:",
        "Set-Item $p",
        "Import-Alias",
        "ipal",
        "New-Module",
        "nmo",
        "Import-PSSession",
        "ipsn",
    ];
    for (label, s) in redefiners {
        let before = if remaps.contains(&label) || scripts.contains(&label) {
            MAY_BE_CRITICAL
        } else if unread.contains(&label) {
            unproven_unread("Env")
        } else {
            unproven("Env")
        };
        let after = if unread.contains(&label) || scripts.contains(&label) {
            unproven_unread("Env")
        } else {
            unproven("Env")
        };
        expect(
            judge(vec![s.clone()], ri("Env:FOO"), Vec::new()),
            &before,
            format!("note 2 before: {label}"),
        );
        expect(
            judge(Vec::new(), ri("Env:FOO"), vec![s]),
            &after,
            format!("note 2 after: {label}"),
        );
    }
    // A command with none of them.
    expect(
        judge(
            vec![stmt(lits("echo", &["x"]), seq)],
            ri("Env:FOO"),
            vec![stmt(ri("Env:BAR"), seq)],
        ),
        &Target::NotAFile,
        "note 2 control".to_string(),
    );
    // Fail closed: without the whole command read, nothing proves the drive.
    let by = delete_by(&ri("Env:FOO"), Shell::Pwsh, Os::Windows);
    expect(
        sorted(target(&lit("Env:FOO"), &base, &env, by, &real(), &far())),
        &MAY_BE_CRITICAL,
        "unread command".to_string(),
    );
    // In bash `Env:FOO` is a file `Env` with a stream.
    let (bash_loc, bash_env) = win(Shell::Bash(BashProfile::GitBash));
    expect(
        resolve(&lit("Env:FOO"), &bash_loc, &bash_env),
        &MAY_BE_CRITICAL,
        "bash Env:FOO".to_string(),
    );
    // Even when a caller says a provider reads it, in a command with nothing else in it.
    let mut read = bash_loc.clone();
    read.read_script(&script(vec![stmt(lits("echo", &["x"]), seq)]));
    expect(
        sorted(target(
            &lit("Env:FOO"),
            &read,
            &bash_env,
            DeleteBy::Provider,
            &real(),
            &far(),
        )),
        &MAY_BE_CRITICAL,
        "bash Env:FOO read by a provider".to_string(),
    );
    // Who reads the drive (note 1): Remove-Item and its aliases in PowerShell, as the OS defines
    // them (pwsh on Linux has no `rm`/`rmdir` alias).
    let mut opaque_rm = lits("rm", &[]);
    opaque_rm.opaque = true;
    for (c, shell, os, want) in [
        (
            lits("Remove-Item", &[]),
            Shell::Pwsh,
            Os::Windows,
            DeleteBy::Provider,
        ),
        (
            lits("rm", &[]),
            Shell::Powershell5,
            Os::Windows,
            DeleteBy::Provider,
        ),
        (lits("ri", &[]), Shell::Pwsh, Os::Posix, DeleteBy::Provider),
        (lits("rm", &[]), Shell::Pwsh, Os::Posix, NATIVE),
        (lits("rmdir", &[]), Shell::Pwsh, Os::Posix, NATIVE),
        (lits("rm.exe", &[]), Shell::Pwsh, Os::Windows, NATIVE),
        (lits("cmd", &[]), Shell::Pwsh, Os::Windows, NATIVE),
        (
            lits("rm", &[]),
            Shell::Bash(BashProfile::GitBash),
            Os::Windows,
            NATIVE,
        ),
        (opaque_rm, Shell::Pwsh, Os::Windows, NATIVE),
    ] {
        let got = delete_by(&c, shell, os);
        if got != want {
            bad.push(format!(
                "delete_by {} {shell:?} {os:?}: got {got:?}, want {want:?}",
                show(&c)
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// A named-drive delete after commands that are all read as written.
fn unproven(drive: &str) -> Target {
    Target::DriveUnproven {
        drive: drive.to_string(),
        unread_before: false,
    }
}

#[test]
fn an_unproven_drive_and_a_session_command_have_their_own_causes() {
    let seq = Some(ChainOp::Seq);
    let (base, env) = win(Shell::Pwsh);
    // The machine the hook runs on: drives C: and D: exist, Z: does not.
    let machine = FakeFs::default()
        .dir(r"C:\Profiles\u")
        .dir(r"D:\elsewhere")
        .shared();
    let mut bad: Vec<String> = Vec::new();
    let mut expect = |got: Target, want: &Target, label: &str| {
        if &got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    };
    // `<before>; <delete>`, the whole command read first; `word` is the delete's first argument.
    let judge_on = |before: Vec<Stmt>, delete: SimpleCommand, shell: Shell, fs: &SharedFs| {
        let (base, env) = win(shell);
        let by = delete_by(&delete, shell, Os::Windows);
        let word = delete.args[0].clone();
        let mut all = before.clone();
        all.push(stmt(delete, seq));
        let mut loc = base.clone();
        loc.read_script(&script(all));
        after_all(&mut loc, &script(before), &env);
        sorted(target(&word, &loc, &env, by, fs, &far()))
    };
    let judge =
        |before: Vec<Stmt>, delete: SimpleCommand| judge_on(before, delete, Shell::Pwsh, &machine);
    let ri = |text: &str| lits("Remove-Item", &[text]);
    let git = || stmt(lits("git", &["status"]), seq);
    let mut opaque = lits("x", &[]);
    opaque.opaque = true;

    // Ruling 33: a plain named-drive path in a command not proven harmless.
    expect(
        judge(vec![git()], ri("Env:FOO")),
        &unproven("Env"),
        "git; Env:FOO",
    );
    expect(
        judge(vec![], ri("Env:FOO")),
        &Target::NotAFile,
        "Env:FOO alone",
    );
    expect(
        judge(vec![], ri(r"Proj:\x")),
        &unproven("Proj"),
        r"Proj:\x alone",
    );
    expect(
        judge(vec![git()], ri(r"Proj:\*")),
        &unproven("Proj"),
        r"git; Proj:\*",
    );
    expect(
        judge(vec![], ri("Variable:foo")),
        &Target::NotAFile,
        "Variable:foo alone",
    );
    expect(
        judge(vec![git()], ri("Variable:foo")),
        &unproven("Variable"),
        "git; Variable:foo",
    );
    // Ruling 35 pin: a literal name with `-Include __sw*` names only itself.
    expect(
        judge(
            vec![],
            lits("Remove-Item", &["Variable:foo", "-Include", "__sw*"]),
        ),
        &Target::NotAFile,
        "Variable:foo -Include __sw*",
    );
    // Two words after a non-harmless part: each on its own.
    for (w, other) in [("Env:A", "Env:B"), ("Env:B", "Env:A")] {
        expect(
            judge(vec![git()], lits("Remove-Item", &[w, other])),
            &unproven("Env"),
            &format!("git; two words, {w}"),
        );
    }
    // C1/I5: one word holding `,`, `;` or `:` after the drive keeps MayBeCritical.
    for (label, before, text) in [
        ("one word Env:A,Env:B alone", vec![], "Env:A,Env:B"),
        ("git; one word Env:A,Env:B", vec![git()], "Env:A,Env:B"),
        (
            "git; one word Env:FOO,<home>",
            vec![git()],
            r"Env:FOO,C:\Profiles\u",
        ),
        ("one word Proj:\\x,<home>", vec![], r"Proj:\x,C:\Profiles\u"),
        ("git; Proj:x;y", vec![git()], "Proj:x;y"),
        ("git; Proj:a:b", vec![git()], "Proj:a:b"),
        ("Function:x,<home>", vec![], r"Function:x,C:\Profiles\u"),
        ("git; Proj:..\\x", vec![git()], r"Proj:..\x"),
    ] {
        expect(judge(before, ri(text)), &MAY_BE_CRITICAL, label);
    }
    // I1: a drive the command visibly remaps keeps MayBeCritical; Ruling 40: after an unread
    // command the drive is unproven, with the fact on the target.
    for (label, remap, proj, env_foo) in [
        (
            "New-PSDrive",
            stmt(lits("New-PSDrive", &["Proj", "FileSystem", r"C:\x"]), seq),
            MAY_BE_CRITICAL,
            MAY_BE_CRITICAL,
        ),
        (
            "ndr",
            stmt(lits("ndr", &["Proj", "-PSProvider", "FileSystem"]), seq),
            MAY_BE_CRITICAL,
            MAY_BE_CRITICAL,
        ),
        (
            "unread",
            stmt(lits("Start-Process", &["pwsh", "-ArgumentList", "x"]), seq),
            unproven_unread("Proj"),
            unproven_unread("Env"),
        ),
        (
            "opaque",
            stmt(opaque.clone(), seq),
            unproven_unread("Proj"),
            unproven_unread("Env"),
        ),
    ] {
        expect(
            judge(vec![remap.clone(), git()], ri(r"Proj:\y")),
            &proj,
            &format!("{label}; git; Proj:\\y"),
        );
        expect(
            judge(vec![remap, git()], ri("Env:FOO")),
            &env_foo,
            &format!("{label}; git; Env:FOO"),
        );
    }
    // Ruling 36: a command the hook does not read as written may define a drive unseen.
    let dynamic_name = {
        let mut c = cmd("", vec![lit("Proj"), lit("FileSystem"), lit(r"C:\x")]);
        c.name = var("c");
        c.typed = "$c".to_string();
        c.canonical = None;
        c
    };
    let defines_f = Stmt::Func {
        name: "f".to_string(),
        body: script(vec![stmt(
            lits("New-PSDrive", &["Proj", "FileSystem", r"C:\x"]),
            None,
        )]),
    };
    for (label, before) in [
        ("opaque", vec![stmt(opaque.clone(), seq)]),
        ("iex $x", vec![stmt(cmd("iex", vec![var("x")]), seq)]),
        ("& $f", vec![stmt(cmd("&", vec![var("f")]), seq)]),
        (". $f", vec![stmt(cmd(".", vec![var("f")]), seq)]),
        ("$c ...", vec![stmt(dynamic_name, seq)]),
        (
            "function f; f",
            vec![defines_f.clone(), stmt(lits("f", &[]), seq)],
        ),
        (
            "function f; & f",
            vec![defines_f, stmt(lits("&", &["f"]), seq)],
        ),
        (
            "Set-Alias g New-PSDrive; g",
            vec![
                stmt(lits("Set-Alias", &["g", "New-PSDrive"]), seq),
                stmt(lits("g", &["Proj", "FileSystem", r"C:\x"]), seq),
            ],
        ),
        ("icm $sb", vec![stmt(cmd("icm", vec![var("sb")]), seq)]),
        // Ruling 37: `&`/`.` read only a literal cmdlet name; a script runs unseen code.
        ("& ./x.ps1", vec![stmt(lits("&", &["./x.ps1"]), seq)]),
        (
            "& C:\\x\\run.ps1",
            vec![stmt(lits("&", &[r"C:\x\run.ps1"]), seq)],
        ),
        (". .\\x.ps1", vec![stmt(lits(".", &[r".\x.ps1"]), seq)]),
        (". m.psm1", vec![stmt(lits(".", &["m.psm1"]), seq)]),
        // Ruling 38: `&`/`.` run the name they are given, and every check reads that name.
        (
            "& Invoke-Expression $x",
            vec![stmt(
                cmd("&", vec![lit("Invoke-Expression"), var("x")]),
                seq,
            )],
        ),
        (
            "& Set-Alias Remove-Item",
            vec![stmt(lits("&", &["Set-Alias", "Remove-Item", "x"]), seq)],
        ),
        ("& $f", vec![stmt(cmd("&", vec![var("f")]), seq)]),
        // A name outside the plain-token shape: a drive-relative path, a colon, a script.
        ("C:x", vec![stmt(lits("C:x", &[]), seq)]),
        ("a:b", vec![stmt(lits("a:b", &[]), seq)]),
        ("& C:x", vec![stmt(lits("&", &["C:x"]), seq)]),
        (
            "& New-PSDrive",
            vec![stmt(
                lits("&", &["New-PSDrive", "Proj", "FileSystem", r"C:\x"]),
                seq,
            )],
        ),
        (
            "function Get-Thing; & Get-Thing",
            vec![
                Stmt::Func {
                    name: "Get-Thing".to_string(),
                    body: script(vec![git()]),
                },
                stmt(lits("&", &["Get-Thing"]), seq),
            ],
        ),
        (
            "Set-Alias G x; g",
            vec![
                stmt(lits("Set-Alias", &["G", "x"]), seq),
                stmt(lits("g", &[]), seq),
            ],
        ),
        // The same for a script called by its path.
        ("setup.ps1", vec![stmt(lits("setup.ps1", &[]), seq)]),
        (".\\x.ps1", vec![stmt(lits(r".\x.ps1", &[]), seq)]),
        ("m.psm1", vec![stmt(lits("m.psm1", &[]), seq)]),
        (
            "Set-Alias $n x",
            vec![stmt(cmd("Set-Alias", vec![var("n"), lit("x")]), seq)],
        ),
    ]
    .into_iter()
    .chain(
        [
            vec!["Set-Alias", "g", "New-PSDrive"],
            vec!["sal", "g", "New-PSDrive"],
            vec!["New-Alias", "g", "New-PSDrive"],
            vec!["nal", "g", "New-PSDrive"],
            vec!["Set-Alias", "-Scope", "Global", "g", "New-PSDrive"],
            vec!["Set-Item", "Function:g", "x"],
            vec!["si", "Function:g", "x"],
            vec!["New-Item", "Function:g", "-Value", "x"],
            vec!["ni", "Function:g", "-Value", "x"],
            vec!["Set-Item", r"Microsoft.PowerShell.Core\Function::g", "x"],
            vec!["Set-Item", "Alias:g", "x"],
            vec!["Set-Item", "Function::g", "x"],
            vec!["Set-Item", r"Function:\g", "x"],
            vec!["Set-Item", "FUNCTION:G", "x"],
            vec!["Set-Item", r"Function:\", "x"],
            vec!["Set-Item", "Function:g*", "x"],
        ]
        .into_iter()
        .map(|d| {
            (
                if d.contains(&"New-PSDrive") {
                    "defines g as New-PSDrive; g"
                } else {
                    "defines g; g"
                },
                vec![
                    stmt(lits(d[0], &d[1..]), seq),
                    stmt(
                        lits(if d[1] == "Function:g*" { "gx" } else { "g" }, &[]),
                        seq,
                    ),
                ],
            )
        }),
    )
    .collect::<Vec<_>>()
    {
        // Ruling 40/41: a remap in sight (an alias or a function body naming a remap command)
        // and a script run keep MayBeCritical; any other part not read as written leaves the
        // drive unproven, with the fact on the target.
        let unread = [
            "opaque",
            "$c ...",
            "icm $sb",
            "& Set-Alias Remove-Item",
            "C:x",
            "a:b",
            "function Get-Thing; & Get-Thing",
            "Set-Alias G x; g",
            "Set-Alias $n x",
            "defines g; g",
        ];
        let want = if unread.contains(&label) {
            unproven_unread("Proj")
        } else {
            MAY_BE_CRITICAL
        };
        let mut with_git = before.clone();
        with_git.push(git());
        expect(
            judge(with_git.clone(), ri(r"Proj:\y")),
            &want,
            &format!("{label}; git; Proj:\\y"),
        );
        expect(
            judge(with_git, ri("Function:x")),
            &MAY_BE_CRITICAL,
            &format!("{label}; git; Function:x"),
        );
    }
    // Each alias-definer spelling on its own, with a value that names no remap command: the
    // name it defines is a call the hook cannot read.
    for d in [
        vec!["sal", "g", "x"],
        vec!["New-Alias", "g", "x"],
        vec!["nal", "g", "x"],
        vec!["Set-Alias", "-Scope", "Global", "g", "x"],
    ] {
        expect(
            judge(
                vec![stmt(lits(d[0], &d[1..]), seq), stmt(lits("g", &[]), seq)],
                ri("Function:y"),
            ),
            &MAY_BE_CRITICAL,
            &format!("{}; g; Function:y", d.join(" ")),
        );
    }
    expect(
        judge(vec![git()], ri(r"Proj:\y")),
        &unproven("Proj"),
        "git; Proj:\\y (Ruling 36 control)",
    );
    // A literal operand and a plain command are read; a defined name not called is no call.
    let in_block = word_at(vec![WordPart::Block(Box::new(script(vec![git()])))], 0);
    for (label, before) in [
        ("& Get-Date", stmt(lits("&", &["Get-Date"]), seq)),
        ("wrapper alone", stmt(lits("command", &[]), seq)),
        // Ruling 38: one control per accepted shape of a plain token.
        ("& run", stmt(lits("&", &["run"]), seq)),
        (". Get-Date", stmt(lits(".", &["Get-Date"]), seq)),
        ("letters", stmt(lits("cargo", &["build"]), seq)),
        ("dot", stmt(lits("rm.exe", &["x"]), seq)),
        ("dash", stmt(lits("Get-Date", &[]), seq)),
        ("underscore and digits", stmt(lits("my_tool2", &[]), seq)),
        (
            "a loop",
            Stmt::Loop {
                body: script(vec![git()]),
                span: Span::default(),
            },
        ),
        (
            "function defined, not called",
            Stmt::Func {
                name: "g".to_string(),
                body: script(vec![git()]),
            },
        ),
        (
            "Set-Alias g; git",
            stmt(lits("Set-Alias", &["g", "x"]), seq),
        ),
        (
            "Set-Alias -Name g",
            stmt(lits("Set-Alias", &["-Name", "g", "x"]), seq),
        ),
        (
            "Set-Alias -N g",
            stmt(lits("Set-Alias", &["-N", "g", "x"]), seq),
        ),
        (
            "Set-Item Env:git",
            stmt(lits("Set-Item", &["Env:git", "x"]), seq),
        ),
        (
            "Invoke-Command { git }",
            stmt(cmd("Invoke-Command", vec![in_block]), seq),
        ),
    ] {
        expect(
            judge(vec![before, git()], ri(r"Proj:\y")),
            &unproven("Proj"),
            &format!("{label}; Proj:\\y"),
        );
    }
    // Ruling 36.2: after a remap `Function:` may be a file-system drive; a removed drive too.
    expect(
        judge(
            vec![stmt(
                lits("New-PSDrive", &["Function", "FileSystem", r"C:\x"]),
                seq,
            )],
            ri(r"Function:\y"),
        ),
        &MAY_BE_CRITICAL,
        "New-PSDrive Function; Function:\\y",
    );
    for remover in ["Remove-PSDrive", "rdr"] {
        expect(
            judge(vec![stmt(lits(remover, &["Env"]), seq)], ri("Env:FOO")),
            &MAY_BE_CRITICAL,
            &format!("{remover} Env; Env:FOO"),
        );
    }
    // I2: every other unknown form, reader and shell stays MayBeCritical.
    for (label, delete) in [
        ("UNC", ri(r"\\srv\share\x")),
        ("C:x", ri("C:x")),
        ("stream", ri("x::$INDEX_ALLOCATION")),
        ("Proj:x*", ri("Proj:x*")),
        ("rm.exe Proj:\\x", lits("rm.exe", &[r"Proj:\x"])),
        ("rm.exe Function:x", lits("rm.exe", &["Function:x"])),
    ] {
        expect(
            judge(vec![git()], delete),
            &MAY_BE_CRITICAL,
            &format!("git; {label}"),
        );
    }
    expect(
        judge_on(
            vec![git()],
            lits("rm", &["Proj:x"]),
            Shell::Bash(BashProfile::GitBash),
            &machine,
        ),
        &MAY_BE_CRITICAL,
        "Git Bash rm -rf Proj:x",
    );
    let mut net_loc = base.clone();
    net_loc.read_script(&script(vec![git()]));
    expect(
        sorted(target(
            &lit(r"Proj:\x"),
            &net_loc,
            &env,
            NATIVE,
            &machine,
            &far(),
        )),
        &MAY_BE_CRITICAL,
        "[IO.Directory]::Delete('Proj:\\x')",
    );
    expect(
        judge(vec![git()], ri(r"FileSystem::Proj:\x")),
        &unproven("Proj"),
        r"git; FileSystem::Proj:\x",
    );
    // A module-qualified provider name takes the provider form `::` only.
    expect(
        judge(vec![], ri(r"Microsoft.PowerShell.Core\Function:x")),
        &MAY_BE_CRITICAL,
        r"Microsoft.PowerShell.Core\Function:x",
    );
    for text in [
        r"FileSystem::C:\Profiles\u",
        r"Microsoft.PowerShell.Core\FileSystem::C:\Profiles\u",
    ] {
        expect(
            judge(vec![git()], ri(text)),
            &paths(&[r"C:\Profiles\u"]),
            &format!("git; {text}"),
        );
    }
    // Pins: a relative delete after `cd $x;` and after an unread command.
    expect(
        judge(vec![stmt(cmd("cd", vec![var("x")]), seq)], ri("build")),
        &MAY_BE_CRITICAL,
        "cd $x; build",
    );
    expect(
        judge(vec![stmt(opaque, seq)], ri("build")),
        &MAY_BE_CRITICAL,
        "unread; build",
    );
    // Ruling 38: a script run by `&` and a source by `.` may move the shell; Ruling 39: `.` of a
    // cmdlet is `&` of it.
    for (label, before) in [
        ("& ./x.ps1", stmt(lits("&", &["./x.ps1"]), seq)),
        (". x", stmt(lits(".", &["x"]), seq)),
    ] {
        expect(
            judge(vec![before], lits("Remove-Item", &["-Recurse", "build"])),
            &MAY_BE_CRITICAL,
            &format!("{label}; -Recurse build"),
        );
    }
    expect(
        judge(vec![stmt(lits(".", &["Get-Date"]), seq)], ri("build")),
        &paths(&[r"C:\w\repo\build"]),
        ". Get-Date; build",
    );
    // Ruling 39: a source is never harmless and never read, unless it names a cmdlet.
    let dot_x = || stmt(lits(".", &["x"]), seq);
    expect(
        judge(vec![dot_x()], ri(r"Proj:\y")),
        &MAY_BE_CRITICAL,
        ". x; Proj:\\y",
    );
    expect(
        judge(vec![dot_x()], ri("Env:FOO")),
        &MAY_BE_CRITICAL,
        ". x; Env:FOO",
    );
    // Not a `Verb-Noun` cmdlet name: a script name.
    for name in ["-Date", "Get-", "Get1-Date", "Get-a.b"] {
        expect(
            judge(vec![stmt(lits(".", &[name]), seq)], ri(r"Proj:\y")),
            &MAY_BE_CRITICAL,
            &format!(". {name}; Proj:\\y"),
        );
    }
    expect(
        judge(vec![stmt(lits(".", &["Get-Date"]), seq)], ri("Env:FOO")),
        &Target::NotAFile,
        ". Get-Date; Env:FOO",
    );
    // `&` of a plain name that may be a script on PATH: read (Ruling 38), never harmless.
    expect(
        judge(vec![stmt(lits("&", &["x"]), seq)], ri("Env:FOO")),
        &unproven("Env"),
        "& x; Env:FOO",
    );
    expect(
        judge(vec![stmt(lits("&", &["Get-Date"]), seq)], ri("Env:FOO")),
        &Target::NotAFile,
        "& Get-Date; Env:FOO",
    );
    // I3 + Ruling 35: a command definition, or a variable that may be the shim's.
    for text in [
        "Function:x",
        r"Function:\x",
        "Function:/x",
        r"function:\__SW_T",
        "Function::x",
        r"Microsoft.PowerShell.Core\Function::x",
        "Alias:x",
        r"ALIAS:\x",
        "Alias::x",
        r"microsoft.powershell.core\alias::x",
        "Variable:__sw_File",
        r"VARIABLE:\__SW_FILE",
        "Variable:/__sw_File",
        "Variable::__sw_File",
        r"Microsoft.PowerShell.Core\Variable::__sw_File",
        "Variable:__s*",
        "Variable:__sw_?ile",
        "Variable:?_sw_File",
        "Variable:[_]_sw_File",
        // `-Include __sw*` widens any wildcard and the root (step0-varfilter.log).
        "Variable:fo*",
        r"Variable:\_*",
        r"Variable:\",
        r"Variable:\*",
        "Variable:",
    ] {
        expect(judge(vec![], ri(text)), &Target::SessionCommand, text);
        expect(
            judge(vec![git()], ri(text)),
            &Target::SessionCommand,
            &format!("git; {text}"),
        );
    }
    // Ruling 34: a letter drive that does not exist when the hook runs, in a command not proven
    // harmless; I8's drive-making method forms.
    let drive_new = || method("ExecutionContext.SessionState.Drive", "New", vec![lit("x")]);
    let invoke = || {
        method(
            "ExecutionContext.InvokeCommand",
            "InvokeScript",
            vec![lit(r"New-PSDrive Z FileSystem C:\Profiles -Scope Global")],
        )
    };
    for (label, before) in [
        ("git", git()),
        ("Drive.New", drive_new()),
        ("InvokeScript", invoke()),
    ] {
        expect(
            judge(vec![before.clone()], ri(r"Z:\u")),
            &MAY_BE_CRITICAL,
            &format!("{label}; Z:\\u"),
        );
        // `git` is read as written; `Drive.New` is a remap in sight (I5); any other method call
        // is unread code, a fact on the target (Ruling 40).
        let want = match label {
            "git" => unproven("Proj"),
            "Drive.New" => MAY_BE_CRITICAL,
            _ => unproven_unread("Proj"),
        };
        expect(
            judge(vec![before.clone()], ri(r"Proj:\u")),
            &want,
            &format!("{label}; Proj:\\u"),
        );
        let want = if label == "git" {
            Target::SessionCommand
        } else {
            MAY_BE_CRITICAL
        };
        expect(
            judge(vec![before], ri(r"Function:\y")),
            &want,
            &format!("{label}; Function:\\y"),
        );
    }
    expect(
        judge(vec![git(), stmt(lits("cd", &[r"Z:\u"]), seq)], ri("x")),
        &MAY_BE_CRITICAL,
        "git; cd Z:\\u; x",
    );
    expect(
        judge(vec![], ri(r"Z:\u")),
        &paths(&[r"Z:\u"]),
        "missing drive, harmless",
    );
    expect(
        judge(vec![git()], ri(r"D:\elsewhere")),
        &paths(&[r"D:\elsewhere"]),
        "git; existing drive",
    );
    expect(
        judge_on(
            vec![git()],
            lits("rm", &[r"Z:\u"]),
            Shell::Bash(BashProfile::GitBash),
            &machine,
        ),
        &paths(&[r"Z:\u"]),
        "Git Bash git; Z:\\u (pwsh only)",
    );
    // A drive root the hook cannot read is not proven to exist.
    expect(
        judge_on(
            vec![git()],
            ri(r"Z:\u"),
            Shell::Pwsh,
            &(Arc::new(RootDenied) as SharedFs),
        ),
        &MAY_BE_CRITICAL,
        "drive root unreadable",
    );
    let hang: SharedFs = Arc::new(Hang("lstat"));
    let mut hang_loc = base.clone();
    hang_loc.read_script(&script(vec![git()]));
    let by = delete_by(&ri(r"Z:\u"), Shell::Pwsh, Os::Windows);
    let start = Instant::now();
    let got = target(
        &lit(r"Z:\u"),
        &hang_loc,
        &env,
        by,
        &hang,
        &Deadline::new(start, 300),
    );
    expect(got, &Target::Timeout, "drive query never returns");
    assert!(start.elapsed() < Duration::from_secs(5), "bounded");
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn pwsh_on_posix_reads_a_drive_path_as_powershell_does() {
    let seq = Some(ChainOp::Seq);
    let fs = FakeFs::default().dir("/h/u").dir("/w/repo").shared();
    // `<before>; <delete>` on POSIX (cwd /w/repo, home /h/u), the whole command read first;
    // `word` is the delete's last argument.
    let judge = |shell: Shell, before: Vec<Stmt>, delete: SimpleCommand| {
        let env = env_view(shell, Os::Posix, [("HOME".to_string(), "/h/u".to_string())]);
        let by = delete_by(&delete, shell, Os::Posix);
        let word = delete.args.last().expect("a target").clone();
        let mut all = before.clone();
        all.push(stmt(delete, seq));
        let mut loc = Location::new(shell, Os::Posix, Some(Path::new("/w/repo")));
        loc.read_script(&script(all));
        after_all(&mut loc, &script(before), &env);
        sorted(target(&word, &loc, &env, by, &fs, &far()))
    };
    let ps = Shell::Pwsh;
    let st = |c: SimpleCommand| stmt(c, seq);
    let git = || st(lits("git", &["status"]));
    let ri = |text: &str| lits("Remove-Item", &[text]);
    let rr = |text: &str| lits("Remove-Item", &["-Recurse", "-Force", text]);
    let to_home = |name: &str| st(lits("New-PSDrive", &[name, "FileSystem", "/h/u"]));
    let rows: Vec<(&str, Shell, Vec<Stmt>, SimpleCommand, Target)> = vec![
        // pwsh on POSIX has no letter drives, but any `name:` is a PSDrive.
        (
            "New-PSDrive Proj /h/u; Proj:/",
            ps,
            vec![to_home("Proj")],
            rr("Proj:/"),
            MAY_BE_CRITICAL,
        ),
        (
            "git; Proj:/y",
            ps,
            vec![git()],
            ri("Proj:/y"),
            unproven("Proj"),
        ),
        ("git; X:/y", ps, vec![git()], ri("X:/y"), unproven("X")),
        (
            "git; Proj:../x",
            ps,
            vec![git()],
            ri("Proj:../x"),
            MAY_BE_CRITICAL,
        ),
        // `Temp:` has no shortcut on POSIX: a remap of it is one in sight.
        (
            "git; Temp:/x",
            ps,
            vec![git()],
            ri("Temp:/x"),
            unproven("Temp"),
        ),
        (
            "Remove-PSDrive Temp; New-PSDrive Temp /h/u; Temp:/",
            ps,
            vec![st(lits("Remove-PSDrive", &["Temp"])), to_home("Temp")],
            rr("Temp:/"),
            MAY_BE_CRITICAL,
        ),
        // Set-Location reads its path through the provider.
        (
            "New-PSDrive Proj /h/u; cd Proj:/; x",
            ps,
            vec![to_home("Proj"), st(lits("Set-Location", &["Proj:/"]))],
            rr("x"),
            MAY_BE_CRITICAL,
        ),
        // Controls: a built-in drive in a harmless command; a native program gets the literal
        // text (fix6\probe-native.log); a `:` after a folder is no drive; bash has no drives.
        ("Env:FOO alone", ps, vec![], ri("Env:FOO"), Target::NotAFile),
        (
            "rm foo:bar (native)",
            ps,
            vec![git()],
            lits("rm", &["-rf", "foo:bar"]),
            paths(&["/w/repo/foo:bar"]),
        ),
        (
            "git; a/b:c",
            ps,
            vec![git()],
            ri("a/b:c"),
            paths(&["/w/repo/a/b:c"]),
        ),
        // pwsh reads `:x` as a relative item (fix6\probe: ItemNotFound, not DriveNotFound).
        ("git; :x", ps, vec![git()], ri(":x"), paths(&["/w/repo/:x"])),
        // A wildcard in the drive's own component: the drive is still read first.
        (
            "New-PSDrive Proj /h/u; Proj:*",
            ps,
            vec![to_home("Proj")],
            rr("Proj:*"),
            MAY_BE_CRITICAL,
        ),
        (
            "git; Proj:x*",
            ps,
            vec![git()],
            ri("Proj:x*"),
            MAY_BE_CRITICAL,
        ),
        (
            "git; module-qualified FileSystem::Proj:x*",
            ps,
            vec![git()],
            ri(r"Microsoft.PowerShell.Core\FileSystem::Proj:x*"),
            MAY_BE_CRITICAL,
        ),
        (
            "rm -rf a:b* (native glob)",
            ps,
            vec![git()],
            lits("rm", &["-rf", "a:b*"]),
            paths(&[]),
        ),
        (
            "bash rm -rf Proj:/x",
            Shell::Bash(BashProfile::Posix),
            vec![git()],
            lits("rm", &["-rf", "Proj:/x"]),
            paths(&["/w/repo/Proj:/x"]),
        ),
    ];
    let bad: Vec<String> = rows
        .into_iter()
        .filter_map(|(label, shell, before, delete, want)| {
            let got = judge(shell, before, delete);
            (got != want).then(|| format!("{label}: got {got:?}, want {want:?}"))
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// A named-drive delete in a command where some part is not read as written.
fn unproven_unread(drive: &str) -> Target {
    Target::DriveUnproven {
        drive: drive.to_string(),
        unread_before: true,
    }
}

/// Ruling 40/41: unread code is a fact on the target (`unread_before`), a remap or a script run in
/// sight keeps MayBeCritical, and a letter path keeps its level when its drive exists.
#[test]
fn unread_code_is_a_fact_and_a_script_run_counts_as_a_remap_in_sight() {
    let seq = Some(ChainOp::Seq);
    // Drives C: and D: exist on this machine, Q: and X: do not.
    let machine = FakeFs::default()
        .dir(r"C:\Profiles\u")
        .dir(r"C:\w\repo\build")
        .dir(r"D:\elsewhere")
        .shared();
    let mut bad: Vec<String> = Vec::new();
    // `<before>; <delete>; <after>`, the whole command read first; `word` is the delete's last
    // argument.
    let judge = |before: Vec<Stmt>, delete: SimpleCommand, after: Vec<Stmt>, shell: Shell| {
        let (base, env) = win(shell);
        let by = delete_by(&delete, shell, Os::Windows);
        let word = delete.args.last().expect("a target").clone();
        let mut all = before.clone();
        all.push(stmt(delete, seq));
        all.extend(after);
        let mut loc = base.clone();
        loc.read_script(&script(all));
        after_all(&mut loc, &script(before), &env);
        sorted(target(&word, &loc, &env, by, &machine, &far()))
    };
    let ri = |text: &str| lits("Remove-Item", &[text]);
    let rr = |text: &str| lits("Remove-Item", &["-Recurse", text]);
    let st = |c: SimpleCommand| stmt(c, seq);
    let git = || st(lits("git", &["status"]));
    let iex = || st(cmd("iex", vec![var("x")]));
    let amp_f = || st(cmd("&", vec![var("f")]));
    let exists = || method("IO.File", "Exists", vec![lit("x")]);
    let block = |stmts: Vec<Stmt>| word_at(vec![WordPart::Block(Box::new(script(stmts)))], 0);
    let piped = |head: SimpleCommand, tail: SimpleCommand| {
        Stmt::Pipeline(Pipeline {
            elems: vec![Elem::Cmd(head), Elem::Cmd(tail)],
            chain: seq,
        })
    };
    let mixed = |head: &str, name: &str| {
        let mut w = word_at(
            vec![
                WordPart::Literal(head.to_string()),
                WordPart::Var(name.to_string()),
            ],
            0,
        );
        w.quote = Quote::Double;
        w
    };
    let mut opaque = lits("x", &[]);
    opaque.opaque = true;
    let pwsh = Shell::Pwsh;
    let proj = r"Proj:\y";
    /// Label, statements before the delete, the delete, statements after it, shell, result.
    type Row<'a> = (&'a str, Vec<Stmt>, SimpleCommand, Vec<Stmt>, Shell, Target);
    let rows: Vec<Row> = vec![
        // Plan rows 1-11 with the amendments.
        (
            "iex; Proj",
            vec![iex()],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "New-PSDrive; Proj",
            vec![st(lits("New-PSDrive", &["Proj", "FileSystem", r"C:\x"]))],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "& $f; existing letter",
            vec![amp_f()],
            rr(r"C:\w\repo\build"),
            vec![],
            pwsh,
            paths(&[r"C:\w\repo\build"]),
        ),
        (
            "& $f; missing letter",
            vec![amp_f()],
            rr(r"Q:\x"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "& $f; relative",
            vec![amp_f()],
            rr("build"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "Set-Content Function:x; Proj",
            vec![st(lits("Set-Content", &["Function:x", "rm x"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "ForEach-Object $sb; Proj",
            vec![st(cmd("ForEach-Object", vec![var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "gci | ForEach-Object { Get-Date }; Proj",
            vec![piped(
                lits("Get-ChildItem", &[]),
                cmd(
                    "ForEach-Object",
                    vec![block(vec![st(lits("Get-Date", &[]))])],
                ),
            )],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            "gci | ForEach-Object { iex $x }; Proj",
            vec![piped(
                lits("Get-ChildItem", &[]),
                cmd("ForEach-Object", vec![block(vec![iex()])]),
            )],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "git; Proj",
            vec![git()],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            ". x; Env:FOO",
            vec![st(lits(".", &["x"]))],
            ri("Env:FOO"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        // M3: unread code anywhere in the command, after the delete too.
        (
            "Proj; [IO.File]::Exists",
            vec![],
            ri(proj),
            vec![exists()],
            pwsh,
            unproven_unread("Proj"),
        ),
        // The unread kinds: a method call, an expression, an opaque name, Start-Process, a
        // cmdlet the shell does not ship.
        (
            "[IO.File]::Exists; Proj",
            vec![exists()],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "expression; Proj",
            vec![Stmt::Pipeline(Pipeline {
                elems: vec![Elem::Expr(lit("$ExecutionContext.SessionState"))],
                chain: seq,
            })],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "opaque; Proj",
            vec![st(opaque.clone())],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "Start-Process; Proj",
            vec![st(lits("Start-Process", &["x"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "Get-Thing; Proj",
            vec![st(lits("Get-Thing", &["x"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "docker-compose; Proj",
            vec![st(lits("docker-compose", &["up"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        // I2: a block from a variable, in every spelling of the block parameter.
        (
            "foreach $sb; Proj",
            vec![st(cmd("foreach", vec![var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "% $sb; Proj",
            vec![st(cmd("%", vec![var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "ForEach-Object -Pr $sb; Proj",
            vec![st(cmd("ForEach-Object", vec![lit("-Pr"), var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "ForEach-Object -Process:$sb; Proj",
            vec![st(cmd("ForEach-Object", vec![mixed("-Process:", "sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "Where-Object $sb; Proj",
            vec![st(cmd("Where-Object", vec![var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "? $sb; Proj",
            vec![st(cmd("?", vec![var("sb")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "icm -ScriptBlock $sb; Proj",
            vec![st(cmd(
                "Invoke-Command",
                vec![lit("-ScriptBlock"), var("sb")],
            ))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "5.1 ForEach-Object $sb; Proj",
            vec![st(cmd("ForEach-Object", vec![var("sb")]))],
            ri(proj),
            vec![],
            Shell::Powershell5,
            unproven_unread("Proj"),
        ),
        // Each shell reads its own table: 5.1 ships no `Get-Error`.
        (
            "Get-Error; Proj",
            vec![st(lits("Get-Error", &[]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            "5.1 Get-Error; Proj",
            vec![st(lits("Get-Error", &[]))],
            ri(proj),
            vec![],
            Shell::Powershell5,
            unproven_unread("Proj"),
        ),
        // 5.1 follows the pwsh rules for remaps and links.
        (
            "5.1 & $f; existing letter",
            vec![amp_f()],
            rr(r"C:\w\repo\build"),
            vec![],
            Shell::Powershell5,
            paths(&[r"C:\w\repo\build"]),
        ),
        // Literal controls: literal words and literal blocks are read, through an alias too.
        (
            "% { Get-Date }; Proj",
            vec![st(cmd("%", vec![block(vec![st(lits("Get-Date", &[]))])]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            "ForEach-Object -Process { Get-Date }; Proj",
            vec![st(cmd(
                "ForEach-Object",
                vec![lit("-Process"), block(vec![st(lits("Get-Date", &[]))])],
            ))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            "Where-Object Name -eq x; Proj",
            vec![st(lits("Where-Object", &["Name", "-eq", "x"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        (
            "Sort-Object -Property $p; Proj (stated limit)",
            vec![st(cmd("Sort-Object", vec![lit("-Property"), var("p")]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        // D6: `&` of a plain token reads as the bare command.
        (
            "& git status; Proj",
            vec![st(lits("&", &["git", "status"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        // I4: one rule for every in-shell script run, and Start-Process keeps its links.
        (
            "& $f; Proj",
            vec![amp_f()],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "Start-Process; existing letter",
            vec![st(lits("Start-Process", &["x"]))],
            rr(r"C:\w\repo\build"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "iex; existing letter",
            vec![iex()],
            rr(r"C:\w\repo\build"),
            vec![],
            pwsh,
            paths(&[r"C:\w\repo\build"]),
        ),
        (
            "iex; New-PSDrive; Proj",
            vec![
                iex(),
                st(lits("New-PSDrive", &["Proj", "FileSystem", r"C:\x"])),
            ],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        // I5: a remap in sight that names no remap command.
        (
            "Drive.New; existing letter",
            vec![method(
                "ExecutionContext.SessionState.Drive",
                "New",
                vec![lit("x")],
            )],
            rr(r"C:\w\repo\build"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "Set-Alias mk New-PSDrive; mk; Proj",
            vec![
                st(lits("Set-Alias", &["mk", "New-PSDrive"])),
                st(lits("mk", &["Proj", "FileSystem", r"C:\Profiles\u"])),
            ],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        // I10: a script the command loads.
        (
            ". .\\setup.ps1; Proj",
            vec![st(lits(".", &[r".\setup.ps1"]))],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "Import-Module .\\m.psm1; Proj",
            vec![st(lits("Import-Module", &[r".\m.psm1"]))],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        (
            "setup.ps1; Proj",
            vec![st(lits("setup.ps1", &[]))],
            ri(proj),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        // M4: a location on an unproven drive stays MayBeCritical.
        (
            "[IO.File]::Exists; cd Proj:\\; -Recurse .",
            vec![exists(), st(lits("cd", &[r"Proj:\"]))],
            rr("."),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
        // I8: a command given a `Function:`/`Alias:` path may define a command there.
        (
            "Copy-Item Function:a Function:b; Proj",
            vec![st(lits("Copy-Item", &["Function:a", "Function:b"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "Set-Content \"Function:$n\"; Proj",
            vec![st(cmd(
                "Set-Content",
                vec![mixed("Function:", "n"), lit("x")],
            ))],
            ri(proj),
            vec![],
            pwsh,
            unproven_unread("Proj"),
        ),
        (
            "Set-Content x.txt; Proj (control)",
            vec![st(lits("Set-Content", &["x.txt", "y"]))],
            ri(proj),
            vec![],
            pwsh,
            unproven("Proj"),
        ),
        // D2: readers and the delete family name a command path without defining one.
        (
            "Remove-Item Function:f",
            vec![],
            ri("Function:f"),
            vec![],
            pwsh,
            Target::SessionCommand,
        ),
        (
            "Get-ChildItem Function:; Function:f",
            vec![st(lits("Get-ChildItem", &["Function:"]))],
            ri("Function:f"),
            vec![],
            pwsh,
            Target::SessionCommand,
        ),
        (
            "gci Function:; Function:f",
            vec![st(lits("gci", &["Function:"]))],
            ri("Function:f"),
            vec![],
            pwsh,
            Target::SessionCommand,
        ),
        (
            "Test-Path Alias:x; Function:f",
            vec![st(lits("Test-Path", &["Alias:x"]))],
            ri("Function:f"),
            vec![],
            pwsh,
            Target::SessionCommand,
        ),
        (
            "ri Function:g; Function:f",
            vec![st(lits("ri", &["Function:g"]))],
            ri("Function:f"),
            vec![],
            pwsh,
            Target::SessionCommand,
        ),
        (
            "Set-Content Function:g; Function:f",
            vec![st(lits("Set-Content", &["Function:g", "x"]))],
            ri("Function:f"),
            vec![],
            pwsh,
            MAY_BE_CRITICAL,
        ),
    ];
    // I8: one row per spelling of a command path.
    let spellings = [
        "Function:x",
        "function::x",
        r"Function:\x",
        "Function:/x",
        r"Microsoft.PowerShell.Core\Function::x",
        "Alias:x",
        "-Path:Function:x",
    ];
    let spelled = spellings.iter().map(|s| {
        (
            *s,
            vec![st(lits("Set-Content", &[s, "x"]))],
            ri(proj),
            Vec::new(),
            pwsh,
            unproven_unread("Proj"),
        )
    });
    for (label, before, delete, after, shell, want) in rows.into_iter().chain(spelled) {
        let got = judge(before, delete, after, shell);
        if got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    }
    // Git Bash keeps every unread command a possible remap (Ruling 34 is pwsh-only).
    let bash = Shell::Bash(BashProfile::GitBash);
    let mut dyn_name = cmd("", vec![lit("X:"), lit("/c/Profiles/u")]);
    dyn_name.name = var("c");
    dyn_name.typed = "$c".to_string();
    dyn_name.canonical = None;
    dyn_name.opaque = true;
    for (label, before) in [
        ("Git Bash $c X: …; rm -rf X:/u", st(dyn_name)),
        (
            "Git Bash env -S subst; rm -rf X:/u",
            st(lits("env", &["-S", "subst X: /c/Profiles/u"])),
        ),
    ] {
        let got = judge(vec![before], lits("rm", &["-rf", "X:/u"]), vec![], bash);
        if got != MAY_BE_CRITICAL {
            bad.push(format!("{label}: got {got:?}, want {MAY_BE_CRITICAL:?}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// `lstat` is refused on every path (the default `drive_exists` reads the root).
struct RootDenied;

impl Fs for RootDenied {
    fn lstat(&self, _p: &Path) -> io::Result<Meta> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
    fn read_dir(&self, _p: &Path) -> io::Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }
    fn link_target(&self, _p: &Path) -> io::Result<Option<PathBuf>> {
        Ok(None)
    }
}

/// The real drive query against the system's own drive list: the system drive exists, a letter
/// `GetLogicalDrives` does not list does not; on POSIX no letter drive does.
#[test]
fn real_fs_reports_whether_a_drive_exists() {
    #[cfg(windows)]
    {
        let sys = std::env::var("SystemDrive").expect("SystemDrive is set");
        let letter = sys.chars().next().expect("a letter");
        assert!(RealFs.drive_exists(letter).expect("readable"), "{sys}");
        // SAFETY: GetLogicalDrives takes no arguments and only returns a bit mask.
        let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
        let free = (b'A'..=b'Z')
            .rev()
            .find(|l| mask & (1 << (l - b'A')) == 0)
            .expect("a free letter") as char;
        assert!(!RealFs.drive_exists(free).expect("readable"), "{free}:");
    }
    #[cfg(not(windows))]
    assert!(!RealFs.drive_exists('C').expect("readable"));
}

/// The oracle for the generated cmdlet table: each shell's `-NoProfile` answer to
/// `(Get-Command <name>).Parameters.Values | Where-Object ParameterType -in [scriptblock],
/// [scriptblock[]]` (the ScriptBlock-typed parameters, after `|`), and `Get-Alias` for an alias
/// (after `=>`).
const CMDLET_ORACLE: &str = "\
Pwsh ForEach-Object|Begin,End,Parallel,Process,RemainingScripts
Pwsh Where-Object|FilterScript
Pwsh Start-Job|InitializationScript,ScriptBlock
Pwsh Invoke-Expression|
Pwsh Sort-Object|
Pwsh Set-Content|
Pwsh %=>ForEach-Object
Pwsh ?=>Where-Object
Pwsh iex=>Invoke-Expression
Powershell5 ForEach-Object|Begin,End,Process,RemainingScripts
Powershell5 Where-Object|FilterScript
Powershell5 Start-Job|InitializationScript,ScriptBlock
Powershell5 Invoke-Expression|
Powershell5 Sort-Object|
Powershell5 Set-Content|
Powershell5 %=>ForEach-Object
Powershell5 ?=>Where-Object
Powershell5 iex=>Invoke-Expression
";

#[test]
fn the_cmdlet_table_matches_get_command() {
    let mut bad = Vec::new();
    let mut rows = 0;
    for line in CMDLET_ORACLE.lines() {
        let (shell, rest) = line.split_once(' ').expect("shell and row");
        let shell = match shell {
            "Pwsh" => Shell::Pwsh,
            _ => Shell::Powershell5,
        };
        let (name, want) = match rest.split_once("=>") {
            // An alias answers as the command it names.
            Some((alias, target)) => (alias, shipped_command(shell, target)),
            None => {
                let (name, blocks) = rest.split_once('|').expect("name|params");
                (name, Some(!blocks.is_empty()))
            }
        };
        rows += 1;
        let got = shipped_command(shell, name);
        if got != want || got.is_none() {
            bad.push(format!("{line}: got {got:?}, want {want:?}"));
        }
    }
    // A cmdlet neither shell ships, and a native program.
    for name in ["Get-Thing", "git"] {
        for shell in [Shell::Pwsh, Shell::Powershell5] {
            if shipped_command(shell, name).is_some() {
                bad.push(format!("{name} {shell:?}: shipped"));
            }
        }
    }
    assert_eq!(rows, 18, "oracle rows read");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn pwsh_param_binds_a_written_name_as_powershell_does() {
    use ParamMatch::{Ambiguous, Exact, Unknown};
    // Expected values: pwsh 7.7 `StaticParameterBinder::BindCommand` on `<cmdlet> <name> x`.
    let cases: &[(&str, &str, ParamMatch)] = &[
        ("New-Item", "-Ty", Exact("ItemType")),
        ("New-Item", "-Typ", Exact("ItemType")),
        ("New-Item", "-it", Exact("ItemType")),
        ("New-Item", "-ItemType:Junction", Exact("ItemType")),
        ("New-Item", "-type", Exact("ItemType")),
        ("New-Item", "-i", Exact("ItemType")),
        ("ni", "-I", Exact("ItemType")),
        ("New-Item", "-t", Ambiguous),
        ("New-Item", "-v", Exact("Value")),
        ("New-Item", "-Target", Exact("Value")),
        ("New-Item", "-n", Exact("Name")),
        ("New-Item", "-f", Exact("Force")),
        ("New-Item", "-c", Exact("Credential")),
        ("New-Item", "-w", Ambiguous),
        ("New-Item", "-wi", Exact("WhatIf")),
        ("New-Item", "-e", Ambiguous),
        // An alias that is also a prefix of another parameter (WarningVariable).
        ("New-Item", "-wa", Exact("WarningAction")),
        ("New-Item", "-p", Exact("Path")),
        ("New-Item", "-o", Ambiguous),
        ("New-Item", "-pr", Exact("ProgressAction")),
        ("New-Item", "-in", Ambiguous),
        ("New-Item", "-Bogus", Unknown),
        ("New-Item", "\u{2014}Ty", Exact("ItemType")),
        ("Set-Location", "-P", Ambiguous),
        ("Set-Location", "-Pa", Ambiguous),
        ("Set-Location", "-Pat", Exact("Path")),
        ("Set-Location", "-L", Exact("LiteralPath")),
        ("Set-Location", "-PSP", Exact("LiteralPath")),
        ("sl", "-lp:x", Exact("LiteralPath")),
        ("Set-Location", "-S", Exact("StackName")),
        ("cd", "-pas", Exact("PassThru")),
        ("Set-Location", "-o", Ambiguous),
        ("Set-Location", "-pr", Exact("ProgressAction")),
        // Set-Location has no -WhatIf.
        ("Set-Location", "-wi", Unknown),
        ("Push-Location", "-S", Exact("StackName")),
        ("pushd", "-P", Ambiguous),
        // Not a parameter, or a cmdlet the hook does not model.
        ("New-Item", "-5", Unknown),
        ("New-Item", "-", Unknown),
        ("New-Item", "x", Unknown),
        ("Remove-Item", "-Recurse", Unknown),
    ];
    let bad: Vec<String> = cases
        .iter()
        .filter_map(|(cmdlet, written, want)| {
            let got = pwsh_param(cmdlet, written);
            (got != *want).then(|| format!("{cmdlet} {written}: got {got:?}, want {want:?}"))
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

// ---------------------------------------------------------------- location

fn after_all(loc: &mut Location, s: &Script, env: &EnvView) {
    for st in &s.stmts {
        loc.after(st, env);
    }
}

#[test]
fn cd_moves_the_location_and_a_cd_that_may_fail_keeps_the_old_one() {
    let (base, env) = win(Shell::Pwsh);
    let up = lit(r"..\..");
    let run = |stmts: Vec<Stmt>| {
        let mut loc = base.clone();
        after_all(&mut loc, &script(stmts), &env);
        resolve(&up, &loc, &env)
    };
    // `cd sub; rm -rf ..\..`: the cd may fail, so both folders are candidates.
    assert_eq!(
        run(vec![stmt(lits("cd", &["sub"]), Some(ChainOp::Seq))]),
        paths(&[r"C:\", r"C:\w"])
    );
    // `cd sub && rm -rf ..\..`
    assert_eq!(
        run(vec![stmt(
            lits("Set-Location", &["sub"]),
            Some(ChainOp::And)
        )]),
        paths(&[r"C:\w"])
    );
    // `cd sub && echo || rm -rf ..\..`: the || branch runs when the cd failed.
    assert_eq!(
        run(vec![
            stmt(lits("cd", &["sub"]), Some(ChainOp::And)),
            stmt(lits("echo", &[]), Some(ChainOp::Or)),
        ]),
        paths(&[r"C:\", r"C:\w"])
    );
    // `echo || cd sub && rm -rf ..\..`: the cd is skipped when echo succeeds.
    assert_eq!(
        run(vec![
            stmt(lits("echo", &[]), Some(ChainOp::Or)),
            stmt(lits("cd", &["sub"]), Some(ChainOp::And)),
        ]),
        paths(&[r"C:\", r"C:\w"])
    );
    // `cd sub && cd x && rm ..\..`
    assert_eq!(
        run(vec![
            stmt(lits("cd", &["sub"]), Some(ChainOp::And)),
            stmt(lits("cd", &["x"]), Some(ChainOp::And)),
        ]),
        paths(&[r"C:\w\repo"])
    );
    // A cd in a pipeline may or may not change the location.
    assert_eq!(
        run(vec![Stmt::Pipeline(Pipeline {
            elems: vec![
                Elem::Cmd(lits("cd", &["sub"])),
                Elem::Cmd(lits("echo", &[]))
            ],
            chain: Some(ChainOp::And),
        })]),
        paths(&[r"C:\", r"C:\w"])
    );
    // Absolute and parameter forms.
    let bad = [
        &[r"C:\a\b\c"][..],
        &["-LiteralPath", r"C:\a\b\c"],
        &["-Path:C:\\a\\b\\c"],
        &["-PassThru", "-Path", r"C:\a\b\c"],
        // Bound as pwsh 7.7's StaticParameterBinder binds them.
        &["-L", r"C:\a\b\c"],
        &["-PSP", r"C:\a\b\c"],
        &["-pat", r"C:\a\b\c"],
        &["-pas", r"C:\a\b\c"],
        &["-Path:", r"C:\a\b\c"],
        &["\u{2013}Path", r"C:\a\b\c"],
        // `-LiteralPath` reads no wildcard.
        &[r"-LiteralPath:C:\a\b\c*"],
    ]
    .iter()
    .filter_map(|args| {
        let got = run(vec![stmt(lits("Set-Location", args), Some(ChainOp::And))]);
        (got != paths(&[r"C:\a"])).then(|| format!("{args:?}: got {got:?}"))
    })
    .collect::<Vec<_>>();
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn a_location_change_the_check_cannot_follow_makes_the_location_unknown() {
    let (base, env) = win(Shell::Pwsh);
    let rel = lit("y");
    let abs = lit(r"C:\abs");
    let unknown_as = |want: Target, stmts: Vec<Stmt>| {
        let mut loc = base.clone();
        after_all(&mut loc, &script(stmts), &env);
        assert_eq!(resolve(&rel, &loc, &env), want);
        assert_eq!(resolve(&abs, &loc, &env), paths(&[r"C:\abs"]));
    };
    let unknown_after = |stmts: Vec<Stmt>| unknown_as(MAY_BE_CRITICAL, stmts);
    let seq = Some(ChainOp::Seq);
    // A folder a variable chose is as dynamic as the variable (`cd $x && …`).
    let and = Some(ChainOp::And);
    unknown_as(DYNAMIC_LOCATION, vec![stmt(cmd("cd", vec![var("x")]), and)]);
    let mut opaque = lits("x", &[]);
    opaque.opaque = true;
    unknown_as(DYNAMIC_LOCATION, vec![stmt(opaque.clone(), and)]);
    // `cd $x; …`: the cd may fail and leave the known folder, whose targets may be critical.
    unknown_after(vec![stmt(cmd("cd", vec![var("x")]), seq)]);
    unknown_after(vec![stmt(opaque, seq)]);
    // Where both apply, the location may be critical: `cd $x && cd sub* | cd a && …`.
    unknown_after(vec![
        stmt(cmd("cd", vec![var("x")]), and),
        Stmt::Pipeline(Pipeline {
            elems: vec![
                Elem::Cmd(lits("cd", &["sub*"])),
                Elem::Cmd(lits("cd", &["a"])),
            ],
            chain: and,
        }),
    ]);
    unknown_after(vec![stmt(lits("cd", &["-"]), seq)]);
    unknown_after(vec![stmt(lits("Set-Location", &[]), seq)]);
    unknown_after(vec![stmt(lits("cd", &["C:x"]), seq)]);
    unknown_after(vec![stmt(lits("cd", &["sub*"]), seq)]);
    unknown_after(vec![stmt(lits("Set-Location", &["-Path:sub*"]), seq)]);
    unknown_after(vec![stmt(lits("Invoke-Expression", &["cd sub"]), seq)]);
    unknown_after(vec![stmt(lits("cd", &["HKCU:\\x"]), seq)]);
    unknown_after(vec![stmt(lits("Set-Location", &["-Bogus", "x"]), seq)]);
    // Ambiguous for the binder (`-P`: Path, PassThru, LiteralPath's alias PSPath).
    unknown_after(vec![stmt(lits("Set-Location", &["-P", "x"]), seq)]);
    unknown_after(vec![stmt(lits("Set-Location", &["@p"]), seq)]);
    unknown_after(vec![stmt(lits("Set-Location", &["-Path"]), seq)]);
    unknown_after(vec![stmt(lits("Pop-Location", &[]), seq)]);
    unknown_after(vec![stmt(lits(r".\cd.exe", &["sub"]), seq)]);
    unknown_after(vec![Stmt::Loop {
        body: script(vec![stmt(lits("cd", &["sub"]), None)]),
        span: Span::default(),
    }]);
    unknown_after(vec![Stmt::Block(script(vec![stmt(
        lits("cd", &["sub"]),
        None,
    )]))]);
    unknown_after(vec![Stmt::Cond {
        branches: vec![script(vec![stmt(lits("cd", &["sub"]), None)])],
        span: Span::default(),
    }]);
    // A cd inside a substitution in an argument.
    let inner = script(vec![stmt(lits("cd", &["sub"]), None)]);
    let arg = word_at(vec![WordPart::Subst(Box::new(inner))], 0);
    unknown_after(vec![stmt(cmd("echo", vec![arg.clone()]), seq)]);
    // The same causes joined by `&&`, where no known folder is left: each cause's own kind.
    unknown_after(vec![stmt(cmd("echo", vec![arg]), and)]);
    unknown_after(vec![stmt(lits("Pop-Location", &[]), and)]);
    unknown_after(vec![stmt(lits("Invoke-Expression", &["cd sub"]), and)]);
    unknown_after(vec![stmt(lits("Set-Location", &["-Path:sub*"]), and)]);
    // A statement without a location change keeps it.
    let mut loc = base.clone();
    loc.after(&stmt(lits("echo", &["x"]), seq), &env);
    assert_eq!(resolve(&rel, &loc, &env), paths(&[r"C:\w\repo\y"]));
}

#[test]
fn pwsh_location_functions_and_script_runs_move_the_shell() {
    let seq = Some(ChainOp::Seq);
    let and = Some(ChainOp::And);
    // `<stmts>; rm -rf <word>` from `cwd`, in `shell`.
    let run = |shell: Shell, cwd: &str, stmts: Vec<Stmt>, word: &str| {
        let (_, env) = win(shell);
        let mut loc = Location::new(shell, Os::Windows, Some(Path::new(cwd)));
        after_all(&mut loc, &script(stmts), &env);
        resolve(&lit(word), &loc, &env)
    };
    let ps = Shell::Pwsh;
    let one = |name: &str, chain| stmt(lits(name, &[]), chain);
    let (sub, deep, repo) = (r"C:\w\repo\sub", r"C:\w\repo\sub\deep", r"C:\w\repo");
    /// Label, shell, starting folder, statements before the delete, the delete's word, result.
    type Row<'a> = (&'a str, Shell, &'a str, Vec<Stmt>, &'a str, Target);
    let rows: Vec<Row> = vec![
        // pwsh ships `cd..`, `cd\` and `cd~` as functions that run Set-Location.
        (
            "cd..; .",
            ps,
            sub,
            vec![one("cd..", seq)],
            ".",
            paths(&[repo, sub]),
        ),
        (
            "cd.. && cd.. && .",
            ps,
            deep,
            vec![one("cd..", and), one("cd..", and)],
            ".",
            paths(&[repo]),
        ),
        (
            r"cd\ && w\repo",
            ps,
            repo,
            vec![one(r"cd\", and)],
            r"w\repo",
            paths(&[repo]),
        ),
        (
            r"cd~ && ..\u",
            ps,
            repo,
            vec![one("cd~", and)],
            r"..\u",
            paths(&[r"C:\Profiles\u"]),
        ),
        // `X:` is a shipped function: that drive's current folder.
        (
            "X:; .",
            ps,
            repo,
            vec![one("X:", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        // A script's Set-Location stays in effect after it ends; pwsh runs `.\up` and `.\up.v2`
        // as `up.ps1` and `up.v2.ps1` (fix6\spike-dot.ps1).
        (
            r".\up.ps1; .",
            ps,
            sub,
            vec![one(r".\up.ps1", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            r".\up; .",
            ps,
            sub,
            vec![one(r".\up", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            r".\up.v2; .",
            ps,
            sub,
            vec![one(r".\up.v2", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        // A script run with no folder in its name.
        (
            "setup.ps1; .",
            ps,
            sub,
            vec![one("setup.ps1", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            "Import-Module m; .",
            ps,
            sub,
            vec![stmt(lits("Import-Module", &["m"]), seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        // The same movers inside a branch, a block and a substitution.
        (
            "if { cd.. }; .",
            ps,
            sub,
            vec![Stmt::Cond {
                branches: vec![script(vec![one("cd..", None)])],
                span: Span::default(),
            }],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            r"{ .\up.ps1 }; .",
            ps,
            sub,
            vec![Stmt::Block(script(vec![one(r".\up.ps1", None)]))],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            "echo $(Invoke-Psake); .",
            ps,
            sub,
            vec![stmt(
                cmd(
                    "echo",
                    vec![word_at(
                        vec![WordPart::Subst(Box::new(script(vec![one(
                            "Invoke-Psake",
                            None,
                        )])))],
                        0,
                    )],
                ),
                seq,
            )],
            ".",
            MAY_BE_CRITICAL,
        ),
        (
            "if { Get-ChildItem }; . (control)",
            ps,
            sub,
            vec![Stmt::Cond {
                branches: vec![script(vec![one("Get-ChildItem", None)])],
                span: Span::default(),
            }],
            ".",
            paths(&[sub]),
        ),
        (
            r"if { sudo .\up.ps1 }; . (control)",
            ps,
            sub,
            vec![Stmt::Cond {
                branches: vec![script(vec![stmt(lits("sudo", &[r".\up.ps1"]), None)])],
                span: Span::default(),
            }],
            ".",
            paths(&[sub]),
        ),
        (
            "Git Bash if { cd.. }; . (control)",
            Shell::Bash(BashProfile::GitBash),
            sub,
            vec![Stmt::Cond {
                branches: vec![script(vec![one("cd..", None)])],
                span: Span::default(),
            }],
            ".",
            paths(&[sub]),
        ),
        // A wrapper runs a program, which cannot move this shell.
        (
            r"sudo .\up.ps1; .",
            ps,
            sub,
            vec![stmt(lits("sudo", &[r".\up.ps1"]), seq)],
            ".",
            paths(&[sub]),
        ),
        // A Verb-Noun name pwsh does not ship may load a module that runs anything.
        (
            "Invoke-Psake; .",
            ps,
            sub,
            vec![one("Invoke-Psake", seq)],
            ".",
            MAY_BE_CRITICAL,
        ),
        // Controls: a shipped cmdlet, a shipped alias, a native program; Windows PowerShell 5.1
        // ships no `cd~`; Git Bash has no such functions.
        (
            "Get-ChildItem; .",
            ps,
            sub,
            vec![one("Get-ChildItem", seq)],
            ".",
            paths(&[sub]),
        ),
        ("ls; .", ps, sub, vec![one("ls", seq)], ".", paths(&[sub])),
        (
            "git status; .",
            ps,
            sub,
            vec![stmt(lits("git", &["status"]), seq)],
            ".",
            paths(&[sub]),
        ),
        (
            "5.1 cd~; .",
            Shell::Powershell5,
            sub,
            vec![one("cd~", seq)],
            ".",
            paths(&[sub]),
        ),
        (
            "Git Bash cd..; .",
            Shell::Bash(BashProfile::GitBash),
            sub,
            vec![one("cd..", seq)],
            ".",
            paths(&[sub]),
        ),
    ];
    let mut bad: Vec<String> = rows
        .into_iter()
        .filter_map(|(label, shell, cwd, stmts, word, want)| {
            let got = run(shell, cwd, stmts, word);
            (got != want).then(|| format!("{label}: got {got:?}, want {want:?}"))
        })
        .collect();
    // A loop whose body moves starts each pass where the last one ended.
    let (_, env) = win(ps);
    let lp = Stmt::Loop {
        body: script(vec![one("cd..", seq), one("x", seq)]),
        span: Span::default(),
    };
    let got = resolve(
        &lit("."),
        &Location::new(ps, Os::Windows, Some(Path::new(sub))).inner(&lp),
        &env,
    );
    if got != MAY_BE_CRITICAL {
        bad.push(format!("foreach {{ cd..; . }} from inner: got {got:?}"));
    }
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn a_wrapper_in_front_of_a_command_is_read_through() {
    let bash = Shell::Bash(BashProfile::GitBash);
    let (base, env) = win(bash);
    let and = Some(ChainOp::And);
    let seq = Some(ChainOp::Seq);
    let repo = lit("repo");
    let mut bad: Vec<String> = Vec::new();
    let mut expect = |got: Target, want: &Target, label: String| {
        if &got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    };
    // `builtin cd .. && rm -rf repo`: the wrappers that run the builtin in this shell move it.
    for wrapped in [
        lits("builtin", &["cd", ".."]),
        lits("command", &["cd", ".."]),
        lits("command", &["-p", "cd", ".."]),
        lits("command", &["--", "cd", ".."]),
        lits("time", &["-p", "cd", ".."]),
        lits("builtin", &["builtin", "cd", ".."]),
        lits("command", &["builtin", "pushd", ".."]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(wrapped.clone(), and), &env);
        expect(
            resolve(&repo, &loc, &env),
            &paths(&[r"C:\w\repo"]),
            show(&wrapped),
        );
    }
    // `command -v cd ..` only describes cd.
    let mut loc = base.clone();
    let describe = lits("command", &["-v", "cd", ".."]);
    loc.after(&stmt(describe.clone(), and), &env);
    expect(
        resolve(&repo, &loc, &env),
        &paths(&[r"C:\w\repo\repo"]),
        show(&describe),
    );
    // A program cannot move this shell, but nothing proves what it does; an option the hook
    // does not model or a name it cannot read hides the command.
    for unknown in [
        lits("env", &["cd", ".."]),
        lits("sudo", &["cd", ".."]),
        lits("exec", &["cd", ".."]),
        lits("nohup", &["cd", ".."]),
        lits("env", &["X=1", "cd", ".."]),
        lits("builtin", &["-x", "cd", ".."]),
        cmd("builtin", vec![var("c"), lit("..")]),
        lits("command", &["-x", "cd", ".."]),
        // A program named like the builtin.
        lits("/usr/bin/command", &["cd", ".."]),
        // A location command inside one word after an option the reader does not model.
        lits("command", &["-x", "cd .."]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(unknown.clone(), and), &env);
        expect(resolve(&repo, &loc, &env), &MAY_BE_CRITICAL, show(&unknown));
    }
    // A loop whose body moves through a wrapper starts each pass somewhere unknown.
    let body = script(vec![stmt(lits("builtin", &["cd", "sub"]), None)]);
    let lp = Stmt::Loop {
        body,
        span: Span::default(),
    };
    expect(
        resolve(&repo, &base.inner(&lp), &env),
        &MAY_BE_CRITICAL,
        "loop { builtin cd sub }".to_string(),
    );
    // PowerShell has no such builtins.
    let (ps_base, ps_env) = win(Shell::Pwsh);
    let mut loc = ps_base.clone();
    let ps_command = lits("command", &["cd", ".."]);
    loc.after(&stmt(ps_command.clone(), and), &ps_env);
    expect(
        resolve(&repo, &loc, &ps_env),
        &MAY_BE_CRITICAL,
        format!("pwsh {}", show(&ps_command)),
    );
    // Links made through a wrapper: where the wrapper is read, the link is placed; where it
    // is not (`sudo -u`), it is a link somewhere unknown.
    let ln = |pre: &[&str]| {
        let mut args: Vec<Word> = pre.iter().map(|a| lit(a)).collect();
        args.extend([
            lit("ln"),
            lit("-s"),
            word_at(vec![WordPart::Tilde], 0),
            lit("t/j"),
        ]);
        args
    };
    for (link, placed) in [
        (cmd("sudo", ln(&[])), true),
        (cmd("env", ln(&["X=1"])), true),
        (cmd("env", ln(&["-i"])), true),
        (cmd("env", ln(&["-"])), true),
        (cmd("env", ln(&["-u", "X"])), true),
        (cmd("env", ln(&["--unset=X"])), true),
        (cmd("env", ln(&["--ignore-environment"])), true),
        (cmd("exec", ln(&["-a", "x"])), true),
        (cmd("exec", ln(&["-c"])), true),
        (cmd("nohup", ln(&[])), true),
        // Every word literal, so no word may be a drive mapping.
        (
            lits("sudo", &["-u", "u", "ln", "-s", r"C:\x", "t/j"]),
            false,
        ),
        // A command inside one word (`sh -c '…'`), or split from one by `env -S`: an env
        // option the reader does not model may run anything.
        (
            lits("sudo", &["-u", "u", "sh", "-c", r"ln -s C:\x t/j"]),
            false,
        ),
        (lits("env", &["-S", r"ln -s C:\x t/j"]), false),
        (lits("env", &[r"--split-string=ln -s C:\x t/j"]), false),
        (lits("env", &["-S", "X"]), false),
        // Start-Process: its arguments are read as words only.
        (
            lits("Start-Process", &["ln", "-ArgumentList", r"-s C:\x t/j"]),
            false,
        ),
        (lits("saps", &[r"ln -s C:\x t/j"]), false),
        (lits("start", &["ln", r"-s C:\x t/j"]), false),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(link.clone(), seq), &env);
        expect(
            resolve(&lit("t"), &loc, &env),
            &MAY_BE_CRITICAL,
            show(&link),
        );
        let want = if placed {
            paths(&[r"D:\elsewhere\u"])
        } else {
            MAY_BE_CRITICAL
        };
        expect(
            resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
            &want,
            format!("{}: elsewhere", show(&link)),
        );
    }
    for mapping in [
        lits("env", &["subst", "X:", r"C:\Profiles\u"]),
        lits("sudo", &["-u", "u", "subst", "X:", r"C:\Profiles\u"]),
    ] {
        let mut loc = base.clone();
        loc.after(&stmt(mapping.clone(), seq), &env);
        expect(
            resolve(&lit(r"X:\sub"), &loc, &env),
            &MAY_BE_CRITICAL,
            show(&mapping),
        );
    }
    // Every Start-Process may run any command, whatever its words name.
    let mut loc = base.clone();
    let notepad = lits("Start-Process", &["notepad", "-ArgumentList", "x.txt"]);
    loc.after(&stmt(notepad.clone(), seq), &env);
    expect(
        resolve(&lit(r"D:\elsewhere\u"), &loc, &env),
        &MAY_BE_CRITICAL,
        show(&notepad),
    );
    // `builtin export TEMP=…; rm -rf $TEMP`: the wrapped builtin assigns the name.
    let temp = var("TEMP");
    for assigner in [
        lits("builtin", &["export", r"TEMP=C:\Profiles\u"]),
        lits("command", &["export", r"TEMP=C:\Profiles\u"]),
        // An unread builtin may assign anything.
        lits("builtin", &["-x", "export", r"TEMP=C:\Profiles\u"]),
    ] {
        let mut assigned = env.clone();
        mark_assigned(
            &mut assigned,
            &script(vec![stmt(assigner.clone(), seq)]),
            "",
        );
        expect(
            resolve(&temp, &base, &assigned),
            &Target::Dynamic(temp.span),
            show(&assigner),
        );
    }
    // A wrapper with nothing to run assigns nothing.
    let mut plain = env.clone();
    let alone = lits("command", &[]);
    mark_assigned(&mut plain, &script(vec![stmt(alone.clone(), seq)]), "");
    expect(
        resolve(&temp, &base, &plain),
        &paths(&[r"C:\Profiles\u\AppData\Local\Temp"]),
        show(&alone),
    );
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn a_command_the_hook_cannot_read_as_plain_arguments_may_be_any_command() {
    let seq = Some(ChainOp::Seq);
    // `New-Item -ItemType Junction t\j -Value C:\` as pwsh's UTF-16LE base64.
    let encoded = "-EncodedCommand,TgBlAHcALQBJAHQAZQBtACAALQBJAHQAZQBtAFQAeQBwAGUAIABKAHUAbgBjAHQAaQBvAG4AIAB0AFwAagAgAC0AVgBhAGwAdQBlACAAQwA6AFwA";
    let rows = [
        // Start-Process: an array that arrives as one word, cmd's `&&` and `^`, an encoded
        // script.
        lits("Start-Process", &["cmd", r"/c,mklink /J t\j %USERPROFILE%"]),
        lits("Start-Process", &["cmd", r"/c echo&&mklink /J t\j C:\"]),
        lits("Start-Process", &["cmd", r"/c m^klink /J t\j C:\"]),
        lits("Start-Process", &["pwsh", "-ArgumentList", encoded]),
        // Behind a wrapper option the reader does not model, a shell reads the word.
        lits("sudo", &["-u", "u", "sh", "-c", "true;ln -s ~ t/j"]),
        lits("sudo", &["-u", "u", "sh", "-c", "true&&ln -s ~ t/j"]),
        lits("sudo", &["-u", "u", "sh", "-c", "(ln -s ~ t/j)"]),
        lits("sudo", &["-u", "u", "sh", "-c", r"l\n -s ~ t/j"]),
    ];
    let mut bad: Vec<String> = Vec::new();
    let mut expect = |got: Target, want: &Target, label: String| {
        if &got != want {
            bad.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    };
    let (ps_base, ps_env) = win(Shell::Pwsh);
    let posix = Shell::Bash(BashProfile::Posix);
    let posix_base = Location::new(posix, Os::Posix, Some(Path::new("/w/repo")));
    let posix_env = env_view(posix, Os::Posix, [("HOME".to_string(), "/h".to_string())]);
    for row in rows {
        let label = show(&row);
        let mut loc = ps_base.clone();
        loc.after(&stmt(row.clone(), seq), &ps_env);
        for gone in ["t", r"D:\elsewhere\u"] {
            expect(
                resolve(&lit(gone), &loc, &ps_env),
                &MAY_BE_CRITICAL,
                format!("{label}: {gone}"),
            );
        }
        // It may make a link anywhere (POSIX has no drive aliases to hide it).
        let mut loc = posix_base.clone();
        loc.after(&stmt(row.clone(), seq), &posix_env);
        expect(
            resolve(&lit("/elsewhere/u"), &loc, &posix_env),
            &MAY_BE_CRITICAL,
            format!("{label}: posix /elsewhere/u"),
        );
    }
    // A bash command run in this shell with an unread name (`command $x -s ~ <link>`) may remap
    // a drive and may make a link: one row needs the remap alone, one the link alone, one either.
    let in_shell = |link: &str| {
        let tilde = word_at(vec![WordPart::Tilde], 0);
        stmt(
            cmd("command", vec![var("x"), lit("-s"), tilde, lit(link)]),
            seq,
        )
    };
    let git_bash = Shell::Bash(BashProfile::GitBash);
    let (gb_base, gb_env) = win(git_bash);
    let mut loc = gb_base.clone();
    loc.after(&in_shell("t/j"), &gb_env);
    // A glob that matches nothing leaves no path for a link to reach.
    let nothing = word_at(
        vec![
            WordPart::Literal("/c/w/repo/nomatch".to_string()),
            WordPart::Glob("*".to_string()),
        ],
        0,
    );
    expect(
        resolve(&nothing, &loc, &gb_env),
        &MAY_BE_CRITICAL,
        "Git Bash command $x -s ~ t/j; /c/w/repo/nomatch* (the remap)".to_string(),
    );
    let mut loc = posix_base.clone();
    loc.after(&in_shell("/w/repo/t/j"), &posix_env);
    expect(
        resolve(&lit("/w/repo/t"), &loc, &posix_env),
        &MAY_BE_CRITICAL,
        "posix command $x -s ~ /w/repo/t/j; /w/repo/t (the link)".to_string(),
    );
    let mut loc = gb_base.clone();
    loc.after(&in_shell("/c/w/repo/t/j"), &gb_env);
    expect(
        resolve(&lit("/c/w/repo/t"), &loc, &gb_env),
        &MAY_BE_CRITICAL,
        "Git Bash command $x -s ~ /c/w/repo/t/j; /c/w/repo/t (either)".to_string(),
    );
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn push_and_pop_location_restore_the_folder() {
    let (base, env) = win(Shell::Pwsh);
    let mut loc = base.clone();
    let s = script(vec![
        stmt(lits("Push-Location", &[r"C:\a"]), Some(ChainOp::And)),
        stmt(lits("pushd", &[r"C:\b"]), Some(ChainOp::And)),
        stmt(lits("Pop-Location", &[]), Some(ChainOp::And)),
    ]);
    after_all(&mut loc, &s, &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), paths(&[r"C:\a\y"]));
    loc.after(&stmt(lits("popd", &[]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), paths(&[r"C:\w\repo\y"]));
}

#[test]
fn bash_cd_without_an_argument_goes_home() {
    let shell = Shell::Bash(BashProfile::GitBash);
    let (base, env) = win(shell);
    let mut loc = base.clone();
    loc.after(&stmt(lits("cd", &[]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), paths(&[r"C:\Profiles\u\y"]));
    // `HOME=… ; cd`: the folder comes from the assignment.
    let mut assigned = env.clone();
    mark_assigned(
        &mut assigned,
        &script(vec![stmt(assign("HOME", "/x"), None)]),
        "",
    );
    let mut loc = base.clone();
    loc.after(&stmt(lits("cd", &[]), Some(ChainOp::And)), &assigned);
    assert_eq!(resolve(&lit("y"), &loc, &assigned), DYNAMIC_LOCATION);
    let mut loc = base.clone();
    loc.after(
        &stmt(lits("cd", &["-L", "--", "/c/a"]), Some(ChainOp::And)),
        &env,
    );
    assert_eq!(resolve(&lit("y"), &loc, &env), paths(&[r"C:\a\y"]));
    // `cd -P` resolves `..` after links.
    let mut loc = base.clone();
    loc.after(&stmt(lits("cd", &["-P", "/c/a"]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), MAY_BE_CRITICAL);
}

#[test]
fn bash_cd_to_a_relative_name_is_unknown_when_cdpath_may_be_set() {
    let shell = Shell::Bash(BashProfile::GitBash);
    let host = [
        ("USERPROFILE".to_string(), r"C:\Profiles\u".to_string()),
        ("CDPATH".to_string(), r"C:\elsewhere".to_string()),
    ];
    let env = env_view(shell, Os::Windows, host);
    let base = Location::new(shell, Os::Windows, Some(Path::new(r"C:\w\repo")));
    let after_cd = |env: &EnvView, to: &str| {
        let mut loc = base.clone();
        loc.after(&stmt(lits("cd", &[to]), Some(ChainOp::And)), env);
        resolve(&lit("y"), &loc, env)
    };
    assert_eq!(after_cd(&env, "sub"), MAY_BE_CRITICAL);
    assert_eq!(after_cd(&env, "./sub"), paths(&[r"C:\w\repo\sub\y"]));
    // `.hidden` is searched in CDPATH like any other relative name.
    assert_eq!(after_cd(&env, ".hidden"), MAY_BE_CRITICAL);
    // The same name split over two literal parts.
    let split = word_at(
        vec![
            WordPart::Literal(".".to_string()),
            WordPart::Literal("hidden".to_string()),
        ],
        0,
    );
    let mut loc = base.clone();
    loc.after(&stmt(cmd("cd", vec![split]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), MAY_BE_CRITICAL);
    // `.` followed by a variable is no `.`.
    let dot_var = word_at(
        vec![
            WordPart::Literal(".".to_string()),
            WordPart::Var("USERPROFILE".to_string()),
        ],
        0,
    );
    let mut loc = base.clone();
    loc.after(&stmt(cmd("cd", vec![dot_var]), Some(ChainOp::And)), &env);
    assert_eq!(resolve(&lit("y"), &loc, &env), MAY_BE_CRITICAL);
    // `cd .$TMP`: what follows the `.` decides whether bash searches CDPATH (`.t` is a
    // relative name), so a `.` followed by anything counts as searched.
    let posix = Shell::Bash(BashProfile::Posix);
    let posix_env = env_view(
        posix,
        Os::Posix,
        [
            ("HOME".to_string(), "/h".to_string()),
            ("TMP".to_string(), "t".to_string()),
            ("CDPATH".to_string(), "/elsewhere".to_string()),
        ],
    );
    let dot_tmp = word_at(
        vec![
            WordPart::Literal(".".to_string()),
            WordPart::Var("TMP".to_string()),
        ],
        0,
    );
    let mut loc = Location::new(posix, Os::Posix, Some(Path::new("/w/repo")));
    loc.after(
        &stmt(cmd("cd", vec![dot_tmp]), Some(ChainOp::And)),
        &posix_env,
    );
    assert_eq!(resolve(&lit("y"), &loc, &posix_env), MAY_BE_CRITICAL);
    // `$CDPATH` never resolves to the hook's own value.
    let w = var("CDPATH");
    let loc = Location::new(shell, Os::Windows, Some(Path::new(r"C:\w\repo")));
    assert_eq!(resolve(&w, &loc, &env), Target::Dynamic(w.span));
    let (_, mut plain) = win(shell);
    assert_eq!(after_cd(&plain, "sub"), paths(&[r"C:\w\repo\sub\y"]));
    mark_assigned(
        &mut plain,
        &script(vec![stmt(assign("CDPATH", "/x"), None)]),
        "",
    );
    assert_eq!(after_cd(&plain, "sub"), MAY_BE_CRITICAL);
}

#[test]
fn bodies_that_run_later_or_repeatedly_start_at_an_unknown_location() {
    let (base, env) = win(Shell::Pwsh);
    let cd_body = script(vec![stmt(lits("cd", &["sub"]), None)]);
    let plain_body = script(vec![stmt(lits("echo", &[]), None)]);
    let lp = |body: Script| Stmt::Loop {
        body,
        span: Span::default(),
    };
    let func = Stmt::Func {
        name: "f".to_string(),
        body: plain_body.clone(),
    };
    let y = lit("y");
    assert_eq!(
        resolve(&y, &base.inner(&lp(cd_body)), &env),
        MAY_BE_CRITICAL
    );
    assert_eq!(
        resolve(&y, &base.inner(&lp(plain_body.clone())), &env),
        paths(&[r"C:\w\repo\y"])
    );
    assert_eq!(resolve(&y, &base.inner(&func), &env), MAY_BE_CRITICAL);
    assert_eq!(
        resolve(&y, &base.inner(&Stmt::Block(plain_body)), &env),
        paths(&[r"C:\w\repo\y"])
    );
}

#[test]
fn a_remap_anywhere_in_the_command_reaches_a_body_that_runs_later_or_again() {
    let seq = Some(ChainOp::Seq);
    let (base, env) = win(Shell::Pwsh);
    // Drives C: and X: exist on this machine.
    let machine = FakeFs::default()
        .dir(r"C:\Profiles\u")
        .dir(r"X:\Documents")
        .shared();
    let by = delete_by(&lits("Remove-Item", &[]), Shell::Pwsh, Os::Windows);
    // The whole command read first; `word` judged at the start of the first statement's body,
    // from `inner` as the `Location` doc prescribes (or from the command's start for a row
    // whose first statement is the delete itself).
    let judge = |whole: Vec<Stmt>, word: &str, from_inner: bool| {
        let s = script(whole);
        let mut loc = base.clone();
        loc.read_script(&s);
        let loc = if from_inner {
            loc.inner(&s.stmts[0])
        } else {
            loc
        };
        sorted(target(&lit(word), &loc, &env, by, &machine, &far()))
    };
    let st = |c: SimpleCommand| stmt(c, seq);
    let ri = |text: &str| st(lits("Remove-Item", &[text]));
    let remap = || st(lits("New-PSDrive", &["Proj", "FileSystem", r"C:\Profiles"]));
    let lp = |body: Vec<Stmt>| Stmt::Loop {
        body: script(body),
        span: Span::default(),
    };
    let drive_new = || method("ExecutionContext.SessionState.Drive", "New", vec![lit("x")]);
    let rows: Vec<(&str, Vec<Stmt>, &str, bool, Target)> = vec![
        (
            "function Clean { Proj:\\x }; New-PSDrive Proj; Clean",
            vec![
                Stmt::Func {
                    name: "Clean".to_string(),
                    body: script(vec![ri(r"Proj:\x")]),
                },
                remap(),
                st(lits("Clean", &[])),
            ],
            r"Proj:\x",
            true,
            MAY_BE_CRITICAL,
        ),
        (
            "foreach { Proj:\\x; New-PSDrive Proj }",
            vec![lp(vec![ri(r"Proj:\x"), remap()])],
            r"Proj:\x",
            true,
            MAY_BE_CRITICAL,
        ),
        (
            "foreach { X:\\Documents; subst X: }",
            vec![lp(vec![
                st(lits("Remove-Item", &["-Recurse", r"X:\Documents"])),
                st(lits("subst", &["X:", r"C:\Profiles"])),
            ])],
            r"X:\Documents",
            true,
            MAY_BE_CRITICAL,
        ),
        (
            "foreach { Proj:\\x; .\\setup.ps1 }",
            vec![lp(vec![ri(r"Proj:\x"), st(lits(r".\setup.ps1", &[]))])],
            r"Proj:\x",
            true,
            MAY_BE_CRITICAL,
        ),
        (
            "foreach { Proj:\\x; Drive.New }",
            vec![lp(vec![ri(r"Proj:\x"), drive_new()])],
            r"Proj:\x",
            true,
            MAY_BE_CRITICAL,
        ),
        (
            "foreach { Function:y; New-PSDrive Function }",
            vec![lp(vec![
                ri("Function:y"),
                st(lits("New-PSDrive", &["Function", "FileSystem", r"C:\x"])),
            ])],
            "Function:y",
            true,
            MAY_BE_CRITICAL,
        ),
        // Controls: a straight-line delete before the remap, a loop with no remap, and a block,
        // which runs once and in order.
        (
            "Proj:\\x; New-PSDrive Proj (straight line)",
            vec![ri(r"Proj:\x"), remap()],
            r"Proj:\x",
            false,
            unproven("Proj"),
        ),
        (
            "foreach { Proj:\\x; git status }",
            vec![lp(vec![ri(r"Proj:\x"), st(lits("git", &["status"]))])],
            r"Proj:\x",
            true,
            unproven("Proj"),
        ),
        (
            "{ Proj:\\x; New-PSDrive Proj } (a block)",
            vec![Stmt::Block(script(vec![ri(r"Proj:\x"), remap()]))],
            r"Proj:\x",
            true,
            unproven("Proj"),
        ),
    ];
    let bad: Vec<String> = rows
        .into_iter()
        .filter_map(|(label, whole, word, from_inner, want)| {
            let got = judge(whole, word, from_inner);
            (got != want).then(|| format!("{label}: got {got:?}, want {want:?}"))
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} rows failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn git_dash_c_moves_the_location_for_that_command_only() {
    let (base, env) = win(Shell::Pwsh);
    let y = lit("y");
    let git = |args: Vec<Word>| base.for_git(&cmd("git", args), &env);
    assert_eq!(
        resolve(
            &y,
            &git(vec![
                lit("-C"),
                lit("sub"),
                lit("-C"),
                lit("x"),
                lit("clean")
            ]),
            &env
        ),
        paths(&[r"C:\w\repo\sub\x\y"])
    );
    assert_eq!(
        resolve(
            &y,
            &git(vec![
                lit("-c"),
                lit("a=b"),
                lit("-C"),
                lit(r"C:\a"),
                lit("clean")
            ]),
            &env
        ),
        paths(&[r"C:\a\y"])
    );
    // Options after the subcommand are the subcommand's.
    assert_eq!(
        resolve(&y, &git(vec![lit("clean"), lit("-C"), lit(r"C:\a")]), &env),
        paths(&[r"C:\w\repo\y"])
    );
    for (args, want) in [
        (vec![lit("-C"), var("x"), lit("clean")], DYNAMIC_LOCATION),
        (vec![var("opts"), lit("clean")], DYNAMIC_LOCATION),
        (vec![lit("-C")], MAY_BE_CRITICAL),
        (vec![lit("--work-tree=x"), lit("clean")], MAY_BE_CRITICAL),
        (
            vec![lit("--git-dir"), lit("x"), lit("clean")],
            MAY_BE_CRITICAL,
        ),
    ] {
        assert_eq!(resolve(&y, &git(args.clone()), &env), want, "{args:?}");
    }
    assert_eq!(resolve(&y, &base, &env), paths(&[r"C:\w\repo\y"]));
}

// ---------------------------------------------------------------- env view

#[test]
fn env_view_takes_home_from_the_profile_on_windows() {
    let host = [
        ("USERPROFILE".to_string(), r"C:\Profiles\u".to_string()),
        ("HOME".to_string(), r"D:\hook-home".to_string()),
        ("Temp".to_string(), r"C:\t".to_string()),
        ("TMP".to_string(), r"C:\t".to_string()),
        (
            "APPDATA".to_string(),
            r"C:\Profiles\u\AppData\Roaming".to_string(),
        ),
        (
            "LOCALAPPDATA".to_string(),
            r"C:\Profiles\u\AppData\Local".to_string(),
        ),
        ("XDG_CONFIG_HOME".to_string(), r"C:\x".to_string()),
        ("TMPDIR".to_string(), r"C:\nope".to_string()),
        ("PATH".to_string(), r"C:\bin".to_string()),
    ];
    let bash = env_view(Shell::Bash(BashProfile::GitBash), Os::Windows, host.clone());
    assert_eq!(bash.home(), Some(r"C:\Profiles\u"));
    assert_eq!(bash.get("HOME"), Some(r"C:\Profiles\u"));
    assert_eq!(bash.get("USERPROFILE"), Some(r"C:\Profiles\u"));
    assert_eq!(bash.get("TEMP"), Some(r"C:\t"));
    assert_eq!(bash.get("TMP"), Some(r"C:\t"));
    // Only the names the hook-vs-tool spike showed equal resolve.
    assert_eq!(bash.get("APPDATA"), None);
    assert_eq!(bash.get("LOCALAPPDATA"), None);
    assert_eq!(bash.get("XDG_CONFIG_HOME"), None);
    assert_eq!(bash.get("TMPDIR"), None);
    assert_eq!(bash.get("PATH"), None);
    assert_eq!(bash.get("temp"), None);

    let ps = env_view(Shell::Pwsh, Os::Windows, host.clone());
    assert_eq!(ps.home(), Some(r"C:\Profiles\u"));
    assert_eq!(ps.get("HOME"), Some(r"C:\Profiles\u"));
    assert_eq!(ps.get("home"), Some(r"C:\Profiles\u"));
    assert_eq!(ps.get("env:HOME"), None);
    assert_eq!(ps.get("ENV:temp"), Some(r"C:\t"));
    assert_eq!(ps.get("env:USERPROFILE"), Some(r"C:\Profiles\u"));
    assert_eq!(ps.get("TEMP"), None);
    assert_eq!(ps.get("env:TMPDIR"), None);

    let none = env_view(
        Shell::Pwsh,
        Os::Windows,
        [("HOME".to_string(), r"D:\h".to_string())],
    );
    assert_eq!(none.home(), None);
    assert_eq!(none.get("HOME"), None);

    let posix = env_view(
        Shell::Bash(BashProfile::Posix),
        Os::Posix,
        [
            ("HOME".to_string(), "/h".to_string()),
            ("TMPDIR".to_string(), "/t".to_string()),
            ("XDG_DATA_HOME".to_string(), "/h/.d".to_string()),
        ],
    );
    assert_eq!(posix.home(), Some("/h"));
    assert_eq!(posix.get("HOME"), Some("/h"));
    assert_eq!(posix.get("TMPDIR"), None);
    assert_eq!(posix.get("XDG_DATA_HOME"), None);
}

fn method(type_name: &str, name: &str, args: Vec<Word>) -> Stmt {
    Stmt::Pipeline(Pipeline {
        elems: vec![Elem::Method(MethodCall {
            type_name: type_name.to_string(),
            method: name.to_string(),
            args,
            span: Span::default(),
        })],
        chain: Some(ChainOp::Seq),
    })
}

#[test]
fn a_name_assigned_anywhere_in_the_command_is_dynamic() {
    let seq = Some(ChainOp::Seq);
    let ps = Shell::Pwsh;
    let bash = Shell::Bash(BashProfile::GitBash);
    let temp = || var("env:TEMP");
    let home = || var("HOME");
    let mut with_prefix = lits("rm", &["-rf"]);
    with_prefix.assigns = vec![("HOME".to_string(), lit("/"))];
    let nested = script(vec![stmt(assign("env:TEMP", r"C:\"), None)]);
    let rows: Vec<(&str, Shell, Script, Word)> = vec![
        (
            "$env:TEMP='C:\\'",
            ps,
            script(vec![stmt(assign("env:TEMP", r"C:\"), seq)]),
            temp(),
        ),
        (
            "$ENV:temp = 'C:\\'",
            ps,
            script(vec![stmt(assign("ENV:temp", r"C:\"), seq)]),
            temp(),
        ),
        (
            "HOME=/ rm -rf \"$HOME\"",
            bash,
            script(vec![stmt(with_prefix, None)]),
            home(),
        ),
        (
            "HOME=/; ...",
            bash,
            script(vec![stmt(assign("HOME", "/"), seq)]),
            home(),
        ),
        (
            "env HOME=/ rm",
            bash,
            script(vec![stmt(lits("env", &["HOME=/", "rm"]), seq)]),
            home(),
        ),
        (
            "env -u HOME rm",
            bash,
            script(vec![stmt(lits("env", &["-u", "HOME", "rm"]), seq)]),
            home(),
        ),
        (
            "export HOME=/",
            bash,
            script(vec![stmt(lits("export", &["HOME=/"]), seq)]),
            home(),
        ),
        (
            "declare -x HOME=/",
            bash,
            script(vec![stmt(lits("declare", &["-x", "HOME=/"]), seq)]),
            home(),
        ),
        (
            "unset HOME",
            bash,
            script(vec![stmt(lits("unset", &["HOME"]), seq)]),
            home(),
        ),
        (
            "read HOME",
            bash,
            script(vec![stmt(lits("read", &["-r", "HOME"]), seq)]),
            home(),
        ),
        (
            "printf -v HOME /",
            bash,
            script(vec![stmt(lits("printf", &["-v", "HOME", "/"]), seq)]),
            home(),
        ),
        (
            "source x",
            bash,
            script(vec![stmt(lits("source", &["x"]), seq)]),
            home(),
        ),
        (
            ". x",
            bash,
            script(vec![stmt(lits(".", &["x"]), seq)]),
            home(),
        ),
        (
            "eval x",
            bash,
            script(vec![stmt(lits("eval", &["x"]), seq)]),
            home(),
        ),
        (
            "Set-Item env:TEMP C:\\",
            ps,
            script(vec![stmt(lits("Set-Item", &["env:TEMP", r"C:\"]), seq)]),
            temp(),
        ),
        (
            "Set-Item -Path Env:\\TEMP",
            ps,
            script(vec![stmt(
                lits("Set-Item", &["-Path", r"Env:\TEMP", "-Value", r"C:\"]),
                seq,
            )]),
            temp(),
        ),
        (
            "ni env:TEMP",
            ps,
            script(vec![stmt(lits("ni", &["env:TEMP"]), seq)]),
            temp(),
        ),
        (
            "Remove-Item env:TEMP",
            ps,
            script(vec![stmt(lits("Remove-Item", &["env:TEMP"]), seq)]),
            temp(),
        ),
        (
            "Set-Item $p",
            ps,
            script(vec![stmt(
                cmd("Set-Item", vec![var("p"), lit(r"C:\")]),
                seq,
            )]),
            temp(),
        ),
        (
            "Set-Item env:*",
            ps,
            script(vec![stmt(lits("Set-Item", &["env:*"]), seq)]),
            temp(),
        ),
        (
            "[Environment]::SetEnvironmentVariable",
            ps,
            script(vec![method(
                "Environment",
                "SetEnvironmentVariable",
                vec![lit("TEMP"), lit(r"C:\")],
            )]),
            temp(),
        ),
        (
            "[System.Environment]::SetEnvironmentVariable($n)",
            ps,
            script(vec![method(
                "System.Environment",
                "setenvironmentvariable",
                vec![var("n"), lit(r"C:\")],
            )]),
            temp(),
        ),
        (
            "Invoke-Expression",
            ps,
            script(vec![stmt(lits("Invoke-Expression", &["x"]), seq)]),
            temp(),
        ),
        (
            "Set-Variable",
            ps,
            script(vec![stmt(
                cmd("Set-Variable", vec![var("n"), lit("x")]),
                seq,
            )]),
            temp(),
        ),
        (
            "in a substitution",
            ps,
            script(vec![stmt(
                cmd(
                    "echo",
                    vec![word_at(vec![WordPart::Subst(Box::new(nested))], 0)],
                ),
                seq,
            )]),
            temp(),
        ),
    ];
    for (name, shell, s, w) in rows {
        let (loc, mut env) = win(shell);
        assert!(
            matches!(resolve(&w, &loc, &env), Target::Paths(_)),
            "{name}: control"
        );
        mark_assigned(&mut env, &s, "");
        assert_eq!(resolve(&w, &loc, &env), Target::Dynamic(w.span), "{name}");
    }
}

#[test]
fn a_loop_variable_named_in_the_loop_text_is_dynamic() {
    let bash = Shell::Bash(BashProfile::GitBash);
    let text = "for HOME in /; do :; done; rm -rf \"$HOME\"";
    let s = script(vec![Stmt::Loop {
        body: script(vec![stmt(lits(":", &[]), None)]),
        span: Span { start: 0, end: 24 },
    }]);
    let (loc, mut env) = win(bash);
    mark_assigned(&mut env, &s, text);
    assert_eq!(
        resolve(&var("HOME"), &loc, &env),
        Target::Dynamic(var("HOME").span)
    );
    let tilde = word_at(vec![WordPart::Tilde], 2);
    assert_eq!(resolve(&tilde, &loc, &env), Target::Dynamic(tilde.span));
    // A loop that names no resolvable variable changes nothing.
    let (loc, mut env) = win(bash);
    mark_assigned(&mut env, &s, "for f in a; do :; done; rm -rf \"$HOME\"");
    assert_eq!(
        resolve(&var("HOME"), &loc, &env),
        paths(&[r"C:\Profiles\u"])
    );
}

#[test]
fn an_assigned_pwd_no_longer_follows_the_location() {
    let bash = Shell::Bash(BashProfile::GitBash);
    let (loc, mut env) = win(bash);
    mark_assigned(&mut env, &script(vec![stmt(assign("PWD", "/"), None)]), "");
    let w = var("PWD");
    assert_eq!(resolve(&w, &loc, &env), Target::Dynamic(w.span));
}

// ---------------------------------------------------------------- critical

#[cfg(windows)]
#[test]
fn critical_reason_names_each_protected_folder_on_windows() {
    let home = Path::new(r"C:\Profiles\u");
    let repo = Path::new(r"C:\w\repo");
    let protected = [PathBuf::from(r"D:\keep\data")];
    let r = |p: &str| critical_reason(Path::new(p), Some(repo), Some(home), &protected);
    let cases: &[(&str, Option<&str>)] = &[
        (r"C:\", Some("drive root")),
        ("d:/", Some("drive root")),
        (r"\\?\C:\", Some("drive root")),
        (r"\\srv\share", Some("drive root")),
        (r"\\?\UNC\srv\share", Some("drive root")),
        (r"\\srv\share\", Some("drive root")),
        (
            r"\\?\Volume{0b1c2d3e-0000-4000-8000-000000000001}\",
            Some("drive root"),
        ),
        ("/", Some("file-system root")),
        (r"\", Some("file-system root")),
        (r"c:\PROFILES\U", Some("home folder")),
        ("C:/Profiles/u/", Some("home folder")),
        (r"\\?\C:\Profiles\u", Some("home folder")),
        (r"C:\Profiles", Some("ancestor of the home folder")),
        (r"C:\W\Repo", Some("repo root")),
        (r"C:\w", Some("ancestor of the repo root")),
        (r"D:\keep\data", Some("protected path")),
        (r"D:\KEEP", Some("ancestor of a protected path")),
        (r"C:\Profiles\u\x", None),
        (r"C:\Profiles\uu", None),
        (r"C:\w\repo2", None),
        // A sibling whose name the repo's name starts with.
        (r"C:\w\rep", None),
        (r"C:\t\clone", None),
    ];
    for (p, want) in cases {
        assert_eq!(r(p), *want, "{p}");
    }
    assert_eq!(critical_reason(Path::new(r"C:\w"), None, None, &[]), None);
}

#[cfg(not(windows))]
#[test]
fn critical_reason_names_each_protected_folder_on_posix() {
    let home = Path::new("/hm/u");
    let repo = Path::new("/w/repo");
    let protected = [PathBuf::from("/keep/data")];
    let r = |p: &str| critical_reason(Path::new(p), Some(repo), Some(home), &protected);
    let cases: &[(&str, Option<&str>)] = &[
        ("/", Some("file-system root")),
        ("//", Some("file-system root")),
        ("/hm/u", Some("home folder")),
        ("/hm/u/", Some("home folder")),
        ("/hm", Some("ancestor of the home folder")),
        ("/w/repo", Some("repo root")),
        ("/w", Some("ancestor of the repo root")),
        ("/keep/data", Some("protected path")),
        ("/keep", Some("ancestor of a protected path")),
        ("/HM/u", None),
        ("/hm/u/x", None),
        ("/tmp/clone", None),
    ];
    for (p, want) in cases {
        assert_eq!(r(p), *want, "{p}");
    }
}

// ---------------------------------------------------------------- repo root

#[test]
fn critical_match_by_identity_sees_through_junctions() {
    let mut t = Tree::new();
    t.mkdir("real/repo/src");
    let j = t.dir_link("j", &t.root.join("real"));
    let repo = j.path.join("repo");
    let real_repo = t.root.join("real").join("repo");
    // The spelling pass alone misses both.
    assert_eq!(critical_reason(&real_repo, Some(&repo), None, &[]), None);
    let r = |p: &Path| critical_by_identity(p, Some(&repo), None, &[], &real(), &far());
    assert_eq!(r(&real_repo), Ok(Some("repo root")));
    assert_eq!(
        r(&t.root.join("real")),
        Ok(Some("ancestor of the repo root"))
    );
    assert_eq!(r(&real_repo.join("src")), Ok(None));
    assert_eq!(r(&t.root.join("nope")), Ok(None));
}

#[test]
fn critical_match_by_identity_sees_through_drive_mappings_and_short_names() {
    // Host-form paths, so `ancestors()` splits them on every OS; ids stand for what the file
    // system reports for the same folder under two spellings.
    let mut fake = FakeFs::default();
    for (p, id) in [
        (at("mapped/repo"), 7), // the repo through a drive mapped before the command
        (at("w2/repo"), 7),
        (at("mapped/sub"), 3), // the repo's parent through the mapping
        (at("w2"), 3),
        (at("PROFIL/u"), 9), // a custom 8.3 name without `~N`
        (at("Profiles/u"), 9),
        (at("other"), 11),
    ] {
        fake.ids.insert(PathBuf::from(p), id);
    }
    let fs = fake.shared();
    let home = PathBuf::from(at("Profiles/u"));
    let repo = PathBuf::from(at("w2/repo"));
    let r = |p: &str| {
        critical_by_identity(
            Path::new(&at(p)),
            Some(&repo),
            Some(&home),
            &[],
            &fs,
            &far(),
        )
    };
    assert_eq!(r("mapped/repo"), Ok(Some("repo root")));
    assert_eq!(r("PROFIL/u"), Ok(Some("home folder")));
    assert_eq!(r("mapped/sub"), Ok(Some("ancestor of the repo root")));
    assert_eq!(r("other"), Ok(None));
    let hang: SharedFs = Arc::new(Hang("file_id"));
    let start = Instant::now();
    let got = critical_by_identity(
        Path::new(&at("mapped/sub")),
        Some(&repo),
        None,
        &[],
        &hang,
        &Deadline::new(start, 100),
    );
    assert!(got.is_err());
    assert!(start.elapsed() < Duration::from_millis(150));
}

#[test]
fn repo_root_finds_the_nearest_git_folder_or_file() {
    let fs = FakeFs::default()
        .dir(&at("repo/.git"))
        .dir(&at("repo/a/b"))
        .file(&at("wt/.git"))
        .dir(&at("wt/c"))
        .dir(&at("plain/d"))
        .shared();
    let root = |p: &str| repo_root(Path::new(&at(p)), &fs, &far());
    assert_eq!(root("repo/a/b"), Ok(Some(PathBuf::from(at("repo")))));
    assert_eq!(root("repo"), Ok(Some(PathBuf::from(at("repo")))));
    assert_eq!(root("wt/c"), Ok(Some(PathBuf::from(at("wt")))));
    assert_eq!(root("plain/d"), Ok(None));
    let hang: SharedFs = Arc::new(Hang("lstat"));
    let start = Instant::now();
    let r = repo_root(Path::new(&at("x")), &hang, &Deadline::new(start, 100));
    assert!(r.is_err());
    assert!(start.elapsed() < Duration::from_millis(150));
}
