//! Delete-target resolution, the folder walk and the bounded file-system calls.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use shellwise::fs::resolve::{
    Location, ParamMatch, Target, UnknownKind, critical_by_identity, critical_reason, env_view,
    mark_assigned, pwsh_param, repo_root, target,
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

fn real() -> SharedFs {
    Arc::new(RealFs)
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

fn resolve(w: &Word, loc: &Location, env: &EnvView) -> Target {
    sorted(target(w, loc, env, &real(), &far()))
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
    let mut fake = FakeFs::default();
    fake.long.insert(
        PathBuf::from(r"C:\PROFILES\U~1"),
        PathBuf::from(r"C:\Profiles\u.name"),
    );
    let fs = fake.shared();
    let t = target(&lit(r"C:\PROFILES\U~1"), &loc, &EnvView::new(), &fs, &far());
    assert_eq!(t, paths(&[r"C:\Profiles\u.name"]));
    let hang: SharedFs = Arc::new(Hang("long_path"));
    let start = Instant::now();
    let t = target(
        &lit(r"C:\PROFILES\U~1"),
        &loc,
        &EnvView::new(),
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
    let r = target(&glob("*"), &loc, &env, &hang, &Deadline::new(start, 100));
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
        target(&w, &loc, &EnvView::new(), &fs, &far()),
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
        target(&lit(text), &loc, &EnvView::new(), &fs, &far())
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
    let mut loc = base.clone();
    loc.after(&stmt(lits("net", &["view"]), Some(ChainOp::Seq)), &env);
    assert_eq!(resolve(&x, &loc, &env), paths(&[r"X:\sub"]));
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
    // A relative target in a folder a variable chose: `cd $x; rm -rf ..`, `$PWD\x`.
    let mut loc = base.clone();
    loc.after(&stmt(cmd("cd", vec![var("x")]), seq), &env);
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
    // A folder a variable chose is as dynamic as the variable.
    unknown_as(DYNAMIC_LOCATION, vec![stmt(cmd("cd", vec![var("x")]), seq)]);
    let mut opaque = lits("x", &[]);
    opaque.opaque = true;
    unknown_as(DYNAMIC_LOCATION, vec![stmt(opaque, seq)]);
    // Where both apply, the location may be critical.
    unknown_after(vec![
        stmt(cmd("cd", vec![var("x")]), seq),
        stmt(lits("cd", &["sub*"]), seq),
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
    unknown_after(vec![stmt(cmd("echo", vec![arg]), seq)]);
    // A statement without a location change keeps it.
    let mut loc = base.clone();
    loc.after(&stmt(lits("echo", &["x"]), seq), &env);
    assert_eq!(resolve(&rel, &loc, &env), paths(&[r"C:\w\repo\y"]));
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
