//! The delete guard, the git rules and the allow marker through `analyse`, against a real
//! fixture tree: `tests/cases/delete.toml` and `tests/cases/git.toml` (their headers describe the
//! tree and the row conventions), the marker's exemptions on real parses, and `SHELLWISE=off`
//! through the spawned binary.

mod case_loader;
mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use case_loader::Row;
use shellwise::config::Config;
use shellwise::fs::resolve::env_view;
use shellwise::level::{Finding, Level, Span, Verdict};
use shellwise::rules::marker;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

// ---------------------------------------------------------------- the fixture

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn at(&self, rel: &str) -> PathBuf {
        self.root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    /// The FX_ names, longest first so none is replaced inside another.
    fn names(&self) -> [(&'static str, PathBuf); 9] {
        [
            ("FX_LINKED", self.at(LINKED)),
            ("FX_MAIN", self.at("main")),
            ("FX_PROTECTED", self.at("protected")),
            ("FX_OUTSIDE", self.at("outside")),
            ("FX_ALLOWED", self.at("allowed")),
            ("FX_NOREPO", self.at("norepo")),
            ("FX_REPO", self.at("repo")),
            ("FX_HOME", self.at("home")),
            ("FX_ROOT", self.root.clone()),
        ]
    }

    /// `command` with every FX_ name replaced by its path; forward slashes for bash.
    fn substitute(&self, command: &str, bash: bool) -> String {
        let mut out = command.to_string();
        for (name, path) in self.names() {
            let mut text = path.to_string_lossy().into_owned();
            if bash {
                text = text.replace('\\', "/");
            }
            out = out.replace(name, &text);
        }
        out
    }
}

fn mkdir(p: &Path) {
    std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("create {p:?}: {e}"));
}

fn touch(p: &Path) {
    mkdir(p.parent().unwrap());
    std::fs::write(p, b"x").unwrap_or_else(|e| panic!("write {p:?}: {e}"));
}

/// A linked worktree of the real repo FX_MAIN, where an agent host puts its own (item 5).
const LINKED: &str = "main/.claude/worktrees/lw";
/// A linked worktree of FX_MAIN beside it, not inside it.
const SIBLING: &str = "sibling";
/// A folder link to LINKED, outside the repos.
const LINKED_LINK: &str = "lwlink";

/// `git` with `args` in `dir`, which must succeed. The identity is passed per call, so no
/// config is read or written.
fn git(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
    assert!(out.status.success(), "git {args:?} in {dir:?}: {out:?}");
}

/// Give `p` the Hidden attribute on Windows; elsewhere a dot name is hidden already.
fn hide(p: &Path) {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("attrib")
            .arg("+h")
            .arg(p)
            .output()
            .unwrap_or_else(|e| panic!("attrib {p:?}: {e}"));
        assert!(out.status.success(), "attrib +h {p:?}: {out:?}");
    }
    #[cfg(not(windows))]
    let _ = p;
}

/// A folder link: a junction on Windows, a symlink elsewhere.
fn dir_link(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(out.status.success(), "mklink /J {link:?}: {out:?}");
    }
    #[cfg(not(windows))]
    std::os::unix::fs::symlink(target, link).unwrap();
}

/// Remove a folder link without touching its target.
fn unlink(link: &Path) {
    #[cfg(windows)]
    let _ = std::fs::remove_dir(link);
    #[cfg(not(windows))]
    let _ = std::fs::remove_file(link);
}

/// A folder nobody may list: the walk of a recursive delete above it cannot read it.
const LOCKED: &str = "repo/locked/inner";

#[cfg(windows)]
fn icacls(p: &Path, args: &[&str]) {
    // `*S-1-1-0` is Everyone: a deny for it holds for the account the tests run as.
    let out = std::process::Command::new("icacls")
        .arg(p)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls {p:?} {args:?}: {out:?}");
}

fn lock(p: &Path) {
    #[cfg(windows)]
    icacls(p, &["/deny", "*S-1-1-0:(RD)"]);
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
}

fn unlock(p: &Path) {
    if !p.exists() {
        return;
    }
    #[cfg(windows)]
    icacls(p, &["/remove:d", "*S-1-1-0"]);
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

const LINKS: [(&str, &str); 5] = [
    ("repolink", "repo"),
    ("repo/linked/out", "outside/target"),
    ("repo/jn", "outside/target"),
    ("repo/wt/node_modules", "outside/target"),
    ("allowed/box", "outside/target"),
];

impl Fixture {
    /// Remove the tree: each link first (so nothing is deleted through it), the locked folder
    /// opened, then the rest.
    fn remove(&self) {
        for (link, _) in LINKS {
            unlink(&self.at(link));
        }
        unlink(&self.at(LINKED_LINK));
        unlock(&self.at(LOCKED));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.remove();
    }
}

/// The fixture, shared by the tests that run at the same time and removed when the last of them
/// drops it: each test holds it for its whole body. A static that never drops would leave one
/// tree per run in the temp folder.
fn fixture() -> Arc<Fixture> {
    static LIVE: Mutex<Weak<Fixture>> = Mutex::new(Weak::new());
    static BUILT: AtomicUsize = AtomicUsize::new(0);
    let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(fx) = live.upgrade() {
        return fx;
    }
    let n = BUILT.fetch_add(1, Ordering::SeqCst);
    let fx = Arc::new({
        let root =
            std::env::temp_dir().join(format!("shellwise-delete-{}-{n}", std::process::id()));
        assert!(
            !root.to_string_lossy().contains(' '),
            "the fixture path {root:?} holds a space; the rows write paths unquoted"
        );
        let fx = Fixture { root };
        if fx.root.exists() {
            fx.remove();
        }
        for dir in [
            "repo/.git",
            "plaingit/.git",
            "repo/build",
            "repo/linked",
            "repo/wt-clean/src",
            "norepo/sub",
            "outside/data",
            "outside/target",
            "allowed/tmp1",
            "home",
            "protected",
        ] {
            mkdir(&fx.at(dir));
        }
        for file in [
            "repo/build/x.o",
            "repo/src/a.txt",
            "repo/clean/f.txt",
            "repo/wt/src/m.js",
            "norepo/sub/f.txt",
            "outside/data/f.txt",
            "outside/target/keep.txt",
            "allowed/tmp1/f.txt",
            "home/f.txt",
            "home/build/x.o",
            "protected/config.toml",
        ] {
            touch(&fx.at(file));
        }
        for (link, target) in LINKS {
            dir_link(&fx.at(link), &fx.at(target));
        }
        // `git init` on Windows hides `.git`; the `plaingit-` repo keeps it plain, as WSL git
        // or a copied repo leaves it (R1-6).
        hide(&fx.at("repo/.git"));
        // A real repo with a real linked worktree: its `.git` is a file naming the main one's.
        mkdir(&fx.at("main"));
        git(&fx.at("main"), &["init", "-q"]);
        git(
            &fx.at("main"),
            &["commit", "-q", "--allow-empty", "-m", "init"],
        );
        let linked = LINKED.trim_start_matches("main/");
        git(
            &fx.at("main"),
            &["worktree", "add", "-q", "--detach", linked],
        );
        assert!(fx.at(LINKED).join(".git").is_file());
        // A linked worktree beside the main tree instead of inside it.
        git(
            &fx.at("main"),
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                &format!("../{SIBLING}"),
            ],
        );
        assert!(fx.at(SIBLING).join(".git").is_file());
        dir_link(&fx.at(LINKED_LINK), &fx.at(LINKED));
        touch(&fx.at(&format!("{LOCKED}/f.txt")));
        lock(&fx.at(LOCKED));
        if let Some(repo) = fx
            .at("norepo")
            .ancestors()
            .find(|d| d.join(".git").exists())
        {
            panic!("the non-repo fixture lies inside the repo {repo:?}");
        }
        fx
    });
    *live = Arc::downgrade(&fx);
    fx
}

/// Two runs of a test that builds the fixture leave the temp folder as empty as they found it.
/// The child runs see a temp folder of their own, so other runs on the machine do not count.
#[test]
fn the_fixture_is_removed_when_its_tests_end() {
    let temp = std::env::temp_dir().join(format!("shellwise-fixture-leak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    mkdir(&temp);
    let exe = std::env::current_exe().unwrap();
    let mut counts = Vec::new();
    for _ in 0..2 {
        let out = std::process::Command::new(&exe)
            .args(["--exact", "git_rows", "--test-threads=1"])
            .env("TEMP", &temp)
            .env("TMP", &temp)
            .env("TMPDIR", &temp)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the child run: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        counts.push(std::fs::read_dir(&temp).unwrap().count());
    }
    let left: Vec<PathBuf> = std::fs::read_dir(&temp)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let _ = std::fs::remove_dir_all(&temp);
    assert_eq!(counts, [0, 0], "left in the temp folder: {left:?}");
}

/// The 8.3 short spelling of `p`, which exists, by `GetShortPathNameW`.
#[cfg(windows)]
fn short_path(p: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let name: Vec<u16> = p.as_os_str().encode_wide().chain([0]).collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: `name` is NUL-terminated; `buf` is writable for the length passed.
    let n = unsafe { GetShortPathNameW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    assert!(
        n > 0 && (n as usize) < buf.len(),
        "GetShortPathNameW {p:?}: {}",
        std::io::Error::last_os_error()
    );
    buf.truncate(n as usize);
    PathBuf::from(OsString::from_wide(&buf))
}

/// A `TEMP` given in its 8.3 short spelling, as on GitHub's Windows runners
/// (`C:\LONGFO~1\Temp`): the fixture then lies under the short spelling while the paths the
/// rules resolve are long, and every row still reads as with a long `TEMP`.
#[cfg(windows)]
#[test]
fn the_rows_hold_with_a_short_temp_spelling() {
    let long = std::env::temp_dir().join(format!("shellwise-short-temp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&long);
    mkdir(&long);
    let short = short_path(&long);
    if short
        .to_string_lossy()
        .eq_ignore_ascii_case(&long.to_string_lossy())
    {
        let _ = std::fs::remove_dir_all(&long);
        // Straight to stderr: the test runner captures `println!` of a passing test.
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "SKIP the_rows_hold_with_a_short_temp_spelling: {long:?} has no 8.3 short name (8.3 names are off on this volume)"
        );
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let mut wrong = Vec::new();
    for test in ["delete_rows", "git_rows"] {
        let out = std::process::Command::new(&exe)
            .args(["--exact", test, "--test-threads=1"])
            .env("TEMP", &short)
            .env("TMP", &short)
            .env("TMPDIR", &short)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !(out.status.success() && stdout.contains("test result: ok. 1 passed;")) {
            wrong.push(format!(
                "{test} with TEMP={short:?}: {stdout} {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&long);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// ---------------------------------------------------------------- running a row

/// The config of a row: the fixture's allowed root and protected path, and the no-verify
/// policy on unless the id starts with `policy-off-`.
fn config(row: &Row) -> Config {
    let fx = fixture();
    let mut cfg = Config {
        allowed_roots: vec![fx.at("allowed")],
        protected: vec![fx.at("protected")],
        ..Config::default()
    };
    cfg.policies.git_no_verify = !row.id.starts_with("policy-off-");
    // A protected path inside the linked worktree (item 5).
    // A protected path inside the linked worktree, the worktree itself, or a junction to it
    // (matched by identity only) (item 5).
    if row.id.starts_with("linkedwt-protected-inside-") {
        cfg.protected.push(fx.at(LINKED).join("keep"));
    } else if row.id.starts_with("linkedwt-protected-exact-") {
        cfg.protected.push(fx.at(LINKED));
    } else if row.id.starts_with("linkedwt-protected-link-") {
        cfg.protected.push(fx.at(LINKED_LINK));
    }
    if row.id.starts_with("scratch-") {
        cfg.scratch_dir = Some(fx.at("outside"));
    }
    cfg
}

const UNC_CWD: &str = r"\\192.0.2.1\share\repo";
/// The admin share of drive C on this machine: a drive root under a share spelling.
const ADMIN_SHARE_CWD: &str = r"\\localhost\C$";

fn cwd(row: &Row) -> Option<PathBuf> {
    let fx = fixture();
    if row.id.starts_with("nocwd-") {
        None
    } else if row.id.starts_with("norepo-") {
        Some(fx.at("norepo"))
    } else if row.id.starts_with("linkedwt-") {
        Some(fx.at(LINKED))
    } else if row.id.starts_with("mainwt-") {
        Some(fx.at("main"))
    } else if row.id.starts_with("sibwt-") {
        Some(fx.at(SIBLING))
    } else if row.id.starts_with("plaingit-") {
        Some(fx.at("plaingit"))
    } else if row.id.starts_with("admincwd-") {
        Some(PathBuf::from(ADMIN_SHARE_CWD))
    } else if row.id.starts_with("unccwd-") {
        // A documentation address no host answers: a file-system call there runs out of time.
        Some(PathBuf::from(UNC_CWD))
    } else {
        Some(fx.at("repo"))
    }
}

/// `command` with each `GEN_<kind>_<n>` written out as the statements `tests/cases/delete.toml`
/// describes before its alias cap and bound rows, joined by `; `.
fn generated(command: &str) -> String {
    let mut out = command.to_string();
    while let Some(at) = out.find("GEN_") {
        let rest = &out[at + 4..];
        // `<KIND>_<n>`: the kind is upper case and `_`, the count follows its last `_`.
        let head: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
            .collect();
        let kind = head
            .strip_suffix('_')
            .unwrap_or_else(|| panic!("{command}: GEN_ without a kind"))
            .to_string();
        let digits: String = rest[head.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let n: usize = digits
            .parse()
            .unwrap_or_else(|_| panic!("{command}: GEN_{kind} without a count"));
        let digits_at = head.len();
        let statements: Vec<String> = match kind.as_str() {
            "CHAIN" => (0..n)
                .map(|i| {
                    let value = if i + 1 == n {
                        "Remove-Item".to_string()
                    } else {
                        format!("a{:03}", i + 1)
                    };
                    format!("Set-Alias a{i:03} {value}")
                })
                .collect(),
            "REDEFINE" => (0..n)
                .map(|i| {
                    if i + 1 == n {
                        "Set-Alias zz Remove-Item".to_string()
                    } else {
                        format!("Set-Alias zz Get-A{i:03}")
                    }
                })
                .collect(),
            "DISTINCT" => (0..n)
                .map(|i| format!("Set-Alias a{i:03} Remove-Item"))
                .collect(),
            "CALLS" => (0..n)
                .map(|i| format!("zz FX_REPO\\build\\x{i:03} -Recurse -Force"))
                .collect(),
            "DEFINER_CALLS" => (0..n)
                .map(|i| format!("sa b{i:03} Get-ChildItem"))
                .collect(),
            k => panic!("{command}: unknown GEN_ kind {k}"),
        };
        let token_len = 4 + digits_at + digits.len();
        out.replace_range(at..at + token_len, &statements.join("; "));
    }
    out
}

fn verdict(row: &Row) -> Verdict {
    let fx = fixture();
    let shell = row.shell();
    let os = Os::host();
    let command = fx.substitute(&generated(&row.command), row.is_bash());
    let home = fx.at("home").to_string_lossy().into_owned();
    let temp = fx.at("allowed").to_string_lossy().into_owned();
    let env = env_view(
        shell,
        os,
        [
            ("USERPROFILE".to_string(), home.clone()),
            ("HOME".to_string(), home),
            ("TEMP".to_string(), temp.clone()),
            ("TMP".to_string(), temp),
        ],
    );
    let input = AnalyseInput {
        bytes: command.as_bytes(),
        shell,
        os,
        cwd: cwd(row),
        env,
        origin: Origin::CommandLine,
        problem: None,
    };
    analyse(&input, &config(row), &Deadline::new(Instant::now(), 8000))
}

fn mismatch(row: &Row) -> Option<String> {
    let v = verdict(row);
    let rules: Vec<&str> = v.findings.iter().map(|f| f.rule).collect();
    let mut wrong = Vec::new();
    if v.level.as_str() != row.level {
        wrong.push(format!("level {} (want {})", v.level.as_str(), row.level));
    }
    if rules != row.rules {
        wrong.push(format!("rules {rules:?} (want {:?})", row.rules));
    }
    if let Some(want) = &row.fix {
        let line = v.findings.first().and_then(|f| f.fix_line());
        if !line.as_deref().is_some_and(|l| l.contains(want.as_str())) {
            wrong.push(format!("fix line {line:?} (want one holding {want:?})"));
        }
    }
    (!wrong.is_empty()).then(|| {
        let messages: Vec<&str> = v.findings.iter().map(|f| f.message.as_str()).collect();
        format!("{}: {} {messages:?}", row.id, wrong.join("; "))
    })
}

fn run_file(name: &str) {
    let _fx = fixture();
    let rows = case_loader::rows(name);
    let wrong: Vec<String> = rows.iter().filter_map(mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("{name}: {} rows ran", rows.len());
}

#[test]
fn generated_statements_are_the_ones_the_header_describes() {
    assert_eq!(
        generated("GEN_CHAIN_3; a000 x"),
        "Set-Alias a000 a001; Set-Alias a001 a002; Set-Alias a002 Remove-Item; a000 x"
    );
    assert_eq!(
        generated("GEN_REDEFINE_2; GEN_DISTINCT_1"),
        "Set-Alias zz Get-A000; Set-Alias zz Remove-Item; Set-Alias a000 Remove-Item"
    );
    assert_eq!(
        generated("GEN_CALLS_1; GEN_DEFINER_CALLS_1"),
        "zz FX_REPO\\build\\x000 -Recurse -Force; sa b000 Get-ChildItem"
    );
}

#[test]
fn delete_rows() {
    run_file("delete.toml");
}

#[test]
fn git_rows() {
    run_file("git.toml");
}

#[test]
fn arith_twin_rows() {
    run_file("arith_twins.toml");
}

/// Ruling 161: arithmetic around a substitution or a name changes no verdict. Each row's command
/// gives the rule ids of its plain twin, in the same fixture cwd.
#[test]
fn arithmetic_reads_like_its_plain_twin() {
    let _fx = fixture();
    let rows = case_loader::rows("arith_twins.toml");
    let ids =
        |row: &Row| -> Vec<&'static str> { verdict(row).findings.iter().map(|f| f.rule).collect() };
    let mut wrong = Vec::new();
    for row in &rows {
        let twin = row
            .twin
            .clone()
            .unwrap_or_else(|| panic!("{}: no twin", row.id));
        let plain = Row {
            command: twin,
            twin: None,
            ..row.clone()
        };
        let (got, want) = (ids(row), ids(&plain));
        if got != want {
            wrong.push(format!("{}: {got:?} (its twin {want:?})", row.id));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} rows differ from their twin:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("arith_twins.toml: {} twins read alike", rows.len());
}

/// A child shell's body reads the same behind any redirect or pipe as bare: every carrier the
/// delete rule reads, wrappers before it, the body as a quoted word or a process substitution,
/// times every redirect form, for a body that deletes the home folder, one that deletes a
/// relative folder and a harmless one, with the bare form's messages.
#[test]
fn a_child_body_behind_a_redirect_reads_as_the_bare_form() {
    let _fx = fixture();
    const BASH: [(&str, &str, &str); 3] = [
        ("rm -rf ~", "danger", "opaque-destructive"),
        ("rm -rf build", "warn", "opaque-destructive"),
        ("echo hi", "ok", ""),
    ];
    const PWSH: [(&str, &str, &str); 3] = [
        (
            "Remove-Item -Recurse -Force ~",
            "danger",
            "opaque-destructive",
        ),
        (
            "Remove-Item -Recurse -Force build",
            "warn",
            "opaque-destructive",
        ),
        ("Write-Output hi", "ok", ""),
    ];
    // The carrier's words before the body, the word that holds the body (`{b}`), and whether
    // the body is PowerShell. A quoted word is read at the bare levels of BASH and PWSH; a
    // process substitution is a script operand, read as its bare form, which is never ok for
    // the home folder.
    const QUOTED: &str = "'{b}'";
    const FED: &str = "<(echo '{b}')";
    let carriers: [(&str, &str, bool); 19] = [
        ("bash -c", QUOTED, false),
        ("sh -c", QUOTED, false),
        ("zsh -c", QUOTED, false),
        ("eval", QUOTED, false),
        ("pwsh -Command", QUOTED, true),
        ("sudo bash -c", QUOTED, false),
        ("env A=1 bash -c", QUOTED, false),
        ("nohup bash -c", QUOTED, false),
        ("timeout 60 bash -c", QUOTED, false),
        ("time bash -c", QUOTED, false),
        ("bash", FED, false),
        ("sh", FED, false),
        ("zsh", FED, false),
        ("bash -x", FED, false),
        ("sudo bash", FED, false),
        ("env A=1 bash", FED, false),
        ("nohup bash", FED, false),
        ("timeout 60 bash", FED, false),
        ("time bash", FED, false),
    ];
    let after = [
        " 2>&1",
        " > log",
        " 2>/dev/null",
        " >> log",
        " &> log",
        " > \"$log\"",
        " > log 2>&1 2>/dev/null",
        " 2>&1 | tail -5",
        " | tee log",
        " <<< x",
        " <<'EOF'\nhi\nEOF",
    ];
    let shells: &[&str] = if cfg!(windows) {
        &["bash", "gitbash"]
    } else {
        &["bash"]
    };
    let read = |shell: &str, command: String| {
        let row = Row {
            id: command.clone(),
            os: "any".to_string(),
            shell: shell.to_string(),
            command,
            level: String::new(),
            rules: Vec::new(),
            fix: None,
            fix_exact: None,
            oracle: None,
            config: None,
            twin: None,
        };
        let v = verdict(&row);
        let ids: Vec<&'static str> = v.findings.iter().map(|f| f.rule).collect();
        let messages: Vec<String> = v.findings.iter().map(|f| f.message.clone()).collect();
        (v.level.as_str().to_string(), ids, messages)
    };
    let mut wrong = Vec::new();
    let mut cells = 0;
    for &shell in shells {
        for (carrier, word, pwsh) in carriers {
            for (body, level, rule) in if pwsh { PWSH } else { BASH } {
                let word = word.replace("{b}", body);
                let bare = format!("{carrier} {word}");
                let want = read(shell, bare.clone());
                let want_ids: Vec<&str> = [rule].into_iter().filter(|r| !r.is_empty()).collect();
                let bare_wrong = if word.starts_with('<') {
                    body.contains('~') && want.0 == "ok"
                } else {
                    (want.0.as_str(), want.1.clone()) != (level, want_ids)
                };
                if bare_wrong {
                    wrong.push(format!("[{shell}] bare {bare:?}: {} {:?}", want.0, want.1));
                }
                let mut forms: Vec<String> = after.iter().map(|a| format!("{bare}{a}")).collect();
                // A redirect after each of the carrier's words, the body's option included.
                let words: Vec<&str> = carrier.split(' ').collect();
                for at in 1..=words.len() {
                    let (head, tail) = words.split_at(at);
                    let tail = tail.iter().map(|w| format!(" {w}")).collect::<String>();
                    forms.push(format!("{} 2>&1{tail} {word}", head.join(" ")));
                }
                // Known miss of another cause: a redirect before `time` makes it a program
                // (delete.toml `known-miss-redirect-before-time-program`).
                if !carrier.starts_with("time ") {
                    forms.push(format!("2>/dev/null {bare}"));
                    forms.push(format!("> log {bare}"));
                }
                for text in forms {
                    cells += 1;
                    let got = read(shell, text.clone());
                    if got != want {
                        wrong.push(format!(
                            "[{shell}] {text:?}: {} {:?} {:?} (bare {} {:?} {:?})",
                            got.0, got.1, got.2, want.0, want.1, want.2
                        ));
                    }
                }
            }
        }
    }
    // Away from the start of the command: in a list, a substitution, a compound, a later line,
    // after a non-ASCII word, piped into, in an unquoted heredoc's substitution.
    let contexts = [
        "cd build && {c}",
        "x=$({c})",
        "x=`{c}`",
        "( {c} )",
        "if true; then {c}; fi",
        "f() { {c}; }; f",
        "echo one\n{c}",
        "echo zażółć && {c}",
        "echo x | {c}",
        "cat <<EOF\n$({c})\nEOF",
    ];
    let pairs = [
        ("bash -c 'rm -rf ~'", "bash -c 'rm -rf ~' 2>&1"),
        ("sudo bash -c 'rm -rf ~'", "sudo bash 2>&1 -c 'rm -rf ~'"),
    ];
    for &shell in shells {
        for ctx in contexts {
            for (bare, redirected) in pairs {
                let want = read(shell, ctx.replace("{c}", bare));
                if want.0 != "danger" {
                    wrong.push(format!(
                        "[{shell}] bare in {ctx:?}: {} {:?}",
                        want.0, want.1
                    ));
                }
                cells += 1;
                let text = ctx.replace("{c}", redirected);
                let got = read(shell, text.clone());
                if got != want {
                    wrong.push(format!("[{shell}] {text:?}: {got:?} (bare {want:?})"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {cells} cells differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!("{cells} redirected child bodies read as their bare form");
}

/// The opaque-destructive message quotes a command as written where its text holds its words: a
/// Bash command with no redirect (its spacing kept) and a PowerShell one (its call operator and
/// redirect kept).
#[test]
fn an_unread_command_is_quoted_as_written() {
    let _fx = fixture();
    let cases = [
        ("bash", "bash -c  'rm -rf ~'", "`bash -c  'rm -rf ~'`"),
        (
            "pwsh",
            "Set-Alias zz Remove-Item; & { zz ~ -Recurse -Force } 2>&1",
            "`& { zz ~ -Recurse -Force } 2>&1`",
        ),
    ];
    for (shell, command, quoted) in cases {
        let row = Row {
            id: command.to_string(),
            os: "any".to_string(),
            shell: shell.to_string(),
            command: command.to_string(),
            level: String::new(),
            rules: Vec::new(),
            fix: None,
            fix_exact: None,
            oracle: None,
            config: None,
            twin: None,
        };
        let v = verdict(&row);
        let messages: Vec<&str> = v
            .findings
            .iter()
            .filter(|f| f.rule == "opaque-destructive")
            .map(|f| f.message.as_str())
            .collect();
        assert!(
            messages.len() == 1 && messages[0].contains(quoted),
            "{command:?}: {messages:?} (want one quoting {quoted})"
        );
    }
}

/// An assignment before a child shell's carrier changes nothing: every carrier the delete rule
/// reads, wrappers before it, the body as a quoted word or a process substitution, behind every
/// assignment shape, bare and behind a redirect, reads as the carrier without the assignment:
/// level, rule ids, and the messages but for the assignment text. A value is data: one that holds
/// delete text fires nothing of its own.
#[test]
fn a_child_body_behind_an_assignment_reads_as_the_bare_form() {
    let _fx = fixture();
    // The body, and the bare carrier's level and rule ids for it: a quoted word, then a process
    // substitution (a script operand: warn whatever it deletes).
    const BASH: [(&str, [&str; 2]); 3] = [
        ("rm -rf ~", ["danger", "warn"]),
        ("rm -rf build", ["warn", "warn"]),
        ("echo hi", ["ok", "ok"]),
    ];
    const PWSH: [(&str, [&str; 2]); 3] = [
        ("Remove-Item -Recurse -Force ~", ["danger", "warn"]),
        ("Remove-Item -Recurse -Force build", ["warn", "warn"]),
        ("Write-Output hi", ["ok", "ok"]),
    ];
    const QUOTED: &str = "'{b}'";
    const FED: &str = "<(echo '{b}')";
    let carriers: [(&str, &str, bool); 19] = [
        ("bash -c", QUOTED, false),
        ("sh -c", QUOTED, false),
        ("zsh -c", QUOTED, false),
        ("eval", QUOTED, false),
        ("pwsh -Command", QUOTED, true),
        ("sudo bash -c", QUOTED, false),
        ("env A=1 bash -c", QUOTED, false),
        ("nohup bash -c", QUOTED, false),
        ("timeout 60 bash -c", QUOTED, false),
        ("time bash -c", QUOTED, false),
        ("bash", FED, false),
        ("sh", FED, false),
        ("zsh", FED, false),
        ("bash -x", FED, false),
        ("sudo bash", FED, false),
        ("env A=1 bash", FED, false),
        ("nohup bash", FED, false),
        ("timeout 60 bash", FED, false),
        ("time bash", FED, false),
    ];
    let assignments = [
        "X=ab",
        "X=a\\ b",
        "X=\"ab\"",
        "X='a b'",
        "X=$'a b'",
        "X=\"\"",
        "X=''",
        "MSG=\"hello world\"",
        "X=\"a=b\"",
        "X=\"it's\"",
        "X='say \"hi\"'",
        "X=\"$(date)\"",
        "X=\"`date`\"",
        "X=\"${V:-d}\"",
        "X=$(date)",
        "X=\"a b\" Y='c d'",
        "X=ab Y=\"c d\"",
        "X+=\"a b\"",
        "X+=ab",
        "A=(a b)",
        "CMD=\"rm -rf ~\"",
        "CMD='Remove-Item -Recurse -Force ~'",
    ];
    let shells: &[&str] = if cfg!(windows) {
        &["bash", "gitbash"]
    } else {
        &["bash"]
    };
    let read = |shell: &str, command: String| {
        let row = Row {
            id: command.clone(),
            os: "any".to_string(),
            shell: shell.to_string(),
            command,
            level: String::new(),
            rules: Vec::new(),
            fix: None,
            fix_exact: None,
            oracle: None,
            config: None,
            twin: None,
        };
        let v = verdict(&row);
        let ids: Vec<&'static str> = v.findings.iter().map(|f| f.rule).collect();
        let messages: Vec<String> = v.findings.iter().map(|f| f.message.clone()).collect();
        (v.level.as_str().to_string(), ids, messages)
    };
    // A message quotes the command's first 80 characters as written: that quote is compared
    // as present, the rest of the message word for word.
    let unquoted = |messages: &[String], text: &str| -> Vec<String> {
        let shown: String = text.chars().take(80).collect();
        messages
            .iter()
            .map(|m| m.replacen(&format!("`{shown}`"), "`<command>`", 1))
            .collect()
    };
    let mut wrong = Vec::new();
    let mut cells = 0;
    for &shell in shells {
        for (carrier, word, pwsh) in carriers {
            // Known miss of another cause: after an assignment `time` is a program, not bash's
            // keyword (delete.toml `known-miss-assignment-before-time-program`).
            if carrier.starts_with("time ") {
                continue;
            }
            for (body, levels) in if pwsh { PWSH } else { BASH } {
                let word = word.replace("{b}", body);
                let bare = format!("{carrier} {word}");
                let level = levels[usize::from(word.starts_with('<'))];
                let want = read(shell, bare.clone());
                let want_ids: Vec<&str> = if level == "ok" {
                    Vec::new()
                } else {
                    vec!["opaque-destructive"]
                };
                if (want.0.as_str(), want.1.clone()) != (level, want_ids) {
                    wrong.push(format!(
                        "[{shell}] bare {bare:?}: {} {:?} (want {level})",
                        want.0, want.1
                    ));
                }
                // The bare carrier behind each redirect form, read with the same assignment.
                let first = carrier.split(' ').next().unwrap_or(carrier);
                let rest = &carrier[first.len()..];
                let forms = [
                    bare.clone(),
                    format!("{bare} 2>&1"),
                    format!("{bare} > log"),
                    format!("{first} 2>&1{rest} {word}"),
                    format!("2>/dev/null {{a}} {bare}"),
                ];
                for form in forms {
                    let bare_text = form.replace("{a} ", "");
                    let bare_form = read(shell, bare_text.clone());
                    if form != bare && (bare_form.0.as_str(), &bare_form.1) != (level, &want.1) {
                        wrong.push(format!(
                            "[{shell}] bare {bare_text:?}: {} {:?} (want {level})",
                            bare_form.0, bare_form.1
                        ));
                    }
                    let bare_messages = unquoted(&bare_form.2, &bare_text);
                    for assign in assignments {
                        // Known over-read of another cause: the scan's PowerShell reading takes
                        // the backtick for its escape, so the value's closing quote is escaped and
                        // the rest reads as code (delete.toml
                        // `known-over-read-backtick-value-before-procsub`).
                        if assign.contains('`') && word.starts_with('<') && body.contains('~') {
                            continue;
                        }
                        let text = if form.contains("{a}") {
                            form.replace("{a}", assign)
                        } else {
                            format!("{assign} {form}")
                        };
                        cells += 1;
                        let got = read(shell, text.clone());
                        let messages = unquoted(&got.2, &text);
                        if (&got.0, &got.1, &messages)
                            != (&bare_form.0, &bare_form.1, &bare_messages)
                        {
                            wrong.push(format!(
                                "[{shell}] {text:?}: {} {:?} {:?} (bare {} {:?} {:?})",
                                got.0, got.1, got.2, bare_form.0, bare_form.1, bare_form.2
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {cells} cells differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!("{cells} child bodies behind an assignment read as their bare form");
}

/// Rows ported from the baseline guard's tests/test_rules.py, per rule, as git.toml's header records
/// them (every OS counted).
const PORTED: [(&str, usize); 3] = [
    ("sg-restore-", 12),
    ("sg-noverify-", 24),
    ("sg-unreadable-", 6),
];

#[test]
fn ported_rows_keep_their_count() {
    let path = format!("{}/tests/cases/git.toml", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    let table: toml::Table = toml::from_str(&text).unwrap();
    let ids: Vec<String> = table["row"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["id"]
                .as_str()
                .unwrap()
                .trim_start_matches("nocwd-")
                .to_string()
        })
        .collect();
    assert!(!ids.is_empty(), "git.toml: no rows");
    for (prefix, want) in PORTED {
        let got = ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert_eq!(got, want, "{prefix} rows");
    }
}

/// Every finding id the two rules report (`tests/rules_meta.rs` sees only each rule's own id).
const FINDING_IDS: [&str; 16] = [
    shellwise::rules::delete::DELETE_CRITICAL,
    shellwise::rules::delete::DELETE_EMPTY_EXPANSION,
    shellwise::rules::delete::DELETE_REPO_CONTENTS,
    shellwise::rules::delete::DELETE_THROUGH_LINK,
    shellwise::rules::delete::DELETE_OUTSIDE_PROJECT,
    shellwise::rules::delete::DELETE_ALLOWED_ROOT,
    shellwise::rules::delete::DELETE_UNKNOWN_LOCATION,
    shellwise::rules::delete::DYNAMIC_TARGET,
    shellwise::rules::delete::WALK_TIMEOUT,
    shellwise::rules::delete::WALK_UNREADABLE,
    shellwise::rules::delete::OPAQUE_DESTRUCTIVE,
    shellwise::rules::git::GIT_RESTORE_DISCARDS,
    shellwise::rules::git::GIT_WORKTREE_JUNCTION,
    shellwise::rules::git::GIT_DISCARD,
    shellwise::rules::git::GIT_NO_VERIFY,
    shellwise::rules::git::GIT_UNREADABLE,
];

/// `walk-timeout` is reported only when a walk sees the deadline pass while the worker still
/// answers before it: `analyse` waits on the same deadline, so the verdict is then
/// `analysis-incomplete`, danger from the raw scan of the delete. No case row can pin that race;
/// `tests/delete_deadline.rs` forces a repo lookup to time out through a test hook instead.
const NO_ROW: [&str; 1] = [shellwise::rules::delete::WALK_TIMEOUT];

/// Findings that are only ever warn (Ruling 122): a row where they fire stands in for the deny row.
const WARN_ONLY: [&str; 5] = [
    shellwise::rules::delete::DELETE_OUTSIDE_PROJECT,
    shellwise::rules::delete::DELETE_ALLOWED_ROOT,
    shellwise::rules::delete::DELETE_UNKNOWN_LOCATION,
    shellwise::rules::delete::DYNAMIC_TARGET,
    shellwise::rules::git::GIT_UNREADABLE,
];

#[test]
fn every_finding_id_has_a_deny_row_a_row_without_it_and_a_doc() {
    let mut rows: Vec<toml::Value> = Vec::new();
    for name in ["delete.toml", "git.toml"] {
        let path = format!("{}/tests/cases/{name}", env!("CARGO_MANIFEST_DIR"));
        let table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        rows.extend(table["row"].as_array().unwrap().iter().cloned());
    }
    assert!(rows.len() > 100, "{} rows", rows.len());
    let fires = |r: &toml::Value, id: &str| {
        r["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str() == Some(id))
    };
    let mut wrong = Vec::new();
    for id in FINDING_IDS {
        let doc = format!("{}/docs/rules/{id}.md", env!("CARGO_MANIFEST_DIR"));
        if !Path::new(&doc).is_file() {
            wrong.push(format!("{id}: no doc"));
        }
        if NO_ROW.contains(&id) {
            continue;
        }
        let want: &[&str] = if WARN_ONLY.contains(&id) {
            &["warn"]
        } else {
            &["danger", "critical"]
        };
        let deny = rows
            .iter()
            .any(|r| fires(r, id) && want.contains(&r["level"].as_str().unwrap()));
        if !deny || rows.iter().all(|r| fires(r, id)) {
            wrong.push(format!("{id}: no deny row, or no row without it"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// ---------------------------------------------------------------- the marker's exemptions

fn found(rule: &'static str, level: Level) -> Finding {
    Finding {
        rule,
        level,
        message: String::new(),
        fix: Some("x".to_string()),
        span: Span::default(),
    }
}

#[test]
fn the_marker_confirms_only_break_and_danger_of_other_rules() {
    let text = "echo hi # shellwise: allow";
    let script = shellwise::parse::bash::parse(text, BashProfile::GitBash).expect("parses");
    assert!(marker::is_marked(&script, text));
    let table = [
        // (rule, level before, level after)
        ("delete-outside-project", Level::Danger, Level::Ok),
        ("some-lint", Level::Break, Level::Ok),
        ("some-lint", Level::Warn, Level::Warn),
        ("delete-critical", Level::Critical, Level::Critical),
        ("too-long", Level::Break, Level::Break),
        ("inline-script-too-long", Level::Break, Level::Break),
        ("parse-error", Level::Danger, Level::Danger),
        ("parse-error-destructive", Level::Danger, Level::Danger),
        ("analysis-incomplete", Level::Danger, Level::Danger),
    ];
    for (rule, before, after) in table {
        let v = marker::apply(
            &script,
            text,
            false,
            Verdict::new(vec![found(rule, before)]),
        );
        assert_eq!(v.findings[0].level, after, "{rule} at {before:?}");
        assert_eq!(v.level, after, "{rule} at {before:?}");
    }
    // A failed parse: nothing shows the marker is a comment.
    let v = marker::apply(
        &script,
        text,
        true,
        Verdict::new(vec![found("delete-outside-project", Level::Danger)]),
    );
    assert_eq!(v.level, Level::Danger);
}

#[test]
fn the_marker_must_end_the_command() {
    for (text, marked) in [
        ("rm -rf x # shellwise: allow", true),
        ("rm -rf x # shellwise: allow\n", true),
        ("rm -rf x #shellwise: allow", true),
        ("rm -rf x # shellwise: allow\nrm -rf y", false),
        ("rm -rf x\n# shellwise: allow", false),
        ("rm -rf x # shellwise: allowed", false),
        ("rm -rf x # SHELLWISE: ALLOW", false),
        ("echo '# shellwise: allow'", false),
    ] {
        let script = shellwise::parse::bash::parse(text, BashProfile::GitBash).expect("parses");
        assert_eq!(marker::is_marked(&script, text), marked, "{text:?}");
    }
}

/// Needs the `too-long` rule (Task 25): Git Bash's limit is 7790 escaped characters.
#[test]
fn the_marker_does_not_confirm_too_long() {
    let text = format!("echo {} # shellwise: allow", "a".repeat(8000));
    let input = AnalyseInput {
        bytes: text.as_bytes(),
        shell: Shell::Bash(BashProfile::GitBash),
        os: Os::host(),
        cwd: None,
        env: shellwise::ir::EnvView::new(),
        origin: Origin::CommandLine,
        problem: None,
    };
    let v = analyse(
        &input,
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
    );
    assert_eq!(v.level, Level::Break, "{v:?}");
    assert!(v.findings.iter().any(|f| f.rule == "too-long"), "{v:?}");
}

/// A level set in the configuration applies to the length stage and to an incomplete analysis
/// too, not only to the rules after the parse.
#[test]
fn a_configured_level_applies_to_the_length_stage_and_to_an_incomplete_analysis() {
    let mut cfg = Config::default();
    // Danger: neither finding's default level here.
    cfg.levels.insert("too-long".to_string(), Level::Danger);
    cfg.levels
        .insert("analysis-incomplete".to_string(), Level::Danger);
    let long = format!("echo {}", "a".repeat(8000));
    for (text, problem, rule) in [
        (long.as_str(), None, "too-long"),
        (
            "echo hi",
            Some("a reason the caller gives"),
            "analysis-incomplete",
        ),
    ] {
        let input = AnalyseInput {
            bytes: text.as_bytes(),
            shell: Shell::Bash(BashProfile::GitBash),
            os: Os::host(),
            cwd: None,
            env: shellwise::ir::EnvView::new(),
            origin: Origin::CommandLine,
            problem,
        };
        let v = analyse(&input, &cfg, &Deadline::new(Instant::now(), 8000));
        let f = v.findings.iter().find(|f| f.rule == rule);
        assert_eq!(f.map(|f| f.level), Some(Level::Danger), "{rule}: {v:?}");
    }
}

/// The default temp root is the temp folder of the environment the check sees (`TEMP` on
/// Windows, `/tmp` on POSIX), not the analysing process's own: the bench replays rows with a
/// synthetic environment.
#[test]
fn the_default_temp_root_is_the_temp_of_the_checked_environment() {
    let level_of = |shell: Shell, os: Os, vars: &[(&str, &str)], command: &str, cwd: &str| {
        let env = env_view(
            shell,
            os,
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())),
        );
        let input = AnalyseInput {
            bytes: command.as_bytes(),
            shell,
            os,
            cwd: Some(PathBuf::from(cwd)),
            env,
            origin: Origin::CommandLine,
            problem: None,
        };
        let v = analyse(
            &input,
            &Config::default(),
            &Deadline::new(Instant::now(), 8000),
        );
        let rules: Vec<&str> = v.findings.iter().map(|f| f.rule).collect();
        format!("{} {rules:?}", v.level.as_str())
    };
    let win = [
        ("USERPROFILE", r"C:\Profiles\bench"),
        ("TEMP", r"C:\Profiles\bench\AppData\Local\Temp"),
        ("TMP", r"C:\Profiles\bench\AppData\Local\Temp"),
    ];
    let cwd = r"C:\Profiles\bench\work";
    let got = [
        level_of(
            Shell::Pwsh,
            Os::Windows,
            &win,
            r"Remove-Item C:\Profiles\bench\AppData\Local\Temp\x.txt",
            cwd,
        ),
        level_of(
            Shell::Bash(BashProfile::GitBash),
            Os::Windows,
            &win,
            "rm /tmp/x.txt",
            cwd,
        ),
        level_of(
            Shell::Bash(BashProfile::Posix),
            Os::Posix,
            &[("HOME", "/h/bench")],
            "rm /tmp/x.txt",
            "/h/bench/work",
        ),
        // The twin: a folder outside both temp and the project.
        level_of(
            Shell::Pwsh,
            Os::Windows,
            &win,
            r"Remove-Item C:\Profiles\other\x.txt",
            cwd,
        ),
    ];
    assert_eq!(
        got,
        [
            "ok []",
            "ok []",
            "ok []",
            r#"warn ["delete-outside-project"]"#
        ]
    );
}

#[test]
fn allowed_roots_come_from_the_user_file_and_never_from_the_repo_file() {
    let fx = fixture();
    let dir = fx.at("cfg");
    mkdir(&dir);
    let user = dir.join("config.toml");
    let repo = dir.join(shellwise::config::REPO_FILE);
    std::fs::write(&user, "allowed_roots = ['scratch']\n").unwrap();
    std::fs::write(&repo, "allowed_roots = ['wide']\n").unwrap();
    assert_eq!(
        Config::default().allowed_roots,
        vec![std::env::temp_dir()],
        "the default is the temp folder"
    );
    let (cfg, out) = Config::load(None, Some(&user), None);
    assert_eq!(cfg.allowed_roots, vec![dir.join("scratch")], "{out:?}");
    let (cfg, out) = Config::load(None, None, Some(&repo));
    assert_eq!(cfg.allowed_roots, vec![std::env::temp_dir()]);
    assert!(
        out.iter()
            .any(|f| f.rule == shellwise::config::CONFIG_REPO_IGNORED),
        "{out:?}"
    );
}

// ---------------------------------------------------------------- the spawned callers

/// A PreToolUse event for the Bash tool as the host sends it.
fn bash_event(command: &str, cwd: &Path) -> Vec<u8> {
    serde_json::json!({
        "session_id": "s",
        "transcript_path": "t",
        "cwd": cwd.to_string_lossy(),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "d"},
        "tool_use_id": "u",
    })
    .to_string()
    .into_bytes()
}

/// The hook's deny reason, or "" when it let the command through.
fn reason(r: &common::Run) -> String {
    assert_eq!(r.code, 0, "the hook exits 0: {} {}", r.stdout, r.stderr);
    if r.stdout.trim().is_empty() {
        return String::new();
    }
    r.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The fixture's home in the variables each OS reads it from.
fn home_env() -> [(&'static str, String); 2] {
    let home = fixture().at("home").to_string_lossy().into_owned();
    [("USERPROFILE", home.clone()), ("HOME", home)]
}

fn env_refs<'a>(env: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    env.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

const HOOK: [&str; 2] = ["hook", "claude-code"];

#[test]
fn the_hook_judges_a_delete_from_the_event_cwd() {
    let fx = fixture();
    let in_repo = common::run(&HOOK, Some(&bash_event("rm -rf .", &fx.at("repo"))), &[]);
    let why = reason(&in_repo);
    assert!(
        why.starts_with("shellwise: critical delete-critical"),
        "{why} | {} | {}",
        in_repo.stdout,
        in_repo.stderr
    );
    // Outside any repo the same text deletes the cwd, which the hook's default allowed root (the
    // temp folder holding the fixture) holds: no critical.
    let outside = common::run(&HOOK, Some(&bash_event("rm -rf .", &fx.at("norepo"))), &[]);
    assert_eq!(reason(&outside), "", "{}", outside.stdout);
}

#[test]
fn the_hook_resolves_the_home_folder_from_its_own_environment() {
    let fx = fixture();
    let env = home_env();
    let r = common::run(
        &HOOK,
        Some(&bash_event("rm -rf ~", &fx.at("repo"))),
        &env_refs(&env),
    );
    let why = reason(&r);
    assert!(
        why.starts_with("shellwise: critical delete-critical"),
        "{why}"
    );
}

#[test]
fn check_resolves_the_home_folder_from_its_own_environment() {
    let fx = fixture();
    let env = home_env();
    let repo = fx.at("repo").to_string_lossy().into_owned();
    let args = [
        "check", "--shell", "bash", "--json", "--cwd", &repo, "--", "rm -rf ~",
    ];
    let r = common::run(&args, None, &env_refs(&env));
    assert_eq!(r.code, 3, "{} {}", r.stdout, r.stderr);
    assert_eq!(
        r.json()["findings"][0]["rule"],
        "delete-critical",
        "{}",
        r.stdout
    );
}

#[test]
fn shellwise_off_lets_the_hook_through_unread() {
    let fx = fixture();
    let event = bash_event("rm -rf /", &fx.at("repo"));
    // Over the hard cap: denied unread, before `analyse` runs.
    let unread = bash_event(&"a".repeat(shellwise::MAX_READ_BYTES), &fx.at("repo"));
    // Controls: the guard is on.
    for input in [event.as_slice(), unread.as_slice()] {
        assert!(!reason(&common::run(&HOOK, Some(input), &[])).is_empty());
    }
    for input in [event.as_slice(), unread.as_slice()] {
        let off = common::run(&HOOK, Some(input), &[("SHELLWISE", "off")]);
        assert_eq!((off.code, off.stdout.as_str()), (0, ""), "{}", off.stderr);
    }
}

// ---------------------------------------------------------------- SHELLWISE=off

#[test]
fn shellwise_off_lets_everything_through() {
    let args = ["check", "--shell", "bash", "--json", "--", "rm -rf /"];
    let on = common::run(&args, None, &[]);
    assert_eq!(on.code, 3, "control: {} {}", on.stdout, on.stderr);
    let off = common::run(&args, None, &[("SHELLWISE", "off")]);
    common::assert_ok(&off);
    // Any other value leaves the guard on.
    let other = common::run(&args, None, &[("SHELLWISE", "on")]);
    assert_eq!(other.code, 3, "{} {}", other.stdout, other.stderr);
}
