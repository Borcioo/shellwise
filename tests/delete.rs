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
    fn names(&self) -> [(&'static str, PathBuf); 7] {
        [
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
            "protected/config.toml",
        ] {
            touch(&fx.at(file));
        }
        for (link, target) in LINKS {
            dir_link(&fx.at(link), &fx.at(target));
        }
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
    } else if row.id.starts_with("admincwd-") {
        Some(PathBuf::from(ADMIN_SHARE_CWD))
    } else if row.id.starts_with("unccwd-") {
        // A documentation address no host answers: a file-system call there runs out of time.
        Some(PathBuf::from(UNC_CWD))
    } else {
        Some(fx.at("repo"))
    }
}

fn verdict(row: &Row) -> Verdict {
    let fx = fixture();
    let shell = row.shell();
    let os = Os::host();
    let command = fx.substitute(&row.command, row.is_bash());
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
fn delete_rows() {
    run_file("delete.toml");
}

#[test]
fn git_rows() {
    run_file("git.toml");
}

/// Rows ported from baseline-guard's tests/test_rules.py, per rule, as git.toml's header records
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
const FINDING_IDS: [&str; 15] = [
    shellwise::rules::delete::DELETE_CRITICAL,
    shellwise::rules::delete::DELETE_EMPTY_EXPANSION,
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
/// `analysis-incomplete`, danger from the raw scan of the delete. No row can pin that race.
const NO_ROW: [&str; 1] = [shellwise::rules::delete::WALK_TIMEOUT];

/// Findings that are only ever warn (Ruling 122): a row where they fire stands in for the deny row.
const WARN_ONLY: [&str; 7] = [
    shellwise::rules::delete::DELETE_THROUGH_LINK,
    shellwise::rules::delete::DELETE_OUTSIDE_PROJECT,
    shellwise::rules::delete::DELETE_ALLOWED_ROOT,
    shellwise::rules::delete::DELETE_UNKNOWN_LOCATION,
    shellwise::rules::delete::DYNAMIC_TARGET,
    shellwise::rules::delete::WALK_UNREADABLE,
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
        ("rm -rf x # baseline-guard: allow\n", true),
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
