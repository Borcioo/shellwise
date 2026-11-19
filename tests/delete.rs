//! The delete guard, the git rules and the allow marker through `analyse`, against a real
//! fixture tree: `tests/cases/delete.toml` and `tests/cases/git.toml` (their headers describe the
//! tree and the row conventions), the marker's exemptions on real parses, and `SHELLWISE=off`
//! through the spawned binary.

mod case_loader;
mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
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

const LINKS: [(&str, &str); 4] = [
    ("repo/linked/out", "outside/target"),
    ("repo/jn", "outside/target"),
    ("repo/wt/node_modules", "outside/target"),
    ("allowed/box", "outside/target"),
];

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("shellwise-delete-{}", std::process::id()));
        assert!(
            !root.to_string_lossy().contains(' '),
            "the fixture path {root:?} holds a space; the rows write paths unquoted"
        );
        let fx = Fixture { root };
        if fx.root.exists() {
            for (link, _) in LINKS {
                unlink(&fx.at(link));
            }
            std::fs::remove_dir_all(&fx.root).unwrap();
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
        if let Some(repo) = fx.at("norepo").ancestors().find(|d| d.join(".git").exists()) {
            panic!("the non-repo fixture lies inside the repo {repo:?}");
        }
        fx
    })
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
    cfg
}

fn cwd(row: &Row) -> Option<PathBuf> {
    let fx = fixture();
    if row.id.starts_with("nocwd-") {
        None
    } else if row.id.starts_with("norepo-") {
        Some(fx.at("norepo"))
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
        .map(|r| r["id"].as_str().unwrap().trim_start_matches("nocwd-").to_string())
        .collect();
    assert!(!ids.is_empty(), "git.toml: no rows");
    for (prefix, want) in PORTED {
        let got = ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert_eq!(got, want, "{prefix} rows");
    }
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
        ("analysis-incomplete", Level::Danger, Level::Danger),
    ];
    for (rule, before, after) in table {
        let v = marker::apply(&script, text, false, Verdict::new(vec![found(rule, before)]));
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
    };
    let v = analyse(&input, &Config::default(), &Deadline::new(Instant::now(), 8000));
    assert_eq!(v.level, Level::Break, "{v:?}");
    assert!(v.findings.iter().any(|f| f.rule == "too-long"), "{v:?}");
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
