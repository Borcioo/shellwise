//! The delete guard when the deadline runs out during the repo lookup, through `analyse`:
//! `SHELLWISE_TESTHOOK=repo-lookup-timeout` makes the lookup time out (deterministic, where a
//! short `SHELLWISE_TESTHOOK_DEADLINE_MS` races the check worker). The lexical match of a
//! protected location never waits on it (critical as without the hook); whatever still needs the
//! lookup is danger on a recursive or forced delete and warn otherwise. With the lookup working,
//! deleting inside a repo root that holds a protected path stays exempt. One test in its own
//! binary: the hook mode is process-wide.
#![cfg(feature = "testhooks")]

use std::path::PathBuf;
use std::time::Instant;

use shellwise::config::Config;
use shellwise::fs::resolve::env_view;
use shellwise::level::Verdict;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let root =
            std::env::temp_dir().join(format!("shellwise-delete-deadline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in [
            "repo/.git",
            "repo/build",
            "repo/keep",
            "repo/src",
            "vault",
            "home",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for file in ["repo/a.txt", "repo/build/x.o", "home/f.txt"] {
            std::fs::write(root.join(file), b"x").unwrap();
        }
        Fixture { root }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One row: the shell, the command, the cwd and the protected path (both under the fixture
/// root), and the level and rules it must get.
struct Row<'a> {
    shell: Shell,
    command: String,
    cwd: &'a str,
    protected: &'a str,
    level: &'a str,
    rules: &'a [&'a str],
}

fn row<'a>(
    shell: Shell,
    command: &str,
    cwd: &'a str,
    protected: &'a str,
    level: &'a str,
    rules: &'a [&'a str],
) -> Row<'a> {
    Row {
        shell,
        command: command.to_string(),
        cwd,
        protected,
        level,
        rules,
    }
}

fn run(fx: &Fixture, r: &Row) -> Verdict {
    let os = Os::host();
    let home = fx.root.join("home").to_string_lossy().into_owned();
    let env = env_view(
        r.shell,
        os,
        [
            ("USERPROFILE".to_string(), home.clone()),
            ("HOME".to_string(), home),
        ],
    );
    let cfg = Config {
        protected: vec![fx.root.join(r.protected)],
        ..Config::default()
    };
    let input = AnalyseInput {
        bytes: r.command.as_bytes(),
        shell: r.shell,
        os,
        cwd: Some(fx.root.join(r.cwd)),
        env,
        origin: Origin::CommandLine,
        problem: None,
    };
    analyse(&input, &cfg, &Deadline::new(Instant::now(), 8000))
}

/// The rows whose verdict differs from what they want.
fn mismatches(fx: &Fixture, rows: &[Row]) -> Vec<String> {
    let mut wrong = Vec::new();
    for r in rows {
        let v = run(fx, r);
        let level = v.level.as_str();
        let rules: Vec<&str> = v.findings.iter().map(|f| f.rule).collect();
        if level != r.level || rules != r.rules {
            let messages: Vec<&str> = v.findings.iter().map(|f| f.message.as_str()).collect();
            wrong.push(format!(
                "{} (cwd {}): {level} {rules:?} (want {} {:?}) {messages:?}",
                r.command, r.cwd, r.level, r.rules
            ));
        }
    }
    wrong
}

#[test]
fn a_repo_lookup_that_times_out_never_lowers_a_delete_to_warn() {
    let fx = Fixture::new();
    let bash = match Os::host() {
        Os::Windows => Shell::Bash(BashProfile::GitBash),
        Os::Posix => Shell::Bash(BashProfile::Posix),
    };
    let pwsh = Shell::Pwsh;
    let system = match Os::host() {
        Os::Windows => "rm -rf /c/Windows",
        Os::Posix => "rm -rf /usr",
    };
    let q = char::from(34u8);
    let repo = fx.root.join("repo").to_string_lossy().replace('\\', "/");
    let absolute = format!("rm -rf {q}{repo}/$X{q}");
    let glob = format!("rm -rf {q}$X{q}*");
    let (out, inside) = ("vault", "repo/keep");
    const DISCARD: &[&str] = &["git-discard"];
    const CRITICAL: &[&str] = &["delete-critical"];
    const TIMEOUT: &[&str] = &["walk-timeout"];
    const OPAQUE: &[&str] = &["opaque-destructive"];
    const REPO_CONTENTS: &[&str] = &["delete-repo-contents"];

    // Without the hook: the lookup finishes. A protected path inside the repo makes the root an
    // ancestor of one, and deleting inside the root stays exempt.
    // SAFETY of the global: this binary holds this one test.
    unsafe { std::env::remove_var("SHELLWISE_TESTHOOK") };
    let control = [
        row(bash, "rm -rf .git", "repo", out, "critical", CRITICAL),
        row(bash, "rm -rf build", "repo", out, "ok", &[]),
        row(bash, "rm -rf .", "repo", inside, "critical", CRITICAL),
        row(
            bash,
            "find . -name '*.o' -delete",
            "repo",
            inside,
            "ok",
            &[],
        ),
        row(bash, "git clean -fd", "repo", inside, "danger", DISCARD),
        // Ruling 127: a folder on disk takes the `cd`; a cwd that is gone reads nothing.
        row(bash, "cd build; rm -rf *", "repo", out, "ok", &[]),
        row(bash, "cd build; rm -rf *", "gone", out, "ok", &[]),
    ];
    let mut wrong = mismatches(&fx, &control);

    unsafe { std::env::set_var("SHELLWISE_TESTHOOK", "repo-lookup-timeout") };
    let rows = [
        // Lexical: no lookup needed.
        row(bash, "rm -rf ~", "repo", out, "critical", CRITICAL),
        row(bash, system, "repo", out, "critical", CRITICAL),
        row(
            pwsh,
            "Remove-Item -Recurse -Force $HOME",
            "repo",
            out,
            "critical",
            CRITICAL,
        ),
        row(bash, "rm -rf ../vault", "repo", out, "critical", CRITICAL),
        row(bash, "rm -rf ~/*", "repo", out, "critical", CRITICAL),
        // Inside a folder that holds a protected path, with the lookup that would exempt the
        // repo root timed out: the lexical reason stands.
        row(
            bash,
            "find . -name '*.o' -delete",
            "repo",
            inside,
            "critical",
            CRITICAL,
        ),
        // The lookup decides: danger for a recursive or forced delete.
        row(bash, "rm -rf .git", "repo", out, "danger", TIMEOUT),
        row(bash, "rm -rf .", "repo", out, "danger", TIMEOUT),
        row(bash, "rm -rf build", "repo", out, "danger", TIMEOUT),
        row(bash, "rm -rf *", "repo", out, "danger", TIMEOUT),
        // C3: a glob over a folder whose repo lookup timed out.
        row(bash, "rm -rf ./*", "repo", out, "danger", TIMEOUT),
        row(bash, "rm -rf ../*", "repo/src", out, "danger", TIMEOUT),
        row(bash, "rm -rf ..", "repo/build", out, "danger", TIMEOUT),
        row(bash, "rm -rf ../.git", "repo/build", out, "danger", TIMEOUT),
        row(
            pwsh,
            "Remove-Item -Recurse -Force .git",
            "repo",
            out,
            "danger",
            TIMEOUT,
        ),
        row(bash, "rm -f a.txt", "repo", out, "danger", TIMEOUT),
        // An empty expansion whose match needs the lookup.
        row(bash, &glob, "repo", out, "danger", TIMEOUT),
        row(bash, &absolute, "repo", out, "danger", TIMEOUT),
        // Neither recursive nor forced: warn.
        row(bash, "rm a.txt", "repo", out, "warn", TIMEOUT),
        // C8: unread code that spells `.git` while the lookup that would place it timed out.
        row(bash, "bash -c 'rm -rf .git'", "repo", out, "danger", OPAQUE),
        row(bash, "bash -c 'rm -rf build'", "repo", out, "warn", OPAQUE),
    ];
    wrong.extend(mismatches(&fx, &rows));
    // Ruling 127: the read of the `cd` target times out: the old folder stays a candidate.
    unsafe { std::env::set_var("SHELLWISE_TESTHOOK", "dir-lookup-timeout") };
    let dir_rows = [
        row(
            bash,
            "cd build; rm -rf *",
            "repo",
            out,
            "danger",
            REPO_CONTENTS,
        ),
        row(
            pwsh,
            "cd build; Remove-Item -Recurse -Force *",
            "repo",
            out,
            "critical",
            CRITICAL,
        ),
    ];
    wrong.extend(mismatches(&fx, &dir_rows));
    unsafe { std::env::remove_var("SHELLWISE_TESTHOOK") };
    let total = control.len() + rows.len() + dir_rows.len();
    assert!(
        wrong.is_empty(),
        "{} of {total} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!("{total} rows ran");
}
