//! shellwise: a command guard and lint for shell commands written by AI coding agents.

use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

pub mod adapter;
pub mod config;
pub mod fs;
pub mod ir;
pub mod level;
pub mod parse;
pub mod programs;
pub mod rules;
pub mod scan;

use config::Config;
use ir::{EnvView, Script};
use level::{Finding, Level, Span, Verdict};

/// Commands longer than this (in bytes) are not parsed; the analysis is incomplete.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Input longer than this (in bytes) is not even scanned: it is `danger` unread.
pub const MAX_READ_BYTES: usize = 1024 * 1024;

/// The rule id of every analysis that did not finish for a reason other than a parse error.
pub const ANALYSIS_INCOMPLETE: &str = "analysis-incomplete";

/// `SHELLWISE=off` turns the whole check off; any other value leaves it on.
const OFF_VAR: &str = "SHELLWISE";
const OFF_VALUE: &str = "off";

/// The stack of the thread that parses and runs the rules.
const WORKER_STACK: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Pwsh,
    Powershell5,
    Bash(BashProfile),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BashProfile {
    GitBash,
    Posix,
}

/// The OS the command runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Posix,
}

impl Os {
    pub fn host() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else {
            Os::Posix
        }
    }
}

/// Where the text comes from: a command line a host is about to run, or a script file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    CommandLine,
    File,
}

/// One text to analyse, as its caller read it.
#[derive(Debug, Clone)]
pub struct AnalyseInput<'a> {
    pub bytes: &'a [u8],
    pub shell: Shell,
    pub os: Os,
    pub cwd: Option<PathBuf>,
    pub env: EnvView,
    pub origin: Origin,
    /// Why the parse and the rules must not run (a config that did not load): the length rules
    /// still run, and the verdict is `incomplete` for this reason.
    pub problem: Option<&'static str>,
}

/// What a rule sees of the command: the decoded text and its context.
#[derive(Debug, Clone)]
pub struct CheckInput<'a> {
    pub shell: Shell,
    pub os: Os,
    pub command: &'a str,
    pub cwd: Option<PathBuf>,
    pub env: EnvView,
    pub origin: Origin,
}

/// The one deadline of a run, started first in `main`.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    start: Instant,
    ms: u64,
}

impl Deadline {
    pub fn new(start: Instant, ms: u64) -> Deadline {
        Deadline { start, ms }
    }

    /// `min(walk_budget_ms, hook_timeout_ms - 1500)` from `start`.
    pub fn for_config(start: Instant, cfg: &Config) -> Deadline {
        let ms = cfg
            .walk_budget_ms
            .min(cfg.hook_timeout_ms.saturating_sub(1500));
        Deadline::new(start, ms)
    }

    pub fn remaining(&self) -> Duration {
        (self.start + Duration::from_millis(self.ms)).saturating_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

/// The whole pipeline for one text, in this order: the length rules on the raw text (before any
/// size cap), the parse and the rules on a big-stack worker inside `catch_unwind` under the
/// deadline, then the config levels. Input over `MAX_READ_BYTES` is `danger` unread; the input's
/// `problem`, invalid UTF-8, input over `MAX_INPUT_BYTES`, a panic, a dead worker, a parser that
/// failed itself and the deadline make the analysis incomplete (`incomplete`).
pub fn analyse(input: &AnalyseInput, cfg: &Config, deadline: &Deadline) -> Verdict {
    if std::env::var_os(OFF_VAR).is_some_and(|v| v == OFF_VALUE) {
        return Verdict::new(Vec::new());
    }
    if input.bytes.len() > MAX_READ_BYTES {
        return unread("input over the hard size cap");
    }
    let invalid = std::str::from_utf8(input.bytes).is_err();
    let command = String::from_utf8_lossy(input.bytes).into_owned();
    let check = CheckInput {
        shell: input.shell,
        os: input.os,
        command: &command,
        cwd: input.cwd.clone(),
        env: input.env.clone(),
        origin: input.origin,
    };
    let mut findings = match length_stage(&check, cfg, deadline) {
        Ok(found) => levels(found, cfg).findings,
        Err(reason) => return levels(incomplete(&command, reason).findings, cfg),
    };
    let problem = if let Some(reason) = input.problem {
        Some(reason)
    } else if invalid {
        Some("invalid UTF-8")
    } else if command.len() > MAX_INPUT_BYTES {
        Some("input over the size cap")
    } else {
        None
    };
    // Each stage's findings already carry their configured levels, and the marker has run.
    findings.extend(checked(&check, problem, cfg, deadline).findings);
    Verdict::new(findings)
}

/// The configured level of each finding.
fn levels(findings: Vec<Finding>, cfg: &Config) -> Verdict {
    Verdict::new(
        findings
            .into_iter()
            .map(|mut f| {
                f.level = cfg.level(f.rule, f.level);
                f
            })
            .collect(),
    )
}

/// The length rules, on the raw text and with no parse. A panic in one is a reason.
fn length_stage(
    input: &CheckInput,
    cfg: &Config,
    deadline: &Deadline,
) -> Result<Vec<Finding>, &'static str> {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let script = Script::default();
        let fs: fs::SharedFs = Arc::new(fs::RealFs);
        let ctx = rules::Ctx {
            input,
            script: &script,
            parse_error: None,
            cfg,
            fs: &fs,
            deadline,
        };
        let mut out = Vec::new();
        for rule in rules::length_rules() {
            if rule.scope().covers(input.origin) {
                rule.check(&ctx, &mut out);
            }
        }
        out
    }))
    .map_err(|_| "internal error in a length rule")
}

/// Parse and run the rules on a big-stack worker inside `catch_unwind` under the deadline. When
/// the worker cannot finish, or `problem` says it must not run, the raw-text scan runs on a second
/// worker and the verdict is `incomplete` from its answer.
fn checked(
    input: &CheckInput,
    problem: Option<&'static str>,
    cfg: &Config,
    deadline: &Deadline,
) -> Verdict {
    let command = Arc::new(input.command.to_string());
    let reason = match problem {
        Some(reason) => reason,
        None => match run_checker(Arc::clone(&command), input, cfg, *deadline) {
            Ok(verdict) => return verdict,
            Err(reason) => reason,
        },
    };
    let verdict = incomplete_from(
        bounded_scan(Arc::clone(&command), deadline),
        &command,
        reason,
    );
    levels(verdict.findings, cfg)
}

/// How long the raw scan may run past the deadline. The deadline ends 1500 ms before the hook
/// timeout, and a scan started when the deadline ran out needs time of its own.
const LATE_SCAN_MS: u64 = 500;

/// The raw scan on a big-stack worker, waiting until the deadline or `LATE_SCAN_MS`, whichever is
/// later; `None` when it gives no answer.
fn bounded_scan(command: Arc<String>, deadline: &Deadline) -> Option<Option<Span>> {
    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("scan".into())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            if testhook_is("panic-scan-sleep") {
                thread::sleep(Duration::from_secs(60));
            }
            if testhook_is("scan-abort") {
                std::process::exit(99);
            }
            let _ = tx.send(panic::catch_unwind(|| scan::destructive_row(&command)));
        });
    if spawned.is_err() {
        return None;
    }
    let wait = deadline
        .remaining()
        .max(Duration::from_millis(LATE_SCAN_MS));
    match rx.recv_timeout(wait) {
        Ok(Ok(hit)) => Some(hit),
        _ => None,
    }
}

fn run_checker(
    command: Arc<String>,
    input: &CheckInput,
    cfg: &Config,
    deadline: Deadline,
) -> Result<Verdict, &'static str> {
    let (tx, rx) = mpsc::channel();
    let cfg = cfg.clone();
    let (shell, os, cwd, env, origin) = (
        input.shell,
        input.os,
        input.cwd.clone(),
        input.env.clone(),
        input.origin,
    );
    let job = move || {
        let input = CheckInput {
            shell,
            os,
            command: &command,
            cwd,
            env,
            origin,
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| check(&input, &cfg, &deadline)));
        if testhook_is("dead-worker") {
            return;
        }
        let _ = tx.send(result);
    };
    let spawned = if testhook_is("spawn-fail") {
        Err(std::io::Error::other("testhook: spawn-fail"))
    } else {
        thread::Builder::new()
            .name("check".into())
            .stack_size(WORKER_STACK)
            .spawn(job)
    };
    if spawned.is_err() {
        return Err("the worker thread did not start");
    }
    match rx.recv_timeout(deadline.remaining()) {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("internal error"),
        Err(mpsc::RecvTimeoutError::Timeout) => Err("deadline"),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("the worker ended without a result"),
    }
}

/// Parse the command and run every rule whose scope covers its origin. On a parse error the
/// rules see an empty script and the error. A deny kind is the only finding: the shell refuses
/// the text, so nothing in it runs. A parser that failed itself is `Err` with its reason.
fn check(input: &CheckInput, cfg: &Config, deadline: &Deadline) -> Result<Verdict, &'static str> {
    let parsed = match input.shell {
        Shell::Pwsh | Shell::Powershell5 => {
            parse::pwsh::parse(input.command, input.shell, input.os)
        }
        Shell::Bash(profile) => parse::bash::parse(input.command, profile),
    };
    let (script, parse_error) = match parsed {
        Ok(script) => (script, None),
        Err(e) => match e.kind {
            parse::ParseKind::Internal(failure) => return Err(failure.reason()),
            _ => (Script::default(), Some(e)),
        },
    };
    let fs: fs::SharedFs = Arc::new(fs::RealFs);
    let ctx = rules::Ctx {
        input,
        script: &script,
        parse_error: parse_error.as_ref(),
        cfg,
        fs: &fs,
        deadline,
    };
    let mut findings = Vec::new();
    for rule in rules::all() {
        if rule.scope().covers(input.origin) {
            rule.check(&ctx, &mut findings);
        }
    }
    if parse_error
        .as_ref()
        .is_some_and(|e| rules::parse_error::is_deny_kind(&e.kind, input.command, input.shell))
    {
        findings.retain(|f| f.rule == rules::parse_error::PARSE_ERROR);
    }
    // The config levels, then the marker: a level the marker lowered is never raised again.
    let verdict = levels(findings, cfg);
    Ok(rules::marker::apply(
        &script,
        input.command,
        parse_error.is_some(),
        verdict,
    ))
}

#[cfg(feature = "testhooks")]
fn testhook_is(mode: &str) -> bool {
    rules::testhooks::active(mode)
}

#[cfg(not(feature = "testhooks"))]
fn testhook_is(_mode: &str) -> bool {
    false
}

/// The longest scan hit (in bytes) the reason quotes.
const MAX_QUOTED: usize = 80;

const SPLIT_FIX: &str = "split the command into simpler calls so each can be checked";

/// The verdict when the analysis cannot finish for `reason`: `danger` when the raw-text scan
/// names a command of the destructive table or a .NET `Delete()` call, and `warn` otherwise, also
/// when the scan finds only a region it cannot read or does not finish. The allow marker has no
/// effect here: without a parse nothing shows it is a comment.
pub fn incomplete(command: &str, reason: &str) -> Verdict {
    incomplete_with(command, reason, scan::destructive_row)
}

fn incomplete_with(
    command: &str,
    reason: &str,
    scan: impl FnOnce(&str) -> Option<Span> + std::panic::UnwindSafe,
) -> Verdict {
    let hit = panic::catch_unwind(|| scan(command)).ok();
    incomplete_from(hit, command, reason)
}

/// `incomplete` from a scan result (`None` when the scan did not finish). A scan hit sets the
/// span and names the command; otherwise the span is the whole text.
fn incomplete_from(hit: Option<Option<Span>>, command: &str, reason: &str) -> Verdict {
    let whole = Span {
        start: 0,
        end: command.len(),
    };
    let (level, span, message) = match hit {
        Some(None) => (
            Level::Warn,
            whole,
            format!(
                "the command could not be analysed ({reason}); its raw text names no command that deletes or discards data"
            ),
        ),
        Some(Some(span)) => match command.get(span.start..span.end) {
            Some(found) if found.len() <= MAX_QUOTED && !found.chars().any(char::is_control) => (
                Level::Danger,
                span,
                format!(
                    "the command could not be analysed ({reason}); the raw scan flags `{found}` as destructive"
                ),
            ),
            _ => (
                Level::Danger,
                span,
                format!(
                    "the command could not be analysed ({reason}); the raw scan flags part of it as destructive"
                ),
            ),
        },
        None => (
            Level::Warn,
            whole,
            format!("the command could not be analysed ({reason}) and the raw scan did not finish"),
        ),
    };
    Verdict::new(vec![Finding {
        rule: ANALYSIS_INCOMPLETE,
        level,
        message,
        fix: Some(SPLIT_FIX.to_string()),
        span,
    }])
}

/// The verdict for input that was not read whole (over the hard cap, stdin still open).
pub fn unread(reason: &str) -> Verdict {
    Verdict::new(vec![Finding {
        rule: ANALYSIS_INCOMPLETE,
        level: Level::Danger,
        message: format!("the command could not be read ({reason}), so it may destroy data"),
        fix: Some(SPLIT_FIX.to_string()),
        span: Span::default(),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_is_the_walk_budget_or_the_hook_timeout_less_1500() {
        let cases = [
            (8000, 10000, 8000),
            (9000, 10000, 8500),
            (60000, 3000, 1500),
            (8000, 1000, 0),
        ];
        let start = Instant::now();
        for (walk, hook, want) in cases {
            let cfg = Config {
                walk_budget_ms: walk,
                hook_timeout_ms: hook,
                ..Config::default()
            };
            let d = Deadline::for_config(start, &cfg);
            assert_eq!(d.ms, want, "walk {walk} hook {hook}");
        }
    }

    #[test]
    fn deadline_counts_down_from_its_start() {
        let d = Deadline::new(Instant::now(), 60_000);
        assert!(!d.expired());
        assert!(d.remaining() > Duration::from_secs(50));
        let past = Instant::now() - Duration::from_millis(20);
        let d = Deadline::new(past, 10);
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    /// Every row whose incomplete verdict is not `level` from `analysis-incomplete`, so a red run
    /// lists all failing rows at once.
    fn not_at<'a>(level: Level, rows: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        rows.into_iter()
            .filter(|cmd| {
                let v = incomplete(cmd, "test");
                v.level != level
                    || v.findings.len() != 1
                    || v.findings[0].rule != ANALYSIS_INCOMPLETE
            })
            .collect()
    }

    fn assert_at(level: Level, v: &Verdict, cmd: &str) {
        assert_eq!(v.level, level, "{cmd:?} -> {v:?}");
        assert_eq!(v.findings.len(), 1, "{cmd:?}");
        assert_eq!(v.findings[0].rule, ANALYSIS_INCOMPLETE, "{cmd:?}");
    }

    #[test]
    fn incomplete_names_the_destructive_command_the_scan_found() {
        let v = incomplete("echo hi; rm -rf x", "test");
        assert_at(Level::Danger, &v, "echo hi; rm -rf x");
        assert_eq!(v.findings[0].span, Span { start: 9, end: 17 });
        let msg = &v.findings[0].message;
        assert!(msg.contains("test") && msg.contains("`rm -rf x`"), "{msg}");
    }

    #[test]
    fn incomplete_quotes_only_a_short_one_line_hit() {
        // A hit may be an unreadable region or the whole text (a spent budget): it is not quoted
        // when long or multi-line, so the reason stays one short line.
        let long = format!("{} #", "env -S ".repeat(100));
        let all = |c: &str| {
            Some(Span {
                start: 0,
                end: c.len(),
            })
        };
        let v = incomplete_with(&long, "test", all);
        assert_at(Level::Danger, &v, &long);
        assert_eq!(
            v.findings[0].span,
            Span {
                start: 0,
                end: long.len()
            }
        );
        let msg = &v.findings[0].message;
        assert!(msg.len() < 200 && !msg.contains("env -S env"), "{msg}");

        let lines = "rm -rf x\nrm -rf y #";
        let v = incomplete_with(lines, "test", all);
        assert_at(Level::Danger, &v, lines);
        let msg = &v.findings[0].message;
        assert!(!msg.contains('\n') && !msg.contains("rm -rf"), "{msg}");
    }

    #[test]
    fn incomplete_is_warn_without_a_scan_hit() {
        let v = incomplete("Get-Date", "test");
        assert_at(Level::Warn, &v, "Get-Date");
        assert_eq!(v.findings[0].span, Span { start: 0, end: 8 });
        assert!(v.findings[0].message.contains("test"));
    }

    #[test]
    fn incomplete_is_warn_when_the_scan_itself_panics() {
        // The scan gave no answer: an internal failure with no destructive match is warn.
        let v = incomplete_with("Get-Date", "test", |_| panic!("scan bug"));
        assert_at(Level::Warn, &v, "Get-Date");
        assert_eq!(v.findings[0].span, Span { start: 0, end: 8 });
        assert!(
            v.findings[0]
                .message
                .contains("the raw scan did not finish"),
            "{}",
            v.findings[0].message
        );
    }

    /// The shapes the re-review found the raw scan missing (N1-N6). They are obfuscations
    /// (Ruling 91), so an incomplete analysis of one is `warn`; each is a row of the hardening
    /// register. U+2018/U+2019 hide a row from the PowerShell reading, as in the review.
    const MISSED_BY_THE_SCAN: &[&str] = &[
        // N1 process substitution feeding more than one command
        "bash <(echo hi; echo 'rm -rf x')",
        "source <(echo hi; echo 'rm -rf x')",
        "bash <(echo hi && echo 'rm -rf x')",
        // N2 command substitution inside code
        "bash -c \"$(echo 'rm -rf x')\"",
        "eval \"$(echo rm -rf x)\"",
        "eval $(echo rm -rf x)",
        "bash <<< \"$(echo 'rm -rf x')\"",
        "sh -c \"`echo rm -rf x`\"",
        "echo \u{2018}a; bash <<EOF\n$(echo rm -rf x)\nEOF\necho \u{2019}",
        "iex (Write-Output 'Remove-Item x')",
        "iex $(Write-Output 'Remove-Item x')",
        // N3 heredoc bodies bash ends or skips earlier
        "echo \u{2018}a; echo $((1<<EOF))\nrm -rf x\nEOF\necho \u{2019}",
        "echo \u{2018}a; ((y=1<<EOF))\nrm -rf x\nEOF\necho \u{2019}",
        "echo \u{2018}a; x=$(cat <<EOF\nhi\nEOF)\nrm -rf x\nEOF\necho \u{2019}",
        // N4 `$'...'` and `$"..."` command names
        "$'rm' -rf x",
        "$\"rm\" -rf x",
        "$''rm -rf x",
        // N5 stdin-as-code consumers
        "(echo 'rm -rf x') | bash",
        "{ echo 'rm -rf x'; } | bash",
        "echo 'rm -rf x' | sudo -s",
        "echo 'rm -rf x' | sudo -i",
        "echo 'rm -rf x' | sudo -u root -s",
        "echo 'rm -rf x' | doas -s",
        "echo 'rm -rf x' | su",
        "echo 'rm -rf x' | bash -c bash",
        "echo 'rm -rf x' | sh -c 'exec sh'",
        "echo 'rm -rf x' | eval \"$(cat)\"",
        "echo 'rm -rf x' | xargs -I{} sh -c {}",
        "echo 'rm -rf x' | busybox sh",
        "'Remove-Item x' | ForEach-Object { iex $_ }",
        "'Remove-Item x' | % { Invoke-Expression $_ }",
        // N6 command-running prefixes and chained pwsh assignments
        "setsid rm -rf x",
        "chroot / rm -rf x",
        "flock /tmp/l rm -rf x",
        "runuser -u root -- rm -rf x",
        "su -c 'rm -rf x'",
        "$a=$b=Remove-Item x",
    ];

    #[test]
    fn incomplete_analysis_of_a_shape_the_scan_misses_is_warn() {
        let wrong = not_at(Level::Warn, MISSED_BY_THE_SCAN.iter().copied());
        assert!(wrong.is_empty(), "not warn: {wrong:?}");
    }

    /// Texts that name no delete: read-only commands, near misses of the old harmless grammar,
    /// and every metacharacter. With the allow-list gone they are all `warn`.
    const NOTHING_DESTRUCTIVE: &[&str] = &[
        "git status",
        "ls src",
        "echo hi",
        "pwd",
        "git log main",
        "git diff HEAD",
        "git show HEAD",
        "grep todo src/lib.rs",
        "head a.txt",
        "tail a.txt",
        "wc a.txt",
        "which git",
        "git --version",
        "cargo --version",
        "rustc --version",
        "node --version",
        "npm --version",
        "python --version",
        "pwsh --version",
        "  echo hi  ",
        "echo  hi",
        "echo rm x",
        "echo hi > x",
        "cat $f",
        "echo ~",
        "ls *",
        "lsx",
        "git",
        "git -C x status",
        "git statusx",
        "gitstatus",
        "./deploy --version",
        "deploy --version x",
        "--version",
        "rg --pre rm x .",
        "rg todo",
        "git diff --output=f",
        "git log --output f",
        "git diff HEAD --output=f",
        "ls -la",
        "echo -e hi",
        "echo hi -",
        "foo --version",
        "cargo --version x",
        "cargo build",
        "git --version --exec-path",
        "git diff \u{2013}output=f",
        "git diff \u{2014}output=f",
        "git log \u{2015}output f",
        "ls /s",
        "echo \u{ef}",
        "git Status",
        "git Log",
        "GIT DIFF",
        "git Show",
        "Git Status",
        "LS src",
        "Cargo --VERSION",
        "Cargo --version",
        "GIT --version",
        "git --VERSION",
        "cat notes.txt",
        "type ls",
        "cat CON",
        "type CON",
        "cat ../../../../../../../dev/stdin",
    ];

    /// The metacharacters of the old harmless grammar, each in `echo a<c>b`.
    const METACHARACTERS: &[&str] = &[
        ";", "&", "|", "<", ">", "(", ")", "$", "`", "\\", "\"", "'", "{", "}", "[", "]", "*", "?",
        "~", "#", "\n", "\r", "\t", "\u{b}", "\u{c}", "\u{a0}", "\u{3000}", "\u{1b}", "\u{0}",
    ];

    #[test]
    fn incomplete_analysis_of_text_with_no_delete_is_warn() {
        let rows: Vec<String> = METACHARACTERS
            .iter()
            .map(|c| format!("echo a{c}b"))
            .collect();
        let wrong = not_at(
            Level::Warn,
            NOTHING_DESTRUCTIVE
                .iter()
                .copied()
                .chain(rows.iter().map(|s| s.as_str())),
        );
        assert!(wrong.is_empty(), "not warn: {wrong:?}");
    }

    #[test]
    fn incomplete_analysis_of_a_delete_is_danger() {
        let wrong = not_at(
            Level::Danger,
            [
                "rm -rf x",
                "rm x",
                "ls; rm x",
                "git status && rm -rf x",
                "Remove-Item -Recurse x",
            ],
        );
        assert!(wrong.is_empty(), "not danger: {wrong:?}");
    }

    #[test]
    fn allow_marker_has_no_effect_on_an_incomplete_analysis() {
        // Without a parse nothing shows the marker is a comment, nor what the command deletes:
        // every row with a delete stays danger, and the marker alone is no delete.
        let wrong = not_at(
            Level::Danger,
            [
                "rm -rf x # shellwise: allow",
                "rm -rf x # baseline-guard: allow",
                "rm -rf x # shellwise: allow\n",
                // Critical targets.
                "rm -rf / # shellwise: allow",
                "rm -rf ~ # baseline-guard: allow",
                "Remove-Item -Recurse -Force C:\\ # shellwise: allow",
                "bash -c 'rm -rf /' # shellwise: allow",
                // The shell does not read these as a comment.
                "rm -rf x\\ # shellwise: allow",
                "rm -rf x \\ # shellwise: allow",
                "Remove-Item x` # shellwise: allow",
                "Remove-Item x --% # shellwise: allow",
                "rm -rf x <<EOF\n # shellwise: allow",
                "rm -rf y\n # shellwise: allow",
            ],
        );
        assert!(wrong.is_empty(), "not danger: {wrong:?}");
        let wrong = not_at(
            Level::Warn,
            [
                "# shellwise: allow",
                "bash <(echo hi; echo 'rm -rf x') # shellwise: allow\r\n",
                "eval $(echo rm -rf /) # shellwise: allow",
                "echo 'rm -rf /' | su # shellwise: allow",
            ],
        );
        assert!(wrong.is_empty(), "not warn: {wrong:?}");
    }
}
