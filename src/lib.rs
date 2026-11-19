//! shellwise: a command guard and lint for shell commands written by AI coding agents.

use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod adapter;
pub mod config;
pub mod fs;
pub mod ir;
pub mod level;
pub mod parse;
pub mod rules;
pub mod scan;

use config::Config;
use ir::{EnvView, Script};
use level::{Finding, Level, Span, Verdict};

/// Commands longer than this (in bytes) are not analysed; they get the fail-closed verdict.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Input longer than this (in bytes) is not even scanned: it is `danger` unread.
pub const MAX_READ_BYTES: usize = 1024 * 1024;

/// The rule id of every fail-closed verdict.
pub const ANALYSIS_FAILED: &str = "analysis-failed";

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

#[derive(Debug, Clone)]
pub struct CheckInput<'a> {
    pub shell: Shell,
    pub os: Os,
    pub command: &'a str,
    pub cwd: Option<PathBuf>,
    pub env: EnvView,
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

/// Analyse one command. Rules run on the IR; there is no parser yet, so the IR is empty.
pub fn check(input: &CheckInput, cfg: &Config, deadline: &Deadline) -> Verdict {
    let script = Script::default();
    let fs = fs::RealFs;
    let ctx = rules::Ctx {
        input,
        script: &script,
        cfg,
        fs: &fs,
        deadline,
    };
    let mut findings = Vec::new();
    for rule in rules::all() {
        rule.check(&ctx, &mut findings);
    }
    Verdict::new(findings)
}

/// The longest scan hit (in bytes) the fail-closed reason quotes.
const MAX_QUOTED: usize = 80;

/// The verdict when the analysis cannot finish: `ok` only when the raw text is a harmless simple
/// command, otherwise `danger`. The allow marker has no effect here: without a parse nothing shows
/// it is a comment or what the command deletes. The raw-text scan only names what it flags.
pub fn fail_closed(command: &str, reason: &str) -> Verdict {
    fail_closed_with(command, reason, scan::raw_destructive)
}

fn fail_closed_with(
    command: &str,
    reason: &str,
    scan: impl FnOnce(&str) -> Option<Span> + std::panic::UnwindSafe,
) -> Verdict {
    let hit = std::panic::catch_unwind(|| scan(command)).ok();
    scan_verdict(hit, command, reason)
}

/// The fail-closed verdict from a scan result (`None` when the scan did not finish). Only the
/// harmless grammar clears the command; a scan hit sets the span and names the command, and
/// otherwise the span is the whole text.
pub fn scan_verdict(hit: Option<Option<Span>>, command: &str, reason: &str) -> Verdict {
    if scan::harmless(command) {
        return Verdict::new(Vec::new());
    }
    let whole = Span {
        start: 0,
        end: command.len(),
    };
    let (span, message) = match hit.flatten() {
        Some(span) => match command.get(span.start..span.end) {
            Some(found) if found.len() <= MAX_QUOTED && !found.chars().any(char::is_control) => (
                span,
                format!(
                    "the command could not be analysed ({reason}); the raw scan flags `{found}` as destructive or unreadable"
                ),
            ),
            Some(_) => (
                span,
                format!(
                    "the command could not be analysed ({reason}); the raw scan flags part of it as destructive or unreadable"
                ),
            ),
            None => (whole, not_simple(reason)),
        },
        None => (whole, not_simple(reason)),
    };
    danger(span, message)
}

fn not_simple(reason: &str) -> String {
    format!(
        "the command could not be analysed ({reason}) and is not a simple read-only command, so it may destroy data"
    )
}

/// The verdict for input that was not read whole (over the hard cap, stdin still open).
pub fn fail_closed_unread(reason: &str) -> Verdict {
    danger(
        Span::default(),
        format!("the command could not be read ({reason}), so it may destroy data"),
    )
}

fn danger(span: Span, message: String) -> Verdict {
    Verdict::new(vec![Finding {
        rule: ANALYSIS_FAILED,
        level: Level::Danger,
        message,
        fix: Some("split the command into simpler calls so each can be checked".to_string()),
        span,
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

    /// Every row whose fail-closed verdict is not `danger` from `analysis-failed`, so a red run
    /// lists all failing rows at once.
    fn not_danger<'a>(rows: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        rows.into_iter()
            .filter(|cmd| {
                let v = fail_closed(cmd, "test");
                v.level != Level::Danger
                    || v.findings.len() != 1
                    || v.findings[0].rule != ANALYSIS_FAILED
            })
            .collect()
    }

    /// Every row whose fail-closed verdict is not the plain `ok`.
    fn not_ok<'a>(rows: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        rows.into_iter()
            .filter(|cmd| fail_closed(cmd, "test") != Verdict::new(vec![]))
            .collect()
    }

    fn assert_danger(v: &Verdict, cmd: &str) {
        assert_eq!(v.level, Level::Danger, "{cmd:?} -> {v:?}");
        assert_eq!(v.findings.len(), 1, "{cmd:?}");
        assert_eq!(v.findings[0].rule, ANALYSIS_FAILED, "{cmd:?}");
    }

    #[test]
    fn fail_closed_names_the_destructive_command_the_scan_found() {
        let v = fail_closed("echo hi; rm -rf x", "test");
        assert_danger(&v, "echo hi; rm -rf x");
        assert_eq!(v.findings[0].span, Span { start: 9, end: 17 });
        let msg = &v.findings[0].message;
        assert!(msg.contains("test") && msg.contains("`rm -rf x`"), "{msg}");
    }

    #[test]
    fn fail_closed_quotes_only_a_short_one_line_hit() {
        // A hit may be an unreadable region or the whole text (a spent budget): it is not quoted
        // when long or multi-line, so the reason stays one short line.
        let long = format!("{} #", "env -S ".repeat(100));
        let all = |c: &str| {
            Some(Span {
                start: 0,
                end: c.len(),
            })
        };
        let v = fail_closed_with(&long, "test", all);
        assert_danger(&v, &long);
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
        let v = fail_closed_with(lines, "test", all);
        assert_danger(&v, lines);
        let msg = &v.findings[0].message;
        assert!(!msg.contains('\n') && !msg.contains("rm -rf"), "{msg}");
    }

    #[test]
    fn fail_closed_is_danger_without_a_scan_hit() {
        // Not harmless, and the scan finds nothing: still danger, spanning the whole text.
        let v = fail_closed("Get-Date", "test");
        assert_danger(&v, "Get-Date");
        assert_eq!(v.findings[0].span, Span { start: 0, end: 8 });
        assert!(v.findings[0].message.contains("test"));
    }

    #[test]
    fn fail_closed_is_danger_when_the_scan_itself_panics() {
        let v = fail_closed_with("Get-Date", "test", |_| panic!("scan bug"));
        assert_danger(&v, "Get-Date");
        assert_eq!(v.findings[0].span, Span { start: 0, end: 8 });
    }

    /// The shapes the re-review found the raw scan missing (N1-N6). U+2018/U+2019 hide a row
    /// from the PowerShell reading, as in the review.
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
    fn failed_analysis_of_a_shape_the_scan_misses_is_danger() {
        let missed = not_danger(MISSED_BY_THE_SCAN.iter().copied());
        assert!(missed.is_empty(), "not danger: {missed:?}");
    }

    /// One harmless row per entry of the read-only list and per `--version` tool, plus spacing
    /// variants.
    const HARMLESS_ROWS: &[&str] = &[
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
    ];

    #[test]
    fn failed_analysis_of_a_harmless_simple_command_is_ok() {
        let wrong = not_ok(HARMLESS_ROWS.iter().copied());
        assert!(wrong.is_empty(), "not ok: {wrong:?}");
    }

    #[test]
    fn harmless_text_is_ok_whatever_the_scan_says() {
        // The scan only names a command; it neither clears nor condemns a harmless text.
        let hit = |_: &str| Some(Span { start: 0, end: 4 });
        assert_eq!(fail_closed_with("echo hi", "t", hit), Verdict::new(vec![]));
        let v = fail_closed_with("echo hi", "t", |_| panic!("scan bug"));
        assert_eq!(v, Verdict::new(vec![]));
        assert_danger(&fail_closed_with("Get-Date", "t", |_| None), "Get-Date");
    }

    /// The metacharacters of the harmless grammar, written out here (not read from the code) so a
    /// character dropped from the code keeps its row. Control and non-ASCII characters count as
    /// metacharacters too.
    const METACHARACTERS: &[&str] = &[
        ";", "&", "|", "<", ">", "(", ")", "$", "`", "\\", "\"", "'", "{", "}", "[", "]", "*", "?",
        "~", "#", "\n", "\r", "\t", "\u{b}", "\u{c}", "\u{a0}", "\u{3000}", "\u{1b}", "\u{0}",
    ];

    /// Near misses of the harmless grammar: each stays danger.
    const NEAR_MISSES: &[&str] = &[
        "echo hi > x",
        "ls; rm x",
        "git status && rm -rf x",
        "cat $f",
        "echo ~",
        "ls *",
        "rm -rf x",
        "rm x",
        "lsx",
        // Shorter than every entry it starts: only the length check refuses it.
        "git",
        "git -C x status",
        "git statusx",
        "gitstatus",
        "./deploy --version",
        "deploy --version x",
        "--version",
        // No option word after the command, and `--version` only alone after a listed tool.
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
        // pwsh reads U+2013/U+2014/U+2015 as dashes and a leading `/` as a switch; no non-ASCII.
        "git diff \u{2013}output=f",
        "git diff \u{2014}output=f",
        "git log \u{2015}output f",
        "ls /s",
        "echo \u{ef}",
        // Words compare case-sensitively: git sends a mixed-case subcommand to alias lookup, and
        // POSIX names differ by case.
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
        // `cat` and `type` are not listed: a device path blocks them.
        "cat notes.txt",
        "type ls",
        "cat CON",
        "type CON",
        "cat ../../../../../../../dev/stdin",
    ];

    #[test]
    fn failed_analysis_of_a_near_miss_is_danger() {
        let rows: Vec<String> = METACHARACTERS
            .iter()
            .map(|c| format!("echo a{c}b"))
            .collect();
        let wrong = not_danger(
            NEAR_MISSES
                .iter()
                .copied()
                .chain(rows.iter().map(|s| s.as_str())),
        );
        assert!(wrong.is_empty(), "not danger: {wrong:?}");
    }

    #[test]
    fn allow_marker_has_no_effect_on_a_failed_analysis() {
        // Without a parse nothing shows the marker is a comment, nor what the command deletes.
        let wrong = not_danger([
            "rm -rf x # shellwise: allow",
            "rm -rf x # baseline-guard: allow",
            "rm -rf x # shellwise: allow\n",
            "# shellwise: allow",
            "bash <(echo hi; echo 'rm -rf x') # shellwise: allow\r\n",
            // Critical targets.
            "rm -rf / # shellwise: allow",
            "rm -rf ~ # baseline-guard: allow",
            "Remove-Item -Recurse -Force C:\\ # shellwise: allow",
            "bash -c 'rm -rf /' # shellwise: allow",
            "eval $(echo rm -rf /) # shellwise: allow",
            "echo 'rm -rf /' | su # shellwise: allow",
            // The shell does not read these as a comment.
            "rm -rf x\\ # shellwise: allow",
            "rm -rf x \\ # shellwise: allow",
            "Remove-Item x` # shellwise: allow",
            "Remove-Item x --% # shellwise: allow",
            "rm -rf x <<EOF\n # shellwise: allow",
            "rm -rf y\n # shellwise: allow",
        ]);
        assert!(wrong.is_empty(), "not danger: {wrong:?}");
    }
}
