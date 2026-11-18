//! shellwise: a command guard and lint for shell commands written by AI coding agents.

use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod adapter;
pub mod config;
pub mod fs;
pub mod ir;
pub mod level;
pub mod rules;
pub mod scan;

use config::Config;
use ir::{EnvView, Script};
use level::{Finding, Level, Span, Verdict};

/// Commands longer than this (in bytes) are not analysed; they get the fail-closed verdict.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

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

/// The verdict when the analysis cannot finish: `danger` when the raw-text destructive scan
/// matches (or cannot run), otherwise `ok`.
pub fn fail_closed(command: &str, reason: &str) -> Verdict {
    fail_closed_with(command, reason, scan::raw_destructive)
}

fn fail_closed_with(
    command: &str,
    reason: &str,
    scan: impl FnOnce(&str) -> Option<Span> + std::panic::UnwindSafe,
) -> Verdict {
    let hit = std::panic::catch_unwind(|| scan(command));
    let span = match hit {
        Ok(None) => return Verdict::new(Vec::new()),
        Ok(Some(span)) => span,
        // The scan itself failed: nothing proves the command harmless.
        Err(_) => Span {
            start: 0,
            end: command.len(),
        },
    };
    Verdict::new(vec![Finding {
        rule: ANALYSIS_FAILED,
        level: Level::Danger,
        message: format!(
            "the command could not be analysed ({reason}) and it holds a destructive command"
        ),
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

    #[test]
    fn fail_closed_is_danger_only_when_the_raw_text_is_destructive() {
        let v = fail_closed("echo hi; rm -rf x", "test");
        assert_eq!(v.level, Level::Danger);
        assert_eq!(v.findings.len(), 1);
        assert_eq!(v.findings[0].rule, ANALYSIS_FAILED);
        assert_eq!(v.findings[0].span, Span { start: 9, end: 17 });
        assert!(
            v.findings[0].message.contains("test"),
            "{}",
            v.findings[0].message
        );
        let v = fail_closed("Get-Date", "test");
        assert_eq!(v, Verdict::new(vec![]));
    }

    #[test]
    fn fail_closed_is_danger_when_the_scan_itself_panics() {
        let v = fail_closed_with("Get-Date", "test", |_| panic!("scan bug"));
        assert_eq!(v.level, Level::Danger);
        assert_eq!(v.findings[0].rule, ANALYSIS_FAILED);
        assert_eq!(v.findings[0].span, Span { start: 0, end: 8 });
    }
}
