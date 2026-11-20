//! `too-long`: a command line Git Bash cuts. The Bash tool runs `bash.exe -c <wrapper>`, where the
//! wrapper holds the command inside `eval '…'` with each `'` written as `'"'"'`, and Git Bash keeps
//! only the first 8186 characters of that text. A command cut inside the quote runs none of it
//! (`unexpected EOF`); one cut after it runs, but the wrapper's own tail is lost. The rule runs on
//! the raw text, before the size cap and the parse (`rules::length_rules`), so it still fires on a
//! command over `MAX_INPUT_BYTES`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Ctx, Rule, Scope};
use crate::level::{Finding, Level, Span};
use crate::{BashProfile, Shell};

pub const TOO_LONG: &str = "too-long";

/// The shortest escaped length Git Bash cuts: its 8186-character limit less the Bash tool's
/// 515-character wrapper, plus one.
const GIT_BASH_ESCAPED_LIMIT: usize = 7672;

/// The length of the command once the wrapper has escaped it: UTF-16 units, as the Windows command
/// line counts them, and four more for each `'` (written as `'"'"'`).
fn escaped_len(command: &str) -> usize {
    command.encode_utf16().count() + 4 * command.matches('\'').count()
}

pub struct TooLong;

impl Rule for TooLong {
    fn id(&self) -> &'static str {
        TOO_LONG
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if ctx.input.shell != Shell::Bash(BashProfile::GitBash) {
            return;
        }
        let command = ctx.input.command;
        let escaped = escaped_len(command);
        if escaped < GIT_BASH_ESCAPED_LIMIT {
            return;
        }
        let file = scratch_file(ctx);
        out.push(Finding {
            rule: TOO_LONG,
            level: Level::Break,
            message: format!(
                "the command is {escaped} characters once the Bash tool escapes it, and Git Bash cuts it from {GIT_BASH_ESCAPED_LIMIT}: it would fail or lose its end"
            ),
            fix: Some(format!(
                "write the command to {file} with the Write tool, run shellwise lint {file}, then run bash {file}"
            )),
            span: Span {
                start: 0,
                end: command.len(),
            },
        });
    }
}

/// Calls in this process so far, so two calls in one clock tick get two names.
static CALLS: AtomicU64 = AtomicU64::new(0);

/// A script file of its own for this call, `command-<pid>-<time>-<n>.sh`, in `scratch_dir` or else a
/// per-user folder under the temp dir, so parallel agents never write the same file. Forward slashes,
/// so Git Bash can use it as written.
fn scratch_file(ctx: &Ctx) -> String {
    let dir = match &ctx.cfg.scratch_dir {
        Some(dir) => dir.clone(),
        None => user_temp_dir(),
    };
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64);
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    let name = format!("command-{:x}-{time:x}-{n}.sh", std::process::id());
    dir.join(name).to_string_lossy().replace('\\', "/")
}

/// `<temp>/shellwise-<user>`: the temp dir is shared on POSIX systems.
fn user_temp_dir() -> PathBuf {
    let user = ["USERNAME", "USER"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "user".to_string());
    std::env::temp_dir().join(format!("shellwise-{user}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ir::EnvView;
    use crate::level::Verdict;
    use crate::{AnalyseInput, Deadline, Origin, Os, analyse};
    use std::time::Instant;

    fn run(command: &str, shell: Shell, origin: Origin, cfg: &Config) -> Verdict {
        let input = AnalyseInput {
            bytes: command.as_bytes(),
            shell,
            os: Os::Windows,
            cwd: None,
            env: EnvView::new(),
            origin,
            problem: None,
        };
        analyse(&input, cfg, &Deadline::new(Instant::now(), 8000))
    }

    fn git_bash(command: &str, origin: Origin, cfg: &Config) -> Verdict {
        run(command, Shell::Bash(BashProfile::GitBash), origin, cfg)
    }

    fn long() -> String {
        format!("echo {}", "a".repeat(8000))
    }

    fn fired(v: &Verdict) -> bool {
        v.findings.iter().any(|f| f.rule == TOO_LONG)
    }

    /// The three paths of a Fix line, which must be one file.
    fn paths(line: &str) -> Vec<&str> {
        let rest = line
            .strip_prefix("Fix: write the command to ")
            .unwrap_or_else(|| panic!("{line}"));
        let (a, rest) = rest
            .split_once(" with the Write tool, run shellwise lint ")
            .unwrap();
        let (b, c) = rest.split_once(", then run bash ").unwrap();
        vec![a, b, c]
    }

    fn fix_line(cfg: &Config) -> String {
        let v = git_bash(&long(), Origin::CommandLine, cfg);
        v.findings[0].fix_line().expect("a fix line")
    }

    #[test]
    fn the_escape_counts_utf16_units_and_four_more_per_quote() {
        // The wrapper of the Bash tool (CLI 2.1.327) writes `a'b` as `a'"'"'b`.
        assert_eq!(escaped_len("a'b"), 7);
        assert_eq!(escaped_len("''"), 10);
        assert_eq!(escaped_len("abc"), 3);
        // Two bytes in UTF-8, one unit on the command line; an emoji is two units.
        assert_eq!(escaped_len("\u{105}\u{105}"), 2);
        assert_eq!(escaped_len("\u{1f600}"), 2);
    }

    /// Mutant M30 (Ruling 106(d)): `length_stage` runs a length rule without asking its scope.
    /// The rule does not check the origin itself, so a file of the same length stays ok only while
    /// the stage's scope check is there.
    #[test]
    fn a_file_of_the_same_length_is_not_too_long() {
        let cfg = Config::default();
        assert!(fired(&git_bash(&long(), Origin::CommandLine, &cfg)));
        let v = git_bash(&long(), Origin::File, &cfg);
        assert!(!fired(&v), "{:?}", v.findings);
    }

    #[test]
    fn only_git_bash_has_the_limit() {
        let cfg = Config::default();
        for shell in [Shell::Bash(BashProfile::Posix), Shell::Pwsh] {
            assert!(
                !fired(&run(&long(), shell, Origin::CommandLine, &cfg)),
                "{shell:?}"
            );
        }
    }

    #[test]
    fn the_fix_line_names_one_new_file_in_the_configured_scratch() {
        let cfg = Config {
            scratch_dir: Some(PathBuf::from("/work/scratch")),
            ..Config::default()
        };
        let line = fix_line(&cfg);
        let p = paths(&line);
        assert!(p[0] == p[1] && p[1] == p[2], "{line}");
        let name = p[0].strip_prefix("/work/scratch/command-").expect(&line);
        assert!(name.ends_with(".sh") && !name.contains('/'), "{line}");
    }

    /// Ruling 109: parallel agents must never be sent to the same file.
    #[test]
    fn two_calls_get_two_file_names() {
        let cfg = Config::default();
        let (a, b) = (fix_line(&cfg), fix_line(&cfg));
        assert_ne!(paths(&a)[0], paths(&b)[0]);
    }

    #[test]
    fn without_a_configured_scratch_the_file_is_in_a_per_user_temp_folder() {
        let line = fix_line(&Config::default());
        let file = paths(&line)[0];
        let temp = std::env::temp_dir().to_string_lossy().replace('\\', "/");
        let rest = file
            .strip_prefix(temp.trim_end_matches('/'))
            .unwrap_or_else(|| panic!("{file} is not under {temp}"));
        let (folder, name) = rest.trim_start_matches('/').split_once('/').expect(file);
        assert!(
            folder.starts_with("shellwise-") && folder.len() > "shellwise-".len(),
            "{file}"
        );
        assert!(
            name.starts_with("command-") && name.ends_with(".sh"),
            "{file}"
        );
    }
}
