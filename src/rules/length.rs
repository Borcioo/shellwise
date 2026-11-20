//! `too-long`: a command line its host cuts or refuses. The rule runs on the raw text, before the
//! size cap and the parse (`rules::length_rules`), so it still fires on a command over
//! `MAX_INPUT_BYTES`. It reports the first limit the command is over, once:
//!
//! - Git Bash. The Bash tool runs `bash.exe -c <wrapper>`, where the wrapper holds the command
//!   inside `eval '…'` with each `'` written as `'"'"'`, and Git Bash keeps only the first 8186
//!   characters of that text. A command cut inside the quote runs none of it (`unexpected EOF`);
//!   one cut after it runs, but the wrapper's own tail is lost. The limit is
//!   `limits.git_bash_command` from the config.
//! - A PowerShell command that starts a program with a `line_limit` in `data/programs.toml`
//!   (`cmd /c …`, Windows only). pwsh starts the program with its full path in place of the typed
//!   word (`launch_path_units` of the row), and the program refuses a longer line; cmd prints
//!   "The command line is too long." and nothing runs, with exit 0 in the PowerShell tool.
//!
//! The PowerShell tool's own text has no limit here: the tool passes it in an environment
//! variable, not on the command line, and scripts of 100,000 characters run.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Ctx, Rule, Scope};
use crate::config::Config;
use crate::level::{Finding, Level, Span};
use crate::{BashProfile, Os, Shell};

pub const TOO_LONG: &str = "too-long";

/// The `extra` keys of a program row this rule reads.
const LINE_LIMIT: &str = "line_limit";
const LAUNCH_PATH_UNITS: &str = "launch_path_units";

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
        let command = ctx.input.command;
        let Some((message, fix)) = git_bash(ctx).or_else(|| program_line(ctx)) else {
            return;
        };
        out.push(Finding {
            rule: TOO_LONG,
            level: Level::Break,
            message,
            fix: Some(fix),
            span: Span {
                start: 0,
                end: command.len(),
            },
        });
    }
}

/// The message and Fix line when the Bash tool's escaped command is at or over the Git Bash limit.
fn git_bash(ctx: &Ctx) -> Option<(String, String)> {
    if ctx.input.shell != Shell::Bash(BashProfile::GitBash) {
        return None;
    }
    let escaped = escaped_len(ctx.input.command);
    let limit = ctx.cfg.limits.git_bash_command;
    if escaped < limit {
        return None;
    }
    Some((
        format!(
            "the command is {escaped} characters once the Bash tool escapes it, at or over the Git Bash limit of {limit}: Git Bash would cut it, so it would fail or lose its end"
        ),
        route_fix(ctx.cfg, ctx.input.shell),
    ))
}

/// The message and Fix line when a PowerShell command starts a program whose command line would
/// be over the program's `line_limit`, counting the full path pwsh starts it by.
fn program_line(ctx: &Ctx) -> Option<(String, String)> {
    let input = ctx.input;
    if input.os != Os::Windows || !matches!(input.shell, Shell::Pwsh | Shell::Powershell5) {
        return None;
    }
    let (word, rest) = leading_word(input.command)?;
    let program = crate::programs::lookup(word, input.shell, input.os)?;
    let units_of = |key: &str| {
        program
            .extra
            .get(key)
            .and_then(|v| v.as_integer())
            .and_then(|n| usize::try_from(n).ok())
    };
    let limit = units_of(LINE_LIMIT)?;
    // pwsh puts the program's path in place of everything up to the end of its word.
    let line = rest.encode_utf16().count() + units_of(LAUNCH_PATH_UNITS).unwrap_or(0);
    if line <= limit {
        return None;
    }
    let fix = program.fix.clone()?;
    Some((
        format!(
            "{} gets a command line of {line} characters, over its limit of {limit}: it refuses it and nothing runs",
            program.name
        ),
        fix,
    ))
}

/// The first word of the command, without its quotes and without a leading call operator, and the
/// text after it.
fn leading_word(text: &str) -> Option<(&str, &str)> {
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (token, after) = rest.split_at(end);
        if token.is_empty() {
            return None;
        }
        if token != "&" {
            return Some((token.trim_matches(|c| c == '"' || c == '\''), after));
        }
        rest = after;
    }
}

/// The Fix line of both length rules: write the command to a file of its own (Ruling 109), lint
/// the file, run it with the shell's runner. The path has forward slashes, so Git Bash reads it as
/// written, and is single-quoted where a shell reads it when it holds a space.
pub fn route_fix(cfg: &Config, shell: Shell) -> String {
    let ext = match shell {
        Shell::Bash(_) => ".sh",
        Shell::Pwsh | Shell::Powershell5 => ".ps1",
    };
    let file = scratch_file(cfg, ext);
    let shell_file = if file.contains(' ') {
        format!("'{file}'")
    } else {
        file.clone()
    };
    let write = format!(
        "write the command to {file} with the Write tool, run shellwise lint {shell_file}, then run"
    );
    match shell {
        Shell::Bash(_) => format!("{write} bash {shell_file}"),
        Shell::Pwsh => format!("{write} pwsh -NoProfile -File {shell_file}"),
        Shell::Powershell5 => format!("{write} powershell -NoProfile -File {shell_file}"),
    }
}

/// Calls in this process so far, so two calls in one clock tick get two names.
static CALLS: AtomicU64 = AtomicU64::new(0);

/// A script file of its own for this call, `command-<pid>-<time>-<n><ext>`, in `scratch_dir` or
/// else a per-user folder under the temp dir, so parallel agents never write the same file. Forward
/// slashes, so Git Bash can use it as written.
fn scratch_file(cfg: &Config, ext: &str) -> String {
    let dir = match &cfg.scratch_dir {
        Some(dir) => dir.clone(),
        None => user_temp_dir(),
    };
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64);
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    let name = format!("command-{:x}-{time:x}-{n}{ext}", std::process::id());
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
        // The wrapper of the Bash tool (CLI 2.1.326) writes `a'b` as `a'"'"'b`.
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

    /// `limits.git_bash_command` moves the boundary. 7672 is the boundary measured on CLI 2.1.326
    /// with a 515-character wrapper, of which Git Bash keeps 8186 characters.
    #[test]
    fn the_configured_limit_moves_the_boundary() {
        let cfg = Config {
            limits: crate::config::Limits {
                git_bash_command: 7672,
            },
            ..Config::default()
        };
        let echo = |n: usize| format!("echo {}", "a".repeat(n - 5));
        assert!(!fired(&git_bash(&echo(7671), Origin::CommandLine, &cfg)));
        assert!(fired(&git_bash(&echo(7672), Origin::CommandLine, &cfg)));
    }

    /// A path with a space is quoted where a shell reads it, and only there.
    #[test]
    fn a_scratch_path_with_a_space_is_quoted_for_the_shell() {
        let cfg = Config {
            scratch_dir: Some(PathBuf::from("/work/my scratch")),
            ..Config::default()
        };
        let line = fix_line(&cfg);
        let p = paths(&line);
        assert!(p[0].starts_with("/work/my scratch/command-"), "{line}");
        let quoted = format!("'{}'", p[0]);
        assert!(p[1] == quoted && p[2] == quoted, "{line}");
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
