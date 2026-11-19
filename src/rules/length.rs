//! `too-long`: a command line Git Bash cuts. The Bash tool hands Git Bash the command inside
//! single quotes, each `'` written as `'\''`; the launcher cuts that text at 7790 characters and
//! runs the part before the cut, sometimes with exit 0. The rule runs on the raw text, before the
//! size cap and the parse (`rules::length_rules`), so it still fires on a command over
//! `MAX_INPUT_BYTES`.

use super::{Ctx, Rule, Scope};
use crate::level::{Finding, Level, Span};
use crate::{BashProfile, Shell};

pub const TOO_LONG: &str = "too-long";

/// The escaped length (`cmd.replace("'", "'\\''").len()`) at which Git Bash cuts the command.
const GIT_BASH_ESCAPED_LIMIT: usize = 7790;

/// The length after the quote escaping: every `'` becomes four bytes.
fn escaped_len(command: &str) -> usize {
    command.len() + 3 * command.bytes().filter(|&b| b == b'\'').count()
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
                "the command is {escaped} characters once its quotes are escaped, and Git Bash cuts a command at {GIT_BASH_ESCAPED_LIMIT}: only the first part would run"
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

/// `<scratch>/command.sh`, with forward slashes so Git Bash can use it as written.
fn scratch_file(ctx: &Ctx) -> String {
    let dir = match &ctx.cfg.scratch_dir {
        Some(dir) => dir.clone(),
        None => std::env::temp_dir().join("shellwise"),
    };
    dir.join("command.sh")
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ir::EnvView;
    use crate::level::Verdict;
    use crate::{AnalyseInput, Deadline, Origin, Os, analyse};
    use std::path::PathBuf;
    use std::time::Instant;

    fn run(command: &str, shell: Shell, origin: Origin, cfg: &Config) -> Verdict {
        let input = AnalyseInput {
            bytes: command.as_bytes(),
            shell,
            os: Os::Windows,
            cwd: None,
            env: EnvView::new(),
            origin,
        };
        analyse(&input, cfg, &Deadline::new(Instant::now(), 8000))
    }

    fn git_bash(command: &str, origin: Origin, cfg: &Config) -> Verdict {
        run(command, Shell::Bash(BashProfile::GitBash), origin, cfg)
    }

    /// `echo ` and a run of `a`, `escaped` characters long once quotes are escaped.
    fn echo_of(escaped: usize) -> String {
        format!("echo {}", "a".repeat(escaped - 5))
    }

    fn fired(v: &Verdict) -> bool {
        v.findings.iter().any(|f| f.rule == TOO_LONG)
    }

    #[test]
    fn the_escape_counts_four_bytes_per_quote() {
        assert_eq!(escaped_len("a'b"), 6);
        assert_eq!(escaped_len("''"), 8);
        assert_eq!(escaped_len("abc"), 3);
    }

    #[test]
    fn the_limit_is_7790_escaped_characters() {
        let cfg = Config::default();
        assert!(!fired(&git_bash(&echo_of(7789), Origin::CommandLine, &cfg)));
        assert!(fired(&git_bash(&echo_of(7790), Origin::CommandLine, &cfg)));
    }

    /// Mutant M30 (Ruling 106(d)): `length_stage` runs a length rule without asking its scope.
    /// The rule must not check the origin itself, so a file of the same length stays ok only
    /// while the stage's scope check is there.
    #[test]
    fn a_file_of_the_same_length_is_not_too_long() {
        let cfg = Config::default();
        let long = echo_of(8000);
        assert!(fired(&git_bash(&long, Origin::CommandLine, &cfg)));
        let v = git_bash(&long, Origin::File, &cfg);
        assert!(!fired(&v), "{:?}", v.findings);
    }

    #[test]
    fn only_git_bash_has_the_limit() {
        let cfg = Config::default();
        let long = echo_of(9000);
        for shell in [Shell::Bash(BashProfile::Posix), Shell::Pwsh] {
            assert!(!fired(&run(&long, shell, Origin::CommandLine, &cfg)), "{shell:?}");
        }
    }

    #[test]
    fn the_fix_line_holds_the_configured_scratch_path() {
        let cfg = Config {
            scratch_dir: Some(PathBuf::from("/work/scratch")),
            ..Config::default()
        };
        let v = git_bash(&echo_of(7790), Origin::CommandLine, &cfg);
        let line = v.findings[0].fix_line().expect("a fix line");
        assert_eq!(
            line,
            "Fix: write the command to /work/scratch/command.sh with the Write tool, run shellwise lint /work/scratch/command.sh, then run bash /work/scratch/command.sh"
        );
    }

    #[test]
    fn without_a_configured_scratch_the_fix_names_the_temp_dir() {
        let v = git_bash(&echo_of(7790), Origin::CommandLine, &Config::default());
        let line = v.findings[0].fix_line().expect("a fix line");
        assert!(line.contains("shellwise/command.sh"), "{line}");
    }
}
