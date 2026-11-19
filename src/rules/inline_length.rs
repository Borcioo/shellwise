//! The length rules beyond Git Bash's escaped limit (`too-long` in `length.rs`): the other hosts'
//! hard limits, and `inline-script-too-long`. Both are break, run on the raw text before the parse
//! (their context has an empty script), cover command lines only, and are not affected by the
//! allow marker.
//!
//! - `too-long` (this file's `HostLimitRule`): on Windows, a PowerShell command line over what
//!   `CreateProcess` accepts, and a command whose first word is a program with a line limit in
//!   `data/programs.toml` (`cmd /c`) over that limit. The command would not run at all.
//! - `inline-script-too-long`: a command over a lines or characters threshold of its shell. It
//!   would run, but a script that long written inline is never linted. The fix routes it to a
//!   file that `shellwise lint` can read.
//!
//! `inline-script-too-long` stays silent when a `too-long` finding is already in the output: the
//! hard limit is the sharper message and both carry the same fix.

use super::{Ctx, Rule, Scope};
use crate::config::Config;
use crate::level::{Finding, Level, Span};
use crate::{Os, Shell};

pub const TOO_LONG: &str = "too-long";
pub const INLINE_SCRIPT_TOO_LONG: &str = "inline-script-too-long";

/// What `CreateProcess` takes as a command line, in UTF-16 code units. S2 measured the PowerShell
/// tool through a direct spawn: 32,000 ran and 32,700 failed with WinError 206.
pub const NATIVE_ARGV_LIMIT: usize = 32767;

/// The file the fix asks for, in the scratch folder.
const NAME_PWSH: &str = "script.ps1";
const NAME_BASH: &str = "script.sh";

const FIX_PWSH: &str = "write the command to {file} with the Write tool, run shellwise lint {file}, then run pwsh -NoProfile -File {file}";
const FIX_POWERSHELL5: &str = "write the command to {file} with the Write tool, run shellwise lint {file}, then run powershell -NoProfile -File {file}";
const FIX_BASH: &str = "write the command to {file} with the Write tool, run shellwise lint {file}, then run bash {file}";

/// A command fires when it has more than `lines` lines or more than `chars` characters. The pair
/// is the one of the fixed grid (lines in 40, 60, 80, 100, 150 and characters in 4,000, 6,000,
/// 8,000) with the most `failed` corpus rows caught while at most 0.5 % of the shell's `ok` rows
/// fire; a tie goes to the lower lines, then the lower characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub lines: usize,
    pub chars: usize,
}

/// 106 of 25,004 `ok` rows (0.42 %) and 17 `failed` rows on the corpus of 2026-11-18.
pub const PWSH_THRESHOLD: Threshold = Threshold {
    lines: 80,
    chars: 6000,
};

/// 69 of 21,590 `ok` rows (0.32 %) that `too-long` does not already own, and 1 `failed` row.
pub const BASH_THRESHOLD: Threshold = Threshold {
    lines: 150,
    chars: 6000,
};

pub fn threshold(shell: Shell) -> Threshold {
    match shell {
        Shell::Pwsh | Shell::Powershell5 => PWSH_THRESHOLD,
        Shell::Bash(_) => BASH_THRESHOLD,
    }
}

/// The rules of this file, in the order they must run: after Git Bash's `too-long`, so that
/// `inline-script-too-long` can see it. `length_rules()` appends them.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(HostLimitRule), Box::new(InlineScriptRule)]
}

/// The correction both length rules give: write the command to a file in the scratch folder
/// (`cfg.scratch_dir`, else the OS temp folder plus `shellwise`), lint the file, run the file.
/// The path has forward slashes, so Git Bash does not read them as escapes, and is double-quoted
/// when it holds a space.
pub fn route_fix(cfg: &Config, shell: Shell) -> String {
    let (name, template) = match shell {
        Shell::Pwsh => (NAME_PWSH, FIX_PWSH),
        Shell::Powershell5 => (NAME_PWSH, FIX_POWERSHELL5),
        Shell::Bash(_) => (NAME_BASH, FIX_BASH),
    };
    let dir = cfg
        .scratch_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("shellwise"));
    let path = dir.join(name).to_string_lossy().replace('\\', "/");
    let file = if path.contains(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path
    };
    template.replace("{file}", &file)
}

fn whole(text: &str) -> Span {
    Span {
        start: 0,
        end: text.len(),
    }
}

/// The first word of the command, without quotes and without a leading call operator.
fn leading_word(text: &str) -> Option<&str> {
    text.split_whitespace()
        .find(|w| *w != "&")
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
}

/// The line limit of the program the command starts with, from `data/programs.toml`.
fn program_line_limit(text: &str, shell: Shell, os: Os) -> Option<usize> {
    let word = leading_word(text)?;
    crate::programs::lookup(word, shell, os).and_then(|p| p.line_limit)
}

/// `too-long` for the hosts other than Git Bash. Windows only: the other OSes' argument limits
/// are in the megabytes.
pub struct HostLimitRule;

impl Rule for HostLimitRule {
    fn id(&self) -> &'static str {
        TOO_LONG
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let input = ctx.input;
        if input.os != Os::Windows {
            return;
        }
        let (limit, host) = match program_line_limit(input.command, input.shell, input.os) {
            Some(limit) => (limit, "the command interpreter"),
            None => match input.shell {
                Shell::Pwsh | Shell::Powershell5 => (NATIVE_ARGV_LIMIT, "Windows"),
                Shell::Bash(_) => return,
            },
        };
        // The limits count UTF-16 code units; a byte or `char` count would be wrong for text
        // outside the basic plane.
        let units = input.command.encode_utf16().count();
        if units <= limit {
            return;
        }
        out.push(Finding {
            rule: TOO_LONG,
            level: Level::Break,
            message: format!(
                "the command is {units} characters and {host} refuses a command line over {limit}, so it would not run at all"
            ),
            fix: Some(route_fix(ctx.cfg, input.shell)),
            span: whole(input.command),
        });
    }
}

/// `inline-script-too-long`: more lines or more characters than the shell's threshold.
pub struct InlineScriptRule;

impl Rule for InlineScriptRule {
    fn id(&self) -> &'static str {
        INLINE_SCRIPT_TOO_LONG
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if out.iter().any(|f| f.rule == TOO_LONG) {
            return;
        }
        let input = ctx.input;
        let text = input.command;
        let limit = threshold(input.shell);
        let lines = text.bytes().filter(|&b| b == b'\n').count() + 1;
        // Characters are at most bytes, so a short text is never counted.
        let chars = if text.len() > limit.chars {
            text.chars().count()
        } else {
            text.len()
        };
        if lines <= limit.lines && chars <= limit.chars {
            return;
        }
        out.push(Finding {
            rule: INLINE_SCRIPT_TOO_LONG,
            level: Level::Break,
            message: format!(
                "the command is {lines} lines and {chars} characters; a script over {} lines or {} characters written inline is never linted before it runs",
                limit.lines, limit.chars
            ),
            fix: Some(route_fix(ctx.cfg, input.shell)),
            span: whole(text),
        });
    }
}
