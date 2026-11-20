//! `inline-script-too-long`: a command over a lines or characters threshold of its shell. It would
//! run, but a script that long written inline is never linted before it runs. Break, on command
//! lines only (a file is what the fix asks for), on the raw text before the parse, and not affected
//! by the allow marker. The Fix line is `too-long`'s: write the command to a file of its own, lint
//! it, run it.
//!
//! The rule stays silent when a `too-long` finding is already in the output: the hard limit is the
//! sharper message and both carry the same fix. `length_rules()` runs it after `too-long`.

use super::length::{TOO_LONG, route_fix};
use super::{Ctx, Rule, Scope};
use crate::Shell;
use crate::level::{Finding, Level, Span};

pub const INLINE_SCRIPT_TOO_LONG: &str = "inline-script-too-long";

/// A command fires when it has more than `lines` lines or more than `chars` characters. The pair
/// is the one of the fixed grid (lines in 40, 60, 80, 100, 150 and characters in 4,000, 6,000,
/// 8,000) with the most `failed` corpus rows caught while at most 0.5 % of the shell's `ok` rows
/// fire; a tie goes to the lower lines, then the lower characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub lines: usize,
    pub chars: usize,
}

/// 106 of 25,004 `ok` rows (0.42 %) and 17 `failed` rows (corpus of 2026-11-19).
pub const PWSH_THRESHOLD: Threshold = Threshold {
    lines: 80,
    chars: 6000,
};

/// 101 of 21,628 `ok` rows (0.47 %) and 3 `failed` rows, not counting the rows `too-long` owns at
/// its default limit of 7500. At that limit every Git Bash command over 8,000 characters is
/// `too-long`, so the character value fires only for the POSIX profile.
pub const BASH_THRESHOLD: Threshold = Threshold {
    lines: 100,
    chars: 8000,
};

pub fn threshold(shell: Shell) -> Threshold {
    match shell {
        Shell::Pwsh | Shell::Powershell5 => PWSH_THRESHOLD,
        Shell::Bash(_) => BASH_THRESHOLD,
    }
}

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
            span: Span {
                start: 0,
                end: text.len(),
            },
        });
    }
}
