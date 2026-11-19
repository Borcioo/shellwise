//! `parse-error`: the text does not parse. A deny kind is `break` (the shell refuses the text and
//! runs none of it); any other kind is `warn`. `parse-error-destructive`: any other kind when the
//! raw text names a command of the destructive table is `danger`, under its own id so that a level
//! configured for `parse-error` does not lower it.

use super::{Ctx, Rule};
use crate::Shell;
use crate::level::{Finding, Level, Span};
use crate::parse::{ParseError, ParseKind, QuoteKind};
use crate::scan;

pub const PARSE_ERROR: &str = "parse-error";
pub const PARSE_ERROR_DESTRUCTIVE: &str = "parse-error-destructive";

/// A backslash before a double quote, from code points.
const BACKSLASH_QUOTE: &str = "\x5c\x22";

/// Whether the shell is proven to refuse every text with this kind of error. An unclosed quote
/// is, except in a PowerShell text holding a here-string opener (`@'`, `@"`), which the parser
/// reads as an unclosed quote where PowerShell accepts some passed as arguments, or a backslash
/// before a double quote, which the PowerShell host ran in texts ParseInput refuses.
pub fn is_deny_kind(kind: &ParseKind, command: &str, shell: Shell) -> bool {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    match kind {
        ParseKind::UnclosedQuote(_) => {
            !(pwsh
                && (command.contains("@'")
                    || command.contains("@\"")
                    || command.contains(BACKSLASH_QUOTE)))
        }
        _ => false,
    }
}

/// The parse error the rules see, when it is not a deny kind and not an internal failure, with
/// whether the raw text names a command of the destructive table.
fn other_kind<'a>(ctx: &Ctx<'a>) -> Option<(&'a ParseError, bool)> {
    let e = ctx.parse_error?;
    if is_deny_kind(&e.kind, ctx.input.command, ctx.input.shell) {
        return None;
    }
    let destructive = scan::destructive_row(ctx.input.command).is_some();
    Some((e, destructive))
}

pub struct ParseErrorRule;

impl Rule for ParseErrorRule {
    fn id(&self) -> &'static str {
        PARSE_ERROR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(e) = ctx.parse_error else {
            return;
        };
        let command = ctx.input.command;
        let at = position(command, e.span.start);
        match e.kind {
            ParseKind::UnclosedQuote(q) if is_deny_kind(&e.kind, command, ctx.input.shell) => {
                let quote = match q {
                    QuoteKind::Single => '\'',
                    QuoteKind::Double => '"',
                    QuoteKind::Backtick => '`',
                };
                out.push(finding(
                    PARSE_ERROR,
                    Level::Break,
                    e,
                    command,
                    format!(
                        "{}: the {quote} opened at {at} is never closed, so the shell refuses the whole command and runs none of it",
                        e.message
                    ),
                    format!(
                        "close the {quote} opened at {at}, or write the text to a file and pass the file"
                    ),
                ));
            }
            _ => {
                if let Some((e, false)) = other_kind(ctx) {
                    out.push(finding(
                        PARSE_ERROR,
                        Level::Warn,
                        e,
                        command,
                        format!("{} at {at}", e.message),
                        syntax_fix(e, &at),
                    ));
                }
            }
        }
    }
}

pub struct ParseErrorDestructiveRule;

impl Rule for ParseErrorDestructiveRule {
    fn id(&self) -> &'static str {
        PARSE_ERROR_DESTRUCTIVE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some((e, true)) = other_kind(ctx) else {
            return;
        };
        let command = ctx.input.command;
        let at = position(command, e.span.start);
        out.push(finding(
            PARSE_ERROR_DESTRUCTIVE,
            Level::Danger,
            e,
            command,
            format!(
                "{} at {at}; the text also names a command that deletes or discards data",
                e.message
            ),
            syntax_fix(e, &at),
        ));
    }
}

fn syntax_fix(e: &ParseError, at: &str) -> String {
    format!("correct the syntax at {at} ({})", e.message)
}

fn finding(
    rule: &'static str,
    level: Level,
    e: &ParseError,
    command: &str,
    message: String,
    fix: String,
) -> Finding {
    Finding {
        rule,
        level,
        message,
        fix: Some(fix),
        span: Span {
            start: e.span.start.min(command.len()),
            end: e.span.end.min(command.len()),
        },
    }
}

/// `column <n>` on the first line, `line <l>, column <n>` after it; both count characters from 1.
fn position(text: &str, at: usize) -> String {
    let before = text.get(..at.min(text.len())).unwrap_or(text);
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    if line == 1 {
        format!("column {column}")
    } else {
        format!("line {line}, column {column}")
    }
}
