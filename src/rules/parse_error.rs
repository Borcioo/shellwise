//! `parse-error`: the text does not parse. A deny kind is `break` (the shell refuses the text and
//! runs none of it); any other kind is `warn`, or `danger` when the raw text names a command that
//! deletes or discards data.

use super::{Ctx, Rule};
use crate::level::{Finding, Level, Span};
use crate::parse::{ParseKind, QuoteKind};
use crate::scan;

pub const PARSE_ERROR: &str = "parse-error";

/// Whether the shell is proven to refuse every text with this kind of error. An unclosed quote
/// is, except in a text holding a here-string opener (`@'`, `@"`): the parser reads some
/// here-strings passed as arguments as an unclosed quote where PowerShell accepts them.
pub fn is_deny_kind(kind: &ParseKind, command: &str) -> bool {
    match kind {
        ParseKind::UnclosedQuote(_) => !(command.contains("@'") || command.contains("@\"")),
        _ => false,
    }
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
        let (level, message, fix) = match e.kind {
            ParseKind::UnclosedQuote(q) if is_deny_kind(&e.kind, command) => {
                let quote = match q {
                    QuoteKind::Single => '\'',
                    QuoteKind::Double => '"',
                    QuoteKind::Backtick => '`',
                };
                (
                    Level::Break,
                    format!(
                        "{}: the {quote} opened at {at} is never closed, so the shell refuses the whole command and runs none of it",
                        e.message
                    ),
                    format!(
                        "close the {quote} opened at {at}, or write the text to a file and pass the file"
                    ),
                )
            }
            _ => {
                let destructive = scan::raw_destructive(command).is_some();
                let level = if destructive {
                    Level::Danger
                } else {
                    Level::Warn
                };
                let tail = if destructive {
                    "; the text also names a command that deletes or discards data"
                } else {
                    ""
                };
                (
                    level,
                    format!("{} at {at}{tail}", e.message),
                    format!("correct the syntax at {at} ({})", e.message),
                )
            }
        };
        out.push(Finding {
            rule: PARSE_ERROR,
            level,
            message,
            fix: Some(fix),
            span: Span {
                start: e.span.start.min(command.len()),
                end: e.span.end.min(command.len()),
            },
        });
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
