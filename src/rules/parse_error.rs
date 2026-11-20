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

/// Whether the shell is proven to refuse every text with this kind of error: an unclosed quote in
/// either shell; in PowerShell also an empty pipe element and a parameter glued to a comma, which
/// the PowerShell parser identifies only in the shapes pwsh refuses.
pub fn is_deny_kind(kind: &ParseKind, _command: &str, shell: Shell) -> bool {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    match kind {
        ParseKind::UnclosedQuote(_) => true,
        ParseKind::EmptyPipeElement | ParseKind::MissingArgument => pwsh,
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
        if is_deny_kind(&e.kind, command, ctx.input.shell) {
            let (message, fix) = deny_text(e, command, ctx.input.shell, &at);
            out.push(finding(PARSE_ERROR, Level::Break, e, command, message, fix));
        } else if let Some((e, false)) = other_kind(ctx) {
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

/// The message and Fix line of a deny kind, the Fix chosen by the shape of the text.
fn deny_text(e: &ParseError, command: &str, shell: Shell, at: &str) -> (String, String) {
    const REFUSED: &str = "so the shell refuses the whole command and runs none of it";
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    match e.kind {
        ParseKind::UnclosedQuote(q) => {
            let quote = match q {
                QuoteKind::Single => '\'',
                QuoteKind::Double => '"',
                QuoteKind::Backtick => '`',
            };
            let here = pwsh && command[e.span.start..].starts_with('@');
            let message = if here {
                format!(
                    "{}: the here-string opened at {at} never ends, {REFUSED}",
                    e.message
                )
            } else {
                format!(
                    "{}: the {quote} opened at {at} is never closed, {REFUSED}",
                    e.message
                )
            };
            let typographic = command
                .char_indices()
                .find(|&(_, c)| ('\u{2018}'..='\u{201e}').contains(&c));
            let fix = if here {
                format!("end the here-string opened at {at} with a line that starts with {quote}@")
            } else if let (true, Some((t, _))) = (pwsh, typographic) {
                format!(
                    "replace the typographic quote at {} with ' or \"",
                    position(command, t)
                )
            } else if pwsh && q == QuoteKind::Double && command.contains(BACKSLASH_QUOTE) {
                "in PowerShell write a quote inside \"…\" as \"\" or use '…'".to_string()
            } else {
                format!(
                    "close the {quote} opened at {at}, or write the text to a file and pass the file"
                )
            };
            (message, fix)
        }
        ParseKind::EmptyPipeElement => {
            let pipe = e.span.end.saturating_sub(1);
            let pipe_at = position(command, pipe);
            let keyword = command
                .get(e.span.start..pipe)
                .filter(|_| pipe > e.span.start)
                .and_then(|t| t.split(|c: char| !c.is_alphanumeric()).next())
                .filter(|k| !k.is_empty());
            match keyword {
                Some(kw) => (
                    format!(
                        "PowerShell cannot pipe a {kw} statement: the | at {pipe_at} starts an empty pipe element, {REFUSED}"
                    ),
                    format!("write $( before the {kw} at {at} and ) before the | at {pipe_at}"),
                ),
                None => (
                    format!("the | at {pipe_at} has no command after it, {REFUSED}"),
                    format!(
                        "remove the empty | at {pipe_at}, or put the command after it on the same line"
                    ),
                ),
            }
        }
        ParseKind::MissingArgument => {
            let word = command.get(e.span.start..e.span.end).unwrap_or("");
            let message = format!(
                "PowerShell reads {word} as a parameter and then finds no argument before the comma, {REFUSED}"
            );
            // Quoting is the fix only for a word of plain text.
            let plain = !word.is_empty()
                && !word.contains(['\'', '"', '`', '$', '@', '(', ')', '{', '}', '#']);
            let fix = if plain {
                format!("quote the argument: '{word}'")
            } else {
                syntax_fix(e, at)
            };
            (message, fix)
        }
        _ => (format!("{} at {at}", e.message), syntax_fix(e, at)),
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
