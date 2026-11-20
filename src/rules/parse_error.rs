//! `parse-error`: the text does not parse. A deny kind is `break` (the shell refuses the text from
//! the error on: PowerShell runs none of it, Bash runs the complete commands before it, which
//! `bash_ran_before` finds); any other kind is `warn`. `parse-error-destructive`: any other kind
//! when the raw text names a command of the destructive table is `danger`, under its own id so
//! that a level configured for `parse-error` does not lower it; so is a raw destructive match in
//! the commands Bash runs before a deny kind when the parser cannot read them.

use super::{Ctx, Rule};
use crate::ir::{ChainOp, Elem, Script, Stmt};
use crate::level::{Finding, Level, Span};
use crate::parse::{self, ParseError, ParseKind, QuoteKind};
use crate::scan;
use crate::{BashProfile, Deadline, Shell};

pub const PARSE_ERROR: &str = "parse-error";
pub const PARSE_ERROR_DESTRUCTIVE: &str = "parse-error-destructive";

/// A backslash before a double quote, from code points.
const BACKSLASH_QUOTE: &str = "\x5c\x22";

/// Whether the shell is proven to refuse the text from this kind of error on: an unclosed quote in
/// either shell; in PowerShell also an empty pipe element and a parameter glued to a comma, which
/// the PowerShell parser identifies only in the shapes pwsh refuses. PowerShell then runs none of
/// the text; Bash runs the complete commands before it (`bash_ran_before`).
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

/// What the shell runs of a text with a deny kind, when it runs none of it.
const REFUSED: &str = "so the shell refuses the whole command and runs none of it";

/// The message and Fix line of a deny kind, the Fix chosen by the shape of the text.
fn deny_text(e: &ParseError, command: &str, shell: Shell, at: &str) -> (String, String) {
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

/// What Bash runs of a text before its deny-kind parse error. Bash reads and runs one complete
/// command at a time, so every complete command before the one holding the error runs (execution
/// oracle, Ruling 126).
#[derive(Debug)]
pub enum BashRan {
    /// Nothing: the error is in the first command Bash reads.
    Nothing,
    /// The complete commands of `command[..end]`, as the parser read them.
    Commands { end: usize, script: Script },
    /// Bash may run `command[..end]`, but the parser could not read where its commands end.
    Unread { end: usize },
}

/// How many line ends `bash_ran_before` tries, from the error's line back, before it gives up and
/// reads the text before the error's line as `Unread`.
const MAX_CUTS: usize = 32;

/// How many bytes all of `bash_ran_before`'s parses may read together before it gives up the
/// same way: a 56 KB text open over 8000 lines took 1.2 s with the cut cap alone (release).
const MAX_CUT_BYTES: usize = 256 * 1024;

/// The command `bash_ran_before` appends to a cut to prove the cut ends a complete command: it
/// stays a statement of its own only after one.
const SENTINEL: &str = ":";

/// What Bash runs of `command` before the deny-kind error at `error_at`: the longest prefix that
/// ends at a line end and holds only complete commands. A prefix proves that when the text with
/// `SENTINEL` appended parses and the sentinel is a statement of its own after it (not an
/// argument after a `\`, a heredoc line, a pipe element or the right side of `&&`/`||`); a
/// prefix that does not parse ends inside a construct still open, so the cut before it is tried.
pub fn bash_ran_before(
    command: &str,
    error_at: usize,
    profile: BashProfile,
    deadline: &Deadline,
) -> BashRan {
    let line_start = command
        .get(..error_at)
        .and_then(|t| t.rfind('\n'))
        .map_or(0, |n| n + 1);
    let cuts = command[..line_start]
        .match_indices('\n')
        .map(|(n, _)| n + 1)
        .rev();
    let mut read = 0usize;
    for (tried, end) in cuts.enumerate() {
        read += end;
        if tried == MAX_CUTS || read > MAX_CUT_BYTES || deadline.expired() {
            return BashRan::Unread { end: line_start };
        }
        let text = format!("{}{SENTINEL}", &command[..end]);
        match parse::bash::parse(&text, profile) {
            Ok(mut script) if sentinel_stands_alone(&script, end) => {
                script.stmts.pop();
                script.joins.truncate(script.stmts.len());
                return if script.stmts.is_empty() {
                    BashRan::Nothing
                } else {
                    BashRan::Commands { end, script }
                };
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind, ParseKind::Internal(_) | ParseKind::TooDeep) => {
                return BashRan::Unread { end: line_start };
            }
            Err(_) => {}
        }
    }
    BashRan::Nothing
}

/// The last statement is the sentinel alone, starting at `end` and joined by a newline.
fn sentinel_stands_alone(script: &Script, end: usize) -> bool {
    let last = script.stmts.len().wrapping_sub(1);
    let alone = match script.stmts.last() {
        Some(Stmt::Pipeline(p)) => match p.elems.as_slice() {
            [Elem::Cmd(c)] => c.span.start == end && c.typed == SENTINEL,
            _ => false,
        },
        _ => false,
    };
    alone
        && matches!(
            script.join(last),
            None | Some(ChainOp::Seq | ChainOp::Background)
        )
}

/// The `parse-error` message of a Bash deny kind whose text runs complete commands before the
/// error, the line the refused text starts on named.
pub fn ran_before_message(message: &str, command: &str, end: usize, sure: bool) -> String {
    let line = command[..end].matches('\n').count() + 1;
    let runs = if sure { "runs" } else { "may run" };
    message.replace(
        REFUSED,
        &format!("so Bash refuses the text from line {line} on, but {runs} the lines before it"),
    )
}

/// `parse-error-destructive` for a raw destructive match at `hit` in the lines Bash runs before a
/// deny-kind error, when the parser could not read them.
pub fn unread_before(e: &ParseError, command: &str, hit: Span) -> Finding {
    let at = position(command, e.span.start);
    Finding {
        rule: PARSE_ERROR_DESTRUCTIVE,
        level: Level::Danger,
        message: format!(
            "{}: Bash runs the lines before the error at {at}, and the raw scan flags part of them as destructive",
            e.message
        ),
        fix: Some(format!(
            "correct the syntax at {at}, then run the command again so each line can be checked"
        )),
        span: hit,
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
