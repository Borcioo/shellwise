//! ShellCheck's checks for `shellwise lint <file>`, through rshellcheck-core in process. A module of
//! the binary, called only by `run_lint`: the library's `analyse`, and with it `check` and
//! `hook`, cannot reach it.
//!
//! - Bash files only; a PowerShell file gets nothing from here.
//! - The dataflow analysis runs on files up to `DATAFLOW_MAX_BYTES`; above it ShellCheck runs
//!   without it (its time grows fastest with it). Above `MAX_BYTES` ShellCheck does not run and
//!   the caller prints a notice.
//! - SC2164 (`cd` without `|| exit`) is left out: it fires on a fifth of the agents' commands.
//! - A dataflow analysis that stopped on an internal error leaves the findings incomplete: one
//!   `warn` finding says so, so such a file never reads as clean.
//! - ShellCheck runs on a big-stack thread under the deadline: a deep script must not overflow the
//!   main thread's stack, and a panic or a timeout is a `warn` finding.

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;

use rshellcheck_core::{CheckSpec, Position, Severity, check_script};
use shellwise::level::{Finding, Level, Span};
use shellwise::{ANALYSIS_INCOMPLETE, Deadline, MAX_INPUT_BYTES, Shell};

/// The largest file the dataflow analysis runs on, in bytes.
pub const DATAFLOW_MAX_BYTES: usize = 15 * 1024;

/// The largest file ShellCheck runs on, in bytes: the size `analyse` itself parses.
pub const MAX_BYTES: usize = MAX_INPUT_BYTES;

/// Codes left out by default.
const EXCLUDED: &[i64] = &[2164];

/// The stack of the thread ShellCheck runs on, as large as `analyse`'s worker.
const STACK: usize = 64 * 1024 * 1024;

/// The columns a tab advances to the next stop of, in ShellCheck's positions.
const TAB_STOP: i64 = 8;

/// ShellCheck's findings for `text`, as the shell `shell` reads it: `None` when ShellCheck does
/// not run on it (not Bash, or over `MAX_BYTES`).
pub fn findings(text: &str, shell: Shell, deadline: &Deadline) -> Option<Vec<Finding>> {
    if !matches!(shell, Shell::Bash(_)) || text.len() > MAX_BYTES {
        return None;
    }
    let spec = CheckSpec {
        filename: "script.sh".to_string(),
        script: text.to_string(),
        shell_type_override: Some(rshellcheck_core::Shell::Bash),
        excluded_warnings: EXCLUDED.to_vec(),
        extended_analysis: Some(text.len() <= DATAFLOW_MAX_BYTES),
        ..CheckSpec::default()
    };
    let (tx, rx) = mpsc::channel();
    let source = text.to_string();
    let spawned = thread::Builder::new()
        .name("shellcheck".into())
        .stack_size(STACK)
        .spawn(move || {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                let result = check_script(&spec);
                let mut out: Vec<Finding> = result
                    .comments
                    .iter()
                    .map(|c| Finding {
                        rule: code_id(c.comment.code),
                        level: level(c.comment.severity),
                        message: c.comment.message.clone(),
                        fix: None,
                        span: Span {
                            start: byte_offset(&source, &c.start),
                            end: byte_offset(&source, &c.end),
                        },
                    })
                    .collect();
                if result.dataflow_error.is_some() {
                    out.push(incomplete(
                        "its dataflow analysis stopped on an internal error",
                    ));
                }
                out
            }));
            let _ = tx.send(result);
        });
    if spawned.is_err() {
        return Some(vec![incomplete("its thread did not start")]);
    }
    Some(match rx.recv_timeout(deadline.remaining()) {
        Ok(Ok(found)) => found,
        Ok(Err(_)) => vec![incomplete("internal error")],
        Err(mpsc::RecvTimeoutError::Timeout) => vec![incomplete("deadline")],
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            vec![incomplete("it ended without a result")]
        }
    })
}

/// The `warn` finding of a ShellCheck run that did not give every finding.
fn incomplete(reason: &str) -> Finding {
    Finding {
        rule: ANALYSIS_INCOMPLETE,
        level: Level::Warn,
        message: format!(
            "ShellCheck's findings are incomplete ({reason}); the shellwise rules ran"
        ),
        fix: None,
        span: Span::default(),
    }
}

/// An error is `break`; a warning, a note and a style hint are `warn`.
fn level(severity: Severity) -> Level {
    match severity {
        Severity::ErrorC => Level::Break,
        Severity::WarningC | Severity::InfoC | Severity::StyleC => Level::Warn,
    }
}

/// `SC<code>` as a rule id, made once per code in this process.
fn code_id(code: i64) -> &'static str {
    static IDS: OnceLock<Mutex<HashMap<i64, &'static str>>> = OnceLock::new();
    let mut ids = IDS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ids.entry(code)
        .or_insert_with(|| Box::leak(format!("SC{code}").into_boxed_str()))
}

/// The byte offset of a ShellCheck position: lines from 1, columns from 1 counting a tab to the
/// next multiple of 8 plus 1. A position past a line's end is the line's end; past the text, its
/// end.
fn byte_offset(text: &str, at: &Position) -> usize {
    let mut start = 0;
    for _ in 1..at.line.max(1) {
        match text[start..].find('\n') {
            Some(i) => start += i + 1,
            None => return text.len(),
        }
    }
    let line = &text[start..];
    let mut column = 1;
    for (i, c) in line.char_indices() {
        if column >= at.column || c == '\n' {
            return start + i;
        }
        column = if c == '\t' {
            (column - 1) / TAB_STOP * TAB_STOP + TAB_STOP + 1
        } else {
            column + 1
        };
    }
    text.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn run(text: &str) -> Vec<Finding> {
        let deadline = Deadline::new(Instant::now(), 8000);
        findings(text, Shell::Bash(shellwise::BashProfile::Posix), &deadline).expect("ran")
    }

    fn codes(text: &str) -> Vec<&'static str> {
        let mut c: Vec<_> = run(text).iter().map(|f| f.rule).collect();
        c.sort();
        c
    }

    /// The span of `code` in `text`, as the text it covers.
    fn covered<'a>(text: &'a str, code: &str) -> &'a str {
        let f = run(text).into_iter().find(|f| f.rule == code).expect(code);
        &text[f.span.start..f.span.end]
    }

    #[test]
    fn an_unquoted_variable_is_sc2086_and_a_clean_script_has_nothing() {
        assert_eq!(codes("rm $var\n"), ["SC2086", "SC2154"]);
        assert!(codes("echo \"hi\"\n").is_empty());
    }

    /// The port's positions count a tab to the next stop of 8 and a character as 1, so the byte
    /// span must cover `$x` after a tab and `$y` after `ó` exactly.
    #[test]
    fn a_span_after_a_tab_or_a_two_byte_character_covers_the_variable() {
        let o = char::from_u32(0xF3).unwrap();
        let text = "#!/bin/bash\n\techo $x\n";
        assert_eq!(covered(text, "SC2154"), "$x");
        let second = format!("echo {o} $y\n");
        assert_eq!(covered(&second, "SC2154"), "$y");
        // Two tabs and a character between them: the second stop is column 17.
        let tabs = "\ta\techo $z\n";
        assert_eq!(covered(tabs, "SC2154"), "$z");
    }

    #[test]
    fn a_position_past_the_line_or_the_text_is_clamped() {
        let text = "ab\ncd";
        let pos = |line, column| Position {
            file: String::new(),
            line,
            column,
        };
        assert_eq!(byte_offset(text, &pos(1, 9)), 2);
        assert_eq!(byte_offset(text, &pos(2, 2)), 4);
        assert_eq!(byte_offset(text, &pos(9, 1)), 5);
    }

    #[test]
    fn sc2164_is_left_out() {
        let text = "cd /tmp\nls\n";
        assert!(!codes(text).contains(&"SC2164"), "{:?}", codes(text));
    }

    #[test]
    fn an_error_is_break_and_a_note_is_warn() {
        let found = run("if true; then\n");
        assert!(found.iter().any(|f| f.level == Level::Break), "{found:?}");
        let found = run("echo $1\n");
        assert!(found.iter().all(|f| f.level == Level::Warn), "{found:?}");
        assert!(!found.is_empty());
    }

    #[test]
    fn a_powershell_file_and_a_file_over_the_cap_get_nothing() {
        let deadline = Deadline::new(Instant::now(), 8000);
        assert!(findings("echo $x", Shell::Pwsh, &deadline).is_none());
        let big = format!("echo $x\n{}", "#".repeat(MAX_BYTES));
        let bash = Shell::Bash(shellwise::BashProfile::Posix);
        assert!(findings(&big, bash, &deadline).is_none());
        let at_cap = format!("echo $x\n{}", "#".repeat(MAX_BYTES - 8));
        assert!(findings(&at_cap, bash, &deadline).is_some());
    }

    #[test]
    fn a_spent_deadline_is_a_warn_not_a_clean_file() {
        let past = Deadline::new(Instant::now() - std::time::Duration::from_secs(1), 0);
        let bash = Shell::Bash(shellwise::BashProfile::Posix);
        let found = findings("rm $var\n", bash, &past).expect("ran");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule, ANALYSIS_INCOMPLETE);
        assert_eq!(found[0].level, Level::Warn);
    }
}
