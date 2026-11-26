//! The generic hook adapter: a JSON event on stdin in, exit code 2 with the findings on stderr for
//! a refused command. It serves hosts whose hook treats exit code 2 as a block and shows stderr to
//! the model; `ask_instead_of_deny` has no effect, since the convention has no "ask".

use std::path::PathBuf;

use serde_json::Value;

use crate::adapter::claude_code::{finding_text, scan_text};
use crate::level::{Finding, Level, Verdict};
use crate::{BashProfile, Deadline, Os, Shell, malformed_within};

/// The exit code that tells the host to block the command.
pub const EXIT_BLOCK: i32 = 2;

/// What the event on stdin asks the adapter to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A command to check, with the shell that runs it and the event's working directory.
    Command {
        shell: Shell,
        command: String,
        cwd: Option<PathBuf>,
    },
    /// No command in any known place: empty stdin, another tool, another shape. No output.
    NotOurs,
    /// Not valid JSON. The raw text decides (`unread_verdict`).
    Malformed(&'static str),
}

/// Read the event: the command is the first string at `tool_input.command`, `command`,
/// `tool_info.command_line`, or `command` inside `toolArgs` when that is a JSON string. The shell
/// is `shell` when given, else `pwsh` for a tool named `powershell` (any case, from `tool_name` or
/// `toolName`), else `pwsh` on Windows and POSIX bash elsewhere.
pub fn parse_event(bytes: &[u8], shell: Option<Shell>, os: Os) -> Event {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Event::NotOurs;
    }
    let Ok(event) = serde_json::from_slice::<Value>(bytes) else {
        return Event::Malformed("the hook event is not valid JSON");
    };
    let Some(command) = find_command(&event) else {
        return Event::NotOurs;
    };
    let shell = shell.unwrap_or_else(|| shell_from(&event, os));
    let cwd = event
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
        .map(PathBuf::from);
    Event::Command {
        shell,
        command,
        cwd,
    }
}

fn find_command(event: &Value) -> Option<String> {
    let string = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    string(event.pointer("/tool_input/command"))
        .or_else(|| string(event.get("command")))
        .or_else(|| string(event.pointer("/tool_info/command_line")))
        .or_else(|| {
            let args = event.get("toolArgs")?.as_str()?;
            let args = serde_json::from_str::<Value>(args).ok()?;
            string(args.get("command"))
        })
}

fn shell_from(event: &Value, os: Os) -> Shell {
    let tool = event
        .get("tool_name")
        .or_else(|| event.get("toolName"))
        .and_then(Value::as_str);
    if tool.is_some_and(|t| t.eq_ignore_ascii_case("powershell")) {
        return Shell::Pwsh;
    }
    match os {
        Os::Windows => Shell::Pwsh,
        Os::Posix => Shell::Bash(BashProfile::Posix),
    }
}

/// The stderr text for a verdict: each finding above `ok` as `hook claude-code` writes it in its
/// reason, the highest level first; `None` for `ok`.
pub fn render(verdict: &Verdict) -> Option<String> {
    if verdict.level == Level::Ok {
        return None;
    }
    let mut shown: Vec<&Finding> = verdict
        .findings
        .iter()
        .filter(|f| f.level > Level::Ok)
        .collect();
    shown.sort_by_key(|f| std::cmp::Reverse(f.level));
    let lines: Vec<String> = shown.iter().map(|f| finding_text(f)).collect();
    Some(lines.join("\n"))
}

/// The stderr text for an event that could not be read (stdin still open, over the size cap, not
/// JSON): the rendered verdict when the raw scan of the bytes read gives `danger` or above (a
/// destructive command, or a scan with no answer), as `claude_code::malformed` decides it; `None`
/// when nothing in them shows a destructive command.
pub fn unread_verdict(bytes: &[u8], reason: &str, deadline: &Deadline) -> Option<String> {
    let raw = scan_text(&String::from_utf8_lossy(bytes));
    let verdict = malformed_within(&raw, reason, deadline);
    if verdict.level >= Level::Danger {
        render(&verdict)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::Span;

    #[test]
    fn the_command_is_found_in_each_host_shape() {
        let rows: [(&str, &str); 5] = [
            (
                r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/w"}"#,
                "ls -la",
            ),
            (r#"{"command":"ls -la","cwd":"/w"}"#, "ls -la"),
            (r#"{"tool_info":{"command_line":"ls -la"}}"#, "ls -la"),
            (
                r#"{"toolName":"bash","toolArgs":"{\"command\":\"ls -la\"}"}"#,
                "ls -la",
            ),
            (
                r#"{"tool_name":"run_shell_command","tool_input":{"command":"ls -la","dir_path":"x"}}"#,
                "ls -la",
            ),
        ];
        for (raw, want) in rows {
            match parse_event(raw.as_bytes(), None, Os::Posix) {
                Event::Command { command, .. } => assert_eq!(command, want, "{raw}"),
                other => panic!("{raw}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_first_string_wins_and_cwd_is_kept_only_when_non_empty() {
        // A key that holds no string does not hide a later place that does.
        let raw = r#"{"tool_input":{"command":7},"command":"pwd","cwd":"/w"}"#;
        assert_eq!(
            parse_event(raw.as_bytes(), None, Os::Posix),
            Event::Command {
                shell: Shell::Bash(BashProfile::Posix),
                command: "pwd".to_string(),
                cwd: Some(PathBuf::from("/w")),
            }
        );
        let raw = r#"{"tool_input":{"command":"ls"},"command":"pwd","cwd":""}"#;
        assert_eq!(
            parse_event(raw.as_bytes(), None, Os::Posix),
            Event::Command {
                shell: Shell::Bash(BashProfile::Posix),
                command: "ls".to_string(),
                cwd: None,
            }
        );
    }

    #[test]
    fn the_shell_comes_from_the_flag_then_the_tool_name_then_the_os() {
        let ps = r#"{"toolName":"PowerShell","toolArgs":"{\"command\":\"Get-Date\"}"}"#;
        let snake = r#"{"tool_name":"powershell","tool_input":{"command":"Get-Date"}}"#;
        let plain = r#"{"command":"ls"}"#;
        let shell = |raw: &str, flag, os| match parse_event(raw.as_bytes(), flag, os) {
            Event::Command { shell, .. } => shell,
            other => panic!("{other:?}"),
        };
        assert_eq!(shell(ps, None, Os::Posix), Shell::Pwsh);
        assert_eq!(shell(snake, None, Os::Posix), Shell::Pwsh);
        assert_eq!(
            shell(ps, Some(Shell::Bash(BashProfile::Posix)), Os::Posix),
            Shell::Bash(BashProfile::Posix)
        );
        assert_eq!(shell(plain, None, Os::Windows), Shell::Pwsh);
        assert_eq!(
            shell(plain, None, Os::Posix),
            Shell::Bash(BashProfile::Posix)
        );
    }

    #[test]
    fn an_event_without_a_command_is_not_ours() {
        for raw in [
            "",
            " \n",
            r#"{"tool_name":"Read","tool_input":{"file_path":"x"}}"#,
            r#"{"command":7}"#,
            r#"{"toolArgs":{"command":"ls"}}"#,
            r#"{"toolArgs":"not json"}"#,
            "[]",
        ] {
            assert_eq!(
                parse_event(raw.as_bytes(), None, Os::Posix),
                Event::NotOurs,
                "{raw}"
            );
        }
        assert!(matches!(
            parse_event(b"{\"command\":\"rm", None, Os::Posix),
            Event::Malformed(_)
        ));
    }

    fn finding(rule: &'static str, level: Level) -> Finding {
        Finding {
            rule,
            level,
            message: format!("{rule} message"),
            fix: Some(format!("{rule} fix")),
            span: Span::default(),
        }
    }

    #[test]
    fn render_lists_the_findings_highest_first_and_nothing_for_ok() {
        assert_eq!(render(&Verdict::new(vec![])), None);
        assert_eq!(render(&Verdict::new(vec![finding("o", Level::Ok)])), None);
        let text = render(&Verdict::new(vec![
            finding("w", Level::Warn),
            finding("o", Level::Ok),
            finding("c", Level::Critical),
        ]));
        assert_eq!(
            text.as_deref(),
            Some(
                "shellwise: critical c: c message\nFix: c fix\nshellwise: warn w: w message\nFix: w fix"
            )
        );
    }

    /// A deadline far enough off for any scan.
    fn later() -> Deadline {
        Deadline::new(std::time::Instant::now(), 8000)
    }

    #[test]
    fn unread_bytes_block_only_when_the_raw_scan_finds_a_destructive_command() {
        let text = unread_verdict(br#"{"command":"rm -rf x"#, "r", &later()).expect("a block");
        assert!(
            text.starts_with("shellwise: danger analysis-incomplete: "),
            "{text}"
        );
        assert_eq!(unread_verdict(br#"{"command":"ls"#, "r", &later()), None);
    }
}
