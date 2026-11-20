//! The Claude Code PreToolUse adapter: the hook event on stdin in, the host's JSON reply out.
//!
//! The reply shapes are the ones `docs/spikes.md` "PreToolUse contract" proved. The adapter never
//! answers `allow`: that skips the host's permission system. `ok` is no output, `warn` is
//! `additionalContext` with no decision, and every deny-level verdict is `deny`, or `ask` when
//! every deny-level finding is a `danger` the config lists in `ask_instead_of_deny`.

use std::cell::RefCell;
use std::fmt;
use std::path::PathBuf;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;
use crate::fs::resolve::env_view;
use crate::ir::EnvView;
use crate::level::{Finding, Level, Verdict};
use crate::{BashProfile, Deadline, Os, Shell, malformed_within};

/// The host refuses or files away hook output past 10,000 characters (CR bytes included). The
/// reply stays below this many bytes, which is never fewer than its characters.
pub const OUTPUT_LIMIT: usize = 9000;

/// One finding's message line and its `Fix:` line are each cut to this many characters, so the
/// first finding always fits in `OUTPUT_LIMIT` whatever JSON escaping does to it.
const LINE_LIMIT: usize = 600;

const EVENT_NAME: &str = "PreToolUse";
const DENY: &str = "deny";
const ASK: &str = "ask";
const TOOL_NAME: &str = "tool_name";

/// What the event on stdin asks the adapter to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A command for one of the two shells, with the event's working directory.
    Command {
        shell: Shell,
        command: String,
        cwd: Option<PathBuf>,
    },
    /// Not a call to check: empty stdin, or a tool that is not a shell. No output.
    Ignored,
    /// Not a readable event. The raw text decides (`malformed`).
    Malformed(&'static str),
}

/// The shell that runs a tool's command: Git Bash for `Bash` on Windows, POSIX bash elsewhere,
/// pwsh for `PowerShell`. The Monitor tool arrives under the `Bash` name. Any other tool is not
/// checked.
pub fn shell_for(tool_name: &str, os: Os) -> Option<Shell> {
    match tool_name {
        "Bash" => Some(Shell::Bash(match os {
            Os::Windows => BashProfile::GitBash,
            Os::Posix => BashProfile::Posix,
        })),
        "PowerShell" => Some(Shell::Pwsh),
        _ => None,
    }
}

/// Read the event: `tool_name`, `tool_input.command` and `cwd`. A tool that is not a shell is
/// ignored before anything else is looked at, so its input never causes a deny.
pub fn parse_event(bytes: &[u8], os: Os) -> Event {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Event::Ignored;
    }
    let Ok(event) = serde_json::from_slice::<Value>(bytes) else {
        return Event::Malformed("the hook event is not valid JSON");
    };
    let Some(tool) = event.get(TOOL_NAME).and_then(Value::as_str) else {
        return Event::Malformed("the hook event names no tool");
    };
    let Some(shell) = shell_for(tool, os) else {
        return Event::Ignored;
    };
    let Some(ToolInput { command }) = event
        .get("tool_input")
        .and_then(|input| ToolInput::deserialize(input).ok())
    else {
        return Event::Malformed("the hook event holds no command");
    };
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

/// True when the start of an event that was not read whole names a tool that is not a shell, so
/// the unread input is none of ours (Ruling 91a). Only the keys before the tool name are read
/// (the host sends it before `tool_input`); bytes that show no tool name give `false`.
pub fn names_another_tool(prefix: &[u8], os: Os) -> bool {
    let found = RefCell::new(None);
    let mut de = serde_json::Deserializer::from_slice(prefix);
    // The rest of the prefix is cut short, so the parse ends in an error after the name is seen.
    let _ = serde::Deserializer::deserialize_map(&mut de, ToolNameSeeker(&found));
    found
        .into_inner()
        .is_some_and(|tool: String| shell_for(&tool, os).is_none())
}

/// Reads an event's keys up to the tool name and stores the name when it is a string.
struct ToolNameSeeker<'a>(&'a RefCell<Option<String>>);

impl<'de> Visitor<'de> for ToolNameSeeker<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a hook event object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == TOOL_NAME {
                if let Ok(name) = map.next_value::<String>() {
                    *self.0.borrow_mut() = Some(name);
                }
                return Ok(());
            }
            map.next_value::<IgnoredAny>()?;
        }
        Ok(())
    }
}

/// The part of a shell tool's input the check reads; other keys are ignored.
#[derive(Deserialize)]
struct ToolInput {
    command: String,
}

/// The reply to an event that could not be read: a deny when its raw text holds a destructive
/// command or the raw scan gives no answer (a timeout, a panic, a worker that did not start), at
/// `danger`; otherwise no output, because nothing shows a command would run. The raw text is read
/// through `scan_text` first, and scanned under `deadline` (`malformed_within`).
pub fn malformed(bytes: &[u8], reason: &str, deadline: &Deadline) -> Option<String> {
    let raw = scan_text(&String::from_utf8_lossy(bytes));
    let verdict = malformed_within(&raw, reason, deadline);
    if verdict.level >= Level::Danger {
        Some(render(Some(DENY), &verdict))
    } else {
        None
    }
}

/// The raw event as the scan should read it: each unescaped `"` becomes a line break, so a
/// command inside a JSON string (`"command":"rm -rf x"`) is a line of its own, not glued to the
/// key before it; the string escapes are decoded best-effort (`\n` and `\r` a line break, `\t` a
/// tab, `\uXXXX` its character, `\"` a quote), so a multi-line command keeps its lines.
fn scan_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => out.push('\n'),
            '\\' => match chars.next() {
                Some('n' | 'r') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b' | 'f') => out.push(' '),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let whole = hex.len() == 4 && hex.chars().all(|h| h.is_ascii_hexdigit());
                    let decoded = whole.then(|| u32::from_str_radix(&hex, 16).ok()).flatten();
                    match decoded.and_then(char::from_u32) {
                        Some(d) => out.push(d),
                        None => {
                            out.push_str("\\u");
                            out.push_str(&hex);
                        }
                    }
                }
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            _ => out.push(c),
        }
    }
    out
}

/// The variables a check may resolve, from the hook's own environment (`env_view`: on Windows
/// `~` comes from `USERPROFILE`). A name or value that is not Unicode is left out.
pub fn hook_env(shell: Shell, os: Os) -> EnvView {
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    env_view(shell, os, vars)
}

/// The host's JSON for a verdict, `None` for no output.
pub fn reply(verdict: &Verdict, cfg: &Config) -> Option<String> {
    match verdict.level {
        Level::Ok => None,
        Level::Warn => Some(render(None, verdict)),
        _ if asks(verdict, cfg) => Some(render(Some(ASK), verdict)),
        _ => Some(render(Some(DENY), verdict)),
    }
}

/// True when every finding at `break` or above is a `danger` whose rule the config turns into an
/// ask. A `break` (certain to fail) or a `critical` is always a deny.
fn asks(verdict: &Verdict, cfg: &Config) -> bool {
    let mut denying = verdict
        .findings
        .iter()
        .filter(|f| f.level >= Level::Break)
        .peekable();
    denying.peek().is_some()
        && denying.all(|f| {
            f.level == Level::Danger && cfg.ask_instead_of_deny.iter().any(|r| r == f.rule)
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Reply<'a> {
    hook_specific_output: Output<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_context: Option<&'a str>,
}

/// One JSON object: with a decision the text is its reason, without one it is the context.
fn reply_json(decision: Option<&'static str>, text: &str) -> String {
    let output = Output {
        hook_event_name: EVENT_NAME,
        permission_decision: decision,
        permission_decision_reason: decision.map(|_| text),
        additional_context: if decision.is_none() { Some(text) } else { None },
    };
    serde_json::to_string(&Reply {
        hook_specific_output: output,
    })
    .expect("a reply always serialises")
}

/// The reply holding as many findings as fit in `OUTPUT_LIMIT`, the highest level first, then a
/// line counting the ones left out.
fn render(decision: Option<&'static str>, verdict: &Verdict) -> String {
    let mut shown: Vec<&Finding> = verdict
        .findings
        .iter()
        .filter(|f| f.level > Level::Ok)
        .collect();
    shown.sort_by_key(|f| std::cmp::Reverse(f.level));
    let lines: Vec<String> = shown.iter().map(|f| finding_text(f)).collect();
    let mut best = reply_json(decision, &text(&lines, 1));
    for n in 2..=lines.len() {
        let next = reply_json(decision, &text(&lines, n));
        if next.len() > OUTPUT_LIMIT {
            break;
        }
        best = next;
    }
    best
}

/// The first `n` finding texts, and a count of the rest when some are left out.
fn text(lines: &[String], n: usize) -> String {
    let n = n.min(lines.len());
    let mut out = lines[..n].join("\n");
    let rest = lines.len() - n;
    if rest > 0 {
        out.push_str(&format!("\nshellwise: {rest} more findings not shown"));
    }
    out
}

/// `shellwise: <level> <rule>: <message>`, then the `Fix:` line when the finding has one.
fn finding_text(f: &Finding) -> String {
    let head = cut(&format!(
        "shellwise: {} {}: {}",
        f.level.as_str(),
        f.rule,
        f.message
    ));
    match f.fix_line() {
        Some(fix) => format!("{head}\n{}", cut(&fix)),
        None => head,
    }
}

/// At most `LINE_LIMIT` characters, ending in `…` when cut.
fn cut(line: &str) -> String {
    match line.char_indices().nth(LINE_LIMIT) {
        Some((at, _)) => format!("{}…", &line[..at]),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::Span;

    /// A deadline far enough off for any scan.
    fn later() -> Deadline {
        Deadline::new(std::time::Instant::now(), 8000)
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

    fn parsed(reply: &str) -> Value {
        serde_json::from_str(reply).unwrap()
    }

    fn decision(reply: &Option<String>) -> Option<String> {
        let v = parsed(reply.as_deref().expect("a reply"));
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .map(str::to_string)
    }

    fn asking(rules: &[&str]) -> Config {
        Config {
            ask_instead_of_deny: rules.iter().map(|r| r.to_string()).collect(),
            ..Config::default()
        }
    }

    #[test]
    fn shell_by_tool_name() {
        let table = [
            ("Bash", Os::Windows, Some(Shell::Bash(BashProfile::GitBash))),
            ("Bash", Os::Posix, Some(Shell::Bash(BashProfile::Posix))),
            ("PowerShell", Os::Windows, Some(Shell::Pwsh)),
            ("PowerShell", Os::Posix, Some(Shell::Pwsh)),
            ("Monitor", Os::Windows, None),
            ("Read", Os::Posix, None),
            ("bash", Os::Posix, None),
            ("", Os::Windows, None),
        ];
        for (tool, os, shell) in table {
            assert_eq!(shell_for(tool, os), shell, "{tool} {os:?}");
        }
    }

    #[test]
    fn event_fields() {
        let ev = br#"{"tool_name":"PowerShell","tool_input":{"command":"Get-Date","description":"d"},"cwd":"C:\\w"}"#;
        assert_eq!(
            parse_event(ev, Os::Windows),
            Event::Command {
                shell: Shell::Pwsh,
                command: "Get-Date".to_string(),
                cwd: Some(PathBuf::from(r"C:\w")),
            }
        );
        let no_cwd = br#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":""}"#;
        assert_eq!(
            parse_event(no_cwd, Os::Posix),
            Event::Command {
                shell: Shell::Bash(BashProfile::Posix),
                command: "ls".to_string(),
                cwd: None,
            }
        );
    }

    #[test]
    fn unreadable_events() {
        let rows: [(&[u8], Event); 9] = [
            (b"", Event::Ignored),
            (b" \r\n\t", Event::Ignored),
            (
                br#"{"tool_name":"Read","tool_input":{"command":"rm -rf x"}}"#,
                Event::Ignored,
            ),
            (
                b"{\"tool_name\":\"Bash\"",
                Event::Malformed("the hook event is not valid JSON"),
            ),
            (
                b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"\xff\"}}",
                Event::Malformed("the hook event is not valid JSON"),
            ),
            (
                br#"["Bash"]"#,
                Event::Malformed("the hook event names no tool"),
            ),
            (
                br#"{"tool_name":7,"tool_input":{"command":"ls"}}"#,
                Event::Malformed("the hook event names no tool"),
            ),
            (
                br#"{"tool_name":"Bash","tool_input":{"cmd":"ls"}}"#,
                Event::Malformed("the hook event holds no command"),
            ),
            (
                br#"{"tool_name":"PowerShell","tool_input":{"command":["ls"]}}"#,
                Event::Malformed("the hook event holds no command"),
            ),
        ];
        for (bytes, want) in rows {
            assert_eq!(
                parse_event(bytes, Os::Windows),
                want,
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn a_cut_prefix_names_another_tool_only_when_it_shows_one() {
        let rows: [(&[u8], bool); 9] = [
            (
                br#"{"cwd":"c","tool_name":"Write","tool_input":{"content":"aaa"#,
                true,
            ),
            (br#"{"tool_name":"Read""#, true),
            (
                br#"{"tool_name":"Bash","tool_input":{"command":"aaa"#,
                false,
            ),
            (br#"{"tool_name":"PowerShell","tool_input":{"#, false),
            // The name is not shown yet, or not as a string, or not at the top level.
            (br#"{"cwd":"c","tool_input":{"content":"aaa"#, false),
            (br#"{"tool_name":"Wri"#, false),
            (br#"{"tool_name":7,"x":"#, false),
            (br#"{"tool_input":{"tool_name":"Write"},"x":"#, false),
            (b"\xff\xfe garbage", false),
        ];
        for (bytes, want) in rows {
            assert_eq!(
                names_another_tool(bytes, Os::Windows),
                want,
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn reply_by_level() {
        let cfg = Config::default();
        assert_eq!(reply(&Verdict::new(vec![]), &cfg), None);
        assert_eq!(
            reply(&Verdict::new(vec![finding("r", Level::Ok)]), &cfg),
            None
        );
        let warn = reply(&Verdict::new(vec![finding("w", Level::Warn)]), &cfg).unwrap();
        assert_eq!(
            warn,
            concat!(
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","#,
                r#""additionalContext":"shellwise: warn w: w message\nFix: w fix"}}"#
            )
        );
        for level in [Level::Break, Level::Danger, Level::Critical] {
            let r = reply(&Verdict::new(vec![finding("d", level)]), &cfg).unwrap();
            let v = parsed(&r);
            let out = &v["hookSpecificOutput"];
            assert_eq!(out["permissionDecision"], "deny", "{level:?}");
            assert_eq!(
                out["permissionDecisionReason"],
                format!("shellwise: {} d: d message\nFix: d fix", level.as_str()),
                "{level:?}"
            );
            assert!(out.get("additionalContext").is_none(), "{r}");
        }
    }

    #[test]
    fn ask_only_when_every_denying_finding_is_a_listed_danger() {
        let cfg = asking(&["a", "b"]);
        let v = |fs: Vec<Finding>| reply(&Verdict::new(fs), &cfg);
        let ask = Some(ASK.to_string());
        let deny = Some(DENY.to_string());
        assert_eq!(decision(&v(vec![finding("a", Level::Danger)])), ask);
        assert_eq!(
            decision(&v(vec![
                finding("a", Level::Danger),
                finding("b", Level::Danger),
                finding("c", Level::Warn),
            ])),
            ask
        );
        assert_eq!(
            decision(&v(vec![
                finding("a", Level::Danger),
                finding("c", Level::Danger)
            ])),
            deny
        );
        assert_eq!(
            decision(&v(vec![
                finding("a", Level::Danger),
                finding("b", Level::Break)
            ])),
            deny
        );
        assert_eq!(decision(&v(vec![finding("a", Level::Break)])), deny);
        assert_eq!(decision(&v(vec![finding("a", Level::Critical)])), deny);
        let none = Config::default();
        assert_eq!(
            decision(&reply(
                &Verdict::new(vec![finding("a", Level::Danger)]),
                &none
            )),
            deny
        );
    }

    #[test]
    fn findings_highest_first_and_ok_left_out() {
        let r = reply(
            &Verdict::new(vec![
                finding("w", Level::Warn),
                finding("o", Level::Ok),
                finding("c", Level::Critical),
            ]),
            &Config::default(),
        )
        .unwrap();
        let reason = parsed(&r)["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            reason,
            "shellwise: critical c: c message\nFix: c fix\nshellwise: warn w: w message\nFix: w fix"
        );
    }

    #[test]
    fn a_long_reply_stays_under_the_host_cap() {
        let quote = char::from_u32(0x22).unwrap().to_string();
        let mut findings = vec![Finding {
            rule: "big",
            level: Level::Break,
            message: quote.repeat(5000),
            fix: Some(quote.repeat(5000)),
            span: Span::default(),
        }];
        findings.extend((0..500).map(|_| finding("w", Level::Warn)));
        let r = reply(&Verdict::new(findings), &Config::default()).unwrap();
        assert!(r.len() <= OUTPUT_LIMIT, "{}", r.len());
        let reason = parsed(&r)["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(reason.starts_with("shellwise: break big: "), "{reason}");
        assert!(reason.contains("\nFix: "), "{reason}");
        assert!(reason.ends_with(" more findings not shown"), "{reason}");
        // A control character is the widest JSON escape (`\u0001`, 6 bytes): the first finding
        // still fits whole, cut to `LINE_LIMIT` characters per line.
        let ctrl = char::from_u32(0x01).unwrap().to_string();
        let wide = Finding {
            rule: "wide",
            level: Level::Danger,
            message: ctrl.repeat(5000),
            fix: Some(ctrl.repeat(5000)),
            span: Span::default(),
        };
        let r = reply(&Verdict::new(vec![wide]), &Config::default()).unwrap();
        assert!(r.len() <= OUTPUT_LIMIT, "{}", r.len());
        let reason = parsed(&r)["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(reason.starts_with("shellwise: danger wide: "), "{reason}");
        assert!(reason.contains("\nFix: "), "{reason}");
        // Every finding that fits is kept.
        let few = (0..3).map(|_| finding("w", Level::Warn)).collect();
        let r = reply(&Verdict::new(few), &Config::default()).unwrap();
        assert!(!r.contains("not shown"), "{r}");
        assert_eq!(r.matches("shellwise: warn w").count(), 3, "{r}");
    }

    #[test]
    fn cut_keeps_whole_characters() {
        let long = "é".repeat(LINE_LIMIT + 5);
        let c = cut(&long);
        assert_eq!(c.chars().count(), LINE_LIMIT + 1);
        assert!(c.ends_with('…'));
        assert_eq!(cut("short"), "short");
    }

    #[test]
    fn a_malformed_event_denies_only_destructive_raw_text() {
        let r = malformed(
            b"{\"tool_input\":{\"command\":\"rm -rf x\"",
            "reason",
            &later(),
        )
        .unwrap();
        let v = parsed(&r);
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.starts_with("shellwise: danger analysis-incomplete: "),
            "{reason}"
        );
        assert_eq!(
            malformed(b"{\"tool_input\":{\"command\":\"ls\"", "r", &later()),
            None
        );
        // A destructive second line of a multi-line command, and an escaped letter.
        for raw in [
            r#"{"tool_input":{"command":"echo a\nrm -rf x"#,
            r#"{"tool_input":{"command":"echo a\r\nrm -rf x"#,
            r#"{"tool_input":{"command":"echo a; \u0072m -rf x"#,
        ] {
            assert!(malformed(raw.as_bytes(), "r", &later()).is_some(), "{raw}");
        }
    }

    #[test]
    fn scan_text_decodes_the_string_escapes() {
        let rows = [
            (r#"{"a":"b"}"#, "{\na\n:\nb\n}"),
            (r"x\ny\rz\tw", "x\ny\nz\tw"),
            (r#"say \"hi\""#, "say \"hi\""),
            (r"C:\\w\/v", r"C:\w/v"),
            (r"\u0072m \uZZZZ \u00", r"rm \uZZZZ \u00"),
            (r"\b\f", "  "),
            ("end\\", "end\\"),
        ];
        for (raw, want) in rows {
            assert_eq!(scan_text(raw), want, "{raw}");
        }
    }
}
