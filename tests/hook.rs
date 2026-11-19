//! `shellwise hook claude-code` through the spawned binary: one row per reply kind (deny with its
//! `Fix:` line, ask, context only, no output), the shell picked by tool name, unreadable events,
//! the config layers and the time a 200 KB command takes.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{Run, run};
use serde_json::{Value, json};

const HOOK: &[&str] = &["hook", "claude-code"];
const DESTRUCTIVE: &str = "rm -rf x";

fn ch(code: u32) -> char {
    char::from_u32(code).unwrap()
}

fn dq() -> char {
    ch(0x22)
}

fn sq() -> char {
    ch(0x27)
}

fn bt() -> char {
    ch(0x60)
}

/// A PreToolUse event as the host sends it (`docs/spikes.md` "Event on stdin").
fn event(tool: &str, command: &str, cwd: &str) -> Vec<u8> {
    json!({
        "session_id": "s",
        "transcript_path": "t",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command, "description": "d"},
        "tool_use_id": "u",
    })
    .to_string()
    .into_bytes()
}

/// A folder of its own under the temp dir, emptied first: the event's `cwd` and a test's config.
fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shellwise-hook-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the test folder");
    dir
}

fn cwd_of(dir: &std::path::Path) -> String {
    dir.to_str().unwrap().to_string()
}

fn hook(tool: &str, command: &str) -> Run {
    let dir = std::env::temp_dir().join("shellwise-tests-empty");
    std::fs::create_dir_all(&dir).unwrap();
    run(HOOK, Some(&event(tool, command, &cwd_of(&dir))), &[])
}

/// The integration config `text` in its own folder, passed as `--config`.
fn hook_with_config(name: &str, text: &str, tool: &str, command: &str) -> Run {
    let dir = folder(name);
    let file = dir.join("integration.toml");
    std::fs::write(&file, text).unwrap();
    let file = file.to_str().unwrap().to_string();
    let args = ["hook", "claude-code", "--config", file.as_str()];
    run(&args, Some(&event(tool, command, &cwd_of(&dir))), &[])
}

/// The one reply object: exit 0, one LF-terminated line, no CR, `hookEventName` set.
fn reply(r: &Run) -> Value {
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert!(!r.stdout.contains('\r'), "{:?}", r.stdout);
    assert!(r.stdout.ends_with('\n'), "{:?}", r.stdout);
    assert_eq!(r.stdout.matches('\n').count(), 1, "{:?}", r.stdout);
    let v = r.json();
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["hookSpecificOutput"], "{v}");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse", "{v}");
    v["hookSpecificOutput"].clone()
}

/// A `deny` or `ask` reply: its reason, with no context key.
fn decided(r: &Run, decision: &str) -> String {
    let out = reply(r);
    assert_eq!(out["permissionDecision"], decision, "{out}");
    assert!(out.get("additionalContext").is_none(), "{out}");
    out["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string()
}

fn denied(r: &Run) -> String {
    decided(r, "deny")
}

/// A context-only reply: no decision key at all, so the host's permission rules still decide.
fn context(r: &Run) -> String {
    let out = reply(r);
    assert!(out.get("permissionDecision").is_none(), "{out}");
    assert!(out.get("permissionDecisionReason").is_none(), "{out}");
    out["additionalContext"].as_str().unwrap().to_string()
}

fn silent(r: &Run) {
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "", "stderr {:?}", r.stderr);
}

#[test]
fn a_break_is_a_deny_with_its_fix_line() {
    let q = sq();
    let reason = denied(&hook("Bash", &format!("echo {q}abc")));
    assert!(
        reason.starts_with("shellwise: break parse-error: "),
        "{reason}"
    );
    assert!(
        reason.contains(&format!("\nFix: close the {q} opened at column 6")),
        "{reason}"
    );
    let d = dq();
    let reason = denied(&hook("PowerShell", &format!("Write-Output {d}abc")));
    assert!(
        reason.contains(&format!("\nFix: close the {d} opened at column 14")),
        "{reason}"
    );
}

#[test]
fn a_danger_is_a_deny_with_its_fix_line() {
    let reason = denied(&hook("PowerShell", &format!("Get-Date ( ; {DESTRUCTIVE}")));
    assert!(
        reason.starts_with("shellwise: danger parse-error: "),
        "{reason}"
    );
    assert!(
        reason.contains("\nFix: correct the syntax at column"),
        "{reason}"
    );
}

#[test]
fn a_warn_is_context_with_no_decision() {
    let text = context(&hook("PowerShell", "Get-Date ("));
    assert!(text.starts_with("shellwise: warn parse-error: "), "{text}");
    assert!(text.contains("\nFix: correct the syntax at column"), "{text}");
}

#[test]
fn ok_is_no_output() {
    for (tool, command) in [
        ("PowerShell", "Get-Date"),
        ("PowerShell", "newtool --any x"),
        ("PowerShell", "timeout 60 newtool -x"),
        ("Bash", "echo hi"),
        ("PowerShell", ""),
    ] {
        silent(&hook(tool, command));
    }
}

#[test]
fn the_tool_name_picks_the_shell() {
    // An unclosed backtick: bash refuses it; in PowerShell the backtick escapes the `d`.
    let b = bt();
    let backtick = format!("echo {b}date");
    let reason = denied(&hook("Bash", &backtick));
    assert!(
        reason.contains(&format!("\nFix: close the {b} opened at column 6")),
        "{reason}"
    );
    // Our pwsh parser is not proven to read this backtick as PowerShell does: assert only that
    // it does not deny, which is what tells the two shells apart here.
    let r = hook("PowerShell", &backtick);
    assert_eq!(r.code, 0, "stderr {:?}", r.stderr);
    assert!(!r.stdout.contains("permissionDecision"), "{:?}", r.stdout);
    // A bash `if`: PowerShell wants a `(` after `if`.
    let bash_if = "if [ -f x ]; then echo y; fi";
    silent(&hook("Bash", bash_if));
    let text = context(&hook("PowerShell", bash_if));
    assert!(text.starts_with("shellwise: warn parse-error: "), "{text}");
}

#[test]
fn a_monitor_event_is_checked_as_bash() {
    // The Monitor tool reaches a `Bash|PowerShell` hook as `tool_name: "Bash"` with only a
    // command and a description, and no `run_in_background`.
    let b = bt();
    let monitor = json!({
        "cwd": cwd_of(&folder("monitor")),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": format!("tail -f log {b}x"), "description": "watch"},
    })
    .to_string();
    let reason = denied(&run(HOOK, Some(monitor.as_bytes()), &[]));
    assert!(reason.contains(&format!("close the {b}")), "{reason}");
}

#[test]
fn an_unknown_tool_is_no_output_whatever_its_input() {
    for tool in ["Read", "Edit", "Write", "WebFetch", "Task"] {
        silent(&hook(tool, DESTRUCTIVE));
    }
    let other = json!({"tool_name": "Grep", "tool_input": {"pattern": DESTRUCTIVE}}).to_string();
    silent(&run(HOOK, Some(other.as_bytes()), &[]));
}

#[test]
fn empty_stdin_is_no_output() {
    silent(&run(HOOK, None, &[]));
    silent(&run(HOOK, Some(b""), &[]));
    silent(&run(HOOK, Some(b"  \n"), &[]));
}

#[test]
fn a_malformed_event_denies_only_destructive_raw_text() {
    let plain = r#"{"tool_name":"Bash","tool_input":{"command":"Get-Date"#;
    silent(&run(HOOK, Some(plain.as_bytes()), &[]));
    let rows = [
        // Cut short.
        format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"{DESTRUCTIVE}"#),
        // A shell tool with no string command.
        format!(r#"{{"tool_name":"Bash","tool_input":{{"cmd":"{DESTRUCTIVE}"}}}}"#),
        format!(r#"{{"tool_name":"PowerShell","tool_input":{{"command":["{DESTRUCTIVE}"]}}}}"#),
        // No tool name, and not an object.
        format!(r#"{{"tool_input":{{"command":"{DESTRUCTIVE}"}}}}"#),
        format!(r#""{DESTRUCTIVE}""#),
    ];
    for row in rows {
        let reason = denied(&run(HOOK, Some(row.as_bytes()), &[]));
        assert!(
            reason.starts_with("shellwise: danger analysis-incomplete: "),
            "{row}: {reason}"
        );
    }
    // Invalid UTF-8 is not a readable event either.
    let mut bytes = br#"{"tool_name":"Bash","tool_input":{"command":"echo "#.to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(format!(r#"; {DESTRUCTIVE}"}}}}"#).as_bytes());
    let reason = denied(&run(HOOK, Some(&bytes), &[]));
    assert!(reason.contains("analysis-incomplete"), "{reason}");
    let mut bytes = br#"{"tool_name":"Bash","tool_input":{"command":"echo "#.to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(br#""}}"#);
    silent(&run(HOOK, Some(&bytes), &[]));
}

#[test]
fn a_200_kb_command_finishes_well_inside_the_hook_timeout() {
    // `hook_timeout_ms` defaults to 10000; the reply must come before 10000 - 1000.
    let long = "Get-Date; ".repeat(20 * 1024);
    for tool in ["PowerShell", "Bash"] {
        let r = hook(tool, &long);
        assert!(r.elapsed < Duration::from_millis(9000), "{tool}: {:?}", r.elapsed);
        let out = reply(&r);
        let text = out["permissionDecisionReason"]
            .as_str()
            .or(out["additionalContext"].as_str())
            .unwrap();
        assert!(text.contains("analysis-incomplete"), "{tool}: {text}");
        assert!(r.stdout.len() <= 9000, "{tool}: {}", r.stdout.len());
    }
}

#[test]
fn an_event_over_the_read_cap_is_a_deny_unread() {
    // Over MAX_READ_BYTES (1 MiB) the event is not read whole, so nothing shows it is harmless.
    let huge = "Get-Date; ".repeat(110 * 1024);
    let reason = denied(&hook("PowerShell", &huge));
    assert!(
        reason.starts_with("shellwise: danger analysis-incomplete: "),
        "{reason}"
    );
    assert!(reason.contains("could not be read"), "{reason}");
}

#[test]
fn a_listed_danger_is_an_ask() {
    let cfg = "ask_instead_of_deny = [\"parse-error\"]\n";
    let danger = format!("Get-Date ( ; {DESTRUCTIVE}");
    let reason = decided(&hook_with_config("ask", cfg, "PowerShell", &danger), "ask");
    assert!(
        reason.starts_with("shellwise: danger parse-error: "),
        "{reason}"
    );
    assert!(reason.contains("\nFix: "), "{reason}");
    // A break stays a deny: the command fails as written whoever approves it.
    let d = dq();
    let r = hook_with_config("ask-break", cfg, "PowerShell", &format!("Write-Output {d}abc"));
    denied(&r);
    // A rule not in the list stays a deny.
    let other = "ask_instead_of_deny = [\"analysis-incomplete\"]\n";
    denied(&hook_with_config("ask-other", other, "PowerShell", &danger));
}

#[test]
fn a_critical_is_a_deny_even_when_its_rule_is_listed() {
    let cfg = "ask_instead_of_deny = [\"parse-error\"]\n[levels]\nparse-error = \"critical\"\n";
    let reason = denied(&hook_with_config("critical", cfg, "PowerShell", "Get-Date ("));
    assert!(
        reason.starts_with("shellwise: critical parse-error: "),
        "{reason}"
    );
}

#[test]
fn a_config_finding_reaches_the_reply() {
    let r = hook_with_config("bad-key", "no_such_key = 1\n", "PowerShell", "Get-Date");
    let text = context(&r);
    assert!(text.contains("config-invalid"), "{text}");
}

#[test]
fn the_repo_file_is_found_from_the_event_cwd() {
    // The repo file raises parse-error to danger, so a warn becomes a deny; it is read only when
    // the event's `cwd` reaches the config discovery.
    let repo = folder("repo-raise");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join(".shellwise.toml"),
        "[levels]\nparse-error = \"danger\"\n",
    )
    .unwrap();
    let inner = repo.join("sub");
    std::fs::create_dir_all(&inner).unwrap();
    let r = run(HOOK, Some(&event("PowerShell", "Get-Date (", &cwd_of(&inner))), &[]);
    let reason = denied(&r);
    assert!(
        reason.starts_with("shellwise: danger parse-error: "),
        "{reason}"
    );
    // The same event outside the repo stays a warn.
    let outside = folder("repo-outside");
    let r = run(HOOK, Some(&event("PowerShell", "Get-Date (", &cwd_of(&outside))), &[]);
    context(&r);
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;

    /// `name` keeps each test's folder its own when tests run in parallel.
    fn with_hook(name: &str, mode: &str, tool: &str, command: &str) -> Run {
        let dir = folder(&format!("testhook-{name}-{mode}-{tool}"));
        run(
            HOOK,
            Some(&event(tool, command, &cwd_of(&dir))),
            &[
                ("SHELLWISE_TESTHOOK", mode),
                ("SHELLWISE_TESTHOOK_DEADLINE_MS", "500"),
            ],
        )
    }

    #[test]
    fn an_incomplete_analysis_is_a_deny_only_with_destructive_text() {
        for mode in ["panic", "sleep", "config-panic", "config-sleep"] {
            let reason = denied(&with_hook("levels", mode, "Bash", DESTRUCTIVE));
            assert!(
                reason.starts_with("shellwise: danger analysis-incomplete: "),
                "{mode}: {reason}"
            );
            let text = context(&with_hook("levels", mode, "PowerShell", "Get-Date"));
            assert!(
                text.starts_with("shellwise: warn analysis-incomplete: "),
                "{mode}: {text}"
            );
        }
    }

    #[test]
    fn a_stuck_analysis_still_replies_before_the_hook_timeout() {
        let r = with_hook("stuck", "sleep", "Bash", DESTRUCTIVE);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
        denied(&r);
    }
}
