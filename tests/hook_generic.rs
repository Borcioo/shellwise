//! `shellwise hook generic` through the spawned binary: exit 0 for `ok` and `warn`, exit 2 with
//! the findings on stderr for `break` and above, the fail-open rows (usage error, `SHELLWISE=off`,
//! a harmless event not read whole) and the fail-closed rows (a destructive command in bytes not
//! read whole, a scan with no answer, an analysis that panics). Commands go on stdin only.

mod common;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::Run;
use serde_json::json;

const DESTRUCTIVE: &str = "rm -rf x";
/// The wall time a test allows a hook whose stdin stays open, process start included.
const HELD_OPEN_LIMIT: Duration = Duration::from_secs(5);

/// An empty folder outside any repo: the working directory and config home of every run.
fn isolated_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("shellwise-tests-empty");
    std::fs::create_dir_all(&dir).expect("create the isolated folder");
    dir
}

/// `shellwise <args>` with the config homes isolated, `DIR`, `SHELLWISE` and the test hooks
/// removed, then `env` set.
fn spawn(args: &[&str], env: &[(&str, &str)]) -> Child {
    let empty = isolated_dir();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellwise"));
    cmd.args(args)
        .current_dir(&empty)
        .env("APPDATA", &empty)
        .env("XDG_CONFIG_HOME", &empty)
        .env("HOME", &empty)
        .env_remove("DIR")
        .env_remove("SHELLWISE")
        .env_remove("SHELLWISE_TESTHOOK")
        .env_remove("SHELLWISE_TESTHOOK_DEADLINE_MS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn shellwise")
}

fn finish(child: Child, start: Instant) -> Run {
    let out = child.wait_with_output().expect("wait for shellwise");
    Run {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
        stderr: String::from_utf8_lossy(&out.stderr).replace("\r\n", "\n"),
        elapsed: start.elapsed(),
    }
}

/// Run with `stdin` written and closed.
fn run_with(args: &[&str], stdin: &[u8], env: &[(&str, &str)]) -> Run {
    let start = Instant::now();
    let mut child = spawn(args, env);
    {
        let mut pipe = child.stdin.take().unwrap();
        // The binary may exit before reading everything; a broken pipe is not a test failure.
        let _ = pipe.write_all(stdin);
    }
    finish(child, start)
}

fn generic(shell: &str, stdin: &[u8], env: &[(&str, &str)]) -> Run {
    run_with(&["hook", "generic", "--shell", shell], stdin, env)
}

/// Run with `stdin` written to a pipe that stays open until the hook exits or `HELD_OPEN_LIMIT`
/// passes twice over (then the hook is killed and the elapsed check fails).
fn held_open(shell: &str, stdin: &[u8]) -> Run {
    let start = Instant::now();
    let mut child = spawn(&["hook", "generic", "--shell", shell], &[]);
    let mut pipe = child.stdin.take().unwrap();
    pipe.write_all(stdin).unwrap();
    pipe.flush().unwrap();
    while child.try_wait().unwrap().is_none() && start.elapsed() < HELD_OPEN_LIMIT * 2 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let r = finish(child, start);
    drop(pipe);
    r
}

/// A shell tool's event in the Claude Code / Gemini shape.
fn event(command: &str) -> Vec<u8> {
    json!({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": isolated_dir()})
        .to_string()
        .into_bytes()
}

fn ch(code: u32) -> String {
    char::from_u32(code).unwrap().to_string()
}

fn blocked(r: &Run) -> &str {
    assert_eq!(r.code, 2, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "", "stderr {:?}", r.stderr);
    &r.stderr
}

fn silent(r: &Run) {
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "", "stderr {:?}", r.stderr);
    assert_eq!(r.stderr, "", "stdout {:?}", r.stdout);
}

/// Exit 0 with one stderr line saying the event was not read.
fn passed_unread(r: &Run) {
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "", "stderr {:?}", r.stderr);
    let lines: Vec<&str> = r.stderr.lines().collect();
    assert_eq!(lines.len(), 1, "{:?}", r.stderr);
    assert!(
        lines[0].starts_with("shellwise: event not read (")
            && lines[0].ends_with("); the command was not checked"),
        "{:?}",
        r.stderr
    );
}

#[test]
fn ok_is_silent() {
    silent(&generic("bash", br#"{"command":"ls"}"#, &[]));
    silent(&generic("pwsh", &event("Get-Date"), &[]));
}

/// A delete of `/` when `DIR` is empty: refused from any working directory.
fn empty_expansion_delete() -> String {
    let d = ch(0x22);
    format!("rm -rf {d}$DIR/{d}")
}

#[test]
fn a_refused_command_exits_2_with_the_fix_on_stderr() {
    let r = generic("bash", &event(&empty_expansion_delete()), &[]);
    let err = blocked(&r);
    assert!(
        err.starts_with("shellwise: danger delete-empty-expansion: "),
        "{err}"
    );
    assert!(err.lines().any(|l| l.starts_with("Fix: ")), "{err}");
}

#[test]
fn a_break_exits_2() {
    let q = ch(0x27);
    let r = generic("bash", &event(&format!("echo {q}abc")), &[]);
    let err = blocked(&r);
    assert!(err.starts_with("shellwise: break parse-error: "), "{err}");
}

#[test]
fn a_warn_exits_0_with_the_note_on_stderr() {
    let r = generic("bash", &event("tail -f app.log"), &[]);
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.starts_with("shellwise: warn follow-unbounded: "),
        "{}",
        r.stderr
    );
}

#[test]
fn switched_off_exits_0_unread() {
    let cut = format!(r#"{{"command":"{DESTRUCTIVE}"#);
    silent(&generic("bash", cut.as_bytes(), &[("SHELLWISE", "off")]));
    // Control: the same bytes block when the switch is not set.
    blocked(&generic("bash", cut.as_bytes(), &[]));
}

#[test]
fn a_usage_error_exits_0() {
    let r = run_with(&["hook", "generic", "--shell", "fish"], b"", &[]);
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert!(r.stderr.contains("fish"), "{}", r.stderr);
}

#[test]
fn stdin_left_open_does_not_block() {
    let r = held_open("bash", br#"{"command":"ls"#);
    assert!(r.elapsed < HELD_OPEN_LIMIT, "{:?}", r.elapsed);
    passed_unread(&r);
    assert!(
        r.stderr.contains("stdin still open at the deadline"),
        "{}",
        r.stderr
    );
}

#[test]
fn stdin_left_open_with_a_destructive_prefix_blocks() {
    let r = held_open("bash", format!(r#"{{"command":"{DESTRUCTIVE}"#).as_bytes());
    assert!(r.elapsed < HELD_OPEN_LIMIT, "{:?}", r.elapsed);
    let err = blocked(&r);
    assert!(
        err.starts_with("shellwise: danger analysis-incomplete: "),
        "{err}"
    );
}

#[test]
fn malformed_json_with_a_destructive_command_blocks() {
    let r = generic(
        "bash",
        format!(r#"{{"command":"{DESTRUCTIVE}""#).as_bytes(),
        &[],
    );
    let err = blocked(&r);
    assert!(
        err.starts_with("shellwise: danger analysis-incomplete: "),
        "{err}"
    );
}

#[test]
fn malformed_json_without_one_passes() {
    passed_unread(&generic("bash", br#"{"command":"ls""#, &[]));
}

#[test]
fn an_event_that_is_not_ours_is_silent() {
    let other = json!({"tool_name": "Write", "tool_input": {"content": DESTRUCTIVE}}).to_string();
    for stdin in [b"".as_slice(), b" \n", other.as_bytes()] {
        silent(&generic("bash", stdin, &[]));
    }
}

#[test]
fn an_event_over_the_size_cap_is_scanned_unread() {
    let padding = " ".repeat(1024 * 1024);
    let big = format!(r#"{{"command":"{DESTRUCTIVE}; {padding}"}}"#);
    let err = blocked(&generic("bash", big.as_bytes(), &[])).to_string();
    assert!(err.contains("over the hard size cap"), "{err}");
}

#[test]
fn claude_code_still_exits_0_on_a_deny() {
    let r = run_with(
        &["hook", "claude-code"],
        &event(&empty_expansion_delete()),
        &[],
    );
    assert_eq!(r.code, 0, "stderr {:?}", r.stderr);
    let v: serde_json::Value = serde_json::from_str(r.stdout.trim_end()).expect(&r.stdout);
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny", "{v}");
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;

    #[test]
    fn an_analysis_panic_blocks() {
        let env = [
            ("SHELLWISE_TESTHOOK", "panic"),
            ("SHELLWISE_TESTHOOK_DEADLINE_MS", "500"),
        ];
        let r = generic("bash", &event(DESTRUCTIVE), &env);
        let err = blocked(&r);
        assert!(
            err.starts_with("shellwise: danger analysis-incomplete: "),
            "{err}"
        );
    }

    #[test]
    fn a_scan_with_no_answer_blocks() {
        let r = generic(
            "bash",
            br#"{"command":"ls""#,
            &[("SHELLWISE_TESTHOOK", "panic-scan-sleep")],
        );
        let err = blocked(&r);
        assert!(err.contains("the raw scan did not finish"), "{err}");
        assert!(r.elapsed < HELD_OPEN_LIMIT, "{:?}", r.elapsed);
    }

    #[test]
    fn a_panic_outside_the_analysis_exits_0_with_one_line() {
        let r = generic(
            "bash",
            &event(&empty_expansion_delete()),
            &[("SHELLWISE_TESTHOOK", "generic-panic")],
        );
        assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
        assert_eq!(r.stdout, "");
        assert_eq!(
            r.stderr,
            "shellwise: internal error; the command was not checked\n"
        );
    }
}
