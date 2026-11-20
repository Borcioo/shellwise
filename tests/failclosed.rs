//! Every path that cannot finish the analysis: `analysis-incomplete`, `danger` when the raw scan
//! finds a command of the destructive table (named in the span), `warn` otherwise, also when the
//! scan does not finish. Input it cannot read at all is `danger`.

mod common;

use common::{assert_failclosed_danger, assert_incomplete_warn, assert_ok, run};

const CHECK: &[&str] = &["check", "--shell", "pwsh", "--json"];

/// Assert `danger` from `analysis-incomplete`, wherever the span is.
fn assert_failed(r: &common::Run) {
    assert_eq!(r.code, 2, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    let findings = r.json()["findings"].clone();
    let incomplete = findings
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "analysis-incomplete");
    assert_eq!(incomplete.unwrap()["level"], "danger", "{findings}");
}

/// A command this long is also `inline-script-too-long` (break, run before the size cap): assert
/// that finding first and `analysis-incomplete` at `level` after it, and the exit code of the two.
/// With `needle`, the incomplete finding's span covers it in `command`.
fn assert_inline_then_incomplete(r: &common::Run, level: &str, hit: Option<(&str, &str)>) {
    let code = if level == "danger" { 2 } else { 1 };
    assert_eq!(r.code, code, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    let v = r.json();
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{v}");
    assert_eq!(findings[0]["rule"], "inline-script-too-long", "{v}");
    assert_eq!(findings[1]["rule"], "analysis-incomplete", "{v}");
    assert_eq!(findings[1]["level"], level, "{v}");
    if let Some((command, needle)) = hit {
        let start = findings[1]["span"]["start"].as_u64().unwrap() as usize;
        let end = findings[1]["span"]["end"].as_u64().unwrap() as usize;
        assert!(
            command.get(start..end).is_some_and(|s| s.contains(needle)),
            "span {start}..{end} misses {needle:?}"
        );
    }
}

#[test]
fn input_over_the_size_cap_fails_closed() {
    let mut cmd = "(".repeat(200 * 1024);
    cmd.push_str("rm -rf x");
    let r = run(CHECK, Some(cmd.as_bytes()), &[]);
    assert_inline_then_incomplete(&r, "danger", Some((&cmd, "rm -rf x")));

    // Nothing destructive in the raw text.
    let mut nested = "(".repeat(200 * 1024);
    nested.push_str("Get-Date");
    assert_inline_then_incomplete(&run(CHECK, Some(nested.as_bytes()), &[]), "warn", None);

    let mut plain = " ".repeat(200 * 1024);
    plain.push_str("echo hi");
    assert_inline_then_incomplete(&run(CHECK, Some(plain.as_bytes()), &[]), "warn", None);

    // Padding past the cap with an allow marker must not clear a delete of `/`.
    let mut marked = " ".repeat(64 * 1024 + 1);
    marked.push_str("rm -rf / # shellwise: allow");
    assert_failed(&run(CHECK, Some(marked.as_bytes()), &[]));
}

#[test]
fn size_cap_is_64_kib() {
    // A command at the cap is analysed: only the inline length rule speaks. One byte more fails
    // closed. The tail is a delete no other rule flags in pwsh or bash, which the raw scan still names.
    let tail = "; Remove-Item -Recurse -Force x";
    let at_cap = format!("{}{tail}", " ".repeat(64 * 1024 - tail.len()));
    assert_eq!(at_cap.len(), 64 * 1024);
    let r = run(CHECK, Some(at_cap.as_bytes()), &[]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let rules: Vec<String> = r.json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(rules, ["inline-script-too-long"], "{}", r.stdout);
    let over = format!(" {at_cap}");
    let r = run(CHECK, Some(over.as_bytes()), &[]);
    assert_inline_then_incomplete(&r, "danger", Some((&over, "Remove-Item -Recurse -Force x")));
}

#[test]
fn input_over_the_hard_cap_is_danger_without_scanning() {
    // 16 MB of harmless text: too big to scan inside the deadline, so it is danger unread.
    let big = vec![b'a'; 16 * 1024 * 1024];
    let r = run(CHECK, Some(&big), &[]);
    assert_eq!(r.code, 2, "{:?}", r.stderr);
    assert_eq!(r.json()["findings"][0]["rule"], "analysis-incomplete");
    let message = r.json()["findings"][0]["message"].to_string();
    assert!(message.contains("could not be read"), "{message}");
    assert!(
        r.elapsed < std::time::Duration::from_secs(9),
        "{:?}",
        r.elapsed
    );
}

#[test]
fn chained_env_split_strings_get_a_verdict() {
    // Each `env -S` link nests one more command. The invalid byte forces the fail path, where the
    // raw scan must still finish in time; past its depth limit the scan cannot read the tail, so
    // only the tail that names a command of the destructive table is danger, printed as JSON.
    // At 63,000 characters the command is also `inline-script-too-long` (break, first).
    for (tail, level) in [("rm -rf x", "danger"), ("echo hi", "warn")] {
        let mut cmd = "env -S ".repeat(9000).into_bytes();
        cmd.extend_from_slice(tail.as_bytes());
        cmd.extend_from_slice(b" #\xff");
        let r = run(&["check", "--shell", "bash", "--json"], Some(&cmd), &[]);
        assert_inline_then_incomplete(&r, level, None);
        // The default deadline is 8 s; one more second covers the process start.
        assert!(
            r.elapsed < std::time::Duration::from_secs(9),
            "{:?}",
            r.elapsed
        );
    }
}

#[cfg(windows)]
#[test]
fn argv_that_is_not_unicode_fails_closed() {
    use std::os::windows::ffi::OsStringExt;
    use std::process::Command;
    // A lone surrogate cannot become UTF-8.
    let mut wide: Vec<u16> = "echo ".encode_utf16().collect();
    wide.push(0xD800);
    wide.extend("; rm -rf x".encode_utf16());
    let out = Command::new(env!("CARGO_BIN_EXE_shellwise"))
        .args(CHECK)
        .arg("--")
        .arg(std::ffi::OsString::from_wide(&wide))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{:?}", out);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["findings"][0]["rule"], "analysis-incomplete");
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;
    use std::time::Duration;

    const DESTRUCTIVE: &str = "Get-Date; rm -rf x";
    const PLAIN: &str = "Get-Date";
    /// A read-only command the removed harmless grammar used to clear.
    const READ_ONLY: &str = "git status";

    fn hook(mode: &str, command: &str) -> common::Run {
        let mut args = CHECK.to_vec();
        args.extend(["--", command]);
        run(
            &args,
            None,
            &[
                ("SHELLWISE_TESTHOOK", mode),
                ("SHELLWISE_TESTHOOK_DEADLINE_MS", "500"),
            ],
        )
    }

    #[test]
    fn worker_that_ends_without_a_result_fails_closed() {
        assert_failclosed_danger(&hook("dead-worker", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_incomplete_warn(&hook("dead-worker", PLAIN));
        assert_incomplete_warn(&hook("dead-worker", READ_ONLY));
    }

    #[test]
    fn worker_that_cannot_start_fails_closed() {
        assert_failclosed_danger(&hook("spawn-fail", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_incomplete_warn(&hook("spawn-fail", PLAIN));
        assert_incomplete_warn(&hook("spawn-fail", READ_ONLY));
    }

    #[test]
    fn scan_that_misses_the_deadline_is_warn() {
        // The rule panics and the raw-text scan is too slow: an internal failure with no
        // destructive match is warn, and the reason says the scan did not finish.
        for cmd in [PLAIN, READ_ONLY, DESTRUCTIVE] {
            let r = hook("panic-scan-sleep", cmd);
            assert_incomplete_warn(&r);
            let message = r.json()["findings"][0]["message"].to_string();
            assert!(message.contains("the raw scan did not finish"), "{message}");
            assert!(r.elapsed < Duration::from_secs(5), "{cmd}: {:?}", r.elapsed);
        }
    }

    #[test]
    fn an_analysis_that_finishes_runs_no_raw_scan() {
        // `scan-abort` ends the process with exit code 99 as soon as the raw scan starts.
        assert_ok(&hook("scan-abort", PLAIN));
        // On the failure path the scan runs.
        let r = hook("scan-abort,panic", PLAIN);
        assert_eq!(r.code, 99, "{}", r.stdout);
    }

    #[test]
    fn allow_marker_has_no_effect_on_a_failed_analysis() {
        let cmd = "Get-Date; rm -rf x # shellwise: allow";
        assert_failclosed_danger(&hook("panic", cmd), cmd, "rm -rf x");
    }

    #[test]
    fn stdin_held_open_ends_at_the_deadline() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::Instant;
        let mut child = Command::new(env!("CARGO_BIN_EXE_shellwise"))
            .args(CHECK)
            .env("SHELLWISE_TESTHOOK_DEADLINE_MS", "500")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"Get-Date; rm -rf x").unwrap();
        stdin.flush().unwrap();
        // stdin stays open while we wait; a hang is killed after 10 s and fails below.
        while child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let elapsed = start.elapsed();
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        drop(stdin);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["findings"][0]["rule"], "analysis-incomplete");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn default_deadline_leaves_time_for_a_slow_rule() {
        // No deadline override: a rule that takes 1 s finishes inside the default deadline.
        let mut args = CHECK.to_vec();
        args.extend(["--", "Get-Date"]);
        let r = run(&args, None, &[("SHELLWISE_TESTHOOK", "slow")]);
        assert_eq!(r.code, 0, "{:?}", r.stderr);
        assert_eq!(
            r.json()["findings"][0]["rule"],
            "testhook-done",
            "{}",
            r.stdout
        );
    }

    #[test]
    fn deep_nesting_is_checked_on_a_big_stack() {
        // A deeply nested command must not overflow the worker's stack (the hook rule recurses).
        // The parse refuses the nesting, and the rules still run on the parse error.
        // At 10,008 characters it is also `inline-script-too-long` (break, first).
        let cmd = format!("{}Get-Date", "(".repeat(10_000));
        let r = hook("recurse", &cmd);
        assert_eq!(r.code, 1, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
        let v = r.json();
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2, "{v}");
        assert_eq!(findings[0]["rule"], "inline-script-too-long", "{v}");
        assert_eq!(findings[1]["rule"], "parse-error", "{v}");
    }
}
