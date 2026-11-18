//! Every path that cannot finish the analysis: `danger` unless the raw text is a harmless simple
//! command; a destructive command the raw scan finds is named in the span.

mod common;

use common::{assert_failclosed_danger, assert_ok, run};

const CHECK: &[&str] = &["check", "--shell", "pwsh", "--json"];

/// Assert `danger` from `analysis-failed`, wherever the span is.
fn assert_failed(r: &common::Run) {
    assert_eq!(r.code, 2, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(r.json()["findings"][0]["rule"], "analysis-failed");
}

#[test]
fn input_over_the_size_cap_fails_closed() {
    let mut cmd = "(".repeat(200 * 1024);
    cmd.push_str("rm -rf x");
    let r = run(CHECK, Some(cmd.as_bytes()), &[]);
    assert_failclosed_danger(&r, &cmd, "rm -rf x");

    // Nothing destructive in the raw text, but not a simple command either.
    let mut nested = "(".repeat(200 * 1024);
    nested.push_str("Get-Date");
    assert_failed(&run(CHECK, Some(nested.as_bytes()), &[]));

    let mut harmless = " ".repeat(200 * 1024);
    harmless.push_str("echo hi");
    assert_ok(&run(CHECK, Some(harmless.as_bytes()), &[]));
}

#[test]
fn size_cap_is_64_kib() {
    // No rules exist yet, so a command at the cap is analysed and passes; one byte more fails closed.
    let tail = "; rm -rf x";
    let at_cap = format!("{}{tail}", " ".repeat(64 * 1024 - tail.len()));
    assert_eq!(at_cap.len(), 64 * 1024);
    assert_ok(&run(CHECK, Some(at_cap.as_bytes()), &[]));
    let over = format!(" {at_cap}");
    assert_failclosed_danger(&run(CHECK, Some(over.as_bytes()), &[]), &over, "rm -rf x");
}

#[test]
fn invalid_utf8_fails_closed() {
    let mut bytes = b"echo \xff\xfe; ".to_vec();
    bytes.extend_from_slice(b"rm -rf x");
    let r = run(CHECK, Some(&bytes), &[]);
    assert_eq!(r.code, 2, "{:?}", r.stdout);
    assert_eq!(r.json()["findings"][0]["rule"], "analysis-failed");

    assert_failed(&run(CHECK, Some(b"Get-\xffDate"), &[]));
    assert_ok(&run(CHECK, Some(b"echo \xff"), &[]));
}

#[test]
fn input_over_the_hard_cap_is_danger_without_scanning() {
    // 16 MB of harmless text: too big to scan inside the deadline, so it is danger unread.
    let big = vec![b'a'; 16 * 1024 * 1024];
    let r = run(CHECK, Some(&big), &[]);
    assert_eq!(r.code, 2, "{:?}", r.stderr);
    assert_eq!(r.json()["findings"][0]["rule"], "analysis-failed");
    assert!(
        r.elapsed < std::time::Duration::from_secs(9),
        "{:?}",
        r.elapsed
    );
}

#[test]
fn chained_env_split_strings_get_a_verdict() {
    // Each `env -S` link nests one more command. The invalid byte makes the raw scan decide; past
    // its depth limit nothing proves the tail harmless, so both tails are danger, printed as JSON.
    for tail in ["rm -rf x", "echo hi"] {
        let mut cmd = "env -S ".repeat(9000).into_bytes();
        cmd.extend_from_slice(tail.as_bytes());
        cmd.extend_from_slice(b" #\xff");
        let r = run(&["check", "--shell", "bash", "--json"], Some(&cmd), &[]);
        assert_eq!(
            r.code, 2,
            "{tail}: stdout {:?} stderr {:?}",
            r.stdout, r.stderr
        );
        assert_eq!(r.json()["findings"][0]["rule"], "analysis-failed");
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
    assert_eq!(v["findings"][0]["rule"], "analysis-failed");
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;
    use std::time::Duration;

    const DESTRUCTIVE: &str = "Get-Date; rm -rf x";
    /// Not destructive, but not a simple read-only command either.
    const NOT_SIMPLE: &str = "Get-Date";
    const HARMLESS: &str = "git status";

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
    fn panic_in_a_rule_fails_closed() {
        assert_failclosed_danger(&hook("panic", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_failed(&hook("panic", NOT_SIMPLE));
        assert_ok(&hook("panic", HARMLESS));
    }

    #[test]
    fn rule_past_the_deadline_fails_closed_in_bounded_time() {
        let r = hook("sleep", DESTRUCTIVE);
        assert_failclosed_danger(&r, DESTRUCTIVE, "rm -rf x");
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
        let r = hook("sleep", NOT_SIMPLE);
        assert_failed(&r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
        let r = hook("sleep", HARMLESS);
        assert_ok(&r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
    }

    #[test]
    fn worker_that_ends_without_a_result_fails_closed() {
        assert_failclosed_danger(&hook("dead-worker", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_failed(&hook("dead-worker", NOT_SIMPLE));
        assert_ok(&hook("dead-worker", HARMLESS));
    }

    #[test]
    fn worker_that_cannot_start_fails_closed() {
        assert_failclosed_danger(&hook("spawn-fail", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_failed(&hook("spawn-fail", NOT_SIMPLE));
        assert_ok(&hook("spawn-fail", HARMLESS));
    }

    #[test]
    fn scan_that_misses_the_deadline_is_danger_unless_harmless() {
        // The rule panics and the raw-text scan is too slow: only the harmless grammar clears it.
        let r = hook("panic-scan-sleep", NOT_SIMPLE);
        assert_failed(&r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
        let r = hook("panic-scan-sleep", HARMLESS);
        assert_ok(&r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
    }

    #[test]
    fn allow_marker_lowers_a_failed_analysis_to_ok() {
        let cmd = "Get-Date; rm -rf x # shellwise: allow";
        assert_ok(&hook("panic", cmd));
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
        assert_eq!(v["findings"][0]["rule"], "analysis-failed");
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
        let cmd = format!("{}Get-Date", "(".repeat(10_000));
        assert_ok(&hook("recurse", &cmd));
    }
}
