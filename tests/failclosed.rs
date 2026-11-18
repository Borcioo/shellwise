//! Every path that cannot finish the analysis: `danger` when the raw text holds a destructive
//! command, otherwise `ok`.

mod common;

use common::{assert_failclosed_danger, assert_ok, run};

const CHECK: &[&str] = &["check", "--shell", "pwsh", "--json"];

#[test]
fn input_over_the_size_cap_fails_closed() {
    let mut cmd = "(".repeat(200 * 1024);
    cmd.push_str("rm -rf x");
    let r = run(CHECK, Some(cmd.as_bytes()), &[]);
    assert_failclosed_danger(&r, &cmd, "rm -rf x");

    let mut harmless = "(".repeat(200 * 1024);
    harmless.push_str("Get-Date");
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

    assert_ok(&run(CHECK, Some(b"Get-\xffDate"), &[]));
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
        assert_ok(&hook("panic", "Get-Date"));
    }

    #[test]
    fn rule_past_the_deadline_fails_closed_in_bounded_time() {
        let r = hook("sleep", DESTRUCTIVE);
        assert_failclosed_danger(&r, DESTRUCTIVE, "rm -rf x");
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
        let r = hook("sleep", "Get-Date");
        assert_ok(&r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
    }

    #[test]
    fn worker_that_ends_without_a_result_fails_closed() {
        assert_failclosed_danger(&hook("dead-worker", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_ok(&hook("dead-worker", "Get-Date"));
    }

    #[test]
    fn worker_that_cannot_start_fails_closed() {
        assert_failclosed_danger(&hook("spawn-fail", DESTRUCTIVE), DESTRUCTIVE, "rm -rf x");
        assert_ok(&hook("spawn-fail", "Get-Date"));
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
