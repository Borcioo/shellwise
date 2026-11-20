//! `analyse` through the spawned binary: a failure that is not a parse error is
//! `analysis-incomplete`, warn without destructive raw text and danger with it.

mod common;

use common::{Run, assert_failclosed_danger, assert_incomplete_warn, run};

const CHECK: &[&str] = &["check", "--shell", "pwsh", "--json"];
const PLAIN: &str = "Get-Date";
const DESTRUCTIVE: &str = "rm -rf x";

#[test]
fn invalid_utf8_is_incomplete() {
    assert_incomplete_warn(&run(CHECK, Some(b"Get-\xffDate"), &[]));
    let mut bytes = b"echo \xff; ".to_vec();
    bytes.extend_from_slice(DESTRUCTIVE.as_bytes());
    let r = run(CHECK, Some(&bytes), &[]);
    let lossy = String::from_utf8_lossy(&bytes).into_owned();
    assert_failclosed_danger(&r, &lossy, DESTRUCTIVE);
    // A .NET `Delete()` call names no table row and is destructive all the same.
    let delete = "(Get-Item x).Delete()";
    let mut bytes = b"echo ".to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(b"; ");
    bytes.extend_from_slice(delete.as_bytes());
    let r = run(CHECK, Some(&bytes), &[]);
    let lossy = String::from_utf8_lossy(&bytes).into_owned();
    assert_failclosed_danger(&r, &lossy, ".Delete");
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;
    use std::time::Duration;

    fn hook(mode: &str, command: &str) -> Run {
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

    fn message(r: &Run) -> String {
        r.json()["findings"][0]["message"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_panic_in_a_rule_is_incomplete() {
        let r = hook("panic", PLAIN);
        assert_incomplete_warn(&r);
        // Caught where it happened, not seen later as a worker that ended without a result.
        assert!(message(&r).contains("(internal error)"), "{}", r.stdout);
        assert_failclosed_danger(&hook("panic", DESTRUCTIVE), DESTRUCTIVE, DESTRUCTIVE);
    }

    #[test]
    fn a_scan_hit_with_no_destructive_row_is_warn() {
        // Each text is opaque to the raw scan (a pipe into a shell, wrappers past its depth
        // limit, a pipe into Invoke-Expression) and names no command of the destructive table.
        for cmd in [
            "cat setup.sh | bash",
            "sudo sudo sudo sudo sudo echo hi",
            "Get-Content setup.ps1 | iex",
        ] {
            // A panic in a rule, and one in a length rule (each path scans on its own).
            for mode in ["panic", "length-panic"] {
                assert_incomplete_warn(&hook(mode, cmd));
            }
        }
    }

    #[test]
    fn a_dotnet_delete_call_is_danger() {
        // No table row names a `Delete()` method call; the scan still reads it as destructive.
        for cmd in [
            "(Get-Item x).Delete()",
            "$d = Get-Item x; $d.Delete($true)",
            "gci x -Recurse | % { $_.Delete() }",
        ] {
            for mode in ["panic", "length-panic"] {
                assert_failclosed_danger(&hook(mode, cmd), cmd, ".Delete");
            }
        }
    }

    #[test]
    fn a_parser_failure_is_incomplete() {
        // The parser itself panics: no syntax error is known, so it is no parse-error finding.
        for shell in ["bash", "pwsh"] {
            let run_on = |cmd: &str| {
                run(
                    &["check", "--shell", shell, "--json", "--", cmd],
                    None,
                    &[("SHELLWISE_TESTHOOK", "parse-panic")],
                )
            };
            let r = run_on(PLAIN);
            assert_incomplete_warn(&r);
            assert!(message(&r).contains("parser"), "{shell}: {}", r.stdout);
            assert_failclosed_danger(&run_on(DESTRUCTIVE), DESTRUCTIVE, DESTRUCTIVE);
        }
    }

    #[test]
    fn a_panic_in_a_length_rule_is_incomplete() {
        let r = hook("length-panic", PLAIN);
        assert_incomplete_warn(&r);
        assert!(message(&r).contains("length rule"), "{}", r.stdout);
        let r = hook("length-panic", DESTRUCTIVE);
        assert_failclosed_danger(&r, DESTRUCTIVE, DESTRUCTIVE);
    }

    #[test]
    fn a_deny_kind_parse_error_is_the_only_finding() {
        // The `slow` hook adds a finding to every analysis that finishes.
        let bash = ["check", "--shell", "bash", "--json", "--", "rm -rf \"x"];
        let r = run(&bash, None, &[("SHELLWISE_TESTHOOK", "slow")]);
        assert_eq!(r.code, 1, "{}", r.stdout);
        assert_eq!(rules(&r), ["parse-error"], "{}", r.stdout);
        // Any other kind keeps every finding.
        let r = run(
            &["check", "--shell", "pwsh", "--json", "--", "Get-Date ("],
            None,
            &[("SHELLWISE_TESTHOOK", "slow")],
        );
        assert_eq!(rules(&r), ["parse-error", "testhook-done"], "{}", r.stdout);
    }

    #[test]
    fn a_rule_past_the_deadline_is_incomplete_in_bounded_time() {
        for (cmd, destructive) in [(PLAIN, false), (DESTRUCTIVE, true)] {
            let r = hook("sleep", cmd);
            if destructive {
                assert_failclosed_danger(&r, cmd, cmd);
            } else {
                assert_incomplete_warn(&r);
            }
            assert!(r.elapsed < Duration::from_secs(5), "{cmd}: {:?}", r.elapsed);
        }
    }

    fn rules(r: &Run) -> Vec<String> {
        r.json()["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_length_rules_run_before_the_size_cap() {
        // The `length` hook is a length rule that fires on any text. Over the 64 KiB cap the
        // analysis is incomplete, and the length rule has still run.
        let over = format!("{}{PLAIN}", " ".repeat(64 * 1024));
        let r = run(
            CHECK,
            Some(over.as_bytes()),
            &[("SHELLWISE_TESTHOOK", "length")],
        );
        assert_eq!(r.code, 1, "{}", r.stdout);
        assert_eq!(
            rules(&r),
            [
                "inline-script-too-long",
                "testhook-length",
                "analysis-incomplete"
            ],
            "{}",
            r.stdout
        );
        let r = run(
            CHECK,
            Some(PLAIN.as_bytes()),
            &[("SHELLWISE_TESTHOOK", "length")],
        );
        assert_eq!(rules(&r), ["testhook-length"], "{}", r.stdout);
    }
}
