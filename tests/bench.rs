//! `shellwise bench` through the spawned binary, on the synthetic fixture in `tests/bench_fixture/`
//! (its README lists every row and the answer each one gives). One test per meter line and per
//! exit condition, each with the passing twin the full run gives.

mod common;

use std::path::PathBuf;

use common::{Run, run};
use serde_json::Value;

fn fixture(name: &str) -> String {
    format!("{}/tests/bench_fixture/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A fresh folder per test, under this build's target dir (never shared with another checkout),
/// for its report, dump and diff files.
fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("bench")
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the test folder");
    dir
}

struct Bench {
    run: Run,
    dir: PathBuf,
}

impl Bench {
    fn report(&self) -> Value {
        let path = self.dir.join("report.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path:?}: {e}; stdout {}", self.run.stdout));
        serde_json::from_str(&text).expect("the report is JSON")
    }

    fn assert_code(&self, code: i32) {
        assert_eq!(
            self.run.code, code,
            "stdout {} stderr {}",
            self.run.stdout, self.run.stderr
        );
    }

    fn assert_fail(&self, text: &str) {
        self.assert_code(1);
        assert!(
            self.run
                .stdout
                .lines()
                .any(|l| l.starts_with("FAIL: ") && l.contains(text)),
            "no FAIL line holding {text:?}: {}",
            self.run.stdout
        );
    }
}

/// Inputs of one run; every field names a fixture file, `None` leaves the flag out.
struct Inputs<'a> {
    corpus: &'a str,
    baseline: &'a str,
    known: &'a str,
    rule_map: Option<&'a str>,
    real_parse: Option<&'a str>,
}

const FULL: Inputs<'static> = Inputs {
    corpus: "corpus.jsonl",
    baseline: "baseline.jsonl",
    known: "known.jsonl",
    rule_map: Some("rule_map.toml"),
    real_parse: Some("real_parse.tsv"),
};

fn bench(test: &str, inputs: &Inputs, extra: &[&str], env: &[(&str, &str)]) -> Bench {
    let dir = scratch(test);
    let out = dir.join("report.json").display().to_string();
    let (corpus, baseline, known) = (
        fixture(inputs.corpus),
        fixture(inputs.baseline),
        fixture(inputs.known),
    );
    let mut args = vec![
        "bench",
        "--corpus",
        &corpus,
        "--baseline",
        &baseline,
        "--known",
        &known,
        "--out",
        &out,
    ];
    let map = inputs.rule_map.map(fixture);
    if let Some(m) = &map {
        args.extend(["--rule-map", m.as_str()]);
    }
    let real = inputs.real_parse.map(fixture);
    if let Some(r) = &real {
        args.extend(["--real-parse", r.as_str()]);
    }
    let extra: Vec<String> = extra
        .iter()
        .map(|a| a.replace("{dir}", &dir.display().to_string()))
        .collect();
    args.extend(extra.iter().map(String::as_str));
    Bench {
        run: run(&args, None, env),
        dir,
    }
}

fn count(v: &Value, line: &str) -> (u64, u64, u64) {
    let c = if v[line]["count"].is_object() {
        &v[line]["count"]
    } else {
        &v[line]
    };
    (
        c["rows"].as_u64().unwrap(),
        c["Bash"].as_u64().unwrap(),
        c["PowerShell"].as_u64().unwrap(),
    )
}

#[test]
fn the_meter_lines_have_their_known_answers() {
    let b = bench("meters", &FULL, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    assert_eq!(count(&v, "rows"), (10, 6, 4), "{v}");
    assert_eq!(v["days"], 2);
    assert_eq!(count(&v["denominators"], "ok"), (8, 5, 3));
    assert_eq!(count(&v["denominators"], "ok_non_destructive"), (7, 4, 3));
    // Rows 3, 4 and 5 are the denied non-destructive ok rows, one on each line.
    assert_eq!(count(&v, "refused_by_real_parser"), (1, 0, 1));
    assert_eq!(count(&v, "parity"), (1, 1, 0));
    assert_eq!(count(&v, "meter_1"), (1, 1, 0));
    assert_eq!(v["meter_1"]["upper_bound"], false);
    assert_eq!(count(&v, "own_line"), (0, 0, 0));
    assert_eq!(count(&v, "meter_2"), (1, 1, 0));
    assert_eq!(v["meter_2"]["per_day"], 0.5);
    assert_eq!(v["parse_kind_false_deny"], 1);
    assert_eq!(v["parse_kind_unmeasured"], 1);
    assert_eq!(v["real_parse_missing"], 1);
    for line in [
        "meter 1: 1 of 7 non-destructive ok rows",
        "refused by the real parser: 1 (Bash 0, PowerShell 1)",
        "parity: 1 (Bash 1, PowerShell 0)",
        "own line: 0 (Bash 0, PowerShell 0)",
        "meter 2: 1 (Bash 1, PowerShell 0)",
        "parse_kind_false_deny: 1",
    ] {
        assert!(b.run.stdout.contains(line), "no {line:?}: {}", b.run.stdout);
    }
}

#[test]
fn per_rule_counts_split_denies_and_warns_by_label() {
    let b = bench("per-rule", &FULL, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    let ok = &v["per_rule"]["parse-error"]["ok"];
    assert_eq!(
        (ok["deny"].as_u64(), ok["warn"].as_u64()),
        (Some(4), Some(1)),
        "{v}"
    );
    // Row 7, the only failed row, is denied under whichever id the destructive arm carries.
    let failed_denies: u64 = v["per_rule"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|labels| labels["failed"]["deny"].as_u64())
        .sum();
    assert_eq!(failed_denies, 1, "{v}");
}

#[test]
fn parity_per_installed_rule_counts_what_shellwise_allows() {
    let b = bench("parity", &FULL, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    let p = &v["parity_per_rule"];
    let row = |sg: &str| {
        (
            p[sg]["baseline_guard_denies"].as_u64().unwrap(),
            p[sg]["shellwise_allows"].as_u64().unwrap(),
            p[sg]["excepted"].as_u64().unwrap(),
            p[sg]["unexplained"].as_u64().unwrap(),
        )
    };
    assert_eq!(row("bash-unterminated-quote"), (1, 0, 0, 0), "{v}");
    assert_eq!(row("bash-too-long"), (1, 1, 0, 1), "{v}");
    // The fixture's parity exception explains the one allowed row of this rule.
    assert_eq!(row("bash-backslash-collapse"), (1, 1, 1, 0), "{v}");
    assert_eq!(
        p["bash-backslash-collapse"]["exceptions"][0]["shape"],
        "fixture-shape"
    );
    assert!(
        b.run
            .stdout
            .contains("parity bash-too-long: baseline-guard denies 1, shellwise allows 1"),
        "{}",
        b.run.stdout
    );
}

#[test]
fn without_real_parse_answers_the_refused_line_and_false_denies_are_not_measured() {
    let inputs = Inputs {
        real_parse: None,
        ..FULL
    };
    let b = bench("no-real-parse", &inputs, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    assert!(v["refused_by_real_parser"].is_null(), "{v}");
    assert_eq!(count(&v, "meter_1"), (2, 1, 1), "{v}");
    assert_eq!(v["meter_1"]["upper_bound"], true, "{v}");
    assert_eq!(count(&v, "parity"), (1, 1, 0), "{v}");
    assert!(v["parse_kind_false_deny"].is_null(), "{v}");
    assert_eq!(v["parse_kind_unmeasured"], 4);
    for line in [
        "parse_kind_false_deny: not measured",
        "refused by the real parser: not measured",
        "an upper bound",
    ] {
        assert!(b.run.stdout.contains(line), "no {line:?}: {}", b.run.stdout);
    }
}

#[test]
fn an_own_line_rule_moves_its_rows_off_meter_1() {
    let inputs = Inputs {
        rule_map: Some("rule_map_own_line.toml"),
        ..FULL
    };
    let b = bench("own-line", &inputs, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    assert_eq!(count(&v, "own_line"), (1, 1, 0), "{v}");
    assert_eq!(count(&v, "meter_1"), (0, 0, 0), "{v}");
    // Parity and the real parser come first.
    assert_eq!(count(&v, "parity"), (1, 1, 0), "{v}");
    assert_eq!(count(&v, "refused_by_real_parser"), (1, 0, 1), "{v}");
}

#[test]
fn the_known_slice_is_checked_and_counted() {
    let b = bench("known", &FULL, &[], &[]);
    b.assert_code(0);
    let k = &b.report()["known"];
    assert_eq!(k["rows"], 4, "{k}");
    assert_eq!(k["checked"], 1, "{k}");
    assert_eq!(k["not_landed"], 1, "{k}");
    assert_eq!(k["none_rows"], 2, "{k}");
    assert_eq!(k["none_denied"], 1, "{k}");
    assert!(
        b.run.stdout.contains("known: 1 of 4 rows checked"),
        "{}",
        b.run.stdout
    );
}

#[test]
fn a_known_row_that_misses_its_mapped_rule_fails() {
    let inputs = Inputs {
        known: "known_miss.jsonl",
        ..FULL
    };
    let b = bench("known-miss", &inputs, &[], &[]);
    b.assert_fail("known row f00000000001 misses parse-error");
    // The report is still written, with the failure in it.
    assert_eq!(b.report()["fails"].as_array().unwrap().len(), 1);
}

#[test]
fn zero_known_rows_checked_fails() {
    let inputs = Inputs {
        known: "known_not_landed.jsonl",
        ..FULL
    };
    bench("known-none", &inputs, &[], &[]).assert_fail("0 of 2 known rows checked");
}

#[test]
fn a_known_row_absent_from_the_corpus_fails() {
    let inputs = Inputs {
        known: "known_absent.jsonl",
        ..FULL
    };
    bench("known-absent", &inputs, &[], &[])
        .assert_fail("known row f000000000ff is not in the corpus");
}

#[test]
fn a_known_row_whose_os_is_not_the_replayed_one_fails() {
    let inputs = Inputs {
        known: "known_os_mismatch.jsonl",
        ..FULL
    };
    bench("known-os", &inputs, &[], &[])
        .assert_fail("known row f00000000004 is Linux in the slice but replays on Windows");
}

#[test]
fn a_missing_known_file_fails() {
    let inputs = Inputs {
        known: "no-such-known.jsonl",
        ..FULL
    };
    bench("known-missing", &inputs, &[], &[]).assert_fail("cannot read");
}

#[test]
fn a_baseline_guard_id_the_map_does_not_name_fails() {
    let inputs = Inputs {
        known: "known_unmapped.jsonl",
        ..FULL
    };
    bench("unmapped-known", &inputs, &[], &[])
        .assert_fail("no shellwise id for these baseline-guard ids: fixture-unknown-id");
    let inputs = Inputs {
        baseline: "baseline_unmapped.jsonl",
        ..FULL
    };
    bench("unmapped-baseline", &inputs, &[], &[])
        .assert_fail("no shellwise id for these baseline-guard ids: fixture-unknown-id");
}

#[test]
fn zero_rows_fails() {
    let inputs = Inputs {
        corpus: "corpus_empty.jsonl",
        ..FULL
    };
    bench("empty", &inputs, &[], &[]).assert_fail("0 rows read from");
}

#[test]
fn zero_rows_for_one_shell_fails() {
    let inputs = Inputs {
        corpus: "corpus_bash_only.jsonl",
        ..FULL
    };
    bench("bash-only", &inputs, &[], &[]).assert_fail("0 PowerShell rows read from");
}

#[test]
fn zero_rows_joined_to_the_baseline_fails() {
    let inputs = Inputs {
        baseline: "baseline_unjoined.jsonl",
        ..FULL
    };
    bench("unjoined", &inputs, &[], &[]).assert_fail("0 corpus rows joined to the baseline");
}

#[test]
fn a_real_parse_file_that_is_empty_or_joins_no_row_fails() {
    let inputs = Inputs {
        real_parse: Some("corpus_empty.jsonl"),
        ..FULL
    };
    bench("real-empty", &inputs, &[], &[]).assert_fail("0 rows read from");
    let inputs = Inputs {
        real_parse: Some("real_parse_unjoined.tsv"),
        ..FULL
    };
    bench("real-unjoined", &inputs, &[], &[])
        .assert_fail("real_parse_unjoined.tsv joined to the corpus");
}

#[test]
fn an_old_dump_that_is_empty_or_joins_no_row_fails() {
    let empty = fixture("corpus_empty.jsonl");
    bench("diff-empty", &FULL, &["--diff", empty.as_str()], &[]).assert_fail("0 rows read from");
    let unjoined = fixture("old_dump_unjoined.tsv");
    bench("diff-unjoined", &FULL, &["--diff", unjoined.as_str()], &[])
        .assert_fail("old_dump_unjoined.tsv joined to the corpus");
}

#[test]
fn the_latency_is_reported_per_shell() {
    let b = bench("latency", &FULL, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    for shell in ["Bash", "PowerShell"] {
        let (p50, p99) = (
            v["latency_ms"][shell]["p50"].as_f64().unwrap(),
            v["latency_ms"][shell]["p99"].as_f64().unwrap(),
        );
        // Every row runs the parse on a worker thread, so no row takes 0 ms.
        assert!(p50 > 0.0 && p99 >= p50, "{shell}: p50 {p50} p99 {p99}");
        assert!(
            b.run.stdout.contains(&format!("latency {shell}: p50 ")),
            "{}",
            b.run.stdout
        );
    }
}

#[test]
fn the_dump_holds_one_line_per_row_with_the_raw_hit() {
    let b = bench("dump", &FULL, &["--dump", "{dir}/dump.tsv"], &[]);
    b.assert_code(0);
    let text = std::fs::read_to_string(b.dir.join("dump.tsv")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "id\tlevel\trules\traw_hit");
    assert_eq!(lines.len(), 11, "{text}");
    assert!(lines.contains(&"f00000000001\tok\t-\tno"), "{text}");
    assert!(
        lines.contains(&"f00000000003\tbreak\tparse-error\tno"),
        "{text}"
    );
    let row7 = lines
        .iter()
        .find(|l| l.starts_with("f00000000007\t"))
        .unwrap();
    assert!(
        row7.starts_with("f00000000007\tdanger\t") && row7.ends_with("\tyes"),
        "{row7}"
    );
}

/// `corpus_os.jsonl`: each row replays on the OS its cwd shape names, and the report counts the
/// rows per OS and per cwd shape. (No rule on this base reads the env into a verdict:
/// `bench::tests` holds the env control.)
#[test]
fn each_row_replays_on_the_os_its_cwd_names() {
    let inputs = Inputs {
        corpus: "corpus_os.jsonl",
        baseline: "baseline_os.jsonl",
        known: "known.jsonl",
        rule_map: Some("rule_map.toml"),
        real_parse: None,
    };
    let b = bench("os", &inputs, &["--dump", "{dir}/dump.tsv"], &[]);
    b.assert_code(0);
    let text = std::fs::read_to_string(b.dir.join("dump.tsv")).unwrap();
    for line in [
        // A drive cwd stays Windows: Git Bash rewrites the POSIX path, as before.
        "f000000000b1\twarn\tbash-msys-path-mangle\tno",
        // The same command from a Linux cwd runs in POSIX bash, which rewrites nothing.
        "f000000000b2\tok\t-\tno",
    ] {
        assert!(text.lines().any(|l| l == line), "no {line:?}: {text}");
    }
    let v = b.report();
    assert_eq!(count(&v["rows_per_os"], "Windows"), (3, 2, 1), "{v}");
    assert_eq!(count(&v["rows_per_os"], "Linux"), (2, 2, 0), "{v}");
    let shapes = &v["cwd_shapes"];
    for (shape, n) in [
        ("drive", 1),
        ("unc", 1),
        ("wsl-mnt", 1),
        ("posix", 1),
        ("missing", 1),
        ("other", 0),
    ] {
        assert_eq!(shapes[shape], n, "{shape}: {shapes}");
    }
    for line in [
        "replayed on Windows: 3 (Bash 2, PowerShell 1)",
        "replayed on Linux: 2 (Bash 2, PowerShell 0)",
        "cwd shapes: drive 1, unc 1, wsl-mnt 1, posix 1, missing 1, other 0",
    ] {
        assert!(
            b.run.stdout.lines().any(|l| l == line),
            "no {line:?}: {}",
            b.run.stdout
        );
    }
}

#[test]
fn the_diff_counts_the_moved_rows_per_os() {
    let inputs = Inputs {
        corpus: "corpus_os.jsonl",
        baseline: "baseline_os.jsonl",
        known: "known.jsonl",
        rule_map: Some("rule_map.toml"),
        real_parse: None,
    };
    let old = fixture("old_dump_os.tsv");
    let b = bench("diff_os", &inputs, &["--diff", old.as_str()], &[]);
    b.assert_code(0);
    let m = &b.report()["moves"];
    assert_eq!(m["down"], 1, "{m}");
    assert_eq!(m["moved_by_os"]["Linux"], 1, "{m}");
    assert_eq!(m["moved_by_os"]["Windows"], 0, "{m}");
    assert_eq!(m["moved"][0]["os"], "Linux", "{m}");
    assert!(
        b.run
            .stdout
            .lines()
            .any(|l| l == "moves by OS: Windows 0, Linux 1"),
        "{}",
        b.run.stdout
    );
}

#[test]
fn the_diff_lists_each_moved_row_by_its_old_and_new_pair() {
    let old = fixture("old_dump.tsv");
    let b = bench("diff", &FULL, &["--diff", old.as_str()], &[]);
    b.assert_code(0);
    let m = &b.report()["moves"];
    assert_eq!(m["up"], 1, "{m}");
    assert_eq!(m["down"], 1, "{m}");
    assert_eq!(m["changed"], 0, "{m}");
    assert_eq!(m["unchanged"], 1, "{m}");
    assert_eq!(m["missing_in_old"], 7, "{m}");
    assert_eq!(m["missing_in_new"], 0, "{m}");
    assert_eq!(m["control_moves"], 0, "{m}");
    for line in [
        "moved up f00000000003 ok[-] -> break[parse-error]",
        "moved down f00000000001 break[parse-error] -> ok[-]",
    ] {
        assert!(b.run.stdout.contains(line), "no {line:?}: {}", b.run.stdout);
    }
}

#[test]
fn the_compiled_in_rule_map_runs_the_fixture() {
    let inputs = Inputs {
        known: "known_default_map.jsonl",
        rule_map: None,
        ..FULL
    };
    let b = bench("default-map", &inputs, &[], &[]);
    b.assert_code(0);
    assert_eq!(b.report()["known"]["checked"], 1);
}

#[test]
fn the_rule_map_names_every_baseline_guard_id() {
    let path = format!("{}/tools/corpus/rule_map.toml", env!("CARGO_MANIFEST_DIR"));
    let table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let map = table["map"].as_table().unwrap();
    // The 15 installed rules and the 6 of the full set that baseline.md and known.jsonl name.
    let ids = [
        "bash-backslash-collapse",
        "bash-too-long",
        "bat-metachar",
        "cli-inline-prose",
        "gate-truncated-pipeline",
        "git-no-verify",
        "git-restore-discards",
        "git-unreadable",
        "git-worktree-junction",
        "ps-bad-parameter",
        "ps-bare-bash",
        "ps-dotnet-relative-path",
        "ps-git-commit-stdin",
        "ps-native-nonewline",
        "stale-write-var",
        "bash-msys-path-mangle",
        "bash-powershell-syntax",
        "bash-unterminated-quote",
        "bash-vendor-bin-shebang",
        "bash-versioned-php",
        "ps-unix-command",
    ];
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut want = ids.to_vec();
    want.sort_unstable();
    assert_eq!(keys, want);
    assert_eq!(map["bash-unterminated-quote"].as_str(), Some("parse-error"));
    assert_eq!(map["bash-too-long"].as_str(), Some("too-long"));
    assert_eq!(
        map["bash-powershell-syntax"].as_str(),
        Some("bash-ps-cmdlet")
    );
    let own: Vec<&str> = table["own_line_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(own, ["inline-script-too-long"]);
}

#[cfg(feature = "testhooks")]
mod hooks {
    use super::*;

    #[test]
    fn a_head_vs_head_control_that_moves_fails() {
        let env = [("SHELLWISE_TESTHOOK", "bench-control-move")];
        let old = fixture("old_dump.tsv");
        let b = bench("control", &FULL, &["--diff", old.as_str()], &env);
        b.assert_fail("the head-vs-head control moved 1 rows");
        assert!(
            b.run
                .stdout
                .contains("control moved f00000000001 ok[-] -> break[-]"),
            "{}",
            b.run.stdout
        );
        assert_eq!(b.report()["moves"]["control_moves"], 1);
        // Without --diff there is no second pass, so the same hook moves nothing.
        bench("control-no-diff", &FULL, &[], &env).assert_code(0);
    }
}
