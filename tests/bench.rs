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
    bench_in(scratch(test), inputs, extra, env)
}

/// `bench` in a folder the test already filled; an input that names an absolute path (a file
/// the test wrote) is used as is, any other names a fixture file.
fn bench_in(dir: PathBuf, inputs: &Inputs, extra: &[&str], env: &[(&str, &str)]) -> Bench {
    let fixture = |name: &str| {
        if std::path::Path::new(name).is_absolute() {
            name.to_string()
        } else {
            fixture(name)
        }
    };
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
        "inline-script-too-long thresholds: PowerShell over 80 lines or 6000 characters, Bash over 100 lines or 8000 characters",
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
    let exceptions = fixture("parity_exceptions.toml");
    let b = bench(
        "parity",
        &FULL,
        &["--parity-exceptions", exceptions.as_str()],
        &[],
    );
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
        p["bash-backslash-collapse"]["keys"][0]["shape"],
        "mapped-silent"
    );
    assert!(
        b.run
            .stdout
            .contains("parity bash-too-long: baseline guard denies 1, shellwise allows 1"),
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
        .assert_fail("no shellwise id for these baseline guard ids: fixture-unknown-id");
    let inputs = Inputs {
        baseline: "baseline_unmapped.jsonl",
        ..FULL
    };
    bench("unmapped-baseline", &inputs, &[], &[])
        .assert_fail("no shellwise id for these baseline guard ids: fixture-unknown-id");
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
    assert_eq!(lines[0], "id\tlevel\trules\traw_hit\trule_levels");
    assert_eq!(lines.len(), 11, "{text}");
    assert!(lines.contains(&"f00000000001\tok\t-\tno\t-"), "{text}");
    assert!(
        lines.contains(&"f00000000003\tbreak\tparse-error\tno\tparse-error:break"),
        "{text}"
    );
    // Row 8's parse error is not a deny kind: the same rule at warn.
    assert!(
        lines.contains(&"f00000000008\twarn\tparse-error\tno\tparse-error:warn"),
        "{text}"
    );
    let row7 = lines
        .iter()
        .find(|l| l.starts_with("f00000000007\t"))
        .unwrap();
    assert!(
        row7.starts_with("f00000000007\tdanger\t") && row7.contains("\tyes\t"),
        "{row7}"
    );
}

/// An old dump without the `rule_levels` column (a build before it) still diffs: rules compare by
/// name, so a row whose rules and level stay is unchanged.
#[test]
fn a_dump_without_rule_levels_diffs_by_rule_names() {
    let old = fixture("old_dump.tsv");
    let b = bench("diff-old-format", &FULL, &["--diff", old.as_str()], &[]);
    b.assert_code(0);
    let m = &b.report()["moves"];
    assert_eq!(
        (m["up"].as_u64(), m["down"].as_u64(), m["changed"].as_u64()),
        (Some(1), Some(1), Some(0)),
        "{m}"
    );
    for line in ["missing in old 7", "missing in new 0"] {
        assert!(b.run.stdout.contains(line), "no {line:?}: {}", b.run.stdout);
    }
}

/// With `rule_levels` on both sides, a rule whose level moved while the row's level stayed is
/// "changed".
#[test]
fn a_rule_level_move_reads_as_changed() {
    let dir = scratch("diff-rule-level");
    let old = dir.join("old.tsv");
    std::fs::write(
        &old,
        "id\tlevel\trules\traw_hit\trule_levels\nf00000000007\tdanger\tparse-error-destructive\tyes\tparse-error-destructive:break\n",
    )
    .unwrap();
    let old = old.display().to_string();
    let b = bench_in(dir, &FULL, &["--diff", old.as_str()], &[]);
    b.assert_code(0);
    let m = &b.report()["moves"];
    let row7 = b.report()["moves"]["moved"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "f00000000007")
        .cloned();
    assert!(row7.is_some_and(|r| r["way"] == "changed"), "{m}");
}

#[test]
fn the_rows_without_a_baseline_row_are_printed() {
    let b = bench("baseline-missing", &FULL, &[], &[]);
    b.assert_code(0);
    assert_eq!(b.report()["baseline_missing"], 0);
    assert!(
        b.run
            .stdout
            .lines()
            .any(|l| l == "baseline missing: 0 rows"),
        "{}",
        b.run.stdout
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
        "f000000000b1\twarn\tbash-msys-path-mangle\tno\tbash-msys-path-mangle:warn",
        // The same command from a Linux cwd runs in POSIX bash, which rewrites nothing.
        "f000000000b2\tok\t-\tno\t-",
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

/// E1: the critical folders of a replayed row are those of the row's OS, not the host's: a Linux
/// `rm -rf /usr` is critical on a Windows host too.
#[test]
fn a_linux_row_deletes_a_linux_system_folder_on_any_host() {
    let inputs = Inputs {
        corpus: "corpus_host_os.jsonl",
        baseline: "baseline_host_os.jsonl",
        known: "known.jsonl",
        rule_map: Some("rule_map.toml"),
        real_parse: None,
    };
    let b = bench("host_os", &inputs, &["--dump", "{dir}/dump.tsv"], &[]);
    b.assert_code(0);
    let text = std::fs::read_to_string(b.dir.join("dump.tsv")).unwrap();
    let line = "f000000000c1\tcritical\tdelete-critical\t";
    assert!(
        text.lines().any(|l| l.starts_with(line)),
        "no {line:?}: {text}"
    );
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

/// One corpus row of a corpus a test writes (no corpus text: every command holds `fixture`).
fn row(id: &str, tool: &str, command: &str, cwd: Option<&str>, destructive: bool) -> Value {
    serde_json::json!({
        "id": id, "session": "fixture", "ts": "2026-11-01T10:00:00.000Z", "tool": tool,
        "command": command, "cwd": cwd, "cli_version": "0.0.0", "label": "ok",
        "denied_by": null, "destructive": destructive, "error_excerpt": "",
    })
}

fn write_jsonl(path: &std::path::Path, rows: &[Value]) -> String {
    let text: String = rows.iter().map(|r| format!("{r}\n")).collect();
    std::fs::write(path, text).unwrap();
    path.display().to_string()
}

/// A corpus a test writes into `dir`, with the rows every run needs around `rows`: one row per
/// shell and a known row (fixture row 4's shape, whose baseline guard id maps to `parse-error`).
/// `installed` gives a row's baseline guard ids. Returns the corpus, baseline and known paths.
fn written(dir: &std::path::Path, rows: &[(Value, &[&str])]) -> (String, String, String) {
    let anchor = row("f000000000a1", "Bash", "echo 'fixture-anchor", None, false);
    let pwsh = row(
        "f000000000a2",
        "PowerShell",
        "Get-Date -Format fixture",
        None,
        false,
    );
    let mut all: Vec<(Value, &[&str])> = vec![(anchor, &["bash-unterminated-quote"]), (pwsh, &[])];
    all.extend(rows.iter().cloned());
    let corpus = write_jsonl(
        &dir.join("corpus.jsonl"),
        &all.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>(),
    );
    let baseline: Vec<Value> = all
        .iter()
        .map(|(r, ids)| serde_json::json!({ "id": r["id"], "full": ids, "installed": ids }))
        .collect();
    let baseline = write_jsonl(&dir.join("baseline.jsonl"), &baseline);
    let known = write_jsonl(
        &dir.join("known.jsonl"),
        &[
            serde_json::json!({ "id": "f000000000a1", "expected_rules": ["bash-unterminated-quote"] }),
        ],
    );
    (corpus, baseline, known)
}

fn inputs<'a>(files: &'a (String, String, String), real_parse: Option<&'a str>) -> Inputs<'a> {
    Inputs {
        corpus: &files.0,
        baseline: &files.1,
        known: &files.2,
        rule_map: Some("rule_map.toml"),
        real_parse,
    }
}

/// A row whose recorded cwd is not a folder on this machine cannot fire a rule that reads the
/// disk: the report counts those rows per OS and names the rules that read the disk.
#[test]
fn rows_whose_cwd_is_gone_here_are_counted_per_os_with_the_disk_rules() {
    let dir = scratch("cwd-missing");
    let here = dir.join("proj");
    std::fs::create_dir_all(&here).unwrap();
    let here = here.display().to_string();
    let gone_win = format!("C:{0}fixture-gone-9f3{0}proj", char::from(0x5c));
    let files = written(
        &dir,
        &[
            (
                row(
                    "f000000000c1",
                    "Bash",
                    "rm -rf fixture-build",
                    Some(&here),
                    true,
                ),
                &[],
            ),
            (
                row(
                    "f000000000c2",
                    "PowerShell",
                    "Get-Date -Format fixture",
                    Some(&gone_win),
                    false,
                ),
                &[],
            ),
            (
                row(
                    "f000000000c3",
                    "Bash",
                    "echo fixture-linux",
                    Some("/fixture-gone-9f3/proj"),
                    false,
                ),
                &[],
            ),
        ],
    );
    let b = bench_in(dir, &inputs(&files, None), &[], &[]);
    b.assert_code(0);
    let v = b.report();
    // The anchors have no cwd and the existing folder counts nowhere.
    assert_eq!(count(&v["rows_cwd_missing"], "Windows"), (1, 0, 1), "{v}");
    assert_eq!(count(&v["rows_cwd_missing"], "Linux"), (1, 1, 0), "{v}");
    for line in [
        "cwd gone here, replayed on Windows: 1 (Bash 0, PowerShell 1)",
        "cwd gone here, replayed on Linux: 1 (Bash 1, PowerShell 0)",
    ] {
        assert!(
            b.run.stdout.lines().any(|l| l == line),
            "no {line:?}: {}",
            b.run.stdout
        );
    }
    let disk = &v["disk_reading_rules"];
    assert!(
        disk["delete-critical"]["rows"].as_u64().unwrap() >= 1,
        "{disk}"
    );
    assert!(disk.get("parse-error").is_none(), "{disk}");
    assert!(
        b.run.stdout.lines().any(|l| l
            .starts_with("rules that read the disk (lower bounds where the cwd is gone): ")
            && l.contains("delete-critical")),
        "{}",
        b.run.stdout
    );
}

/// Every rule's own check is timed per shell, on every row it runs on.
#[test]
fn each_rule_reports_its_cost_per_shell() {
    let b = bench("rule-cost", &FULL, &[], &[]);
    b.assert_code(0);
    let v = b.report();
    let cost = &v["rule_cost_ms"];
    // Length rules and parse rules both run on every row of the fixture: 6 Bash, 4 PowerShell.
    for rule in ["too-long", "parse-error"] {
        for (shell, rows) in [("Bash", 6), ("PowerShell", 4)] {
            let c = &cost[rule][shell];
            assert_eq!(c["rows"], rows, "{rule} {shell}: {cost}");
            let (p50, p99) = (c["p50"].as_f64().unwrap(), c["p99"].as_f64().unwrap());
            assert!(p50 >= 0.0 && p99 >= p50, "{rule} {shell}: {c}");
        }
    }
    assert!(
        b.run
            .stdout
            .lines()
            .any(|l| l.starts_with("rule cost parse-error Bash: 6 rows, p50 ")),
        "{}",
        b.run.stdout
    );
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    let n = v.len();
    (v[(n - 1) / 2] + v[n / 2]) / 2.0
}

#[test]
fn the_latency_is_the_median_of_the_passes() {
    let b = bench("passes", &FULL, &["--passes", "3"], &[]);
    b.assert_code(0);
    let v = b.report();
    assert_eq!(v["passes"], 3, "{v}");
    for shell in ["Bash", "PowerShell"] {
        let l = &v["latency_ms"][shell];
        for p in ["p50", "p99"] {
            let per: Vec<f64> = l[format!("{p}_per_pass")]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_f64().unwrap())
                .collect();
            assert_eq!(per.len(), 3, "{l}");
            assert_eq!(l[p].as_f64().unwrap(), median(per), "{shell} {p}: {l}");
        }
    }
    bench("passes-0", &FULL, &["--passes", "0"], &[]).assert_fail("--passes must be at least 1");
}

#[test]
fn a_config_file_sets_what_the_bench_measures() {
    let dir = scratch("config");
    let cfg = dir.join("shellwise.toml");
    std::fs::write(&cfg, "[levels]\nparse-error = \"warn\"\n").unwrap();
    let cfg = cfg.display().to_string();
    let b = bench_in(dir.clone(), &FULL, &["--config", cfg.as_str()], &[]);
    b.assert_code(0);
    let v = b.report();
    // The three denied non-destructive ok rows of the default run (one per line) are warn now.
    assert_eq!(count(&v, "meter_1"), (0, 0, 0), "{v}");
    assert_eq!(count(&v, "parity"), (0, 0, 0), "{v}");
    assert_eq!(count(&v, "refused_by_real_parser"), (0, 0, 0), "{v}");
    assert_eq!(v["config"], cfg.as_str(), "{v}");
    assert!(
        b.run.stdout.lines().any(|l| l == format!("config: {cfg}")),
        "{}",
        b.run.stdout
    );
    // A config the bench cannot load measures nothing.
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "fixture_no_such_key = 1\n").unwrap();
    let bad = bad.display().to_string();
    bench_in(
        scratch("config-bad"),
        &FULL,
        &["--config", bad.as_str()],
        &[],
    )
    .assert_fail("the config did not load");
    let gone = dir.join("gone.toml").display().to_string();
    bench_in(
        scratch("config-gone"),
        &FULL,
        &["--config", gone.as_str()],
        &[],
    )
    .assert_fail("the config did not load");
}

/// Parity exceptions are keyed by baseline guard rule, shape class and label: an exception for the
/// `ok` rows of a rule does not explain its `denied-hook` rows.
#[test]
fn parity_exceptions_are_keyed_by_shape_and_label() {
    let dir = scratch("parity-keys");
    let ex = dir.join("exceptions.toml");
    std::fs::write(
        &ex,
        "[[exception]]\nbaseline_guard = \"bash-too-long\"\nshape = \"mapped-silent\"\nlabel = \"ok\"\nexpected = 1\nwhy = \"fixture: the wrong label\"\n",
    )
    .unwrap();
    let ex = ex.display().to_string();
    let b = bench_in(dir, &FULL, &["--parity-exceptions", ex.as_str()], &[]);
    b.assert_code(0);
    let p = &b.report()["parity_per_rule"]["bash-too-long"];
    assert_eq!(p["unexplained"], 1, "{p}");
    assert_eq!(p["excepted_over_allows"], 1, "{p}");
    let keys = p["keys"].as_array().unwrap();
    let key = |label: &str| keys.iter().find(|k| k["label"] == label).cloned().unwrap();
    let hook = key("denied-hook");
    assert_eq!(
        (
            hook["shape"].as_str(),
            hook["allows"].as_u64(),
            hook["expected"].as_u64(),
            hook["unexplained"].as_u64()
        ),
        (Some("mapped-silent"), Some(1), Some(0), Some(1)),
        "{p}"
    );
    let ok = key("ok");
    assert_eq!(
        (
            ok["allows"].as_u64(),
            ok["expected"].as_u64(),
            ok["unexplained"].as_u64()
        ),
        (Some(0), Some(1), Some(0)),
        "{p}"
    );
    assert!(
        b.run.stdout.lines().any(|l| l == "parity bash-too-long mapped-silent denied-hook: shellwise allows 1, expected 0, unexplained 1"),
        "{}",
        b.run.stdout
    );
}

/// A row whose mapped rule still names it below break is the `mapped-warn` shape.
#[test]
fn a_mapped_rule_at_warn_is_its_own_shape() {
    let dir = scratch("parity-warn");
    // Fixture row 8's shape: an open `(` is a parse error below break.
    let files = written(
        &dir,
        &[(
            row("f000000000d1", "PowerShell", "Get-Date (", None, false),
            &["bash-unterminated-quote"],
        )],
    );
    // parse-error fires on both shells: widen the fixture's entry, or the run fails on runs_on.
    let map = std::fs::read_to_string(fixture("rule_map.toml"))
        .unwrap()
        .replace(
            "bash-unterminated-quote = { tools = [\"Bash\"]",
            "bash-unterminated-quote = { tools = [\"Bash\", \"PowerShell\"]",
        );
    let wide = dir.join("wide.toml");
    std::fs::write(&wide, map).unwrap();
    let wide = wide.display().to_string();
    let inputs = Inputs {
        rule_map: Some(&wide),
        ..inputs(&files, None)
    };
    let b = bench_in(dir, &inputs, &[], &[]);
    b.assert_code(0);
    let p = &b.report()["parity_per_rule"]["bash-unterminated-quote"];
    let keys = p["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "{p}");
    assert_eq!(
        (keys[0]["shape"].as_str(), keys[0]["allows"].as_u64()),
        (Some("mapped-warn"), Some(1)),
        "{p}"
    );
}

#[test]
fn a_parity_exception_file_that_cannot_be_read_as_keys_fails() {
    let dir = scratch("parity-bad");
    for (name, body, fail) in [
        (
            "shape",
            "baseline_guard = \"bash-too-long\"\nshape = \"fixture-shape\"\nlabel = \"ok\"\nexpected = 1\nwhy = \"x\"\n",
            "shape fixture-shape is not one of",
        ),
        (
            "label",
            "baseline_guard = \"bash-too-long\"\nshape = \"mapped-silent\"\nlabel = \"fixture\"\nexpected = 1\nwhy = \"x\"\n",
            "label fixture is not one of",
        ),
        (
            "unmapped",
            "baseline_guard = \"fixture-unknown-id\"\nshape = \"mapped-silent\"\nlabel = \"ok\"\nexpected = 1\nwhy = \"x\"\n",
            "names fixture-unknown-id, which the map does not",
        ),
        (
            "zero",
            "baseline_guard = \"bash-too-long\"\nshape = \"mapped-silent\"\nlabel = \"ok\"\nexpected = 0\nwhy = \"x\"\n",
            "an expected count above 0",
        ),
        (
            "no-why",
            "baseline_guard = \"bash-too-long\"\nshape = \"mapped-silent\"\nlabel = \"ok\"\nexpected = 1\nwhy = \"\"\n",
            "a why",
        ),
    ] {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, format!("[[exception]]\n{body}")).unwrap();
        let path = path.display().to_string();
        bench_in(
            scratch(&format!("parity-bad-{name}")),
            &FULL,
            &["--parity-exceptions", path.as_str()],
            &[],
        )
        .assert_fail(fail);
    }
    let twice = dir.join("twice.toml");
    let one = "[[exception]]\nbaseline_guard = \"bash-too-long\"\nshape = \"mapped-silent\"\nlabel = \"ok\"\nexpected = 1\nwhy = \"x\"\n";
    std::fs::write(&twice, format!("{one}{one}")).unwrap();
    let twice = twice.display().to_string();
    bench_in(
        scratch("parity-bad-twice"),
        &FULL,
        &["--parity-exceptions", twice.as_str()],
        &[],
    )
    .assert_fail("bash-too-long mapped-silent ok is listed twice");
    let gone = dir.join("gone.toml").display().to_string();
    bench_in(
        scratch("parity-bad-gone"),
        &FULL,
        &["--parity-exceptions", gone.as_str()],
        &[],
    )
    .assert_fail("cannot read");
}

/// Meter 2 splits by the line each row would count on and by whether a delete or git rule denies
/// it.
#[test]
fn meter_2_splits_by_line_and_by_rule_family() {
    let dir = scratch("meter2");
    let dq = char::from(0x22);
    let files = written(
        &dir,
        &[
            // Deleted through an empty expansion: a delete rule denies it, no other line takes it.
            (
                row(
                    "f000000000e1",
                    "Bash",
                    "rm -rf $FIXTURE_UNSET/*",
                    None,
                    true,
                ),
                &[],
            ),
            // Fixture row 6's shape twice: the real parser refuses one, the baseline guard denies the other.
            (
                row(
                    "f000000000e2",
                    "Bash",
                    &format!("rm -rf {dq}fixture-dir"),
                    None,
                    true,
                ),
                &[],
            ),
            (
                row(
                    "f000000000e3",
                    "Bash",
                    &format!("rm -rf {dq}fixture-two"),
                    None,
                    true,
                ),
                &["bash-unterminated-quote"],
            ),
        ],
    );
    let real = dir.join("real.tsv");
    std::fs::write(&real, "id\trefused\terror_id\nf000000000e2\tyes\tunexpected EOF\nf000000000e3\tno\t\nf000000000e1\tno\t\n").unwrap();
    let real = real.display().to_string();
    let b = bench_in(dir, &inputs(&files, Some(&real)), &[], &[]);
    b.assert_code(0);
    let v = b.report();
    let m = &v["meter_2"];
    assert_eq!(count(&v, "meter_2"), (3, 3, 0), "{m}");
    assert_eq!(count(&m["by_line"], "refused"), (1, 1, 0), "{m}");
    assert_eq!(count(&m["by_line"], "parity"), (1, 1, 0), "{m}");
    assert_eq!(count(&m["by_line"], "own_line"), (0, 0, 0), "{m}");
    assert_eq!(count(&m["by_line"], "meter_1"), (1, 1, 0), "{m}");
    assert_eq!(count(&m["by_family"], "delete_git"), (1, 1, 0), "{m}");
    assert_eq!(count(&m["by_family"], "other"), (2, 2, 0), "{m}");
    for line in [
        "meter 2 by line: refused 1, parity 1, own line 0, meter 1 1",
        "meter 2 by family: delete/git 1, other 2",
    ] {
        assert!(
            b.run.stdout.lines().any(|l| l == line),
            "no {line:?}: {}",
            b.run.stdout
        );
    }
}

/// `[runs_on]` in the rule map says where each mapped rule can fire; the known slice trusts it,
/// so a map key without an entry, or a rule that fires outside its entry on a row the baseline
/// guard denies with that id, fails the run.
#[test]
fn the_runs_on_table_covers_every_mapped_rule_and_where_it_fires() {
    let dir = scratch("runs-on");
    let map = std::fs::read_to_string(fixture("rule_map.toml")).unwrap();
    let narrowed = dir.join("narrowed.toml");
    let entry = "bash-unterminated-quote = { tools = [\"Bash\"], os = [\"Windows\", \"Linux\"], why = \"parse-error: every shell and OS\" }";
    assert!(map.contains(entry), "{map}");
    std::fs::write(
        &narrowed,
        map.replace(entry, "bash-unterminated-quote = { tools = [\"Bash\"], os = [\"Linux\"], why = \"fixture: too narrow\" }"),
    )
    .unwrap();
    let narrowed = narrowed.display().to_string();
    let inputs = Inputs {
        rule_map: Some(&narrowed),
        ..FULL
    };
    bench_in(dir.clone(), &inputs, &[], &[])
        .assert_fail("bash-unterminated-quote (parse-error) fires on 1 Bash rows on Windows outside its runs_on entry");
    // The full set counts too: row 4 with the id in `full` only.
    let base = std::fs::read_to_string(fixture("baseline.jsonl")).unwrap();
    let row4 = "{\"id\": \"f00000000004\", \"full\": [\"bash-unterminated-quote\"], \"installed\": [\"bash-unterminated-quote\"]}";
    assert!(base.contains(row4), "{base}");
    let full_only = dir.join("full_only.jsonl");
    std::fs::write(
        &full_only,
        base.replace(row4, "{\"id\": \"f00000000004\", \"full\": [\"bash-unterminated-quote\"], \"installed\": []}"),
    )
    .unwrap();
    let full_only = full_only.display().to_string();
    let inputs = Inputs {
        rule_map: Some(&narrowed),
        baseline: &full_only,
        ..FULL
    };
    bench_in(scratch("runs-on-full"), &inputs, &[], &[])
        .assert_fail("bash-unterminated-quote (parse-error) fires on 1 Bash rows on Windows outside its runs_on entry");
    let missing = dir.join("missing.toml");
    std::fs::write(&missing, map.replace(entry, "")).unwrap();
    let missing = missing.display().to_string();
    let inputs = Inputs {
        rule_map: Some(&missing),
        ..FULL
    };
    bench_in(scratch("runs-on-missing"), &inputs, &[], &[])
        .assert_fail("no runs_on entry for bash-unterminated-quote");
    let extra = "fixture-extra = { tools = [\"Bash\"], os = [\"Linux\"], why = \"fixture\" }";
    let wrong_tool = entry.replace("[\"Bash\"]", "[\"fixture-shell\"]");
    let wrong_os = entry.replace("\"Windows\", \"Linux\"", "\"fixture-os\"");
    let no_why = entry.replace("parse-error: every shell and OS", "");
    for (name, text, fail) in [
        (
            "extra",
            format!("{map}\n{extra}\n"),
            "runs_on names fixture-extra, which the map does not",
        ),
        (
            "tool",
            map.replace(entry, &wrong_tool),
            "runs_on bash-unterminated-quote needs tools from",
        ),
        (
            "os",
            map.replace(entry, &wrong_os),
            "runs_on bash-unterminated-quote needs tools from",
        ),
        (
            "why",
            map.replace(entry, &no_why),
            "runs_on bash-unterminated-quote needs tools from",
        ),
    ] {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, text).unwrap();
        let path = path.display().to_string();
        let inputs = Inputs {
            rule_map: Some(&path),
            ..FULL
        };
        bench_in(scratch(&format!("runs-on-{name}")), &inputs, &[], &[]).assert_fail(fail);
    }
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
