//! `shellwise lint <file>` (`src/lint_file.rs`) and the length rules of `src/rules/inline_length.rs`
//! (`inline-script-too-long` and the hosts' `too-long`), through `analyse` and the real parsers.
//!
//! The fixtures in `tests/lint_fixture/` are text files. Files that hold bytes a text editor would
//! not keep (a byte-order mark, invalid UTF-8, UTF-16) and files of an exact size are written by
//! each test into its own folder. Over-long commands are generated: their rows would not be
//! readable in a case file. The line thresholds also have rows in `tests/cases/inline_length.toml`.

mod common;

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Instant;

use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::{Finding, Level, Span, Verdict};
use shellwise::lint_file::{self, Refusal, Report};
use shellwise::{AnalyseInput, BashProfile, Deadline, MAX_READ_BYTES, Origin, Os, Shell, analyse};

// --- helpers ---

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/lint_fixture")
        .join(name)
}

/// A fresh folder of this test's own under the target's temp dir.
fn folder(tag: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("lint_file_{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn lint(path: &Path) -> Result<Report, Refusal> {
    lint_file::lint(
        path,
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
    )
}

fn ids(r: &Report) -> Vec<&'static str> {
    r.findings.iter().map(|l| l.finding.rule).collect()
}

fn pwsh() -> Shell {
    Shell::Pwsh
}

fn bash() -> Shell {
    Shell::Bash(BashProfile::Posix)
}

/// The verdict `analyse` gives a command line.
fn check_with(shell: Shell, os: Os, text: &str, cfg: &Config) -> Verdict {
    let input = AnalyseInput {
        bytes: text.as_bytes(),
        shell,
        os,
        cwd: None,
        env: EnvView::new(),
        origin: Origin::CommandLine,
    };
    analyse(&input, cfg, &Deadline::new(Instant::now(), 8000))
}

fn check(shell: Shell, os: Os, text: &str) -> Verdict {
    check_with(shell, os, text, &Config::default())
}

fn rules_of(v: &Verdict) -> Vec<&'static str> {
    v.findings.iter().map(|f| f.rule).collect()
}

/// `Write-Output '<a…>'` of exactly `len` characters.
fn pwsh_text(len: usize) -> String {
    let text = format!("Write-Output '{}'", "a".repeat(len - 15));
    assert_eq!(text.chars().count(), len);
    text
}

/// `echo <a…>` of exactly `len` characters.
fn bash_text(len: usize) -> String {
    let text = format!("echo {}", "a".repeat(len - 5));
    assert_eq!(text.chars().count(), len);
    text
}

fn lines_of(line: &str, n: usize) -> String {
    vec![line; n].join("\n")
}

fn utf16_units(text: &str) -> usize {
    text.encode_utf16().count()
}

// --- lint <file> ---

#[test]
fn a_clean_file_lints_ok_with_exit_0() {
    for name in ["ok.sh", "ok.ps1"] {
        let path = fixture(name);
        let report = lint(&path).unwrap();
        assert!(report.findings.is_empty(), "{name}: {:?}", ids(&report));
        assert_eq!(report.exit_code(), 0, "{name}");
        assert_eq!(report.render(&path), format!("{}: ok\n", path.display()));
    }
}

#[test]
fn an_unclosed_quote_in_a_file_is_break_at_its_line_and_column() {
    let path = fixture("bad.sh");
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["parse-error"]);
    assert_eq!(report.level, Level::Break);
    assert_eq!(report.exit_code(), 1);
    let at = &report.findings[0];
    assert_eq!((at.line, at.column), (1, 6));
    let text = report.render(&path);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    let head = format!("{}:1:6: break parse-error: ", path.display());
    assert!(lines[0].starts_with(&head), "{text}");
    assert!(lines[1].starts_with("  Fix: close the ' opened at column 6"), "{text}");
}

#[test]
fn a_variable_followed_by_a_colon_in_a_ps1_file_is_ps_var_colon() {
    let path = fixture("bad.ps1");
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["ps-var-colon"]);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.findings[0].line, 2);
    // The braced twin is clean.
    assert!(lint(&fixture("ok.ps1")).unwrap().findings.is_empty());
}

#[test]
fn a_line_and_column_count_from_1_in_characters() {
    // Two lines; the quote opens after a two-byte character on the second.
    let o = char::from_u32(0xF3).unwrap();
    let dir = folder("position");
    let path = dir.join("pos.sh");
    std::fs::write(&path, format!("echo ok\necho {o}'abc\n")).unwrap();
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["parse-error"]);
    assert_eq!((report.findings[0].line, report.findings[0].column), (2, 7));
}

#[test]
fn a_utf8_byte_order_mark_is_accepted_and_is_not_counted() {
    let dir = folder("bom");
    let mut bad = vec![0xEF, 0xBB, 0xBF];
    bad.extend_from_slice(&std::fs::read(fixture("bad.sh")).unwrap());
    let path = dir.join("bom_bad.sh");
    std::fs::write(&path, &bad).unwrap();
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["parse-error"]);
    assert_eq!((report.findings[0].line, report.findings[0].column), (1, 6));

    let mut ok = vec![0xEF, 0xBB, 0xBF];
    ok.extend_from_slice(&std::fs::read(fixture("ok.sh")).unwrap());
    let path = dir.join("bom_ok.sh");
    std::fs::write(&path, &ok).unwrap();
    assert!(lint(&path).unwrap().findings.is_empty());
}

#[test]
fn a_name_that_is_not_ps1_sh_or_bash_is_refused_with_exit_64() {
    let dir = folder("dialect");
    for name in ["x.txt", "noext", "ok.sh.txt", "script"] {
        let path = dir.join(name);
        std::fs::write(&path, "echo hi\n").unwrap();
        let refusal = lint(&path).unwrap_err();
        assert!(matches!(refusal, Refusal::Dialect), "{name}: {refusal:?}");
        assert_eq!(refusal.exit_code(), 64, "{name}");
    }
    // The fixture itself, and the three accepted names in any case.
    assert!(matches!(
        lint(&fixture("x.txt")).unwrap_err(),
        Refusal::Dialect
    ));
    for name in ["UP.SH", "Mixed.Ps1", "tool.bash"] {
        let path = dir.join(name);
        std::fs::write(&path, "Get-Date\n").unwrap();
        // `Get-Date` is a valid line in either dialect only as far as the parser goes: it must
        // not be refused for its name.
        assert!(!matches!(lint(&path), Err(Refusal::Dialect)), "{name}");
    }
}

#[test]
fn a_file_that_is_not_utf8_is_refused_with_its_reason() {
    let dir = folder("utf8");
    let path = dir.join("bad_utf8.sh");
    std::fs::write(&path, b"echo \xFF\n").unwrap();
    let refusal = lint(&path).unwrap_err();
    assert!(matches!(refusal, Refusal::NotUtf8(5)), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 64);
    let text = refusal.render(&path);
    assert!(text.contains("not valid UTF-8"), "{text}");
    assert!(text.contains("offset 5"), "{text}");

    // Valid UTF-8 outside ASCII is not refused: the check is strict, not an ASCII filter.
    let word: String = [0x7A, 0x142, 0x107]
        .iter()
        .map(|&c| char::from_u32(c).unwrap())
        .collect();
    let path = dir.join("good_utf8.sh");
    std::fs::write(&path, format!("echo {word}\n")).unwrap();
    assert!(lint(&path).unwrap().findings.is_empty());
}

#[test]
fn a_utf16_file_is_refused_by_its_byte_order_mark() {
    let dir = folder("utf16");
    let mut bytes = vec![0xFF, 0xFE];
    for unit in "echo hi\n".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let path = dir.join("wide.ps1");
    std::fs::write(&path, &bytes).unwrap();
    let refusal = lint(&path).unwrap_err();
    assert!(matches!(refusal, Refusal::Utf16), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 64);
    assert!(refusal.render(&path).contains("UTF-16"));
}

#[test]
fn a_file_over_the_read_cap_is_refused_and_one_at_the_cap_is_read() {
    let dir = folder("cap");
    let at_cap = dir.join("at_cap.sh");
    std::fs::write(&at_cap, vec![b'#'; MAX_READ_BYTES]).unwrap();
    let report = lint(&at_cap).expect("a file of exactly MAX_READ_BYTES is read");
    // Over the analysis cap, so the analysis is incomplete: a warn, which does not fail the file.
    assert_eq!(report.exit_code(), 0);

    let over = dir.join("over.sh");
    std::fs::write(&over, vec![b'#'; MAX_READ_BYTES + 1]).unwrap();
    let refusal = lint(&over).unwrap_err();
    assert!(matches!(refusal, Refusal::TooBig), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 64);
}

#[test]
fn a_missing_file_is_unreadable_with_exit_74() {
    let path = folder("missing").join("nope.sh");
    let refusal = lint(&path).unwrap_err();
    assert!(matches!(refusal, Refusal::Unreadable(_)), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 74);
}

#[test]
fn a_long_script_is_a_finding_as_a_command_line_and_clean_as_a_file() {
    let dir = folder("scope");
    let cases = [
        ("long.sh", bash(), lines_of("echo hi", 200)),
        ("long.ps1", pwsh(), lines_of("Get-Date", 120)),
    ];
    for (name, shell, text) in cases {
        let line = check(shell, Os::Posix, &text);
        assert_eq!(rules_of(&line), ["inline-script-too-long"], "{name} as a command");
        let path = dir.join(name);
        std::fs::write(&path, &text).unwrap();
        let report = lint(&path).unwrap();
        assert!(report.findings.is_empty(), "{name} as a file: {:?}", ids(&report));
    }
}

#[test]
fn a_10_kb_sh_with_a_doubled_backslash_lints_clean() {
    // Git Bash collapses `\\` in a Bash tool command, so the backslash rule is a command-line
    // rule: in a file bash reads the text itself.
    let backslash = '\\';
    let mut text = format!("printf 'a{backslash}{backslash}b'\n");
    while text.len() < 10_000 {
        text.push_str(&format!("echo {}\n", "x".repeat(95)));
    }
    let dir = folder("backslash");
    let path = dir.join("printf.sh");
    std::fs::write(&path, &text).unwrap();
    let report = lint(&path).unwrap();
    assert!(report.findings.is_empty(), "{:?}", ids(&report));
    assert_eq!(report.exit_code(), 0);
    // The same text as a command is over the inline limit: the file's silence is the scope.
    let line = check(bash(), Os::Posix, &text);
    assert!(rules_of(&line).contains(&"inline-script-too-long"));
}

#[test]
fn an_external_linter_adds_findings_sorted_and_deduplicated() {
    let dir = folder("external");
    let path = dir.join("two.sh");
    std::fs::write(&path, "echo ok\necho 'abc\n").unwrap();
    let saw_text = Cell::new(false);
    let external = |text: &str, shell: Shell| -> Vec<Finding> {
        saw_text.set(text == "echo ok\necho 'abc\n" && shell == Shell::Bash(shell_profile()));
        vec![
            // Line 1, a rule of its own: kept, and sorted before our line 2.
            Finding {
                rule: "ext-a",
                level: Level::Warn,
                message: "outside finding".to_string(),
                fix: None,
                span: Span { start: 0, end: 4 },
            },
            // Line 2, the rule we already report there: dropped.
            Finding {
                rule: "parse-error",
                level: Level::Break,
                message: "the same finding again".to_string(),
                fix: None,
                span: Span { start: 13, end: 14 },
            },
        ]
    };
    let cfg = Config::default();
    let report = lint_file::lint_with(&path, &cfg, &Deadline::new(Instant::now(), 8000), &external)
        .unwrap();
    assert!(saw_text.get(), "the external linter did not get the text and shell");
    assert_eq!(ids(&report), ["ext-a", "parse-error"]);
    assert!(!report.findings[1].finding.message.contains("again"));
    assert_eq!(report.exit_code(), 1);
}

/// The profile `lint` gives a `.sh` file on this host.
fn shell_profile() -> BashProfile {
    if Os::host() == Os::Windows {
        BashProfile::GitBash
    } else {
        BashProfile::Posix
    }
}

#[test]
fn a_panic_in_the_external_linter_keeps_ours_and_adds_a_warn() {
    let path = fixture("bad.sh");
    let external = |_: &str, _: Shell| -> Vec<Finding> { panic!("external linter failed") };
    let report = lint_file::lint_with(
        &path,
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
        &external,
    )
    .unwrap();
    let mut got = ids(&report);
    got.sort();
    assert_eq!(got, ["analysis-incomplete", "parse-error"]);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn lint_of_a_500_line_file_takes_under_50_ms_in_process() {
    let dir = folder("speed");
    let path = dir.join("long.sh");
    let text: String = (0..500).map(|i| format!("echo line {i}\n")).collect();
    std::fs::write(&path, text).unwrap();
    let mut times = Vec::new();
    for _ in 0..11 {
        let start = Instant::now();
        let report = lint(&path).unwrap();
        times.push(start.elapsed());
        assert!(report.findings.is_empty());
    }
    times.sort();
    let median = times[times.len() / 2];
    assert!(median.as_millis() < 50, "median {median:?}");
}

// --- the Fix line of a length rule routes to a file `lint` reads ---

#[test]
fn the_fix_line_names_a_file_that_lints_and_the_command_that_runs_it() {
    let dir = folder("route");
    let cases = [
        (bash(), lines_of("echo hi", 200), "bash", "script.sh"),
        (pwsh(), lines_of("Get-Date", 120), "pwsh -NoProfile -File", "script.ps1"),
    ];
    for (shell, text, runner, name) in cases {
        let cfg = Config {
            scratch_dir: Some(dir.clone()),
            ..Config::default()
        };
        let verdict = check_with(shell, Os::Posix, &text, &cfg);
        assert_eq!(rules_of(&verdict), ["inline-script-too-long"], "{name}");
        let fix = verdict.findings[0].fix_line().unwrap();
        let file = fix
            .split("write the command to ")
            .nth(1)
            .and_then(|s| s.split(" with the Write tool").next())
            .unwrap_or_else(|| panic!("no file in {fix}"))
            .trim_matches('"');
        assert!(file.contains("lint_file_route"), "{fix}");
        assert!(file.ends_with(name), "{fix}");
        assert!(fix.contains(&format!("run shellwise lint {file},")), "{fix}");
        assert!(fix.ends_with(&format!("then run {runner} {file}")), "{fix}");
        // Follow the line: write the text to the file it names, and lint that file.
        std::fs::write(file, &text).unwrap();
        let report = lint(Path::new(file)).unwrap();
        assert!(report.findings.is_empty(), "{name}: {:?}", ids(&report));
    }
}

#[test]
fn the_fix_line_quotes_a_scratch_path_with_a_space_and_uses_forward_slashes() {
    let cfg = Config {
        scratch_dir: Some(PathBuf::from("C:\\with space\\scratch")),
        ..Config::default()
    };
    let verdict = check_with(bash(), Os::Posix, &lines_of("echo hi", 151), &cfg);
    let fix = verdict.findings[0].fix_line().unwrap();
    let file = "\"C:/with space/scratch/script.sh\"";
    assert_eq!(fix.matches(file).count(), 3, "{fix}");
}

#[test]
fn the_fix_line_runs_the_runner_of_the_shell() {
    let verdict = check(Shell::Powershell5, Os::Posix, &lines_of("Get-Date", 81));
    let fix = verdict.findings[0].fix_line().unwrap();
    assert!(fix.contains("then run powershell -NoProfile -File "), "{fix}");
    // With no scratch folder configured, the OS temp folder plus `shellwise`.
    let verdict = check(bash(), Os::Posix, &lines_of("echo hi", 151));
    let fix = verdict.findings[0].fix_line().unwrap();
    assert!(fix.contains("/shellwise/script.sh"), "{fix}");
}

// --- inline-script-too-long: the thresholds ---

#[test]
fn pwsh_fires_over_80_lines_or_6000_characters() {
    let at = |text: String| rules_of(&check(pwsh(), Os::Posix, &text));
    assert!(at(lines_of("Get-Date", 80)).is_empty());
    assert_eq!(at(lines_of("Get-Date", 81)), ["inline-script-too-long"]);
    assert!(at(pwsh_text(6000)).is_empty());
    assert_eq!(at(pwsh_text(6001)), ["inline-script-too-long"]);
    // Windows PowerShell 5.1 has the same threshold.
    let v5 = |text: String| rules_of(&check(Shell::Powershell5, Os::Posix, &text));
    assert!(v5(lines_of("Get-Date", 80)).is_empty());
    assert_eq!(v5(lines_of("Get-Date", 81)), ["inline-script-too-long"]);
}

#[test]
fn bash_fires_over_150_lines_or_6000_characters() {
    let at = |text: String| rules_of(&check(bash(), Os::Posix, &text));
    assert!(at(lines_of("echo hi", 150)).is_empty());
    assert_eq!(at(lines_of("echo hi", 151)), ["inline-script-too-long"]);
    assert!(at(bash_text(6000)).is_empty());
    assert_eq!(at(bash_text(6001)), ["inline-script-too-long"]);
}

#[test]
fn the_threshold_counts_characters_not_bytes() {
    // 3,001 two-byte characters are 6,002 bytes but 3,001 characters: not over 6,000.
    let o = char::from_u32(0xF3).unwrap();
    let text = format!("echo {}", o.to_string().repeat(3001));
    assert!(text.len() > 6000 && text.chars().count() < 6000);
    assert!(rules_of(&check(bash(), Os::Posix, &text)).is_empty());
}

#[test]
fn the_message_names_the_size_and_the_limit() {
    let v = check(pwsh(), Os::Posix, &lines_of("Get-Date", 81));
    let f = &v.findings[0];
    assert_eq!(f.level, Level::Break);
    assert!(f.message.contains("81 lines"), "{}", f.message);
    assert!(f.message.contains("80 lines"), "{}", f.message);
    assert_eq!(f.span.start, 0);
}

// --- too-long: the hosts' hard limits ---

#[test]
fn a_powershell_command_over_the_createprocess_limit_is_too_long_on_windows() {
    let at = |text: String, os: Os| check(pwsh(), os, &text);
    // At the limit it still runs: only the inline rule speaks (the text is over 6,000 characters).
    assert_eq!(rules_of(&at(pwsh_text(32767), Os::Windows)), ["inline-script-too-long"]);
    // One over: the command cannot start, and the inline finding steps aside.
    let v = at(pwsh_text(32768), Os::Windows);
    assert_eq!(rules_of(&v), ["too-long"]);
    assert_eq!(v.level, Level::Break);
    let fix = v.findings[0].fix_line().unwrap();
    assert!(fix.contains("shellwise lint"), "{fix}");
    assert!(fix.contains("script.ps1"), "{fix}");
    assert!(fix.contains("pwsh -NoProfile -File"), "{fix}");
    // Not on another OS.
    assert_eq!(rules_of(&at(pwsh_text(32768), Os::Posix)), ["inline-script-too-long"]);
}

#[test]
fn the_createprocess_limit_counts_utf16_units() {
    // `Write-Output '` + 16,376 emoji + `'` is 32,767 units but 16,391 characters and 65,519 bytes.
    let emoji = char::from_u32(0x1F600).unwrap().to_string();
    let at_limit = format!("Write-Output '{}'", emoji.repeat(16376));
    assert_eq!(utf16_units(&at_limit), 32767);
    assert_eq!(
        rules_of(&check(pwsh(), Os::Windows, &at_limit)),
        ["inline-script-too-long"]
    );
    let over = format!("Write-Output '{}a'", emoji.repeat(16376));
    assert_eq!(utf16_units(&over), 32768);
    assert_eq!(rules_of(&check(pwsh(), Os::Windows, &over)), ["too-long"]);
}

#[test]
fn a_cmd_command_line_over_8191_is_too_long_on_windows() {
    let cmd = |len: usize| format!("cmd /c echo {}", "a".repeat(len - 12));
    assert_eq!(cmd(8191).chars().count(), 8191);
    assert_eq!(
        rules_of(&check(pwsh(), Os::Windows, &cmd(8191))),
        ["inline-script-too-long"]
    );
    let v = check(pwsh(), Os::Windows, &cmd(8192));
    assert_eq!(rules_of(&v), ["too-long"]);
    // The limit follows the program: the same length for another program is only inline.
    assert_eq!(
        rules_of(&check(pwsh(), Os::Windows, &pwsh_text(8192))),
        ["inline-script-too-long"]
    );
    // And the OS: no `cmd` limit off Windows.
    assert_eq!(
        rules_of(&check(pwsh(), Os::Posix, &cmd(8192))),
        ["inline-script-too-long"]
    );
}

#[test]
fn a_git_bash_command_over_the_escaped_limit_is_too_long_once() {
    // Git Bash's own limit is Task 25's rule; the inline rule steps aside for it.
    let v = check(
        Shell::Bash(BashProfile::GitBash),
        Os::Windows,
        &bash_text(7795),
    );
    assert_eq!(rules_of(&v), ["too-long"]);
}

// --- the spawned binary ---

#[test]
fn the_lint_subcommand_exits_0_1_and_64() {
    let arg = |p: &Path| p.to_string_lossy().into_owned();

    let ok = fixture("ok.sh");
    let r = common::run(&["lint", &arg(&ok)], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{}: ok\n", ok.display()));

    let bad = fixture("bad.sh");
    let r = common::run(&["lint", &arg(&bad)], None, &[]);
    assert_eq!(r.code, 1, "{} {}", r.stdout, r.stderr);
    let head = format!("{}:1:6: break parse-error: ", bad.display());
    assert!(r.stdout.lines().next().unwrap().starts_with(&head), "{}", r.stdout);
    assert!(r.stdout.lines().nth(1).unwrap().starts_with("  Fix: "), "{}", r.stdout);

    let txt = fixture("x.txt");
    let r = common::run(&["lint", &arg(&txt)], None, &[]);
    assert_eq!(r.code, 64, "{} {}", r.stdout, r.stderr);
    assert!(!r.stderr.is_empty());

    let r = common::run(&["lint"], None, &[]);
    assert_eq!(r.code, 64, "{} {}", r.stdout, r.stderr);

    let dir = folder("cli_missing");
    let r = common::run(&["lint", &arg(&dir.join("nope.sh"))], None, &[]);
    assert_eq!(r.code, 74, "{} {}", r.stdout, r.stderr);
}

#[test]
fn the_lint_subcommand_lints_the_file_the_fix_line_names() {
    let dir = folder("cli_route");
    let cfg = Config {
        scratch_dir: Some(dir.clone()),
        ..Config::default()
    };
    let text = lines_of("echo hi", 200);
    let verdict = check_with(bash(), Os::Posix, &text, &cfg);
    let fix = verdict.findings[0].fix_line().unwrap();
    let file = fix
        .split("run shellwise lint ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim_matches('"')
        .to_string();
    std::fs::write(&file, &text).unwrap();
    let r = common::run(&["lint", &file], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
}
