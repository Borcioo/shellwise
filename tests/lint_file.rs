//! `shellwise lint <file>` (`src/lint_file.rs`, ShellCheck's checks in `src/shellcheck.rs`) and the
//! length rules `inline-script-too-long` (`src/rules/inline_length.rs`) and `too-long`'s cmd.exe
//! branch (`src/rules/length.rs`), through `analyse`, the real parsers and the spawned binary.
//!
//! The fixtures in `tests/lint_fixture/` are text files. Files that hold bytes a text editor would
//! not keep (a byte-order mark, invalid UTF-8, UTF-16) and files of an exact size are written by
//! each test into its own folder. Over-long commands are generated: their rows would not be
//! readable in a case file. The line thresholds and the cmd.exe rows are in
//! `tests/cases/inline_length.toml`.

mod case_loader;
mod common;

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Instant;

use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::{Finding, Level, Span, Verdict};
use shellwise::lint_file::{self, Refusal, Report};
use shellwise::{
    ANALYSIS_INCOMPLETE, AnalyseInput, BashProfile, Deadline, MAX_INPUT_BYTES, MAX_READ_BYTES,
    Origin, Os, Shell, analyse,
};

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
        problem: None,
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

/// The file a length rule's Fix line names, and the text after `then run `.
fn fix_parts(fix: &str) -> (String, String) {
    let rest = fix
        .strip_prefix("Fix: write the command to ")
        .unwrap_or_else(|| panic!("{fix}"));
    let (file, rest) = rest
        .split_once(" with the Write tool, run shellwise lint ")
        .unwrap();
    let (linted, run) = rest.split_once(", then run ").unwrap();
    let quoted = if file.contains(' ') {
        format!("'{file}'")
    } else {
        file.to_string()
    };
    assert_eq!(linted, quoted, "{fix}");
    assert!(run.ends_with(&format!(" {quoted}")), "{fix}");
    (file.to_string(), run.to_string())
}

// --- lint <file>: the read path ---

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
    assert!(
        lines[1].starts_with("  Fix: close the ' opened at column 6"),
        "{text}"
    );
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

/// D4: the alias-shadow shape is a finding of its own in a script file too.
#[test]
fn a_function_an_alias_outranks_is_a_warn_in_a_ps1_file() {
    let d = folder("alias_shadow");
    let path = d.join("helpers.ps1");
    std::fs::write(
        &path,
        "function md { New-Item -ItemType Directory -Path $args[0] }\nmd out\n",
    )
    .unwrap();
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["ps-alias-shadow"]);
    assert_eq!(report.level, Level::Warn);
    assert_eq!(report.exit_code(), 0);
}

/// D2: `stale-write-var` reads command lines only. In a script the variable a `New-Variable` line
/// binds is there for the next line: the binary passes the file.
#[test]
fn a_ps1_that_binds_a_variable_with_new_variable_then_writes_it_passes() {
    let d = folder("new_variable");
    let path = d.join("write.ps1");
    std::fs::write(&path, "New-Variable v 1\nSet-Content a.txt $v\n").unwrap();
    let r = common::run(&["lint", &path.to_string_lossy()], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{}: ok\n", path.display()));
}

/// A wait loop with no bound hangs a script as it hangs a command line: break in `lint` too.
#[test]
fn an_unbounded_wait_loop_in_a_sh_file_is_a_break() {
    let d = folder("wait_loop");
    let path = d.join("wait.sh");
    std::fs::write(
        &path,
        "#!/bin/bash\nuntil grep -q done run.log; do\n  sleep 15\ndone\n",
    )
    .unwrap();
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["wait-loop-unbounded"]);
    assert_eq!(report.exit_code(), 1);
    // The bounded twin is clean.
    let ok = d.join("bounded.sh");
    std::fs::write(
        &ok,
        "#!/bin/bash\nfor i in $(seq 1 40); do\n  grep -q done run.log && break\n  sleep 15\ndone\n",
    )
    .unwrap();
    assert!(lint(&ok).unwrap().findings.is_empty());
}

/// D6: Git Bash drops the CR of a CRLF script and runs it (Linux bash reads `$'\r'`). In the Git
/// Bash profile (a Windows host) a CRLF `.sh` gets one warn, and the shellwise rules and the
/// external linter read its LF twin.
#[cfg(windows)]
#[test]
fn a_crlf_sh_is_one_warn_in_the_git_bash_profile() {
    let d = folder("crlf");
    let path = d.join("build.sh");
    std::fs::write(
        &path,
        "#!/bin/bash\r\nif true; then\r\n  echo \"$1 'x\"\r\nfi\r\n",
    )
    .unwrap();
    let saw_cr = Cell::new(false);
    let report = lint_file::lint_with(
        &path,
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
        &|text, _| {
            saw_cr.set(text.contains('\r'));
            Vec::new()
        },
    )
    .unwrap();
    assert_eq!(ids(&report), ["bash-crlf"], "{report:?}");
    assert_eq!(report.level, Level::Warn);
    assert_eq!(report.findings[0].line, 1);
    assert!(!saw_cr.get(), "the external linter got the CRs");
    // Control: the LF twin is clean, and a CRLF .ps1 is no finding (PowerShell reads CRLF).
    let lf = d.join("lf.sh");
    std::fs::write(&lf, "#!/bin/bash\nif true; then\n  echo \"$1 'x\"\nfi\n").unwrap();
    assert!(lint(&lf).unwrap().findings.is_empty());
    let ps = d.join("crlf.ps1");
    std::fs::write(&ps, "Get-Date\r\nGet-Date\r\n").unwrap();
    assert!(lint(&ps).unwrap().findings.is_empty());
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

    // Only one mark is dropped: a second is text, which bash reads as part of a command name.
    let mut twice = vec![0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF];
    twice.extend_from_slice(b"echo 'abc\n");
    let path = dir.join("bom_twice.sh");
    std::fs::write(&path, &twice).unwrap();
    let report = lint(&path).unwrap();
    assert_eq!(ids(&report), ["parse-error"]);
    assert_eq!((report.findings[0].line, report.findings[0].column), (1, 7));
}

#[test]
fn a_name_that_is_not_ps1_sh_or_bash_is_refused_with_exit_64() {
    let dir = folder("dialect");
    for name in [
        "x.txt",
        "noext",
        "ok.sh.txt",
        "script",
        "x.ps",
        "x.bat",
        "x.psm1",
    ] {
        let path = dir.join(name);
        std::fs::write(&path, "echo hi\n").unwrap();
        let refusal = lint(&path).unwrap_err();
        assert!(matches!(refusal, Refusal::Dialect), "{name}: {refusal:?}");
        assert_eq!(refusal.exit_code(), 64, "{name}");
        assert!(
            refusal.render(&path).contains(".ps1, .sh or .bash"),
            "{name}"
        );
    }
    assert!(matches!(
        lint(&fixture("x.txt")).unwrap_err(),
        Refusal::Dialect
    ));
    // Each accepted name, in any case, picks its dialect: `$n:` is a finding in PowerShell only,
    // an unclosed quote in either.
    let pwsh_only = "echo \"$n: x\"\n";
    for (name, want) in [
        ("a.ps1", vec!["ps-var-colon"]),
        ("Mixed.Ps1", vec!["ps-var-colon"]),
        ("a.sh", vec![]),
        ("UP.SH", vec![]),
        ("tool.bash", vec![]),
        ("TOOL.BASH", vec![]),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, pwsh_only).unwrap();
        let report = lint(&path).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(ids(&report), want, "{name}");
    }
}

#[test]
fn a_file_that_is_not_utf8_is_refused_with_its_reason() {
    let dir = folder("utf8");
    let cases: [(&str, &[u8], usize); 4] = [
        ("byte_ff.sh", b"echo \xFF\n", 5),
        ("cp1250.ps1", b"Write-Output 'za\xBF\xF3\xB3\xE6'\n", 16),
        ("truncated.sh", b"echo \xC5", 5),
        // The offset counts from after the byte-order mark.
        ("bom_then_bad.sh", b"\xEF\xBB\xBFecho \xFF\n", 5),
    ];
    for (name, bytes, at) in cases {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        let refusal = lint(&path).unwrap_err();
        assert!(
            matches!(refusal, Refusal::NotUtf8(n) if n == at),
            "{name}: {refusal:?}"
        );
        assert_eq!(refusal.exit_code(), 64, "{name}");
        let text = refusal.render(&path);
        assert!(text.contains("not valid UTF-8"), "{text}");
        assert!(text.contains(&format!("offset {at}")), "{text}");
    }

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
    let wide = |bom: [u8; 2], big_endian: bool| {
        let mut bytes = bom.to_vec();
        for unit in "echo hi\n".encode_utf16() {
            let pair = if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            };
            bytes.extend_from_slice(&pair);
        }
        bytes
    };
    for (name, bytes) in [
        ("le.ps1", wide([0xFF, 0xFE], false)),
        ("be.sh", wide([0xFE, 0xFF], true)),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, &bytes).unwrap();
        let refusal = lint(&path).unwrap_err();
        assert!(matches!(refusal, Refusal::Utf16), "{name}: {refusal:?}");
        assert_eq!(refusal.exit_code(), 64);
        assert!(refusal.render(&path).contains("UTF-16"), "{name}");
    }
}

#[test]
fn a_file_over_the_read_cap_is_refused_and_one_at_the_cap_is_read() {
    let dir = folder("cap");
    let at_cap = dir.join("at_cap.sh");
    std::fs::write(&at_cap, vec![b'#'; MAX_READ_BYTES]).unwrap();
    let report = lint(&at_cap).expect("a file of exactly MAX_READ_BYTES is read");
    // Over the analysis cap: incomplete, a warn that does not fail the file and is never "ok".
    assert_eq!(ids(&report), [ANALYSIS_INCOMPLETE]);
    assert_eq!(report.level, Level::Warn);
    assert_eq!(report.exit_code(), 0);

    let over = dir.join("over.sh");
    std::fs::write(&over, vec![b'#'; MAX_READ_BYTES + 1]).unwrap();
    let refusal = lint(&over).unwrap_err();
    assert!(matches!(refusal, Refusal::TooBig), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 64);
    assert!(
        refusal
            .render(&over)
            .contains(&format!("over {MAX_READ_BYTES} bytes")),
        "{}",
        refusal.render(&over)
    );
}

#[test]
fn a_missing_file_is_unreadable_with_exit_74() {
    let path = folder("missing").join("nope.sh");
    let refusal = lint(&path).unwrap_err();
    assert!(matches!(refusal, Refusal::Unreadable(_)), "{refusal:?}");
    assert_eq!(refusal.exit_code(), 74);
    assert!(refusal.render(&path).contains("cannot read the file"));
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
        assert_eq!(
            rules_of(&line),
            ["inline-script-too-long"],
            "{name} as a command"
        );
        let path = dir.join(name);
        std::fs::write(&path, &text).unwrap();
        let report = lint(&path).unwrap();
        assert!(
            report.findings.is_empty(),
            "{name} as a file: {:?}",
            ids(&report)
        );
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
    // The same text as a Git Bash command is denied by the backslash rule.
    let line = check(Shell::Bash(BashProfile::GitBash), Os::Windows, &text);
    assert!(
        rules_of(&line).contains(&"bash-backslash-collapse"),
        "{:?}",
        rules_of(&line)
    );
    // And the binary, ShellCheck included, finds nothing either.
    let r = common::run(&["lint", &path.to_string_lossy()], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
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
    let report =
        lint_file::lint_with(&path, &cfg, &Deadline::new(Instant::now(), 8000), &external).unwrap();
    assert!(
        saw_text.get(),
        "the external linter did not get the text and shell"
    );
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
    let clean = lint_file::lint_with(
        &fixture("ok.sh"),
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
        &external,
    )
    .unwrap();
    assert_eq!(ids(&clean), ["analysis-incomplete"]);
    assert_eq!(clean.level, Level::Warn);
}

// --- the Fix line of a length rule routes to a file `lint` reads ---

#[test]
fn the_fix_line_names_a_new_file_that_lints_and_the_command_that_runs_it() {
    let dir = folder("route");
    let cfg = Config {
        scratch_dir: Some(dir.clone()),
        ..Config::default()
    };
    let cases = [
        (bash(), lines_of("echo hi", 200), "bash", ".sh"),
        (
            pwsh(),
            lines_of("Get-Date", 120),
            "pwsh -NoProfile -File",
            ".ps1",
        ),
        (
            Shell::Powershell5,
            lines_of("Get-Date", 81),
            "powershell -NoProfile -File",
            ".ps1",
        ),
    ];
    for (shell, text, runner, ext) in cases {
        let verdict = check_with(shell, Os::Posix, &text, &cfg);
        assert_eq!(rules_of(&verdict), ["inline-script-too-long"], "{runner}");
        let fix = verdict.findings[0].fix_line().unwrap();
        let (file, run) = fix_parts(&fix);
        let dir_text = dir.to_string_lossy().replace('\\', "/");
        let name = file
            .strip_prefix(&format!("{dir_text}/command-"))
            .unwrap_or_else(|| panic!("{fix}"));
        assert!(name.ends_with(ext) && !name.contains('/'), "{fix}");
        assert_eq!(run, format!("{runner} {file}"), "{fix}");
        // Follow the line: write the text to the file it names, and lint that file.
        std::fs::write(&file, &text).unwrap();
        let report = lint(Path::new(&file)).unwrap();
        assert!(report.findings.is_empty(), "{runner}: {:?}", ids(&report));
        // Ruling 109: a second call names another file.
        let again = check_with(shell, Os::Posix, &text, &cfg).findings[0]
            .fix_line()
            .unwrap();
        assert_ne!(fix_parts(&again).0, file);
    }
}

#[test]
fn the_fix_line_single_quotes_a_scratch_path_with_a_space_and_uses_forward_slashes() {
    let cfg = Config {
        scratch_dir: Some(PathBuf::from("C:\\with space\\scratch")),
        ..Config::default()
    };
    let verdict = check_with(pwsh(), Os::Posix, &lines_of("Get-Date", 81), &cfg);
    let fix = verdict.findings[0].fix_line().unwrap();
    let (file, _) = fix_parts(&fix);
    assert!(file.starts_with("C:/with space/scratch/command-"), "{fix}");
    assert_eq!(fix.matches(&format!("'{file}'")).count(), 2, "{fix}");
}

#[test]
fn without_a_scratch_folder_the_file_is_in_a_per_user_temp_folder() {
    let verdict = check(bash(), Os::Posix, &lines_of("echo hi", 101));
    let fix = verdict.findings[0].fix_line().unwrap();
    let (file, _) = fix_parts(&fix);
    let temp = std::env::temp_dir().to_string_lossy().replace('\\', "/");
    let rest = file
        .strip_prefix(temp.trim_end_matches('/'))
        .unwrap_or_else(|| panic!("{file} is not under {temp}"));
    let (folder, name) = rest.trim_start_matches('/').split_once('/').expect(&file);
    assert!(
        folder.starts_with("shellwise-") && folder.len() > "shellwise-".len(),
        "{file}"
    );
    assert!(
        name.starts_with("command-") && name.ends_with(".sh"),
        "{file}"
    );
}

/// `too-long` and `inline-script-too-long` print one routing text: the same sentence, for the same
/// shell, with only the file's unique name differing.
#[test]
fn both_length_rules_print_the_same_routing_text() {
    let cfg = Config {
        scratch_dir: Some(PathBuf::from("/work")),
        ..Config::default()
    };
    let gitbash = Shell::Bash(BashProfile::GitBash);
    let hard = check_with(gitbash, Os::Windows, &bash_text(7600), &cfg);
    let inline = check_with(gitbash, Os::Windows, &lines_of("echo hi", 101), &cfg);
    assert_eq!(rules_of(&hard), ["too-long"]);
    assert_eq!(rules_of(&inline), ["inline-script-too-long"]);
    let shape = |v: &Verdict| {
        let (file, run) = fix_parts(&v.findings[0].fix_line().unwrap());
        let name = file.rsplit('/').next().unwrap().to_string();
        (
            v.findings[0].fix_line().unwrap().replace(&name, "<name>"),
            run.replace(&name, "<name>"),
        )
    };
    assert_eq!(shape(&hard), shape(&inline));
    assert_eq!(shape(&hard).1, "bash /work/<name>");
}

// --- inline-script-too-long: the thresholds ---

#[test]
fn inline_length_rows() {
    let rows = case_loader::rows("inline_length.toml");
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("inline_length.toml: {} rows ran", rows.len());
}

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
    assert!(v5(pwsh_text(6000)).is_empty());
    assert_eq!(v5(pwsh_text(6001)), ["inline-script-too-long"]);
}

#[test]
fn bash_fires_over_100_lines_or_8000_characters() {
    let at = |text: String| rules_of(&check(bash(), Os::Posix, &text));
    assert!(at(lines_of("echo hi", 100)).is_empty());
    assert_eq!(at(lines_of("echo hi", 101)), ["inline-script-too-long"]);
    assert!(at(bash_text(8000)).is_empty());
    assert_eq!(at(bash_text(8001)), ["inline-script-too-long"]);
}

#[test]
fn the_threshold_counts_characters_not_bytes() {
    // 4,001 two-byte characters are 8,007 bytes but 4,006 characters: not over 8,000 (bash) and
    // over 6,000 bytes but not 6,000 characters (pwsh).
    let o = char::from_u32(0xF3).unwrap();
    let text = format!("echo {}", o.to_string().repeat(4001));
    assert!(text.len() > 8000 && text.chars().count() < 6000);
    assert!(rules_of(&check(bash(), Os::Posix, &text)).is_empty());
    assert!(rules_of(&check(pwsh(), Os::Posix, &text)).is_empty());
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

/// The marker downgrades break to ok elsewhere; on a length rule it changes nothing (F7).
#[test]
fn the_allow_marker_does_not_lower_the_length_rules() {
    let marked = format!("{}\n# shellwise: allow", lines_of("Get-Date", 81));
    let v = check(pwsh(), Os::Posix, &marked);
    assert_eq!(rules_of(&v), ["inline-script-too-long"]);
    assert_eq!(v.level, Level::Break);
}

// --- too-long: the hosts' hard limits ---

/// The PowerShell tool passes its text in an environment variable, not on the command line: a
/// 40,000-character script runs (probe: pwsh 7.7 with the tool's launcher ran 100,000). Only the
/// inline rule speaks.
#[test]
fn a_long_powershell_command_is_not_too_long() {
    let v = check(pwsh(), Os::Windows, &pwsh_text(40_000));
    assert_eq!(rules_of(&v), ["inline-script-too-long"]);
}

#[test]
fn a_cmd_command_line_over_the_limit_is_too_long_with_its_own_fix() {
    let cmd = |len: usize| {
        let text = format!("cmd /c echo {}", "a".repeat(len - 12));
        assert_eq!(text.chars().count(), len);
        text
    };
    let v = check(pwsh(), Os::Windows, &cmd(8166));
    assert_eq!(rules_of(&v), ["too-long"]);
    let f = &v.findings[0];
    assert!(f.message.contains("8192"), "{}", f.message);
    assert!(f.message.contains("8191"), "{}", f.message);
    let fix = f.fix_line().unwrap();
    // Routing the command to a script would not help: the script starts the same cmd line.
    assert!(!fix.contains("shellwise lint"), "{fix}");
    assert!(fix.contains("delete the leading cmd /c"), "{fix}");
    // Another program of the same length is only inline, and so is cmd off Windows.
    assert_eq!(
        rules_of(&check(pwsh(), Os::Windows, &pwsh_text(8166))),
        ["inline-script-too-long"]
    );
    assert_eq!(
        rules_of(&check(pwsh(), Os::Posix, &cmd(8166))),
        ["inline-script-too-long"]
    );
    // The limit counts UTF-16 units: 4,083 two-unit characters are 8,166 units, over it.
    let emoji = char::from_u32(0x1F600).unwrap().to_string();
    let wide = format!("cmd /c echo {}", emoji.repeat(4077));
    assert_eq!(wide.encode_utf16().count(), 8166);
    assert_eq!(rules_of(&check(pwsh(), Os::Windows, &wide)), ["too-long"]);
    let narrow = format!("cmd /c echo {}a", emoji.repeat(4076));
    assert_eq!(narrow.encode_utf16().count(), 8165);
    assert_ne!(rules_of(&check(pwsh(), Os::Windows, &narrow)), ["too-long"]);
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
    // A `cmd //c` line that long is Git Bash's finding, once.
    let long_cmd = format!("cmd //c echo {}", "a".repeat(8200));
    let v = check(Shell::Bash(BashProfile::GitBash), Os::Windows, &long_cmd);
    assert_eq!(rules_of(&v), ["too-long"]);
    assert!(
        v.findings[0].message.contains("Git Bash"),
        "{}",
        v.findings[0].message
    );
    // The cmd branch counts pwsh's launch (a quoted path in place of the word); Git Bash starts
    // cmd otherwise (measured: a typed `cmd //c echo a...` runs at 8168), so it is not applied
    // there even when the Git Bash limit is raised past it.
    let raised = Config {
        limits: shellwise::config::Limits {
            git_bash_command: 20_000,
        },
        ..Config::default()
    };
    let runs = format!("cmd //c echo {}", "a".repeat(8168 - 13));
    assert_eq!(runs.len(), 8168);
    let v = check_with(
        Shell::Bash(BashProfile::GitBash),
        Os::Windows,
        &runs,
        &raised,
    );
    assert!(!rules_of(&v).contains(&"too-long"), "{:?}", rules_of(&v));
}

// --- the spawned binary ---

#[test]
fn the_lint_subcommand_exits_0_1_64_and_74() {
    let arg = |p: &Path| p.to_string_lossy().into_owned();

    let ok = fixture("ok.sh");
    let r = common::run(&["lint", &arg(&ok)], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{}: ok\n", ok.display()));

    let bad = fixture("bad.sh");
    let r = common::run(&["lint", &arg(&bad)], None, &[]);
    assert_eq!(r.code, 1, "{} {}", r.stdout, r.stderr);
    let head = format!("{}:1:6: break parse-error: ", bad.display());
    let lines: Vec<&str> = r.stdout.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(&head))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    assert!(lines[at + 1].starts_with("  Fix: "), "{}", r.stdout);

    let bad_ps1 = fixture("bad.ps1");
    let r = common::run(&["lint", &arg(&bad_ps1)], None, &[]);
    assert_eq!(r.code, 1, "{} {}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains(":2:15: break ps-var-colon: "),
        "{}",
        r.stdout
    );

    let txt = fixture("x.txt");
    let r = common::run(&["lint", &arg(&txt)], None, &[]);
    assert_eq!(r.code, 64, "{} {}", r.stdout, r.stderr);
    assert!(r.stderr.contains(".ps1, .sh or .bash"), "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{}", r.stdout);

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
    let (file, _) = fix_parts(&verdict.findings[0].fix_line().unwrap());
    std::fs::write(&file, &text).unwrap();
    let r = common::run(&["lint", &file], None, &[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
}

// --- ShellCheck's checks, through the binary ---

/// `shellwise lint` of a file `name` holding `text`, in a folder of the test's own.
fn lint_cli(tag: &str, name: &str, text: &str) -> (PathBuf, common::Run) {
    let path = folder(tag).join(name);
    std::fs::write(&path, text).unwrap();
    let r = common::run(&["lint", &path.to_string_lossy()], None, &[]);
    (path, r)
}

/// `<line>:<col>: <level> <rule>` of each finding line, sorted.
fn places(path: &Path, r: &common::Run) -> Vec<String> {
    let prefix = format!("{}:", path.display());
    let mut out: Vec<String> = r
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix(&prefix))
        .filter_map(|rest| {
            let (line, rest) = rest.split_once(':')?;
            let (col, rest) = rest.split_once(": ")?;
            let (head, _) = rest.split_once(": ")?;
            Some(format!("{line}:{col}: {head}"))
        })
        .collect();
    out.sort();
    out
}

/// Real ShellCheck 0.11.0 on the same text (`shellcheck -f gcc`) puts SC2154 and SC2086 at 2:7 after
/// a tab, at 3:8 after a two-byte character and at 4:9 after two tabs: character columns.
#[test]
fn shellcheck_findings_print_at_the_columns_real_shellcheck_gives() {
    let o = char::from_u32(0xF3).unwrap();
    let text = format!("#!/bin/bash\n\techo $x\necho {o} $y\n\ta\techo $z\n");
    let (path, r) = lint_cli("sc_columns", "cols.sh", &text);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(
        places(&path, &r),
        [
            "2:7: warn SC2086",
            "2:7: warn SC2154",
            "3:8: warn SC2086",
            "3:8: warn SC2154",
            "4:9: warn SC2086",
            "4:9: warn SC2154"
        ],
        "{}",
        r.stdout
    );
}

/// Real ShellCheck 0.11.0 (`-f gcc`) gives each variable its own pair: two findings of one code on
/// one line are both kept.
#[test]
fn shellcheck_findings_of_one_code_on_one_line_are_all_printed() {
    let (path, r) = lint_cli("sc_same_line", "two.sh", "echo $a $b\n");
    assert_eq!(
        places(&path, &r),
        [
            "1:6: warn SC2086",
            "1:6: warn SC2154",
            "1:9: warn SC2086",
            "1:9: warn SC2154"
        ],
        "{}",
        r.stdout
    );
}

#[test]
fn a_shellcheck_error_and_a_warning_are_warn_and_pass_the_file() {
    // The delete guard's warn about the unread target sits beside ShellCheck's.
    let (path, r) = lint_cli("sc_levels", "var.sh", "rm $var\n");
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(
        places(&path, &r),
        [
            "1:1: warn dynamic-target",
            "1:4: warn SC2086",
            "1:4: warn SC2154"
        ],
        "{}",
        r.stdout
    );
    // `[[ ]]` needs spaces inside: SC1035 is an error, and bash still parses the line. ShellCheck
    // gives no one-step Fix line, so an error is warn (D5).
    let (path, r) = lint_cli(
        "sc_levels_error",
        "test.sh",
        "if [[$1 == x]]; then echo y; fi\n",
    );
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert!(
        places(&path, &r)
            .iter()
            .any(|p| p.contains(": warn SC1035")),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("parse-error"), "{}", r.stdout);
}

/// SC2164 (`cd` without `|| exit`) is left out by default; real ShellCheck reports it on this text.
#[test]
fn sc2164_is_left_out_of_a_linted_file() {
    let (path, r) = lint_cli("sc2164", "cd.sh", "cd /tmp\nls\n");
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{}: ok\n", path.display()));
}

/// With the dataflow analysis ShellCheck knows `$x` holds `1` and asks for no quotes; without it,
/// above `DATAFLOW_MAX_BYTES` (20 KiB), it does.
#[test]
fn the_dataflow_analysis_runs_on_files_up_to_20_kib() {
    let script = "x=1\necho $x\n";
    let sized = |len: usize| {
        let text = format!("{script}{}\n", "#".repeat(len - script.len() - 1));
        assert_eq!(text.len(), len);
        text
    };
    let (path, r) = lint_cli("sc_dataflow_small", "small.sh", script);
    assert_eq!(r.stdout, format!("{}: ok\n", path.display()));
    let (path, r) = lint_cli("sc_dataflow_at", "at.sh", &sized(20 * 1024));
    assert_eq!(r.stdout, format!("{}: ok\n", path.display()));
    let (path, r) = lint_cli("sc_dataflow_over", "over.sh", &sized(20 * 1024 + 1));
    assert_eq!(places(&path, &r), ["2:6: warn SC2086"], "{}", r.stdout);
}

#[test]
fn a_file_over_64_kib_skips_shellcheck_with_a_notice() {
    let pad = |n: usize| format!("ls $var\n{}\n", "#".repeat(n));
    let over = pad(MAX_INPUT_BYTES);
    let (path, r) = lint_cli("sc_over", "over.sh", &over);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(
        r.stderr.trim_end(),
        format!(
            "{}: ShellCheck skipped: the file is over {MAX_INPUT_BYTES} bytes",
            path.display()
        )
    );
    assert_eq!(
        places(&path, &r),
        [format!("1:1: warn {ANALYSIS_INCOMPLETE}")]
    );
    // At the cap ShellCheck runs and says nothing on stderr.
    let at = pad(MAX_INPUT_BYTES - 9);
    assert_eq!(at.len(), MAX_INPUT_BYTES);
    let (path, r) = lint_cli("sc_at", "at.sh", &at);
    assert!(r.stderr.is_empty(), "{}", r.stderr);
    assert!(
        places(&path, &r).contains(&"1:4: warn SC2086".to_string()),
        "{}",
        r.stdout
    );
}

/// A script nested deeper than the main thread's stack takes: the lint still ends with a verdict.
#[test]
fn a_deeply_nested_script_does_not_abort_the_lint() {
    let depth = 4000;
    let text = format!("echo {}x{}\n", "$(".repeat(depth), ")".repeat(depth));
    assert!(text.len() < MAX_INPUT_BYTES);
    let (_, r) = lint_cli("sc_deep", "deep.sh", &text);
    assert!(matches!(r.code, 0 | 1), "exit {}: {}", r.code, r.stderr);
    assert!(!r.stdout.is_empty());
}

/// ShellCheck is linked for `lint <file>` only (Ruling 112(a)): no library file names it, so
/// `analyse` and with it `check` and `hook` cannot reach it, and in `src/main.rs` only `run_lint`
/// calls it.
#[test]
fn shellcheck_is_reachable_from_lint_only() {
    use syn::visit::Visit;

    struct Mentions(bool);
    impl<'ast> Visit<'ast> for Mentions {
        fn visit_path(&mut self, p: &'ast syn::Path) {
            if p.segments.iter().any(|s| s.ident == "shellcheck") {
                self.0 = true;
            }
            syn::visit::visit_path(self, p);
        }
    }

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut dirs = vec![src.clone()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    assert!(files.len() > 10, "{files:?}");
    let mut wrong = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "main.rs" || rel == "shellcheck.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        if text.contains("rshellcheck_core") || text.contains("shellcheck::") {
            wrong.push(rel);
        }
    }
    assert!(
        wrong.is_empty(),
        "these files name the ShellCheck port: {wrong:?}"
    );

    let main = syn::parse_file(&std::fs::read_to_string(src.join("main.rs")).unwrap()).unwrap();
    let callers: Vec<String> = main
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f) => {
                let mut m = Mentions(false);
                m.visit_item_fn(f);
                m.0.then(|| f.sig.ident.to_string())
            }
            _ => None,
        })
        .collect();
    assert_eq!(callers, ["run_lint"]);
}
