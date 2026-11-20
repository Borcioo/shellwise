//! The `parse-error` rule through `analyse`: `tests/cases/parse_error.toml` and
//! `tests/cases/pwsh_gaps_verdict.toml`, and with the
//! `oracle` feature the real shells' parsers on every row that says what they do.

mod case_loader;

/// The rows of `parse_error.toml` and `pwsh_gaps_verdict.toml`; each must exist and run rows.
fn all_rows() -> Vec<case_loader::Row> {
    let mut rows = case_loader::rows("parse_error.toml");
    rows.extend(case_loader::rows("pwsh_gaps_verdict.toml"));
    rows
}

#[test]
fn parse_error_rows() {
    let rows = all_rows();
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!(
        "parse_error.toml and pwsh_gaps_verdict.toml: {} rows ran",
        rows.len()
    );
}

#[test]
fn every_break_row_says_the_real_parser_refuses_it() {
    let rows = all_rows();
    let unproven: Vec<&str> = rows
        .iter()
        .filter(|r| r.level == "break" && r.oracle.as_deref() != Some("refuses"))
        .map(|r| r.id.as_str())
        .collect();
    assert!(
        unproven.is_empty(),
        "break rows without oracle = \"refuses\": {unproven:?}"
    );
}

#[cfg(feature = "oracle")]
mod oracle {
    use super::case_loader::Row;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    #[cfg(windows)]
    const BASH: &str = r"C:\Program Files\Git\bin\bash.exe";
    #[cfg(not(windows))]
    const BASH: &str = "/bin/bash";

    /// A fresh folder of this test's own under the target's temp dir.
    fn folder(tag: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("parse_error_oracle_{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn with_oracle(bash: bool) -> Vec<Row> {
        let rows: Vec<Row> = super::all_rows()
            .into_iter()
            .filter(|r| r.oracle.is_some() && r.is_bash() == bash)
            .collect();
        // A shell that refused everything (or accepted everything) must fail the check.
        for want in ["refuses", "accepts"] {
            assert!(
                rows.iter().any(|r| r.oracle.as_deref() == Some(want)),
                "no {want:?} row for {}",
                if bash { "bash" } else { "pwsh" }
            );
        }
        rows
    }

    /// Compare each row's `oracle` with the shell's answer (`id refuses|accepts` lines).
    fn compare(rows: &[Row], said: &str) {
        let answers: Vec<(&str, &str)> = said
            .lines()
            .filter_map(|l| l.trim_end().rsplit_once(' '))
            .filter(|(_, a)| matches!(*a, "refuses" | "accepts"))
            .collect();
        assert_eq!(answers.len(), rows.len(), "an answer per row: {said}");
        let wrong: Vec<String> = rows
            .iter()
            .zip(&answers)
            .filter(|(r, (id, a))| *id != r.id || Some(*a) != r.oracle.as_deref())
            .map(|(r, (id, a))| format!("{}: the shell {a} ({id})", r.id))
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn bash_n_gives_every_row_its_oracle_answer() {
        let rows = with_oracle(true);
        let dir = folder("bash");
        let mut args = Vec::new();
        for (i, r) in rows.iter().enumerate() {
            let file = dir.join(format!("{i}.sh"));
            std::fs::write(&file, &r.command).unwrap();
            args.push(r.id.clone());
            args.push(file.to_string_lossy().replace('\\', "/"));
        }
        assert!(
            Path::new(BASH).is_file(),
            "{BASH} is missing: the oracle needs it"
        );
        // One invocation prints the version of the bash that judges every row. The driver is a
        // file: Git Bash re-parses quotes in its Windows command line.
        let driver = dir.join("driver.sh");
        std::fs::write(
            &driver,
            "echo \"bash $BASH_VERSION\"\nwhile [ $# -gt 0 ]; do\n  \
             if \"$BASH\" --norc --noprofile -n \"$2\" 2>/dev/null; then echo \"$1 accepts\"; \
             else echo \"$1 refuses\"; fi\n  shift 2\ndone\n",
        )
        .unwrap();
        let out = Command::new(BASH)
            .args(["--norc", "--noprofile"])
            .arg(driver.to_string_lossy().replace('\\', "/"))
            .args(&args)
            .output()
            .expect("bash runs");
        let said = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        assert!(
            out.status.success(),
            "{said}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let version = said.lines().next().unwrap_or_default();
        assert!(version.starts_with("bash ") && version.len() > 5, "{said}");
        eprintln!("{version}");
        compare(&rows, &said);
    }

    /// Reads the rows file (one JSON array of {id, command}) with `ParseInput`.
    const PWSH: &str = r#"
param([Parameter(Mandatory)][string]$In)
$ErrorActionPreference = 'Stop'
"PowerShell $($PSVersionTable.PSVersion)"
$rows = [IO.File]::ReadAllText($In, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
foreach ($r in $rows) {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput([string]$r.command, [ref]$tokens, [ref]$errors)
    "$($r.id) $(if ($errors.Count -gt 0) { 'refuses' } else { 'accepts' })"
}
"#;

    #[test]
    fn pwsh_parse_input_gives_every_row_its_oracle_answer() {
        let rows = with_oracle(false);
        let dir = folder("pwsh");
        let script = dir.join("oracle.ps1");
        let input = dir.join("rows.json");
        std::fs::write(&script, PWSH).unwrap();
        let json: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| serde_json::json!({"id": r.id, "command": r.command}))
            .collect();
        std::fs::write(&input, serde_json::to_string(&json).unwrap()).unwrap();
        let out = Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .arg("-In")
            .arg(&input)
            .output()
            .expect("pwsh is required by the oracle feature: install PowerShell 7");
        let said = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        assert!(
            out.status.success(),
            "{said}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let version = said.lines().next().unwrap_or_default();
        assert!(version.starts_with("PowerShell 7"), "{said}");
        eprintln!("{version}");
        compare(&rows, &said);
    }
}
