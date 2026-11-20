//! The `ps-var-colon` rule through `analyse`: `tests/cases/ps_var_colon.toml`, and with the
//! `oracle` feature pwsh's `ParseInput` on every row that says what it does.

mod case_loader;

#[test]
fn ps_var_colon_rows() {
    let rows = case_loader::rows("ps_var_colon.toml");
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("ps_var_colon.toml: {} rows ran", rows.len());
}

/// A pwsh row's verdict follows the real parser: break where it refuses, ok where it accepts.
#[test]
fn every_pwsh_row_says_what_the_real_parser_does() {
    let rows = case_loader::rows("ps_var_colon.toml");
    let wrong: Vec<&str> = rows
        .iter()
        .filter(|r| r.shell == "pwsh")
        .filter(|r| {
            let want = if r.level == "break" {
                "refuses"
            } else {
                "accepts"
            };
            r.oracle.as_deref() != Some(want)
        })
        .map(|r| r.id.as_str())
        .collect();
    assert!(
        wrong.is_empty(),
        "rows without the matching oracle: {wrong:?}"
    );
}

#[cfg(feature = "oracle")]
mod oracle {
    use super::case_loader;
    use std::path::Path;
    use std::process::Command;

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
        let rows: Vec<case_loader::Row> = case_loader::rows("ps_var_colon.toml")
            .into_iter()
            .filter(|r| r.oracle.is_some())
            .collect();
        for want in ["refuses", "accepts"] {
            assert!(
                rows.iter().any(|r| r.oracle.as_deref() == Some(want)),
                "no {want:?} row"
            );
        }
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ps_var_colon_oracle");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
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
            .map(|(r, (id, a))| format!("{}: pwsh {a} ({id})", r.id))
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
