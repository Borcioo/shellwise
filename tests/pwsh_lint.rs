//! The PowerShell lint rules through `analyse`: `tests/cases/pwsh_lint.toml`, and with the
//! `oracle` feature pwsh's own parser on every row that says what it does with the text.

mod case_loader;

const FILE: &str = "pwsh_lint.toml";

#[test]
fn pwsh_lint_rows() {
    let rows = case_loader::rows(FILE);
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("{FILE}: {} rows ran", rows.len());
}

#[test]
fn every_break_row_states_its_fix_line() {
    let rows = case_loader::rows(FILE);
    let missing: Vec<&str> = rows
        .iter()
        .filter(|r| r.level == "break" && r.fix.is_none())
        .map(|r| r.id.as_str())
        .collect();
    assert!(missing.is_empty(), "break rows without `fix`: {missing:?}");
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

    /// A text pwsh refuses: the control that the oracle can say "refuses" at all.
    const CONTROL: (&str, &str) = ("control-unclosed-quote", "Write-Output 'open");

    #[test]
    fn pwsh_parse_input_gives_every_row_its_oracle_answer() {
        let rows: Vec<case_loader::Row> = case_loader::rows(super::FILE)
            .into_iter()
            .filter(|r| r.oracle.is_some() && !r.is_bash())
            .collect();
        assert!(!rows.is_empty(), "no pwsh row with an oracle answer");
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pwsh_lint_oracle");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("oracle.ps1");
        let input = dir.join("rows.json");
        std::fs::write(&script, PWSH).unwrap();
        let mut json: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| serde_json::json!({"id": r.id, "command": r.command}))
            .collect();
        json.push(serde_json::json!({"id": CONTROL.0, "command": CONTROL.1}));
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
            .skip(1)
            .filter_map(|l| l.trim_end().rsplit_once(' '))
            .collect();
        assert_eq!(answers.len(), rows.len() + 1, "an answer per row: {said}");
        assert_eq!(answers.last(), Some(&(CONTROL.0, "refuses")), "{said}");
        let wrong: Vec<String> = rows
            .iter()
            .zip(&answers)
            .filter(|(r, (id, a))| *id != r.id || Some(*a) != r.oracle.as_deref())
            .map(|(r, (id, a))| format!("{}: pwsh {a} ({id})", r.id))
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
