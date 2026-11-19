//! The gap and mechanism rows (`tests/cases/pwsh_*.toml`) against `parse::pwsh`. Each row holds
//! PowerShell's own answer (`tests/pwsh_oracle.rs` checks that against the real `ParseInput`);
//! here the parser must give the same commands, comments and static calls, or refuse a row
//! PowerShell reads as an error.

use serde::Deserialize;
use shellwise::parse::pwsh;
use shellwise::{Os, Shell};

#[derive(Deserialize)]
struct File {
    row: Vec<Row>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Row {
    id: String,
    mechanism: Option<String>,
    /// `"refuses"`: the parser fails closed on a command PowerShell accepts.
    parser: Option<String>,
    command: String,
    error: bool,
    cmds: Vec<Vec<String>>,
    comments: Vec<String>,
    methods: Vec<String>,
}

fn rows(name: &str, count: usize) -> Vec<Row> {
    let path = format!("{}/tests/cases/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("read the rows file");
    let file: File = toml::from_str(&text).expect("rows toml");
    assert_eq!(file.row.len(), count, "{name}: row count");
    file.row
}

fn check(name: &str, count: usize) {
    let mut bad = Vec::new();
    for r in rows(name, count) {
        let parsed = pwsh::parse(&r.command, Shell::Pwsh, Os::Windows);
        if r.parser.as_deref() == Some("refuses") {
            if parsed.is_ok() {
                bad.push(format!("{}: accepted a row the parser must refuse", r.id));
            }
            continue;
        }
        match parsed {
            Err(e) if !r.error => bad.push(format!("{}: refused ({})", r.id, e.message)),
            Ok(_) if r.error => bad.push(format!("{}: accepted a PowerShell parse error", r.id)),
            Err(_) => {}
            Ok(script) => {
                let seen = pwsh::seen(&r.command, &script);
                let want = pwsh::Seen {
                    cmds: r.cmds,
                    comments: r.comments,
                    methods: r.methods,
                };
                if seen != want {
                    bad.push(format!("{}: got {seen:?}, want {want:?}", r.id));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{name}:\n{}", bad.join("\n"));
}

#[test]
fn gap_rows_read_as_powershell_reads_them() {
    check("pwsh_gaps.toml", 29);
}

#[test]
fn mechanism_rows_read_as_powershell_reads_them() {
    check("pwsh_mechanisms.toml", 426);
}

/// Each glued pair the parser accepts cites a row that holds it and that the parser reads as
/// PowerShell does (the checks above prove the reading, `tests/pwsh_oracle.rs` the answer).
#[test]
fn every_glue_table_entry_cites_a_kept_row_holding_its_pair() {
    let mut all = rows("pwsh_gaps.toml", 29);
    all.extend(rows("pwsh_mechanisms.toml", 426));
    let table = pwsh::glue_table();
    assert!(table.len() >= 50, "glue table has {} entries", table.len());
    let mut bad = Vec::new();
    for (key, id) in &table {
        match all.iter().find(|r| r.id == *id) {
            None => bad.push(format!("{key}: no row {id}")),
            Some(r) if r.error || r.parser.is_some() => {
                bad.push(format!("{key}: row {id} is not a row the parser reads"));
            }
            Some(r) if !pwsh::glue_keys(&r.command).contains(key) => {
                bad.push(format!("{key}: row {id} holds no such glued pair"));
            }
            Some(_) => {}
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
