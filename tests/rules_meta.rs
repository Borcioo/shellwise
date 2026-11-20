//! Every rule is documented and has rows: for each id in `rules::all()` and
//! `rules::length_rules()`, one case file under `tests/cases/` holds a row where it denies (break,
//! danger or critical; for a rule in `WARN_DEFAULT`, any row where it fires) and a row where it
//! does not fire, and `docs/rules/<id>.md` exists. Every
//! deny in every case file carries a Fix line. The `testhook` fault injectors are left out.

mod case_loader;

use std::path::Path;

fn rule_ids() -> Vec<&'static str> {
    let mut ids: Vec<&str> = shellwise::rules::all().iter().map(|r| r.id()).collect();
    ids.extend(shellwise::rules::length_rules().iter().map(|r| r.id()));
    ids.retain(|id| !id.starts_with("testhook"));
    assert!(!ids.is_empty(), "no rules");
    ids
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Rules whose default level is warn: no row can deny by them, so a row where they fire stands in
/// for the deny row. An id leaves the list when its default becomes a deny level.
const WARN_DEFAULT: &[&str] = &[
    "bash-msys-path-mangle",
    "bash-versioned-php",
    "bash-vendor-bin-shebang",
    "ps-unix-command",
    "pwsh-file-list-arg",
    "ps-kill-wrapper",
    "ps-auto-variable",
    "ps-remove-item-star",
    "ps-stdin-script",
    "ps-empty-arg",
    "rg-follow-L",
    "wsl-argv-rejoin",
    "claude-cmd-live-config",
    "gate-truncated-pipeline",
    "ps-bare-bash",
    "ps-dotnet-relative-path",
];

fn is_deny(level: &str) -> bool {
    matches!(level, "break" | "danger" | "critical")
}

/// Every case file with verdict rows, and its rows that run on this OS.
fn case_files() -> Vec<(String, Vec<case_loader::Row>)> {
    let mut files = Vec::new();
    for e in std::fs::read_dir(root().join("tests/cases")).unwrap() {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        // The parser gap tables are parser rows without verdicts.
        if name.ends_with(".toml") && !name.contains("gaps") && !name.contains("mechanisms") {
            files.push(name);
        }
    }
    files.sort();
    assert!(!files.is_empty(), "no case files");
    files
        .into_iter()
        .map(|f| {
            let rows = case_loader::rows(&f);
            (f, rows)
        })
        .collect()
}

#[test]
fn every_rule_has_a_deny_row_an_allow_row_and_a_doc() {
    let files = case_files();
    let mut wrong = Vec::new();
    let ids = rule_ids();
    for id in WARN_DEFAULT.iter().filter(|id| !ids.contains(id)) {
        wrong.push(format!("{id}: in WARN_DEFAULT but no such rule"));
    }
    for id in ids {
        let fires = |r: &case_loader::Row| r.rules.iter().any(|x| x == id);
        let stands_in = |r: &case_loader::Row| is_deny(&r.level) || WARN_DEFAULT.contains(&id);
        let covered = files.iter().any(|(_, rows)| {
            rows.iter().any(|r| fires(r) && stands_in(r)) && rows.iter().any(|r| !fires(r))
        });
        if !covered {
            wrong.push(format!(
                "{id}: no case file holds both a deny row and a row where it does not fire"
            ));
        }
    }
    for id in rule_ids()
        .into_iter()
        .chain([shellwise::ANALYSIS_INCOMPLETE])
    {
        if !root().join("docs/rules").join(format!("{id}.md")).is_file() {
            wrong.push(format!("{id}: no docs/rules/{id}.md"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_deny_carries_a_fix_line() {
    let files = case_files();
    let mut checked = 0;
    let mut wrong = Vec::new();
    for (file, rows) in &files {
        for row in rows {
            for f in case_loader::verdict(row).findings {
                if is_deny(f.level.as_str()) {
                    checked += 1;
                    if !f.fix_line().is_some_and(|l| l.len() > "Fix: ".len()) {
                        wrong.push(format!("{file} {}: {} has no Fix line", row.id, f.rule));
                    }
                }
            }
        }
    }
    assert!(checked > 0, "no deny finding in the case files");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
