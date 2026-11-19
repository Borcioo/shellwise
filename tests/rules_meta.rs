//! Every rule is documented and has rows: for each id in `rules::all()` and
//! `rules::length_rules()`, `tests/cases/<id with _>.toml` holds a row where it denies (break,
//! danger or critical) and a row where it does not fire, and `docs/rules/<id>.md` exists. Every
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

fn is_deny(level: &str) -> bool {
    matches!(level, "break" | "danger" | "critical")
}

#[test]
fn every_rule_has_a_deny_row_an_allow_row_and_a_doc() {
    let mut wrong = Vec::new();
    for id in rule_ids() {
        let file = format!("{}.toml", id.replace('-', "_"));
        if !root().join("tests/cases").join(&file).is_file() {
            wrong.push(format!("{id}: no tests/cases/{file}"));
            continue;
        }
        let rows = case_loader::rows(&file);
        let fires = |r: &&case_loader::Row| r.rules.iter().any(|x| x == id);
        if !rows.iter().any(|r| fires(&r) && is_deny(&r.level)) {
            wrong.push(format!("{id}: no deny row in {file}"));
        }
        if !rows.iter().any(|r| !fires(&r)) {
            wrong.push(format!("{id}: no allow row in {file}"));
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
    let mut files = Vec::new();
    for e in std::fs::read_dir(root().join("tests/cases")).unwrap() {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        // The parser gap tables are parser rows without verdicts.
        if name.ends_with(".toml") && !name.contains("gaps") && !name.contains("mechanisms") {
            files.push(name);
        }
    }
    assert!(!files.is_empty(), "no case files");
    let mut checked = 0;
    let mut wrong = Vec::new();
    for file in &files {
        for row in case_loader::rows(file) {
            for f in case_loader::verdict(&row).findings {
                if is_deny(f.level.as_str()) {
                    checked += 1;
                    if !f.fix_line().is_some_and(|l| l.len() > "Fix: ".len()) {
                        wrong.push(format!("{file} {}: {} has no Fix line", row.id, f.rule));
                    }
                }
            }
        }
    }
    assert!(checked > 0, "no deny finding in {files:?}");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
