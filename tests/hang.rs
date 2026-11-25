//! The `will-hang` rule through `analyse`: `tests/cases/hang.toml`, and the scope check (a script
//! file is not a command line).

mod case_loader;

use std::time::Instant;

use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

#[test]
fn hang_rows() {
    let rows = case_loader::rows("hang.toml");
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("hang.toml: {} rows ran", rows.len());
}

const LOOP_RULES: [&str; 2] = ["wait-loop-unbounded", "follow-unbounded"];

/// A wait-loop or follow row's `fix` is that finding's whole Fix text, not a part of it; and the
/// Fix, run back through the same check, is no finding of its rule: a weak model copies it as is.
#[test]
fn wait_and_follow_fix_lines_are_whole_and_settle() {
    let rows = case_loader::rows("hang.toml");
    let mut wrong = Vec::new();
    let mut checked = 0;
    for row in &rows {
        let Some(want) = &row.fix else { continue };
        let Some(rule) = row.rules.iter().find(|r| LOOP_RULES.contains(&r.as_str())) else {
            continue;
        };
        checked += 1;
        let v = case_loader::verdict(row);
        let line = v
            .findings
            .iter()
            .find(|f| f.rule == rule)
            .and_then(|f| f.fix_line());
        if line.as_deref() != Some(format!("Fix: {want}").as_str()) {
            wrong.push(format!("{}: fix line {line:?}\n  want Fix: {want}", row.id));
            continue;
        }
        let pasted = case_loader::Row {
            command: want.clone(),
            fix: None,
            ..row.clone()
        };
        let again: Vec<&str> = case_loader::verdict(&pasted)
            .findings
            .iter()
            .map(|f| f.rule)
            .filter(|r| LOOP_RULES.contains(r))
            .collect();
        if !again.is_empty() {
            wrong.push(format!("{}: the Fix itself gives {again:?}", row.id));
        }
    }
    assert!(checked > 0, "no wait-loop or follow row states a fix");
    assert!(
        wrong.is_empty(),
        "{} of {checked} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!("hang.toml: {checked} Fix lines checked whole");
}

/// A script file may run in a terminal, where a prompt is answered: the rule reads command lines
/// only. The same text as a command line is the control.
#[test]
fn a_read_in_a_script_file_is_not_a_finding() {
    let rules = |origin: Origin| -> Vec<&'static str> {
        let input = AnalyseInput {
            bytes: b"read x",
            shell: Shell::Bash(BashProfile::Posix),
            os: Os::host(),
            cwd: None,
            env: EnvView::new(),
            origin,
            problem: None,
        };
        let v = analyse(
            &input,
            &Config::default(),
            &Deadline::new(Instant::now(), 8000),
        );
        v.findings.iter().map(|f| f.rule).collect()
    };
    assert_eq!(rules(Origin::CommandLine), ["will-hang"]);
    assert!(!rules(Origin::File).contains(&"will-hang"));
}
