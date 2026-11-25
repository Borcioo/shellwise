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

/// A wait-loop or follow row's `fix` is that finding's whole Fix text, not a part of it (every
/// follow finding of the command carries it); and the Fix, run back through the same check, is
/// no finding of its rule: a weak model copies it as is. A Fix that is a command draws no finding
/// of any rule, in Windows PowerShell 5.1 too for a PowerShell row.
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
        let lines: Vec<Option<String>> = v
            .findings
            .iter()
            .filter(|f| f.rule == rule)
            .map(|f| f.fix_line())
            .collect();
        let line = lines.first().cloned().flatten();
        if line.as_deref() != Some(format!("Fix: {want}").as_str()) {
            wrong.push(format!("{}: fix line {line:?}\n  want Fix: {want}", row.id));
            continue;
        }
        if rule == "follow-unbounded" && lines.iter().any(|l| *l != line) {
            wrong.push(format!("{}: the follow findings differ: {lines:?}", row.id));
        }
        // A Fix that is a command parses; a sentence (rows `…-is-a-sentence`) is no command.
        let sentence = row.id.ends_with("-is-a-sentence");
        let mut shells = vec![row.shell.clone()];
        if !sentence && row.shell == "pwsh" {
            shells.push("powershell5".to_string());
        }
        for shell in shells {
            let pasted = case_loader::Row {
                command: want.clone(),
                fix: None,
                shell,
                ..row.clone()
            };
            let again: Vec<&str> = case_loader::verdict(&pasted)
                .findings
                .iter()
                .map(|f| f.rule)
                .filter(|r| !sentence || LOOP_RULES.contains(r))
                .collect();
            if !again.is_empty() {
                wrong.push(format!(
                    "{} ({}): the Fix itself gives {again:?}",
                    row.id, pasted.shell
                ));
            }
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

/// A Bash follow sentence names the form to write, after the first `: `` ` and before its reason,
/// and that form reads ok: no finding of any rule. A weak model copies it as is.
#[test]
fn the_form_a_bash_follow_sentence_names_reads_ok() {
    let rows = case_loader::rows("hang.toml");
    let mut wrong = Vec::new();
    let mut checked = 0;
    for row in &rows {
        let Some(fix) = &row.fix else { continue };
        if !(row.is_bash()
            && row.id.ends_with("-is-a-sentence")
            && row.rules.iter().any(|r| r == "follow-unbounded"))
        {
            continue;
        }
        checked += 1;
        let head = fix.split(" (no command is built:").next().unwrap_or_default();
        let Some(form) = head
            .split_once(": `")
            .and_then(|(_, f)| f.strip_suffix('`'))
        else {
            wrong.push(format!("{}: the sentence names no form: {fix}", row.id));
            continue;
        };
        let pasted = case_loader::Row {
            command: form.to_string(),
            fix: None,
            ..row.clone()
        };
        let again: Vec<&str> = case_loader::verdict(&pasted)
            .findings
            .iter()
            .map(|f| f.rule)
            .collect();
        if !again.is_empty() {
            wrong.push(format!("{}: the form `{form}` gives {again:?}", row.id));
        }
    }
    assert!(checked > 0, "no Bash follow sentence row");
    assert!(
        wrong.is_empty(),
        "{} of {checked} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!("hang.toml: {checked} follow sentence forms read ok");
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
