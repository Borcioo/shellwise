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
