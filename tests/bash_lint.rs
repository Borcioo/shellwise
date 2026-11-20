//! The Git Bash rules through `analyse`: `tests/cases/bash_lint.toml`. The rows ported from
//! the baseline guard (`sg-` ids) must number what the file's header says.

mod case_loader;

const FILE: &str = "bash_lint.toml";

#[test]
fn bash_lint_rows() {
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
fn the_ported_rows_number_what_the_header_says() {
    let path = format!("{}/tests/cases/{FILE}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    let want: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("# baseline guard rows: "))
        .expect("the header names the ported row count")
        .trim()
        .parse()
        .unwrap();
    let got = text.lines().filter(|l| l.starts_with("id = \"sg-")).count();
    assert_eq!(got, want, "sg- rows against the header");
    assert!(got > 0);
}
