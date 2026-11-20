//! The `too-long` rule through `analyse`: `tests/cases/length.toml`.

mod case_loader;

#[test]
fn length_rows() {
    let rows = case_loader::rows("length.toml");
    let wrong: Vec<String> = rows.iter().filter_map(case_loader::mismatch).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} rows:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
    eprintln!("length.toml: {} rows ran", rows.len());
}
