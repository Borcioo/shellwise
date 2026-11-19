//! The vendored PowerShell grammar: the generated parser matches its grammar, and the fork keeps
//! its licence and change list.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn fork() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/tree-sitter-powershell")
}

fn sha256(relative: &str) -> String {
    let bytes = std::fs::read(fork().join(relative)).expect(relative);
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(fork().join(relative)).expect(relative)
}

#[test]
fn generated_records_the_hashes_of_the_grammar_files() {
    let want = format!(
        "grammar.js sha256 {}\nsrc/grammar.json sha256 {}\ntree-sitter-cli 0.27.2\n",
        sha256("grammar.js"),
        sha256("src/grammar.json")
    );
    assert_eq!(
        read("GENERATED"),
        want,
        "grammar.js or src/grammar.json changed without scripts/regen-grammar.ps1"
    );
}

#[test]
fn notice_names_the_upstream_version_and_lists_the_grammar_changes() {
    let notice = read("NOTICE.md");
    assert!(notice.contains("version 0.26.6"), "{notice}");
    let changes = notice
        .split_once("## Grammar changes")
        .map(|(_, rest)| rest)
        .expect("a Grammar changes section");
    let listed = changes.lines().filter(|l| l.starts_with("- ")).count();
    assert!(listed >= 1, "no grammar change listed:\n{changes}");
}

#[test]
fn license_is_the_upstream_mit_text() {
    let license = read("LICENSE");
    assert!(license.starts_with("MIT License\n"), "{license}");
    assert!(license.contains("Copyright (c) 2023 Airbus CERT"));
    assert!(license.contains("Permission is hereby granted, free of charge"));
}
