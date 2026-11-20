//! Embeds every `docs/rules/<id>.md` (`OUT_DIR/rule_docs.rs`), so `shellwise explain <id>` works
//! from an installed binary that has no `docs/` folder next to it.

use std::fmt::Write as _;

pub fn generate(out_dir: &std::path::Path) {
    println!("cargo::rerun-if-changed=docs/rules");
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let dir = std::path::Path::new(&root).join("docs/rules");
    let mut docs: Vec<(String, String)> = std::fs::read_dir(&dir)
        .expect("read docs/rules")
        .map(|e| e.expect("a docs/rules entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .map(|p| {
            println!("cargo::rerun-if-changed={}", p.display());
            let id = p.file_stem().unwrap().to_string_lossy().into_owned();
            (id, p.to_string_lossy().into_owned())
        })
        .collect();
    assert!(!docs.is_empty(), "docs/rules holds no .md file");
    docs.sort();
    let mut out = String::from(
        "/// Every rule's doc, sorted by id.\npub static RULE_DOCS: &[(&str, &str)] = &[\n",
    );
    for (id, path) in &docs {
        writeln!(out, "    ({id:?}, include_str!({path:?})),").unwrap();
    }
    out.push_str("];\n");
    std::fs::write(out_dir.join("rule_docs.rs"), out).expect("write the rule docs table");
}
