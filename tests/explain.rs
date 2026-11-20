//! `shellwise explain <id>`: the rule's doc, embedded in the binary.

mod common;

#[test]
fn explain_prints_the_embedded_doc_of_every_rule() {
    let ids: Vec<&str> = shellwise::rules::all().iter().map(|r| r.id()).collect();
    let ids: Vec<&str> = ids
        .into_iter()
        .filter(|id| !id.starts_with("testhook"))
        .collect();
    assert!(ids.len() > 20, "{ids:?}");
    for id in ["bat-metachar", "ps-bad-parameter", "parse-error"] {
        assert!(ids.contains(&id), "{id}");
        let r = common::run(&["explain", id], None, &[]);
        assert_eq!(r.code, 0, "{id}: {}", r.stderr);
        let want =
            std::fs::read_to_string(format!("{}/docs/rules/{id}.md", env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        assert_eq!(r.stdout, want, "{id}");
    }
}

#[test]
fn explain_refuses_an_unknown_id() {
    let r = common::run(&["explain", "no-such-rule"], None, &[]);
    assert_eq!(r.code, 64, "{}", r.stdout);
    assert!(
        r.stderr.contains("no rule \"no-such-rule\""),
        "{}",
        r.stderr
    );
}
