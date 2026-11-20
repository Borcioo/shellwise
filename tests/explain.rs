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

/// D5: a ShellCheck code `lint` reports gets an answer that names it and its page.
#[test]
fn explain_answers_a_shellcheck_code() {
    let r = common::run(&["explain", "SC2086"], None, &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.starts_with("# SC2086\n"), "{}", r.stdout);
    assert!(
        r.stdout.contains("https://www.shellcheck.net/wiki/SC2086"),
        "{}",
        r.stdout
    );
    // Not a code in the spelling `lint` gives one.
    for id in ["SC", "SC08", "SCx"] {
        assert_eq!(common::run(&["explain", id], None, &[]).code, 64, "{id}");
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
