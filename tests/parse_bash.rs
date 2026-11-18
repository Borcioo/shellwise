//! Bash lowering: the shapes the rules rely on, comments, heredocs, errors, nesting and the gap table.

mod bash_util;

use bash_util::{command_shape, commands, names};
use shellwise::BashProfile;
use shellwise::ir::{ChainOp, EnvView, MAX_NESTING, Quote, Redirect, Script, Stmt, WordPart};
use shellwise::parse::QuoteKind;
use shellwise::parse::bash::parse;

fn ok(src: &str) -> Script {
    parse(src, BashProfile::GitBash).unwrap_or_else(|e| panic!("{src:?}: {e:?}"))
}

fn env() -> EnvView {
    EnvView::new()
}

#[test]
fn quoted_variable_target_is_dynamic() {
    let s = ok(r#"rm -rf "$d"/x"#);
    let c = commands(&s);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].canonical.as_deref(), Some("rm"));
    assert_eq!(c[0].args[0].static_value(&env()).as_deref(), Some("-rf"));
    let target = &c[0].args[1];
    assert!(target.is_dynamic());
    assert_eq!(target.static_value(&env()), None);
    assert_eq!(target.quote, Quote::Mixed);
    let mut e = env();
    e.set("d", "/tmp");
    assert_eq!(target.static_value(&e).as_deref(), Some("/tmp/x"));
}

#[test]
fn and_list_is_two_commands_joined_by_and() {
    let s = ok("cd /x && git checkout -- f");
    assert_eq!(s.stmts.len(), 2);
    match &s.stmts[0] {
        Stmt::Pipeline(p) => assert_eq!(p.chain, Some(ChainOp::And)),
        other => panic!("{other:?}"),
    }
    assert_eq!(names(&s), ["cd", "git"]);
    let s = ok("a || b; c & d");
    let chains: Vec<_> = s
        .stmts
        .iter()
        .map(|st| match st {
            Stmt::Pipeline(p) => p.chain,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        chains,
        [
            Some(ChainOp::Or),
            Some(ChainOp::Seq),
            Some(ChainOp::Background),
            None
        ]
    );
}

#[test]
fn loops_mark_their_commands() {
    for src in [
        "for w in a b; do rm \"$w\"; done",
        "while read -r w; do rm \"$w\"; done",
        "until false; do rm x; done",
        "for ((i=0; i<3; i++)); do rm x; done",
    ] {
        let s = ok(src);
        let body = match &s.stmts[..] {
            [Stmt::Loop { body, .. }] => body,
            other => panic!("{src}: {other:?}"),
        };
        let inner = commands(body);
        assert!(
            inner.iter().any(|c| c.canonical.as_deref() == Some("rm")),
            "{src}"
        );
        assert!(inner.iter().all(|c| c.in_loop), "{src}");
    }
    assert!(commands(&ok("rm x")).iter().all(|c| !c.in_loop));
}

#[test]
fn loop_word_list_substitution_is_visible() {
    let s = ok("for f in $(git ls-files); do rm \"$f\"; done");
    assert_eq!(names(&s), ["git", "rm"]);
}

#[test]
fn process_substitution_holds_its_command() {
    for src in ["cat <(git status)", "diff <(git show a) <(git show b)"] {
        let s = ok(src);
        assert_eq!(names(&s)[0], src.split(' ').next().unwrap(), "{src}");
        assert!(names(&s)[1..].iter().all(|n| n == "git"), "{src}");
        assert!(names(&s).len() >= 2, "{src}");
    }
    assert_eq!(names(&ok("tee >(git apply) < f")), ["tee", "git"]);
    assert_eq!(
        names(&ok("while read l; do rm \"$l\"; done < <(git ls-files)")),
        ["git", "read", "rm"]
    );
}

#[test]
fn assignment_substitution_holds_its_command() {
    let s = ok("x=$(git rev-parse HEAD)");
    let c = commands(&s);
    assert_eq!(c[0].name.parts, vec![]);
    assert_eq!(c[0].assigns.len(), 1);
    assert_eq!(c[0].assigns[0].0, "x");
    match &c[0].assigns[0].1.parts[..] {
        [WordPart::Subst(inner)] => assert_eq!(names(inner), ["git"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(names(&s), ["<none>", "git"]);
    assert_eq!(names(&ok("X=1 git status")), ["git"]);
    let s = ok("export D=/tmp/x; rm -rf \"$D\"");
    let assigned: Vec<_> = commands(&s)[0]
        .assigns
        .iter()
        .map(|(n, w)| (n.as_str(), w.static_value(&env())))
        .collect();
    assert_eq!(
        assigned,
        [("D", Some("/tmp/x".to_string()))],
        "a declaration builtin assigns"
    );
    assert_eq!(
        names(&ok("export X=$(git rev-parse HEAD)")),
        ["export", "git"]
    );
}

#[test]
fn dynamic_execution_is_opaque_and_xargs_shows_its_command() {
    for src in [
        r#"eval "$c""#,
        "$cmd -rf x",
        "\"$(which rm)\" x",
        "${RM:-rm} x",
        "r? -rf x",
    ] {
        let c = commands(&ok(src))[0].clone();
        assert!(c.opaque, "{src}");
    }
    let c = commands(&ok("eval 'echo hi'"))[0].clone();
    assert!(!c.opaque, "static eval text is a nested script, not opaque");
    let c = commands(&ok("find . -name x | xargs rm -rf"))[1].clone();
    assert_eq!(c.canonical.as_deref(), Some("xargs"));
    assert!(!c.opaque);
    assert_eq!(c.args[0].static_value(&env()).as_deref(), Some("rm"));
}

#[test]
fn unterminated_quotes_name_the_quote() {
    let cases = [
        ("echo 'abc", Some(QuoteKind::Single)),
        ("echo $'abc", Some(QuoteKind::Single)),
        ("echo \"abc", Some(QuoteKind::Double)),
        ("echo `abc", Some(QuoteKind::Backtick)),
        ("echo $(abc", None),
        ("if true; then", None),
    ];
    for (src, want) in cases {
        let e = parse(src, BashProfile::Posix).expect_err(src);
        assert_eq!(e.unclosed, want, "{src}: {e:?}");
        assert!(e.span.end <= src.len(), "{src}: {e:?}");
    }
}

#[test]
fn heredoc_body_expands_only_with_an_unquoted_delimiter() {
    let s = ok("cat <<EOF\nhi $(rm -rf x)\nEOF");
    let c = commands(&s);
    match &c[0].redirects[..] {
        [Redirect::Heredoc { body, expands, .. }] => {
            assert!(expands);
            assert!(body.parts.iter().any(|p| matches!(p, WordPart::Subst(_))));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(names(&s), ["cat", "rm"]);
    for src in [
        "cat <<'EOF'\nhi $(rm -rf x)\nEOF",
        "cat <<\"EOF\"\n$(rm x)\nEOF",
        "cat <<\\EOF\n`rm x`\nEOF",
    ] {
        let s = ok(src);
        match &commands(&s)[0].redirects[..] {
            [Redirect::Heredoc { body, expands, .. }] => {
                assert!(!expands, "{src}");
                assert!(!body.is_dynamic(), "{src}");
            }
            other => panic!("{src}: {other:?}"),
        }
        assert_eq!(names(&s), ["cat"], "{src}");
    }
    let s = ok("cat <<-EOF > f && rm y\n\t$(git status)\n\tEOF\n");
    assert_eq!(names(&s), ["cat", "git", "rm"]);
}

#[test]
fn hidden_commands_inside_words_are_found() {
    let cases: &[(&str, &[&str])] = &[
        ("echo ${x:-$(git status)}", &["echo", "git"]),
        ("echo \"${x/$(rm -rf a)/b}\"", &["echo", "rm"]),
        ("echo `git status`", &["echo", "git"]),
        ("echo \"a `rm x` b\"", &["echo", "rm"]),
        ("echo $((1 + $(rm x)))", &["echo", "rm"]),
        ("[[ -n $(rm x) ]]", &["[[", "rm"]),
        ("(( $(rm x) ))", &["rm"]),
        ("case $(git branch) in main) rm x;; esac", &["git", "rm"]),
        (
            "echo $(echo $(echo $(git status)))",
            &["echo", "echo", "echo", "git"],
        ),
        ("f() { rm -rf x; }; f", &["rm", "f"]),
        ("{ git status; } > >(rm x)", &["rm", "git"]),
    ];
    for (src, want) in cases {
        assert_eq!(names(&ok(src)), *want, "{src}");
    }
}

#[test]
fn compound_statements_keep_their_kind() {
    let s = ok("if git diff --quiet; then rm x; elif true; then a; else b; fi");
    match &s.stmts[..] {
        [Stmt::Cond { branches, .. }] => assert_eq!(branches.len(), 3),
        other => panic!("{other:?}"),
    }
    match &ok("f() { rm -rf x; }").stmts[..] {
        [Stmt::Func { name, body }] => {
            assert_eq!(name, "f");
            assert_eq!(names(body), ["rm"]);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(&ok("{ a; b; }").stmts[..], [Stmt::Block(_)]));
    assert!(matches!(&ok("(cd x && rm y)").stmts[..], [Stmt::Block(_)]));
    let s = ok("{ cd x; rm y; } | head");
    assert!(
        matches!(&s.stmts[..], [Stmt::Block(_)]),
        "a pipeline with a compound stage"
    );
    assert_eq!(names(&s), ["cd", "rm", "head"]);
}

#[test]
fn word_parts_follow_bash_quoting() {
    let c = commands(&ok(
        r#"rm -rf *.tmp ~/x 'a b' $'\x2drf' \-f "q"z {a,b} @(a|b) "*""#,
    ))[0]
        .clone();
    let shapes: Vec<_> = c.args.iter().map(bash_util::shape).collect();
    assert_eq!(
        shapes,
        [
            "-rf", "*.tmp", "~/x", "a b", "-rf", "-f", "qz", "{a,b}", "@(a|b)", "*"
        ]
    );
    assert!(
        matches!(c.args[8].parts[..], [WordPart::Glob(_)]),
        "extglob"
    );
    assert!(
        matches!(c.args[9].parts[..], [WordPart::Literal(_)]),
        "quoted * is literal"
    );
    assert!(matches!(c.args[1].parts[..], [WordPart::Glob(_)]));
    assert!(matches!(c.args[2].parts[0], WordPart::Tilde));
    assert_eq!(c.args[3].quote, Quote::Single);
    assert!(
        matches!(c.args[7].parts[..], [WordPart::Glob(_)]),
        "brace expansion is not a literal"
    );
    assert_eq!(c.args[6].quote, Quote::Mixed);
}

#[test]
fn canonical_name_per_profile() {
    let cases = [
        ("RM.exe -rf x", BashProfile::GitBash, Some("rm")),
        ("/usr/bin/rm x", BashProfile::GitBash, Some("rm")),
        ("/usr/bin/rm x", BashProfile::Posix, Some("rm")),
        ("RM x", BashProfile::Posix, Some("RM")),
        ("\\rm x", BashProfile::Posix, Some("rm")),
        ("'git' status", BashProfile::Posix, Some("git")),
        ("'C:\\x\\rm.exe' -rf x", BashProfile::GitBash, Some("rm")),
        ("'C:\\x\\rm' -rf x", BashProfile::Posix, Some("C:\\x\\rm")),
        ("$x status", BashProfile::Posix, None),
    ];
    for (src, profile, want) in cases {
        let s = parse(src, profile).unwrap();
        assert_eq!(commands(&s)[0].canonical.as_deref(), want, "{src}");
        assert_eq!(
            commands(&s)[0].typed,
            src.split(' ').next().unwrap(),
            "{src}"
        );
    }
}

#[test]
fn spans_are_byte_offsets_into_the_original() {
    let cases = [
        ("echo hi; rm -rf x", "rm -rf x"),
        ("echo é; rm -rf x", "rm -rf x"),
        ("echo \"é $(rm -rf x)\"", "rm -rf x"),
        ("cat <<EOF\né $(rm -rf x)\nEOF", "rm -rf x"),
    ];
    for (src, want) in cases {
        let s = ok(src);
        let rm = commands(&s)
            .into_iter()
            .find(|c| c.canonical.as_deref() == Some("rm"))
            .unwrap_or_else(|| panic!("{src}"));
        assert_eq!(&src[rm.span.start..rm.span.end], want, "{src}");
        assert_eq!(
            &src[rm.args[1].span.start..rm.args[1].span.end],
            "x",
            "{src}"
        );
    }
}

#[test]
fn comments_are_collected_with_their_trailing_flag() {
    let cases: &[(&str, &[(&str, bool)])] = &[
        (
            "git status # shellwise: allow",
            &[("# shellwise: allow", true)],
        ),
        ("# lead\nls", &[("# lead", false)]),
        (
            "  # indented\nls # t\n",
            &[("# indented", false), ("# t", true)],
        ),
        (
            "cat <<EOF # c1\nbody # not\nEOF\necho é # c3\n",
            &[("# c1", true), ("# c3", true)],
        ),
        ("echo '# no' \"# no\" a#b ${#x}", &[]),
        ("cat <<'EOF'\nrm -rf x # shellwise: allow\nEOF", &[]),
        ("echo 'a\nb' # after", &[("# after", true)]),
        ("ls;# glued", &[("# glued", true)]),
    ];
    for (src, want) in cases {
        let s = ok(src);
        let got: Vec<_> = s
            .comments
            .iter()
            .map(|c| (c.text.as_str(), c.trailing))
            .collect();
        assert_eq!(got, *want, "{src}");
        for c in &s.comments {
            assert_eq!(&src[c.span.start..c.span.end], c.text, "{src}");
        }
    }
}

/// A deep nesting of each construct that recurses in the parser, `n` levels.
fn nested(kind: &str, n: usize) -> String {
    let (open, mid, close) = match kind {
        "subst" => ("echo $(", "true", ")"),
        "paren" => ("(", "true", ")"),
        "brace" => ("{ ", "true", "; }"),
        "if" => ("if true; then ", "true", "; fi"),
        "while" => ("while true; do ", "true", "; done"),
        "case" => ("case x in a) ", "true", " ;; esac"),
        "param" => ("${x:-", "y", "}"),
        "dq" => ("\"$(echo ", "y", ")\""),
        "arith" => ("$((", "1", "))"),
        "procsub" => ("cat <(", "true", ")"),
        "backtick" => ("echo `", "true", "`"),
        "func" => ("f() { ", "true", "; }"),
        // A `]` argument per level hides the nesting from a bracket count.
        "masked_subst" => ("echo $(: ] ", "true", ")"),
        "masked_brace" => ("{ : ]; ", "true", "; }"),
        "masked_param" => ("${x:-]", "y", "}"),
        _ => unreachable!(),
    };
    format!("{}{mid}{}", open.repeat(n), close.repeat(n))
}

/// Each construct and the guard that must refuse 64 KiB of it.
const BRACKETS: &str = "brackets nested deeper than 200 levels";
const LOWERING: &str = "nesting deeper than 200 levels";
const BUDGET: &str = "nested text too large to parse in time";
const NESTED_KINDS: [(&str, &str); 15] = [
    ("subst", BRACKETS),
    ("paren", BRACKETS),
    ("brace", BRACKETS),
    ("if", LOWERING),
    ("while", LOWERING),
    ("case", LOWERING),
    ("param", BRACKETS),
    ("dq", BRACKETS),
    ("arith", BRACKETS),
    ("procsub", BRACKETS),
    // Unescaped backticks do not nest, they pair up: only the absence of a crash counts.
    ("backtick", ""),
    ("func", BRACKETS),
    ("masked_subst", BUDGET),
    ("masked_brace", LOWERING),
    ("masked_param", BUDGET),
];

#[test]
fn nesting_past_the_limit_is_an_error_not_a_crash() {
    for (kind, guard) in NESTED_KINDS {
        // 64 KiB of the construct: far past MAX_NESTING and deep enough to overflow a naive stack.
        let per_level = nested(kind, 2).len() - nested(kind, 1).len();
        let src = nested(kind, 64 * 1024 / per_level);
        assert!(src.len() > 60 * 1024, "{kind}: {}", src.len());
        let got = parse(&src, BashProfile::GitBash);
        if guard.is_empty() {
            continue;
        }
        assert_eq!(got.expect_err(kind).message, guard, "{kind}");
    }
    for kind in [
        "subst",
        "brace",
        "if",
        "param",
        "masked_subst",
        "masked_brace",
        "masked_param",
    ] {
        let src = nested(kind, MAX_NESTING + 1);
        assert!(nested(kind, MAX_NESTING).len() < src.len());
        let e = parse(&src, BashProfile::GitBash).expect_err(kind);
        assert!(e.message.contains("nest"), "{kind}: {e:?}");
    }
    for kind in ["masked_brace", "if"] {
        let src = nested(kind, MAX_NESTING);
        assert!(
            parse(&src, BashProfile::GitBash).is_ok(),
            "{kind} at the limit"
        );
    }
    // Each substitution level is parsed again with everything inside it; the reparse budget
    // (32 times the command's length) allows about 60 levels that each wrap the whole rest.
    for kind in ["masked_subst", "masked_param"] {
        let src = nested(kind, 50);
        assert!(
            parse(&src, BashProfile::GitBash).is_ok(),
            "{kind} at 50 levels"
        );
    }
    for kind in ["subst", "brace", "if", "param"] {
        let src = nested(kind, MAX_NESTING + 5);
        let e = parse(&src, BashProfile::GitBash).expect_err(kind);
        assert!(e.message.contains("nest"), "{kind}: {e:?}");
    }
}

#[test]
fn nesting_under_the_limit_parses() {
    for (kind, levels) in [
        ("brace", MAX_NESTING / 2),
        ("if", MAX_NESTING / 2),
        ("subst", 50),
        ("param", 50),
        ("dq", 50),
        ("procsub", 50),
    ] {
        let src = nested(kind, levels);
        assert!(parse(&src, BashProfile::GitBash).is_ok(), "{kind}");
    }
}

#[test]
fn long_flat_lists_parse() {
    for sep in [" && ", " | ", "; ", "\n", " || "] {
        let src = vec!["true"; 64 * 1024 / (4 + sep.len())].join(sep);
        let s = ok(&src);
        assert!(commands(&s).len() > 1000, "{sep:?}");
    }
}

// ---------- gap table ----------

#[derive(serde::Deserialize)]
struct GapFile {
    row: Vec<GapRow>,
}

#[derive(serde::Deserialize)]
pub struct GapRow {
    pub command: String,
    /// Every command bash runs, in pre-order (nested ones after their host command).
    #[serde(default)]
    pub commands: Vec<String>,
    /// `true` when the parser must refuse the row (fail closed).
    #[serde(default)]
    pub error: bool,
    pub why: String,
}

#[test]
fn gap_table_rows_lower_to_the_commands_bash_runs() {
    let text = std::fs::read_to_string("tests/cases/bash_gaps.toml").unwrap();
    let file: GapFile = toml::from_str(&text).unwrap();
    assert!(file.row.len() >= 19, "rows: {}", file.row.len());
    for r in &file.row {
        assert!(!r.why.is_empty(), "{}", r.command);
        let got = parse(&r.command, BashProfile::GitBash);
        if r.error {
            assert!(got.is_err(), "{:?} must be refused: {got:?}", r.command);
            assert!(r.commands.is_empty(), "{}", r.command);
        } else {
            let s = got.unwrap_or_else(|e| panic!("{:?}: {e:?}", r.command));
            assert_eq!(names(&s), r.commands, "{:?}", r.command);
        }
    }
}

#[test]
fn command_shapes_render_arguments() {
    let s = ok("X=1 rm -rf \"$d\" $(git x)");
    assert_eq!(command_shape(commands(&s)[0]), "X=1 rm -rf $ $()");
}
