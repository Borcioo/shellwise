//! Bash lowering: the shapes the rules rely on, comments, heredocs, errors, nesting and the gap table.

mod bash_util;

use bash_util::{command_shape, commands, names};
use shellwise::BashProfile;
use shellwise::ir::{ChainOp, EnvView, MAX_NESTING, Quote, Redirect, Script, Stmt, WordPart};
use shellwise::parse::bash::parse;
use shellwise::parse::{ParseKind, QuoteKind};

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
fn every_statement_keeps_the_operator_before_it() {
    use ChainOp::{And, Background, Or, Seq};
    let cases: &[(&str, &[Option<ChainOp>])] = &[
        (
            "[[ -d y ]] || cd /tmp/x && rm -rf .",
            &[None, Some(Or), Some(And)],
        ),
        (
            "( true ) || cd /tmp/x && rm -rf .",
            &[None, Some(Or), Some(And)],
        ),
        (
            "{ true; } || cd /tmp/x && rm -rf .",
            &[None, Some(Or), Some(And)],
        ),
        (
            "if true; then :; fi || cd /tmp/x && rm -rf .",
            &[None, Some(Or), Some(And)],
        ),
        ("for f in a; do :; done && rm x", &[None, Some(And)]),
        ("a; b & c", &[None, Some(Seq), Some(Background)]),
        ("a\nb", &[None, Some(Seq)]),
        // The word-list substitution and the loop are one statement of the chain.
        (
            "true || for f in $(ls); do :; done",
            &[None, Some(Or), Some(Or)],
        ),
        (
            "(( x )) || cd /tmp/x && rm -rf .",
            &[None, Some(Or), Some(And)],
        ),
    ];
    for (src, want) in cases {
        let s = ok(src);
        let got: Vec<_> = (0..s.stmts.len()).map(|i| s.join(i)).collect();
        assert_eq!(got, *want, "{src}");
    }
    // Every pipeline followed by `&&`/`||` carries that operator, in every nested list too.
    let mut bad = Vec::new();
    for src in [
        "(( x )) || cd /tmp/x && rm -rf .",
        "[[ -d y ]] && cd /tmp/x || rm -rf .",
        "echo $( (( x )) || cd /tmp/x && rm -rf . )",
        "cat <<EOF\n$( (( x )) && rm -rf . )\nEOF",
        "if (( x )) || cd /tmp/x; then rm -rf .; fi",
        "f() { (( x )) && rm -rf .; }",
        "while (( x )) && cd y; do rm -rf .; done",
    ] {
        chains_agree(&ok(src), src, &mut bad);
    }
    assert!(bad.is_empty(), "{} rows: {bad:#?}", bad.len());
    let chains: Vec<_> = [
        "[[ -d y ]] || cd x",
        "(( x )) || cd x",
        "(( x )) > f || cd x",
    ]
    .iter()
    .map(|src| match &ok(src).stmts[0] {
        Stmt::Pipeline(p) => p.chain,
        other => panic!("{src}: {other:?}"),
    })
    .collect();
    assert_eq!(chains, [Some(Or); 3], "each keeps its pipeline chain");
    let s = ok("while cd x; do rm -rf .; done");
    match &s.stmts[..] {
        [Stmt::Loop { body, .. }] => assert_eq!(body.join(1), Some(Seq), "body after condition"),
        other => panic!("{other:?}"),
    }
}

/// Each pipeline whose next statement is joined by `&&` or `||` has that operator as its chain,
/// in `s` and in every list nested in it.
fn chains_agree(s: &Script, src: &str, bad: &mut Vec<String>) {
    for (i, st) in s.stmts.iter().enumerate() {
        let next = s.join(i + 1);
        if let Stmt::Pipeline(p) = st
            && matches!(next, Some(ChainOp::And | ChainOp::Or))
            && p.chain != next
        {
            bad.push(format!(
                "{src}: statement {i} chain {:?}, next {next:?}",
                p.chain
            ));
        }
        match st {
            Stmt::Pipeline(p) => {
                for e in &p.elems {
                    let words: Vec<&shellwise::ir::Word> = match e {
                        shellwise::ir::Elem::Cmd(c) => c
                            .args
                            .iter()
                            .chain(c.redirects.iter().map(|r| match r {
                                Redirect::File { target, .. } => target,
                                Redirect::Heredoc { body, .. } => body,
                            }))
                            .collect(),
                        shellwise::ir::Elem::Expr(w) => vec![w],
                        shellwise::ir::Elem::Method(_) => Vec::new(),
                    };
                    for w in words {
                        for part in &w.parts {
                            if let WordPart::Subst(inner) = part {
                                chains_agree(inner, src, bad);
                            }
                        }
                    }
                }
            }
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                chains_agree(body, src, bad)
            }
            Stmt::Cond { branches, .. } => branches.iter().for_each(|b| chains_agree(b, src, bad)),
        }
    }
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
        // `for (( … ))` puts its header first, as a `((` command.
        let body = match &s.stmts[..] {
            [Stmt::Loop { body, .. }] | [_, Stmt::Loop { body, .. }] => body,
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
    // The `for (( … ))` header runs before its loop: `;` joins them.
    match &ok("true || for ((i=0; i<3; i++)); do rm x; done").stmts[..] {
        [_, Stmt::Pipeline(header), Stmt::Loop { .. }] => {
            assert_eq!(header.chain, Some(ChainOp::Seq))
        }
        other => panic!("{other:?}"),
    }
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
        "~ x",
        r#"builtin eval "$c""#,
        r#"command eval "$c""#,
        r#"exec eval "$c""#,
        r#"command -p eval "$c""#,
        r#"exec -a name eval "$c""#,
        r#"builtin source "$f""#,
        r#"command . "$f""#,
        r#"exec source "$f""#,
    ] {
        let c = commands(&ok(src))[0].clone();
        assert!(c.opaque, "{src}");
    }
    for src in [
        "builtin eval 'echo hi'",
        r#"command ls "$d""#,
        "exec git status",
    ] {
        let c = commands(&ok(src))[0].clone();
        assert!(!c.opaque, "{src}");
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
        let unclosed = match e.kind {
            ParseKind::UnclosedQuote(q) => Some(q),
            _ => None,
        };
        assert_eq!(unclosed, want, "{src}: {e:?}");
        assert!(e.span.end <= src.len(), "{src}: {e:?}");
    }
}

#[test]
fn an_unterminated_heredoc_is_its_own_kind() {
    let e = parse("cat <<EOF\nhi", BashProfile::Posix).unwrap_err();
    assert_eq!(e.kind, ParseKind::UnterminatedHeredoc, "{e:?}");
    let e = parse("if true; then", BashProfile::Posix).unwrap_err();
    assert_eq!(e.kind, ParseKind::Syntax, "{e:?}");
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
        ("(( $(rm x) ))", &["((", "rm"]),
        // A substitution in arithmetic is lowered wherever the parser ends it.
        ("(( $(rm -rf /tmp/x) + 1 ))", &["((", "rm"]),
        ("(( $(rm -rf /tmp/x <<< a) + 1 ))", &["((", "rm"]),
        ("(( $(\nrm -rf /tmp/x\n) + 1 ))", &["((", "rm"]),
        (
            "t=1; echo $(( $(rm -rf /tmp/x) - t ))",
            &["<none>", "echo", "rm"],
        ),
        ("(( x )) > $(rm x)", &["((", "rm"]),
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
    // The parser cannot end a `case` pattern inside `$(…)` in arithmetic: an error, which fails
    // closed, never a script without the command.
    for src in [
        "(( $(case x in a) rm -rf /tmp/x;; esac) + 1 ))",
        "x=1; (( $(case a in a) : ;; esac) + x ))",
    ] {
        assert!(parse(src, BashProfile::GitBash).is_err(), "{src}");
    }
}

/// Each row checked in Git Bash 5.2 with a canary file: a "runs" row created it, a "no" row did not.
#[test]
fn subscripts_bash_evaluates_run_their_substitutions() {
    let runs: &[(&str, &[&str])] = &[
        ("let 'a[$(rm -rf x)]'", &["let", "rm"]),
        ("builtin let 'a[$(rm -rf x)]'", &["builtin", "rm"]),
        ("printf -v 'a[$(rm -rf x)]' %s 1", &["printf", "rm"]),
        ("printf -v'a[$(rm -rf x)]' x", &["printf", "rm"]),
        ("read 'a[$(rm -rf x)]' < f", &["read", "rm"]),
        ("read -r 'a[$(rm -rf x)]' < f", &["read", "rm"]),
        ("test -v 'a[$(rm -rf x)]'", &["test", "rm"]),
        ("[ -v 'a[$(rm -rf x)]' ]", &["[", "rm"]),
        ("[[ -v 'a[$(rm -rf x)]' ]]", &["[[", "rm"]),
        ("[[ 1 -eq 'a[$(rm -rf x)]' ]]", &["[[", "rm"]),
        ("[[ 'a[$(rm -rf x)]' -lt 1 ]]", &["[[", "rm"]),
        ("x['$(rm -rf x)']=1", &["<none>", "rm"]),
        ("declare 'a[$(rm -rf x)]=1'", &["declare", "rm"]),
        ("typeset 'a[`rm -rf x`]=1'", &["typeset", "rm"]),
        ("f() { local 'a[$(rm -rf x)]=1'; }", &["local", "rm"]),
        // `unset` of an indexed array element (bash runs nothing when `a` is no array: lowered
        // anyway, on the safe side).
        (
            "a=(1 2); unset 'a[$(rm -rf x)]'",
            &["<none>", "unset", "rm"],
        ),
        // A nameref's target is a name: its subscript runs where `$r` expands.
        (
            "declare -n r='a[$(rm -rf x)]'; a=(1 2); echo \"$r\"",
            &["declare", "rm", "<none>", "echo"],
        ),
        (
            "declare -n r='a[$(rm -rf y)]'; echo $r",
            &["declare", "rm", "echo"],
        ),
        // Parameter offsets and lengths are arithmetic.
        (
            "s=abc; echo ${s:0:'a[$(rm -rf x)]'}",
            &["<none>", "echo", "rm"],
        ),
        (
            "s=abc; echo ${s:'a[$(rm -rf x)]'}",
            &["<none>", "echo", "rm"],
        ),
        (
            "s=abc; echo ${s:'a[$(rm -rf x)]':1}",
            &["<none>", "echo", "rm"],
        ),
        // A subscript ends at its own `]`, not at one inside quotes or a substitution.
        ("let 'a[\"]\"+$(rm -rf x)]'", &["let", "rm"]),
        ("let 'a[$(echo \"]\")+$(rm -rf x)]'", &["let", "echo", "rm"]),
        ("let 'a[b[1]+$(rm -rf x)]'", &["let", "rm"]),
        ("let 'a[$(echo ])+$(rm -rf x)]'", &["let", "echo", "rm"]),
        ("let 'a[${y:-]}+$(rm -rf x)]'", &["let", "rm"]),
        ("let 'a[\\]+$(rm -rf x)]'", &["let", "rm"]),
        ("let 'a[\"\\\"]\"+$(rm -rf x)]'", &["let", "rm"]),
        // The value assigned to an integer name is arithmetic.
        (
            "declare -i n; n='a[$(rm -rf x)]'",
            &["declare", "<none>", "rm"],
        ),
        // bash refuses an unclosed subscript; it is read to the end, on the safe side.
        ("let 'a[$(rm -rf x)'", &["let", "rm"]),
        // A nameref declared by `local` or `typeset`: its target's subscript runs.
        (
            "f() { local -n r='a[$(rm -rf x)]'; echo \"$r\"; }; a=(1 2); f",
            &["local", "rm", "echo", "<none>", "f"],
        ),
        (
            "a=(1 2); typeset -n r='a[$(rm -rf x)]'; echo \"$r\"",
            &["<none>", "typeset", "rm", "echo"],
        ),
        // A write through a nameref to an integer name is arithmetic.
        (
            "declare -i n; declare -n r=n; r='a[$(rm -rf x)]'",
            &["declare", "declare", "<none>", "rm"],
        ),
        // Before the command word, after a `{NAME}>f`, an assignment is bash's.
        (
            "declare -i n; {x}>f n='a[$(>y)]'",
            &["declare", "<none>", "<none>"],
        ),
        // `wait -p NAME` assigns NAME.
        (
            "sleep 0 & wait -n -p 'a[$(>y)]'",
            &["sleep", "wait", "<none>"],
        ),
        (
            "sleep 0 & wait -n -p'a[$(>y)]'",
            &["sleep", "wait", "<none>"],
        ),
        (
            "declare -a a; sleep 0 & wait -n -p 'a[$(>y)]'",
            &["declare", "sleep", "wait", "<none>"],
        ),
    ];
    let no: &[(&str, &[&str])] = &[
        ("a=(1); let 'a[\"[\"]+$(rm -rf x)'", &["<none>", "let"]),
        ("export 'a[$(rm -rf x)]'=1", &["export"]),
        ("let '$(rm -rf x)'", &["let"]),
        ("echo 'a[$(rm -rf x)]'", &["echo"]),
        ("[[ -n 'a[$(rm -rf x)]' ]]", &["[["]),
    ];
    // Every failing row is listed, not only the first.
    let bad: Vec<String> = runs
        .iter()
        .chain(no)
        .filter_map(|(src, want)| {
            let got = parse(src, BashProfile::GitBash).map(|s| names(&s));
            let pass = got.as_ref().is_ok_and(|g| g == want);
            (!pass).then(|| format!("{src}: {got:?}"))
        })
        .collect();
    assert!(bad.is_empty(), "{} rows: {bad:#?}", bad.len());
}

/// A `{NAME}` word that touches a redirect operator is part of the redirect: the command bash runs
/// is the next word, with its own wrapper target and operands, so an `eval` of dynamic text behind
/// it stays opaque. A location that does not hold the word's text (a line continuation) leaves
/// the word bash runs unknown. The parser misreads `coproc NAME [[ … ]]` (and splits the test at
/// `||`): the test fails closed. Each row checked in Git Bash 5.2 with a canary file.
#[test]
fn eval_behind_a_descriptor_name_and_a_misread_coproc_are_opaque() {
    // (row, the command that must be opaque: the last one with this name)
    let rows: &[(&str, &str)] = &[
        (r#"y='>y'; {x}>f eval "$y""#, "eval"),
        (r#"y='>y'; a=1 {x}>f eval "$y""#, "eval"),
        (r#"y='>y'; >g {x}>f eval "$y""#, "eval"),
        (r#"y='>y'; {x}>f {z}>g eval "$y""#, "eval"),
        (r#"y='>y'; command {x}>f eval "$y""#, "command"),
        (r#"y='>y'; builtin {x}>f eval "$y""#, "builtin"),
        (r#"y='>y'; ! {x}>f eval "$y""#, "eval"),
        (r#"y='>y'; time {x}>f eval "$y""#, "eval"),
        (r#"y='>y'; coproc {x}>f eval "$y"; wait"#, "eval"),
        (r#"y='>y'; {x}>f eval "$y" | cat"#, "eval"),
        (r#"y='>y'; f() { {x}>f eval "$y"; }; f"#, "eval"),
        (r#"y='>y'; {a[0]}>f eval "$y""#, "eval"),
        (r#"y='>y'; {x}<<<z eval "$y""#, "eval"),
        (r#"y='>y'; {x}>>f eval "$y""#, "eval"),
        (r#"y='>y'; {x}<>f eval "$y""#, "eval"),
        (r#"y='>y'; {x}>|f eval "$y""#, "eval"),
        ("y='>y'; {x}<<E eval \"$y\"\nE", "eval"),
        (r#"y='>y'; exec 3>f; {x}>&3 eval "$y""#, "eval"),
        (r#"y='>y'; {x}>f eval "$y" {z}>g"#, "eval"),
        (r#"y='>y'; if :; then {x}>f eval "$y"; fi"#, "eval"),
        (r#"y='>y'; {x}>f eval "$y" && :"#, "eval"),
        (r#"y='>y'; {x}>f command eval "$y""#, "command"),
        (r#"y='>y'; {x}>f builtin eval "$y""#, "builtin"),
        (r#"y='>y'; {x}>f eval {z}>g "$y""#, "eval"),
        (r#"y='>y'; {x}>f eval "$y"; {x}>f :"#, "eval"),
        (r#"y='>y'; : > f; {x}<f eval "$y""#, "eval"),
        (r#"y='>y'; {x}>f a=1 eval "$y""#, "eval"),
        ("y='>y'; {x\\\n}>f eval \"$y\"", "{x}"),
        (r#"x='a[$(>y)]'; coproc C [[ x -eq 1 ]]; wait"#, "[["),
        (r#"x='a[$(>y)]'; coproc PATH [[ x -eq 1 ]]; wait"#, "[["),
        (r#"x='a[$(>y)]'; coproc C [[ 1 -eq x ]]; wait"#, "[["),
        (r#"x='a[$(>y)]'; coproc C [[ x -eq 1 ]] && :; wait"#, "[["),
        (
            r#"x='a[$(>y)]'; coproc C [[ x == 1 || x -lt 2 ]]; wait"#,
            "[[",
        ),
        (r#"y='>y'; coproc C [[ 1 ]]; eval "$y"; wait"#, "[["),
    ];
    // Every failing row is listed, not only the first.
    let mut bad = Vec::new();
    for (src, name) in rows {
        let s = ok(src);
        let c = commands(&s);
        match c.iter().rev().find(|c| bash_util::name_of(c) == *name) {
            None => bad.push(format!("no {name}: {src}")),
            Some(c) if !c.opaque => bad.push(format!("not opaque: {src}")),
            Some(_) => {}
        }
    }
    assert!(bad.is_empty(), "{} rows: {bad:#?}", bad.len());
}

/// A command that writes a name the lowering cannot read (a name that is not static or no name,
/// an option letter it does not know, `${x:=…}`) is opaque: the write may reach any name. Outside
/// any command (`case`, a `coproc` name) the text gets an opaque `((` command. A static name, a
/// known option, and `let` (arithmetic, read like the same text outside it) mark nothing.
#[test]
fn a_write_to_a_name_the_lowering_cannot_read_is_opaque() {
    // (row, the command that must be opaque: the last one with this name)
    let opaque: &[(&str, &str)] = &[
        ("read \"$v\" <<< 1", "read"),
        ("read -k x", "read"),
        ("mapfile -k a < f", "mapfile"),
        ("getopts ab", "getopts"),
        ("wait -n -p \"$v\"", "wait"),
        ("o=-v; printf $o n %s 1", "printf"),
        ("printf -v", "printf"),
        ("declare -i \"$k=1\"", "declare"),
        ("declare \"$k=1\"", "declare"),
        ("declare 'x:-y=1'", "declare"),
        ("echo \"${a[x]:=d}\"", "echo"),
        ("echo \"${a[x]=}\"", "echo"),
        ("declare -i n; : ${n:='a[$(rm -rf y)]'}", ":"),
        ("[[ ${x:=1} == 1 ]]", "[["),
        ("(( ${x:=1} ))", "(("),
        ("case ${x:=a} in *) ;; esac", "(("),
        ("x=PATH; coproc $x { :; }; wait", "(("),
        ("x=C; coproc $x [[ 1 ]]; wait", "(("),
    ];
    let plain = [
        "read -r -a arr < f",
        "read -rs -p x n < f",
        "mapfile -t a < f",
        "getopts ab o",
        "wait -n -p x",
        "printf -v n %s 1",
        "declare x=1 'y=2'",
        "let \"n = $(git rev-list --count HEAD)\"",
        "let $v",
        "coproc C { :; }; wait",
    ];
    let mut bad = Vec::new();
    for (src, name) in opaque {
        let s = ok(src);
        let c = commands(&s);
        match c.iter().rev().find(|c| bash_util::name_of(c) == *name) {
            None => bad.push(format!("no {name}: {src}")),
            Some(c) if !c.opaque => bad.push(format!("not opaque: {src}")),
            Some(_) => {}
        }
    }
    for src in plain {
        if commands(&ok(src)).iter().any(|c| c.opaque) {
            bad.push(format!("opaque: {src}"));
        }
    }
    assert!(bad.is_empty(), "{} rows: {bad:#?}", bad.len());
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
        ("~/bin/rm -rf x", BashProfile::Posix, Some("rm")),
        (
            "~/bin/GIT.exe clean -fdx",
            BashProfile::GitBash,
            Some("git"),
        ),
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
    let (pre, post) = match kind {
        k if k.starts_with("test_") => ("[[ ", " ]]"),
        k if k.starts_with("let_") => ("let 'a[", "]'"),
        "masked_arith" => ("(( ", " ))"),
        _ => ("", ""),
    };
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
        // `!` and `&&`/`||` recurse in the parser without opening a bracket or a keyword.
        "bang" => ("! ", "true", ""),
        "coproc" => ("coproc ", "true", ""),
        "test_not" => ("! ", "-n x", ""),
        "test_and" => ("x && ", "x", ""),
        "test_or" => ("x || ", "x", ""),
        "test_paren" => ("( ", "x", " )"),
        "test_not_paren" => ("! ( ", "x", " )"),
        "test_masked_paren" => ("] || ( ", "x", " )"),
        // Parameter offsets and subscripts bash evaluates as arithmetic.
        "offset" => ("echo ${s:0:", "1", "}"),
        "let_bracket" => ("a[", "$(rm x)", "]"),
        "let_quoted" => ("\"]\"", "$(rm x)", ""),
        // Nested `$((` that a bracket count misses, read by the arithmetic scan.
        "masked_arith" => ("$((]] + ", "1", "))"),
        _ => unreachable!(),
    };
    format!("{pre}{}{mid}{}{post}", open.repeat(n), close.repeat(n))
}

/// Each construct and the guard that must refuse 64 KiB of it.
const BRACKETS: &str = "brackets nested deeper than 200 levels";
const LOWERING: &str = "nesting deeper than 200 levels";
const BUDGET: &str = "nested text too large to parse in time";
/// 64 KiB of a two-byte operator (`! `) is 32k levels: past the stack cap in a debug build, which
/// sizes 64 KiB per level; a release build (16 KiB per level) parses it and lowering decides.
const STACK_CAP: &str = "nesting too deep to parse safely";
const PARSES: &str = "parses";
const NESTED_KINDS: [(&str, &str); 27] = [
    ("masked_arith", BUDGET),
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
    // `! ! … cmd` is one negated pipeline, but every `!` counts toward the stack bound.
    (
        "bang",
        if cfg!(debug_assertions) {
            STACK_CAP
        } else {
            PARSES
        },
    ),
    (
        "test_not",
        if cfg!(debug_assertions) {
            STACK_CAP
        } else {
            LOWERING
        },
    ),
    ("coproc", LOWERING),
    ("test_and", LOWERING),
    ("test_or", LOWERING),
    ("test_paren", BRACKETS),
    ("test_not_paren", BRACKETS),
    ("test_masked_paren", LOWERING),
    ("offset", BRACKETS),
    ("let_bracket", BRACKETS),
    // One subscript holding many quoted `]`: flat, but every `"` counts toward the stack bound.
    (
        "let_quoted",
        if cfg!(debug_assertions) {
            STACK_CAP
        } else {
            PARSES
        },
    ),
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
        if guard == PARSES {
            assert!(got.is_ok(), "{kind}: {got:?}");
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
            for c in commands(&s) {
                if !c.name.parts.is_empty() && c.canonical.is_none() {
                    assert!(
                        c.opaque,
                        "a name no rule can match must be opaque: {:?}",
                        r.command
                    );
                }
            }
        }
    }
}

#[test]
fn command_shapes_render_arguments() {
    let s = ok("X=1 rm -rf \"$d\" $(git x)");
    assert_eq!(command_shape(commands(&s)[0]), "X=1 rm -rf $ $()");
}

/// A `{NAME}` word that touches a redirect operator is no word of the command: the command keeps
/// its name and operands, an assignment before it is bash's, and the commands in a subscript stay.
/// With a space bash runs `{NAME}`. The words of a misread `coproc NAME [[ … ]]` are no commands.
#[test]
fn descriptor_names_leave_the_word_list() {
    let rows: &[(&str, &[&str])] = &[
        ("{x}>f echo hi", &["echo hi"]),
        ("exec {x}>f", &["exec"]),
        ("echo {x}", &["echo {x}"]),
        ("{x}>f exec bash -c", &["exec bash -c"]),
        (r#"{x}>f exec bash -c "$y""#, &["exec bash -c $"]),
        ("{x}>f a=1 echo hi", &["a=1 echo hi"]),
        ("{x}>f PATH=10", &["PATH=10 <none>"]),
        (": {a[$(rm -rf x)]}>f", &["a=$() :", "rm -rf x"]),
        ("{x} >f eval", &["{x} eval"]),
        ("{x}>f <(:) a", &["$() a", ":"]),
        ("coproc C [[ x == 1 || x -lt 2 ]]; wait", &["[[", "wait"]),
    ];
    let bad: Vec<String> = rows
        .iter()
        .filter_map(|(src, want)| {
            let got = parse(src, BashProfile::GitBash).map(|s| {
                commands(&s)
                    .into_iter()
                    .map(command_shape)
                    .collect::<Vec<_>>()
            });
            let pass = got.as_ref().is_ok_and(|g| g == want);
            (!pass).then(|| format!("{src}: {got:?}"))
        })
        .collect();
    assert!(bad.is_empty(), "{} rows: {bad:#?}", bad.len());
}
