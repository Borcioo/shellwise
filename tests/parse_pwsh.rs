//! PowerShell lowered to the IR: what the rules read from a command.

use shellwise::ir::{
    ChainOp, Elem, EnvView, MAX_NESTING, Quote, Script, SimpleCommand, Stmt, Word, WordPart,
};
use shellwise::parse::pwsh::parse;
use shellwise::{Os, Shell};

fn win(src: &str) -> Script {
    parse(src, Shell::Pwsh, Os::Windows).unwrap_or_else(|e| panic!("{src:?}: {e:?}"))
}

/// Every command in the script, nested ones too, in source order.
fn commands(s: &Script) -> Vec<&SimpleCommand> {
    let mut out = Vec::new();
    collect(s, &mut out);
    out.sort_by_key(|c| c.span.start);
    out
}

fn collect<'a>(s: &'a Script, out: &mut Vec<&'a SimpleCommand>) {
    for st in &s.stmts {
        match st {
            Stmt::Pipeline(p) => {
                for e in &p.elems {
                    match e {
                        Elem::Cmd(c) => {
                            if !c.typed.is_empty() {
                                out.push(c);
                            }
                            for w in c.args.iter().chain(std::iter::once(&c.name)) {
                                word(w, out);
                            }
                            for (_, w) in &c.assigns {
                                word(w, out);
                            }
                        }
                        Elem::Method(m) => m.args.iter().for_each(|w| word(w, out)),
                        Elem::Expr(w) => word(w, out),
                    }
                }
            }
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                collect(body, out)
            }
            Stmt::Cond { branches, .. } => branches.iter().for_each(|b| collect(b, out)),
        }
    }
}

fn word<'a>(w: &'a Word, out: &mut Vec<&'a SimpleCommand>) {
    for p in &w.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = p {
            collect(s, out);
        }
    }
}

fn only(src: &str) -> SimpleCommand {
    let s = win(src);
    let c = commands(&s);
    assert_eq!(c.len(), 1, "{src:?}: {c:?}");
    c[0].clone()
}

fn lit(s: &str) -> WordPart {
    WordPart::Literal(s.to_string())
}

fn var(s: &str) -> WordPart {
    WordPart::Var(s.to_string())
}

#[test]
fn remove_item_resolves_and_keeps_a_static_target() {
    let c = only(r"Remove-Item -Recurse -Force 'C:\x'");
    assert_eq!(c.canonical.as_deref(), Some("remove-item"));
    let last = c.args.last().unwrap();
    assert_eq!(last.static_value(&EnvView::new()).as_deref(), Some(r"C:\x"));
    assert_eq!(last.quote, Quote::Single);
    assert!(!c.opaque);
}

#[test]
fn a_variable_target_is_dynamic_and_its_assignment_is_recorded() {
    let s = win("$p = 'a'; ri $p");
    let Stmt::Pipeline(first) = &s.stmts[0] else {
        panic!("{s:?}")
    };
    let Elem::Cmd(assign) = &first.elems[0] else {
        panic!("{first:?}")
    };
    assert_eq!(assign.typed, "");
    assert_eq!(assign.assigns.len(), 1);
    assert_eq!(assign.assigns[0].0, "p");
    assert_eq!(assign.assigns[0].1.parts, vec![lit("a")]);
    let ri = commands(&s)[0];
    assert_eq!(ri.canonical.as_deref(), Some("remove-item"));
    assert!(ri.args[0].is_dynamic());
    assert_eq!(ri.args[0].parts, vec![var("p")]);
}

#[test]
fn assignment_targets_name_the_variables_they_set() {
    let cases: &[(&str, &[&str])] = &[
        ("$o=git status", &["o"]),
        ("${o} = git status", &["o"]),
        ("$a.b = git status", &["a"]),
        ("$a[0] = git status", &["a"]),
        ("$a, $b = git status", &["a", "b"]),
        ("[string] $o = git status", &["o"]),
        ("$env:X = 'v'", &["env:X"]),
    ];
    for (src, names) in cases {
        let s = win(src);
        let Stmt::Pipeline(p) = &s.stmts[0] else {
            panic!("{src}: {s:?}")
        };
        let Elem::Cmd(c) = &p.elems[0] else {
            panic!("{src}: {p:?}")
        };
        let got: Vec<&str> = c.assigns.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(&got, names, "{src}");
        // The assigned command runs once and stays visible.
        let n = commands(&s).iter().filter(|c| c.typed == "git").count();
        assert_eq!(n, usize::from(src.contains("git")), "{src}");
    }
}

#[test]
fn foreach_body_is_a_loop() {
    let s = win("foreach ($w in 'a','b') { git worktree remove $w }");
    let lp = s.stmts.iter().find(|st| matches!(st, Stmt::Loop { .. }));
    let Some(Stmt::Loop { body, .. }) = lp else {
        panic!("{s:?}")
    };
    let git = commands(body)[0];
    assert_eq!(git.typed, "git");
    assert!(git.in_loop);
    assert_eq!(git.args.last().unwrap().parts, vec![var("w")]);
}

#[test]
fn here_strings_are_one_word() {
    let c = only("Write-Output @'\nit's \"here\"\n'@");
    assert_eq!(c.args.len(), 1);
    assert_eq!(c.args[0].parts, vec![lit("it's \"here\"")]);
    let c = only("Write-Output @\"\nit's $x\n\"@");
    assert_eq!(c.args.len(), 1);
    assert_eq!(c.args[0].parts, vec![lit("it's "), var("x")]);
    // A CR-only here-string ends at its CR line.
    let s = win("$t = @'\rit's\r'@\rgit status");
    assert_eq!(commands(&s).last().unwrap().typed, "git");
}

#[test]
fn a_call_by_path_names_the_program() {
    let c = only(r"& 'C:\Program Files\Git\cmd\git.exe' status");
    assert_eq!(c.typed, r"C:\Program Files\Git\cmd\git.exe");
    assert!(!c.opaque);
    assert_eq!(c.canonical, None);
    assert_eq!(c.args[0].parts, vec![lit("status")]);
    let c = only("& $tool status");
    assert!(c.opaque);
    assert_eq!(c.canonical, None);
}

#[test]
fn a_static_method_call_spans_from_its_receiver() {
    let src = "$x = 1; [IO.Directory]::Delete($p, $true)";
    let s = win(src);
    let m = s
        .stmts
        .iter()
        .find_map(|st| match st {
            Stmt::Pipeline(p) => p.elems.iter().find_map(|e| match e {
                Elem::Method(m) => Some(m),
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{s:?}"));
    assert_eq!(m.span.start, src.find('[').unwrap());
    assert_eq!(m.type_name, "IO.Directory");
    assert_eq!(m.method, "Delete");
    assert_eq!(m.args.len(), 2);
    assert_eq!(m.args[0].parts, vec![var("p")]);
}

#[test]
fn a_script_block_argument_holds_its_commands() {
    let s = win("Get-ChildItem | % { ri -r $_ }");
    let pct = commands(&s)[1];
    assert_eq!(pct.canonical.as_deref(), Some("foreach-object"));
    let [WordPart::Block(body)] = pct.args[0].parts.as_slice() else {
        panic!("{pct:?}")
    };
    let ri = commands(body)[0];
    assert_eq!(ri.canonical.as_deref(), Some("remove-item"));
    assert!(ri.in_loop, "ForEach-Object runs its block per object");
}

#[test]
fn aliases_follow_the_dialect_and_os() {
    let rm = |os| parse("rm x", Shell::Pwsh, os).unwrap();
    assert_eq!(commands(&rm(Os::Posix))[0].canonical, None);
    assert_eq!(
        commands(&rm(Os::Windows))[0].canonical.as_deref(),
        Some("remove-item")
    );
    let ri = parse("ri x", Shell::Pwsh, Os::Posix).unwrap();
    assert_eq!(commands(&ri)[0].canonical.as_deref(), Some("remove-item"));
    // Windows PowerShell 5.1 still has `curl` as an alias, PowerShell 7 does not.
    let curl = |sh| parse("curl x", sh, Os::Windows).unwrap();
    assert_eq!(
        commands(&curl(Shell::Powershell5))[0].canonical.as_deref(),
        Some("invoke-webrequest")
    );
    assert_eq!(commands(&curl(Shell::Pwsh))[0].canonical, None);
    // Case and a module qualifier do not hide the command.
    for src in [
        "REMOVE-ITEM x",
        r"Microsoft.PowerShell.Management\Remove-Item x",
    ] {
        assert_eq!(only(src).canonical.as_deref(), Some("remove-item"), "{src}");
    }
    assert_eq!(only(r".\rm x").canonical, None);
    assert_eq!(only("git status").canonical, None);
}

#[test]
fn a_command_inside_a_syntax_error_fails_the_parse() {
    for src in [
        r"Write-Output (; Remove-Item -Recurse -Force C:\x",
        "Remove-Item -Recurse $p }",
        "Remove-Item 'x",
        "$x = (; ri -r y",
    ] {
        let e = parse(src, Shell::Pwsh, Os::Windows).expect_err(src);
        assert!(e.message.contains("syntax error"), "{src}: {e:?}");
    }
    let e = parse("Remove-Item 'x", Shell::Pwsh, Os::Windows).unwrap_err();
    assert_eq!(e.unclosed, Some(shellwise::parse::QuoteKind::Single));
    let e = parse("Remove-Item \"x", Shell::Pwsh, Os::Windows).unwrap_err();
    assert_eq!(e.unclosed, Some(shellwise::parse::QuoteKind::Double));
}

#[test]
fn a_missing_closer_names_what_is_missing() {
    let e = parse("if ($a) { Remove-Item x", Shell::Pwsh, Os::Windows).unwrap_err();
    assert!(e.message.contains("missing `}`"), "{e:?}");
}

#[test]
fn a_subexpression_inside_a_quoted_part_of_a_word_fails_closed() {
    // The `$(…)` runs in PowerShell; the tree reads the word as text.
    for src in [
        r#"Write-Output a"$(Remove-Item x)""#,
        r#"Write-Output a"b$(ri x)c""#,
    ] {
        let e = parse(src, Shell::Pwsh, Os::Windows).expect_err(src);
        assert!(e.message.contains("subexpression"), "{src}: {e:?}");
    }
}
#[test]
fn a_colon_the_grouping_would_drop_fails_closed() {
    // PowerShell keeps `:b` as text; the elements would lose the colon.
    let e = parse("Write-Output (1):b", Shell::Pwsh, Os::Windows).unwrap_err();
    assert!(e.message.contains("not modelled"), "{e:?}");
}

#[test]
fn chains_record_their_operators() {
    let s = win("a && b || c; d");
    let chains: Vec<Option<ChainOp>> = s
        .stmts
        .iter()
        .map(|st| match st {
            Stmt::Pipeline(p) => p.chain,
            _ => panic!("{st:?}"),
        })
        .collect();
    assert_eq!(
        chains,
        vec![
            Some(ChainOp::And),
            Some(ChainOp::Or),
            Some(ChainOp::Seq),
            None
        ]
    );
    assert_eq!(
        s.joins,
        vec![
            None,
            Some(ChainOp::And),
            Some(ChainOp::Or),
            Some(ChainOp::Seq)
        ]
    );
    let s = win("npm run dev &");
    let Stmt::Pipeline(p) = &s.stmts[0] else {
        panic!()
    };
    assert_eq!(p.chain, Some(ChainOp::Background));
    // Windows PowerShell 5.1 has no `&&` or `||`: the command would not run there.
    assert!(parse("a && b", Shell::Powershell5, Os::Windows).is_err());
}

#[test]
fn comments_are_collected_with_their_place() {
    let s = win("git status # shellwise: allow\n# own line\ngit log");
    let got: Vec<(&str, bool)> = s
        .comments
        .iter()
        .map(|c| (c.text.as_str(), c.trailing))
        .collect();
    assert_eq!(
        got,
        vec![("# shellwise: allow", true), ("# own line", false)]
    );
    // `#` inside a string or after an escape is text, not a comment.
    let s = win("echo \"`n# a\" 'b # c' a`#b");
    assert!(s.comments.is_empty(), "{:?}", s.comments);
}

#[test]
fn redirections_are_not_arguments() {
    let c = only("git status 2>$null");
    assert!(c.args.iter().all(|a| a.parts != vec![lit("2>$null")]));
    assert_eq!(c.args.len(), 1);
    let r = &c.redirects[0];
    assert_eq!(
        (r.op.as_str(), r.target.parts.clone()),
        ("2>", vec![var("null")])
    );
    let c = only("cmd /c x 2>&1");
    assert_eq!(
        (
            c.redirects[0].op.as_str(),
            c.redirects[0].target.parts.clone()
        ),
        ("2>&", vec![lit("1")])
    );
    let c = only("echo x *> out.txt");
    assert_eq!(c.redirects[0].op, "*>");
    let c = only("echo x 1> out.txt");
    assert_eq!(c.redirects[0].op, "1>");
    // Inside a word `>` is text: PowerShell reads `a>b` as one argument.
    let c = only("echo a>b");
    assert_eq!(c.args[0].parts, vec![lit("a>b")]);
}

#[test]
fn variables_glued_to_text_stay_one_dynamic_word() {
    let c = only(r"Remove-Item $env:TEMP\x");
    assert_eq!(c.args[0].parts, vec![var("env:TEMP"), lit(r"\x")]);
    let c = only(r"Remove-Item $d\sub");
    assert_eq!(c.args[0].parts, vec![var("d"), lit(r"\sub")]);
    let c = only("Write-Output ${name}:");
    assert_eq!(c.args[0].parts, vec![var("name"), lit(":")]);
    // A subexpression glued to the end of a word is part of it, never a path ending in `$`.
    let c = only(r"git worktree remove --force F:\w\$($p[0])");
    let last = c.args.last().unwrap();
    assert!(last.is_dynamic(), "{last:?}");
    assert_eq!(last.parts[0], lit(r"F:\w\"));
    assert!(matches!(last.parts[1], WordPart::Subst(_)));
    assert_eq!(c.args.len(), 4);
}

#[test]
fn a_parenthesised_range_is_an_expression_not_a_command() {
    let s = win("(1..5) | % { ri $_ }");
    let names: Vec<&str> = commands(&s).iter().map(|c| c.typed.as_str()).collect();
    assert_eq!(names, vec!["%", "ri"]);
    let c = only("Get-Content x -TotalCount (1MB)");
    assert_eq!(c.args.len(), 3);
}

#[test]
fn member_calls_keep_their_argument_lists() {
    let s = win("Where-Object LastWriteTime -gt (Get-Date).AddDays(-5)");
    let c = commands(&s)[0];
    assert_eq!(c.args.len(), 3);
    assert!(c.args[2].is_dynamic());
    let s = win("Write-Output $x.Trim('a') 'b'");
    assert_eq!(commands(&s)[0].args.len(), 2);
    let c = only("Write-Output -split '\\s+'");
    assert_eq!(c.args.len(), 2);
}

#[test]
fn unicode_separators_and_typographic_quotes_read_as_powershell_does() {
    for sep in ['\u{a0}', '\u{3000}', '\u{2002}'] {
        let s = win(&format!("Get-Date;{sep}git status"));
        let names: Vec<&str> = commands(&s).iter().map(|c| c.typed.as_str()).collect();
        assert_eq!(names, vec!["Get-Date", "git"], "{sep:?}");
    }
    let s = win("Get-Date\u{a0}# don't\ngit status");
    assert_eq!(s.comments.len(), 1);
    let s = win("$x = \u{2018}literal\u{2019}; git checkout $w");
    let names: Vec<&str> = commands(&s).iter().map(|c| c.typed.as_str()).collect();
    assert_eq!(names, vec!["git"]);
}

#[test]
fn stop_parsing_passes_the_rest_as_written() {
    let c = only("Write-Output --% don't");
    let args: Vec<Vec<WordPart>> = c.args.iter().map(|a| a.parts.clone()).collect();
    assert_eq!(args, vec![vec![lit("--%")], vec![lit("don't")]]);
}

/// How a comma argument lowers (Task 9 reads it): one word, separators as their own
/// `ListSep` parts; a quoted or escaped comma is text.
#[test]
fn comma_lists_are_one_word_with_separator_parts() {
    let sep = || WordPart::ListSep;
    let cases: Vec<(&str, Vec<WordPart>, Quote)> = vec![
        ("a,b", vec![lit("a"), sep(), lit("b")], Quote::None),
        ("a, b", vec![lit("a"), sep(), lit("b")], Quote::None),
        (
            "Env:A,Env:B",
            vec![lit("Env:A"), sep(), lit("Env:B")],
            Quote::None,
        ),
        ("a,$b", vec![lit("a"), sep(), var("b")], Quote::None),
        ("'a','b'", vec![lit("a"), sep(), lit("b")], Quote::Mixed),
        ("\"a\",b", vec![lit("a"), sep(), lit("b")], Quote::Mixed),
        // A path ending in `\` inside quotes: two targets, not one Mixed word.
        (
            "\"C:\\\",x",
            vec![lit("C:\\"), sep(), lit("x")],
            Quote::Mixed,
        ),
        (
            "'C:\\','x'",
            vec![lit("C:\\"), sep(), lit("x")],
            Quote::Mixed,
        ),
        // Quoted and escaped commas are text.
        ("'a,b'", vec![lit("a,b")], Quote::Single),
        ("\"a,b\"", vec![lit("a,b")], Quote::Double),
        ("a`,b", vec![lit("a,b")], Quote::Mixed),
        ("a`,`b", vec![lit("a,b")], Quote::Mixed),
        (
            "-Path:a,b",
            vec![lit("-Path:a"), sep(), lit("b")],
            Quote::None,
        ),
    ];
    for (arg, parts, quote) in cases {
        let src = format!("Remove-Item {arg}");
        let c = only(&src);
        assert_eq!(c.args.len(), 1, "{src}: {:?}", c.args);
        assert_eq!(c.args[0].parts, parts, "{src}");
        assert_eq!(c.args[0].quote, quote, "{src}");
        assert_eq!(c.args[0].span.end, src.len(), "{src}");
    }
    // PowerShell also reads `a ,b` as one list; the grammar does not, so it fails closed.
    assert!(parse("Remove-Item a ,b", Shell::Pwsh, Os::Windows).is_err());
    // A native program gets the same word.
    let c = only("git log a,b");
    assert_eq!(c.args[1].parts, vec![lit("a"), sep(), lit("b")]);
    // An expression-mode list carries the same separators.
    let s = win("$x = 'a','b'");
    let Stmt::Pipeline(p) = &s.stmts[0] else {
        panic!("{s:?}")
    };
    let Elem::Cmd(c) = &p.elems[0] else {
        panic!("{p:?}")
    };
    let [WordPart::Subst(v)] = c.assigns[0].1.parts.as_slice() else {
        panic!("{c:?}")
    };
    let Stmt::Pipeline(p) = &v.stmts[0] else {
        panic!("{v:?}")
    };
    let Elem::Expr(w) = &p.elems[0] else {
        panic!("{p:?}")
    };
    assert_eq!(w.parts, vec![lit("a"), sep(), lit("b")]);
    // `@(…)` runs its contents: a substitution, never a static list.
    assert!(only("Remove-Item @('C:\','x')").args[0].is_dynamic());
}

fn depth_error(src: &str) -> Option<String> {
    parse(src, Shell::Pwsh, Os::Windows)
        .err()
        .map(|e| e.message)
}

/// Each way the text opens a nesting level: depth `MAX_NESTING` lowers, one more is refused by
/// the nesting cap (not by a syntax error), and 64 KiB of it returns without overflowing.
#[test]
fn nesting_is_capped_for_every_bracket_form() {
    type Shape = fn(usize) -> String;
    let shapes: &[(&str, Shape)] = &[
        ("(", |n| format!("{}1{}", "(".repeat(n), ")".repeat(n))),
        ("$(", |n| format!("{}{}", "$(".repeat(n), ")".repeat(n))),
        ("@(", |n| format!("{}{}", "@(".repeat(n), ")".repeat(n))),
        ("& {", |n| format!("{}1{}", "& {".repeat(n), "}".repeat(n))),
        ("if", |n| {
            format!("{}{}", "if (1) {".repeat(n), "}".repeat(n))
        }),
        ("@{", |n| format!("{}1{}", "@{a=".repeat(n), "}".repeat(n))),
        ("=", |n| format!("{}1", "$a=".repeat(n))),
        ("\"$(", |n| {
            format!("{}{}", "\"$(".repeat(n), ")\"".repeat(n))
        }),
    ];
    for (name, shape) in shapes {
        let ok = shape(MAX_NESTING);
        assert_eq!(depth_error(&ok), None, "{name} at {MAX_NESTING}");
        let over = depth_error(&shape(MAX_NESTING + 1));
        assert!(
            over.as_deref()
                .is_some_and(|m| m.contains("nesting deeper than 200")),
            "{name} at {}: {over:?}",
            MAX_NESTING + 1
        );
        let n = 64 * 1024 / shape(1).len();
        let big = depth_error(&shape(n));
        assert!(big.is_some(), "{name} x{n}");
    }
}

/// Operator chains and prefix operators are walked without recursion: 64 KiB of each lowers.
#[test]
fn long_operator_chains_do_not_overflow() {
    let n = 64 * 1024;
    let shapes = [
        format!("{}$a", "-not ".repeat(n / 5)),
        format!("{}$a", "!".repeat(n)),
        format!("{}$a", ",".repeat(n)),
        format!("{}$a", "[int]".repeat(n / 5)),
        format!("$a{}", "+$a".repeat(n / 3)),
        format!("$a{}", " -and $a".repeat(n / 8)),
        format!("$a{}", ".b".repeat(n / 2)),
        format!("$a{}", "[0]".repeat(n / 3)),
        format!("a{}", " | a".repeat(n / 4)),
        "a;".repeat(n / 2),
        format!("(1){}", "(".repeat(n)),
    ];
    for s in &shapes {
        // Lowered, or refused with an error; never a crash.
        let _ = parse(s, Shell::Pwsh, Os::Windows);
    }
    assert!(parse(&shapes[0], Shell::Pwsh, Os::Windows).is_ok());
    assert!(parse(&format!("(1){}", "(".repeat(n)), Shell::Pwsh, Os::Windows).is_err());
}

#[test]
fn bash_is_not_a_powershell_dialect() {
    let e = parse("ls", Shell::Bash(shellwise::BashProfile::Posix), Os::Posix).unwrap_err();
    assert!(e.message.contains("not a PowerShell dialect"));
}

#[test]
fn an_instance_call_at_a_pipeline_head_is_a_method_call_with_its_receiver() {
    let s = win("$x.Delete($true)");
    let [Stmt::Pipeline(p)] = s.stmts.as_slice() else {
        panic!("{s:?}");
    };
    let [Elem::Method(m)] = p.elems.as_slice() else {
        panic!("{p:?}");
    };
    assert_eq!(m.type_name, "");
    assert_eq!(m.method, "Delete");
    assert_eq!(m.args.len(), 2, "{m:?}");
    assert_eq!(m.args[0].parts, vec![var("x")]);
}
