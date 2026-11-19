//! `parse::pwsh` against the real PowerShell parser (`pwsh -NoProfile`, `Parser::ParseInput`).
//! Feature `oracle`: needs `pwsh` on PATH and fails when it is missing.
//!
//! 1. Every row of `tests/cases/pwsh_gaps.toml` and `pwsh_mechanisms.toml`: PowerShell's answer
//!    must equal the row's recorded answer, and the parser must give it.
//! 2. A differential fuzz: seeded mutations of those rows at token boundaries (comment, quote,
//!    escape and whitespace variants). The parser may refuse a mutant PowerShell accepts (that
//!    fails closed) and must never read a mutant PowerShell accepts differently, except the
//!    `LISTED` ones. It may accept a mutant PowerShell rejects, since PowerShell runs nothing of
//!    a script it cannot parse; the test counts and prints those.
#![cfg(feature = "oracle")]

use std::process::Command;

use serde::{Deserialize, Serialize};
use shellwise::parse::pwsh;
use shellwise::{Os, Shell};

/// Seeds and size (per seed) of the differential fuzz.
const SEEDS: [u64; 10] = [
    0x5EED_0005,
    0x5EED_0006,
    0x5EED_0007,
    0x5EED_0008,
    0x5EED_0009,
    0x5EED_000A,
    0x5EED_000B,
    0x5EED_000C,
    0x5EED_000D,
    0x5EED_000E,
];
const MUTANTS: usize = 2_000;

/// The rows the gate's fuzz mutates, pinned at fix round 3's start: rows added later are not
/// seeds, so a new row cannot change the mutants. Order matters: seeds are picked by index.
const SEED_ROWS: &[&str] = &[
    "glued-value",
    "glued-index",
    "glued-type",
    "glued-subexpr",
    "glued-array",
    "glued-paren",
    "glued-assign-eq",
    "glued-assign-comma",
    "glued-string",
    "glued-block-comment",
    "word-block-comment",
    "word-block-comment-quote",
    "nbsp-sep",
    "ff-sep",
    "ideographic-sep",
    "nbsp-comment",
    "cr-herestring",
    "stop-parsing",
    "assign-nospace",
    "assign-member",
    "assign-index",
    "assign-multi",
    "assign-typed-space",
    "assign-braced",
    "typographic-quote",
    "call-git-path",
    "cd-dotdot",
    "cd-backslash",
    "dotnet-delete",
    "var-glued-path",
    "env-glued-path",
    "comma-glued-vars",
    "multiplier",
    "multiplier-upper",
    "at-word",
    "param-glued-quote",
    "param-glued-dquote",
    "null-coalescing",
    "null-coalescing-assign",
    "null-conditional-member",
    "ternary",
    "switch-one-line",
    "escaped-quotes",
    "hash-after-escape",
    "early-error-delete",
    "foreach-method",
    "negative-number",
    "glued-redirect",
    "merge-redirect",
    "all-redirect",
    "lone-redirect",
    "redirect-char-in-word",
    "paren-range",
    "paren-range-var",
    "member-call",
    "member-after-herestring",
    "subexpr-glued-end",
    "subexpr-in-param",
    "braced-colon",
    "split-operator",
    "date-call",
    "comment-trailing",
    "comment-own-line",
    "comment-after-pipe",
    "comment-in-block",
    "comment-after-semicolon",
    "comment-block-multiline",
    "comment-hash-in-strings",
    "comment-in-param-block",
    "fuzz-bare-dash-glued-to-name",
    "fuzz-stop-parsing-glued",
    "fuzz-stop-parsing-after-quote",
    "fuzz-backtick-line-end-in-name",
    "fuzz-redirect-first",
    "fuzz-glued-comment-param",
    "fuzz-glued-comment-redirect",
    "fuzz-comment-after-quote",
    "fuzz-dollar-dollar-subexpr",
    "fuzz-subexpr-glued-to-name",
    "fuzz-bare-dash-glued-to-word",
    "fuzz-glued-comment-inside",
    "fuzz-odd-dollar-run-subexpr",
    "fuzz-stop-parsing-nbsp",
    "fuzz-redirect-glued-to-param",
    "fuzz-param-value-unicode-space",
    "fuzz-redirect-target-glued-word",
    "fuzz-hash-starts-comment",
    "fuzz-unicode-space-between-args",
    "fuzz-static-member-on-variable",
    "fuzz-redirect-after-string",
    "fuzz-one-dash-param-subexpr",
    "review-stop-parsing-pipe",
    "review-stop-parsing-quoted-pipe",
    "review-stop-parsing-or",
    "fix1-verbatim-and",
    "fix1-verbatim-and-glued",
    "fix1-verbatim-and-quoted",
    "fix1-verbatim-and-after-quote",
    "fix1-verbatim-and-tab",
    "fix1-verbatim-and-triple",
    "fix1-verbatim-and-backtick",
    "fix1-verbatim-pipe-backtick",
    "fix1-verbatim-lf",
    "fix1-verbatim-cr",
    "fix1-verbatim-crlf",
    "fix1-verbatim-unclosed-quote",
    "fix1-verbatim-unclosed-quote-lf",
    "fix1-verbatim-keeps-semicolon",
    "fix1-verbatim-keeps-amp",
    "fix1-verbatim-keeps-amp-amp-spaced",
    "fix1-verbatim-keeps-gt",
    "fix1-verbatim-keeps-merge",
    "fix1-verbatim-keeps-hash",
    "fix1-verbatim-trailing-amp",
    "fix1-verbatim-trailing-amp-lf",
    "fix1-param-one-dash-backtick-lf",
    "fix1-param-one-dash-backtick-recurse",
    "fix1-param-two-dash-backtick-lf",
    "fix1-param-two-dash-backtick-equals",
    "fix1-escaped-comma-ends-word",
    "fix1-escaped-comma-ab",
    "fix1-param-value-subexpr-two-dash",
    "fix1-param-value-subexpr-one-dash",
    "fix1-param-value-var",
    "fix1-param-value-bare-var",
    "fix1-param-value-single",
    "fix1-param-value-plain",
    "fix1-param-value-backtick-quote",
    "fix1-stmt-redirect-glued-comment",
    "fix1-expr-redirect-glued-comment",
    "fix1-expr-redirect-subst",
    "fix1-glued-stop-parsing",
    "fix1-subexpr-glued-text",
    "fix1-subexpr-glued-text-x",
    "fix1-instance-call-paren",
    "fix1-instance-call-var",
    "fix1-static-call-assigned",
    "fix1-instance-call-argument",
    "fix1-instance-call-second-statement",
    "fix1-instance-call-on-static",
    "fix1-verbatim-typographic-quotes",
    "fix1-stop-parsing-after-quote",
    "fix1-instance-call-foreach-block",
    "fix1-name-subexpr-constant",
    "fix1-escaped-stop-parsing",
    "fix1-foreach-block-after-line-end",
    "fix1-stop-parsing-after-double-quote",
    "fix1-command-redirect-glued-comment",
    "fix1-instance-call-assigned",
    "fix1-semicolon-after-redirect",
    "fix1-comment-glued-to-name",
    "fix2-r1-en-dash-param-backtick-lf",
    "fix2-r1-em-dash-param-backtick-lf",
    "fix2-r1-bar-dash-param-backtick-lf",
    "fix2-r1-en-dash-param-backtick-semicolon",
    "fix2-r1-en-dash-param-value-lf",
    "fix2-r1-param-value-rdq",
    "fix2-r1-param-value-ldq",
    "fix2-r1-param-value-bdq",
    "fix2-r1-param-value-rsq",
    "fix2-r1-param-value-lsq",
    "fix2-r1-param-value-bsq",
    "fix2-r1-param-value-revsq",
    "fix2-r1-one-dash-param-value-rdq",
    "fix2-r1-param-value-rdq-pipe",
    "fix2-r1-nel-splits",
    "fix2-r1-line-separator-splits",
    "fix2-r1-paragraph-separator-splits",
    "fix2-r1-line-separator-after-name",
    "fix2-r1-dash-param-in-subexpr",
    "fix2-r1-en-dash-in-single",
    "fix2-r1-em-dash-in-double",
    "fix2-r1-bar-in-single",
    "fix2-r1-lsq-in-double",
    "fix2-r1-rsq-in-double",
    "fix2-r1-bsq-revsq-in-double",
    "fix2-r1-ldq-rdq-in-single",
    "fix2-r1-bdq-in-single",
    "fix2-r1-line-separator-in-single",
    "fix2-r1-nel-in-double",
    "fix2-r1-in-comment",
    "fix2-r1-in-block-comment",
    "fix2-r1-in-here-string",
    "fix2-r1-in-expandable-here-string",
    "fix2-r1-doubled-rdq-in-double",
    "fix2-r1-doubled-rsq-in-single",
    "fix2-r1-closing-quote-then-word",
    "fix2-r1-word-section-lsq-rsq",
    "fix2-r1-word-section-bsq-revsq",
    "fix2-r1-word-section-ldq-rdq",
    "fix2-r1-word-section-bdq",
    "fix2-r1-word-section-hides-no-separator",
    "fix2-r1-mid-word-en-dash",
    "fix2-r1-mid-word-em-dash",
    "fix2-r1-mid-word-bar",
    "fix2-r1-in-subexpr",
    "fix2-r1-here-string-typographic-delimiters",
    "fix2-r1-verbatim-here-string-typographic-delimiters",
    "fix2-r1-word-start-dash-after-comma",
    "fix2-r1-line-separator-in-word-section",
    "fix2-r2-lt-after-target-lf",
    "fix2-r2-gt-after-target-lf",
    "fix2-r2-append-after-target-lf",
    "fix2-r2-star-after-target-lf",
    "fix2-r2-lt-blank-line",
    "fix2-r2-lt-comment-line",
    "fix2-r2-lt-block-comment",
    "fix2-r2-lt-crlf",
    "fix2-r2-lt-cr",
    "fix2-r2-lt-tab-lf",
    "fix2-r2-gt-lf",
    "fix2-r2-stream-lf",
    "fix2-r2-star-lf",
    "fix2-r2-append-lf",
    "fix2-r2-after-string-lf",
    "fix2-r2-after-paren-lf",
    "fix2-r2-after-merge-lf",
    "fix2-r2-statement-redirect-lf",
    "fix2-r2e-space-then-lf",
    "fix2-r2e-statement-space-then-lf",
    "fix2-r2-target-same-line",
    "fix2-r2-merge-then-lf",
    "fix2-r3-quoted-member",
    "fix2-r3-double-quoted-member",
    "fix2-r3-expandable-member",
    "fix2-r3-typographic-quoted-member",
    "fix2-r3-variable-member",
    "fix2-r3-braced-variable-member",
    "fix2-r3-paren-member",
    "fix2-r3-subexpr-member",
    "fix2-r3-array-member",
    "fix2-r3-index-then-quoted-member",
    "fix2-r3-chain-then-quoted-member",
    "fix2-r3-paren-receiver-quoted-member",
    "fix2-r3-paren-receiver-variable-member",
    "fix2-r3-env-quoted-member",
    "fix2-r3-null-conditional",
    "fix2-r3-null-conditional-variable-member",
    "fix2-r3-null-conditional-chain",
    "fix2-r3-null-conditional-index",
    "fix2-r3-env-null-conditional",
    "fix2-r3-member-then-null-conditional",
    "fix2-r3-braced-null-conditional",
    "fix2-r3-block-call",
    "fix2-r3-block-call-paren-receiver",
    "fix2-r3-block-call-paren-null-conditional",
    "fix2-r3-block-call-quoted-foreach",
    "fix2-r3-block-call-null-conditional-foreach",
    "fix2-r3-block-call-chain",
    "fix2-r3-block-call-variable-member",
    "fix2-r3-block-call-quoted-member",
    "fix2-r3-block-call-null-conditional",
    "fix2-r3-in-list-quoted-member",
    "fix2-r3-in-list-null-conditional",
    "fix2-r3-after-colon-quoted-member",
    "fix2-r3-after-colon-null-conditional",
    "fix2-r3-after-colon-block-call",
    "fix2-r3-simple-member-call",
    "fix2-r3-foreach-block",
    "fix2-r3-glued-paren-after-word",
    "fix2-r3-property-null-conditional",
    "fix2-param-value-trailing-comma-space",
    "fix2-param-value-trailing-comma-unicode-space",
    "fix2-param-value-trailing-comma-parameter",
    "fix2-r2-glued-redirect-comment",
    "fix2-r2-glued-redirect-gt",
    "fix2-r2-glued-redirect-semicolon",
    "fix2-r2-comment-before-target",
    "fix2-null-conditional-member-glued-comment",
    "fix2-null-conditional-index",
    "fix2-comma-backtick-line-end",
    "fix2-comma-block-comment",
    "fix2-dot-variable-word",
    "fix2-dot-subexpr-word",
    "fix2-dot-variable-glued-word",
    "fix2-dot-path-variable-word",
    "fix2-dot-single-quote-word",
    "fix2-dot-double-quote-word",
    "fix2-dot-single-quote-word-comment",
    "fix2-dot-typographic-single-quote-word",
    "fix2-dot-typographic-double-quote-word",
    "fix2-question-mark-after-variable",
    "fix2-question-marks-member-glued-comment",
    "fix2-question-mark-after-braced-variable",
    "fix2-question-mark-variable-kept",
    "fix2-comment-inside-name-redirect",
    "fix2-comment-inside-name-text",
    "fix2-i1-dot-typographic-name",
    "fix2-i1-dot-typographic-double-name",
    "fix2-i1-dot-ascii-quote-name",
    "fix2-i1-comment-in-static-call",
    "fix2-i1-number-member-statement",
    "fix2-i1-number-quoted-member-in-block",
    "fix2-i1-number-variable-member-in-block",
    "fix2-i1-question-mark-member-variable",
    "fix2-i1-dot-in-one-dash-value",
    "fix2-i1-dot-at-two-dash-value-start",
    "fix2-i1-dot-after-comma-in-value",
    "fix2-i1-dot-in-two-dash-value-kept",
    "fix2-i1-dot-list-element",
    "fix2-i1-index-after-string",
    "fix2-i1-member-after-string",
    "fix2-i1-index-after-here-string",
    "fix2-i1-question-word-after-string-kept",
    "fix2-i1-braced-variable-in-value",
    "fix2-i1-braced-variable-after-dollars",
    "fix2-i1-comment-in-member-target",
    "fix2-i2-number-dot-call",
    "fix2-i2-number-dot-call-plain",
    "fix2-i2-number-name-kept",
    "fix2-i2-member-line-end",
    "fix2-i2-member-lf",
    "fix2-i2-member-space-before-dot-kept",
    "fix2-i2-variable-dots-name",
    "fix2-i2-variable-dots-name-call",
    "fix2-i2-variable-path-name-kept",
    "fix2-i2-redirect-glued-to-name",
    "fix2-i2-redirect-glued-to-name-plain-kept",
    "fix2-i2-redirect-glued-to-variable-kept",
    "fix2-i2-redirect-after-quoted-name-kept",
    "fix2-i2-stop-parsing-escaped-after-quote",
    "fix2-i2-stop-parsing-escaped",
    "fix2-i2-stop-parsing-escaped-dash",
    "fix2-i2-stop-parsing-escaped-redirect",
    "fix2-i2-quote-dash-nbsp",
    "fix2-i2-quote-dash-param",
    "fix2-i2-quote-two-dash-param",
    "fix2-i2-one-dash-dot-end",
    "fix2-i2-one-dash-dot-name",
    "fix2-i2-one-dash-dot-plain",
    "fix2-i2-one-dash-dot-colon",
    "fix2-i2-one-dash-dot-space",
    "fix2-i2-one-dash-dot-dollars",
    "fix2-i2-one-dash-dot-question",
    "fix2-i2-one-dash-dot-quote-lf",
    "fix2-i2-colon-value-dot-kept",
    "fix2-i2-nel-before-comment",
    "fix2-i2-nel-before-string",
    "fix2-i2-nel-before-here-string",
    "fix2-i2-nel-in-comment",
    "fix2-i2-backtick-lf-after-glued-quote",
    "fix2-i2-backtick-lf-after-word-quote-kept",
    "fix2-i2-backtick-lf-after-quote-kept",
    "fix2-i2-comment-after-glued-backtick-lf-kept",
    "fix2-i2-comment-after-redirect-backtick-lf",
    "fix2-i2-comment-after-spaced-backtick-lf-kept",
    "fix2-i2-comment-in-two-dash-param",
    "fix2-i2-comment-in-one-dash-param",
];

/// Commands whose arguments the delete guard resolves: a disagreement in one of their
/// statements must be a refusal, never a listed shape.
const GUARDED: &[&str] = &[
    "remove-item",
    "ri",
    "rm",
    "rmdir",
    "del",
    "rd",
    "erase",
    "git",
    "robocopy",
    "cmd",
];

/// Text inserted at a token boundary: each member of PowerShell's dash, quote and extra space
/// classes, member and call forms, and a line end after each redirect operator.
const INSERTS: &[&str] = &[
    " ", "\t", "  ", "`", "#", "# x", "<#x#>", "'", "\"", "`\"", "''", "\u{00A0}", "\u{3000}",
    "\u{2018}", "\u{2019}", "\u{201A}", "\u{201B}", "\u{201C}", "\u{201D}", "\u{201E}", "\u{2013}",
    "\u{2014}", "\u{2015}", "\u{85}", "\u{2028}", "\u{2029}", ";", ",", "\r", "\n", "\r\n", "`\n",
    "$", "@", "(", ")", "{", "}", "--%", ">", "2>&1", ":", "-", "?.", "?[0]", ".'x'", ".$m",
    ".(\"x\")", "()", "{1}", ">\n", ">>\n", "2>\n", "2>>\n", "*>\n", "<\n", "$null<\n",
];

#[derive(Deserialize)]
struct File {
    row: Vec<Row>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Row {
    id: String,
    mechanism: Option<String>,
    /// `"refuses"`: the parser fails closed on a command PowerShell accepts.
    parser: Option<String>,
    command: String,
    error: bool,
    cmds: Vec<Vec<String>>,
    comments: Vec<String>,
    methods: Vec<String>,
}

#[derive(Serialize)]
struct Input<'a> {
    id: String,
    command: &'a str,
}

#[derive(Deserialize)]
struct Answer {
    id: String,
    error: bool,
    cmds: Vec<Vec<String>>,
    comments: Vec<String>,
    methods: Vec<String>,
}

impl Answer {
    fn seen(&self) -> pwsh::Seen {
        pwsh::Seen {
            cmds: self.cmds.clone(),
            comments: self.comments.clone(),
            methods: self.methods.clone(),
        }
    }
}

/// Reads each row with `ParseInput` and writes PowerShell's answer, one JSON object per line.
const ORACLE: &str = r#"
param([Parameter(Mandatory)][string]$In, [Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$L = [System.Management.Automation.Language.Parser]
$rows = [IO.File]::ReadAllText($In, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
$lines = [Collections.Generic.List[string]]::new()
foreach ($r in $rows) {
    $tokens = $null; $errors = $null
    $ast = $L::ParseInput([string]$r.command, [ref]$tokens, [ref]$errors)
    $cmds = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true) |
        Sort-Object { $_.Extent.StartOffset } |
        ForEach-Object { , @($_.CommandElements | ForEach-Object { $_.Extent.Text }) })
    $ms = [Collections.Generic.List[object]]::new(); foreach ($m in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) { $ms.Add([pscustomobject]@{ At = $m.Extent.StartOffset; Text = $m.Expression.Extent.Text + $(if ($m.Static) { '::' } else { '.' }) + $m.Member.Extent.Text }) }; $ms.Sort([Comparison[object]] { param($x, $y) $c = $x.At.CompareTo($y.At); if ($c -ne 0) { $c } else { [string]::CompareOrdinal($x.Text, $y.Text) } })
    $methods = @($ms | ForEach-Object Text)

    $comments = @($tokens | Where-Object Kind -eq 'Comment' | ForEach-Object Text)
    $lines.Add((ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{
        id = $r.id; error = ($errors.Count -gt 0); cmds = $cmds; comments = $comments; methods = $methods })))
}
[IO.File]::WriteAllText($Out, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
"PowerShell $($PSVersionTable.PSVersion) rows $($lines.Count)"
"#;

fn rows(name: &str) -> Vec<Row> {
    let path = format!("{}/tests/cases/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("read the rows file");
    let file: File = toml::from_str(&text).expect("rows toml");
    assert!(!file.row.is_empty(), "{name}: no rows");
    file.row
}

/// PowerShell's answer for each `(id, command)`, in order.
fn ask_powershell(tag: &str, inputs: &[Input]) -> Vec<Answer> {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pwsh_oracle_{tag}"));
    std::fs::create_dir_all(&dir).expect("create the oracle folder");
    let script = dir.join("oracle.ps1");
    let input = dir.join("in.json");
    let output = dir.join("out.jsonl");
    std::fs::write(&script, ORACLE).expect("write the oracle script");
    std::fs::write(&input, serde_json::to_string(inputs).expect("rows json"))
        .expect("write the rows");
    let _ = std::fs::remove_file(&output);
    let run = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .arg("-In")
        .arg(&input)
        .arg("-Out")
        .arg(&output)
        .output()
        .expect("pwsh is required by the oracle feature: install PowerShell 7");
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "pwsh failed: {said}{}",
        String::from_utf8_lossy(&run.stderr)
    );
    eprintln!("{}", said.trim());
    let text = std::fs::read_to_string(&output).expect("read PowerShell's answers");
    let answers: Vec<Answer> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("answer json"))
        .collect();
    assert_eq!(answers.len(), inputs.len(), "PowerShell answered every row");
    for (a, i) in answers.iter().zip(inputs) {
        assert_eq!(a.id, i.id, "answers in row order");
    }
    answers
}

/// What the parser gets wrong about `src`, given PowerShell's answer: `None` when it agrees or
/// refuses (fails closed) a command PowerShell accepts.
fn disagreement(src: &str, ps: &Answer) -> Option<String> {
    match pwsh::parse(src, Shell::Pwsh, Os::Windows) {
        Err(_) => None,
        Ok(_) if ps.error => Some("accepted a PowerShell parse error".to_string()),
        Ok(script) => {
            let seen = pwsh::seen(src, &script);
            let want = ps.seen();
            (seen != want && !nested_comment_artefact(src, &seen, &want))
                .then(|| format!("got {seen:?}, want {want:?}"))
        }
    }
}

/// `ParseInput` lists a comment inside a word's `$(…)` only among that word's nested tokens, so
/// its top-level comment list lacks it. Everything else agrees, and each comment only the parser
/// lists sits inside a `$(` glued to the word (no space between them).
fn nested_comment_artefact(src: &str, seen: &pwsh::Seen, want: &pwsh::Seen) -> bool {
    if seen.cmds != want.cmds || seen.methods != want.methods {
        return false;
    }
    let mut extra = seen.comments.clone();
    for c in &want.comments {
        match extra.iter().position(|e| e == c) {
            Some(i) => {
                extra.remove(i);
            }
            None => return false,
        }
    }
    !extra.is_empty()
        && extra.iter().all(|c| {
            src.match_indices(c.as_str()).any(|(p, _)| {
                src[..p]
                    .rfind("$(")
                    .is_some_and(|o| !src[o..p].contains(char::is_whitespace))
            })
        })
}

#[test]
fn a_comment_outside_a_glued_subexpression_stays_a_disagreement() {
    let seen = |comments: &[&str]| pwsh::Seen {
        cmds: vec![vec!["Write-Output".to_string(), "x".to_string()]],
        comments: comments.iter().map(|c| c.to_string()).collect(),
        methods: Vec::new(),
    };
    // The artefact's shape: the extra comment sits in a `$(` glued to its word.
    assert!(nested_comment_artefact(
        "Write-Output x$(<#c#>1)",
        &seen(&["<#c#>"]),
        &seen(&[])
    ));
    // A `$(` before it, but a space between: a real comment difference.
    assert!(!nested_comment_artefact(
        "Write-Output x $(1) <#c#>",
        &seen(&["<#c#>"]),
        &seen(&[])
    ));
}

#[test]
fn rows_hold_powershells_answer_and_the_parser_gives_it() {
    let mut all = rows("pwsh_gaps.toml");
    all.extend(rows("pwsh_mechanisms.toml"));
    let inputs: Vec<Input> = all
        .iter()
        .map(|r| Input {
            id: r.id.clone(),
            command: &r.command,
        })
        .collect();
    let answers = ask_powershell("rows", &inputs);
    let mut bad = Vec::new();
    for (r, a) in all.iter().zip(&answers) {
        let recorded = pwsh::Seen {
            cmds: r.cmds.clone(),
            comments: r.comments.clone(),
            methods: r.methods.clone(),
        };
        if a.error != r.error || a.seen() != recorded {
            bad.push(format!("{}: the recorded answer is not PowerShell's", r.id));
        }
        let refused = pwsh::parse(&r.command, Shell::Pwsh, Os::Windows).is_err();
        let must_refuse = a.error || r.parser.as_deref() == Some("refuses");
        if refused != must_refuse {
            bad.push(format!(
                "{}: parser error {refused}, PowerShell {}",
                r.id, a.error
            ));
        } else if let Some(d) = disagreement(&r.command, a) {
            bad.push(format!("{}: {d}", r.id));
        }
    }
    eprintln!("oracle rows {}", answers.len());
    assert!(answers.len() >= 151, "ran {} rows", answers.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// A small deterministic generator (SplitMix64): the same seed gives the same mutants.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Byte offsets where one kind of character meets another (and both ends).
fn boundaries(s: &str) -> Vec<usize> {
    let class = |c: char| {
        if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
            0
        } else if c.is_whitespace() {
            1
        } else {
            2 + c as u32
        }
    };
    let mut at = vec![0];
    let mut prev: Option<u32> = None;
    for (i, c) in s.char_indices() {
        let k = class(c);
        if prev.is_some_and(|p| p != k || k >= 2) {
            at.push(i);
        }
        prev = Some(k);
    }
    at.push(s.len());
    at
}

fn mutate(src: &str, rng: &mut Rng) -> String {
    let at = boundaries(src);
    let i = at[rng.below(at.len())];
    match rng.below(4) {
        // Delete the character after the boundary.
        0 if i < src.len() => {
            let n = src[i..].chars().next().map_or(0, char::len_utf8);
            format!("{}{}", &src[..i], &src[i + n..])
        }
        // Double the character after the boundary.
        1 if i < src.len() => {
            let n = src[i..].chars().next().map_or(0, char::len_utf8);
            format!("{}{}{}", &src[..i + n], &src[i..i + n], &src[i + n..])
        }
        _ => {
            let ins = INSERTS[rng.below(INSERTS.len())];
            format!("{}{ins}{}", &src[..i], &src[i..])
        }
    }
}

/// How a disagreement differs from PowerShell's reading.
#[derive(Debug, PartialEq)]
enum Class {
    /// PowerShell runs a command name or a method the parser does not see in its place, or the
    /// statements break elsewhere: never allowed.
    A,
    /// Only argument boundaries, argument text or comments differ, or the parser sees a method
    /// PowerShell does not call.
    B,
}

fn class(seen: &pwsh::Seen, want: &pwsh::Seen) -> Class {
    let names = |s: &pwsh::Seen| -> Vec<String> {
        s.cmds
            .iter()
            .map(|c| c.first().cloned().unwrap_or_default())
            .collect()
    };
    if names(seen) != names(want) {
        return Class::A;
    }
    let mut extra = seen.methods.clone();
    for m in &want.methods {
        match extra.iter().position(|e| e == m) {
            Some(i) => {
                extra.remove(i);
            }
            None => return Class::A,
        }
    }
    Class::B
}

/// Whether a statement PowerShell or the parser reads names a delete-guard command.
fn guarded(s: &pwsh::Seen) -> bool {
    s.cmds.iter().filter_map(|c| c.first()).any(|name| {
        let base = name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(name)
            .to_lowercase();
        let base = base.strip_suffix(".exe").unwrap_or(&base);
        GUARDED.contains(&base)
    })
}

/// Shapes of class-B disagreements the parser may keep: a text that an argument the two readings
/// disagree on holds, a pinned input that must show the disagreement, and its mechanism in
/// `docs/spikes.md` ("PowerShell grammar fork"). None is in a guarded statement. A change to the
/// seeds, the generator or the seed rows makes new mutants: refuse each.
const LISTED: &[(&str, &str, &str)] = &[(
    "$?.ForEach{1}",
    "Write-Output $?.ForEach{1}",
    "a member glued to `$?` is not a member access in argument mode",
)];

/// The arguments one reading has where the other has none or another: for each statement, the
/// elements at positions where the two differ, from both readings.
fn differing_elements<'s>(seen: &'s pwsh::Seen, want: &'s pwsh::Seen) -> Vec<&'s str> {
    let mut out = Vec::new();
    for i in 0..seen.cmds.len().max(want.cmds.len()) {
        let (a, b) = (seen.cmds.get(i), want.cmds.get(i));
        let n = a.map_or(0, Vec::len).max(b.map_or(0, Vec::len));
        for j in 0..n {
            let (x, y) = (a.and_then(|c| c.get(j)), b.and_then(|c| c.get(j)));
            if x != y {
                out.extend(x.map(String::as_str));
                out.extend(y.map(String::as_str));
            }
        }
    }
    out
}

/// The `LISTED` shape a class-B disagreement belongs to: one held by an argument that differs.
fn listed_shape(seen: &pwsh::Seen, want: &pwsh::Seen) -> Option<usize> {
    let differ = differing_elements(seen, want);
    LISTED
        .iter()
        .position(|(l, _, _)| differ.iter().any(|e| e.contains(l)))
}

#[test]
fn disagreements_are_classed_by_what_powershell_runs() {
    let cmd = |names: &[&[&str]]| pwsh::Seen {
        cmds: names
            .iter()
            .map(|c| c.iter().map(|s| s.to_string()).collect())
            .collect(),
        comments: Vec::new(),
        methods: Vec::new(),
    };
    let ls_ri = cmd(&[&["ls"], &["ri", "C:\\x"]]);
    assert_eq!(class(&cmd(&[&["ls", "ri", "C:\\x"]]), &ls_ri), Class::A);
    assert_eq!(class(&cmd(&[&["ls"], &["rm", "C:\\x"]]), &ls_ri), Class::A);
    assert_eq!(
        class(&cmd(&[&["ls"], &["ri", "C:\\", "x"]]), &ls_ri),
        Class::B
    );
    let mut called = cmd(&[&["Write-Output", "x"]]);
    called.methods = vec!["$x.Delete".to_string()];
    assert_eq!(class(&cmd(&[&["Write-Output", "x"]]), &called), Class::A);
    assert_eq!(class(&called, &cmd(&[&["Write-Output", "x"]])), Class::B);
    assert!(guarded(&cmd(&[&["C:\\Windows\\System32\\CMD.EXE", "/c"]])));
    assert!(guarded(&cmd(&[&["ls"], &["Remove-Item", "x"]])));
    assert!(!guarded(&cmd(&[&["Write-Output", "rm"]])));
}

#[test]
fn seeded_mutants_never_read_differently_from_powershell() {
    let mut all = rows("pwsh_gaps.toml");
    all.extend(rows("pwsh_mechanisms.toml"));
    let seeds: Vec<&Row> = SEED_ROWS
        .iter()
        .map(|id| {
            all.iter()
                .find(|r| r.id == *id)
                .unwrap_or_else(|| panic!("pinned seed row {id} is missing"))
        })
        .collect();
    let f = fuzz("fuzz", &SEEDS, &seeds, mutate);
    eprintln!("{}", f.summary);
    assert_eq!(f.mutants, MUTANTS * SEEDS.len());
    assert!(f.bad.is_empty(), "{}", f.bad.join("\n"));
    // Each listed shape still shows on its pinned input, as that shape.
    let inputs: Vec<Input> = LISTED
        .iter()
        .enumerate()
        .map(|(i, (_, pinned, _))| Input {
            id: format!("listed-{i}"),
            command: pinned,
        })
        .collect();
    let answers = ask_powershell("listed", &inputs);
    let mut stale = Vec::new();
    for (i, ((shape, pinned, _), a)) in LISTED.iter().zip(&answers).enumerate() {
        let shows = !a.error
            && disagreement(pinned, a).is_some()
            && pwsh::parse(pinned, Shell::Pwsh, Os::Windows).is_ok_and(|s| {
                let seen = pwsh::seen(pinned, &s);
                let want = a.seen();
                class(&seen, &want) == Class::B
                    && !guarded(&seen)
                    && !guarded(&want)
                    && listed_shape(&seen, &want) == Some(i)
            });
        if !shows {
            stale.push(*shape);
        }
    }
    assert!(
        stale.is_empty(),
        "listed shapes their pinned input no longer shows: {stale:?}"
    );
}

/// The acceptance run: seeds the fix rounds never iterated against, over every current row, once
/// with the gate's cuts and once also cutting at `-` and `.` (`cargo test --features oracle
/// --release --test pwsh_oracle held_out -- --ignored`). A run spends its seeds.
#[test]
#[ignore = "held-out acceptance run, once per round"]
fn held_out_mutants_never_read_differently_from_powershell() {
    let mut all = rows("pwsh_gaps.toml");
    all.extend(rows("pwsh_mechanisms.toml"));
    let every: Vec<&Row> = all.iter().collect();
    let plain = fuzz("held_out", &HELD_OUT_SEEDS, &every, mutate);
    let fine = fuzz("held_out_fine", &HELD_OUT_SEEDS, &every, mutate_fine);
    eprintln!("held-out, gate cuts: {}", plain.summary);
    eprintln!("held-out, also at - and .: {}", fine.summary);
    let mut bad = plain.bad;
    bad.extend(fine.bad.into_iter().map(|b| format!("fine: {b}")));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Seeds for the held-out run only: never used by the gate or by a fix round's iterations.
const HELD_OUT_SEEDS: [u64; 10] = [1009, 2027, 3049, 4093, 5101, 6143, 7177, 8191, 9203, 10007];

/// `boundaries`, also cutting inside a word at each `-` and `.` (before and after it).
fn boundaries_fine(s: &str) -> Vec<usize> {
    let mut at = boundaries(s);
    for (i, c) in s.char_indices() {
        if c == '-' || c == '.' {
            at.push(i);
            at.push(i + 1);
        }
    }
    at.sort_unstable();
    at.dedup();
    at
}

/// `mutate` over `boundaries_fine`.
fn mutate_fine(src: &str, rng: &mut Rng) -> String {
    let at = boundaries_fine(src);
    let i = at[rng.below(at.len())];
    match rng.below(4) {
        0 if i < src.len() => {
            let n = src[i..].chars().next().map_or(0, char::len_utf8);
            format!("{}{}", &src[..i], &src[i + n..])
        }
        1 if i < src.len() => {
            let n = src[i..].chars().next().map_or(0, char::len_utf8);
            format!("{}{}{}", &src[..i + n], &src[i..i + n], &src[i + n..])
        }
        _ => {
            let ins = INSERTS[rng.below(INSERTS.len())];
            format!("{}{ins}{}", &src[..i], &src[i..])
        }
    }
}

/// What one fuzz run found.
struct Fuzz {
    mutants: usize,
    bad: Vec<String>,
    summary: String,
}

/// Mutants of `seeds` (picked by each RNG seed, `MUTANTS` per seed) against PowerShell, classed.
fn fuzz(
    tag: &str,
    rng_seeds: &[u64],
    seeds: &[&Row],
    mutator: fn(&str, &mut Rng) -> String,
) -> Fuzz {
    let mut mutants: Vec<(String, String)> = Vec::new();
    for &seed in rng_seeds {
        let mut rng = Rng(seed);
        mutants.extend((0..MUTANTS).map(|n| {
            let base = seeds[rng.below(seeds.len())];
            let mut text = mutator(&base.command, &mut rng);
            if rng.below(3) == 0 {
                text = mutator(&text, &mut rng);
            }
            (format!("{}~{seed:x}~{n}", base.id), text)
        }));
    }
    let inputs: Vec<Input> = mutants
        .iter()
        .map(|(id, c)| Input {
            id: id.clone(),
            command: c,
        })
        .collect();
    let answers = ask_powershell(tag, &inputs);
    let mut bad = Vec::new();
    let mut used = vec![0usize; LISTED.len()];
    let (mut refused, mut accepted, mut a_count, mut b_count) = (0usize, 0usize, 0usize, 0usize);
    for ((id, src), a) in mutants.iter().zip(&answers) {
        let parsed = pwsh::parse(src, Shell::Pwsh, Os::Windows);
        match (&parsed, a.error) {
            (Err(_), false) => refused += 1,
            // PowerShell runs nothing of a script it cannot parse; the parser judges more.
            (Ok(_), true) => accepted += 1,
            _ => {}
        }
        if a.error {
            continue;
        }
        let Some(d) = disagreement(src, a) else {
            continue;
        };
        let Ok(script) = parsed else {
            continue;
        };
        let seen = pwsh::seen(src, &script);
        let want = a.seen();
        match class(&seen, &want) {
            Class::A => {
                a_count += 1;
                bad.push(format!("A {id} {src:?}: {d}"));
            }
            Class::B if guarded(&seen) || guarded(&want) => {
                b_count += 1;
                bad.push(format!("B in a guarded statement {id} {src:?}: {d}"));
            }
            Class::B => {
                b_count += 1;
                match listed_shape(&seen, &want) {
                    Some(i) => used[i] += 1,
                    None => bad.push(format!("B unlisted {id} {src:?}: {d}")),
                }
            }
        }
    }
    let summary = format!(
        "fuzz seeds {}: {} mutants; class A {a_count}, class B {b_count} (listed {used:?}); \
         {} failing; {refused} refused that PowerShell accepts; {accepted} accepted that \
         PowerShell rejects",
        rng_seeds.len(),
        answers.len(),
        bad.len()
    );
    Fuzz {
        mutants: answers.len(),
        bad,
        summary,
    }
}
