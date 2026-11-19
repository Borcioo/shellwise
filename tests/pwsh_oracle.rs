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

/// Shapes of class-B disagreements the parser may keep, each by a text the mutant holds and its
/// mechanism in `docs/spikes.md` ("PowerShell grammar fork"). None is in a guarded statement. A
/// change to the seeds, the generator or the seed rows makes new mutants: refuse or list each.
const LISTED: &[(&str, &str)] = &[
    (
        "1`\n",
        "a backtick after a leading digit escapes the line end",
    ),
    (
        "$?.",
        "a member glued to `$?` is not a member access in argument mode",
    ),
];

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
    let mut seeds = rows("pwsh_gaps.toml");
    seeds.extend(rows("pwsh_mechanisms.toml"));
    let mut mutants: Vec<(String, String)> = Vec::new();
    for seed in SEEDS {
        let mut rng = Rng(seed);
        mutants.extend((0..MUTANTS).map(|n| {
            let base = &seeds[rng.below(seeds.len())];
            let mut text = mutate(&base.command, &mut rng);
            if rng.below(3) == 0 {
                text = mutate(&text, &mut rng);
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
    let answers = ask_powershell("fuzz", &inputs);
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
                match LISTED.iter().position(|(l, _)| src.contains(l)) {
                    Some(i) => used[i] += 1,
                    None => bad.push(format!("B unlisted {id} {src:?}: {d}")),
                }
            }
        }
    }
    eprintln!(
        "fuzz seeds {}: {} mutants; class A {a_count}, class B {b_count} (listed {:?}); \
         {} failing; {refused} refused that PowerShell accepts; {accepted} accepted that \
         PowerShell rejects",
        SEEDS.len(),
        answers.len(),
        used,
        bad.len()
    );
    assert_eq!(answers.len(), MUTANTS * SEEDS.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let stale: Vec<_> = LISTED
        .iter()
        .zip(&used)
        .filter(|(_, n)| **n == 0)
        .map(|(l, _)| l)
        .collect();
    assert!(stale.is_empty(), "listed shapes no mutant shows: {stale:?}");
}
