//! `parse::pwsh` against the real PowerShell parser (`pwsh -NoProfile`, `Parser::ParseInput`).
//! Feature `oracle`: needs `pwsh` on PATH and fails when it is missing.
//!
//! 1. Every row of `tests/cases/pwsh_gaps.toml` and `pwsh_mechanisms.toml`: PowerShell's answer
//!    must equal the row's recorded answer, and the parser must give it.
//! 2. A differential fuzz: seeded mutations of those rows at token boundaries (comment, quote,
//!    escape and whitespace variants). The parser may refuse a mutant PowerShell accepts (that
//!    fails closed); it must never accept a mutant PowerShell rejects, nor read one differently.
#![cfg(feature = "oracle")]

use std::process::Command;

use serde::{Deserialize, Serialize};
use shellwise::parse::pwsh;
use shellwise::{Os, Shell};

/// Seed and size of the differential fuzz.
const SEED: u64 = 0x5EED_0005;
const MUTANTS: usize = 2_000;

/// Text inserted at a token boundary.
const INSERTS: &[&str] = &[
    " ", "\t", "  ", "`", "#", "# x", "<#x#>", "'", "\"", "`\"", "''", "\u{00A0}", "\u{3000}",
    "\u{2018}", "\u{201C}", ";", ",", "\r", "\n", "\r\n", "`\n", "$", "@", "(", ")", "{", "}",
    "--%", ">", "2>&1", ":", "-",
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
    $methods = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $a.Static }, $true) |
        Sort-Object { $_.Extent.StartOffset } |
        ForEach-Object { $_.Expression.Extent.Text + '::' + $_.Member.Extent.Text })
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
            (seen != want).then(|| format!("got {seen:?}, want {want:?}"))
        }
    }
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
    assert!(answers.len() >= 91, "ran {} rows", answers.len());
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

/// Mutants the parser reads differently from PowerShell, by their text, each listed with its
/// mechanism in `docs/spikes.md` ("PowerShell grammar fork"). Every one splits or joins argument
/// text; none hides a command PowerShell runs or names one it does not. A change to the seed,
/// the generator or the seed rows makes new mutants: list or fix each new one.
const LISTED: &[(&str, &str)] = &[
    (
        "Write-Output ('a'),# don't\ngit status",
        "a comma, a comment and a line end continue a comma list",
    ),
    (
        "git worktree remove --force F:\\w\\$(#$p[0]\r\n)",
        "`ParseInput` lists a comment inside a word's `$(…)` only among its nested tokens",
    ),
    (
        "Get-ChildItem  | # note\nSelect-Object -First 1`\n",
        "a backtick after a leading digit escapes the line end",
    ),
];

#[test]
fn seeded_mutants_never_read_differently_from_powershell() {
    let mut seeds = rows("pwsh_gaps.toml");
    seeds.extend(rows("pwsh_mechanisms.toml"));
    let mut rng = Rng(SEED);
    let mut mutants: Vec<(String, String)> = (0..MUTANTS)
        .map(|n| {
            let base = &seeds[rng.below(seeds.len())];
            let mut text = mutate(&base.command, &mut rng);
            if rng.below(3) == 0 {
                text = mutate(&text, &mut rng);
            }
            (format!("{}~{n}", base.id), text)
        })
        .collect();
    // The listed texts run every time, so a fix that makes one agree shows up.
    mutants.extend(
        LISTED
            .iter()
            .enumerate()
            .map(|(i, (text, _))| (format!("listed~{i}"), text.to_string())),
    );
    let inputs: Vec<Input> = mutants
        .iter()
        .map(|(id, c)| Input {
            id: id.clone(),
            command: c,
        })
        .collect();
    let answers = ask_powershell("fuzz", &inputs);
    let mut bad = Vec::new();
    let mut listed = Vec::new();
    let (mut refused, mut accepted) = (0usize, 0usize);
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
        if let Some(d) = disagreement(src, a) {
            if LISTED.iter().any(|(l, _)| l == src) {
                listed.push(src.as_str());
            } else {
                bad.push(format!("{id} {src:?}: {d}"));
            }
        }
    }
    eprintln!(
        "fuzz seed {SEED:#x}: {} mutants; read differently: {} unlisted, {} listed; \
         {refused} refused that PowerShell accepts; {accepted} accepted that PowerShell rejects",
        answers.len(),
        bad.len(),
        listed.len()
    );
    assert_eq!(answers.len(), MUTANTS + LISTED.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let stale: Vec<_> = LISTED.iter().filter(|(l, _)| !listed.contains(l)).collect();
    assert!(stale.is_empty(), "listed mutants that now agree: {stale:?}");
}
