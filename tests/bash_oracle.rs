//! The bash parser against bash itself. Each row becomes the body of a function imported through
//! the environment and bash prints it back with `declare -f`: bash parses the row without running
//! it (an import holding anything after the closing brace is refused), and the printed text is its
//! own reading of the row. The row and bash's text must lower to the same commands.
//!
//! Needs Git Bash on Windows (`bin\bash.exe`) or `/bin/bash`; fails when it is missing.

#![cfg(feature = "oracle")]

mod bash_util;

use std::path::{Path, PathBuf};
use std::process::Command;

use bash_util::{command_shape, commands};
use shellwise::BashProfile;
use shellwise::parse::bash::parse;

#[cfg(windows)]
const BASH: &str = r"C:\Program Files\Git\bin\bash.exe";
#[cfg(not(windows))]
const BASH: &str = "/bin/bash";

/// Rows whose reference cannot judge them, with why. At most 10.
const EXCLUDED: &[(&str, &str)] = &[(
    "cat <<EOF && rm -rf build\nbody\nEOF",
    "bash prints a heredoc followed by && with the operator at the start of the line after the \
     body, which no parser reads back; tests/parse_bash.rs checks the row's commands",
)];

/// Rows beyond the gap table: the shapes tests/parse_bash.rs relies on.
const EXTRA: &[&str] = &[
    "rm -rf \"$d\"/x",
    "cd /x && git checkout -- f",
    "for w in a b; do rm \"$w\"; done",
    "cat <(git status)",
    "x=$(git rev-parse HEAD)",
    "eval \"$c\"",
    "find . -name x | xargs rm -rf",
    "echo \"${x/$(rm -rf a)/b}\"",
    "[[ -n $(rm x) ]]",
    "rm -rf *.tmp ~/x 'a b' $'\\x2drf' \\-f \"q\"z {a,b}",
    "X=1 rm -rf \"$d\" $(git x)",
    "a || b; c & d",
    "if git diff --quiet; then rm x; elif true; then a; else b; fi",
    "{ git status; } > >(rm x)",
];

/// A fresh empty folder; the reference runs there and nothing may appear in it.
fn canary_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("shellwise-oracle-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bash() -> Command {
    assert!(
        Path::new(BASH).is_file(),
        "{BASH} is missing: the oracle needs it"
    );
    let mut c = Command::new(BASH);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("BASH_FUNC_") {
            c.env_remove(k);
        }
    }
    c
}

/// bash's own text of `row` as a function body, or `None` when bash refuses the row.
fn reference(row: &str, cwd: &Path) -> Option<String> {
    let out = bash()
        .args(["--norc", "--noprofile", "-c", "declare -f __sw"])
        .env("BASH_FUNC___sw%%", format!("() {{ {row}\n}}"))
        .current_dir(cwd)
        .output()
        .expect("bash runs");
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();
    if !out.status.success()
        || lines.len() < 3
        || !lines[0].starts_with("__sw ()")
        || lines[1].trim_end() != "{"
    {
        return None;
    }
    let mut body = lines[2..].to_vec();
    while body.last() == Some(&"") {
        body.pop();
    }
    if body.pop() != Some("}") {
        return None;
    }
    Some(body.join("\n") + "\n")
}

/// Every command a text lowers to, as `name arg …` in value shapes; `None` on a parse error.
fn reading(text: &str) -> Option<Vec<String>> {
    let s = parse(text, BashProfile::GitBash).ok()?;
    Some(commands(&s).into_iter().map(command_shape).collect())
}

#[test]
fn reference_never_runs_a_row() {
    let dir = canary_dir("canary");
    let canary = dir.join("CANARY");
    // Positive control: the same row pasted into a script does run.
    let script = dir.join("naive.sh");
    std::fs::write(
        &script,
        "__sw() { true; }; touch CANARY; __x() { true;\n}\n",
    )
    .unwrap();
    let st = bash()
        .args(["--norc", "--noprofile", "naive.sh"])
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(
        st.success() && canary.exists(),
        "control: the naive form must create the canary"
    );
    std::fs::remove_file(&canary).unwrap();
    std::fs::remove_file(&script).unwrap();
    let rows = [
        "touch CANARY",
        "true; }; touch CANARY; __x() { true;",
        "echo $(touch CANARY)",
        "cat <<EOF\n$(touch CANARY)\nEOF",
        "x=`touch CANARY` echo hi",
    ];
    for row in rows {
        let r = reference(row, &dir);
        assert!(!canary.exists(), "{row:?} ran");
        // The breakout row is refused; the others come back as bash's text.
        assert_eq!(r.is_some(), !row.contains('}'), "{row:?}: {r:?}");
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[derive(serde::Deserialize)]
struct GapFile {
    row: Vec<GapRow>,
}

#[derive(serde::Deserialize)]
struct GapRow {
    command: String,
    #[serde(default)]
    error: bool,
}

fn gap_rows() -> Vec<GapRow> {
    let text = std::fs::read_to_string("tests/cases/bash_gaps.toml").unwrap();
    toml::from_str::<GapFile>(&text).unwrap().row
}

#[derive(Debug, PartialEq)]
enum Outcome {
    /// Both read the same commands, or both refuse.
    Agree,
    /// bash reads the row, the parser refuses it (fail closed).
    ParserRefuses,
    /// bash refuses the row, the parser reads it.
    BashRefuses,
    /// bash's own text does not parse back.
    ReferenceUnreadable,
    /// Both read it, with different commands.
    Silent { row: Vec<String>, bash: Vec<String> },
}

fn judge(row: &str, cwd: &Path) -> Outcome {
    match (reference(row, cwd), reading(row)) {
        (None, None) => Outcome::Agree,
        (None, Some(_)) => Outcome::BashRefuses,
        (Some(_), None) => Outcome::ParserRefuses,
        (Some(canon), Some(mine)) => match reading(&canon) {
            None => Outcome::ReferenceUnreadable,
            Some(theirs) if theirs == mine => Outcome::Agree,
            Some(theirs) => Outcome::Silent {
                row: mine,
                bash: theirs,
            },
        },
    }
}

#[test]
fn gap_and_shape_rows_match_bash() {
    let dir = canary_dir("rows");
    let gaps = gap_rows();
    let mut ran = 0;
    for r in &gaps {
        if EXCLUDED.iter().any(|(c, _)| *c == r.command) {
            continue;
        }
        let got = judge(&r.command, &dir);
        let want = if r.error {
            Outcome::ParserRefuses
        } else {
            Outcome::Agree
        };
        assert_eq!(got, want, "{:?}", r.command);
        ran += 1;
    }
    for row in EXTRA {
        assert_eq!(judge(row, &dir), Outcome::Agree, "{row:?}");
        ran += 1;
    }
    assert!(EXCLUDED.len() <= 10);
    assert!(
        EXCLUDED
            .iter()
            .all(|(c, why)| !why.is_empty() && gaps.iter().any(|r| r.command == *c))
    );
    assert_eq!(ran, gaps.len() - EXCLUDED.len() + EXTRA.len());
    assert!(ran >= gaps.len());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "a row ran");
    let _ = std::fs::remove_dir_all(&dir);
}

/// xorshift64*: a fixed seed gives the same mutations on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Text inserted at the start of a word (after a blank): blanks, a line continuation, empty
/// quotes glued to the word, an escape of its first character, a comment, a newline.
const INSERTS: &[&str] = &[
    " ", "\t", "\\\n", "''", "\"\"", "$''", "\\", " #c\n", "\n", " \\\n ",
];

fn mutate(row: &str, rng: &mut Rng) -> String {
    let mut s = row.to_string();
    for _ in 0..1 + rng.below(2) {
        let starts: Vec<usize> = s
            .char_indices()
            .filter(|&(i, c)| c != ' ' && i > 0 && s.as_bytes()[i - 1] == b' ')
            .map(|(i, _)| i)
            .collect();
        if starts.is_empty() {
            break;
        }
        let at = starts[rng.below(starts.len())];
        s.insert_str(at, INSERTS[rng.below(INSERTS.len())]);
    }
    s
}

const MUTATIONS: usize = 2000;

/// Mutations bash reads and the parser refuses (fail closed): at most 1 %.
const MAX_REFUSALS: usize = MUTATIONS / 100;

#[test]
fn mutations_of_the_gap_rows_match_bash() {
    let dir = canary_dir("fuzz");
    let rows: Vec<String> = gap_rows()
        .into_iter()
        .filter(|r| !r.error && !EXCLUDED.iter().any(|(c, _)| *c == r.command))
        .map(|r| r.command)
        .collect();
    let mut rng = Rng(0x5eed_0006_ba5e_0001);
    let inputs: Vec<String> = (0..MUTATIONS)
        .map(|i| mutate(&rows[i % rows.len()], &mut rng))
        .collect();
    let outcomes: Vec<(String, Outcome)> = std::thread::scope(|sc| {
        let chunks: Vec<_> = inputs
            .chunks(MUTATIONS.div_ceil(8))
            .map(|chunk| {
                let dir = &dir;
                sc.spawn(move || {
                    chunk
                        .iter()
                        .map(|m| (m.clone(), judge(m, dir)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        chunks.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(outcomes.len(), MUTATIONS);
    let count = |f: &dyn Fn(&Outcome) -> bool| outcomes.iter().filter(|(_, o)| f(o)).count();
    let silent: Vec<_> = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Silent { .. }))
        .collect();
    let refused: Vec<_> = outcomes
        .iter()
        .filter(|(_, o)| !matches!(o, Outcome::Agree | Outcome::Silent { .. }))
        .collect();
    eprintln!(
        "fuzz: {} mutations, agree {}, parser refuses {}, bash refuses {}, reference unreadable {}, silent {}",
        outcomes.len(),
        count(&|o| *o == Outcome::Agree),
        count(&|o| *o == Outcome::ParserRefuses),
        count(&|o| *o == Outcome::BashRefuses),
        count(&|o| *o == Outcome::ReferenceUnreadable),
        silent.len()
    );
    for (m, o) in refused.iter().take(20) {
        eprintln!("  {o:?}: {m:?}");
    }
    assert!(silent.is_empty(), "silent mismatches: {silent:#?}");
    // Known mechanism (seed above: 9 rows): a newline before `<(…)` makes the process
    // substitution the first word of a command, which bash runs and brush-parser refuses. A
    // refusal fails closed, so it may not hide a command; it is bounded, not forbidden.
    assert!(
        refused.len() <= MAX_REFUSALS,
        "error-status mismatches: {}",
        refused.len()
    );
    assert!(
        refused.iter().all(|(_, o)| *o == Outcome::ParserRefuses),
        "only parser refusals are expected"
    );
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "a mutation ran"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
