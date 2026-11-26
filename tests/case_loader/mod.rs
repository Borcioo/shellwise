//! Case rows in TOML, run in process through `shellwise::analyse`.
//!
//! Each `[[row]]` holds `id`, `os` (`"windows"`, `"posix"` or `"any"`), `shell` (`"pwsh"`,
//! `"powershell5"`, `"bash"` or `"gitbash"`), `command`, the expected `level`, the expected rule
//! ids in order (`rules`), and optionally `fix` (a text the first finding's Fix line holds),
//! `fix_exact` (the whole text of the first finding's Fix line, after `Fix: `),
//! `oracle` (`"refuses"` or `"accepts"`: what the real shell's parser does with the text) and
//! `config` (the text of an integration config file the row runs under, loaded by `Config::load`)
//! and `twin` (a command that must give the same rule ids: `tests/delete.rs` checks it).
//! A row for another OS is skipped and counted; loading fails when no row runs.

#![allow(dead_code)]

use std::time::Instant;

use serde::Deserialize;
use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::Verdict;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub id: String,
    pub os: String,
    pub shell: String,
    pub command: String,
    pub level: String,
    pub rules: Vec<String>,
    pub fix: Option<String>,
    pub fix_exact: Option<String>,
    pub oracle: Option<String>,
    pub config: Option<String>,
    pub twin: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    row: Vec<Row>,
}

impl Row {
    pub fn shell(&self) -> Shell {
        match self.shell.as_str() {
            "pwsh" => Shell::Pwsh,
            "powershell5" => Shell::Powershell5,
            "bash" => Shell::Bash(BashProfile::Posix),
            "gitbash" => Shell::Bash(BashProfile::GitBash),
            s => panic!("{}: unknown shell {s:?}", self.id),
        }
    }

    pub fn is_bash(&self) -> bool {
        matches!(self.shell(), Shell::Bash(_))
    }

    fn runs_here(&self) -> bool {
        match self.os.as_str() {
            "any" => true,
            "windows" => Os::host() == Os::Windows,
            "posix" => Os::host() == Os::Posix,
            s => panic!("{}: unknown os {s:?}", self.id),
        }
    }
}

/// Every row of `tests/cases/<name>`, for whatever OS: for checks of what the table declares,
/// never for verdicts. Panics on an empty file.
pub fn all_rows(name: &str) -> Vec<Row> {
    let path = format!("{}/tests/cases/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let file: File = toml::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert!(!file.row.is_empty(), "{name}: no rows");
    file.row
}

/// The rows of `tests/cases/<name>` that run on this OS. Prints how many were skipped and why;
/// panics when none is left.
pub fn rows(name: &str) -> Vec<Row> {
    let path = format!("{}/tests/cases/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let file: File = toml::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let total = file.row.len();
    let (here, skipped): (Vec<Row>, Vec<Row>) = file.row.into_iter().partition(Row::runs_here);
    for os in ["windows", "posix"] {
        let n = skipped.iter().filter(|r| r.os == os).count();
        if n > 0 {
            eprintln!(
                "{name}: skipped {n} rows for os = {os:?} (this host is {:?})",
                Os::host()
            );
        }
    }
    assert!(!here.is_empty(), "{name}: 0 of {total} rows run on this OS");
    here
}

/// The verdict `analyse` gives a row, as a command line with no cwd and the default config.
pub fn verdict(row: &Row) -> Verdict {
    let input = AnalyseInput {
        bytes: row.command.as_bytes(),
        shell: row.shell(),
        os: Os::host(),
        cwd: None,
        env: EnvView::new(),
        origin: Origin::CommandLine,
        problem: None,
    };
    analyse(&input, &config(row), &Deadline::new(Instant::now(), 8000))
}

/// What is wrong with a row's verdict, or `None` when it matches.
pub fn mismatch(row: &Row) -> Option<String> {
    let v = verdict(row);
    let rules: Vec<&str> = v.findings.iter().map(|f| f.rule).collect();
    let mut wrong = Vec::new();
    if v.level.as_str() != row.level {
        wrong.push(format!("level {} (want {})", v.level.as_str(), row.level));
    }
    if rules != row.rules {
        wrong.push(format!("rules {rules:?} (want {:?})", row.rules));
    }
    if let Some(want) = &row.fix {
        let line = v.findings.first().and_then(|f| f.fix_line());
        if !line
            .as_deref()
            .is_some_and(|l| l.starts_with("Fix: ") && l.contains(want.as_str()))
        {
            wrong.push(format!("fix line {line:?} (want one holding {want:?})"));
        }
    }
    if let Some(want) = &row.fix_exact {
        let line = v.findings.first().and_then(|f| f.fix_line());
        if line.as_deref() != Some(format!("Fix: {want}").as_str()) {
            wrong.push(format!("fix line {line:?} (want exactly \"Fix: {want}\")"));
        }
    }
    (!wrong.is_empty()).then(|| format!("{}: {}", row.id, wrong.join("; ")))
}

/// The language of a body fed to a shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Bash,
    Pwsh,
}

/// One stdin-fed form of a body and its `-c` twin, in one shell.
#[derive(Debug, Clone)]
pub struct FedCell {
    pub shell: &'static str,
    /// The command that feeds the body to the shell on stdin.
    pub fed: String,
    /// The same shell given the same body as its `-c` / `-Command` argument.
    pub twin: String,
    pub lang: Lang,
    /// The index of the body in the bodies given to `fed_cells`.
    pub body: usize,
    /// A wrapper bounds how long the shell runs (`timeout 60`).
    pub bounded: bool,
    /// A bash called by its bare name from PowerShell (the twin draws `ps-bare-bash` too).
    pub bare_bash: bool,
}

/// Bash carriers: the words before the shell's own options, the shell, and whether it is bounded.
const BASH_CARRIERS: [(&str, bool); 8] = [
    ("bash", false),
    ("sh", false),
    ("zsh", false),
    ("sudo bash", false),
    ("env A=1 bash", false),
    ("nohup bash", false),
    ("timeout 60 bash", true),
    ("bash -o pipefail", false),
];

/// Forms that feed a Bash body (`{b}`) to a Bash carrier (`{c}`).
const BASH_FORMS: [&str; 8] = [
    "{c} <<'EOF'\n{b}\nEOF",
    "{c} <<EOF\n{b}\nEOF",
    "{c} <<-'EOF'\n\t{b}\n\tEOF",
    "{c} <<-EOF\n\t{b}\n\tEOF",
    "{c} <<< '{b}'",
    "{c} <<< \"{b}\"",
    "{c} -s <<'EOF'\n{b}\nEOF",
    "{c} -s -- arg <<'EOF'\n{b}\nEOF",
];

/// PowerShell carriers that read their stdin as the program, with their `-Command` twin's words.
const PWSH_CARRIERS: [(&str, &str); 7] = [
    ("pwsh -Command -", "pwsh -Command"),
    ("pwsh -c -", "pwsh -c"),
    ("pwsh -NoProfile -Command -", "pwsh -NoProfile -Command"),
    ("pwsh -File -", "pwsh -Command"),
    ("pwsh -", "pwsh -Command"),
    ("pwsh", "pwsh -Command"),
    ("powershell -Command -", "powershell -Command"),
];

/// Forms that feed a PowerShell body (`{b}`) to a PowerShell carrier (`{c}`) from Bash.
const PWSH_FORMS_IN_BASH: [&str; 2] = ["{c} <<'EOF'\n{b}\nEOF", "{c} <<< '{b}'"];

/// The shells a Bash form runs in on this host.
pub fn bash_shells() -> &'static [&'static str] {
    if cfg!(windows) {
        &["bash", "gitbash"]
    } else {
        &["bash"]
    }
}

/// Every stdin-fed form of each body with its `-c` twin: Bash bodies to every Bash carrier, and
/// PowerShell bodies to every PowerShell carrier, from Bash and from PowerShell.
pub fn fed_cells(bash_bodies: &[&str], pwsh_bodies: &[&str]) -> Vec<FedCell> {
    let mut out = Vec::new();
    for &shell in bash_shells() {
        for (carrier, bounded) in BASH_CARRIERS {
            for (body, b) in bash_bodies.iter().enumerate() {
                for form in BASH_FORMS {
                    out.push(FedCell {
                        shell,
                        fed: form.replace("{c}", carrier).replace("{b}", b),
                        twin: format!("{carrier} -c '{b}'"),
                        lang: Lang::Bash,
                        body,
                        bounded,
                        bare_bash: false,
                    });
                }
            }
        }
        for (carrier, twin) in PWSH_CARRIERS {
            for (body, b) in pwsh_bodies.iter().enumerate() {
                for form in PWSH_FORMS_IN_BASH {
                    out.push(FedCell {
                        shell,
                        fed: form.replace("{c}", carrier).replace("{b}", b),
                        twin: format!("{twin} '{b}'"),
                        lang: Lang::Pwsh,
                        body,
                        bounded: false,
                        bare_bash: false,
                    });
                }
            }
        }
    }
    out
}

/// A verdict as the twin rule compares it: level, rule ids in order, and each message with every
/// backtick-quoted text (the command as written) left out.
pub fn reading(v: &Verdict) -> (String, Vec<&'static str>, Vec<String>) {
    let messages = v
        .findings
        .iter()
        .map(|f| {
            f.message
                .split('`')
                .enumerate()
                .map(|(k, part)| if k % 2 == 1 { "`…`" } else { part })
                .collect()
        })
        .collect();
    (
        v.level.as_str().to_string(),
        v.findings.iter().map(|f| f.rule).collect(),
        messages,
    )
}

/// The verdict of `command` in `shell`, as a row with no cwd and the default config reads it.
pub fn verdict_of(shell: &str, command: &str) -> Verdict {
    verdict(&Row {
        id: command.to_string(),
        os: "any".to_string(),
        shell: shell.to_string(),
        command: command.to_string(),
        level: String::new(),
        rules: Vec::new(),
        fix: None,
        fix_exact: None,
        oracle: None,
        config: None,
        twin: None,
    })
}

/// The row's config: the defaults, or its `config` text loaded as an integration file, which
/// must load without a finding.
fn config(row: &Row) -> Config {
    let Some(text) = &row.config else {
        return Config::default();
    };
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("case_configs");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.toml", row.id));
    std::fs::write(&path, text).unwrap();
    let (cfg, findings) = Config::load(Some(&path), None, None);
    assert!(
        findings.is_empty(),
        "{}: the config gave {findings:?}",
        row.id
    );
    cfg
}
