//! Case rows in TOML, run in process through `shellwise::analyse`.
//!
//! Each `[[row]]` holds `id`, `os` (`"windows"`, `"posix"` or `"any"`), `shell` (`"pwsh"`,
//! `"powershell5"`, `"bash"` or `"gitbash"`), `command`, the expected `level`, the expected rule
//! ids in order (`rules`), and optionally `fix` (a text the first finding's Fix line holds),
//! `oracle` (`"refuses"` or `"accepts"`: what the real shell's parser does with the text) and
//! `config` (the text of an integration config file the row runs under, loaded by `Config::load`).
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
    pub oracle: Option<String>,
    pub config: Option<String>,
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
    (!wrong.is_empty()).then(|| format!("{}: {}", row.id, wrong.join("; ")))
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
