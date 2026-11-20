//! `shellwise lint <file>`: the same parsers and rules as `check`, run over a script file.
//!
//! The dialect comes from the file name (`.ps1`, `.sh`, `.bash`); any other name is refused. The
//! file is read strictly as UTF-8 (a UTF-8 byte-order mark is accepted and dropped) and is refused
//! over `MAX_READ_BYTES`. The text goes through `analyse` with `Origin::File`, which skips the
//! rules whose scope is `Scope::CommandLine` (the length rules and the rules about what a host
//! does to a command line). Findings print as `<path>:<line>:<col>: <level> <rule>: <message>`
//! with a `Fix:` line under each that has one, and the exit code is 1 on `break` or worse.
//!
//! An external linter (ShellCheck's Rust port) is not called from here: the caller passes it to
//! `lint_with` as a function, so this file does not depend on it.

use std::fs::File;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::time::Instant;

use crate::config::Config;
use crate::ir::EnvView;
use crate::level::{Finding, Level, Span, Verdict};
use crate::{
    ANALYSIS_INCOMPLETE, AnalyseInput, BashProfile, Deadline, MAX_READ_BYTES, Origin, Os, Shell,
    analyse,
};

/// Exit code when findings reach `break` or worse.
pub const EXIT_FINDINGS: i32 = 1;
/// Exit code for a file `lint` refuses to read (unknown name, too big, not UTF-8).
pub const EXIT_REFUSED: i32 = 64;
/// Exit code when the file cannot be opened or read.
pub const EXIT_UNREADABLE: i32 = 74;

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const UTF16_BOMS: [[u8; 2]; 2] = [[0xFF, 0xFE], [0xFE, 0xFF]];

/// A file `lint` does not analyse, and why.
#[derive(Debug)]
pub enum Refusal {
    /// The name does not end in `.ps1`, `.sh` or `.bash`.
    Dialect,
    TooBig,
    /// The byte offset (after a UTF-8 byte-order mark, if any) of the first invalid byte.
    NotUtf8(usize),
    Utf16,
    Unreadable(std::io::Error),
}

impl Refusal {
    pub fn exit_code(&self) -> i32 {
        match self {
            Refusal::Unreadable(_) => EXIT_UNREADABLE,
            _ => EXIT_REFUSED,
        }
    }

    /// One line, `<path>: <reason>`.
    pub fn render(&self, path: &Path) -> String {
        let reason = match self {
            Refusal::Dialect => {
                "cannot tell the shell: the file name must end in .ps1, .sh or .bash".to_string()
            }
            Refusal::TooBig => {
                format!("the file is over {MAX_READ_BYTES} bytes and is not read")
            }
            Refusal::NotUtf8(at) => format!(
                "the file is not valid UTF-8 (first invalid byte at offset {at}); save it as UTF-8"
            ),
            Refusal::Utf16 => {
                "the file starts with a UTF-16 byte-order mark; save it as UTF-8".to_string()
            }
            Refusal::Unreadable(e) => format!("cannot read the file: {e}"),
        };
        format!("{}: {reason}", path.display())
    }
}

/// A finding with its place in the file, both counted from 1; the column counts characters.
#[derive(Debug, Clone)]
pub struct Located {
    pub line: usize,
    pub column: usize,
    pub finding: Finding,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub level: Level,
    pub findings: Vec<Located>,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        if self.level >= Level::Break {
            EXIT_FINDINGS
        } else {
            0
        }
    }

    /// The text `lint` prints: one line per finding with its `Fix:` line under it, or
    /// `<path>: ok` when there is none.
    pub fn render(&self, path: &Path) -> String {
        if self.findings.is_empty() {
            return format!("{}: ok\n", path.display());
        }
        let mut out = String::new();
        for l in &self.findings {
            let f = &l.finding;
            out.push_str(&format!(
                "{}:{}:{}: {} {}: {}\n",
                path.display(),
                l.line,
                l.column,
                f.level.as_str(),
                f.rule,
                f.message
            ));
            if let Some(fix) = f.fix_line() {
                out.push_str(&format!("  {fix}\n"));
            }
        }
        out
    }
}

/// The shell a file is written for, from its name (case-insensitive).
pub fn dialect(path: &Path) -> Option<Shell> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name.ends_with(".ps1") {
        Some(Shell::Pwsh)
    } else if name.ends_with(".sh") || name.ends_with(".bash") {
        let profile = if Os::host() == Os::Windows {
            BashProfile::GitBash
        } else {
            BashProfile::Posix
        };
        Some(Shell::Bash(profile))
    } else {
        None
    }
}

/// The deadline of a lint run: `cfg.walk_budget_ms` from `start`.
pub fn deadline(start: Instant, cfg: &Config) -> Deadline {
    Deadline::new(start, cfg.walk_budget_ms)
}

/// The file's text: read at most `MAX_READ_BYTES`, strict UTF-8, no byte-order mark.
pub fn read_text(path: &Path) -> Result<String, Refusal> {
    let file = File::open(path).map_err(Refusal::Unreadable)?;
    let mut bytes = Vec::new();
    file.take(MAX_READ_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(Refusal::Unreadable)?;
    if bytes.len() > MAX_READ_BYTES {
        return Err(Refusal::TooBig);
    }
    if UTF16_BOMS.iter().any(|bom| bytes.starts_with(bom)) {
        return Err(Refusal::Utf16);
    }
    let body = bytes.strip_prefix(&UTF8_BOM[..]).unwrap_or(&bytes[..]);
    std::str::from_utf8(body)
        .map(str::to_string)
        .map_err(|e| Refusal::NotUtf8(e.valid_up_to()))
}

/// Line and column of a byte offset, both from 1; the column counts characters. An offset inside
/// a character reads as the character's start.
pub fn position(text: &str, at: usize) -> (usize, usize) {
    let mut end = at.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let before = &text[..end];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, column)
}

/// Lint a file with the shellwise rules only.
pub fn lint(path: &Path, cfg: &Config, deadline: &Deadline) -> Result<Report, Refusal> {
    lint_with(path, cfg, deadline, &|_, _| Vec::new())
}

/// Lint a file with the shellwise rules and `external`, which returns more findings for the
/// text (spans are byte offsets into it). An external finding on a line where a shellwise
/// finding of the same rule exists is dropped. A panic in `external` is a `warn`
/// `analysis-incomplete` finding, and the shellwise findings stay.
pub fn lint_with(
    path: &Path,
    cfg: &Config,
    deadline: &Deadline,
    external: &dyn Fn(&str, Shell) -> Vec<Finding>,
) -> Result<Report, Refusal> {
    let shell = dialect(path).ok_or(Refusal::Dialect)?;
    let text = read_text(path)?;
    let input = AnalyseInput {
        bytes: text.as_bytes(),
        shell,
        os: Os::host(),
        cwd: std::env::current_dir().ok(),
        env: EnvView::new(),
        origin: Origin::File,
        problem: None,
    };
    let own = analyse(&input, cfg, deadline).findings;
    let mut located: Vec<Located> = own.into_iter().map(|f| locate(&text, f)).collect();

    let extra = match panic::catch_unwind(AssertUnwindSafe(|| external(&text, shell))) {
        Ok(found) => found,
        Err(_) => vec![Finding {
            rule: ANALYSIS_INCOMPLETE,
            level: Level::Warn,
            message: "the external linter failed (internal error); the shellwise rules ran"
                .to_string(),
            fix: None,
            span: Span::default(),
        }],
    };
    // Only the shellwise findings are compared: the external linter's own findings of one rule on
    // one line are distinct (one per variable).
    let own_count = located.len();
    for mut f in extra {
        f.level = cfg.level(f.rule, f.level);
        let l = locate(&text, f);
        let seen = located[..own_count]
            .iter()
            .any(|o| o.line == l.line && o.finding.rule == l.finding.rule);
        if !seen {
            located.push(l);
        }
    }
    located.sort_by_key(|l| (l.line, l.column));
    let level = Verdict::new(located.iter().map(|l| l.finding.clone()).collect()).level;
    Ok(Report {
        level,
        findings: located,
    })
}

fn locate(text: &str, finding: Finding) -> Located {
    let (line, column) = position(text, finding.span.start);
    Located {
        line,
        column,
        finding,
    }
}
