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

/// The warn of a CRLF `.sh` linted in the Git Bash profile, which is then read as its LF twin.
pub const BASH_CRLF: &str = "bash-crlf";

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

/// `position` for many offsets into one text: the line starts are found once.
struct Lines<'a> {
    text: &'a str,
    /// The byte offset each line starts at, the first line's 0 included.
    starts: Vec<usize>,
}

impl<'a> Lines<'a> {
    fn new(text: &'a str) -> Lines<'a> {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        Lines { text, starts }
    }

    /// The same answer as `position(text, at)`.
    fn position(&self, at: usize) -> (usize, usize) {
        let mut end = at.min(self.text.len());
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        // The lines whose start is at or before `end`: one per `\n` before it, and the first.
        let line = self.starts.partition_point(|&s| s <= end);
        let column = self.text[self.starts[line - 1]..end].chars().count() + 1;
        (line, column)
    }
}

/// Lint a file with the shellwise rules only.
pub fn lint(path: &Path, cfg: &Config, deadline: &Deadline) -> Result<Report, Refusal> {
    lint_with(path, cfg, deadline, &|_, _| Vec::new())
}

/// Lint a file with the shellwise rules and `external`, which returns more findings for the
/// text (spans are byte offsets into it). An external finding on a line where a shellwise
/// finding of the same rule exists is dropped. An external `break` stays `break` only when the
/// shellwise parser fails at the same place (a `parse-error` finding on its line, one at the end
/// of the file, or, for an external finding at the end of the file, one whose span runs there),
/// else it is `warn`. A panic in `external` is a `warn` `analysis-incomplete` finding, and the
/// shellwise findings stay. `external` runs on the calling thread while `analyse` runs on another,
/// both under the same deadline.
pub fn lint_with(
    path: &Path,
    cfg: &Config,
    deadline: &Deadline,
    external: &dyn Fn(&str, Shell) -> Vec<Finding>,
) -> Result<Report, Refusal> {
    let shell = dialect(path).ok_or(Refusal::Dialect)?;
    let mut text = read_text(path)?;
    // Git Bash reads a CRLF script as its LF twin; Linux bash does not.
    let crlf = shell == Shell::Bash(BashProfile::GitBash) && text.contains("\r\n");
    if crlf {
        text = text.replace("\r\n", "\n");
    }
    let input = AnalyseInput {
        bytes: text.as_bytes(),
        shell,
        os: Os::host(),
        cwd: std::env::current_dir().ok(),
        env: EnvView::new(),
        origin: Origin::File,
        problem: None,
    };
    let text = &text;
    let run_external = || panic::catch_unwind(AssertUnwindSafe(|| external(text, shell)));
    let (mut own, extra) = std::thread::scope(|s| {
        let ours = if crate::testhook_is("lint-spawn-fail") {
            Err(std::io::Error::other("testhook: lint-spawn-fail"))
        } else {
            std::thread::Builder::new().spawn_scoped(s, || analyse(&input, cfg, deadline).findings)
        };
        match ours {
            Ok(ours) => {
                let extra = run_external();
                // `analyse` catches its own panics; one past it fails the lint as it would here.
                let own = ours.join().unwrap_or_else(|e| panic::resume_unwind(e));
                (own, extra)
            }
            // No thread for the analysis: both run here, one after the other.
            Err(_) => (analyse(&input, cfg, deadline).findings, run_external()),
        }
    });
    if crlf {
        let mut f = Finding {
            rule: BASH_CRLF,
            level: Level::Warn,
            message: "the file has CRLF line ends: Git Bash runs it, Linux bash stops at each CR ($'\\r': command not found)".to_string(),
            fix: Some("save the file with LF line ends".to_string()),
            span: Span::default(),
        };
        f.level = cfg.level(f.rule, f.level);
        own.insert(0, f);
    }
    let lines = Lines::new(text);
    let mut located: Vec<Located> = own.into_iter().map(|f| locate(&lines, f)).collect();

    let extra = match extra {
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
    // An external `break` is a parse error the shell refuses only when our parser fails at the
    // same place (Ruling 138). A call operator is such a failure, reported under its own id.
    let failed: Vec<&Located> = located
        .iter()
        .filter(|l| {
            l.finding.rule == crate::rules::parse_error::PARSE_ERROR
                || l.finding.rule == crate::rules::bash_lint::PS_CALL_OPERATOR
        })
        .collect();
    let eof = text.trim_end().len();
    let refused_at = |f: &Finding| {
        let line = lines.position(f.span.start).0;
        failed.iter().any(|p| {
            p.line == line
                // Our parser ran into the end of the file: the construct left open may start on
                // any line.
                || p.finding.span.start >= eof
                // ShellCheck's "expected the end" of a construct our parser saw left open.
                || (f.span.start >= eof && p.finding.span.end >= eof)
        })
    };
    let refused: Vec<bool> = extra.iter().map(refused_at).collect();
    for (mut f, refused) in extra.into_iter().zip(refused) {
        if f.level == Level::Break && !refused {
            f.level = Level::Warn;
            f.fix = None;
        }
        f.level = cfg.level(f.rule, f.level);
        let l = locate(&lines, f);
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

fn locate(lines: &Lines, finding: Finding) -> Located {
    let (line, column) = lines.position(finding.span.start);
    Located {
        line,
        column,
        finding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line index gives `position`'s answer at every offset: line starts, offsets inside a
    /// multi-byte character, a CR before a newline, a text without a final newline, past the end.
    #[test]
    fn the_line_index_answers_as_position_at_every_offset() {
        let o = char::from_u32(0xF3).unwrap();
        let euro = char::from_u32(0x20AC).unwrap();
        let texts = [
            String::new(),
            "\n".to_string(),
            "\n\n".to_string(),
            "a".to_string(),
            format!("ab{o}c\r\n{euro}\n\nx{o}{o}\ny"),
            format!("{euro}\n"),
        ];
        let mut checked = 0;
        for text in &texts {
            let lines = Lines::new(text);
            for at in 0..text.len() + 3 {
                assert_eq!(lines.position(at), position(text, at), "{text:?} at {at}");
                checked += 1;
            }
        }
        assert!(checked > 30, "{checked}");
    }
}
