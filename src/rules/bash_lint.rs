//! The Git Bash rules: mistakes that break a command only in Git Bash on Windows, where the Bash
//! tool runs. Each rule fires only for the Git Bash profile, at most once per text, and names
//! programs and options only through `data/programs.toml` (`crate::programs`).
//!
//! The default level of each rule is the `*_LEVEL` constant next to it (the collapse rule's level
//! follows `PROVEN`). The plan lands these rules by the landing rule: break only when the corpus
//! replay denies at most 5 non-destructive `ok` rows; a constant set to `Warn` names the count that
//! decided it.

use super::{Ctx, Rule, Scope};
use crate::ir::{EnvView, Redirect, SimpleCommand, Word};
use crate::level::{Finding, Level, Span};
use crate::programs::{self, Escapes, Kind, Program};
use crate::{BashProfile, Os, Shell};

pub const BACKSLASH_COLLAPSE: &str = "bash-backslash-collapse";
pub const MSYS_PATH_MANGLE: &str = "bash-msys-path-mangle";
pub const PS_CMDLET: &str = "bash-ps-cmdlet";
pub const VERSIONED_PHP: &str = "bash-versioned-php";
pub const VENDOR_BIN_SHEBANG: &str = "bash-vendor-bin-shebang";
pub const CD_SLASH_D: &str = "bash-cd-slash-d";
pub const UNQUOTED_BACKSLASH_PATH: &str = "bash-unquoted-backslash-path";

/// Every rule of this file, in the order they run.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(BackslashCollapse),
        Box::new(MsysPathMangle),
        Box::new(PsCmdlet),
        Box::new(VersionedPhp),
        Box::new(VendorBinShebang),
        Box::new(CdSlashD),
        Box::new(UnquotedBackslashPath),
    ]
}

/// Two backslashes, which Git Bash turns into one before bash reads the command.
const PAIR: &str = "\\\\";

fn git_bash(ctx: &Ctx) -> bool {
    ctx.input.shell == Shell::Bash(BashProfile::GitBash)
}

/// The source text of `span`, empty when the span is not inside the text.
fn raw(command: &str, span: Span) -> &str {
    command.get(span.start..span.end).unwrap_or("")
}

fn value(word: &Word) -> Option<String> {
    word.static_value(&EnvView::new())
}

/// The table row the (unwrapped) command `c` runs.
fn program(ctx: &Ctx, c: &SimpleCommand) -> Option<&'static Program> {
    programs::lookup(&value(&c.name)?, ctx.input.shell, ctx.input.os)
}

fn finding(rule: &'static str, level: Level, message: String, fix: Option<String>, span: Span) -> Finding {
    Finding {
        rule,
        level,
        message,
        fix,
        span,
    }
}

// --- bash-backslash-collapse ---------------------------------------------------------------

/// A text shape whose `\\` changes what the command writes once Git Bash collapses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `\\` in an argument of a program that reads escapes itself (`printf`, `echo -e`).
    Escapes,
    /// `\\` in the body of a heredoc with a quoted delimiter.
    HeredocBody,
    /// `\\d` or `\\w` in a regex program's arguments (`sed`).
    RegexClass,
}

/// The shapes spike S4 proved collapse in the real Bash tool (Ruling 99 Q2, Ruling 100(b)): `\\`
/// there is `break`, in every other shape `warn`. S4 probed printf, `echo -e` and a `<<'EOF'`
/// body; its sed `\d` probe showed a missing regex class in GNU sed, not a collapse, so
/// `RegexClass` stays out.
pub const PROVEN: &[Shape] = &[Shape::Escapes, Shape::HeredocBody];

/// The regex classes that lose their meaning when their backslash pair collapses.
const REGEX_CLASSES: [char; 2] = ['d', 'w'];

const COLLAPSE_FIX: &str = "write the text with the Write tool to <file> and run bash <file>";

pub struct BackslashCollapse;

impl Rule for BackslashCollapse {
    fn id(&self) -> &'static str {
        BACKSLASH_COLLAPSE
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        let command = ctx.input.command;
        let Some(first) = command.find(PAIR) else {
            return;
        };
        let hits = shapes(ctx);
        let proven = hits.iter().find(|(s, _)| PROVEN.contains(s)).copied();
        let (level, at, why) = match proven {
            Some((shape, at)) => (
                Level::Break,
                at,
                match shape {
                    Shape::Escapes => "the program then reads one backslash as an escape",
                    Shape::HeredocBody => "the heredoc body is written with one backslash",
                    Shape::RegexClass => "the regex loses its class",
                },
            ),
            None => (
                Level::Warn,
                hits.first().map_or(first, |&(_, at)| at),
                "check that the text still means the same with one backslash",
            ),
        };
        let (line, text) = collapsed_line(command, at);
        out.push(finding(
            BACKSLASH_COLLAPSE,
            level,
            format!(
                "Git Bash turns every \\\\ in a Bash tool command into \\ before bash reads it, inside quotes and heredoc bodies too: line {line} reaches bash as `{text}`; {why}"
            ),
            Some(COLLAPSE_FIX.to_string()),
            Span {
                start: at,
                end: at + PAIR.len(),
            },
        ));
    }
}

/// Every shape hit of the text, with the byte offset of its first `\\`, in command order.
fn shapes(ctx: &Ctx) -> Vec<(Shape, usize)> {
    let command = ctx.input.command;
    let mut hits = Vec::new();
    for c in programs::commands(ctx.script) {
        // Only a quoted delimiter (`<<'EOF'`) keeps `\\` as written; in an expanding body bash
        // itself reads `\\` as one backslash, so the collapse there is not the proven shape.
        for r in &c.redirects {
            if let Redirect::Heredoc { body, expands, .. } = r
                && !expands
                && let Some(p) = raw(command, body.span).find(PAIR)
            {
                hits.push((Shape::HeredocBody, body.span.start + p));
            }
        }
        let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
        let Some(p) = program(ctx, &c) else {
            continue;
        };
        let shape = match p.escapes {
            Some(Escapes::Always) => pair_in(command, &c.args, |_| true).map(|at| (Shape::Escapes, at)),
            Some(Escapes::Option) if escapes_on(p, &c.args) => {
                pair_in(command, &c.args, |_| true).map(|at| (Shape::Escapes, at))
            }
            Some(Escapes::Regex) => {
                pair_in(command, &c.args, |next| next.is_some_and(|n| REGEX_CLASSES.contains(&n)))
                    .map(|at| (Shape::RegexClass, at))
            }
            _ => None,
        };
        hits.extend(shape);
    }
    hits
}

/// The offset of the first `\\` in `args` whose next character passes `next`.
fn pair_in(command: &str, args: &[Word], next: impl Fn(Option<char>) -> bool) -> Option<usize> {
    args.iter().find_map(|w| {
        let text = raw(command, w.span);
        text.match_indices(PAIR)
            .find(|(i, _)| next(text[i + PAIR.len()..].chars().next()))
            .map(|(i, _)| w.span.start + i)
    })
}

/// Whether the leading options of `args` turn escapes on (`echo -e`, `echo -n -e`, `echo -ne`).
fn escapes_on(p: &Program, args: &[Word]) -> bool {
    for w in args {
        let Some(v) = value(w) else {
            return false;
        };
        if v.len() < 2 || !v.starts_with('-') {
            return false;
        }
        if p.escape_options.iter().any(|o| Program::option_matches(&v, o)) {
            return true;
        }
    }
    false
}

/// The 1-based line holding `at`, and at most 60 characters of it as bash receives it.
fn collapsed_line(command: &str, at: usize) -> (usize, String) {
    let at = at.min(command.len());
    let start = command[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = command[at..].find('\n').map_or(command.len(), |i| at + i);
    let line = command[..at].matches('\n').count() + 1;
    let column = command[start..at].replace(PAIR, "\\").chars().count();
    let text: Vec<char> = command[start..end].replace(PAIR, "\\").chars().collect();
    let from = column.saturating_sub(30).min(text.len().saturating_sub(60));
    (line, text[from..(from + 60).min(text.len())].iter().collect())
}

// --- bash-msys-path-mangle -----------------------------------------------------------------

/// Warn: 173 `ok` corpus rows match (Task 29 plan).
pub const MSYS_LEVEL: Level = Level::Warn;

pub struct MsysPathMangle;

impl Rule for MsysPathMangle {
    fn id(&self) -> &'static str {
        MSYS_PATH_MANGLE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        let command = ctx.input.command;
        let opt_out = &programs::msys().opt_out;
        // `export MSYS_NO_PATHCONV=1; docker …` turns the conversion off for the rest.
        if opt_out.iter().any(|n| command.contains(&format!("{n}="))) {
            return;
        }
        for c in programs::commands(ctx.script) {
            let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
            let Some(p) = program(ctx, &c).filter(|p| p.is(Kind::NativeMsys)) else {
                continue;
            };
            if c.assigns.iter().any(|(n, _)| opt_out.contains(n)) {
                continue;
            }
            let Some((w, v)) = c
                .args
                .iter()
                .find_map(|w| value(w).filter(|v| converted(v)).map(|v| (w, v)))
            else {
                continue;
            };
            out.push(finding(
                MSYS_PATH_MANGLE,
                MSYS_LEVEL,
                format!(
                    "Git Bash rewrites `{v}` into a path under Git's install folder before `{}` sees it",
                    p.name
                ),
                p.fix.clone(),
                w.span,
            ));
            return;
        }
    }
}

/// Whether Git Bash rewrites `word` as a POSIX path: `/<root>`, `/<root>/…` or `/<root>:…`, alone
/// or as the value of `--opt=` / `-o=`. `//x` is how a slash is kept.
fn converted(word: &str) -> bool {
    let path = match word.split_once('=') {
        Some((opt, v)) if opt.starts_with('-') => v,
        _ => word,
    };
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let root = rest.split(['/', ':']).next().unwrap_or_default();
    programs::msys().roots.iter().any(|r| r == root)
}

// --- bash-ps-cmdlet ------------------------------------------------------------------------

/// Warn by the landing rule: the draft matcher counted 47 `ok` rows (Task 29 plan).
pub const PS_CMDLET_LEVEL: Level = Level::Warn;

const PS_CMDLET_FIX: &str = "run this in the PowerShell tool";

pub struct PsCmdlet;

impl Rule for PsCmdlet {
    fn id(&self) -> &'static str {
        PS_CMDLET
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        for c in programs::commands(ctx.script) {
            let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
            let Some(name) = value(&c.name) else {
                continue;
            };
            if !name.contains('-') || program(ctx, &c).is_some() {
                continue;
            }
            // A cmdlet by its own name: an alias such as `ls` or `cat` is a real program here.
            let lower = name.to_lowercase();
            if crate::parse::pwsh::canonical(&name, Shell::Pwsh, Os::Windows).as_deref()
                != Some(lower.as_str())
            {
                continue;
            }
            out.push(finding(
                PS_CMDLET,
                PS_CMDLET_LEVEL,
                format!("`{name}` is a PowerShell cmdlet, but this is the Bash tool (Git Bash)"),
                Some(PS_CMDLET_FIX.to_string()),
                c.name.span,
            ));
            return;
        }
    }
}

// --- bash-versioned-php --------------------------------------------------------------------

/// Warn by the landing rule: a draft matcher counted 35 `ok` rows that ran a versioned name.
pub const VERSIONED_PHP_LEVEL: Level = Level::Warn;

pub struct VersionedPhp;

impl Rule for VersionedPhp {
    fn id(&self) -> &'static str {
        VERSIONED_PHP
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        for c in programs::commands(ctx.script) {
            let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
            let Some(p) = program(ctx, &c).filter(|p| p.is(Kind::Launcher)) else {
                continue;
            };
            // The path comes only from the config, never from a guess.
            let fix = p.fix.as_ref().map(|f| match ctx.cfg.tool_paths.get(&p.name) {
                Some(path) => format!("{f}: \"{}\"", path.display()),
                None => f.clone(),
            });
            out.push(finding(
                VERSIONED_PHP,
                VERSIONED_PHP_LEVEL,
                format!(
                    "`{}` is a Windows launcher script, which Git Bash does not run by that name",
                    c.typed
                ),
                fix,
                c.name.span,
            ));
            return;
        }
    }
}

// --- bash-vendor-bin-shebang ---------------------------------------------------------------

/// Warn by the landing rule: a draft matcher counted 23 `ok` rows.
pub const VENDOR_BIN_LEVEL: Level = Level::Warn;

/// The Composer bin folder, as a path prefix.
const VENDOR_BIN: &str = "vendor/bin/";
/// The launcher suffix Composer writes next to each script, which Git Bash can run.
const BAT_SUFFIX: &str = ".bat";

pub struct VendorBinShebang;

impl Rule for VendorBinShebang {
    fn id(&self) -> &'static str {
        VENDOR_BIN_SHEBANG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        for c in programs::commands(ctx.script) {
            let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
            let Some(name) = value(&c.name) else {
                continue;
            };
            if !vendor_script(&name) {
                continue;
            }
            out.push(finding(
                VENDOR_BIN_SHEBANG,
                VENDOR_BIN_LEVEL,
                format!(
                    "`{name}` starts with `#!/usr/bin/env php`, and Git Bash has no php on its PATH"
                ),
                Some(format!("php {name}")),
                c.name.span,
            ));
            return;
        }
    }
}

/// `vendor/bin/<tool>` or `./vendor/bin/<tool>`, not its `.bat` launcher.
fn vendor_script(name: &str) -> bool {
    let path = name.strip_prefix("./").unwrap_or(name);
    let Some(tool) = path.strip_prefix(VENDOR_BIN) else {
        return false;
    };
    !tool.is_empty()
        && tool
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !tool.to_ascii_lowercase().ends_with(BAT_SUFFIX)
}

// --- bash-cd-slash-d -----------------------------------------------------------------------

/// Break: 0 `ok` corpus rows give `cd /d` a path (the 2 matches have no path after it).
pub const CD_SLASH_D_LEVEL: Level = Level::Break;

pub struct CdSlashD;

impl Rule for CdSlashD {
    fn id(&self) -> &'static str {
        CD_SLASH_D
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        let command = ctx.input.command;
        for c in programs::commands(ctx.script) {
            let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
            let Some(p) = program(ctx, &c).filter(|p| !p.cmd_options.is_empty()) else {
                continue;
            };
            let [first, path, ..] = &c.args[..] else {
                continue;
            };
            let Some(v) = value(first) else {
                continue;
            };
            let Some(option) = p.cmd_options.iter().find(|o| o.eq_ignore_ascii_case(&v)) else {
                continue;
            };
            let path_text = raw(command, path.span);
            if !one_word(path_text) {
                continue;
            }
            let path = forward_slashes(unquote(path_text));
            let fix = p
                .fix
                .as_ref()
                .map(|f| f.replace("<path>", &format!("\"{path}\"")));
            out.push(finding(
                CD_SLASH_D,
                CD_SLASH_D_LEVEL,
                format!(
                    "`{} {option}` is cmd.exe syntax; bash reads `{option}` as the folder and fails with too many arguments",
                    p.name
                ),
                fix,
                first.span,
            ));
            return;
        }
    }
}

/// Whether `text` is one shell word: no whitespace outside quotes. A word nested in `$(…)` may
/// carry its outer word's span (the parser's inexact origin); its text is then not one word, and
/// a Fix line must not quote it.
fn one_word(text: &str) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            c if c.is_whitespace() && !single && !double => return false,
            _ => {}
        }
    }
    !text.is_empty()
}

fn unquote(text: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = text.strip_prefix(q).and_then(|t| t.strip_suffix(q)) {
            return inner;
        }
    }
    text
}

fn forward_slashes(text: &str) -> String {
    text.replace('\\', "/")
}

// --- bash-unquoted-backslash-path ----------------------------------------------------------

/// Warn by the landing rule until the replay counts it: a draft matcher counted 87 `ok` rows
/// (it did not tell quoted words from unquoted ones).
pub const UNQUOTED_PATH_LEVEL: Level = Level::Warn;

pub struct UnquotedBackslashPath;

impl Rule for UnquotedBackslashPath {
    fn id(&self) -> &'static str {
        UNQUOTED_BACKSLASH_PATH
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !git_bash(ctx) {
            return;
        }
        let command = ctx.input.command;
        for c in programs::commands(ctx.script) {
            for w in std::iter::once(&c.name).chain(&c.args) {
                let text = raw(command, w.span);
                if !one_word(text) || !unquoted_drive_backslash(text) {
                    continue;
                }
                out.push(finding(
                    UNQUOTED_BACKSLASH_PATH,
                    UNQUOTED_PATH_LEVEL,
                    format!(
                        "bash drops the backslashes of the unquoted path `{text}`, so the command gets `{}`",
                        text.replace('\\', "")
                    ),
                    Some(format!("write {} with forward slashes", forward_slashes(text))),
                    w.span,
                ));
                return;
            }
        }
    }
}

/// Whether `word` (its source text) holds a drive path whose backslash bash removes: `X:\` outside
/// quotes, with no letter or digit before the drive letter and no second backslash after it
/// (`X:\\` is the collapse rule's).
fn unquoted_drive_backslash(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    let (mut single, mut double) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '\\' if !single => {
                let drive = !double
                    && i >= 2
                    && chars[i - 1] == ':'
                    && chars[i - 2].is_ascii_alphabetic()
                    && (i == 2 || !chars[i - 3].is_ascii_alphanumeric())
                    && chars.get(i + 1) != Some(&'\\');
                if drive {
                    return true;
                }
                // The backslash escapes the next character.
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquoted_drive_backslash_reads_quotes_and_escapes() {
        let yes = ["X:\\src", "a=X:\\x", "--path=C:\\x"];
        let no = [
            "\"X:\\src\"",
            "'X:\\src'",
            "X:/src",
            "X:\\\\src",
            "AX:\\src",
            "1X:\\src",
        ];
        for w in yes {
            assert!(unquoted_drive_backslash(w), "{w}");
        }
        for w in no {
            assert!(!unquoted_drive_backslash(w), "{w}");
        }
    }

    #[test]
    fn collapsed_line_counts_lines_and_collapses_pairs() {
        let (line, text) = collapsed_line("echo ok\nprintf 'a\\\\b'\n", 17);
        assert_eq!(line, 2);
        assert_eq!(text, "printf 'a\\b'");
    }

    #[test]
    fn one_word_reads_quotes_and_escapes() {
        for w in ["X:\\src", "\"D:/my x\"", "'a b'", "a\\ b"] {
            assert!(one_word(w), "{w}");
        }
        for w in ["$(ls X:\\a)", "a b", ""] {
            assert!(!one_word(w), "{w}");
        }
    }

    #[test]
    fn vendor_script_shapes() {
        assert!(vendor_script("vendor/bin/pint"));
        assert!(vendor_script("./vendor/bin/phpunit"));
        assert!(!vendor_script("vendor/bin/phpunit.bat"));
        assert!(!vendor_script("vendor/bin/"));
        assert!(!vendor_script("x/vendor/bin/pint"));
    }
}
