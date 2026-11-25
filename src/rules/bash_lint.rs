//! The Git Bash rules: mistakes that break a command only in Git Bash on Windows, where the Bash
//! tool runs. Each rule fires only for the Git Bash profile, at most once per text, and names
//! programs and options only through `data/programs.toml` (`crate::programs`). The exception is
//! `bash-ps-call-operator`: bash refuses a leading `&` in either profile, so it fires in both.
//!
//! The default level of each rule is the `*_LEVEL` constant next to it (the collapse rule's level
//! follows `PROVEN`). The plan lands these rules by the landing rule: break only when the corpus
//! replay denies at most 5 non-destructive `ok` rows; a constant set to `Warn` names the count that
//! decided it.

use super::{Ctx, Rule, Scope};
use crate::ir::{Elem, EnvView, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::parse::{self, ParseError, ParseKind};
use crate::programs::{self, Escapes, Kind, Program};
use crate::{BashProfile, Deadline, Origin, Os, Shell};

pub const BACKSLASH_COLLAPSE: &str = "bash-backslash-collapse";
pub const MSYS_PATH_MANGLE: &str = "bash-msys-path-mangle";
pub const PS_CMDLET: &str = "bash-ps-cmdlet";
pub const VERSIONED_PHP: &str = "bash-versioned-php";
pub const VENDOR_BIN_SHEBANG: &str = "bash-vendor-bin-shebang";
pub const CD_SLASH_D: &str = "bash-cd-slash-d";
pub const UNQUOTED_BACKSLASH_PATH: &str = "bash-unquoted-backslash-path";
pub const PS_CALL_OPERATOR: &str = "bash-ps-call-operator";

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
        Box::new(PsCallOperator),
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

fn finding(
    rule: &'static str,
    level: Level,
    message: String,
    fix: Option<String>,
    span: Span,
) -> Finding {
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
    /// `\\` in a heredoc body where the collapse changes the bytes written: any pair under a
    /// quoted delimiter, and under an expanding one a pair before `$`, `` ` ``, `\` or a newline.
    HeredocBody,
}

/// The shapes the real Bash tool was shown to corrupt (spike S4, Ruling 110): `\\` there is
/// `break`, in every other shape `warn`.
pub const PROVEN: &[Shape] = &[Shape::Escapes, Shape::HeredocBody];

/// The characters an expanding heredoc body gives a backslash meaning before: `\\` there reads as
/// `\` either way, except in front of one of these.
const HEREDOC_SPECIAL: [char; 4] = ['$', '`', '\\', '\n'];

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
        // A quoted delimiter (`<<'EOF'`) keeps every `\\` as written. In an expanding body bash
        // itself reads `\\` as one backslash, so only a pair before a character that gives the
        // backslash a meaning there (`\\$x`, `\\\\`) changes the bytes.
        for r in &c.redirects {
            if let Redirect::Heredoc { body, expands, .. } = r
                && let Some(p) = first_pair(raw(command, body.span), |next| {
                    !expands || next.is_some_and(|n| HEREDOC_SPECIAL.contains(&n))
                })
            {
                hits.push((Shape::HeredocBody, body.span.start + p));
            }
        }
        let c = programs::strip_wrappers(c, ctx.input.shell, ctx.input.os);
        let Some(p) = program(ctx, &c) else {
            continue;
        };
        let escapes = match p.escapes {
            Some(Escapes::Always) => true,
            Some(Escapes::Option) => escapes_on(p, &c.args),
            None => false,
        };
        if escapes {
            hits.extend(
                c.args
                    .iter()
                    .find_map(|w| {
                        first_pair(raw(command, w.span), |_| true).map(|i| w.span.start + i)
                    })
                    .map(|at| (Shape::Escapes, at)),
            );
        }
    }
    hits
}

/// The offset in `text` of the first `\\` whose next character passes `next`.
fn first_pair(text: &str, next: impl Fn(Option<char>) -> bool) -> Option<usize> {
    text.match_indices(PAIR)
        .find(|(i, _)| next(text[i + PAIR.len()..].chars().next()))
        .map(|(i, _)| i)
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
        if p.escape_options
            .iter()
            .any(|o| Program::option_matches(&v, o))
        {
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
    (
        line,
        text[from..(from + 60).min(text.len())].iter().collect(),
    )
}

// --- bash-msys-path-mangle -----------------------------------------------------------------

/// Warn: 249 `ok` corpus rows match (the corpus replay at 667aa40).
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

/// Break by the landing rule: the corpus replay denies 2 `ok` rows (both a cmdlet that failed
/// behind `2>/dev/null`).
pub const PS_CMDLET_LEVEL: Level = Level::Break;

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

/// Warn by the landing rule: the corpus replay at 667aa40 counts 33 `ok` rows that ran a versioned name.
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
            let fix = p
                .fix
                .as_ref()
                .map(|f| match ctx.cfg.tool_paths.get(&p.name) {
                    Some(path) => format!("{f}: \"{}\"", path.display()),
                    None => f.clone(),
                });
            out.push(finding(
                VERSIONED_PHP,
                VERSIONED_PHP_LEVEL,
                format!(
                    "`{}` is a Windows launcher script (.bat), which Git Bash runs by that name only when a shell profile defines it",
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

/// Warn by the landing rule: the corpus replay at 667aa40 counts 31 `ok` rows.
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
            if !exact_spans(&c) {
                continue;
            }
            let path = bash_path(unquote(path_text));
            let fix = p.fix.as_ref().map(|f| f.replace("<path>", &path));
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

/// Whether the command's words carry their own spans: each argument starts after the name ends. A
/// command nested in `$(…)` whose text the parser could not place gives every word the outer
/// word's span (`echo "$(cd /d \<newline>D:/x)"`), which may still read as one quoted word.
fn exact_spans(c: &SimpleCommand) -> bool {
    c.args.iter().all(|a| a.span.start >= c.name.span.end)
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

/// The path with forward slashes and no trailing whitespace (a `C:\ ` escapes the space after it).
fn forward_slashes(text: &str) -> String {
    text.replace('\\', "/").trim_end().to_string()
}

/// A cmd.exe path as one bash word that names the same folder: forward slashes, `%NAME%` as
/// `$NAME` (Git Bash has the Windows variables), double-quoted, with a leading `~` left outside
/// the quotes so bash still expands it.
fn bash_path(text: &str) -> String {
    let path = cmd_variables(&forward_slashes(text));
    match path.strip_prefix('~') {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') => format!("~/\"{}\"", &rest[1..]),
        _ => format!("\"{path}\""),
    }
}

/// `%NAME%` as `$NAME`, for a name of letters, digits and `_`; any other `%` stays.
fn cmd_variables(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('%') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let name_len = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        let name = &after[..name_len];
        let valid = !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit());
        if valid && after[name_len..].starts_with('%') {
            out.push('$');
            out.push_str(name);
            rest = &after[name_len + 1..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

// --- bash-unquoted-backslash-path ----------------------------------------------------------

/// Break by the landing rule: the corpus replay denies 0 `ok` rows.
pub const UNQUOTED_PATH_LEVEL: Level = Level::Break;

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
        for span in path_spans(ctx.script, command) {
            let text = raw(command, span);
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
                span,
            ));
            return;
        }
    }
}

/// The spans of the words bash reads as a path or a value: each command's name and arguments,
/// its file redirect targets (`> C:\x`) and assigned values (`P=C:\x make`), then the words of
/// every `for` header (`for f in C:\a`).
fn path_spans(script: &Script, command: &str) -> Vec<Span> {
    let mut out = Vec::new();
    for c in programs::commands(script) {
        out.push(c.name.span);
        out.extend(c.args.iter().map(|w| w.span));
        for r in &c.redirects {
            if let Redirect::File { target, .. } = r {
                out.push(target.span);
            }
        }
        out.extend(c.assigns.iter().map(|(_, w)| w.span));
    }
    for_headers(script, command, &mut out);
    out
}

/// The words after `in` of every `for` loop, read from the loop's source text: the parser gives
/// those words the span of the whole loop.
fn for_headers(script: &Script, command: &str, out: &mut Vec<Span>) {
    for st in &script.stmts {
        match st {
            Stmt::Loop { body, span, .. } => {
                out.extend(for_list(command, *span));
                for_headers(body, command, out);
            }
            Stmt::Func { body, .. } | Stmt::Block(body) => for_headers(body, command, out),
            Stmt::Cond { branches, .. } => {
                for b in branches {
                    for_headers(b, command, out);
                }
            }
            Stmt::Pipeline(p) => {
                for e in &p.elems {
                    let Elem::Cmd(c) = e else { continue };
                    for w in std::iter::once(&c.name).chain(&c.args) {
                        for part in &w.parts {
                            if let WordPart::Subst(s) = part {
                                for_headers(s, command, out);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The spans of the words between `for NAME in` and the `;`, newline or `do` that ends the list,
/// in a loop whose text starts with `for`; none for any other loop.
fn for_list(command: &str, span: Span) -> Vec<Span> {
    let text = raw(command, span);
    let mut words = Vec::new();
    let (mut start, mut quote, mut escaped) = (None::<usize>, None::<char>, false);
    for (i, ch) in text.char_indices() {
        let ends = quote.is_none() && !escaped && (ch.is_whitespace() || ch == ';');
        if ends {
            if let Some(s) = start.take() {
                words.push(s..i);
            }
            if ch == ';' || ch == '\n' {
                break;
            }
            continue;
        }
        start.get_or_insert(i);
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && (ch == '\'' || ch == '"') {
            quote = Some(ch);
        }
    }
    match words.as_slice() {
        [first, _, keyword, list @ ..]
            if &text[first.clone()] == "for" && &text[keyword.clone()] == "in" =>
        {
            list.iter()
                .take_while(|w| &text[(*w).clone()] != "do")
                .map(|w| Span {
                    start: span.start + w.start,
                    end: span.start + w.end,
                })
                .collect()
        }
        _ => Vec::new(),
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

// --- bash-ps-call-operator -----------------------------------------------------------------

/// Break: bash refuses the line holding it (syntax error, exit 2) and runs none of that line.
pub const PS_CALL_OPERATOR_LEVEL: Level = Level::Break;

/// How many call operators the Fix takes out of one text before it gives up for the sentence.
const MAX_CALLS: usize = 8;

/// The longest text the Fix rebuilds and parses again; a longer one gets the sentence.
const MAX_FIX_BYTES: usize = 4 * 1024;

const CALL_SENTENCE: &str = "remove the leading & and start the program by its path, or run this command in the PowerShell tool";
const CALL_PS1: &str = "run this command in the PowerShell tool: bash cannot run a .ps1 script";

/// Bash words after which a command starts, where a `&` is a call operator.
const COMMAND_KEYWORDS: [&str; 7] = ["if", "then", "else", "elif", "do", "while", "until"];

/// PowerShell's constants and its pipeline variable: `$null` is empty in bash, `$true` too.
const PS_CONSTANTS: [&str; 4] = ["null", "true", "false", "_"];

/// The lines of `after` that differ from those of `before`; all of `after` when the two do not
/// have the same number of lines (an operand that held a line break).
fn changed_lines(before: &str, after: &str) -> String {
    let old: Vec<&str> = before.trim_end().lines().collect();
    let new: Vec<&str> = after.lines().collect();
    if old.len() != new.len() {
        return after.to_string();
    }
    new.iter()
        .zip(&old)
        .filter(|(n, o)| n != o)
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct PsCallOperator;

impl Rule for PsCallOperator {
    fn id(&self) -> &'static str {
        PS_CALL_OPERATOR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some((at, profile)) = call_operator(ctx) else {
            return;
        };
        let command = ctx.input.command;
        let operand = operand_start(command, at);
        let end = operand + word_len(&command[operand..]);
        let fix = match bash_way(command, profile, ctx.deadline) {
            // A script's Fix is its corrected lines, not the whole file.
            Call::Command(text) if ctx.input.origin == Origin::File => {
                changed_lines(command, &text)
            }
            Call::Command(text) => text,
            Call::Ps1 => CALL_PS1.to_string(),
            Call::Sentence => CALL_SENTENCE.to_string(),
        };
        out.push(finding(
            PS_CALL_OPERATOR,
            PS_CALL_OPERATOR_LEVEL,
            format!(
                "the `&` at {} starts a command, as the PowerShell call operator does; bash reads it as a syntax error and runs none of that line (exit 2)",
                super::parse_error::position(command, at)
            ),
            Some(fix),
            Span { start: at, end },
        ));
    }
}

/// The offset of the PowerShell call operator the parse failed on, in a Bash shell: the syntax
/// error sits at a `&` with an operand after it, or at the `;` of a `;&` before one. Redirects (`&>`, `2>&1`, `<&3`), `|&`, `&&` and
/// a background `&` parse as operators, so no error sits at their `&`; nor in quotes or a heredoc
/// body. With the Bash profile, for the Fix's parse.
pub fn call_operator(ctx: &Ctx) -> Option<(usize, BashProfile)> {
    let Shell::Bash(profile) = ctx.input.shell else {
        return None;
    };
    call_operator_at(ctx.input.command, ctx.parse_error?).map(|at| (at, profile))
}

fn call_operator_at(command: &str, e: &ParseError) -> Option<usize> {
    if e.kind != ParseKind::Syntax {
        return None;
    }
    let mut at = e.span.start;
    // `;&` outside a `case` arm, which bash lexes as one operator: the call operator after `;`.
    if command.get(at..)?.starts_with(";&") {
        at += 1;
    }
    command.get(at..)?.strip_prefix('&')?;
    // An operand a call operator runs: a quoted name, a variable, a script block, an expression
    // or a path. Not another operator (`&&`, `&>`, `&;`) and not the end of the text.
    let operand = &command[operand_start(command, at)..];
    operand
        .starts_with(|c: char| {
            c.is_alphanumeric()
                || matches!(
                    c,
                    '"' | '\'' | '$' | '{' | '(' | '.' | '/' | '\\' | '~' | '_'
                )
        })
        .then_some(at)
}

/// The offset of the operand after the `&` at `at`: past the blanks after it.
fn operand_start(command: &str, at: usize) -> usize {
    let after = &command[at + 1..];
    at + 1 + (after.len() - after.trim_start_matches([' ', '\t']).len())
}

/// The byte length of the shell word `text` starts with: up to an unquoted blank or operator.
fn word_len(text: &str) -> usize {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (i, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            c if !single
                && !double
                && (c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '<' | '>')) =>
            {
                return i;
            }
            _ => {}
        }
    }
    text.len()
}

/// What the Fix of a call operator is.
#[derive(Debug, PartialEq, Eq)]
enum Call {
    /// The text with every call operator taken out, which bash parses.
    Command(String),
    /// The operand is a PowerShell script.
    Ps1,
    /// No command can be built from the text.
    Sentence,
}

/// The text run the Bash way, in one pass: each `&` where a command starts (a call operator) is
/// taken out and its operand written as bash reads it, and every other word must be a form that
/// means the same in bash and PowerShell (`same_word`). Anything else gives the sentence: a
/// PowerShell-only operand (a script block, `$env:X`, an expression), a PowerShell assignment, a
/// heredoc, more than `MAX_CALLS` call operators, a text over `MAX_FIX_BYTES`, the analysis
/// deadline, or a result that does not parse (a `&` this pass does not take for a call operator
/// stays, and bash still refuses it).
fn bash_way(command: &str, profile: BashProfile, deadline: &Deadline) -> Call {
    if command.len() > MAX_FIX_BYTES || has_ps_assignment(command) {
        return Call::Sentence;
    }
    // Git Bash collapses `\\` before bash reads the text, in any quotes.
    let git_bash = profile == BashProfile::GitBash;
    if git_bash && command.contains(PAIR) {
        return Call::Sentence;
    }
    let b = command.as_bytes();
    let mut out = String::with_capacity(command.len());
    let (mut i, mut at_start, mut calls) = (0, true, 0);
    // Inside the words of a call's own command, and right after a redirect operator, whose target
    // is no argument.
    let (mut in_call, mut after_redirect) = (false, false);
    while i < b.len() {
        let next = b.get(i + 1).copied();
        match b[i] {
            b' ' | b'\t' => out.push(char::from(b[i])),
            b'\n' | b';' | b'(' => {
                out.push(char::from(b[i]));
                at_start = true;
            }
            b')' => {
                out.push(')');
                at_start = false;
            }
            // A comment, in both shells.
            b'#' => {
                let end = command[i..].find('\n').map_or(b.len(), |n| i + n);
                out.push_str(&command[i..end]);
                i = end;
                continue;
            }
            b'|' => {
                out.push('|');
                if let Some(c @ (b'|' | b'&')) = next {
                    out.push(char::from(c));
                    i += 1;
                }
                at_start = true;
            }
            b'&' if next == Some(b'&') => {
                out.push_str("&&");
                i += 1;
                at_start = true;
            }
            b'&' if at_start => {
                calls += 1;
                if calls > MAX_CALLS {
                    return Call::Sentence;
                }
                let start = operand_start(command, i);
                let raw = &command[start..start + word_len(&command[start..])];
                let operand = match bash_operand(raw) {
                    Operand::Word(w) => w,
                    Operand::Ps1 => return Call::Ps1,
                    Operand::None => return Call::Sentence,
                };
                let same = if raw.starts_with(['"', '\'']) {
                    same_word(&operand, 0, false, false)
                        .is_some_and(|(end, _)| end == operand.len())
                } else {
                    !is_cmdlet(&operand)
                };
                if !same {
                    return Call::Sentence;
                }
                out.push_str(&operand);
                i = start + raw.len();
                at_start = false;
                in_call = true;
                after_redirect = false;
                continue;
            }
            // A background job.
            b'&' => {
                out.push('&');
                at_start = true;
            }
            b'<' if next == Some(b'<') => return Call::Sentence,
            // `>&2`, `<&3`: a duplication, no call operator.
            b'<' | b'>' => {
                out.push(char::from(b[i]));
                if next == Some(b'&') {
                    out.push('&');
                    i += 1;
                }
                after_redirect = true;
            }
            _ => {
                let quote_vars = in_call && !after_redirect;
                let Some((end, word)) = same_word(command, i, git_bash, quote_vars) else {
                    return Call::Sentence;
                };
                at_start = at_start && COMMAND_KEYWORDS.contains(&word.as_str());
                after_redirect = false;
                out.push_str(&word);
                i = end;
                continue;
            }
        }
        // An operator that starts a command ends the call's own.
        if at_start {
            in_call = false;
        }
        i += 1;
    }
    if deadline.expired() {
        return Call::Sentence;
    }
    match parse::bash::parse(&out, profile) {
        Ok(_) => Call::Command(out.trim_end().to_string()),
        Err(_) => Call::Sentence,
    }
}

/// The word at `i` written for bash, and where it ends, when every part of it means the same in
/// bash and PowerShell: plain characters (letters, digits, `/._+=:%-`), a single-quoted string,
/// a double-quoted string whose `$` starts a `$name`/`${name}` and whose backslashes bash keeps,
/// both of printable ASCII and not doubled (`'it''s'` is one quote in PowerShell), or a whole word
/// `$name`/`${name}`. Not a `-Name:value` parameter nor a cmdlet name, and in Git Bash
/// (`git_bash`) not a word it rewrites as a POSIX path (`/tmp/x`, `--out=/usr/x`).
///
/// An argument of the call's own command (`quote_vars`) may hold a `$name` anywhere, written in
/// double quotes: PowerShell passes `$d`, `$d/f` or `pre$d` as one argument where bash splits it
/// (pwsh 7.7). It must end the word or stand before `/`, `-`, `+`, `%` or another `$`: before `.`
/// it is a property, before `:` a scope, and `$d=x` is two arguments in PowerShell.
fn same_word(text: &str, i: usize, git_bash: bool, quote_vars: bool) -> Option<(usize, String)> {
    let b = text.as_bytes();
    let ends = |j: usize| {
        b.get(j)
            .is_none_or(|c| c.is_ascii_whitespace() || b"|&;()<>".contains(c))
    };
    if b[i] == b'$' && !quote_vars {
        let end = variable(text, i)?;
        return ends(end).then(|| (end, text[i..end].to_string()));
    }
    let printable = |c: u8| c == b'\t' || (b' '..=b'~').contains(&c);
    let mut j = i;
    let mut out = String::new();
    while !ends(j) {
        let from = j;
        match b[j] {
            b'$' if quote_vars => {
                let end = variable(text, j)?;
                if !(ends(end) || b"/-+%$".contains(&b[end])) {
                    return None;
                }
                out.push('"');
                out.push_str(&text[j..end]);
                out.push('"');
                j = end;
                continue;
            }
            b'\'' => {
                let close = j + 1 + text[j + 1..].find('\'')?;
                if !text.as_bytes()[j + 1..close].iter().all(|&c| printable(c)) {
                    return None;
                }
                j = close + 1;
                if b.get(j) == Some(&b'\'') {
                    return None;
                }
            }
            b'"' => {
                j += 1;
                loop {
                    match *b.get(j)? {
                        b'"' => break,
                        b'`' => return None,
                        b'\\'
                            if matches!(b.get(j + 1), Some(b'"' | b'$' | b'`' | b'\\' | b'\n')) =>
                        {
                            return None;
                        }
                        b'$' => {
                            j = variable(text, j)?;
                            if b.get(j) == Some(&b':') {
                                return None;
                            }
                        }
                        c if printable(c) => j += 1,
                        _ => return None,
                    }
                }
                j += 1;
                if b.get(j) == Some(&b'"') {
                    return None;
                }
            }
            c if c.is_ascii_alphanumeric() || b"/._+=:%-".contains(&c) => j += 1,
            _ => return None,
        }
        out.push_str(&text[from..j]);
    }
    // Another blank (`\r`) ends the word before it starts.
    if j == i {
        return None;
    }
    let word = &text[i..j];
    if let Some(rest) = word.strip_prefix('-') {
        let name = rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if name > 0 && rest[name..].starts_with(':') {
            return None;
        }
    }
    // A quoted word keeps its quotes here, so only a bare cmdlet name matches.
    if is_cmdlet(word) || (git_bash && converted(&word.replace(['"', '\''], ""))) {
        return None;
    }
    Some((j, out))
}

/// The end of the `$name` or `${name}` at `i`, a bash variable name that is no PowerShell
/// constant.
fn variable(text: &str, i: usize) -> Option<usize> {
    let rest = &text[i + 1..];
    let (name, end) = match rest.strip_prefix('{') {
        Some(inner) => {
            let n = inner.find('}')?;
            (&inner[..n], i + 3 + n)
        }
        None => {
            let n = rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            (&rest[..n], i + 1 + n)
        }
    };
    let constant = PS_CONSTANTS.iter().any(|c| c.eq_ignore_ascii_case(name));
    (shell_name(name) && !constant).then_some(end)
}

/// A PowerShell cmdlet by its own name (`Out-Null`): an alias such as `ls` is a real program here.
/// Every cmdlet name holds a `-`, which spares the table lookup for most words.
fn is_cmdlet(word: &str) -> bool {
    word.contains('-')
        && crate::parse::pwsh::canonical(word, Shell::Pwsh, Os::Windows).as_deref()
            == Some(word.to_lowercase().as_str())
}

enum Operand {
    Word(String),
    Ps1,
    None,
}

/// The operand as bash runs it: a quoted path as written, `$name` in double quotes, a bare path
/// with forward slashes (bash drops an unquoted backslash).
fn bash_operand(w: &str) -> Operand {
    if unquote(w).to_ascii_lowercase().ends_with(".ps1") {
        return Operand::Ps1;
    }
    let quoted = w.len() >= 2
        && ((w.starts_with('"') && w.ends_with('"')) || (w.starts_with('\'') && w.ends_with('\'')));
    if quoted && one_word(w) {
        return Operand::Word(w.to_string());
    }
    let name = w
        .strip_prefix("${")
        .and_then(|n| n.strip_suffix('}'))
        .or_else(|| w.strip_prefix('$'));
    if let Some(n) = name {
        return if shell_name(n) {
            Operand::Word(format!("\"{}\"", dollar(w, n)))
        } else {
            Operand::None
        };
    }
    let bare = !w.is_empty()
        && w.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '\\' | '.' | ':' | '_' | '-' | '+' | '~')
        });
    if bare {
        Operand::Word(forward_slashes(w))
    } else {
        Operand::None
    }
}

/// `$name` or `${name}`, as the user wrote it.
fn dollar(w: &str, n: &str) -> String {
    if w.starts_with("${") {
        format!("${{{n}}}")
    } else {
        format!("${n}")
    }
}

/// A bash variable name: a letter or `_`, then letters, digits or `_`.
fn shell_name(n: &str) -> bool {
    let mut chars = n.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A statement that starts as a PowerShell assignment (`$t = 'x'`): bash has no such statement,
/// so a Fix that keeps it would still fail.
fn has_ps_assignment(command: &str) -> bool {
    command
        .split([';', '\n', '|', '&', '(', '{'])
        .filter_map(|s| s.trim_start().strip_prefix('$'))
        .any(|s| {
            let name_len = s
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                .unwrap_or(s.len());
            let rest = s[name_len..].trim_start();
            name_len > 0 && rest.starts_with('=') && !rest.starts_with("==")
        })
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

    /// Only a plain syntax error is a call operator's: an error of another kind at a `&` keeps
    /// its own finding (an unclosed quote stays a deny-kind `parse-error`).
    #[test]
    fn a_call_operator_is_only_a_syntax_error() {
        let command = "& \"x.exe\" a";
        let at = |kind| ParseError {
            span: Span { start: 0, end: 1 },
            message: String::new(),
            kind,
        };
        assert_eq!(call_operator_at(command, &at(ParseKind::Syntax)), Some(0));
        for kind in [
            ParseKind::UnclosedQuote(parse::QuoteKind::Double),
            ParseKind::Unmodelled,
            ParseKind::TooDeep,
        ] {
            assert_eq!(call_operator_at(command, &at(kind)), None, "{kind:?}");
        }
    }

    /// Past the analysis deadline the Fix gives the sentence.
    #[test]
    fn the_call_operator_fix_stops_at_the_deadline() {
        let command = "& \"C:/t/a.exe\" x";
        let open = Deadline::new(std::time::Instant::now(), 8000);
        let gone = Deadline::new(std::time::Instant::now(), 0);
        let fix = |d: &Deadline| bash_way(command, BashProfile::GitBash, d);
        assert_eq!(fix(&open), Call::Command("\"C:/t/a.exe\" x".to_string()));
        assert_eq!(fix(&gone), Call::Sentence);
    }

    /// Git Bash collapses `\\` in any quotes before bash reads the text, so there the Fix would
    /// pass one backslash; POSIX bash keeps both in single quotes.
    #[test]
    fn the_call_operator_fix_refuses_a_backslash_pair_in_git_bash() {
        let open = Deadline::new(std::time::Instant::now(), 8000);
        let command = "& \"C:/t/a.exe\" '\\\\server\\share'";
        assert_eq!(
            bash_way(command, BashProfile::GitBash, &open),
            Call::Sentence
        );
        assert_eq!(
            bash_way(command, BashProfile::Posix, &open),
            Call::Command("\"C:/t/a.exe\" '\\\\server\\share'".to_string())
        );
    }

    /// Ruling 150: the Fix is built for a text of at most 4 KiB; one byte more gets the sentence.
    #[test]
    fn the_call_operator_fix_is_built_up_to_4_kib() {
        let open = Deadline::new(std::time::Instant::now(), 8000);
        let of_len = |n: usize| {
            let mut s = String::from("& \"C:/t/a.exe\" x\n");
            while s.len() + 7 <= n {
                s.push_str("echo a\n");
            }
            s.push_str(&"#".repeat(n - s.len()));
            assert_eq!(s.len(), n);
            s
        };
        assert!(matches!(
            bash_way(&of_len(4096), BashProfile::GitBash, &open),
            Call::Command(_)
        ));
        assert_eq!(
            bash_way(&of_len(4097), BashProfile::GitBash, &open),
            Call::Sentence
        );
    }

    /// The Fix rebuilds a text of at most `MAX_FIX_BYTES`: a longer one gets the sentence.
    #[test]
    fn the_call_operator_fix_stops_at_its_byte_budget() {
        let open = Deadline::new(std::time::Instant::now(), 8000);
        let fix = |text: &str| bash_way(text, BashProfile::GitBash, &open);
        let call = "& \"C:/t/a.exe\" x\n";
        let small = format!("{call}{}", "echo a\n".repeat(100));
        let big = format!("{call}{}", "echo a\n".repeat(MAX_FIX_BYTES / 7));
        assert!(matches!(fix(&small), Call::Command(_)));
        assert_eq!(fix(&big), Call::Sentence);
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
