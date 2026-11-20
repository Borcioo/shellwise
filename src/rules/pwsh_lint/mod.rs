//! The PowerShell lint rules: commands that break, write the wrong thing or hang when an agent
//! runs them in the PowerShell tool.
//!
//! - `ports`: the installed baseline guard rules: `ps-bad-parameter`, `ps-native-nonewline`,
//!   `stale-write-var`, `ps-git-commit-stdin` and `cli-inline-prose` at its level (break);
//!   `gate-truncated-pipeline`, `ps-bare-bash` and `ps-dotnet-relative-path` at warn. `bat` holds
//!   `bat-metachar` (break).
//! - `catalogue`: the rules from the trap catalogue (warn).
//! - `table` and `bind`: the generated pwsh 7 command table and the parameter binder.
//!
//! Every program, cmdlet and option name comes from data: `data/programs.toml` (each row's `lint`
//! table: `tags` and the option lists the rules read) and the command table. Parameter names
//! compared in code are the table's canonical names, after binding.
//!
//! Derived in part from Specter (https://github.com/rjmholt/Specter), a reimplementation of
//! PSScriptAnalyzer: the table's shape follows its command database, and `ps-bad-parameter`,
//! `ps-auto-variable` and `cli-inline-prose` follow a Specter rule each (named on the rule's
//! doc). Specter's licence notice:
//!
//! > MIT License. Copyright (c) Specter Contributors. Permission is hereby granted, free of
//! > charge, to any person obtaining a copy of this software and associated documentation files
//! > (the "Software"), to deal in the Software without restriction, including without limitation
//! > the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
//! > of the Software, and to permit persons to whom the Software is furnished to do so, subject
//! > to the following conditions: The above copyright notice and this permission notice shall be
//! > included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED
//! > "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
//! > WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
//! > EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
//! > CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use super::{Ctx, Rule};
use crate::ir::{Elem, MethodCall, Pipeline, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::programs::{self, Program};
use crate::{Os, Shell};

mod bat;
mod bind;
mod catalogue;
mod ports;
mod table;

pub use bat::BAT_METACHAR;
pub use catalogue::{
    CLAUDE_CMD_LIVE_CONFIG, PS_AUTO_VARIABLE, PS_EMPTY_ARG, PS_KILL_WRAPPER, PS_REMOVE_ITEM_STAR,
    PS_STDIN_SCRIPT, PS_UNIX_COMMAND, PWSH_FILE_LIST_ARG, RG_FOLLOW_L, WSL_ARGV_REJOIN,
};
pub use ports::{
    CLI_INLINE_PROSE, GATE_TRUNCATED_PIPELINE, PS_BAD_PARAMETER, PS_BARE_BASH,
    PS_DOTNET_RELATIVE_PATH, PS_GIT_COMMIT_STDIN, PS_NATIVE_NONEWLINE, STALE_WRITE_VAR,
};

use table::Facts;

/// Every rule of this module, in the order they run.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(bat::BatMetachar),
        Box::new(ports::GateTruncatedPipeline),
        Box::new(ports::BadParameter),
        Box::new(ports::BareBash),
        Box::new(ports::NativeNonewline),
        Box::new(ports::DotnetRelativePath),
        Box::new(ports::StaleWriteVar),
        Box::new(ports::GitCommitStdin),
        Box::new(ports::InlineProse),
        Box::new(catalogue::UnixCommand),
        Box::new(catalogue::FileListArg),
        Box::new(catalogue::KillWrapper),
        Box::new(catalogue::AutoVariable),
        Box::new(catalogue::RemoveItemStar),
        Box::new(catalogue::StdinScript),
        Box::new(catalogue::EmptyArg),
        Box::new(catalogue::RgFollow),
        Box::new(catalogue::WslArgvRejoin),
        Box::new(catalogue::ClaudeLiveConfig),
    ]
}

// ---------------------------------------------------------------------------------------------
// Facts from `data/programs.toml`
// ---------------------------------------------------------------------------------------------

/// The row `name` names in this shell.
fn program(ctx: &Ctx, name: &str) -> Option<&'static Program> {
    programs::lookup(name, ctx.input.shell, ctx.input.os)
}

/// The row of a command: by the cmdlet an alias resolves to, else by the name as typed.
fn program_of(ctx: &Ctx, c: &SimpleCommand) -> Option<&'static Program> {
    if c.opaque {
        return None;
    }
    c.canonical
        .as_deref()
        .and_then(|n| program(ctx, n))
        .or_else(|| program(ctx, &c.typed))
}

/// The strings of `lint.<key>` on a row.
fn lint<'p>(p: &'p Program, key: &str) -> Vec<&'p str> {
    p.extra
        .get("lint")
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default()
}

fn tagged(p: &Program, tag: &str) -> bool {
    lint(p, "tags").contains(&tag)
}

fn command_tagged(ctx: &Ctx, c: &SimpleCommand, tag: &str) -> Option<&'static Program> {
    program_of(ctx, c).filter(|p| tagged(p, tag))
}

// ---------------------------------------------------------------------------------------------
// The script walk
// ---------------------------------------------------------------------------------------------

/// A simple command and where it stands: its pipeline and its index in it.
#[derive(Clone, Copy)]
struct Site<'a> {
    cmd: &'a SimpleCommand,
    pipe: &'a Pipeline,
    index: usize,
}

/// Everything the rules read from one script.
#[derive(Default)]
struct Walk<'a> {
    sites: Vec<Site<'a>>,
    methods: Vec<&'a MethodCall>,
    /// Functions the script defines, lowercase: a call to one is not the cmdlet of that name.
    functions: Vec<String>,
    /// Variables the script assigns, lowercase, without a scope prefix.
    assigned: Vec<String>,
}

fn walk(script: &Script) -> Walk<'_> {
    let mut w = Walk::default();
    let mut scripts: Vec<&Script> = vec![script];
    let mut words: Vec<&Word> = Vec::new();
    loop {
        if let Some(word) = words.pop() {
            for p in &word.parts {
                if let WordPart::Subst(s) | WordPart::Block(s) = p {
                    scripts.push(s);
                }
            }
            continue;
        }
        let Some(s) = scripts.pop() else { break };
        for st in &s.stmts {
            match st {
                Stmt::Pipeline(p) => {
                    for (index, e) in p.elems.iter().enumerate() {
                        match e {
                            Elem::Cmd(c) => {
                                w.sites.push(Site {
                                    cmd: c,
                                    pipe: p,
                                    index,
                                });
                                for (name, value) in &c.assigns {
                                    w.assigned.push(plain_var(name));
                                    words.push(value);
                                }
                                words.push(&c.name);
                                words.extend(c.args.iter());
                            }
                            Elem::Method(m) => {
                                w.methods.push(m);
                                words.extend(m.args.iter());
                            }
                            Elem::Expr(x) => words.push(x),
                        }
                    }
                }
                Stmt::Func { name, body } => {
                    w.functions.push(name.to_lowercase());
                    scripts.push(body);
                }
                Stmt::Loop { body, .. } | Stmt::Block(body) => scripts.push(body),
                Stmt::Cond { branches, .. } => scripts.extend(branches.iter()),
            }
        }
    }
    w
}

/// The scope prefix of an environment variable.
const ENV_SCOPE: &str = "env:";

/// `script:x` → `x`; `env:X` stays as it is (an environment variable).
fn plain_var(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.starts_with(ENV_SCOPE) {
        return lower;
    }
    match lower.split_once(':') {
        Some((_, rest)) => rest.to_string(),
        None => lower,
    }
}

fn is_pwsh(ctx: &Ctx) -> bool {
    matches!(ctx.input.shell, Shell::Pwsh | Shell::Powershell5)
}

fn text(src: &str, s: Span) -> &str {
    src.get(s.start..s.end).unwrap_or("")
}

/// The word's value when every part is literal.
fn literal(w: &Word) -> Option<String> {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) | WordPart::Glob(s) => out.push_str(s),
            _ => return None,
        }
    }
    Some(out)
}

fn has_folder(name: &str) -> bool {
    name.contains(['/', '\\'])
}

/// The table name of a command: the cmdlet its alias or name resolves to, when the table holds
/// it and the script does not define a function of that name. The parser's alias resolution
/// comes first; the table's aliases are Windows ones.
fn table_name(c: &SimpleCommand, t: Facts, os: Os, w: &Walk) -> Option<&'static table::Cmdlet> {
    if c.opaque || c.typed.is_empty() {
        return None;
    }
    let lower = c.typed.to_lowercase();
    if w.functions.contains(&lower) {
        return None;
    }
    // `Microsoft.PowerShell.Utility\Select-String`: a module-qualified name.
    let bare = match lower.rsplit_once('\\') {
        Some((module, name))
            if !module.is_empty()
                && module
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_') =>
        {
            name.to_string()
        }
        Some(_) => return None,
        None if has_folder(&lower) => return None,
        None => lower,
    };
    let name = c
        .canonical
        .as_deref()
        .map(str::to_lowercase)
        .or_else(|| {
            (os == Os::Windows)
                .then(|| t.alias_target(&bare))
                .flatten()
                .map(str::to_string)
        })
        .unwrap_or(bare);
    t.cmdlet(&name)
}

/// The command's text with the byte range `cut` of the source replaced by `with`.
fn replaced(src: &str, whole: Span, cut: Span, with: &str) -> String {
    let start = cut.start.clamp(whole.start, whole.end);
    let end = cut.end.clamp(start, whole.end);
    format!("{}{with}{}", &src[whole.start..start], &src[end..whole.end])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn finding(rule: &'static str, level: Level, span: Span, message: String, fix: String) -> Finding {
    Finding {
        rule,
        level,
        message,
        fix: Some(fix),
        span,
    }
}

/// The pipeline element before `site`, if any.
fn upstream<'a>(site: &Site<'a>) -> Option<&'a Elem> {
    site.index
        .checked_sub(1)
        .and_then(|i| site.pipe.elems.get(i))
}

fn elem_span(e: &Elem) -> Span {
    match e {
        Elem::Cmd(c) => c.span,
        Elem::Method(m) => m.span,
        Elem::Expr(w) => w.span,
    }
}

/// A native program (not a cmdlet, alias, function or script): its output reaches the next
/// stage as lines of text.
fn is_native(c: &SimpleCommand, t: Facts, os: Os, w: &Walk) -> bool {
    if c.opaque || c.typed.is_empty() || c.canonical.is_some() {
        return false;
    }
    let lower = c.typed.to_lowercase();
    if lower.ends_with(".ps1") || w.functions.contains(&lower) || table_name(c, t, os, w).is_some()
    {
        return false;
    }
    // A Verb-Noun name with an approved verb is a cmdlet from some module.
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    !base
        .split_once('-')
        .is_some_and(|(verb, noun)| !noun.is_empty() && t.is_approved_verb(verb))
}
