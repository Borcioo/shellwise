//! The PowerShell lint rules: commands that break, write the wrong thing or hang when an agent
//! runs them in the PowerShell tool.
//!
//! - Ports of the installed baseline-guard rules, at its level (break): `bat-metachar`,
//!   `gate-truncated-pipeline`, `ps-bad-parameter`, `ps-bare-bash`, `ps-native-nonewline`,
//!   `ps-dotnet-relative-path`, `stale-write-var`, `ps-git-commit-stdin`, `cli-inline-prose`.
//! - Rules from the trap catalogue (warn): `ps-unix-command`, `pwsh-file-list-arg`,
//!   `ps-kill-wrapper`, `ps-auto-variable`, `ps-remove-item-star`, `ps-stdin-script`,
//!   `ps-empty-arg`, `rg-follow-L`, `wsl-argv-rejoin`, `claude-cmd-live-config`.
//! - Ports of Specter rules (warn): `ps-missing-mandatory`, `ps-misleading-backtick`,
//!   `ps-null-comparison`, `ps-assign-in-condition`,
//!   `ps-redirect-in-condition`; `ps-bad-parameter`, `ps-auto-variable` and `cli-inline-prose`
//!   also follow a Specter rule each.
//!
//! Derived in part from Specter (https://github.com/rjmholt/Specter), a reimplementation of
//! PSScriptAnalyzer. Specter's licence notice:
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
//!
//! The Specter source of each derived rule is named on the rule. Every program, cmdlet and option
//! name comes from data: `data/programs.toml` (each row's `lint` table: `tags` and the option
//! lists below) and the generated command table `data/pwsh_commands.tsv`
//! (`tools/pwsh_commands.ps1`). Parameter names compared in code are the table's canonical names,
//! after binding.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tree_sitter::{Node, Parser, Tree};

use super::{Ctx, Rule};
use crate::ir::{Elem, MethodCall, Pipeline, Quote, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::parse::cmd::reparse_bat_arg;
use crate::programs::{self, Program};
use crate::{Os, Shell};

/// Every rule of this file, in the order they run.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(BatMetachar),
        Box::new(GateTruncatedPipeline),
        Box::new(BadParameter),
        Box::new(BareBash),
        Box::new(NativeNonewline),
        Box::new(DotnetRelativePath),
        Box::new(StaleWriteVar),
        Box::new(GitCommitStdin),
        Box::new(InlineProse),
        Box::new(UnixCommand),
        Box::new(FileListArg),
        Box::new(KillWrapper),
        Box::new(AutoVariable),
        Box::new(RemoveItemStar),
        Box::new(StdinScript),
        Box::new(EmptyArg),
        Box::new(RgFollow),
        Box::new(WslArgvRejoin),
        Box::new(ClaudeLiveConfig),
        Box::new(MissingMandatory),
        Box::new(MisleadingBacktick),
        Box::new(NullComparison),
        Box::new(AssignInCondition),
        Box::new(RedirectInCondition),
    ]
}

// ---------------------------------------------------------------------------------------------
// The generated command table (`data/pwsh_commands.tsv`)
// ---------------------------------------------------------------------------------------------

const TABLE_TEXT: &str = include_str!("../../data/pwsh_commands.tsv");

/// Row kinds of the table (its header lists the columns).
const ROW_CMDLET: &str = "cmdlet";
const ROW_PARAM: &str = "param";
const ROW_COMMON: &str = "common";
const ROW_ALIAS: &str = "aka";
const ROW_VARIABLE: &str = "variable";
const ROW_VERB: &str = "verb";
const ROW_DOTNET: &str = "dotnet";

/// The table's rows, indexed once per process by command name.
struct Index {
    /// Command name → its `cmdlet` and `param` rows.
    commands: HashMap<&'static str, Vec<Vec<&'static str>>>,
    common: Vec<Vec<&'static str>>,
    /// Alias → its rows (editions, target).
    aliases: HashMap<&'static str, Vec<Vec<&'static str>>>,
    variables: HashMap<&'static str, Vec<Vec<&'static str>>>,
    verbs: Vec<Vec<&'static str>>,
    /// .NET methods that take a path: (editions, type, method, positions).
    dotnet: Vec<Vec<&'static str>>,
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut ix = Index {
            commands: HashMap::new(),
            common: Vec::new(),
            aliases: HashMap::new(),
            variables: HashMap::new(),
            verbs: Vec::new(),
            dotnet: Vec::new(),
        };
        for line in TABLE_TEXT.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let f: Vec<&'static str> = line.split('\t').collect();
            if f.len() < 3 {
                continue;
            }
            match f[0] {
                ROW_CMDLET | ROW_PARAM => ix.commands.entry(f[2]).or_default().push(f),
                ROW_COMMON => ix.common.push(f),
                ROW_ALIAS => ix.aliases.entry(f[2]).or_default().push(f),
                ROW_VARIABLE => ix.variables.entry(f[2]).or_default().push(f),
                ROW_VERB => ix.verbs.push(f),
                ROW_DOTNET => ix.dotnet.push(f),
                _ => {}
            }
        }
        ix
    })
}

/// The table's edition key for a dialect: `7` for pwsh, `5` for Windows PowerShell 5.1.
fn edition(shell: Shell) -> char {
    match shell {
        Shell::Powershell5 => '5',
        _ => '7',
    }
}

fn other_edition(ed: char) -> char {
    if ed == '5' { '7' } else { '5' }
}

fn in_edition(row: &[&str], ed: char) -> bool {
    row.get(1).is_some_and(|e| e.contains(ed))
}

/// One member of a parameter set: the set, the position (`-1` for named only), mandatory.
#[derive(Debug, Clone)]
struct Member {
    set: &'static str,
    position: i32,
    mandatory: bool,
}

#[derive(Debug, Clone)]
struct Param {
    name: &'static str,
    switch: bool,
    /// A provider's dynamic parameter: bound only when no other parameter matches.
    dynamic: bool,
    aliases: Vec<&'static str>,
    sets: Vec<Member>,
    common: bool,
}

/// A cmdlet or function of one edition, with the parameters it binds.
#[derive(Debug, Clone)]
struct Cmdlet {
    name: &'static str,
    flags: &'static str,
    params: Vec<Param>,
}

impl Cmdlet {
    /// Takes `ValueFromRemainingArguments`: an unknown `-name` is bound as an argument.
    fn takes_remaining(&self) -> bool {
        self.flags.contains('R')
    }
}

fn split_list(s: &'static str) -> Vec<&'static str> {
    s.split(',').filter(|x| !x.is_empty()).collect()
}

fn members(s: &'static str) -> Vec<Member> {
    s.split(';')
        .filter_map(|m| {
            let mut it = m.split(':');
            let set = it.next()?;
            let position = it.next()?.parse().ok()?;
            let mandatory = it.next()? == "1";
            Some(Member {
                set,
                position,
                mandatory,
            })
        })
        .collect()
}

/// The command `name` (lowercase) of edition `ed`, or `None` when the table does not hold it.
fn cmdlet(name: &str, ed: char) -> Option<Cmdlet> {
    let rows = index().commands.get(name)?;
    let head = rows
        .iter()
        .find(|r| r[0] == ROW_CMDLET && in_edition(r, ed))?;
    let flags = head.get(6).copied().unwrap_or("");
    let mut params: Vec<Param> = rows
        .iter()
        .filter(|r| r[0] == ROW_PARAM && in_edition(r, ed) && r.len() >= 8)
        .map(|r| Param {
            name: r[3],
            switch: r[4] == "switch",
            dynamic: r[5] == "1",
            aliases: split_list(r[6]),
            sets: members(r[7]),
            common: false,
        })
        .collect();
    for r in &index().common {
        if !in_edition(r, ed) || r.len() < 6 {
            continue;
        }
        let group = r[5];
        if !flags.contains(group) {
            continue;
        }
        params.push(Param {
            name: r[2],
            switch: r[3] == "switch",
            dynamic: false,
            aliases: split_list(r[4]),
            sets: Vec::new(),
            common: true,
        });
    }
    Some(Cmdlet {
        name: head[2],
        flags,
        params,
    })
}

/// The command an alias names in edition `ed`.
fn alias_target(name: &str, ed: char) -> Option<&'static str> {
    index()
        .aliases
        .get(name)?
        .iter()
        .find(|r| in_edition(r, ed) && r.len() >= 4)
        .map(|r| r[3])
}

/// What a session does with an assignment to `$name`: `constant`/`readonly` (it fails),
/// `automatic` (PowerShell overwrites it), `session` (the session set it), or `None`.
fn variable_kind(name: &str, ed: char) -> Option<&'static str> {
    index()
        .variables
        .get(name.to_lowercase().as_str())?
        .iter()
        .find(|r| in_edition(r, ed) && r.len() >= 4)
        .map(|r| r[3])
}

fn is_approved_verb(verb: &str) -> bool {
    let v = verb.to_lowercase();
    index().verbs.iter().any(|r| r.get(2) == Some(&v.as_str()))
}

/// How PowerShell binds a parameter name.
enum Bound<'c> {
    Param(&'c Param),
    Ambiguous(Vec<&'static str>),
    Missing,
}

/// Bind `typed` (the name after the dash) as PowerShell does: an exact name, then an exact alias,
/// then a unique prefix of a name or an alias; when several parameters match, a single one that
/// is not a common parameter wins. Dynamic parameters are tried only when no other one matches
/// (`Get-ChildItem -fo` binds `-Force`, not `-FollowSymlink`). Checked against real calls in
/// pwsh 7.7 and 5.1, and against `CommandInfo.ResolveParameter` for static parameters.
fn bind<'c>(c: &'c Cmdlet, typed: &str) -> Bound<'c> {
    match bind_among(c, typed, false) {
        Bound::Missing => bind_among(c, typed, true),
        found => found,
    }
}

fn bind_among<'c>(c: &'c Cmdlet, typed: &str, dynamic: bool) -> Bound<'c> {
    let n = typed.to_lowercase();
    let pool: Vec<&Param> = c.params.iter().filter(|p| p.dynamic == dynamic).collect();
    if let Some(p) = pool.iter().find(|p| p.name == n) {
        return Bound::Param(*p);
    }
    if let Some(p) = pool.iter().find(|p| p.aliases.contains(&n.as_str())) {
        return Bound::Param(*p);
    }
    let hits: Vec<&Param> = pool
        .into_iter()
        .filter(|p| p.name.starts_with(&n) || p.aliases.iter().any(|a| a.starts_with(&n)))
        .collect();
    match hits.as_slice() {
        [] => Bound::Missing,
        [one] => Bound::Param(*one),
        _ => {
            let own: Vec<&&Param> = hits.iter().filter(|p| !p.common).collect();
            match own.as_slice() {
                [one] => Bound::Param(**one),
                _ => Bound::Ambiguous(hits.iter().map(|p| p.name).collect()),
            }
        }
    }
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

/// The scope prefix of an environment variable.
const ENV_SCOPE: &str = "env:";

fn is_pwsh(ctx: &Ctx) -> bool {
    matches!(ctx.input.shell, Shell::Pwsh | Shell::Powershell5)
}

fn text<'a>(src: &'a str, s: Span) -> &'a str {
    src.get(s.start..s.end).unwrap_or("")
}

/// A dash PowerShell reads as the start of a parameter: ASCII `-` and the en, em and horizontal
/// bar dashes.
fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

/// A parameter token as written: the name after the dash, and the value after `:` when it is
/// attached (`-Path:x`).
struct ParamToken<'a> {
    name: &'a str,
    attached: Option<&'a str>,
}

/// The parameter token `w` is, or `None` for an argument: an unquoted dash then a letter, `_` or
/// `?` (a negative number is an argument).
fn param_token<'a>(src: &'a str, w: &Word) -> Option<ParamToken<'a>> {
    if matches!(w.quote, Quote::Single | Quote::Double) {
        return None;
    }
    if !matches!(w.parts.first(), Some(WordPart::Literal(_))) {
        return None;
    }
    let raw = text(src, w.span);
    let mut chars = raw.char_indices();
    let (_, first) = chars.next()?;
    if !is_dash(first) {
        return None;
    }
    let (at, second) = chars.next()?;
    // `--name` is an argument: PowerShell binds it to no parameter.
    if !(second.is_alphabetic() || second == '_' || second == '?') {
        return None;
    }
    let body = &raw[at..];
    Some(match body.split_once(':') {
        Some((name, value)) => ParamToken {
            name,
            attached: Some(value),
        },
        None => ParamToken {
            name: body,
            attached: None,
        },
    })
}

/// `--`: the end of parameters, after which every word is an argument.
fn ends_parameters(src: &str, w: &Word) -> bool {
    w.quote == Quote::None && text(src, w.span) == "--"
}

/// `--%`: stop parsing; the rest of the line goes to the program as written.
fn stops_parsing(src: &str, w: &Word) -> bool {
    text(src, w.span).starts_with("--%")
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

/// The table name of a command in edition `ed`: the cmdlet its alias or name resolves to, when
/// the table holds it and the script does not define a function of that name.
fn table_name(c: &SimpleCommand, ed: char, w: &Walk) -> Option<String> {
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
        .clone()
        .or_else(|| alias_target(&bare, ed).map(str::to_string))
        .unwrap_or(bare);
    cmdlet(&name, ed).map(|_| name)
}

/// Each argument of a cmdlet call with what binding makes of it.
enum Arg<'w> {
    /// A parameter token and what it binds to; `value` is the separate word it takes.
    Named {
        word: &'w Word,
        token_name: String,
        attached: Option<String>,
        bound: Option<&'static str>,
        problem: Option<Problem>,
        value: Option<&'w Word>,
    },
    Positional(&'w Word),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Problem {
    Missing,
    Ambiguous(Vec<&'static str>),
    NoValue(&'static str),
}

/// The arguments of `c` bound against `cmd`, as PowerShell's binder reads them; `None` after
/// `--%`, which hands the rest to the program as text.
fn bind_args<'w>(src: &str, c: &'w SimpleCommand, cmd: &Cmdlet) -> Option<Vec<Arg<'w>>> {
    // `bind` borrows the cmdlet; the names it returns are 'static table text.
    let mut out = Vec::new();
    let mut i = 0;
    let mut params_over = false;
    while i < c.args.len() {
        let w = &c.args[i];
        if stops_parsing(src, w) {
            return None;
        }
        if !params_over && ends_parameters(src, w) {
            params_over = true;
            i += 1;
            continue;
        }
        let token = if params_over {
            None
        } else {
            param_token(src, w)
        };
        let Some(t) = token else {
            out.push(Arg::Positional(w));
            i += 1;
            continue;
        };
        let (bound, mut problem, switch) = match bind(cmd, t.name) {
            Bound::Param(p) => (Some(p.name), None, p.switch),
            Bound::Ambiguous(names) => (None, Some(Problem::Ambiguous(names)), true),
            Bound::Missing => (None, Some(Problem::Missing), true),
        };
        let mut value = None;
        if !switch && t.attached.is_none() {
            match c.args.get(i + 1) {
                Some(next) if param_token(src, next).is_none() && !stops_parsing(src, next) => {
                    value = Some(next);
                    i += 1;
                }
                _ => problem = bound.map(Problem::NoValue),
            }
        }
        out.push(Arg::Named {
            word: w,
            token_name: t.name.to_string(),
            attached: t.attached.map(str::to_string),
            bound,
            problem,
            value,
        });
        i += 1;
    }
    Some(out)
}

/// The bound parameter `param` of the call, with its separate value word or attached text.
fn named<'a, 'w>(args: &'a [Arg<'w>], param: &str) -> Option<&'a Arg<'w>> {
    args.iter()
        .find(|a| matches!(a, Arg::Named { bound: Some(b), .. } if *b == param))
}

/// A switch given and not turned off with `:$false`.
fn switch_on(args: &[Arg], param: &str) -> bool {
    matches!(named(args, param), Some(Arg::Named { attached, .. })
        if !attached.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("$false")))
}

fn positional<'a, 'w>(args: &'a [Arg<'w>]) -> Vec<&'w Word> {
    args.iter()
        .filter_map(|a| match a {
            Arg::Positional(w) => Some(*w),
            _ => None,
        })
        .collect()
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
    site.index.checked_sub(1).and_then(|i| site.pipe.elems.get(i))
}

/// A native program (not a cmdlet, alias, function or script): its output reaches the next
/// stage as lines of text.
fn is_native(c: &SimpleCommand, ed: char, w: &Walk) -> bool {
    if c.opaque || c.typed.is_empty() || c.canonical.is_some() {
        return false;
    }
    let lower = c.typed.to_lowercase();
    if lower.ends_with(".ps1") || w.functions.contains(&lower) || table_name(c, ed, w).is_some() {
        return false;
    }
    // A Verb-Noun name with an approved verb is a cmdlet from some module.
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    !base
        .split_once('-')
        .is_some_and(|(verb, noun)| !noun.is_empty() && is_approved_verb(verb))
}

// ---------------------------------------------------------------------------------------------
// The tree-sitter tree, for the rules that read expressions the IR does not keep
// ---------------------------------------------------------------------------------------------

thread_local! {
    /// The last text parsed on this thread and its tree: the rules of one check share it.
    static TREE: RefCell<Option<(String, Tree)>> = const { RefCell::new(None) };
}

/// Run `f` on the tree of `src`, parsing it once per check.
fn with_tree<R>(src: &str, f: impl FnOnce(Node) -> R) -> Option<R> {
    TREE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.as_ref().is_none_or(|(s, _)| s != src) {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_powershell::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(src, None)?;
            *slot = Some((src.to_string(), tree));
        }
        slot.as_ref().map(|(_, t)| f(t.root_node()))
    })
}

/// Every node under `root` (itself included), depth first, without recursion.
fn descendants<'t>(root: Node<'t>, skip_into: &[&str]) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        out.push(n);
        if n.id() != root.id() && skip_into.contains(&n.kind()) {
            continue;
        }
        let mut cursor = n.walk();
        let kids: Vec<Node> = n.children(&mut cursor).collect();
        stack.extend(kids.into_iter().rev());
    }
    out
}

fn node_text<'a>(src: &'a str, n: Node) -> &'a str {
    src.get(n.start_byte()..n.end_byte()).unwrap_or("")
}

fn node_span(n: Node) -> Span {
    Span {
        start: n.start_byte(),
        end: n.end_byte(),
    }
}

/// The condition pipelines of every `if`, `elseif`, `while` and `do` statement.
fn conditions(root: Node) -> Vec<Node> {
    let mut out = Vec::new();
    for n in descendants(root, &[]) {
        match n.kind() {
            "if_statement" | "elseif_clause" => out.extend(n.child_by_field_name("condition")),
            "while_statement" | "do_statement" => {
                if let Some(c) = n.child_by_field_name("condition") {
                    let mut cursor = c.walk();
                    out.extend(c.named_children(&mut cursor).filter(|k| k.kind() == "pipeline"));
                }
            }
            _ => {}
        }
    }
    out
}

/// The tree-sitter rules run only on a text that parsed: a parse error has its own finding.
fn parsed(ctx: &Ctx) -> bool {
    is_pwsh(ctx) && ctx.parse_error.is_none()
}

// ---------------------------------------------------------------------------------------------
// bat-metachar
// ---------------------------------------------------------------------------------------------

pub const BAT_METACHAR: &str = "bat-metachar";

/// An argument to a `.bat`/`.cmd` launcher that cmd.exe re-parses: an operator character outside
/// double quotes, or a `%NAME%` of a defined variable (expanded even inside quotes). Launchers are
/// the names in `cfg.bat_launchers`, or any name ending in `.bat` or `.cmd`; a launcher name is
/// checked to reach cmd.exe the way PowerShell finds it (PATH, PATHEXT, `.ps1` first).
pub struct BatMetachar;

impl Rule for BatMetachar {
    fn id(&self) -> &'static str {
        BAT_METACHAR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if c.opaque || c.typed.is_empty() || c.canonical.is_some() {
                continue;
            }
            let explicit = has_bat_extension(&c.typed);
            // The launcher patterns compile globs: matched only once an argument needs it.
            let mut launcher: Option<bool> = explicit.then_some(true);
            for (k, arg) in c.args.iter().enumerate() {
                if stops_parsing(src, arg) {
                    break;
                }
                let Some(value) = literal(arg) else { continue };
                let r = reparse_bat_arg(&value, ps_wraps(&value));
                let defined = r.percent_vars.iter().find(|n| env_defined(ctx, n));
                if r.metachars.is_empty() && defined.is_none() {
                    continue;
                }
                let named_launcher = *launcher
                    .get_or_insert_with(|| launcher_named(&c.typed, &ctx.cfg.bat_launchers));
                if !named_launcher || (!explicit && !reaches_cmd(ctx, &c.typed)) {
                    break;
                }
                let raw = text(src, arg.span);
                let fix = bat_fix(ctx, c, k, defined.is_some());
                let message = match defined {
                    Some(name) => format!(
                        "`{}` is a .bat launcher, so cmd.exe replaces `%{name}%` in the argument {raw} with that variable's value before the program sees it, even inside quotes",
                        c.typed
                    ),
                    None => format!(
                        "`{}` is a .bat launcher, so cmd.exe re-parses the argument {raw} and treats its `{}` as an operator (\"... is not recognized as an internal or external command\", or the character vanishes)",
                        c.typed, r.metachars[0]
                    ),
                };
                out.push(finding(BAT_METACHAR, Level::Break, arg.span, message, fix));
                break;
            }
        }
    }
}

fn has_bat_extension(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// `name` matches a `bat_launchers` pattern: on its file name when the pattern has no folder, on
/// its path (folders `/` or `\`, any leading folders) otherwise; `*` and `[...]` as in a glob.
fn launcher_named(name: &str, patterns: &[String]) -> bool {
    let norm = name.replace('\\', "/").to_lowercase();
    let norm = norm.trim_start_matches("./").to_string();
    let base = norm.rsplit('/').next().unwrap_or(&norm).to_string();
    let base = base
        .strip_suffix(".bat")
        .or_else(|| base.strip_suffix(".cmd"))
        .unwrap_or(&base)
        .to_string();
    let path = norm
        .strip_suffix(".bat")
        .or_else(|| norm.strip_suffix(".cmd"))
        .unwrap_or(&norm)
        .to_string();
    patterns.iter().any(|p| {
        let p = p.replace('\\', "/").to_lowercase();
        let (subject, globs) = if p.contains('/') {
            (path.as_str(), vec![p.clone(), format!("*/{p}")])
        } else {
            (base.as_str(), vec![p.clone()])
        };
        globs.iter().any(|g| {
            globset::GlobBuilder::new(g)
                .literal_separator(false)
                .backslash_escape(false)
                .build()
                .is_ok_and(|m| m.compile_matcher().is_match(subject))
        })
    })
}

/// PowerShell's rule for a native argument to a batch file: it wraps the value in double quotes
/// when it is empty or holds whitespace outside its own double quotes (a `"` after `\` does not
/// count).
fn ps_wraps(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut quotes = 0;
    let mut prev = '\0';
    for ch in value.chars() {
        if ch == '"' && prev != '\\' {
            quotes += 1;
        } else if ch.is_whitespace() && quotes % 2 == 0 {
            return true;
        }
        prev = ch;
    }
    false
}

fn env_value(ctx: &Ctx, name: &str) -> Option<String> {
    ctx.input
        .env
        .get(name)
        .map(str::to_string)
        .or_else(|| std::env::var(name).ok())
}

/// cmd.exe expands `%NAME%` only for a defined variable (names ignore case on Windows).
fn env_defined(ctx: &Ctx, name: &str) -> bool {
    env_value(ctx, name).is_some()
        || std::env::vars_os().any(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
}

/// Whether PowerShell starts `name` through cmd.exe: the first match in its folder (or in each
/// PATH folder, in order) with `.ps1` first, then each PATHEXT extension, then the bare name,
/// is a `.bat` or `.cmd`. A name with a folder that resolves to nothing counts as one: the
/// launchers are batch files and the check cannot follow every `cd`. A bare name found nowhere
/// is no program.
fn reaches_cmd(ctx: &Ctx, name: &str) -> bool {
    let pathext = env_value(ctx, "PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut exts: Vec<String> = vec![".ps1".to_string()];
    exts.extend(pathext.split(';').filter(|e| !e.is_empty()).map(str::to_string));
    exts.push(String::new());
    let (folders, base): (Vec<PathBuf>, String) = if has_folder(name) {
        let p = Path::new(name);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            match &ctx.input.cwd {
                Some(cwd) => cwd.join(p),
                None => return true,
            }
        };
        let base = full
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_default();
        (full.parent().map(Path::to_path_buf).into_iter().collect(), base)
    } else {
        let path = env_value(ctx, "PATH").unwrap_or_default();
        (
            std::env::split_paths(&path).filter(|d| !d.as_os_str().is_empty()).collect(),
            name.to_string(),
        )
    };
    for folder in &folders {
        for ext in &exts {
            let candidate = folder.join(format!("{base}{ext}"));
            if ctx.fs.lstat(&candidate).is_ok_and(|m| m.is_file) {
                return has_bat_extension(&candidate.to_string_lossy());
            }
        }
    }
    has_folder(name)
}

/// The Fix line: the program by its path when `cfg.tool_paths` names one for the launcher;
/// otherwise, for an operator, the same call after `--%` with the argument in double quotes,
/// which cmd.exe leaves alone.
fn bat_fix(ctx: &Ctx, c: &SimpleCommand, bad: usize, percent: bool) -> String {
    let src = ctx.input.command;
    let base = c
        .typed
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let base = base
        .strip_suffix(".bat")
        .or_else(|| base.strip_suffix(".cmd"))
        .unwrap_or(&base)
        .to_string();
    let rest = text(
        src,
        Span {
            start: c.name.span.end,
            end: c.span.end,
        },
    )
    .trim();
    if let Some(path) = ctx.cfg.tool_paths.get(&base) {
        return format!("call the program directly: & \"{}\" {rest}", path.display());
    }
    if percent {
        return format!(
            "call the program `{}` starts by its own path (its .exe), not through the .bat, or keep %NAME% out of the argument",
            c.typed
        );
    }
    let mut words = Vec::new();
    for (k, a) in c.args.iter().enumerate() {
        let Some(v) = literal(a) else {
            return format!(
                "call the program `{}` starts by its own path (its .exe), not through the .bat",
                c.typed
            );
        };
        if k == bad {
            if v.contains('"') {
                return format!(
                    "call the program `{}` starts by its own path (its .exe), not through the .bat",
                    c.typed
                );
            }
            words.push(format!("\"{v}\""));
        } else {
            words.push(v);
        }
    }
    format!("{} --% {}", c.typed, words.join(" "))
}

// ---------------------------------------------------------------------------------------------
// gate-truncated-pipeline
// ---------------------------------------------------------------------------------------------

pub const GATE_TRUNCATED_PIPELINE: &str = "gate-truncated-pipeline";

/// A gate, test run or tee'd log piped into a truncator (`Select-Object -First`, `head`): the
/// truncator stops the producer once it has its lines, so the exit code reads as success and the
/// log is cut off. A producer is a gate when its name matches `cfg.gate_commands` or a script
/// host runs a script that does; behind a `Tee-Object` any producer counts.
pub struct GateTruncatedPipeline;

impl Rule for GateTruncatedPipeline {
    fn id(&self) -> &'static str {
        GATE_TRUNCATED_PIPELINE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            if site.index == 0 || !truncates(ctx, site.cmd, ed, &w) {
                continue;
            }
            let Some(blamed) = gate_upstream(ctx, site) else {
                continue;
            };
            let first = &site.pipe.elems[0];
            let producer_end = elem_span(&site.pipe.elems[site.index - 1]).end;
            let producer = text(
                src,
                Span {
                    start: elem_span(first).start,
                    end: producer_end,
                },
            )
            .trim();
            out.push(finding(
                GATE_TRUNCATED_PIPELINE,
                Level::Break,
                site.cmd.span,
                format!(
                    "`{blamed}` is piped into `{}`, which stops the producer as soon as it has its lines: the exit code then reads as success and the log is cut off; `Select-Object -Last N` reads the whole stream and is fine",
                    site.cmd.typed
                ),
                format!("$out = {producer} 2>&1; $out | Select-Object -Last 20"),
            ));
            return;
        }
    }
}

fn elem_span(e: &Elem) -> Span {
    match e {
        Elem::Cmd(c) => c.span,
        Elem::Method(m) => m.span,
        Elem::Expr(w) => w.span,
    }
}

/// `Select-Object -First` (a row tagged `truncator` whose `lint.truncate_params` names the
/// bound parameter), or a truncator with no such list (`head`).
fn truncates(ctx: &Ctx, c: &SimpleCommand, ed: char, w: &Walk) -> bool {
    let Some(p) = command_tagged(ctx, c, "truncator") else {
        return false;
    };
    let params = lint(p, "truncate_params");
    if params.is_empty() {
        return true;
    }
    let Some(name) = table_name(c, ed, w) else {
        return false;
    };
    let Some(cmd) = cmdlet(&name, ed) else {
        return false;
    };
    let Some(args) = bind_args(ctx.input.command, c, &cmd) else {
        return false;
    };
    params.iter().any(|p| named(&args, p).is_some())
}

/// The producer to blame, nearest first: behind a tee, the command feeding it; a gate itself.
fn gate_upstream(ctx: &Ctx, site: &Site) -> Option<String> {
    let mut chain: Vec<&SimpleCommand> = Vec::new();
    for e in site.pipe.elems[..site.index].iter().rev() {
        if let Elem::Cmd(c) = e {
            chain.push(c);
        }
    }
    for (k, c) in chain.iter().enumerate() {
        if command_tagged(ctx, c, "tee-cmdlet").is_some() {
            let feeder = chain[k + 1..]
                .iter()
                .find(|u| command_tagged(ctx, u, "tee-cmdlet").is_none());
            return Some(feeder.map_or(c.typed.clone(), |u| u.typed.clone()));
        }
        if is_gate(ctx, c) {
            return Some(c.typed.clone());
        }
    }
    None
}

fn gate_named(ctx: &Ctx, name: &str) -> bool {
    !ctx.cfg.gate_commands.is_empty() && launcher_named(name, &ctx.cfg.gate_commands)
}

/// A gate by its name, or a script host (`lint.script_flags`, `lint.command_flags`, else the
/// first positional word) running one.
fn is_gate(ctx: &Ctx, c: &SimpleCommand) -> bool {
    if c.opaque {
        return false;
    }
    if gate_named(ctx, &c.typed) {
        return true;
    }
    let Some(host) = program(ctx, &c.typed).filter(|p| !lint(p, "script_flags").is_empty()) else {
        return false;
    };
    let script_flags = lint(host, "script_flags");
    let command_flags = lint(host, "command_flags");
    let values: Vec<Option<String>> = c.args.iter().map(literal).collect();
    let mut k = 0;
    while k < values.len() {
        let Some(v) = values[k].as_deref() else {
            return false;
        };
        let low = v.to_lowercase();
        if script_flags.iter().any(|f| f.eq_ignore_ascii_case(&low)) {
            return values
                .get(k + 1)
                .and_then(|x| x.as_deref())
                .is_some_and(|s| gate_named(ctx, s));
        }
        if command_flags.iter().any(|f| f.eq_ignore_ascii_case(&low)) {
            let body: Vec<String> = values[k + 1..].iter().flatten().cloned().collect();
            return body
                .join(" ")
                .split(|ch: char| ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '\'' | '"'))
                .any(|t| !t.is_empty() && gate_named(ctx, t));
        }
        if v.starts_with(['-', '+']) {
            let takes = host.value_options.iter().any(|o| o.eq_ignore_ascii_case(v));
            k += if takes { 2 } else { 1 };
            continue;
        }
        return gate_named(ctx, v);
    }
    false
}

// ---------------------------------------------------------------------------------------------
// ps-bad-parameter (baseline-guard port; Specter UseCompatibleCommands, UseCmdletCorrectly)
// ---------------------------------------------------------------------------------------------

pub const PS_BAD_PARAMETER: &str = "ps-bad-parameter";

/// A parameter the cmdlet does not have in this edition, a prefix that matches several, or a
/// parameter that needs a value and gets none: PowerShell refuses the call. Bound against the
/// generated table of the target edition. A row's `lint.flag_hints` (`"-la=-Force"`; a key ending
/// in `#` fires only before a number, `"-A#=-Context 0,"`) gives the replacement for a bash
/// spelling, including one that binds (`Select-String -A 2` binds `-AllMatches`).
pub struct BadParameter;

impl Rule for BadParameter {
    fn id(&self) -> &'static str {
        PS_BAD_PARAMETER
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(name) = table_name(c, ed, &w) else {
                continue;
            };
            let Some(cmd) = cmdlet(&name, ed) else {
                continue;
            };
            if let Some(f) = hint_finding(ctx, c, &cmd) {
                out.push(f);
                continue;
            }
            if cmd.takes_remaining() {
                continue;
            }
            let Some(args) = bind_args(src, c, &cmd) else {
                continue;
            };
            let before = out.len();
            for a in &args {
                let Arg::Named {
                    word,
                    token_name,
                    problem: Some(problem),
                    ..
                } = a
                else {
                    continue;
                };
                let typed = text(src, word.span);
                let (message, fix) = match problem {
                    Problem::Missing => {
                        let elsewhere = cmdlet(&name, other_edition(ed))
                            .is_some_and(|o| matches!(bind(&o, token_name), Bound::Param(_)));
                        let tail = if elsewhere {
                            format!(
                                " (it exists in {} only)",
                                if ed == '7' {
                                    "Windows PowerShell 5.1"
                                } else {
                                    "PowerShell 7"
                                }
                            )
                        } else {
                            String::new()
                        };
                        (
                            format!(
                                "`{}` has no parameter `{typed}`{tail}, so PowerShell refuses the call (\"A parameter cannot be found that matches parameter name\")",
                                cmd.name
                            ),
                            format!("remove `{typed}`: {}", replaced(src, c.span, word.span, "")),
                        )
                    }
                    Problem::Ambiguous(names) => {
                        let list = names
                            .iter()
                            .map(|n| format!("-{n}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        (
                            format!(
                                "`{typed}` matches several parameters of `{}` ({list}), so PowerShell refuses the call",
                                cmd.name
                            ),
                            format!("write the full parameter name, one of {list}"),
                        )
                    }
                    Problem::NoValue(p) => (
                        format!(
                            "`{typed}` binds `-{p}` of `{}`, which needs a value, and none follows, so PowerShell refuses the call (\"Missing an argument for parameter\")",
                            cmd.name
                        ),
                        format!(
                            "give -{p} a value or remove it: {}",
                            replaced(src, c.span, word.span, "")
                        ),
                    ),
                };
                out.push(finding(PS_BAD_PARAMETER, Level::Break, word.span, message, fix));
                break;
            }
            if out.len() == before {
                out.extend(extra_positional(src, c, &cmd, &args));
            }
        }
    }
}

/// A `lint.flag_hints` spelling on the cmdlet's row, as typed (case counts, as in bash).
fn hint_finding(ctx: &Ctx, c: &SimpleCommand, cmd: &Cmdlet) -> Option<Finding> {
    let src = ctx.input.command;
    let row = program(ctx, cmd.name)?;
    let hints = lint(row, "flag_hints");
    for (k, a) in c.args.iter().enumerate() {
        if a.quote != Quote::None {
            continue;
        }
        let typed = text(src, a.span);
        for h in &hints {
            let Some((key, replacement)) = h.split_once('=') else {
                continue;
            };
            let (spelling, before_number) = match key.strip_suffix('#') {
                Some(s) => (s, true),
                None => (key, false),
            };
            if typed != spelling {
                continue;
            }
            if before_number {
                let Some(next) = c.args.get(k + 1) else { continue };
                let Some(n) = literal(next).filter(|v| !v.is_empty() && v.chars().all(|d| d.is_ascii_digit()))
                else {
                    continue;
                };
                let cut = Span {
                    start: a.span.start,
                    end: next.span.end,
                };
                return Some(finding(
                    PS_BAD_PARAMETER,
                    Level::Break,
                    cut,
                    format!(
                        "`{typed} {n}` is a bash flag: `{}` reads `{typed}` as another parameter and refuses `{n}`",
                        cmd.name
                    ),
                    format!(
                        "use {replacement}{n}: {}",
                        replaced(src, c.span, cut, &format!("{replacement}{n}"))
                    ),
                ));
            }
            let (message, fix) = if replacement.is_empty() {
                (
                    format!("`{typed}` is cmd.exe or bash syntax that `{}` refuses", cmd.name),
                    format!("remove `{typed}`: {}", replaced(src, c.span, a.span, "")),
                )
            } else {
                (
                    format!(
                        "`{typed}` is a bash flag that `{}` refuses; PowerShell's spelling is {replacement}",
                        cmd.name
                    ),
                    format!(
                        "use {replacement}: {}",
                        replaced(src, c.span, a.span, replacement)
                    ),
                )
            };
            return Some(finding(PS_BAD_PARAMETER, Level::Break, a.span, message, fix));
        }
    }
    None
}

/// More positional arguments than any parameter set has positions for: PowerShell refuses the
/// call ("A positional parameter cannot be found that accepts argument"). Not judged with a
/// splat, which may bind any parameter.
fn extra_positional(src: &str, c: &SimpleCommand, cmd: &Cmdlet, args: &[Arg]) -> Option<Finding> {
    if c.args.iter().any(|a| text(src, a.span).starts_with('@')) {
        return None;
    }
    let given = positional(args);
    let max = max_positional(cmd);
    let extra = given.get(max)?;
    Some(finding(
        PS_BAD_PARAMETER,
        Level::Break,
        extra.span,
        format!(
            "`{}` takes at most {max} positional argument(s) and `{}` is one more, so PowerShell refuses the call (\"A positional parameter cannot be found that accepts argument\")",
            cmd.name,
            text(src, extra.span)
        ),
        format!(
            "name the parameter for `{}` or remove it: {}",
            text(src, extra.span),
            replaced(src, c.span, extra.span, "")
        ),
    ))
}

/// The most positions one parameter set offers (its own parameters and those in every set).
fn max_positional(cmd: &Cmdlet) -> usize {
    let mut sets: Vec<&str> = cmd
        .params
        .iter()
        .flat_map(|p| p.sets.iter().map(|m| m.set))
        .filter(|s| *s != ALL_SETS)
        .collect();
    sets.sort_unstable();
    sets.dedup();
    if sets.is_empty() {
        sets.push(ALL_SETS);
    }
    sets.iter()
        .map(|set| {
            cmd.params
                .iter()
                .filter(|p| {
                    p.sets
                        .iter()
                        .any(|m| m.position >= 0 && (m.set == *set || m.set == ALL_SETS))
                })
                .count()
        })
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// ps-bare-bash
// ---------------------------------------------------------------------------------------------

pub const PS_BARE_BASH: &str = "ps-bare-bash";

/// `bash` typed in PowerShell on Windows runs System32's `bash.exe`, which is WSL, not Git Bash.
/// The row tagged `wsl-bash` holds the name and the replacement call (`fix`).
pub struct BareBash;

impl Rule for BareBash {
    fn id(&self) -> &'static str {
        PS_BARE_BASH
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if c.opaque || has_folder(&c.typed) {
                continue;
            }
            let Some(p) = command_tagged(ctx, c, "wsl-bash") else {
                continue;
            };
            let call = p.fix.as_deref().unwrap_or("the Bash tool");
            let rest = text(
                src,
                Span {
                    start: c.name.span.end,
                    end: c.span.end,
                },
            )
            .trim();
            out.push(finding(
                PS_BARE_BASH,
                Level::Break,
                c.name.span,
                format!(
                    "`{}` typed in PowerShell runs the System32 bash.exe, which is WSL, not Git Bash: Windows paths and CRLF scripts break there; use the Bash tool, or call wsl on purpose",
                    c.typed
                ),
                format!("{call} {rest}").trim().to_string(),
            ));
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ps-native-nonewline
// ---------------------------------------------------------------------------------------------

pub const PS_NATIVE_NONEWLINE: &str = "ps-native-nonewline";

/// A native program piped into a writer (`lint.tags = ["file-writer"]`) with `-NoNewline`: the
/// output arrives as lines and `-NoNewline` joins them into one line.
pub struct NativeNonewline;

impl Rule for NativeNonewline {
    fn id(&self) -> &'static str {
        PS_NATIVE_NONEWLINE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if command_tagged(ctx, c, "file-writer").is_none() {
                continue;
            }
            let Some(cmd) = table_name(c, ed, &w).and_then(|n| cmdlet(&n, ed)) else {
                continue;
            };
            let Some(args) = bind_args(src, c, &cmd) else {
                continue;
            };
            if !switch_on(&args, "nonewline") {
                continue;
            }
            let Some(native) = upstream(site).and_then(|e| native_producer(e, ed, &w)) else {
                continue;
            };
            let Some(Arg::Named { word, .. }) = named(&args, "nonewline") else {
                continue;
            };
            out.push(finding(
                PS_NATIVE_NONEWLINE,
                Level::Break,
                c.span,
                format!(
                    "`{native}` output reaches `{}` as separate lines, and -NoNewline joins them into one line, so every line break is lost",
                    c.typed
                ),
                format!(
                    "drop -NoNewline: {}",
                    replaced(src, c.span, word.span, "")
                ),
            ));
            return;
        }
    }
}

/// The native program an upstream element runs: a native command, or a parenthesised one.
fn native_producer(e: &Elem, ed: char, w: &Walk) -> Option<String> {
    match e {
        Elem::Cmd(c) if is_native(c, ed, w) => Some(c.typed.clone()),
        Elem::Expr(word) => match word.parts.as_slice() {
            [WordPart::Subst(s)] => match s.stmts.as_slice() {
                [Stmt::Pipeline(p)] => p.elems.last().and_then(|last| native_producer(last, ed, w)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// ps-dotnet-relative-path
// ---------------------------------------------------------------------------------------------

pub const PS_DOTNET_RELATIVE_PATH: &str = "ps-dotnet-relative-path";

/// The path argument positions of a .NET call whose relative paths resolve against the process
/// directory (the table's `dotnet` rows: File's whole-file readers and writers, every Directory
/// method). `type_name` as written, with or without `System.`.
fn dotnet_path_args(type_name: &str, method: &str, ed: char) -> Option<Vec<usize>> {
    let ty = type_name.to_lowercase();
    let ty = ty.strip_prefix("system.").unwrap_or(&ty);
    let method = method.to_lowercase();
    index()
        .dotnet
        .iter()
        .find(|r| r.len() >= 5 && in_edition(r, ed) && r[2] == ty && r[3] == method)
        .map(|r| r[4].split(',').filter_map(|i| i.parse().ok()).collect())
}

/// `[IO.File]::ReadAllText('rel\x')`, `[IO.Directory]::CreateDirectory('rel')`: a relative
/// literal path is resolved against `[Environment]::CurrentDirectory`, which `cd` and
/// Set-Location never move, so the call reads or writes in another folder.
pub struct DotnetRelativePath;

impl Rule for DotnetRelativePath {
    fn id(&self) -> &'static str {
        PS_DOTNET_RELATIVE_PATH
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        for m in walk(ctx.script).methods {
            let Some(indexes) = dotnet_path_args(&m.type_name, &m.method, ed) else {
                continue;
            };
            for k in indexes {
                let Some(arg) = m.args.get(k) else { continue };
                let raw = text(src, arg.span).trim();
                let Some(head) = literal_path_head(raw) else {
                    continue;
                };
                if head.is_empty() || is_rooted(&head) {
                    continue;
                }
                let call = format!("[{}]::{}", m.type_name, m.method);
                out.push(finding(
                    PS_DOTNET_RELATIVE_PATH,
                    Level::Break,
                    arg.span,
                    format!(
                        "`{call}` resolves the relative path `{head}` against the process directory, not the location `cd` / Set-Location set, so it reads or writes a file in another folder"
                    ),
                    format!(
                        "pass an absolute path: {}",
                        replaced(src, m.span, arg.span, &format!("(Join-Path $PWD {raw})"))
                    ),
                ));
                return;
            }
        }
    }
}

/// The literal text a path argument starts with: all of a `'...'` string, a `"..."` string up to
/// its first `$` or backtick; `None` for a variable, a call or an expression.
fn literal_path_head(raw: &str) -> Option<String> {
    let inner = |q: char| raw.strip_prefix(q).and_then(|r| r.strip_suffix(q));
    if raw.len() >= 2 {
        if let Some(s) = inner('\'') {
            return Some(s.replace("''", "'"));
        }
        if let Some(s) = inner('"') {
            return Some(s.split(['$', '`']).next().unwrap_or("").to_string());
        }
    }
    None
}

fn is_rooted(path: &str) -> bool {
    let b = path.as_bytes();
    matches!(b.first(), Some(b'\\' | b'/'))
        || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
}

// ---------------------------------------------------------------------------------------------
// stale-write-var (Specter AvoidUsingUninitializedVariable, for the bound names)
// ---------------------------------------------------------------------------------------------

pub const STALE_WRITE_VAR: &str = "stale-write-var";

/// A variable written into a file that this command never assigns. Shell state does not survive
/// between tool calls, so it reads as `$null` and the write empties the file. Writers are the rows
/// tagged `file-writer` (their content: `-Value`/`-InputObject`, the positional word at
/// `lint.content_position`, or a bare expression piped in; `lint.append_params` skips an append)
/// and `[IO.File]::WriteAll*`. Bound names: assignments, `-OutVariable`/`-PipelineVariable`,
/// `foreach` variables and parameters.
pub struct StaleWriteVar;

/// `[IO.File]::WriteAll*`: (type, method prefix).
const WRITE_ALL: &[(&str, &str)] = &[("io.file", "writeall"), ("system.io.file", "writeall")];

/// Common parameters that bind a variable by name.
const VARIABLE_PARAMS: &[&str] = &["outvariable", "pipelinevariable"];

impl Rule for StaleWriteVar {
    fn id(&self) -> &'static str {
        STALE_WRITE_VAR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        let mut contents: Vec<(Span, String)> = Vec::new();
        for m in &w.methods {
            let ty = m.type_name.to_lowercase();
            let method = m.method.to_lowercase();
            if WRITE_ALL
                .iter()
                .any(|(t, p)| *t == ty && method.starts_with(p))
            {
                if let Some(a) = m.args.get(1) {
                    contents.push((a.span, text(src, a.span).to_string()));
                }
            }
        }
        let mut bound: Vec<String> = w.assigned.clone();
        for site in &w.sites {
            let c = site.cmd;
            let Some(cmd) = table_name(c, ed, &w).and_then(|n| cmdlet(&n, ed)) else {
                continue;
            };
            let Some(args) = bind_args(src, c, &cmd) else {
                continue;
            };
            for p in VARIABLE_PARAMS {
                if let Some(v) = named_value(src, &args, p) {
                    bound.push(v.trim_start_matches('+').to_lowercase());
                }
            }
            let Some(row) = command_tagged(ctx, c, "file-writer") else {
                continue;
            };
            if lint(row, "append_params").iter().any(|p| switch_on(&args, p)) {
                continue;
            }
            for p in ["value", "inputobject"] {
                if let Some(Arg::Named { word, value, attached, .. }) = named(&args, p) {
                    match (value, attached) {
                        (Some(v), _) => contents.push((v.span, text(src, v.span).to_string())),
                        (None, Some(a)) => contents.push((word.span, a.clone())),
                        _ => {}
                    }
                }
            }
            let path_named = ["path", "literalpath", "filepath"]
                .iter()
                .any(|p| named(&args, p).is_some());
            let content_named = ["value", "inputobject"]
                .iter()
                .any(|p| named(&args, p).is_some());
            if !content_named {
                if let Some(pos) = lint(row, "content_position")
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    let pos = if path_named { pos.saturating_sub(1) } else { pos };
                    if let Some(word) = positional(&args).get(pos) {
                        contents.push((word.span, text(src, word.span).to_string()));
                    }
                }
            }
            if let Some(Elem::Expr(x)) = upstream(site) {
                contents.push((x.span, text(src, x.span).to_string()));
            }
        }
        bound.extend(tree_bound_names(src));
        for (span, expr) in contents {
            if let Some(name) = stale_var(&expr, &bound, ed) {
                out.push(finding(
                    STALE_WRITE_VAR,
                    Level::Break,
                    span,
                    format!(
                        "`${name}` is written into the file but never assigned in this command, and shell state does not survive between tool calls: it reads as $null and overwrites the file with nothing"
                    ),
                    format!(
                        "assign ${name} in this same command before the write (${name} = <value>; ...), or append with Add-Content"
                    ),
                ));
                return;
            }
        }
    }
}

/// The value given to a bound parameter: its separate word or its attached text.
fn named_value(src: &str, args: &[Arg], param: &str) -> Option<String> {
    match named(args, param)? {
        Arg::Named {
            value: Some(v), ..
        } => Some(literal(v).unwrap_or_else(|| text(src, v.span).to_string())),
        Arg::Named {
            attached: Some(a), ..
        } => Some(a.trim_matches(['\'', '"']).to_string()),
        _ => None,
    }
}

/// Names bound without an assignment: `foreach ($x in …)` and parameters (`param($a)`,
/// `function f($a)`).
fn tree_bound_names(src: &str) -> Vec<String> {
    with_tree(src, |root| {
        let mut names = Vec::new();
        for n in descendants(root, &[]) {
            let holder = match n.kind() {
                "foreach_statement" | "script_parameter" => true,
                _ => false,
            };
            if !holder {
                continue;
            }
            let mut cursor = n.walk();
            for k in n.named_children(&mut cursor) {
                if k.kind() == "variable" {
                    names.push(plain_var(node_text(src, k).trim_start_matches('$')));
                    break;
                }
            }
        }
        names
    })
    .unwrap_or_default()
}

/// The first variable `expr` expands that is neither bound nor a variable the session sets.
fn stale_var(expr: &str, bound: &[String], ed: char) -> Option<String> {
    let code = expandable(expr);
    let b = code.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' || (i > 0 && b[i - 1] == b'`') {
            i += 1;
            continue;
        }
        let rest = &code[i + 1..];
        let take = |s: &str| -> usize {
            s.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .count()
        };
        let first = rest.chars().next();
        if !first.is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
            i += 1;
            continue;
        }
        let mut name_len = take(rest);
        let mut name = &rest[..name_len];
        if rest[name_len..].starts_with(':') {
            if rest[..name_len + 1].eq_ignore_ascii_case(ENV_SCOPE) {
                i += 1 + name_len;
                continue;
            }
            let after = &rest[name_len + 1..];
            let n2 = take(after);
            if n2 > 0 {
                name = &after[..n2];
                name_len += 1 + n2;
            }
        }
        let low = name.to_lowercase();
        if variable_kind(&low, ed).is_none() && !bound.contains(&low) {
            return Some(name.to_string());
        }
        i += 1 + name_len;
    }
    None
}

/// `expr` without the text that expands nothing: single-quoted strings and verbatim
/// here-strings.
fn expandable(expr: &str) -> String {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut dq = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            out.extend(chars[i..(i + 2).min(chars.len())].iter());
            i += 2;
            continue;
        }
        if c == '@' && !dq && chars.get(i + 1) == Some(&'\'') {
            let rest: String = chars[i..].iter().collect();
            match rest.find("\n'@") {
                Some(j) => i += rest[..j + 3].chars().count(),
                None => i = chars.len(),
            }
            continue;
        }
        if c == '"' {
            dq = !dq;
        } else if c == '\'' && !dq {
            let mut j = i + 1;
            while j < chars.len() {
                if chars[j] == '\'' {
                    if chars.get(j + 1) == Some(&'\'') {
                        j += 2;
                        continue;
                    }
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------------------------
// ps-git-commit-stdin
// ---------------------------------------------------------------------------------------------

pub const PS_GIT_COMMIT_STDIN: &str = "ps-git-commit-stdin";

/// `git commit -F -` with nothing piped in: PowerShell passes the here-string after it as a
/// pathspec, and no commit is made. The row tagged `git-cli` lists in `lint`: `global_value_options` (git's own
/// options that take a value), `stdin_commit` (the subcommand), `file_long` (`--file`) and
/// `file_short` (`F`).
pub struct GitCommitStdin;

impl Rule for GitCommitStdin {
    fn id(&self) -> &'static str {
        PS_GIT_COMMIT_STDIN
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if site.index > 0 {
                continue;
            }
            let Some(git) = command_tagged(ctx, c, "git-cli") else {
                continue;
            };
            let values: Vec<String> = c
                .args
                .iter()
                .map(|a| literal(a).unwrap_or_default())
                .collect();
            let globals = lint(git, "global_value_options");
            let mut k = 0;
            while k < values.len() && values[k].starts_with('-') {
                k += if globals.contains(&values[k].as_str()) { 2 } else { 1 };
            }
            let commit = lint(git, "stdin_commit");
            if !values.get(k).is_some_and(|s| commit.contains(&s.as_str())) {
                continue;
            }
            if reads_stdin(&values[k + 1..], &lint(git, "file_long"), &lint(git, "file_short")) {
                out.push(finding(
                    PS_GIT_COMMIT_STDIN,
                    Level::Break,
                    c.span,
                    "`git commit -F -` reads the message from stdin, but nothing is piped into it: PowerShell passes the here-string after it as a pathspec (\"error: pathspec ...\"), so no commit is made".to_string(),
                    "replace `-F -` with `-m` and keep the here-string after it (closing '@ at column 0), or write the message to a file and run git commit -F <file>".to_string(),
                ));
                return;
            }
        }
    }
}

fn reads_stdin(args: &[String], long: &[&str], short: &[&str]) -> bool {
    for (i, v) in args.iter().enumerate() {
        if v == "--" {
            return false;
        }
        let next = args.get(i + 1).map(String::as_str);
        if long.iter().any(|l| *v == format!("{l}=-") || (v.as_str() == *l && next == Some("-"))) {
            return true;
        }
        let Some(cluster) = v.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        for s in short {
            let letters_then = |tail: &str| {
                cluster
                    .strip_suffix(tail)
                    .is_some_and(|head| head.chars().all(|c| c.is_ascii_alphabetic()))
            };
            if (letters_then(*s) && next == Some("-")) || letters_then(&format!("{s}-")) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------------------------
// cli-inline-prose (Specter AvoidSmartQuotes, for the strings PowerShell tears)
// ---------------------------------------------------------------------------------------------

pub const CLI_INLINE_PROSE: &str = "cli-inline-prose";

/// The typographic quotes that end a string opened by each straight quote.
const TORN_BY: [(char, &[char]); 2] = [
    ('"', &['\u{201e}', '\u{201c}', '\u{201d}']),
    ('\'', &['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}']),
];

/// `gh pr create --body "it „works”"`: PowerShell ends a string at a typographic quote of its own
/// family, so the text reaches gh torn into pieces. The row tagged `prose-cli` lists the
/// subcommands (`lint.prose_subcommands`) and the flags (`lint.prose_flags`, `"--body=--body-file"`
/// when a file form exists).
pub struct InlineProse;

impl Rule for InlineProse {
    fn id(&self) -> &'static str {
        CLI_INLINE_PROSE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "prose-cli") else {
                continue;
            };
            let subs = lint(row, "prose_subcommands");
            let first_positional = c
                .args
                .iter()
                .filter_map(literal)
                .find(|v| !v.starts_with('-'));
            if !first_positional.is_some_and(|v| subs.contains(&v.as_str())) {
                continue;
            }
            let flags: Vec<(&str, Option<&str>)> = lint(row, "prose_flags")
                .into_iter()
                .map(|f| match f.split_once('=') {
                    Some((a, b)) => (a, Some(b)),
                    None => (f, None),
                })
                .collect();
            for (i, a) in c.args.iter().enumerate() {
                let raw = text(src, a.span);
                let mut hit: Option<(&str, Option<&str>, usize)> = None;
                for (flag, file) in &flags {
                    if raw == *flag {
                        if let Some(next) = c.args.get(i + 1) {
                            hit = Some((*flag, *file, next.span.start));
                        }
                    } else if let Some(rest) = raw.strip_prefix(flag) {
                        let attached = rest.starts_with('=')
                            || (!flag.starts_with("--") && !rest.is_empty());
                        if attached {
                            let skip = usize::from(rest.starts_with('='));
                            hit = Some((*flag, *file, a.span.start + flag.len() + skip));
                        }
                    }
                    if hit.is_some() {
                        break;
                    }
                }
                let Some((flag, file, at)) = hit else { continue };
                let tail = text(
                    src,
                    Span {
                        start: at,
                        end: c.span.end,
                    },
                );
                let Some((open, typographic)) = torn_quote(tail) else {
                    continue;
                };
                let other = if open == '"' { "'...'" } else { "\"...\" (mind `$` in it)" };
                let file_fix = file
                    .map(|f| format!(", or write the text with the Write tool and pass {f} <file>"))
                    .unwrap_or_default();
                out.push(finding(
                    CLI_INLINE_PROSE,
                    Level::Break,
                    a.span,
                    format!(
                        "PowerShell ends a string opened by `{open}` at a typographic `{typographic}` too, so the text after {flag} reaches {} torn into pieces or stripped of its quotes",
                        c.typed
                    ),
                    format!("quote the {flag} text with {other} instead{file_fix}"),
                ));
                return;
            }
        }
    }
}

/// (opening quote, typographic quote) for the first string at the start of `raw` that holds a
/// quote of its own family. A here-string ends only at its closing line, so it is never torn.
fn torn_quote(raw: &str) -> Option<(char, char)> {
    if raw.starts_with("@'") || raw.starts_with("@\"") {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let q = *chars.first()?;
    let (_, family) = TORN_BY.iter().find(|(open, _)| *open == q)?;
    let mut j = 1;
    while j < chars.len() && chars[j] != q {
        if family.contains(&chars[j]) {
            return Some((q, chars[j]));
        }
        j += if chars[j] == '`' && q == '"' { 2 } else { 1 };
    }
    None
}

// ---------------------------------------------------------------------------------------------
// The warn rules from the trap catalogue
// ---------------------------------------------------------------------------------------------

pub const PS_UNIX_COMMAND: &str = "ps-unix-command";

/// A Unix tool PowerShell does not have here (`tail`, `grep`, `sed`, `export`): the row tagged
/// `unix-only` names the PowerShell way in its `fix`. Warn: with coreutils on PATH some of them
/// run.
pub struct UnixCommand;

impl Rule for UnixCommand {
    fn id(&self) -> &'static str {
        PS_UNIX_COMMAND
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if c.opaque || c.canonical.is_some() || has_folder(&c.typed) {
                continue;
            }
            if w.functions.contains(&c.typed.to_lowercase()) {
                continue;
            }
            let Some(p) = command_tagged(ctx, c, "unix-only") else {
                continue;
            };
            let instead = p.fix.as_deref().unwrap_or("the PowerShell cmdlet");
            out.push(finding(
                PS_UNIX_COMMAND,
                Level::Warn,
                c.name.span,
                format!(
                    "`{}` is a Unix tool that PowerShell does not have unless coreutils is on PATH",
                    c.typed
                ),
                format!("use {instead} in PowerShell, or run the command with the Bash tool"),
            ));
            return;
        }
    }
}

pub const PWSH_FILE_LIST_ARG: &str = "pwsh-file-list-arg";

/// `pwsh -File x.ps1 -Exclude a,b`: through `-File` a comma list reaches the script as one
/// string, not as an array. The host row lists its `lint.script_flags`.
pub struct FileListArg;

impl Rule for FileListArg {
    fn id(&self) -> &'static str {
        PWSH_FILE_LIST_ARG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(host) = program_of(ctx, c).filter(|p| !lint(p, "script_flags").is_empty())
            else {
                continue;
            };
            let flags = lint(host, "script_flags");
            let Some(at) = c.args.iter().position(|a| {
                literal(a).is_some_and(|v| flags.iter().any(|f| f.eq_ignore_ascii_case(&v)))
            }) else {
                continue;
            };
            let Some(list) = c
                .args
                .iter()
                .skip(at + 2)
                .find(|a| a.parts.iter().any(|p| matches!(p, WordPart::ListSep)))
            else {
                continue;
            };
            out.push(finding(
                PWSH_FILE_LIST_ARG,
                Level::Warn,
                list.span,
                format!(
                    "`{}` passes `{}` to the script as one string through -File, not as a list, so a parameter that takes several values gets one",
                    c.typed,
                    text(ctx.input.command, list.span)
                ),
                "pass the list as one quoted value, or use -Command".to_string(),
            ));
            return;
        }
    }
}

pub const PS_KILL_WRAPPER: &str = "ps-kill-wrapper";

/// Stopping a process by name (`Stop-Process -Name node`, `taskkill /IM`, `pkill`): it stops
/// other sessions' runs, and stopping a `npm`/`pnpm` wrapper leaves its `node` child holding the
/// port. Rows tagged `process-stop`: `lint.name_params` (bound cmdlet parameters), `lint.name_flags`
/// (`/IM`), `lint.always = ["yes"]` for a tool that only kills by name.
pub struct KillWrapper;

impl Rule for KillWrapper {
    fn id(&self) -> &'static str {
        PS_KILL_WRAPPER
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "process-stop") else {
                continue;
            };
            let by_name = !lint(row, "always").is_empty()
                || lint(row, "name_flags").iter().any(|f| {
                    c.args
                        .iter()
                        .any(|a| literal(a).is_some_and(|v| v.eq_ignore_ascii_case(f)))
                })
                || table_name(c, ed, &w)
                    .and_then(|n| cmdlet(&n, ed))
                    .and_then(|cmd| bind_args(src, c, &cmd))
                    .is_some_and(|args| {
                        lint(row, "name_params").iter().any(|p| named(&args, p).is_some())
                    });
            if !by_name {
                continue;
            }
            out.push(finding(
                PS_KILL_WRAPPER,
                Level::Warn,
                c.span,
                format!(
                    "`{}` stops processes by name: that also stops other sessions' runs, and stopping an npm/pnpm wrapper leaves its node child holding the port",
                    c.typed
                ),
                "stop the process that owns the port: Get-NetTCPConnection -LocalPort <p> | % OwningProcess | Stop-Process".to_string(),
            ));
            return;
        }
    }
}

pub const PS_AUTO_VARIABLE: &str = "ps-auto-variable";

/// An assignment to an automatic variable (Specter AvoidAssignmentToAutomaticVariable):
/// read-only and constant ones (`$HOME`, `$PID`, `$Host`) fail, the others (`$input`, `$args`,
/// `$matches`, `$PWD`) are overwritten by PowerShell. Names and kinds come from the table's
/// `variable` rows; names ignore case.
pub struct AutoVariable;

impl Rule for AutoVariable {
    fn id(&self) -> &'static str {
        PS_AUTO_VARIABLE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let ed = edition(ctx.input.shell);
        for site in walk(ctx.script).sites {
            for (name, _) in &site.cmd.assigns {
                if name.contains(':') {
                    continue;
                }
                let Some(kind) = variable_kind(name, ed) else {
                    continue;
                };
                let what = match kind {
                    "constant" | "readonly" => "is read-only, so the assignment fails",
                    "automatic" => "is set by PowerShell itself, which overwrites the value",
                    _ => continue,
                };
                out.push(finding(
                    PS_AUTO_VARIABLE,
                    Level::Warn,
                    site.cmd.span,
                    format!("`${name}` is an automatic variable: it {what}"),
                    format!("rename the variable, for example ${name}Value"),
                ));
                return;
            }
        }
    }
}

pub const PS_REMOVE_ITEM_STAR: &str = "ps-remove-item-star";

/// `Remove-Item <dir>\*`: the host's tool guard refuses a delete of a path ending in `\*`, and
/// the folder stays full. Rows tagged `children-delete` (Remove-Item).
pub struct RemoveItemStar;

impl Rule for RemoveItemStar {
    fn id(&self) -> &'static str {
        PS_REMOVE_ITEM_STAR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if command_tagged(ctx, c, "children-delete").is_none() {
                continue;
            }
            for a in &c.args {
                if param_token(src, a).is_some() {
                    continue;
                }
                let raw = text(src, a.span).trim_matches(['\'', '"']);
                let Some(dir) = raw.strip_suffix("\\*").or_else(|| raw.strip_suffix("/*")) else {
                    continue;
                };
                if dir.is_empty() {
                    continue;
                }
                out.push(finding(
                    PS_REMOVE_ITEM_STAR,
                    Level::Warn,
                    a.span,
                    format!(
                        "`{}` on `{raw}`: the tool guard refuses a delete of a path ending in `\\*`, so the folder is not emptied",
                        c.typed
                    ),
                    format!("Get-ChildItem -LiteralPath {dir} -Force | Remove-Item -Recurse -Force"),
                ));
                return;
            }
        }
    }
}

pub const PS_STDIN_SCRIPT: &str = "ps-stdin-script";

/// Script text piped into an interpreter's stdin (`$code | python -`): PowerShell re-encodes it
/// and non-ASCII characters arrive as U+FFFD. Rows tagged `interpreter`; `lint.stdin_args` are
/// the arguments that read the script from stdin (`-`); no argument at all reads it too.
pub struct StdinScript;

impl Rule for StdinScript {
    fn id(&self) -> &'static str {
        PS_STDIN_SCRIPT
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if site.index == 0 {
                continue;
            }
            let Some(row) = command_tagged(ctx, c, "interpreter") else {
                continue;
            };
            let stdin = lint(row, "stdin_args");
            let reads = c.args.is_empty()
                || c
                    .args
                    .iter()
                    .any(|a| literal(a).is_some_and(|v| stdin.contains(&v.as_str())));
            if !reads {
                continue;
            }
            out.push(finding(
                PS_STDIN_SCRIPT,
                Level::Warn,
                c.span,
                format!(
                    "script text piped into `{}` through PowerShell's stdin loses its non-ASCII characters (they arrive as U+FFFD)",
                    c.typed
                ),
                format!(
                    "write the script to a UTF-8 file with the Write tool and run {} <file>",
                    c.typed
                ),
            ));
            return;
        }
    }
}

pub const PS_EMPTY_ARG: &str = "ps-empty-arg";

/// `'""'` as a native argument passes two quote characters, not an empty value
/// (`ssh-keygen -N '""'` sets the passphrase to `""`).
pub struct EmptyArg;

impl Rule for EmptyArg {
    fn id(&self) -> &'static str {
        PS_EMPTY_ARG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if !is_native(c, ed, &w) {
                continue;
            }
            let Some(a) = c
                .args
                .iter()
                .find(|a| a.quote == Quote::Single && literal(a).as_deref() == Some("\"\""))
            else {
                continue;
            };
            out.push(finding(
                PS_EMPTY_ARG,
                Level::Warn,
                a.span,
                format!(
                    "`'\"\"'` reaches `{}` as two quote characters, not as an empty value",
                    c.typed
                ),
                "write an empty native argument as ''".to_string(),
            ));
            return;
        }
    }
}

pub const RG_FOLLOW_L: &str = "rg-follow-L";

/// `rg -L` is `--follow` (follow symlinks), not grep's "files without a match". The rg row's
/// `lint.follow_flags` holds the spelling and its `fix` the right option.
pub struct RgFollow;

impl Rule for RgFollow {
    fn id(&self) -> &'static str {
        RG_FOLLOW_L
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = program_of(ctx, c).filter(|p| !lint(p, "follow_flags").is_empty())
            else {
                continue;
            };
            let flags = lint(row, "follow_flags");
            let Some(a) = c
                .args
                .iter()
                .find(|a| flags.contains(&text(src, a.span)))
            else {
                continue;
            };
            let instead = row.fix.as_deref().unwrap_or("the long option name");
            out.push(finding(
                RG_FOLLOW_L,
                Level::Warn,
                a.span,
                format!(
                    "`{} {}` follows symbolic links; it does not list the files without a match",
                    c.typed,
                    text(src, a.span)
                ),
                format!(
                    "for files without a match use {instead}: {}",
                    replaced(src, c.span, a.span, instead)
                ),
            ));
            return;
        }
    }
}

pub const WSL_ARGV_REJOIN: &str = "wsl-argv-rejoin";

/// `wsl <command> <args>` joins its arguments into one line that the Linux shell parses again,
/// so quotes, `$` and spaces inside an argument change meaning. `--exec` passes them as they are.
/// The row tagged `wsl-launcher`: `lint.exec_flags` (`-e`, `--exec`), `value_options` (`-d`, `-u`).
pub struct WslArgvRejoin;

impl Rule for WslArgvRejoin {
    fn id(&self) -> &'static str {
        WSL_ARGV_REJOIN
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "wsl-launcher") else {
                continue;
            };
            let exec = lint(row, "exec_flags");
            let values: Vec<Option<String>> = c.args.iter().map(literal).collect();
            let mut k = 0;
            let mut runs = None;
            while k < values.len() {
                let Some(v) = values[k].as_deref() else {
                    runs = Some(k);
                    break;
                };
                if exec.iter().any(|e| e.eq_ignore_ascii_case(v)) {
                    runs = None;
                    k = values.len();
                    break;
                }
                if v == "--" {
                    runs = Some(k + 1);
                    break;
                }
                if v.starts_with('-') {
                    let takes = row.value_options.iter().any(|o| o.eq_ignore_ascii_case(v));
                    k += if takes { 2 } else { 1 };
                    continue;
                }
                runs = Some(k);
                break;
            }
            let Some(start) = runs else { continue };
            let reparsed = c.args.iter().skip(start).find(|a| {
                literal(a).is_none_or(|v| {
                    v.chars().any(|ch| {
                        ch.is_whitespace()
                            || matches!(ch, '$' | '`' | '"' | '\'' | '\\' | ';' | '|' | '&' | '<' | '>' | '*' | '?' | '(' | ')')
                    })
                })
            });
            let Some(a) = reparsed else { continue };
            out.push(finding(
                WSL_ARGV_REJOIN,
                Level::Warn,
                a.span,
                format!(
                    "`{}` joins its arguments into one line that the Linux shell parses again, so `{}` may not arrive as written",
                    c.typed,
                    text(ctx.input.command, a.span)
                ),
                "run it as wsl.exe --exec <shell> -c '<command>'".to_string(),
            ));
            return;
        }
    }
}

pub const CLAUDE_CMD_LIVE_CONFIG: &str = "claude-cmd-live-config";

/// A `claude` CLI command run against the live config dir: it writes `.claude.json`, `backups/`
/// and the like there. The row tagged `claude-cli`: `lint.config_env` (the variable that moves the
/// config dir) and `lint.harmless` (arguments that write nothing).
pub struct ClaudeLiveConfig;

impl Rule for ClaudeLiveConfig {
    fn id(&self) -> &'static str {
        CLAUDE_CMD_LIVE_CONFIG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "claude-cli") else {
                continue;
            };
            let env_names = lint(row, "config_env");
            let set_here = env_names.iter().any(|n| {
                let key = format!("{ENV_SCOPE}{}", n.to_lowercase());
                w.assigned.contains(&key)
            });
            let set_before = env_names.iter().any(|n| ctx.input.env.get(n).is_some());
            if set_here || set_before {
                continue;
            }
            let harmless = lint(row, "harmless");
            let writes = c
                .args
                .iter()
                .any(|a| literal(a).is_none_or(|v| !harmless.contains(&v.as_str())));
            if !writes {
                continue;
            }
            let var = env_names.first().copied().unwrap_or("CLAUDE_CONFIG_DIR");
            out.push(finding(
                CLAUDE_CMD_LIVE_CONFIG,
                Level::Warn,
                c.span,
                format!(
                    "`{}` writes into the live config dir (.claude.json, backups/) unless ${var} points elsewhere",
                    c.typed
                ),
                format!(
                    "$env:{var} = Join-Path $env:TEMP 'claude-scratch'; {}",
                    text(ctx.input.command, c.span)
                ),
            ));
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Specter ports
// ---------------------------------------------------------------------------------------------

pub const PS_MISSING_MANDATORY: &str = "ps-missing-mandatory";

/// A cmdlet called with no positional argument, nothing piped in and no parameter set whose
/// mandatory parameters are all given (Specter UseCmdletCorrectly): PowerShell prompts for them,
/// which a non-interactive tool cannot answer.
pub struct MissingMandatory;

impl Rule for MissingMandatory {
    fn id(&self) -> &'static str {
        PS_MISSING_MANDATORY
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let ed = edition(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if site.index > 0 {
                continue;
            }
            let Some(cmd) = table_name(c, ed, &w).and_then(|n| cmdlet(&n, ed)) else {
                continue;
            };
            if c.args
                .iter()
                .any(|a| text(src, a.span).starts_with('@') || stops_parsing(src, a))
            {
                continue;
            }
            let Some(args) = bind_args(src, c, &cmd) else {
                continue;
            };
            if !positional(&args).is_empty()
                || args
                    .iter()
                    .any(|a| matches!(a, Arg::Named { problem: Some(_), .. }))
            {
                continue;
            }
            let given: Vec<&str> = args
                .iter()
                .filter_map(|a| match a {
                    Arg::Named { bound: Some(b), .. } => Some(*b),
                    _ => None,
                })
                .collect();
            let Some(missing) = unsatisfied(&cmd, &given) else {
                continue;
            };
            out.push(finding(
                PS_MISSING_MANDATORY,
                Level::Warn,
                c.span,
                format!(
                    "`{}` needs -{missing} and gets no value for it, so PowerShell prompts for it, which a non-interactive tool cannot answer",
                    cmd.name
                ),
                format!("pass it: {} -{missing} <value>", text(src, c.span).trim()),
            ));
            return;
        }
    }
}

const ALL_SETS: &str = "__AllParameterSets";

/// The first mandatory parameter left unbound in the first set, when no parameter set has all its
/// mandatory parameters given.
fn unsatisfied(cmd: &Cmdlet, given: &[&str]) -> Option<&'static str> {
    let mut sets: Vec<&str> = Vec::new();
    for p in &cmd.params {
        for m in &p.sets {
            if m.set != ALL_SETS && !sets.contains(&m.set) {
                sets.push(m.set);
            }
        }
    }
    if sets.is_empty() {
        sets.push(ALL_SETS);
    }
    let needs = |set: &str| -> Vec<&'static str> {
        cmd.params
            .iter()
            .filter(|p| {
                p.sets
                    .iter()
                    .any(|m| m.mandatory && (m.set == set || m.set == ALL_SETS))
            })
            .map(|p| p.name)
            .collect()
    };
    let mut first_gap = None;
    for set in &sets {
        let gap: Vec<&'static str> = needs(set)
            .into_iter()
            .filter(|n| !given.contains(n))
            .collect();
        if gap.is_empty() {
            return None;
        }
        if first_gap.is_none() {
            first_gap = gap.first().copied();
        }
    }
    first_gap
}

pub const PS_MISLEADING_BACKTICK: &str = "ps-misleading-backtick";

/// String and comment node kinds: a backtick inside one is text.
const TEXT_NODES: &[&str] = &[
    "string_literal",
    "expandable_string_literal",
    "expandable_here_string_literal",
    "verbatim_string_characters",
    "verbatim_here_string_characters",
    "comment",
];

/// A line ending in a backtick and whitespace (Specter MisleadingBacktick): the backtick escapes
/// the space, not the line break, so the next line runs as a separate command.
pub struct MisleadingBacktick;

impl Rule for MisleadingBacktick {
    fn id(&self) -> &'static str {
        PS_MISLEADING_BACKTICK
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !parsed(ctx) {
            return;
        }
        let src = ctx.input.command;
        if !src.contains('`') {
            return;
        }
        let mut at = 0;
        for line in src.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let trimmed = body.trim_end_matches([' ', '\t']);
            let ends_with_space = trimmed.len() < body.len();
            if ends_with_space && trimmed.ends_with('`') && !escaped_backtick(trimmed) {
                let tick = at + trimmed.len() - 1;
                let in_text = with_tree(src, |root| {
                    let mut n = root.descendant_for_byte_range(tick, tick + 1);
                    while let Some(x) = n {
                        if TEXT_NODES.contains(&x.kind()) {
                            return true;
                        }
                        n = x.parent();
                    }
                    false
                })
                .unwrap_or(true);
                if !in_text {
                    let span = Span {
                        start: tick,
                        end: at + body.len(),
                    };
                    out.push(finding(
                        PS_MISLEADING_BACKTICK,
                        Level::Warn,
                        span,
                        "this line ends in a backtick and then whitespace: the backtick escapes the space, not the line break, so the next line runs as a separate command".to_string(),
                        "delete the spaces after the backtick at the end of the line".to_string(),
                    ));
                    return;
                }
            }
            at += line.len();
        }
    }
}

/// The text ends in an even run of backticks before the last one (`` `` `` is an escaped
/// backtick): then the last one is text too.
fn escaped_backtick(trimmed: &str) -> bool {
    let run = trimmed.chars().rev().take_while(|c| *c == '`').count();
    run % 2 == 0
}

pub const PS_NULL_COMPARISON: &str = "ps-null-comparison";

/// `$x -eq $null` with `$null` on the right (Specter PossibleIncorrectComparisonWithNull): when
/// `$x` is an array the operator filters it and the test reads the result, not "is it null".
pub struct NullComparison;

impl Rule for NullComparison {
    fn id(&self) -> &'static str {
        PS_NULL_COMPARISON
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !parsed(ctx) {
            return;
        }
        let src = ctx.input.command;
        if !src.to_lowercase().contains("$null") {
            return;
        }
        let ed = edition(ctx.input.shell);
        let hit = with_tree(src, |root| {
            for n in descendants(root, &[]) {
                if n.kind() != "comparison_expression" {
                    continue;
                }
                let mut cursor = n.walk();
                let kids: Vec<Node> = n.named_children(&mut cursor).collect();
                let [left, op, right] = kids.as_slice() else {
                    continue;
                };
                if op.kind() != "comparison_operator" || !equality(node_text(src, *op)) {
                    continue;
                }
                let r = node_text(src, *right).trim();
                let l = node_text(src, *left).trim();
                if !r.eq_ignore_ascii_case("$null") || l.eq_ignore_ascii_case("$null") {
                    continue;
                }
                // An automatic variable has a known type (Specter: IsSpecialVariable).
                if let Some(v) = l.strip_prefix('$') {
                    if variable_kind(v, ed).is_some_and(|k| k != "session") {
                        continue;
                    }
                }
                return Some((
                    node_span(n),
                    format!("$null {} {l}", node_text(src, *op).trim()),
                ));
            }
            None
        })
        .flatten();
        if let Some((span, swapped)) = hit {
            out.push(finding(
                PS_NULL_COMPARISON,
                Level::Warn,
                span,
                "`$null` on the right of an equality test: when the left side is an array, PowerShell filters it and the test reads the filtered result, not whether it is null".to_string(),
                format!("put $null on the left: {swapped}"),
            ));
        }
    }
}

/// `-eq`, `-ne` and their `c`/`i` forms.
fn equality(op: &str) -> bool {
    let o = op.trim().trim_start_matches(is_dash).to_lowercase();
    let o = if o.len() == 3 {
        o.strip_prefix(['c', 'i']).unwrap_or(&o).to_string()
    } else {
        o
    };
    o == "eq" || o == "ne"
}

pub const PS_ASSIGN_IN_CONDITION: &str = "ps-assign-in-condition";

/// `if ($a = $b)` (Specter PossibleIncorrectUsageOfAssignmentOperator): an assignment where a
/// comparison was meant. Specter's exceptions stand: a value that runs a command or a method, and
/// a condition wrapped in a second pair of parentheses, are taken as meant.
pub struct AssignInCondition;

impl Rule for AssignInCondition {
    fn id(&self) -> &'static str {
        PS_ASSIGN_IN_CONDITION
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !parsed(ctx) {
            return;
        }
        let src = ctx.input.command;
        if !src.contains('=') {
            return;
        }
        let hit = with_tree(src, |root| {
            for cond in conditions(root) {
                for n in descendants(cond, &["script_block"]) {
                    if n.kind() != "assignment_expression" {
                        continue;
                    }
                    let Some(value) = n.child_by_field_name("value") else {
                        continue;
                    };
                    let rhs = node_text(src, value).trim();
                    let left = n
                        .named_child(0)
                        .map(|l| node_text(src, l).trim().to_string())
                        .unwrap_or_default();
                    let typo = rhs.starts_with('=') || left.eq_ignore_ascii_case("$null");
                    let runs = descendants(value, &[])
                        .iter()
                        .any(|k| matches!(k.kind(), "command_name" | "command_name_expr" | "invokation_expression"));
                    let ctext = node_text(src, cond).trim();
                    let wrapped = ctext.starts_with('(') && ctext.ends_with(')');
                    if typo || (!runs && !wrapped) {
                        return Some((node_span(n), left, rhs.to_string()));
                    }
                }
            }
            None
        })
        .flatten();
        if let Some((span, left, rhs)) = hit {
            let rhs = rhs.trim_start_matches('=').trim();
            out.push(finding(
                PS_ASSIGN_IN_CONDITION,
                Level::Warn,
                span,
                "`=` in a condition assigns; it does not compare, so the condition tests the assigned value".to_string(),
                format!("compare with -eq: {left} -eq {rhs}"),
            ));
        }
    }
}

pub const PS_REDIRECT_IN_CONDITION: &str = "ps-redirect-in-condition";

/// `if ($a > $b)` (Specter PossibleIncorrectUsageOfRedirectionOperator): `>` redirects to a file
/// named after the right side instead of comparing.
pub struct RedirectInCondition;

impl Rule for RedirectInCondition {
    fn id(&self) -> &'static str {
        PS_REDIRECT_IN_CONDITION
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !parsed(ctx) {
            return;
        }
        let src = ctx.input.command;
        if !src.contains('>') {
            return;
        }
        let hit = with_tree(src, |root| {
            for cond in conditions(root) {
                for n in descendants(cond, &["script_block"]) {
                    if n.kind() != "redirection" {
                        continue;
                    }
                    let Some(op) = n.named_child(0) else { continue };
                    if op.kind() != "file_redirection_operator" {
                        continue;
                    }
                    return Some((node_span(n), node_text(src, op).trim().to_string()));
                }
            }
            None
        })
        .flatten();
        if let Some((span, op)) = hit {
            let fix = if op.contains('>') {
                "compare with -gt instead of >"
            } else {
                "compare with -lt instead of <"
            };
            out.push(finding(
                PS_REDIRECT_IN_CONDITION,
                Level::Warn,
                span,
                format!(
                    "`{op}` in a condition redirects output to a file named after the right side; it does not compare"
                ),
                fix.to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_holds_both_editions() {
        let gci = cmdlet("get-childitem", '7').expect("pwsh has Get-ChildItem");
        assert!(gci.params.iter().any(|p| p.name == "recurse"));
        assert!(gci.params.iter().any(|p| p.common), "common parameters are bound");
        assert!(cmdlet("get-wmiobject", '7').is_none());
        assert!(cmdlet("get-wmiobject", '5').is_some());
        assert_eq!(alias_target("ls", '7'), Some("get-childitem"));
        assert_eq!(variable_kind("HOME", '7'), Some("readonly"));
        assert_eq!(variable_kind("args", '7'), Some("automatic"));
        assert!(is_approved_verb("Get"));
        assert!(!is_approved_verb("Frob"));
    }

    fn bound(cmd: &str, typed: &str) -> String {
        let c = cmdlet(cmd, '7').unwrap();
        match bind(&c, typed) {
            Bound::Param(p) => p.name.to_string(),
            Bound::Ambiguous(_) => "ambiguous".to_string(),
            Bound::Missing => "missing".to_string(),
        }
    }

    /// Known answers from real calls in an empty folder and `(Get-Command <cmd>).ResolveParameter`
    /// on pwsh 7.7.
    #[test]
    fn binding_follows_powershell() {
        let table = [
            ("select-string", "C", "ambiguous"),
            ("select-string", "Context", "context"),
            ("select-string", "A", "allmatches"),
            ("select-string", "i", "ambiguous"),
            ("select-string", "Recurse", "missing"),
            ("get-childitem", "la", "missing"),
            ("get-childitem", "l", "literalpath"),
            // A dynamic parameter loses to a static one (`-fo`: -Force, not -FollowSymlink) and is
            // tried when no static one matches (`-a`: -Attributes and the -ad/-af/... aliases).
            ("get-childitem", "fo", "force"),
            ("get-childitem", "a", "ambiguous"),
            ("get-childitem", "fi", "filter"),
            ("get-childitem", "h", "hidden"),
            ("get-content", "e", "exclude"),
            ("get-content", "w", "ambiguous"),
            ("set-content", "n", "nonewline"),
            ("get-childitem", "ea", "erroraction"),
            ("get-childitem", "File", "file"),
            // An alias prefix counts (`-psp` → `-PSPath`, an alias of `-LiteralPath`).
            ("get-childitem", "psp", "literalpath"),
            // A single non-common match beats common ones (`-e`: Exclude, ErrorAction, ...).
            ("get-childitem", "e", "exclude"),
            // ShouldProcess parameters only on cmdlets that support them.
            ("get-childitem", "whatif", "missing"),
            ("remove-item", "whatif", "whatif"),
        ];
        for (cmd, typed, want) in table {
            assert_eq!(bound(cmd, typed), want, "{cmd} -{typed}");
        }
    }

    #[test]
    fn the_null_comparison_operators_are_the_equality_ones() {
        for op in ["-eq", "-ne", "-ceq", "-ine", "-EQ", "\u{2013}eq"] {
            assert!(equality(op), "{op}");
        }
        for op in ["-gt", "-like", "-in", "-contains", "-ge"] {
            assert!(!equality(op), "{op}");
        }
    }

    #[test]
    fn a_stale_variable_is_one_the_command_does_not_bind() {
        let bound = vec!["report".to_string()];
        assert_eq!(stale_var("$text", &bound, '7').as_deref(), Some("text"));
        assert_eq!(stale_var("$report", &bound, '7'), None);
        assert_eq!(stale_var("'$text'", &bound, '7'), None);
        assert_eq!(stale_var("$env:TEXT", &bound, '7'), None);
        assert_eq!(stale_var("$null", &bound, '7'), None);
        assert_eq!(stale_var("\"say `$x\"", &bound, '7'), None);
        assert_eq!(stale_var("($t + 'x')", &bound, '7').as_deref(), Some("t"));
        assert_eq!(stale_var("$script:report", &bound, '7'), None);
    }

    #[test]
    fn a_torn_string_holds_a_quote_of_its_own_family() {
        assert_eq!(
            torn_quote("\"Zmiana \u{201e}x\u{201d} gotowa\""),
            Some(('"', '\u{201e}'))
        );
        assert_eq!(torn_quote("'Fix \u{2018}x\u{2019} now'"), Some(('\'', '\u{2018}')));
        assert_eq!(torn_quote("'Zmiana \u{201e}x\u{201d}'"), None);
        assert_eq!(torn_quote("@'\n\u{201e}x\u{201d}\n'@"), None);
    }

    #[test]
    fn rooted_paths() {
        for p in ["C:\\x", "c:/x", "\\\\srv\\s", "/x"] {
            assert!(is_rooted(p), "{p}");
        }
        for p in ["tools\\x.php", "~/.claude/x", "x", "C:x"] {
            assert!(!is_rooted(p), "{p}");
        }
    }

    #[test]
    fn launcher_patterns_match_names_and_paths() {
        let pats: Vec<String> = ["php", "php8[0-9]", r"vendor\bin\*", "composer"]
            .map(String::from)
            .to_vec();
        for n in [
            "php",
            "PHP.bat",
            "php84",
            r"vendor\bin\phpunit",
            r".\vendor\bin\phpunit",
            "./vendor/bin/phpcs",
            r"tools\composer.bat",
        ] {
            assert!(launcher_named(n, &pats), "{n}");
        }
        for n in ["php7", "phpx", r"vendor\phpunit", "rg"] {
            assert!(!launcher_named(n, &pats), "{n}");
        }
    }

    #[test]
    fn powershell_wraps_a_native_argument_with_whitespace() {
        assert!(ps_wraps(""));
        assert!(ps_wraps("a b"));
        assert!(!ps_wraps("a|b"));
        assert!(!ps_wraps("x\"a b\"y"));
        assert!(ps_wraps("a\\\" b"));
    }
}
