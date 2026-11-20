//! The delete guard (Ruling 98(2), F14). Each target of a command in the delete family is
//! resolved as the shell would and judged in this order, the first match deciding:
//!
//! 1. **critical:** a system path, a drive root, `/`, the home folder, the root of the repo
//!    holding the cwd, a protected path, or an ancestor of one of them;
//! 2. **danger:** a target the guard cannot place (dynamic, unknown location, a walk that did
//!    not finish) or a delete that goes through a link;
//! 3. **ok:** inside an allowed root (`cfg.allowed_roots`); deleting an allowed root itself is
//!    danger;
//! 4. **ok:** inside the project (the repo root of the cwd, or the cwd outside any repo);
//! 5. **danger:** anything else.
//!
//! The family and its flags come from `data/destructive.toml`; which words a program deletes
//! comes from its `delete` facts in `data/programs.toml` (`Program::extra`). A command whose
//! code the guard cannot read (an opaque name, a shell or eval body, an unread wrapper) is
//! danger only when its raw text names a destructive command (Ruling 91a). The git commands
//! are judged in `git.rs`.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{Ctx, Rule};
use crate::fs::resolve::{self, DeleteBy, Location, Target, UnknownKind};
use crate::fs::walk::{self, WalkResult, is_within};
use crate::fs::{TimedOut, bounded};
use crate::ir::{
    Elem, EnvView, MethodCall, Pipeline, Quote, Redirect, Script, SimpleCommand, Stmt, Word,
    WordPart,
};
use crate::level::{Finding, Level, Span};
use crate::programs::{self, Kind, Program};
use crate::{Os, Shell, scan};

/// A delete program's facts: the `[program.delete]` table of its row.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct DeleteFacts {
    /// Options that make the delete recursive: a native short flag matches inside a cluster
    /// (`-rf`), a cmdlet parameter by prefix (`-r`, `-Rec`).
    pub recursive: Vec<String>,
    /// Every call is recursive (`robocopy /MIR`).
    pub always_recursive: bool,
    /// Options that make it delete nothing (`-WhatIf`, robocopy's `/L`).
    pub dry_run: Vec<String>,
    /// Cmdlet parameters whose value is a target (`-Path`, `-LiteralPath`).
    pub target_options: Vec<String>,
    /// Which words name what it deletes.
    pub targets: TargetWords,
    /// It deletes inside each target, not the target itself (`find <dir> -delete`).
    pub contents: bool,
    /// Its options start with `/` too (robocopy).
    pub slash_options: bool,
    /// Options that start a clause running another command (`find -exec`).
    pub exec_options: Vec<String>,
    /// Words that end such a clause (`;`, `+`).
    pub exec_ends: Vec<String>,
    /// It deletes nothing itself but runs the command after its options on names read from
    /// its input (`xargs rm`).
    pub runner: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TargetWords {
    /// Every operand.
    #[default]
    Operands,
    /// The second operand (robocopy's destination).
    Second,
    /// The operands before the first option (find's start folders; `.` when there is none).
    Leading,
}

/// The `key` table of every program row, parsed once, in `programs::table()` order. An entry
/// that does not parse is a bug in the embedded table: it panics like the table's own load.
pub(crate) fn facts_of<T: DeserializeOwned + Send + Sync + 'static>(
    cache: &'static OnceLock<Vec<Option<T>>>,
    key: &str,
    prog: &Program,
) -> Option<&'static T> {
    let all = cache.get_or_init(|| {
        programs::table()
            .iter()
            .map(|p| {
                p.extra.get(key).map(|v| {
                    v.clone().try_into().unwrap_or_else(|e| {
                        panic!("data/programs.toml: {:?}: bad {key} facts: {e}", p.name)
                    })
                })
            })
            .collect()
    });
    let i = programs::table().iter().position(|p| std::ptr::eq(p, prog))?;
    all.get(i)?.as_ref()
}

pub(crate) fn delete_facts(prog: &Program) -> Option<&'static DeleteFacts> {
    static CACHE: OnceLock<Vec<Option<DeleteFacts>>> = OnceLock::new();
    facts_of(&CACHE, "delete", prog)
}

pub const DELETE_CRITICAL: &str = "delete-critical";
pub const DELETE_THROUGH_LINK: &str = "delete-through-link";
pub const DELETE_OUTSIDE_PROJECT: &str = "delete-outside-project";
pub const DELETE_ALLOWED_ROOT: &str = "delete-allowed-root";
pub const DELETE_UNKNOWN_LOCATION: &str = "delete-unknown-location";
pub const DYNAMIC_TARGET: &str = "dynamic-target";
pub const WALK_TIMEOUT: &str = "walk-timeout";
pub const WALK_UNREADABLE: &str = "walk-unreadable";
pub const OPAQUE_DESTRUCTIVE: &str = "opaque-destructive";

/// The Fix line of every danger the marker may confirm.
pub(crate) const CONFIRM_FIX: &str =
    "if this is intended, run the same command again with ` # shellwise: allow` at its end";

pub struct DeleteRule;

impl Rule for DeleteRule {
    fn id(&self) -> &'static str {
        DELETE_CRITICAL
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let shell = ctx.input.shell;
        let os = ctx.input.os;
        let command = ctx.input.command;
        // Cheap first pass: no file system, no location, unless some command may delete.
        if !any_node(ctx.script, &mut |n| match n {
            Node::Cmd { cmd, .. } => match read_call(cmd, false, shell, os) {
                Read::Unread => unread_hits(cmd, command),
                Read::Call(call, prog) => in_family(&call, prog, shell, os),
                Read::Plain => false,
            },
            Node::Method(m) => method_row(m).is_some(),
        }) {
            return;
        }
        let mut scene = Scene::new(ctx);
        let env = scene.env.clone();
        let mut loc = scene.location();
        walk_script(ctx.script, &mut loc, &env, &mut |node, loc| {
            let found = match node {
                Node::Cmd { cmd, piped } => match read_call(cmd, piped, shell, os) {
                    Read::Unread if unread_hits(cmd, command) => Some(opaque(cmd, command)),
                    Read::Call(call, prog) if in_family(&call, prog, shell, os) => {
                        scene.judge_call(&call, prog, loc)
                    }
                    _ => None,
                },
                Node::Method(m) => scene.judge_method(m, loc),
            };
            out.extend(found);
        });
    }
}

// ------------------------------------------------------------------ reading a command

/// A command once its wrappers are read: the name it runs and that command.
pub(crate) struct Call<'a> {
    /// The name as the guard matches it: the cmdlet a PowerShell alias stands for, otherwise
    /// the program's base name, lowercased, without its folder or `.exe`.
    pub name: String,
    /// A PowerShell cmdlet (its parameters bind by prefix), not a native program.
    pub cmdlet: bool,
    /// The command run, wrappers read (`programs::strip_wrappers`).
    pub run: Cow<'a, SimpleCommand>,
    /// Not the first element of its pipeline: it may read its targets from the pipeline.
    pub piped: bool,
    /// The command as written, wrappers included.
    pub original: &'a SimpleCommand,
}

impl Call<'_> {
    pub fn args(&self) -> &[Word] {
        &self.run.args
    }

    /// The span of the whole command, wrappers included.
    pub fn span(&self) -> Span {
        self.original.span
    }
}

pub(crate) enum Read<'a> {
    Call(Call<'a>, &'static Program),
    /// A program the table does not know: never a reason to deny by itself (Ruling 91a).
    Plain,
    /// Code the guard does not read: an opaque name, an unread wrapper, a shell or eval body.
    Unread,
}

pub(crate) fn is_pwsh(shell: Shell) -> bool {
    matches!(shell, Shell::Pwsh | Shell::Powershell5)
}

/// `raw` (lowercased) without its folder and without `.exe`.
pub(crate) fn base_name(raw: &str) -> String {
    let lower = raw.to_lowercase();
    let base = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    if base.is_empty() {
        lower.clone()
    } else {
        base.to_string()
    }
}

/// The word's text when it is one literal.
pub(crate) fn literal(w: &Word) -> Option<String> {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) => out.push_str(s),
            _ => return None,
        }
    }
    Some(out)
}

/// The literal text the word starts with (`-Recurse:` of `-Recurse:$x`).
pub(crate) fn leading_literal(w: &Word) -> Option<&str> {
    match w.parts.first() {
        Some(WordPart::Literal(s)) => Some(s.as_str()),
        _ => None,
    }
}

pub(crate) fn read_call(c: &SimpleCommand, piped: bool, shell: Shell, os: Os) -> Read<'_> {
    if c.opaque {
        return Read::Unread;
    }
    let run = programs::strip_wrappers(c, shell, os);
    if run.opaque {
        return Read::Unread;
    }
    let (name, cmdlet) = match (&run.canonical, is_pwsh(shell)) {
        (Some(cmdlet), true) => (cmdlet.to_lowercase(), true),
        _ => (base_name(&run.typed), false),
    };
    let Some(prog) = programs::lookup(&name, shell, os) else {
        return Read::Plain;
    };
    // A wrapper left after the strip runs something the table cannot read.
    if prog.is(Kind::Shell) || prog.is(Kind::Eval) || prog.is(Kind::Wrapper) {
        return Read::Unread;
    }
    Read::Call(
        Call {
            name,
            cmdlet,
            run,
            piped,
            original: c,
        },
        prog,
    )
}

/// The text of `c` names a destructive command: a raw-scan hit on a table row or a .NET
/// `Delete()` call in its own span. A region the scan cannot read (an encoded or too-deep body)
/// is no destructive match (Ruling 106(a)).
fn unread_hits(c: &SimpleCommand, command: &str) -> bool {
    command
        .get(c.span.start..c.span.end)
        .is_some_and(|t| scan::destructive_row(t).is_some())
}

fn opaque(c: &SimpleCommand, command: &str) -> Finding {
    let text = command.get(c.span.start..c.span.end).unwrap_or_default();
    let shown: String = text.chars().take(80).collect();
    finding(
        OPAQUE_DESTRUCTIVE,
        Level::Danger,
        format!(
            "the guard cannot read what `{shown}` runs, and its text names a command that deletes or discards data"
        ),
        "run the delete as a plain command of its own, or, if this is intended, run the same command again with ` # shellwise: allow` at its end".to_string(),
        c.span,
    )
}

// ------------------------------------------------------------------ the family

/// The literal text of each word, `None` for a word that is not one literal.
pub(crate) fn literals(args: &[Word]) -> Vec<Option<String>> {
    args.iter().map(literal).collect()
}

/// Whether the destructive table row for `name` holds for these later words: one of
/// `requires_any` is present (or it is empty) and none of `unless_any` stands before `--`.
/// `None` when no row names the command.
pub(crate) fn row_holds(name: &[String], later: &[Option<String>]) -> Option<bool> {
    let words: Vec<&str> = later.iter().flatten().map(String::as_str).collect();
    let before_end: Vec<&str> = words.iter().copied().take_while(|w| *w != "--").collect();
    let mut named = false;
    for entry in scan::table() {
        if !entry.names.iter().any(|n| n.as_slice() == name) {
            continue;
        }
        named = true;
        let required = entry.requires_any.is_empty()
            || entry
                .requires_any
                .iter()
                .any(|e| words.iter().any(|w| scan::flag_matches(e, w)));
        let refused = entry
            .unless_any
            .iter()
            .any(|e| before_end.iter().any(|w| scan::flag_matches(e, w)));
        if required && !refused {
            return Some(true);
        }
    }
    named.then_some(false)
}

/// The call deletes: a delete program whose table row holds (or that has no row), a runner
/// (`xargs`) that runs one, or a program whose exec clause (`find -exec`) runs one.
fn in_family(call: &Call, prog: &Program, shell: Shell, os: Os) -> bool {
    let Some(facts) = delete_facts(prog) else {
        return false;
    };
    if facts.runner {
        return runner_runs_delete(call.args(), prog, shell, os);
    }
    let exec = exec_deletes(call.args(), facts, shell, os);
    match row_holds(std::slice::from_ref(&call.name), &literals(call.args())) {
        Some(holds) => holds || exec,
        // A delete program the destructive table has no row for still deletes.
        None => true,
    }
}

/// A program that deletes by itself (not a runner).
fn deletes(prog: &Program) -> bool {
    delete_facts(prog).is_some_and(|f| !f.runner)
}

/// The table row a .NET call such as `[IO.Directory]::Delete` matches.
fn method_row(m: &MethodCall) -> Option<()> {
    if m.type_name.is_empty() {
        return None;
    }
    let name = format!("[{}]::{}", m.type_name, m.method).to_lowercase();
    (row_holds(std::slice::from_ref(&name), &[]) == Some(true)).then_some(())
}

/// The program a runner such as `xargs` starts, after its options.
fn runner_runs_delete(args: &[Word], runner: &Program, shell: Shell, os: Os) -> bool {
    let mut i = 0;
    while i < args.len() {
        let Some(t) = literal(&args[i]) else {
            return false;
        };
        if t.starts_with('-') && t.len() > 1 {
            i += if runner.value_options.contains(&t) { 2 } else { 1 };
            continue;
        }
        return programs::lookup(&base_name(&t), shell, os).is_some_and(deletes);
    }
    false
}

/// An exec clause of `args` (`-exec rm -rf {} +`) runs a delete program.
fn exec_deletes(args: &[Word], facts: &DeleteFacts, shell: Shell, os: Os) -> bool {
    if facts.exec_options.is_empty() {
        return false;
    }
    let lits = literals(args);
    lits.iter().enumerate().any(|(i, t)| {
        t.as_ref().is_some_and(|t| facts.exec_options.contains(t))
            && lits
                .get(i + 1)
                .and_then(|n| n.as_deref())
                .and_then(|n| programs::lookup(&base_name(n), shell, os))
                .is_some_and(deletes)
    })
}

// ------------------------------------------------------------------ which words it deletes

/// The words a delete names and how it deletes them.
#[derive(Default)]
struct Picked {
    words: Vec<Word>,
    recursive: bool,
    contents: bool,
    dry_run: bool,
}

fn is_pwsh_param(t: &str) -> bool {
    let mut chars = t.chars();
    matches!(
        chars.next(),
        Some('-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
    ) && chars
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '?')
}

/// `written` (`-Rec`, `-Recurse:$true`) binds to one of `list` as PowerShell binds by prefix.
fn pwsh_matches(list: &[String], written: &str) -> bool {
    let name = written
        .trim_start_matches(['-', '\u{2013}', '\u{2014}', '\u{2015}'])
        .split(':')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    !name.is_empty()
        && list
            .iter()
            .any(|e| e.trim_start_matches('-').to_lowercase().starts_with(&name))
}

fn word_of(text: &str, like: &Word) -> Word {
    Word {
        parts: vec![WordPart::Literal(text.to_string())],
        span: like.span,
        quote: like.quote,
    }
}

/// The targets of a cmdlet: positional words and the values of its target parameters.
fn cmdlet_targets(args: &[Word], facts: &DeleteFacts, prog: &Program) -> Picked {
    let mut p = Picked::default();
    let mut i = 0;
    while i < args.len() {
        let w = &args[i];
        i += 1;
        let Some(lead) = leading_literal(w).filter(|t| is_pwsh_param(t)) else {
            p.words.push(w.clone());
            continue;
        };
        let inline = lead.split_once(':').map(|(_, v)| v.to_string());
        let whole = literal(w);
        if pwsh_matches(&facts.dry_run, lead) {
            p.dry_run = true;
        } else if pwsh_matches(&facts.recursive, lead) {
            p.recursive = true;
        } else if pwsh_matches(&facts.target_options, lead) {
            match (inline, whole) {
                (Some(v), Some(_)) if !v.is_empty() => p.words.push(word_of(&v, w)),
                // `-Path:$x`: the value is the dynamic rest of the word.
                (Some(v), None) if !v.is_empty() || w.parts.len() > 1 => p.words.push(w.clone()),
                _ => {
                    if let Some(v) = args.get(i) {
                        p.words.push(v.clone());
                        i += 1;
                    }
                }
            }
        } else if pwsh_matches(&prog.value_options, lead) && inline.is_none() {
            i += 1;
        }
    }
    p
}

/// The targets of a native program, by its `targets` fact.
fn native_targets(args: &[Word], facts: &DeleteFacts, prog: &Program) -> Picked {
    let mut p = Picked {
        recursive: facts.always_recursive,
        contents: facts.contents,
        ..Picked::default()
    };
    let mut operands: Vec<Word> = Vec::new();
    let mut seen_option = false;
    let mut ended = false;
    let mut i = 0;
    while i < args.len() {
        let w = &args[i];
        i += 1;
        let t = literal(w);
        if let Some(t) = t.as_deref().filter(|_| !ended) {
            if t == "--" {
                ended = true;
                continue;
            }
            let option = t.len() > 1
                && (t.starts_with('-') || (facts.slash_options && t.starts_with('/')));
            if option {
                seen_option = true;
                p.recursive |= facts.recursive.iter().any(|e| scan::flag_matches(e, t));
                p.dry_run |= facts.dry_run.iter().any(|e| scan::flag_matches(e, t));
                if facts.exec_options.iter().any(|e| e == t) {
                    // The clause runs once per match: what it deletes lies inside the targets.
                    while i < args.len() {
                        let end = literal(&args[i]).is_some_and(|x| facts.exec_ends.contains(&x));
                        i += 1;
                        if end {
                            break;
                        }
                    }
                } else if prog.value_options.iter().any(|e| e == t) {
                    i += 1;
                }
                continue;
            }
        }
        if facts.targets == TargetWords::Leading && seen_option {
            continue;
        }
        operands.push(w.clone());
    }
    p.words = match facts.targets {
        TargetWords::Operands | TargetWords::Leading => operands,
        TargetWords::Second => operands.into_iter().nth(1).into_iter().collect(),
    };
    if facts.targets == TargetWords::Leading && p.words.is_empty() {
        // `find -delete` starts at the current folder.
        p.words.push(Word {
            parts: vec![WordPart::Literal('.'.to_string())],
            span: Span::default(),
            quote: Quote::None,
        });
    }
    p
}

/// A pwsh list word (`a,C:\`) as one word per element; any other word as itself.
pub(crate) fn elements(w: &Word) -> Vec<Word> {
    if !w.parts.contains(&WordPart::ListSep) {
        return vec![w.clone()];
    }
    w.parts
        .split(|p| *p == WordPart::ListSep)
        .map(|parts| Word {
            parts: parts.to_vec(),
            span: w.span,
            quote: w.quote,
        })
        .collect()
}

// ------------------------------------------------------------------ the scene

/// What a delete's targets are judged against: the env with every name the command assigns
/// marked dynamic, the home folder from the hook's own environment, and the repo of the cwd,
/// looked up once and only when a delete needs it.
pub(crate) struct Scene<'a> {
    pub ctx: &'a Ctx<'a>,
    pub env: EnvView,
    home: Option<PathBuf>,
    repo: Option<Result<Option<PathBuf>, TimedOut>>,
}

/// How a delete treats one target.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct How {
    pub recursive: bool,
    pub contents: bool,
}

impl<'a> Scene<'a> {
    pub fn new(ctx: &'a Ctx<'a>) -> Scene<'a> {
        let mut env = ctx.input.env.clone();
        resolve::mark_assigned(&mut env, ctx.script, ctx.input.command);
        Scene {
            ctx,
            env,
            // Read before any marking: a command that assigns `HOME` does not move the home
            // folder critical paths are compared with.
            home: ctx.input.env.home().map(PathBuf::from),
            repo: None,
        }
    }

    pub fn location(&self) -> Location {
        let input = self.ctx.input;
        let mut loc = Location::new(input.shell, input.os, input.cwd.as_deref());
        loc.read_script(self.ctx.script);
        loc
    }

    fn os(&self) -> Os {
        self.ctx.input.os
    }

    fn key(&self, p: &Path) -> String {
        resolve::path_key(&p.to_string_lossy(), self.os())
    }

    /// The root of the repo holding the cwd.
    pub fn repo(&mut self) -> Result<Option<PathBuf>, TimedOut> {
        if self.repo.is_none() {
            let found = match &self.ctx.input.cwd {
                Some(cwd) if !resolve::is_network_or_device(cwd, self.os()) => {
                    resolve::repo_root(cwd, self.ctx.fs, self.ctx.deadline)
                }
                // On a share the guard looks for no repo: the project is the cwd itself.
                _ => Ok(None),
            };
            self.repo = Some(found);
        }
        self.repo.clone().unwrap_or(Ok(None))
    }

    /// The project: the repo root of the cwd, or the cwd itself outside any repo (F14).
    fn project(&mut self) -> Result<Option<PathBuf>, TimedOut> {
        Ok(self.repo()?.or_else(|| self.ctx.input.cwd.clone()))
    }

    /// Why deleting `p` is critical. Deleting inside the repo root (`contents`, as in
    /// `find . -name '*.o' -delete` from the root) is not; inside a drive root, `/`, a system
    /// path, the home folder, a protected path or an ancestor of one still is.
    pub fn critical(&mut self, p: &Path, contents: bool) -> Result<Option<&'static str>, TimedOut> {
        let repo = self.repo()?;
        let cfg = self.ctx.cfg;
        let reason = resolve::critical_by_identity(
            p,
            repo.as_deref(),
            self.home.as_deref(),
            &cfg.protected,
            self.ctx.fs,
            self.ctx.deadline,
        )?;
        if contents
            && reason.is_some()
            && repo.as_deref().is_some_and(|r| self.key(r) == self.key(p))
        {
            return Ok(None);
        }
        Ok(reason)
    }

    /// The finding for one resolved path, or `None` when deleting it is ok.
    pub fn judge_path(&mut self, p: &Path, how: How, span: Span, shown: &str) -> Option<Finding> {
        if resolve::is_network_or_device(p, self.os()) {
            return Some(self.unknown_location(
                span,
                shown,
                "it is a network or device path, which the guard does not read",
            ));
        }
        match self.critical(p, how.contents) {
            Err(TimedOut) => return Some(self.timeout(span, shown)),
            Ok(Some(reason)) => return Some(critical(p, reason, span)),
            Ok(None) => {}
        }
        let os = self.os();
        let key = self.key(p);
        let mut placed = false;
        let cfg = self.ctx.cfg;
        for root in cfg.allowed_roots.iter().chain(cfg.scratch_dir.as_ref()) {
            let rk = self.key(root);
            if rk == key && !how.contents {
                return Some(finding(
                    DELETE_ALLOWED_ROOT,
                    Level::Danger,
                    format!(
                        "`{}` is an allowed scratch or temp root itself: deleting it removes every other session's files in it",
                        p.display()
                    ),
                    format!(
                        "delete only what you made inside it, for example `{}`",
                        p.join("<name>").display()
                    ),
                    span,
                ));
            }
            if is_within(&key, &rk, os) {
                placed = true;
                break;
            }
        }
        if !placed {
            match self.project() {
                Err(TimedOut) => return Some(self.timeout(span, shown)),
                Ok(Some(project)) => {
                    let pk = self.key(&project);
                    let inside = (key != pk && is_within(&key, &pk, os)) || (how.contents && key == pk);
                    if !inside {
                        return Some(outside(p, key == pk, span));
                    }
                }
                Ok(None) => return Some(outside(p, false, span)),
            }
        }
        self.links(p, how, span, shown)
    }

    /// A delete that would go through a link: a recursive delete of a tree holding a link that
    /// leads out of it (or that is a link itself), or any delete below a link.
    fn links(&mut self, p: &Path, how: How, span: Span, shown: &str) -> Option<Finding> {
        let shell = self.ctx.input.shell;
        if how.recursive && !how.contents {
            return match walk::outside_links(p, self.ctx.fs, self.ctx.deadline) {
                WalkResult::Clean => None,
                WalkResult::Outside(links) => {
                    let first = links.first().map(|l| l.path.clone()).unwrap_or_default();
                    Some(through_link(p, &first, shell, span))
                }
                WalkResult::Unreadable(at) => Some(finding(
                    WALK_UNREADABLE,
                    Level::Danger,
                    format!(
                        "the guard cannot read `{}` inside the tree `{}` deletes, so it cannot tell whether a link there leads outside it",
                        at.display(),
                        shown
                    ),
                    CONFIRM_FIX.to_string(),
                    span,
                )),
                WalkResult::Timeout => Some(self.timeout(span, shown)),
            };
        }
        let fs = Arc::clone(self.ctx.fs);
        let d = *self.ctx.deadline;
        let path = p.to_path_buf();
        let above = bounded(self.ctx.deadline, move || {
            for a in path.ancestors().skip(1) {
                if d.expired() {
                    return Err(TimedOut);
                }
                if fs.lstat(a).is_ok_and(|m| m.is_symlink) {
                    return Ok(Some(a.to_path_buf()));
                }
            }
            Ok(None)
        });
        match above {
            Ok(Ok(None)) => None,
            Ok(Ok(Some(link))) => Some(through_link(p, &link, shell, span)),
            _ => Some(self.timeout(span, shown)),
        }
    }

    pub fn timeout(&self, span: Span, shown: &str) -> Finding {
        finding(
            WALK_TIMEOUT,
            self.ctx.cfg.dynamic_target,
            format!(
                "the guard ran out of time while checking what `{shown}` deletes, so it cannot tell whether that is safe"
            ),
            CONFIRM_FIX.to_string(),
            span,
        )
    }

    pub fn dynamic(&self, span: Span, shown: &str, why: &str) -> Finding {
        finding(
            DYNAMIC_TARGET,
            self.ctx.cfg.dynamic_target,
            format!("the guard cannot tell what `{shown}` deletes: {why}"),
            "write the path literally, or, if this is intended, run the same command again with ` # shellwise: allow` at its end".to_string(),
            span,
        )
    }

    pub fn unknown_location(&self, span: Span, shown: &str, why: &str) -> Finding {
        finding(
            DELETE_UNKNOWN_LOCATION,
            Level::Danger,
            format!("the guard cannot tell which folder `{shown}` names: {why}"),
            "use the full path of the folder, or, if this is intended, run the same command again with ` # shellwise: allow` at its end".to_string(),
            span,
        )
    }

    /// The finding for one target word (each list element resolved; the highest level wins).
    pub fn judge_word(
        &mut self,
        word: &Word,
        loc: &Location,
        by: DeleteBy,
        how: How,
        span: Span,
    ) -> Option<Finding> {
        let mut worst: Option<Finding> = None;
        for el in elements(word) {
            let found = self.judge_element(&el, loc, by, how, span);
            worst = max_finding(worst, found);
        }
        worst
    }

    fn judge_element(
        &mut self,
        word: &Word,
        loc: &Location,
        by: DeleteBy,
        how: How,
        span: Span,
    ) -> Option<Finding> {
        let input = self.ctx.input;
        let shown = input
            .command
            .get(word.span.start..word.span.end)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| literal(word))
            .unwrap_or_default();
        // A literal root or system path is critical wherever the shell stands.
        if let Some(text) = literal(word)
            && let Some(reason) = resolve::critical_reason(Path::new(&text), None, None, &[])
        {
            return Some(critical(Path::new(&text), reason, span));
        }
        let target = resolve::target(word, loc, &self.env, by, self.ctx.fs, self.ctx.deadline);
        match target {
            Target::Paths(paths) => {
                let mut worst = None;
                for p in paths {
                    let found = self.judge_path(&p, how, span, &shown);
                    worst = max_finding(worst, found);
                }
                worst
            }
            Target::Dynamic(_) | Target::UnknownLocation(UnknownKind::Dynamic) => Some(self.dynamic(
                span,
                &shown,
                "it holds a variable or a substitution the command sets or the guard cannot read",
            )),
            Target::UnknownLocation(UnknownKind::MayBeCritical) => Some(self.unknown_location(
                span,
                &shown,
                "the command moves to a folder the guard cannot follow, defines a function or alias, maps a drive, runs a script or makes a link before it",
            )),
            Target::DriveUnproven { drive, .. } => Some(self.unknown_location(
                span,
                &shown,
                &format!("nothing shows the drive `{drive}:` is the file system the guard sees"),
            )),
            Target::NotAFile | Target::SessionCommand => None,
            Target::Timeout => Some(self.timeout(span, &shown)),
        }
    }

    fn judge_call(&mut self, call: &Call, prog: &Program, loc: &Location) -> Option<Finding> {
        let span = call.span();
        let shown = self
            .ctx
            .input
            .command
            .get(span.start..span.end)
            .unwrap_or_default()
            .to_string();
        let facts = delete_facts(prog)?;
        if facts.runner {
            return Some(self.dynamic(span, &shown, "it deletes the names it reads from its input"));
        }
        let picked = if call.cmdlet {
            cmdlet_targets(call.args(), facts, prog)
        } else {
            native_targets(call.args(), facts, prog)
        };
        if picked.dry_run {
            return None;
        }
        let how = How {
            recursive: picked.recursive || facts.always_recursive,
            contents: picked.contents,
        };
        if picked.words.is_empty() {
            // `Get-ChildItem x | Remove-Item`: the targets come from the pipeline.
            return (call.cmdlet && call.piped)
                .then(|| self.dynamic(span, &shown, "it deletes what the pipeline feeds it"));
        }
        let by = resolve::delete_by(&call.run, self.ctx.input.shell, self.ctx.input.os);
        let mut worst = None;
        for w in &picked.words {
            let found = self.judge_word(w, loc, by, how, span);
            worst = max_finding(worst, found);
        }
        worst
    }

    fn judge_method(&mut self, m: &MethodCall, loc: &Location) -> Option<Finding> {
        method_row(m)?;
        let target = m.args.first()?;
        // `Delete(path, $true)` deletes the whole tree; `Delete(path)` only an empty folder,
        // a link or a file.
        let how = How {
            recursive: m.args.len() >= 2,
            contents: false,
        };
        self.judge_word(target, loc, DeleteBy::Native, how, m.span)
    }
}

/// The higher of two findings; the first on a tie.
pub(crate) fn max_finding(a: Option<Finding>, b: Option<Finding>) -> Option<Finding> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.level > a.level { b } else { a }),
        (a, b) => a.or(b),
    }
}

pub(crate) fn finding(
    rule: &'static str,
    level: Level,
    message: String,
    fix: String,
    span: Span,
) -> Finding {
    Finding {
        rule,
        level,
        message,
        fix: Some(fix),
        span,
    }
}

pub(crate) fn critical(p: &Path, reason: &str, span: Span) -> Finding {
    finding(
        DELETE_CRITICAL,
        Level::Critical,
        format!(
            "deleting `{}` is blocked: it is the {reason}, and the allow marker cannot confirm it",
            p.display()
        ),
        format!(
            "delete only the folders inside it you mean, each by its full path, for example `{}`",
            p.join("<name>").display()
        ),
        span,
    )
}

fn outside(p: &Path, is_cwd: bool, span: Span) -> Finding {
    let message = if is_cwd {
        format!(
            "`{}` is the working folder itself (outside any repo): deleting it removes everything the session works in",
            p.display()
        )
    } else {
        format!(
            "`{}` is outside the project and outside every allowed scratch or temp root",
            p.display()
        )
    };
    finding(DELETE_OUTSIDE_PROJECT, Level::Danger, message, CONFIRM_FIX.to_string(), span)
}

fn through_link(p: &Path, link: &Path, shell: Shell, span: Span) -> Finding {
    let unlink = if is_pwsh(shell) {
        format!("[IO.Directory]::Delete('{}')", link.display())
    } else {
        let shown = link.display().to_string().replace('\\', "/");
        format!("rm '{shown}'")
    };
    finding(
        DELETE_THROUGH_LINK,
        Level::Danger,
        format!(
            "deleting `{}` goes through the link `{}`, so it would also delete files outside the tree",
            p.display(),
            link.display()
        ),
        format!("remove the link itself first with `{unlink}` in a command of its own, then run the delete again"),
        span,
    )
}

// ------------------------------------------------------------------ walking the IR

/// One command or .NET call of the script.
#[derive(Clone, Copy)]
pub(crate) enum Node<'a> {
    Cmd { cmd: &'a SimpleCommand, piped: bool },
    Method(&'a MethodCall),
}

fn cmd_words(c: &SimpleCommand) -> impl Iterator<Item = &Word> {
    std::iter::once(&c.name)
        .chain(c.args.iter())
        .chain(c.assigns.iter().map(|(_, w)| w))
        .chain(c.redirects.iter().map(|r| match r {
            Redirect::File { target, .. } => target,
            Redirect::Heredoc { body, .. } => body,
        }))
}

/// True when `pred` holds for some command or .NET call anywhere in `s`.
pub(crate) fn any_node(s: &Script, pred: &mut dyn FnMut(Node<'_>) -> bool) -> bool {
    s.stmts.iter().any(|st| any_in_stmt(st, pred))
}

fn any_in_stmt(st: &Stmt, pred: &mut dyn FnMut(Node<'_>) -> bool) -> bool {
    match st {
        Stmt::Pipeline(p) => p.elems.iter().enumerate().any(|(k, e)| match e {
            Elem::Cmd(c) => {
                pred(Node::Cmd { cmd: c, piped: k > 0 })
                    || cmd_words(c).any(|w| any_in_word(w, pred))
            }
            Elem::Method(m) => pred(Node::Method(m)) || m.args.iter().any(|w| any_in_word(w, pred)),
            Elem::Expr(w) => any_in_word(w, pred),
        }),
        Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
            any_node(body, pred)
        }
        Stmt::Cond { branches, .. } => branches.iter().any(|b| any_node(b, pred)),
    }
}

fn any_in_word(w: &Word, pred: &mut dyn FnMut(Node<'_>) -> bool) -> bool {
    w.parts.iter().any(|p| match p {
        WordPart::Subst(s) | WordPart::Block(s) => any_node(s, pred),
        _ => false,
    })
}

/// Visit every command and .NET call of `s` in order, each with the location the shell is in
/// when it runs (`Location`'s contract: statements in order, nested bodies from `inner`,
/// script blocks from `inner_block`, substitutions from a clone).
pub(crate) fn walk_script(
    s: &Script,
    loc: &mut Location,
    env: &EnvView,
    f: &mut dyn FnMut(Node<'_>, &Location),
) {
    for i in 0..s.stmts.len() {
        walk_stmt(&s.stmts[i], loc, env, f);
        loc.after_in(s, i, env);
    }
}

fn walk_stmt(st: &Stmt, loc: &Location, env: &EnvView, f: &mut dyn FnMut(Node<'_>, &Location)) {
    match st {
        Stmt::Pipeline(p) => {
            for (k, e) in p.elems.iter().enumerate() {
                match e {
                    Elem::Cmd(c) => {
                        f(Node::Cmd { cmd: c, piped: k > 0 }, loc);
                        for w in cmd_words(c) {
                            walk_word(w, p, loc, env, f);
                        }
                    }
                    Elem::Method(m) => {
                        f(Node::Method(m), loc);
                        for w in &m.args {
                            walk_word(w, p, loc, env, f);
                        }
                    }
                    Elem::Expr(w) => walk_word(w, p, loc, env, f),
                }
            }
        }
        Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
            let mut inner = loc.inner(st);
            walk_script(body, &mut inner, env, f);
        }
        Stmt::Cond { branches, .. } => {
            for b in branches {
                let mut inner = loc.inner(st);
                walk_script(b, &mut inner, env, f);
            }
        }
    }
}

fn walk_word(
    w: &Word,
    owner: &Pipeline,
    loc: &Location,
    env: &EnvView,
    f: &mut dyn FnMut(Node<'_>, &Location),
) {
    for p in &w.parts {
        match p {
            WordPart::Subst(s) => {
                let mut inner = loc.clone();
                walk_script(s, &mut inner, env, f);
            }
            WordPart::Block(b) => {
                let mut inner = loc.inner_block(b, owner);
                walk_script(b, &mut inner, env, f);
            }
            _ => {}
        }
    }
}
