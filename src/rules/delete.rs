//! The delete guard (Rulings 98(2) and 122, F14): deleting is allowed and signalled; a block is
//! for what is truly dangerous. Each target of a command in the delete family is resolved as the
//! shell would and judged in this order, the first match deciding:
//!
//! 1. **critical:** a system path, a drive root, `/`, the home folder, the root of the repo
//!    holding the cwd, its `.git`, a protected path, or an ancestor of one of them; a glob over
//!    the direct contents of one of them but the repo root (`rm -rf ~/*`, Ruling 125). The
//!    lexical match runs before the repo lookup and never waits on it;
//! 2. **danger:** a glob over the repo root's contents that leaves `.git`
//!    (`delete-repo-contents`); a recursive or forced delete whose target, with every variable
//!    or substitution the guard cannot read taken as empty, is one of those or their direct
//!    contents (`delete-empty-expansion`: `rm -rf "$X/"`, `Remove-Item -Recurse "$x\*"`); a
//!    recursive or forced delete whose repo lookup or identity match ran out of time
//!    (`walk-timeout`);
//! 3. **warn:** a target the guard cannot place (dynamic, unknown location, a walk that did not
//!    finish), a delete that passes a link, an allowed root itself;
//! 4. **ok:** inside an allowed root (`cfg.allowed_roots`) or inside the project (the repo root
//!    of the cwd, or the cwd outside any repo);
//! 5. **warn:** anything else (`delete-outside-project`).
//!
//! The family and its flags come from `data/destructive.toml`; which words a program deletes
//! comes from its `delete` facts in `data/programs.toml` (`Program::extra`). A command whose
//! code the guard cannot read (an opaque name, a shell or eval body, an unread wrapper) is
//! flagged only when its raw text names a destructive command (Ruling 91a): danger when its
//! words also hold a literal protected location, warn otherwise. The git commands are judged in
//! `git.rs`.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{Ctx, Rule};
use crate::fs::assigned::{Assigned, resolve_assigned};
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
    /// Options that force the delete (`-f`, `-Force`), matched as `recursive` is.
    pub forced: Vec<String>,
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
    /// It deletes through a link inside the tree and empties the link's target (`robocopy /MIR`).
    pub follows_links: bool,
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
    let i = programs::table()
        .iter()
        .position(|p| std::ptr::eq(p, prog))?;
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
pub const DELETE_EMPTY_EXPANSION: &str = "delete-empty-expansion";
pub const DELETE_REPO_CONTENTS: &str = "delete-repo-contents";

/// The reason a system folder is critical (`resolve::critical_reason` says the same).
const SYSTEM_FOLDER: &str = "system folder";

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
                    Read::Unread if unread_hits(cmd, command) => Some(scene.opaque(cmd)),
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
    Call(Box<Call<'a>>, &'static Program),
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
    // An opaque command stays opaque through the strip.
    let run = programs::strip_wrappers(c, shell, os);
    if run.opaque {
        return Read::Unread;
    }
    // A native name as the shell reads it: unquoted (`"rm"`, `'/usr/bin/rm'` run `rm`).
    let (name, cmdlet) = match (&run.canonical, is_pwsh(shell)) {
        (Some(cmdlet), true) => (cmdlet.to_lowercase(), true),
        _ => (
            base_name(&literal(&run.name).unwrap_or(run.typed.clone())),
            false,
        ),
    };
    let Some(prog) = programs::lookup(&name, shell, os) else {
        return Read::Plain;
    };
    // A wrapper left after the strip runs nothing (`command -v rm`) and has no delete facts, so
    // it reads as a plain command.
    if prog.is(Kind::Shell) || prog.is(Kind::Eval) {
        return Read::Unread;
    }
    Read::Call(
        Box::new(Call {
            name,
            cmdlet,
            run,
            piped,
            original: c,
        }),
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

/// The words a destructive hit acts on: those after its command's name, up to the end of that
/// statement (`;`, `&`, `|`, a newline), so a wrapper's own switch (Git Bash's `//c`) or a `cd`
/// before the delete is no target. The name matches as the scan matches it: without its folder,
/// module or `.exe` (`/usr/bin/rm`, `rm.exe`, `Microsoft.PowerShell.Management\Remove-Item`).
/// Every word for a hit no table row names (a `.Delete()`), and for a hit whose name no word
/// spells (`r""m`): the scan matched it, so its words are never none.
fn target_words(text: &str, kind: scan::Kind) -> Vec<&str> {
    let entry = match kind {
        scan::Kind::Row(k) => scan::table().get(k),
        _ => None,
    };
    let Some(entry) = entry else {
        return raw_words(text).collect();
    };
    let verbs: Vec<&str> = entry
        .names
        .iter()
        .filter_map(|n| n.last().map(String::as_str))
        .collect();
    let mut out = Vec::new();
    let mut named = false;
    for statement in text.split([';', '&', '|', '\n']) {
        let words: Vec<&str> = raw_words(statement).collect();
        if let Some(i) = words
            .iter()
            .position(|w| verbs.iter().any(|v| base_name(w) == v.to_lowercase()))
        {
            named = true;
            out.extend_from_slice(&words[i + 1..]);
        }
    }
    if !named {
        return raw_words(text).collect();
    }
    out
}

/// The words of raw command text, split at whitespace, quotes and shell punctuation.
fn raw_words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || "'\"`;&|()<>=,".contains(c))
        .filter(|w| !w.is_empty())
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
            i += if runner.value_options.contains(&t) {
                2
            } else {
                1
            };
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
    forced: bool,
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
        } else if pwsh_matches(&facts.forced, lead) {
            p.forced = true;
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
            let option =
                t.len() > 1 && (t.starts_with('-') || (facts.slash_options && t.starts_with('/')));
            if option {
                seen_option = true;
                p.recursive |= facts.recursive.iter().any(|e| scan::flag_matches(e, t));
                p.forced |= facts.forced.iter().any(|e| scan::flag_matches(e, t));
                if !facts.forced.is_empty() && t.starts_with("--") && t.len() > 2 {
                    // GNU reads a long option by any unique prefix (`--recur`, `--forc`); one
                    // the table does not list may force or recurse, for the danger gate.
                    let name = t.split('=').next().unwrap_or(t);
                    let rec = facts.recursive.iter().any(|e| e.starts_with(name));
                    p.recursive |= rec;
                    p.forced |= !rec;
                }
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
    /// Names with several literal values (a pwsh list, a loop over a literal list): a target
    /// that uses one is judged once per value.
    multi: Vec<Assigned>,
    home: Option<PathBuf>,
    repo: Option<Result<Option<PathBuf>, TimedOut>>,
}

/// How a delete treats one target.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct How {
    pub recursive: bool,
    pub forced: bool,
    pub contents: bool,
    /// The program deletes through a link inside the tree (`DeleteFacts::follows_links`).
    pub follows_links: bool,
}

impl<'a> Scene<'a> {
    pub fn new(ctx: &'a Ctx<'a>) -> Scene<'a> {
        let mut env = ctx.input.env.clone();
        let input = ctx.input;
        let multi = resolve_assigned(&mut env, ctx.script, input.command, input.shell, input.os);
        Scene {
            ctx,
            env,
            multi,
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
        loc.read_text(input.command);
        loc.use_disk(self.ctx.fs, self.ctx.deadline, self.first_change());
        loc
    }

    /// The offset of the first command that may delete or discard data: a delete the guard
    /// reads, a .NET delete, or any command whose text the raw scan matches as destructive.
    fn first_change(&self) -> Option<usize> {
        let input = self.ctx.input;
        let (shell, os, command) = (input.shell, input.os, input.command);
        let mut first: Option<usize> = None;
        any_node(self.ctx.script, &mut |n| {
            let at = match n {
                Node::Cmd { cmd, .. } => {
                    let family = matches!(
                        read_call(cmd, false, shell, os),
                        Read::Call(call, prog) if in_family(&call, prog, shell, os)
                    );
                    (family || unread_hits(cmd, command)).then_some(cmd.span.start)
                }
                Node::Method(m) => method_row(m).map(|_| m.span.start),
            };
            if let Some(a) = at {
                first = Some(first.map_or(a, |f| f.min(a)));
            }
            false
        });
        first
    }

    fn os(&self) -> Os {
        self.ctx.input.os
    }

    /// The temp folder of the hook's environment as the check sees it: `TEMP` on Windows (the
    /// folder Git Bash's `/tmp` maps to), `/tmp` on POSIX.
    fn env_temp(&self) -> Option<PathBuf> {
        let env = &self.ctx.input.env;
        match self.os() {
            Os::Posix => Some(PathBuf::from("/tmp")),
            Os::Windows => env
                .get("TEMP")
                .or_else(|| env.get("env:TEMP"))
                .map(PathBuf::from),
        }
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
    /// On a network or device path only the lexical match runs: no file-system call there
    /// (Ruling 114(f)).
    pub fn critical(&mut self, p: &Path, contents: bool) -> Result<Option<&'static str>, TimedOut> {
        let cfg = self.ctx.cfg;
        // The lexical match first, so it never waits on the repo lookup. Deleting inside the
        // repo root stays exempt (a protected path inside it makes it an ancestor of one);
        // when the lookup that tells times out, the lexical reason stands.
        if let Some(reason) =
            resolve::critical_reason(p, None, self.home.as_deref(), &cfg.protected)
        {
            let inside_root =
                contents && matches!(self.repo(), Ok(Some(r)) if self.key(&r) == self.key(p));
            return Ok((!inside_root).then_some(reason));
        }
        let repo = self.repo()?;
        let (home, protected) = (self.home.as_deref(), &cfg.protected);
        let reason = if resolve::is_network_or_device(p, self.os()) {
            resolve::critical_reason(p, repo.as_deref(), home, protected)
        } else {
            resolve::critical_by_identity(
                p,
                repo.as_deref(),
                home,
                protected,
                self.ctx.fs,
                self.ctx.deadline,
            )?
        };
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
        // The critical match first: a share or device spelling of a protected folder stays
        // critical. Past it, such a path is not read at all.
        match self.critical(p, how.contents) {
            Err(TimedOut) => return Some(self.lookup_timeout(how, span, shown)),
            Ok(Some(reason)) => return Some(critical(p, reason, span)),
            Ok(None) => {}
        }
        if resolve::is_network_or_device(p, self.os()) {
            return Some(self.unknown_location(
                span,
                shown,
                "it is a network or device path, which the guard does not read",
            ));
        }
        let os = self.os();
        let key = self.key(p);
        let mut placed = false;
        let cfg = self.ctx.cfg;
        // The default root, the analysing process's temp folder, stands for the temp folder of
        // the environment the check sees (the same folder in the hook; a synthetic one in the
        // bench).
        let process_temp = std::env::temp_dir();
        let env_temp = self.env_temp();
        let roots: Vec<PathBuf> = cfg
            .allowed_roots
            .iter()
            .map(|r| match &env_temp {
                Some(t) if *r == process_temp => t.clone(),
                _ => r.clone(),
            })
            .chain(cfg.scratch_dir.clone())
            .collect();
        for root in &roots {
            let rk = self.key(root);
            if rk == key && !how.contents {
                return Some(finding(
                    DELETE_ALLOWED_ROOT,
                    Level::Warn,
                    format!(
                        "this deletes `{}`, an allowed scratch or temp root itself, with every other session's files in it",
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
                    let inside =
                        (key != pk && is_within(&key, &pk, os)) || (how.contents && key == pk);
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
                    let mut f = through_link(p, &first, shell, span);
                    if how.follows_links {
                        // `robocopy /MIR` empties a junction's target (probed, also with /XJ).
                        f.level = Level::Danger;
                        f.message = format!(
                            "this empties `{}` and follows the link `{}` inside it, deleting the files of its target outside the tree",
                            p.display(),
                            first.display()
                        );
                    }
                    Some(f)
                }
                WalkResult::Unreadable(at) => Some(finding(
                    WALK_UNREADABLE,
                    Level::Danger,
                    format!(
                        "this deletes the tree `{}`, and the guard cannot read `{}` inside it to tell whether a link there leads outside it",
                        p.display(),
                        at.display()
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
        warn(
            WALK_TIMEOUT,
            format!("the guard ran out of time and could not read what `{shown}` deletes"),
            None,
            span,
        )
    }

    /// The deadline passed before the guard could tell whether a target is the repo root, its
    /// `.git` or the same folder as a protected one: danger for a recursive or forced delete
    /// (it may take one of them), warn otherwise.
    fn lookup_timeout(&self, how: How, span: Span, shown: &str) -> Finding {
        if !(how.recursive || how.forced) {
            return self.timeout(span, shown);
        }
        finding(
            WALK_TIMEOUT,
            Level::Danger,
            format!(
                "the guard ran out of time before it could tell whether `{shown}` is the repo root, its .git or a protected folder, which this recursive or forced delete would take"
            ),
            CONFIRM_FIX.to_string(),
            span,
        )
    }

    pub fn dynamic(&self, span: Span, shown: &str, why: &str) -> Finding {
        warn(
            DYNAMIC_TARGET,
            format!("the guard could not read what `{shown}` deletes: {why}"),
            Some("write the path literally so the guard can check it".to_string()),
            span,
        )
    }

    pub fn unknown_location(&self, span: Span, shown: &str, why: &str) -> Finding {
        warn(
            DELETE_UNKNOWN_LOCATION,
            format!("the guard could not read which folder `{shown}` deletes: {why}"),
            Some("use the full path of the folder so the guard can check it".to_string()),
            span,
        )
    }

    /// The text `word` names: `~` (and a provider path's leading `~` in pwsh) as the home
    /// folder of the hook's environment, which `critical` compares with; each variable as the
    /// env holds it. With `empty`, a variable or substitution the guard cannot read is empty;
    /// without, such a word has no text.
    fn text_of(&self, word: &Word, by: DeleteBy, empty: bool) -> Option<String> {
        let home = self.home.as_ref().map(|h| h.to_string_lossy().into_owned());
        let mut text = String::new();
        for part in &word.parts {
            match part {
                WordPart::Literal(s) | WordPart::Glob(s) => text.push_str(s),
                WordPart::Var(name) => match self.env.get(name) {
                    Some(v) => text.push_str(v),
                    // `${X:?}` stops the command when X is empty or unset: it never reads empty.
                    None if empty && stops_when_empty(name) => return None,
                    None if empty => {}
                    None => return None,
                },
                WordPart::Tilde => text.push_str(home.as_deref()?),
                WordPart::Subst(_) | WordPart::Block(_) if empty => {}
                WordPart::Subst(_) | WordPart::Block(_) | WordPart::ListSep => return None,
            }
        }
        let tilde = text == "~" || text.starts_with("~\\") || text.starts_with("~/");
        if is_pwsh(self.ctx.input.shell) && by == DeleteBy::Provider && tilde {
            text = format!("{}{}", home?, &text[1..]);
        }
        Some(text)
    }

    /// Ruling 125: a glob over the literal contents of a protected folder (`rm -rf ~/*`, `cd / &&
    /// rm -rf *`) is critical like the folder; over the repo root's it is danger
    /// (`delete-repo-contents`), unless the glob takes `.git` too (a Bash step starting with
    /// `.`, a PowerShell wildcard with `-Force`). `None` when the word is no such glob or its
    /// folder is none of them: it is judged path by path.
    fn glob_contents(
        &mut self,
        word: &Word,
        loc: &Location,
        by: DeleteBy,
        how: How,
        span: Span,
    ) -> Option<Finding> {
        let shell = self.ctx.input.shell;
        // Bash expands only an unquoted glob; PowerShell's -Path reads any `*` as one.
        if !is_pwsh(shell) && !matches!(word.parts.last(), Some(WordPart::Glob(_))) {
            return None;
        }
        let text = self.text_of(word, by, false)?;
        let (folder, step) = match text.rfind(['/', '\\']) {
            Some(i) => (text[..=i].to_string(), text[i + 1..].to_string()),
            None => (".".to_string(), text.clone()),
        };
        if !is_all_glob(&step) {
            return None;
        }
        if self.msys_system(&folder) {
            return Some(critical_contents(Path::new(&folder), SYSTEM_FOLDER, span));
        }
        // A relative glob after a Git Bash `cd` to an MSYS system folder (`cd /usr && rm -rf *`).
        if let Some(dir) = loc
            .msys_folder()
            .filter(|_| !(Path::new(&folder).is_absolute() || folder.starts_with(['/', '\\'])))
        {
            let inside = format!("{}/{}", dir.trim_end_matches('/'), folder);
            if self.msys_system(&inside) {
                return Some(critical_contents(Path::new(&inside), SYSTEM_FOLDER, span));
            }
        }
        let as_word = Word {
            parts: vec![WordPart::Literal(folder)],
            span: word.span,
            quote: Quote::Single,
        };
        let Target::Paths(paths) =
            resolve::target(&as_word, loc, &self.env, by, self.ctx.fs, self.ctx.deadline)
        else {
            return None;
        };
        let cfg = self.ctx.cfg;
        for p in paths {
            let home = self.home.clone();
            if let Some(reason) =
                resolve::critical_reason(&p, None, home.as_deref(), &cfg.protected)
            {
                return Some(critical_contents(&p, reason, span));
            }
            // A folder above the repo root (`../*` from it) is judged path by path, as the
            // delete of each match; a lookup that times out may have been the root.
            let root = match self.repo() {
                Ok(Some(root)) => root,
                Ok(None) => continue,
                Err(TimedOut) => return Some(self.lookup_timeout(how, span, &text)),
            };
            if self.key(&root) == self.key(&p) {
                // A PowerShell wildcard leaves the hidden `.git` without -Force (Ruling 127).
                let takes_git = (is_pwsh(shell) && how.forced) || step.starts_with('.');
                if !takes_git {
                    return Some(repo_contents(&p, span));
                }
                let git = p.join(".git");
                let reason =
                    resolve::critical_reason(&git, Some(&root), home.as_deref(), &cfg.protected)?;
                return Some(critical(&git, reason, span));
            }
        }
        None
    }

    /// In Git Bash, a rooted path with no drive under a system folder of the MSYS tree
    /// (`/usr`, `/etc/`): the guard's list of POSIX system folders.
    fn msys_system(&self, text: &str) -> bool {
        self.ctx.input.shell == Shell::Bash(crate::BashProfile::GitBash)
            && self.os() == Os::Windows
            && resolve::is_msys_system_path(text)
    }

    /// In Git Bash, `/c` or `/c/rest`: the Windows path `C:\rest` it names.
    fn msys_drive_path(&self, text: &str) -> Option<PathBuf> {
        if self.ctx.input.shell != Shell::Bash(crate::BashProfile::GitBash)
            || self.os() != Os::Windows
        {
            return None;
        }
        let rest = text.strip_prefix('/')?;
        let mut chars = rest.chars();
        let letter = chars.next().filter(char::is_ascii_alphabetic)?;
        let after = chars.as_str();
        if !(after.is_empty() || after.starts_with('/')) {
            return None;
        }
        Some(PathBuf::from(format!(
            "{}:\\{}",
            letter.to_ascii_uppercase(),
            after.trim_start_matches('/').replace('/', "\\")
        )))
    }

    /// Danger (a) of Ruling 122: a recursive or forced delete of `word` that, with every
    /// variable or substitution the guard cannot read taken as empty, names a protected
    /// location or its direct contents (`rm -rf "$X/"`, `rm -rf $X/*`, `Remove-Item "$x\*"`).
    fn empty_expansion(
        &mut self,
        word: &Word,
        loc: &Location,
        by: DeleteBy,
        how: How,
        span: Span,
        shown: &str,
    ) -> Option<Finding> {
        if !(how.recursive || how.forced) {
            return None;
        }
        let text = self.text_of(word, by, true)?;
        // The last step all glob (`*`, `.*`): the delete takes the folder's direct contents.
        let (folder, contents) = match text.rfind(['/', '\\']) {
            Some(i) if is_all_glob(&text[i + 1..]) => (text[..=i].to_string(), true),
            None if is_all_glob(&text) => (".".to_string(), true),
            _ => (text.clone(), false),
        };
        if folder.trim().is_empty() {
            return None;
        }
        // An absolute text is judged as written (a Git Bash `/x` may map anywhere); a relative
        // one from the location the delete runs in.
        // A repo lookup that runs out of time leaves a match that needs it unknown: danger.
        let hit = if Path::new(&folder).is_absolute() || folder.starts_with(['/', '\\']) {
            let p = PathBuf::from(&folder);
            let home = self.home.clone();
            let protected = &self.ctx.cfg.protected;
            let lexical = resolve::critical_reason(&p, None, home.as_deref(), protected)
                .or_else(|| self.msys_system(&folder).then_some(SYSTEM_FOLDER));
            let reason = match lexical {
                Some(r) => Some(r),
                None => match self.repo() {
                    Ok(repo) => {
                        resolve::critical_reason(&p, repo.as_deref(), home.as_deref(), protected)
                    }
                    Err(TimedOut) => return Some(self.lookup_timeout(how, span, shown)),
                },
            };
            reason.map(|r| (p, r))
        } else {
            let as_word = Word {
                parts: vec![WordPart::Literal(folder)],
                span: word.span,
                quote: Quote::Single,
            };
            match resolve::target(&as_word, loc, &self.env, by, self.ctx.fs, self.ctx.deadline) {
                Target::Paths(paths) => {
                    let mut hit = None;
                    for p in paths {
                        match self.critical(&p, false) {
                            Ok(Some(r)) => {
                                hit = Some((p, r));
                                break;
                            }
                            Ok(None) => {}
                            Err(TimedOut) => return Some(self.lookup_timeout(how, span, shown)),
                        }
                    }
                    hit
                }
                _ => None,
            }
        };
        let (p, reason) = hit?;
        let what = if contents {
            format!("everything inside `{}`, the {reason}", p.display())
        } else {
            format!("`{}`, the {reason}", p.display())
        };
        let fix = if is_pwsh(self.ctx.input.shell) {
            "test the variable first, for example `if ($x) { Remove-Item -Recurse -Force \"$x\\build\" }`"
        } else {
            "write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf \"${X:?}/build\"`"
        };
        Some(finding(
            DELETE_EMPTY_EXPANSION,
            Level::Danger,
            format!("if the variable or substitution in `{shown}` is empty, this deletes {what}"),
            format!("{fix}; or, {CONFIRM_FIX}"),
            span,
        ))
    }

    /// The finding for code the guard does not read whose text names a destructive command:
    /// danger when its words hold a literal protected location (Ruling 122 (b)), else warn.
    fn opaque(&mut self, c: &SimpleCommand) -> Finding {
        let command = self.ctx.input.command;
        let text = command.get(c.span.start..c.span.end).unwrap_or_default();
        let shown: String = text.chars().take(80).collect();
        // Only the words of the destructive commands themselves: a `cd` to the repo root
        // elsewhere in the body names no target.
        let words: Vec<String> = scan::hits(scan::table(), text)
            .into_iter()
            .filter(|h| h.kind != scan::Kind::Unreadable)
            .filter_map(|h| Some((h.kind, text.get(h.span.start..h.span.end)?)))
            .flat_map(|(kind, t)| target_words(t, kind))
            .map(str::to_string)
            .collect();
        let protected = words.iter().find_map(|w| self.protected_word(w));
        match protected {
            Some((p, reason)) => finding(
                OPAQUE_DESTRUCTIVE,
                Level::Danger,
                format!(
                    "the guard cannot read what `{shown}` runs; its text names a command that deletes or discards data, and `{p}`, the {reason}"
                ),
                format!("run the delete as a plain command of its own, or, {CONFIRM_FIX}"),
                c.span,
            ),
            None => warn(
                OPAQUE_DESTRUCTIVE,
                format!(
                    "the guard could not read what `{shown}` runs, and its text names a command that deletes or discards data"
                ),
                Some(
                    "run the delete as a plain command of its own so the guard can check it"
                        .to_string(),
                ),
                c.span,
            ),
        }
    }

    /// A raw word that spells a protected location literally: an absolute path, `~` or `$HOME`
    /// for the home folder, `.git` from the repo root.
    fn protected_word(&mut self, w: &str) -> Option<(String, &'static str)> {
        let lower = w.to_ascii_lowercase();
        let home_spelling = matches!(
            lower.trim_end_matches(['/', '\\']),
            "~" | "$home" | "${home}" | "$env:userprofile" | "$env:home" | "%userprofile%"
        );
        if home_spelling {
            return self.home.clone().map(|_| (w.to_string(), "home folder"));
        }
        let git_spelling = lower == ".git" || lower == "./.git" || lower == ".\\.git";
        if self.msys_system(w) {
            return Some((w.to_string(), SYSTEM_FOLDER));
        }
        let path = if git_spelling {
            self.ctx.input.cwd.as_ref()?.join(".git")
        } else if let Some(drive) = self.msys_drive_path(w) {
            drive
        } else if Path::new(w).is_absolute() || w.starts_with(['/', '\\']) {
            PathBuf::from(w)
        } else {
            return None;
        };
        let repo = match self.repo() {
            Ok(repo) => repo,
            // The lookup that would place `.git` ran out of time: it may be the repo's.
            Err(TimedOut) if git_spelling => return Some((w.to_string(), "repo's .git")),
            Err(TimedOut) => None,
        };
        let reason = resolve::critical_reason(
            &path,
            repo.as_deref(),
            self.home.as_deref(),
            &self.ctx.cfg.protected,
        )?;
        Some((w.to_string(), reason))
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
            let found = match self.multi_in(&el) {
                // Once per value, the highest level winning.
                Some(a) => {
                    let mut w = None;
                    for v in &a.values {
                        let one = with_value(&el, &a.name, v, is_pwsh(self.ctx.input.shell));
                        w = max_finding(w, self.judge_element(&one, loc, by, how, span));
                    }
                    w
                }
                None => self.judge_element(&el, loc, by, how, span),
            };
            worst = max_finding(worst, found);
        }
        worst
    }

    /// The first name with several values that `w` uses where it holds them.
    fn multi_in(&self, w: &Word) -> Option<Assigned> {
        let fold = is_pwsh(self.ctx.input.shell);
        let same = |a: &str, b: &str| {
            let (a, b) = (a.trim_start_matches('$'), b.trim_start_matches('$'));
            if fold {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        };
        w.parts.iter().find_map(|p| match p {
            WordPart::Var(n) => self
                .multi
                .iter()
                .find(|a| same(&a.name, n) && a.holds_at(w.span))
                .cloned(),
            _ => None,
        })
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
        if let Some(text) = literal(word) {
            let reason = resolve::critical_reason(Path::new(&text), None, None, &[])
                .or_else(|| self.msys_system(&text).then_some(SYSTEM_FOLDER));
            if let Some(reason) = reason {
                return Some(critical(Path::new(&text), reason, span));
            }
        }
        if let Some(found) = self.glob_contents(word, loc, by, how, span) {
            return Some(found);
        }
        let target = resolve::target_how(
            word,
            loc,
            &self.env,
            by,
            self.ctx.fs,
            self.ctx.deadline,
            how.recursive || how.contents,
        );
        match target {
            Target::Paths(paths) => {
                let mut worst = None;
                for p in paths {
                    let found = self.judge_path(&p, how, span, &shown);
                    worst = max_finding(worst, found);
                }
                worst
            }
            Target::Dynamic(_) | Target::UnknownLocation(UnknownKind::Dynamic) => self
                .empty_expansion(word, loc, by, how, span, &shown)
                .or_else(|| {
                    Some(self.dynamic(
                        span,
                        &shown,
                        "it holds a variable or a substitution the command sets or the guard cannot read",
                    ))
                }),
            Target::UnknownLocation(UnknownKind::MayBeCritical) => Some(self.unknown_location(
                span,
                &shown,
                "the command moves to a folder the guard cannot follow, defines a function or alias, maps a drive, runs a script or makes a link before it",
            )),
            // `Env:X`, the registry or another built-in drive that is no file system, which the
            // command does not visibly remap: no file is deleted (Ruling 122).
            Target::DriveUnproven { .. }
                if word
                    .static_value(&self.env)
                    .is_some_and(|t| resolve::on_non_fs_drive(&t)) =>
            {
                None
            }
            Target::DriveUnproven { drive, .. } => Some(self.unknown_location(
                span,
                &shown,
                &format!("nothing shows the drive `{drive}:` is the file system the guard sees"),
            )),
            Target::NotAFile | Target::SessionCommand => None,
            // A target the deadline left unread may be any of the protected folders.
            Target::Timeout => Some(self.lookup_timeout(how, span, &shown)),
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
            return Some(self.dynamic(
                span,
                &shown,
                "it deletes the names it reads from its input",
            ));
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
            recursive: picked.recursive,
            forced: picked.forced,
            follows_links: facts.follows_links,
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
            forced: false,
            contents: false,
            follows_links: false,
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

/// A warn finding: it blocks nothing, so the allow marker plays no part in its Fix line.
pub(crate) fn warn(
    rule: &'static str,
    message: String,
    fix: Option<String>,
    span: Span,
) -> Finding {
    Finding {
        rule,
        level: Level::Warn,
        message,
        fix,
        span,
    }
}

/// `w` with each use of the variable `name` written as `value`.
fn with_value(w: &Word, name: &str, value: &str, fold: bool) -> Word {
    let name = name.trim_start_matches('$');
    let parts = w
        .parts
        .iter()
        .map(|p| match p {
            WordPart::Var(n)
                if (fold && n.trim_start_matches('$').eq_ignore_ascii_case(name))
                    || n.trim_start_matches('$') == name =>
            {
                WordPart::Literal(value.to_string())
            }
            other => other.clone(),
        })
        .collect();
    Word {
        parts,
        span: w.span,
        quote: w.quote,
    }
}

/// A Bash expansion `${NAME:?…}` as the IR keeps it (`NAME:?…`): the operator right after the
/// name, so a default that holds `:?` (`${X:-a:?b}`) is none.
fn stops_when_empty(var: &str) -> bool {
    var.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_')
        .starts_with(":?")
}

/// A path step made only of glob stars and dots (`*`, `.*`, `*.*`).
fn is_all_glob(step: &str) -> bool {
    step.contains('*') && step.chars().all(|c| c == '*' || c == '.')
}

pub(crate) fn critical(p: &Path, reason: &str, span: Span) -> Finding {
    finding(
        DELETE_CRITICAL,
        Level::Critical,
        format!(
            "deleting `{}` is blocked: it is the {reason}, and the allow marker cannot confirm it",
            p.display()
        ),
        critical_fix(p, reason),
        span,
    )
}

/// The Fix of a critical delete: the folders inside `p`, unless every path below it is critical
/// too (a system folder), where only the user can run it.
fn critical_fix(p: &Path, reason: &str) -> String {
    if reason == SYSTEM_FOLDER {
        return "do not delete in a system folder; if it must go, ask the user to run the command themselves".to_string();
    }
    format!(
        "delete only the folders inside it you mean, each by its full path, for example `{}`",
        p.join("<name>").display()
    )
}

/// A glob over the contents of `p`, a protected folder (Ruling 125).
fn critical_contents(p: &Path, reason: &str, span: Span) -> Finding {
    finding(
        DELETE_CRITICAL,
        Level::Critical,
        format!(
            "deleting everything inside `{}` is blocked: it is the {reason}, and the allow marker cannot confirm it",
            p.display()
        ),
        critical_fix(p, reason),
        span,
    )
}

/// A glob over the repo root's contents that leaves `.git` (Ruling 125).
fn repo_contents(p: &Path, span: Span) -> Finding {
    finding(
        DELETE_REPO_CONTENTS,
        Level::Danger,
        format!(
            "this deletes everything in the repo root `{}` but its .git: the whole working tree, uncommitted and untracked files included",
            p.display()
        ),
        format!(
            "name each folder you mean in place of the glob, for example `{}`; or, {CONFIRM_FIX}",
            p.join("build").display()
        ),
        span,
    )
}

fn outside(p: &Path, is_cwd: bool, span: Span) -> Finding {
    let message = if is_cwd {
        format!(
            "this deletes `{}`, the working folder itself (outside any repo), with everything the session works in",
            p.display()
        )
    } else {
        format!(
            "this deletes `{}`, which is outside the project and outside every allowed scratch or temp root",
            p.display()
        )
    };
    warn(DELETE_OUTSIDE_PROJECT, message, None, span)
}

fn through_link(p: &Path, link: &Path, shell: Shell, span: Span) -> Finding {
    let unlink = if is_pwsh(shell) {
        format!("[IO.Directory]::Delete('{}')", link.display())
    } else {
        let shown = link.display().to_string().replace('\\', "/");
        format!("rm '{shown}'")
    };
    warn(
        DELETE_THROUGH_LINK,
        format!(
            "this deletes `{}`, which holds or lies below the link `{}`; a tool that follows links would delete files outside the tree",
            p.display(),
            link.display()
        ),
        Some(format!(
            "remove the link itself first with `{unlink}` in a command of its own"
        )),
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
                pred(Node::Cmd {
                    cmd: c,
                    piped: k > 0,
                }) || cmd_words(c).any(|w| any_in_word(w, pred))
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
                        f(
                            Node::Cmd {
                                cmd: c,
                                piped: k > 0,
                            },
                            loc,
                        );
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
