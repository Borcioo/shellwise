//! `wait-loop-unbounded`: a loop that waits for something outside it and that nothing bounds. It
//! polls (its body waits) or its condition is always true, and no counter, deadline or `timeout`
//! ends it: when what it waits for never comes, it runs forever (a worker's `until grep -q <line>
//! <log>; do sleep 15; done` ran orphaned for nine hours).
//!
//! What the loop is comes from its header (`LoopHead`): a loop over items ends with its items, a
//! counted `for` with a condition ends by its counter. The commands are data: a `[[program]]`
//! row's `loop_role` says whether it waits, and `[loops]` holds the keywords and clocks a bound
//! is read from. This file holds no program or option name.
//!
//! A bound is visible when the loop's condition, or a test guarding a `break`/`exit`/`return` in
//! its body, compares a clock or a counter (a variable whose new value reads its old one); or when
//! the loop runs under a wrapper that bounds its wait (`timeout 600 bash -c '…'`). A loop with no wait whose condition
//! can fail (`while read line`) is no wait loop. A loop whose body runs a command the guard cannot
//! read (a dynamic name, `eval`) is not judged: that command may end it. PowerShell keeps no
//! `break` in the IR, so its guards are the `if` statements whose text holds an exit word.

use super::{Ctx, Rule};
use crate::ir::{
    ChainOp, Elem, LoopHead, MethodCall, Pipeline, Redirect, Script, SimpleCommand, Stmt, Word,
    WordPart,
};
use crate::level::{Finding, Level, Span};
use crate::parse::bash;
use crate::programs::{self, Kind, Program};
use crate::{BashProfile, Os, Shell};

pub const WAIT_LOOP_UNBOUNDED: &str = "wait-loop-unbounded";
pub const FOLLOW_UNBOUNDED: &str = "follow-unbounded";

/// The `extra` keys of a program row this rule reads.
const ROLE: &str = "loop_role";
const WAIT_WHEN: &str = "loop_wait_when";
const WAIT_MS: &str = "loop_wait_ms";
const WAIT_IN_MS: &str = "loop_wait_in_ms";
const WAIT_UNITS: &str = "loop_wait_units";
const READS_INPUT: &str = "loop_reads_input";
const SKIPS_ROUND: &str = "loop_skips_round";
const BODY: &str = "loop_body";
const BOUNDS: &str = "bounds_wait";
const DURATION_SUFFIXES: &str = "duration_suffixes";
const FOLLOW: &str = "follow";
const FOLLOW_WHEN: &str = "follow_when";
const FOLLOW_SUB: &str = "follow_sub";
const FOLLOW_FIX: &str = "follow_fix";
const FOLLOW_JOB: &str = "follow_job";
const FOLLOW_FIX_LOCALS: &str = "follow_fix_locals";
const FOLLOW_FIX_SCOPES: &str = "follow_fix_scopes";
const FOLLOW_FIX_SETS: &str = "follow_fix_sets";
const FOLLOW_FIX_SENTENCE: &str = "follow_fix_sentence";
const FOLLOW_FIX_WRAPPERS: &str = "follow_fix_wrappers";
const FOLLOW_FIX_LOOKUP: &str = "follow_fix_lookup";
const FOLLOW_FIX_LOOKUP_VARS: &str = "follow_fix_lookup_vars";
const FOLLOW_FIX_DURATION: &str = "follow_fix_duration";
/// The `extra` keys of a wrapper row that runs only shell builtins, and of one that is a builtin.
const BUILTINS_ONLY: &str = "builtins_only";
const SHELL_BUILTIN: &str = "shell_builtin";
const LOOP_JOIN: &str = "loop_join";
const INTEGER_WHEN: &str = "loop_integer_when";
/// The `loop_join` values.
const JOIN_AND: &str = "and";
const JOIN_OR: &str = "or";
const JOB_TIMEOUT_WHEN: &str = "job_timeout_when";
/// The placeholders of a `follow_fix`.
const COMMAND: &str = "<command>";
const PIPELINE: &str = "<pipeline>";
const JOB: &str = "<job>";
/// Why a follow Fix is a sentence (Ruling 148).
const IN_CHILD: &str = "the follow runs in a child shell";
const NESTED: &str = "the follow runs inside another statement or an expression: an `if`, a function, a loop, a block, an assignment or a substitution";
const IN_STATEMENT: &str = "the follow pipeline is part of a longer statement";
const SETS_VARIABLE: &str =
    "the pipeline assigns a variable or names its scope, which `$using:` cannot pass";
const SET_LATER: &str = "a variable it reads is assigned only after it";
const UNDER_WRAPPER: &str = "the follow runs under a wrapper the bound was not shown to run, or under a shell builtin it cannot run";
const UNDER_BUILTINS_ONLY: &str = "the follow runs under a wrapper that runs only shell builtins";
const SETS_LOOKUP: &str =
    "an assignment in front of the follow sets where the bound itself is looked up";
/// The `loop_role` of a command that pauses.
const WAIT: &str = "wait";

/// How long the loop in a Fix line may wait at most, in seconds: the longest call of an agent
/// host's shell tool.
const FIX_BUDGET_SECS: f64 = 600.0;

/// Child-shell bodies read inside each other at most this deep.
const MAX_DEPTH: usize = 4;

pub struct WaitLoopRule;

impl Rule for WaitLoopRule {
    fn id(&self) -> &'static str {
        WAIT_LOOP_UNBOUNDED
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let shell = ctx.input.shell;
        Walk {
            src: ctx.input.command,
            shell,
            os: ctx.input.os,
            depth: 0,
            out,
            sites: &mut Vec::new(),
            ints: integers(&ctx.script.stmts, shell, ctx.input.os),
            outer: None,
            mode: Mode::Loops,
            root: ctx.script,
            job_timeout: Some(false),
            command: ctx.input.command,
            in_loop: false,
        }
        .script(ctx.script, false);
    }
}

/// `follow-unbounded`: a command that follows a file or a stream (`tail -f`, `Get-Content
/// -Wait`, `watch`, `kubectl logs -f`) with no time bound: no `timeout`, no job waited for with a
/// timeout. A later stage that waits for a line (`| grep -m1`) is no bound. Warn: it may be meant
/// to run in the background.
pub struct FollowRule;

impl Rule for FollowRule {
    fn id(&self) -> &'static str {
        FOLLOW_UNBOUNDED
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut sites = Vec::new();
        Walk {
            src: ctx.input.command,
            shell: ctx.input.shell,
            os: ctx.input.os,
            depth: 0,
            out,
            sites: &mut sites,
            ints: Vec::new(),
            outer: None,
            mode: Mode::Follow,
            root: ctx.script,
            job_timeout: None,
            command: ctx.input.command,
            in_loop: false,
        }
        .script(ctx.script, false);
        follow_fixes(ctx.input.command, out, &sites);
    }
}

/// A follow finding and how its Fix replaces the follow in the command.
struct Site {
    /// The finding's index in the output.
    at: usize,
    row: &'static Program,
    /// The text that replaces the follow in place, or why none can.
    edit: Result<(Span, String), NoCommand>,
}

/// Why a follow is not replaced in place, and the sentence's head when it names this follow's
/// own bounded form (else the row's sentence).
struct NoCommand {
    why: &'static str,
    head: Option<String>,
}

impl From<&'static str> for NoCommand {
    fn from(why: &'static str) -> Self {
        NoCommand { why, head: None }
    }
}

/// Every follow finding's Fix (Ruling 148): the whole command with each follow replaced in place,
/// the same text on each finding, so a pasted Fix follows nothing without end; when one follow
/// cannot be replaced, every finding gets a sentence and no command.
fn follow_fixes(command: &str, out: &mut [Finding], sites: &[Site]) {
    let mut edits: Vec<(Span, &str)> = Vec::new();
    for s in sites {
        if let Ok((span, text)) = &s.edit
            && !edits.iter().any(|(e, _)| e == span)
        {
            edits.push((*span, text));
        }
    }
    // The replaced texts are the command's own statements (Bash: their follow commands), which
    // never overlap; a PowerShell pipeline with two follows is replaced once. Right to left, so
    // each span still points at its text.
    edits.sort_by_key(|(s, _)| std::cmp::Reverse(s.start));
    let mut text = command.to_string();
    for (span, t) in &edits {
        text.replace_range(span.start..span.end, t);
    }
    // Every finding gives the first reason's sentence, so each carries the same text.
    let why = sites
        .iter()
        .find_map(|s| s.edit.as_ref().err().map(|e| (s.row, e)));
    let sentence = why.and_then(|(row, e)| follow_sentence(row, e));
    for s in sites {
        let Some(f) = out.get_mut(s.at) else { continue };
        f.fix = match why {
            None => Some(text.trim().to_string()),
            Some(_) => sentence.clone(),
        };
    }
}

/// A follow's sentence: the head that names its bounded form, else its row's
/// `follow_fix_sentence` or one made from its `follow_fix`, with why no command is built.
fn follow_sentence(row: &Program, e: &NoCommand) -> Option<String> {
    let text = |k: &str| row.extra.get(k).and_then(|v| v.as_str());
    let head = match (&e.head, text(FOLLOW_FIX_SENTENCE)) {
        (Some(h), _) => h.clone(),
        (None, Some(s)) => s.to_string(),
        (None, None) => format!("rewrite each follow as `{}` in place", text(FOLLOW_FIX)?),
    };
    Some(format!("{head} (no command is built: {})", e.why))
}

/// What a walk looks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Loops,
    Follow,
}

/// How a loop's condition reads, for its Fix line.
#[derive(Clone, Copy)]
struct Form {
    /// No condition can end it.
    always: bool,
    /// It ends when the condition holds.
    until: bool,
    /// The condition comes after the body (`do … while`).
    at_end: bool,
}

/// A loop's Fix: the command that replaces it, or a sentence when no command can be built.
enum Fixed {
    Command(String),
    Sentence(String),
}

struct Walk<'a, 'b> {
    mode: Mode,
    /// The text the spans of the script point into.
    src: &'a str,
    shell: Shell,
    os: Os,
    depth: usize,
    out: &'b mut Vec<Finding>,
    /// The follow findings, whose Fix is built once the whole command is read.
    sites: &'b mut Vec<Site>,
    /// The Bash names the script declares integers (`declare -i n`).
    ints: Vec<String>,
    /// The span of the command whose child-shell body this is: a finding points at it.
    outer: Option<Span>,
    /// The whole script the check reads.
    root: &'a Script,
    /// The command waits for a job with a timeout (`Wait-Job $j -Timeout 60`): a follow inside a
    /// job bounds that way (Ruling 137). Read from `root` once a job is met.
    job_timeout: Option<bool>,
    /// The whole command's text: a Fix's counter is a name it never uses.
    command: &'a str,
    /// The walk is inside a loop's body: a fixed loop's failure would not end that loop.
    in_loop: bool,
}

impl Walk<'_, '_> {
    /// Whether the command waits for a job with a timeout.
    fn job_bound(&mut self) -> bool {
        if let Some(b) = self.job_timeout {
            return b;
        }
        let (shell, os) = (self.shell, self.os);
        let b = commands(&self.root.stmts)
            .iter()
            .any(|c| waits_on_job_with_timeout(c, shell, os));
        self.job_timeout = Some(b);
        b
    }

    /// `bounded`: a wrapper around this script bounds its wait.
    fn script(&mut self, s: &Script, bounded: bool) {
        for st in &s.stmts {
            match st {
                Stmt::Pipeline(p) => self.pipeline(p, bounded),
                Stmt::Loop { body, span, head } => {
                    if !bounded && self.mode == Mode::Loops {
                        self.judge(body, *span, *head);
                    }
                    let outer = std::mem::replace(&mut self.in_loop, true);
                    self.script(body, bounded);
                    self.in_loop = outer;
                }
                Stmt::Cond { branches, .. } => {
                    for b in branches {
                        self.script(b, bounded);
                    }
                }
                Stmt::Func { body, .. } | Stmt::Block(body) => self.script(body, bounded),
            }
        }
    }

    fn pipeline(&mut self, p: &Pipeline, bounded: bool) {
        if self.mode == Mode::Follow {
            self.follows(p, bounded);
        }
        for elem in &p.elems {
            match elem {
                Elem::Cmd(c) => self.command(c, bounded),
                Elem::Method(m) => m.args.iter().for_each(|w| self.word(w, bounded)),
                Elem::Expr(w) => self.word(w, bounded),
            }
        }
    }

    fn word(&mut self, w: &Word, bounded: bool) {
        for part in &w.parts {
            if let WordPart::Subst(s) | WordPart::Block(s) = part {
                self.script(s, bounded);
            }
        }
    }

    fn command(&mut self, c: &SimpleCommand, bounded: bool) {
        let (shell, os) = (self.shell, self.os);
        // A wrapper that bounds the wait (`timeout`) as the outermost command bounds what it runs,
        // only with a duration that sets a limit: `timeout 0 bash -c 'tail -f x'` and
        // `timeout 0 bash -c 'while true; do sleep 1; done'` run without one.
        let bounded = bounded
            || (programs::lookup(&c.typed, shell, os).is_some_and(|w| flag(w, BOUNDS))
                && programs::wrapper_chain(c, shell, os)
                    .first()
                    .is_none_or(limits));
        // A job (`Start-Job { … }`) the command waits for with a timeout bounds its follow.
        // A script block first: the table is read only for a command that passes one.
        let bounded = bounded
            || (self.mode == Mode::Follow
                && c.args
                    .iter()
                    .any(|w| w.parts.iter().any(|p| matches!(p, WordPart::Block(_))))
                && named_row(c, shell, os).is_some_and(|p| flag(p, FOLLOW_JOB))
                && self.job_bound());
        for w in std::iter::once(&c.name).chain(&c.args) {
            self.word(w, bounded);
        }
        for r in &c.redirects {
            match r {
                Redirect::File { target, .. } => self.word(target, bounded),
                Redirect::Heredoc { body, .. } => self.word(body, bounded),
            }
        }
        for (_, w) in &c.assigns {
            self.word(w, bounded);
        }
        if self.depth < MAX_DEPTH {
            let inner = programs::strip_wrappers(c, shell, os);
            if let Some(body) = child_body(&inner, shell, os) {
                self.child(&body, c.span, bounded);
            }
        }
    }

    /// The body of a child Bash (`bash -c '…'`), read with the Bash parser.
    fn child(&mut self, body: &str, at: Span, bounded: bool) {
        let profile = match self.shell {
            Shell::Bash(p) => p,
            _ if self.os == Os::Windows => BashProfile::GitBash,
            _ => BashProfile::Posix,
        };
        let Ok(script) = bash::parse(body, profile) else {
            return;
        };
        Walk {
            src: body,
            shell: Shell::Bash(profile),
            os: self.os,
            depth: self.depth + 1,
            out: self.out,
            sites: self.sites,
            ints: integers(&script.stmts, Shell::Bash(profile), self.os),
            outer: Some(self.outer.unwrap_or(at)),
            mode: self.mode,
            root: self.root,
            job_timeout: Some(false),
            command: self.command,
            in_loop: self.in_loop,
        }
        .script(&script, bounded);
    }

    /// A follow command in `p` with no time bound: not under `timeout`, not in a job a `Wait-Job
    /// -Timeout` waits for. A later stage that waits for a line or a count (`| grep -m1`, `|
    /// head`) is no bound: it ends the follow only if the line comes (Ruling 137).
    fn follows(&mut self, p: &Pipeline, bounded: bool) {
        let (shell, os) = (self.shell, self.os);
        let cmds: Vec<&SimpleCommand> = p
            .elems
            .iter()
            .map(|e| match e {
                Elem::Cmd(c) => Some(c),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        if bounded {
            return;
        }
        for c in cmds {
            let Some(row) = follows(c, shell, os) else {
                continue;
            };
            // `timeout 60 tail -f log`, `nohup timeout 60 tail -f log`: a wrapper of this very
            // command, at any place in its chain, bounds it.
            if programs::wrapper_chain(c, shell, os).iter().any(limits) {
                continue;
            }
            let span = self.outer.unwrap_or(c.span);
            self.out.push(Finding {
                rule: FOLLOW_UNBOUNDED,
                level: Level::Warn,
                message: format!(
                    "`{}` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout",
                    c.typed
                ),
                fix: None,
                span,
            });
            if row.extra.contains_key(FOLLOW_FIX) {
                self.sites.push(Site {
                    at: self.out.len() - 1,
                    row,
                    edit: self.follow_edit(p, c, row),
                });
            }
        }
    }

    /// How the follow `c` in `p` is replaced in the command (Ruling 148), from its row's
    /// `follow_fix`: `<command>` is the follow command, put back in its pipeline so the later
    /// stages stay; `<pipeline>` is the whole pipeline, which then must be a statement of its own
    /// (the job is several). Only a follow among the command's own statements is replaced: in a
    /// child shell, a block, a function, a loop or a substitution the Fix is a sentence.
    fn follow_edit(
        &self,
        p: &Pipeline,
        c: &SimpleCommand,
        row: &Program,
    ) -> Result<(Span, String), NoCommand> {
        let template = row
            .extra
            .get(FOLLOW_FIX)
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if self.outer.is_some() {
            return Err(IN_CHILD.into());
        }
        // A statement of the command, or the first stage of one whose later stage is a compound
        // command (`tail -f log | while read l; do …; done`), which the lowering makes a block.
        let feeds = pipeline_extent(p)
            .and_then(|e| self.src.get(e.end..))
            .is_some_and(|t| {
                let t = t.trim_start_matches([' ', '\t']);
                t.starts_with('|') && !t.starts_with("||")
            });
        let top = self.root.stmts.iter().any(|s| match s {
            Stmt::Pipeline(q) => std::ptr::eq(q, p),
            Stmt::Block(b) => {
                feeds && matches!(b.stmts.first(), Some(Stmt::Pipeline(q)) if std::ptr::eq(q, p))
            }
            _ => false,
        });
        let Some(whole) = pipeline_extent(p).filter(|_| top) else {
            return Err(NESTED.into());
        };
        if !template.contains(PIPELINE) {
            // The bound goes right before the command's name, after its assignments and leading
            // redirects; around a wrapper only when the row says the bound runs that wrapper.
            let (shell, os) = (self.shell, self.os);
            let chain = programs::wrapper_chain(c, shell, os);
            // A bound with no limit (`timeout 0 tail`, Ruling 155): the bound's duration goes in
            // its place, so the bound is not doubled.
            if let (Some(word), Some(duration)) = (
                chain.iter().find_map(no_limit),
                row.extra.get(FOLLOW_FIX_DURATION).and_then(|v| v.as_str()),
            ) {
                return Ok((word.span, duration.to_string()));
            }
            let inner = programs::strip_wrappers(c, shell, os);
            let listed = strings(row, FOLLOW_FIX_WRAPPERS);
            // Every wrapper of the chain, not only the first, must be listed (`nohup nice tail`).
            let unlisted = std::iter::once(&c.name)
                .chain(&c.args)
                .filter(|w| w.span.start < inner.name.span.start)
                .filter_map(literal)
                .any(|n| {
                    programs::lookup(&n, shell, os).is_some_and(|p| p.is(Kind::Wrapper))
                        && !listed.contains(&n.as_str())
                });
            let under =
                unlisted || (inner.name.span != c.name.span && !listed.contains(&c.typed.as_str()));
            // A wrapper that runs only builtins fails in front of what is none (`builtin tail`,
            // `builtin nohup tail`); in front of a builtin wrapper it runs (`builtin command tail`).
            let builtins_only = (0..chain.len()).find(|&k| {
                flag(chain[k].row, BUILTINS_ONLY)
                    && chain
                        .get(k + 1)
                        .is_none_or(|next| !flag(next.row, SHELL_BUILTIN))
            });
            // An assignment in front (`PATH=/x tail`) applies to the bound too; an append
            // (`PATH+=:/x`) keeps the old value first. The parser also holds one after a wrapper
            // (`env PATH=/x tail`) as an assignment. Its word spans the whole `NAME=value`.
            let lookup = strings(row, FOLLOW_FIX_LOOKUP_VARS);
            let sets_lookup = c.assigns.iter().any(|(n, w)| {
                w.span.start < c.name.span.start
                    && lookup.contains(&n.as_str())
                    && !self
                        .slice(w.span)
                        .get(n.len()..)
                        .is_some_and(|t| t.starts_with("+="))
            });
            let end = command_extent(c).end;
            // The bound goes on the name's own line: a line continuation before it stays.
            let at = Span {
                start: self.code_from(c.name.span.start),
                end,
            };
            if !(under || builtins_only.is_some() || sets_lookup) {
                return Ok((at, template.replace(COMMAND, self.slice(at).trim())));
            }
            // The sentence names this follow's bounded form: the bound right before the program,
            // after the wrappers (without the one that fails); an assignment that sets the lookup
            // moves behind the bound (`follow_fix_lookup`).
            let word = |span: Span| {
                self.slice(Span {
                    start: self.code_from(span.start),
                    end: span.end,
                })
                .trim()
            };
            let program = self
                .slice(Span {
                    start: self.code_from(inner.name.span.start),
                    end,
                })
                .trim();
            let mut wrappers = String::new();
            for (k, w) in chain.iter().enumerate() {
                let next = chain
                    .get(k + 1)
                    .map_or(inner.name.span.start, |n| n.name.start);
                if builtins_only != Some(k) {
                    wrappers.push_str(self.slice(Span {
                        start: self.code_from(w.name.start),
                        end: self.code_from(next),
                    }));
                }
            }
            // The text in front of the name: its assignments and leading redirects. The Bash
            // lowering gives a command with a redirect the span of its name only (`2>&1 sudo
            // tail`); the earliest of that span and its redirects' spans starts at the command's
            // first word, assignments included (rows `fu-bash-fix-…-redirect-…`).
            let front_start = c
                .redirects
                .iter()
                .map(|r| match r {
                    Redirect::File { span, .. } | Redirect::Heredoc { span, .. } => span.start,
                })
                .fold(c.span.start, usize::min);
            let front = self.slice(Span {
                start: front_start,
                end: at.start,
            });
            let form = match row.extra.get(FOLLOW_FIX_LOOKUP).and_then(|v| v.as_str()) {
                Some(moved) if sets_lookup => format!(
                    "{wrappers}{}",
                    moved.replace(COMMAND, &format!("{} {program}", trim_code(front)))
                ),
                _ => format!("{front}{wrappers}{}", template.replace(COMMAND, program)),
            };
            let bound = template.replace(COMMAND, "");
            let bound = bound.trim();
            let (why, head) = if let Some(k) = builtins_only {
                let wrapper = word(chain[k].name);
                let name = chain
                    .get(k + 1)
                    .map_or(inner.typed.as_str(), |n| word(n.name));
                (
                    UNDER_BUILTINS_ONLY,
                    format!(
                        "Bash has no `{name}` builtin, so `{wrapper} {name}` fails and follows nothing: drop `{wrapper}` and bound the program: `{form}`"
                    ),
                )
            } else if sets_lookup {
                (
                    SETS_LOOKUP,
                    format!("put `{bound}` in front and set the assignments after it: `{form}`"),
                )
            } else {
                (
                    UNDER_WRAPPER,
                    format!("put `{bound}` after the wrappers, right before the program: `{form}`"),
                )
            };
            return Err(NoCommand {
                why,
                head: Some(head),
            });
        }
        let (before, after) = (
            self.src.get(..whole.start).unwrap_or_default(),
            self.src.get(whole.end..).unwrap_or_default(),
        );
        let before_ends = before.trim_end_matches([' ', '\t']);
        let after_starts = after.trim_start_matches([' ', '\t']);
        let alone = (before_ends.is_empty() || before_ends.ends_with([';', '\n', '\r']))
            && (after_starts.is_empty() || after_starts.starts_with([';', '\n', '\r']));
        if !alone {
            return Err(IN_STATEMENT.into());
        }
        // A job sees none of the caller's variables: they go in through `$using:` (Ruling 143),
        // each one the command sets before the follow or not at all (Ruling 148).
        let mut pipeline = self.slice(whole).trim().to_string();
        if row.extra.contains_key(FOLLOW_FIX_LOCALS) {
            let Some((text, names)) = pass_variables(&pipeline, row) else {
                return Err(SETS_VARIABLE.into());
            };
            let sets = strings(row, FOLLOW_FIX_SETS);
            if names
                .iter()
                .any(|n| assigned_in(after, n, &sets) && !assigned_in(before, n, &sets))
            {
                return Err(SET_LATER.into());
            }
            pipeline = text;
        }
        // The job's variable is a name the command never uses, in no case either.
        let taken = |v: &str| {
            self.command
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w.eq_ignore_ascii_case(v))
        };
        let job = ["j".to_string(), "job".to_string()]
            .into_iter()
            .chain((2..).map(|k| format!("job{k}")))
            .find(|v| !taken(v))
            .unwrap_or_default();
        Ok((
            whole,
            template.replace(JOB, &job).replace(PIPELINE, &pipeline),
        ))
    }

    /// One loop, its children aside: a finding when it waits or never ends by its condition, and
    /// no bound is visible.
    fn judge(&mut self, body: &Script, span: Span, head: LoopHead) {
        let stmts = &body.stmts[..];
        let (cond, rest, at_end, until) = match head {
            LoopHead::Items | LoopHead::Counted { open: false } => return,
            LoopHead::Counted { open: true } => (&stmts[..0], stmts, false, false),
            LoopHead::Test {
                cond,
                at_end,
                until,
            } => {
                let n = cond.min(stmts.len());
                if at_end {
                    let (b, c) = stmts.split_at(stmts.len() - n);
                    (c, b, true, until)
                } else {
                    let (c, b) = stmts.split_at(n);
                    (c, b, false, until)
                }
            }
        };
        let (shell, os) = (self.shell, self.os);
        if commands(stmts).iter().any(|c| unreadable(c, shell, os)) {
            return;
        }
        let bash = matches!(shell, Shell::Bash(_));
        // The condition as written: in Bash, the header's text between the keyword and `do`, its
        // `!`, parentheses and braces kept.
        let cond_src = if bash {
            self.bash_condition(span, cond, rest)
        } else {
            self.text_of(cond)
        };
        let negated = bash && cond_src.starts_with('!');
        // A reader condition (`while read -r line`) ends with its input: a sleep in the body only
        // paces it (Ruling 134). `until read` and `while ! read` loop while the read fails.
        if !until
            && !negated
            && commands(cond)
                .iter()
                .any(|c| reads_input(c, shell, os) && !waits(c, shell, os))
        {
            return;
        }
        let loops = programs::loops();
        let cond_text = self.text_of(cond);
        let always = matches!(head, LoopHead::Counted { open: true })
            || (!until && is_always(&cond_text, &loops.always));
        // A wait in a `while` condition (`while sleep 5`) paces the loop as one in its body; a
        // reader's own timeout (`while read -t 5 line`) ends the loop instead.
        let cond_waits = !until
            && commands(cond)
                .iter()
                .any(|c| waits(c, shell, os) && !reads_input(c, shell, os));
        let waits = any_wait(rest, shell, os) || cond_waits;
        if !waits && !always {
            return;
        }
        let whole = self.slice(span);
        let fold = !matches!(shell, Shell::Bash(_));
        let counters = counters(whole, fold, &self.ints);
        let header = match head {
            LoopHead::Test { .. } if !cond.is_empty() => {
                let from = if at_end { stmts.len() - cond.len() } else { 0 };
                self.condition_bounds(body, from, cond.len(), until, &counters)
            }
            _ => bounds(&self.header(span, rest, at_end), &counters, fold),
        };
        if header || self.guards(rest).iter().any(|t| bounds(t, &counters, fold)) {
            return;
        }
        // The Fix runs the condition as written (Ruling 136). A list of commands is grouped, so
        // `&& break` reads its last command's status as the loop did.
        let mut cond_src = cond_src;
        if bash {
            let list = cond.iter().rev().skip(1).any(|s| {
                !matches!(
                    s,
                    Stmt::Pipeline(Pipeline {
                        chain: Some(ChainOp::And | ChainOp::Or),
                        ..
                    })
                )
            });
            if list {
                cond_src = format!("{{ {cond_src}; }}");
            }
        }
        let fix = self.fix_line(
            span,
            self.fix(
                span,
                &cond_src,
                stmts,
                rest,
                Form {
                    always,
                    until,
                    at_end,
                },
            ),
        );
        let what = if waits {
            "polls"
        } else {
            "has a condition that is always true"
        };
        self.out.push(Finding {
            rule: WAIT_LOOP_UNBOUNDED,
            level: Level::Break,
            message: format!(
                "the loop {what} and nothing bounds it: no counter, deadline or timeout ends it, so when what it waits for never comes it runs forever"
            ),
            fix: Some(fix),
            span: self.outer.unwrap_or(span),
        });
    }

    /// The whole command with the loop at `span` replaced by `loop_fix`, when the command is one
    /// line and not a child shell's script; then the hint as a trailing comment, so the line
    /// still runs as pasted.
    fn fix_line(&self, span: Span, loop_fix: Fixed) -> String {
        let loops = programs::loops();
        let hint = if matches!(self.shell, Shell::Bash(_)) {
            &loops.hint_bash
        } else {
            &loops.hint_pwsh
        };
        let loop_fix = match loop_fix {
            Fixed::Command(c) => c,
            Fixed::Sentence(s) => return format!("{s}; {hint}"),
        };
        let whole = match (self.src.get(..span.start), self.src.get(span.end..)) {
            (Some(before), Some(after)) if self.outer.is_none() && !self.src.contains('\n') => {
                format!("{before}{loop_fix}{after}")
            }
            _ => loop_fix,
        };
        format!("{}  # {hint}", whole.trim_end())
    }

    /// The source text of `span`, empty when it does not lie in the text.
    fn slice(&self, span: Span) -> &str {
        self.src.get(span.start..span.end).unwrap_or("")
    }

    /// The first place at or after `pos` that is no blank, line end or Bash line continuation (a
    /// word's span may start at the line end a continuation leaves).
    fn code_from(&self, pos: usize) -> usize {
        let mut at = pos;
        loop {
            let t = self.src.get(at..).unwrap_or("");
            let t = t.trim_start_matches([' ', '\t', '\n', '\r']);
            let t = t
                .strip_prefix("\\\n")
                .or_else(|| t.strip_prefix("\\\r\n"))
                .unwrap_or(t);
            let next = self.src.len() - t.len();
            if next <= at {
                return at;
            }
            at = next;
        }
    }

    /// The text from the first to the last of `stmts`.
    fn text_of(&self, stmts: &[Stmt]) -> String {
        match range(stmts) {
            Some(r) => self.slice(r).trim().to_string(),
            None => String::new(),
        }
    }

    /// A Bash loop's condition as written: the header between its keyword and `do`, so a `!`, a
    /// subshell or a brace group around it stays (the lowering keeps none of them). When the
    /// header may hold a comment, or does not hold the condition's statements, their text with
    /// the `!` before them.
    fn bash_condition(&self, span: Span, cond: &[Stmt], rest: &[Stmt]) -> String {
        let stmts = self.text_of(cond);
        let header = match self.bash_do(span, cond, rest) {
            Some(d) => self.slice(Span {
                start: span.start,
                end: d,
            }),
            None => self.slice(span),
        };
        let c = header
            .trim_start()
            .split_once(char::is_whitespace)
            .map_or("", |(_, c)| c)
            .trim_end();
        let c = c.strip_suffix("do").unwrap_or(c).trim_end();
        let c = c.strip_suffix(';').unwrap_or(c).trim();
        if !stmts.is_empty() && !c.contains('#') && c.contains(stmts.as_str()) {
            return c.to_string();
        }
        let negated = range(cond).is_some_and(|r| {
            self.slice(Span {
                start: span.start,
                end: r.start,
            })
            .trim_end()
            .ends_with('!')
        });
        if negated { format!("! {stmts}") } else { stmts }
    }

    /// Where a Bash loop's `do` stands: the first `do` after the condition's statements, comments
    /// aside. Between the two stand only the condition's closing words, a `;` and comments (the
    /// body's first statement may start inside a `{` or `(`, and a comment may hold `do`).
    fn bash_do(&self, span: Span, cond: &[Stmt], rest: &[Stmt]) -> Option<usize> {
        let from = range(cond).map_or(span.start, |r| r.end);
        let text = self.src.get(from..range(rest)?.start)?;
        let mut at = 0;
        for line in text.split_inclusive('\n') {
            let code = line.find('#').map_or(line, |h| &line[..h]);
            if let Some(i) = code.find("do") {
                return Some(from + at + i);
            }
            at += line.len();
        }
        None
    }

    /// A Bash loop's body as written: from after its `do` to the loop's closing `done`, without
    /// the `;` before it. `None` when the loop's text does not end in `done` (a redirect after
    /// it).
    fn bash_body(&self, span: Span, cond: &[Stmt], rest: &[Stmt]) -> Option<String> {
        let start = self.bash_do(span, cond, rest)? + 2;
        let t = self.src.get(start..span.end)?.trim();
        let t = t.strip_suffix("done")?.trim_end();
        Some(t.strip_suffix(';').unwrap_or(t).trim_end().to_string())
    }

    /// A PowerShell loop's body as written: the text inside its braces, so a `try` or another
    /// statement the lowering opens without its first word stays whole. The braces follow the
    /// condition (`while (…) {`), or open the loop (`do {`).
    fn pwsh_body(&self, span: Span, cond: &[Stmt], at_end: bool) -> Option<String> {
        let from = match range(cond) {
            Some(r) if !at_end => r.end,
            _ => span.start,
        };
        let open = from + self.src.get(from..span.end)?.find('{')?;
        let close = open + closing_brace(self.src.get(open..span.end)?)?;
        Some(self.src.get(open + 1..close)?.trim().to_string())
    }

    /// The loop's header: its text before the body (after it for `do … while`), the whole loop
    /// when the body is empty.
    fn header(&self, span: Span, rest: &[Stmt], at_end: bool) -> String {
        let Some(r) = range(rest) else {
            return self.slice(span).to_string();
        };
        let part = if at_end {
            Span {
                start: r.end,
                end: span.end,
            }
        } else {
            Span {
                start: span.start,
                end: r.start,
            }
        };
        self.slice(part).to_string()
    }

    /// The loop's condition (`n` statements of `body` from `from`) ends it by a bound (Ruling
    /// 141): reaching the bound stops the loop whatever the other tests say. `until A || bound`
    /// and `while A && bound` do; `until A && bound` and `while A || bound` wait for `A` too. The
    /// tests are read left to right, as both shells bind `&&`/`||` and `-and`/`-or`; a group or a
    /// test command (`( … )`, `[[ … ]]`) is one test.
    fn condition_bounds(
        &self,
        body: &Script,
        from: usize,
        n: usize,
        until: bool,
        counters: &[String],
    ) -> bool {
        let stmts = &body.stmts[from..from + n];
        let fold = !matches!(self.shell, Shell::Bash(_));
        let terms: Vec<(Option<ChainOp>, String)> = if fold {
            pwsh_terms(&self.text_of(stmts), self.shell, self.os)
        } else {
            (0..n)
                .map(|j| {
                    let op = if j > 0 { body.join(from + j) } else { None };
                    (op, self.text_of(&stmts[j..=j]))
                })
                .collect()
        };
        // Whether a bound can make the tests so far true, and whether it can make them false. A
        // `;` starts again: a list's last and-or chain decides.
        let mut can = (false, false);
        for (k, (op, t)) in terms.iter().enumerate() {
            let b = bounds(t, counters, fold);
            can = match op {
                Some(ChainOp::And) if k > 0 => (can.0 && b, can.1 || b),
                Some(ChainOp::Or) if k > 0 => (can.0 || b, can.1 && b),
                _ => (b, b),
            };
        }
        if until { can.0 } else { can.1 }
    }

    /// The text of every test that guards an exit in `stmts`: an `if` whose text holds an exit
    /// word, and the commands an `&&` or `||` chain runs before an exit command.
    fn guards(&self, stmts: &[Stmt]) -> Vec<String> {
        let exits = &programs::loops().exits;
        let fold = !matches!(self.shell, Shell::Bash(_));
        let mut out = Vec::new();
        let script_joins = |i: usize, s: &[Stmt]| -> bool {
            // `a && break`: the chain operator is on the pipeline before.
            i > 0
                && matches!(
                    &s[i - 1],
                    Stmt::Pipeline(Pipeline {
                        chain: Some(ChainOp::And | ChainOp::Or),
                        ..
                    })
                )
        };
        for (i, st) in stmts.iter().enumerate() {
            match st {
                Stmt::Cond { .. } => {
                    let t = self.text_of(std::slice::from_ref(st));
                    if words(&t).any(|w| has_word(exits, w, fold)) {
                        out.push(t);
                    }
                }
                Stmt::Pipeline(p) if pipeline_exits(p, exits, fold) => {
                    let mut first = i;
                    while script_joins(first, stmts) {
                        first -= 1;
                    }
                    out.push(self.text_of(&stmts[first..=i]));
                }
                Stmt::Block(b) => {
                    // A subshell's `exit` or `break` leaves the subshell, not the loop (the
                    // lowering gives `( … )` and `{ … }` the same node: the source tells them
                    // apart).
                    let subshell = range(&b.stmts).is_some_and(|r| {
                        self.src
                            .get(..r.start)
                            .is_some_and(|t| t.trim_end().ends_with('('))
                    });
                    if subshell {
                        continue;
                    }
                    // `[ $n -gt 9 ] && { echo timeout; exit 1; }`: the chain before a block that
                    // exits guards that exit.
                    let block_exits = b
                        .stmts
                        .iter()
                        .any(|s| matches!(s, Stmt::Pipeline(p) if pipeline_exits(p, exits, fold)));
                    if block_exits && script_joins(i, stmts) {
                        let mut first = i;
                        while script_joins(first, stmts) {
                            first -= 1;
                        }
                        out.push(self.text_of(&stmts[first..=i]));
                    }
                    out.extend(self.guards(&b.stmts));
                }
                _ => {}
            }
        }
        out
    }

    /// The Fix (Ruling 136): a counted loop of about ten minutes that runs the condition's own
    /// text first (`C || break` for `while C`, `C && break` for `until C`) and fails when its
    /// rounds run out, so a command after `&&` does not run: Bash ends the body with `[ "$i" -lt
    /// N ]`, PowerShell throws after the loop. A loop over several lines keeps its lines; a loop
    /// whose text cannot be rebuilt (a here-document) gets a sentence.
    fn fix(&self, span: Span, cond: &str, all: &[Stmt], rest: &[Stmt], form: Form) -> Fixed {
        let Form {
            always,
            until,
            at_end,
        } = form;
        let (shell, os) = (self.shell, self.os);
        // The body as written: the spans of a Bash `if`, group or subshell stop before their
        // closing word, the last statement's `&` is outside its text, and a group or a `try`
        // starts at its first inner statement.
        let cond_stmts = if at_end {
            &all[rest.len()..]
        } else {
            &all[..all.len() - rest.len()]
        };
        let source_body = if matches!(shell, Shell::Bash(_)) {
            self.bash_body(span, cond_stmts, rest)
        } else {
            self.pwsh_body(span, cond_stmts, at_end)
        };
        let mut body = source_body.clone().unwrap_or_else(|| self.text_of(rest));
        if source_body.is_none()
            && matches!(
                rest.last(),
                Some(Stmt::Pipeline(Pipeline {
                    chain: Some(ChainOp::Background),
                    ..
                }))
            )
        {
            body.push_str(" &");
        }
        let n = attempts(all, shell, os);
        // The counter is a name the whole command never uses (Ruling 142), in PowerShell in no
        // case either.
        let fold = !matches!(shell, Shell::Bash(_));
        let taken = |v: &str| {
            self.command
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| same(w, v, fold))
        };
        let var = ["i".to_string(), "attempt".to_string()]
            .into_iter()
            .chain((2..).map(|k| format!("attempt{k}")))
            .find(|v| !taken(v))
            .unwrap_or_default();
        let multi = body.contains('\n') || cond.contains('\n');
        let mut parts: Vec<String> = Vec::new();
        if matches!(shell, Shell::Bash(_)) {
            let heredoc = commands(all).iter().any(|c| {
                c.redirects
                    .iter()
                    .any(|r| matches!(r, Redirect::Heredoc { .. }))
            });
            // `continue` would skip the round test at the end of the body, and the fixed loop
            // would end 0 after its rounds.
            let skips = commands(rest)
                .iter()
                .any(|c| row(c, shell, os).is_some_and(|p| flag(p, SKIPS_ROUND)));
            // The fixed loop's failure must reach where the command goes on (Ruling 142): a later
            // stage of a pipeline decides its status, and a loop around it goes on. The loop's
            // redirects (`done 2>&1 | tee log`) stand between it and the pipe.
            let piped = self.src.get(span.end..).is_some_and(|t| {
                let t = past_redirects(t);
                t.starts_with('|') && !t.starts_with("||")
            });
            let why = if heredoc {
                Some(("", "the loop holds a here-document"))
            } else if skips {
                Some(("", "the body's `continue` would skip the round test"))
            } else if piped {
                Some((
                    ", and make the pipeline fail when the loop does",
                    "a later stage of the pipeline decides its status",
                ))
            } else if self.in_loop {
                Some((
                    ", and end the loop around it with a failure then",
                    "the loop around it would go on after a timeout",
                ))
            } else {
                None
            };
            if let Some((then, why)) = why {
                let test = if always {
                    ""
                } else {
                    " that runs its condition first and breaks on it, and"
                };
                return Fixed::Sentence(format!(
                    "rewrite the loop as a loop of at most {n} rounds{test} that fails when the rounds run out{then} (no command is built: {why})"
                ));
            }
            if !always {
                let op = if until { "&&" } else { "||" };
                parts.push(format!("{cond} {op} break"));
            }
            if !body.is_empty() {
                parts.push(body);
            }
            parts.push(format!("[ \"${var}\" -lt {n} ]"));
            let head = format!("for {var} in $(seq 1 {n}); do");
            if multi {
                let lines: String = parts.iter().map(|p| format!("  {p}\n")).collect();
                return Fixed::Command(format!("{head}\n{lines}done"));
            }
            let mut joined = String::new();
            for p in &parts {
                joined.push_str(p);
                // A command sent to the background ends with its `&`: a `;` after it is an error.
                let background = p.ends_with('&') && !p.ends_with("&&");
                joined.push_str(if background { " " } else { "; " });
            }
            Fixed::Command(format!("{head} {joined}done"))
        } else {
            let test = (!always).then(|| {
                if until {
                    format!("if ({cond}) {{ break }}")
                } else {
                    format!("if (-not ({cond})) {{ break }}")
                }
            });
            let body = (!body.is_empty()).then_some(body);
            parts.extend(
                if at_end { [body, test] } else { [test, body] }
                    .into_iter()
                    .flatten(),
            );
            let head = format!("for (${var} = 0; ${var} -lt {n}; ${var}++)");
            let tail = format!("if (${var} -eq {n}) {{ throw 'the wait timed out' }}");
            if multi {
                let lines: String = parts.iter().map(|p| format!("  {p}\n")).collect();
                return Fixed::Command(format!("{head} {{\n{lines}}}\n{tail}"));
            }
            let inner = if parts.is_empty() {
                " ".to_string()
            } else {
                format!(" {} ", parts.join("; "))
            };
            Fixed::Command(format!("{head} {{{inner}}}; {tail}"))
        }
    }
}

/// The duration word of a wrapper that bounds the wait when it sets no limit (Ruling 155): GNU
/// timeout reads `0` in any spelling (`00`, `0s`, `0.0`), `inf` and `infinity` as none. A
/// duration the guard cannot read, or that is no number, is taken as a limit.
fn no_limit(w: &programs::Wrapped) -> Option<&Word> {
    if !flag(w.row, BOUNDS) {
        return None;
    }
    let word = w.operands.first()?;
    let text = literal(word)?;
    let suffixes = strings(w.row, DURATION_SUFFIXES);
    let number = suffixes
        .iter()
        .find_map(|s| text.strip_suffix(s))
        .unwrap_or(&text);
    let value: f64 = number.parse().ok()?;
    (value == 0.0 || value.is_infinite()).then_some(word)
}

/// The wrapper bounds the wait: a `bounds_wait` row with a duration that sets a limit.
fn limits(w: &programs::Wrapped) -> bool {
    flag(w.row, BOUNDS) && no_limit(w).is_none()
}

fn flag(p: &Program, key: &str) -> bool {
    p.extra.get(key).and_then(|v| v.as_bool()) == Some(true)
}

fn strings<'a>(p: &'a Program, key: &str) -> Vec<&'a str> {
    p.extra
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

/// The row of the command `c` runs once its wrappers are read.
fn row(c: &SimpleCommand, shell: Shell, os: Os) -> Option<&'static Program> {
    let inner = programs::strip_wrappers(c, shell, os);
    if inner.opaque {
        return None;
    }
    programs::lookup(&inner.typed, shell, os)
}

/// The command reads its input (`read`): a `loop_reads_input` row.
fn reads_input(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    row(c, shell, os).is_some_and(|p| flag(p, READS_INPUT))
}

/// The command pauses: a `wait` row, with one of its `loop_wait_when` options when it has some.
fn waits(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    let Some(p) = row(c, shell, os).filter(|p| strings(p, ROLE).contains(&WAIT)) else {
        return false;
    };
    let when = strings(p, WAIT_WHEN);
    when.is_empty()
        || c.args.iter().any(|w| {
            let Some(a) = literal(w) else { return false };
            when.iter().any(|o| {
                a == *o
                    || o.strip_prefix('-').is_some_and(|letter| {
                        a.starts_with('-') && !a.starts_with("--") && a[1..].contains(letter)
                    })
            })
        })
}

/// The row of `c` by its canonical name (a PowerShell alias such as `gc`), else as typed.
fn named_row(inner: &SimpleCommand, shell: Shell, os: Os) -> Option<&'static Program> {
    if inner.opaque {
        return None;
    }
    inner
        .canonical
        .as_deref()
        .and_then(|n| programs::lookup(n, shell, os))
        .or_else(|| programs::lookup(&inner.typed, shell, os))
}

/// `args` hold one of `options`: exactly (ignoring case in PowerShell), as `--opt=value`, or a
/// short one as a letter of a cluster (`-fn`).
fn has_opt(args: &[String], options: &[&str], fold: bool) -> bool {
    args.iter().any(|a| {
        options.iter().any(|o| {
            let same = |x: &str| {
                if fold {
                    x.eq_ignore_ascii_case(o)
                } else {
                    x == *o
                }
            };
            same(a)
                || a.split_once('=')
                    .is_some_and(|(n, _)| o.starts_with("--") && same(n))
                || (!fold
                    && !o.starts_with("--")
                    && o.len() == 2
                    && a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].chars().all(|ch| ch.is_ascii_alphanumeric())
                    && a[1..].contains(&o[1..]))
        })
    })
}

/// The row of `c` when it follows a file or a stream: a `follow` row, or one of its
/// `follow_when` options; with a `follow_sub` only after that subcommand (`kubectl logs -f`).
fn follows(c: &SimpleCommand, shell: Shell, os: Os) -> Option<&'static Program> {
    let c = programs::strip_wrappers(c, shell, os);
    let p = named_row(&c, shell, os)?;
    let when = strings(p, FOLLOW_WHEN);
    if !flag(p, FOLLOW) && when.is_empty() {
        return None;
    }
    let args: Vec<String> = c.args.iter().filter_map(literal).collect();
    if args.len() != c.args.len() {
        // A dynamic word might hold the bound.
        return None;
    }
    let sub = p.extra.get(FOLLOW_SUB).and_then(|v| v.as_str());
    let args = match sub {
        Some(s) => args[args.iter().position(|a| a == s)? + 1..].to_vec(),
        None => args,
    };
    (flag(p, FOLLOW) || has_opt(&args, &when, !matches!(shell, Shell::Bash(_)))).then_some(p)
}

/// A job wait with a time bound (`Wait-Job $j -Timeout 60`): a `job_timeout_when` option.
fn waits_on_job_with_timeout(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    named_row(c, shell, os).is_some_and(|p| {
        let when = strings(p, JOB_TIMEOUT_WHEN);
        let args: Vec<String> = c.args.iter().filter_map(literal).collect();
        !when.is_empty() && has_opt(&args, &when, !matches!(shell, Shell::Bash(_)))
    })
}

/// The Bash text `t` after the redirects at its start (`2>&1`, `> out.txt`, `&>/dev/null`), blanks
/// aside.
fn past_redirects(t: &str) -> &str {
    const OPS: [&str; 8] = ["&>>", "&>", ">>", ">&", "<&", ">|", ">", "<"];
    let mut t = t.trim_start_matches([' ', '\t']);
    loop {
        let rest = t.trim_start_matches(|c: char| c.is_ascii_digit());
        let Some(op) = OPS.iter().find(|o| rest.starts_with(**o)) else {
            return t;
        };
        let rest = rest[op.len()..].trim_start_matches([' ', '\t']);
        // The target word ends at a blank or an operator outside quotes (`>"my out.txt"`).
        let mut quote: Option<char> = None;
        let mut escaped = false;
        let word = rest
            .char_indices()
            .find(|&(_, c)| {
                if escaped {
                    escaped = false;
                    return false;
                }
                match (quote, c) {
                    (Some('"'), '\\') | (None, '\\') => escaped = true,
                    (Some(q), c) if c == q => quote = None,
                    (Some(_), _) => {}
                    (None, '\'' | '"') => quote = Some(c),
                    (None, c) => return [' ', '\t', '|', ';', '&', '\n'].contains(&c),
                }
                false
            })
            .map_or(rest.len(), |(k, _)| k);
        if word == 0 {
            return t;
        }
        t = rest[word..].trim_start_matches([' ', '\t']);
    }
}

/// A PowerShell pipeline with each of the caller's variables read through `$using:`, as a job
/// needs (Ruling 143): `$pat` becomes `$using:pat`, `${pat}` `${using:pat}`. The variables the
/// pipeline or the shell sets (the row's `follow_fix_locals`: `$_`, `$true`), the scopes the job
/// reads as the caller does (`follow_fix_scopes`: `$env:`), single-quoted text and an escaped
/// `` `$ `` stay. `None` when the pipeline assigns a variable or names another scope: `$using:`
/// cannot pass either. With the names it passed.
fn pass_variables(text: &str, row: &Program) -> Option<(String, Vec<String>)> {
    let (locals, scopes) = (
        strings(row, FOLLOW_FIX_LOCALS),
        strings(row, FOLLOW_FIX_SCOPES),
    );
    let sets = strings(row, FOLLOW_FIX_SETS);
    let mut names: Vec<String> = Vec::new();
    let mut out = String::with_capacity(text.len() + 16);
    // Where the text stands: inside `"…"` (`None`), or in the code of a `"$( … )"` with this many
    // `(` open (`Some`), which is code again; empty outside any string.
    let mut quotes: Vec<Option<usize>> = Vec::new();
    let mut i = 0;
    while let Some(ch) = text[i..].chars().next() {
        let rest = &text[i..];
        let n = ch.len_utf8();
        let dq = quotes.last() == Some(&None);
        match ch {
            '`' => {
                let m = n + rest[n..].chars().next().map_or(0, char::len_utf8);
                out.push_str(&rest[..m]);
                i += m;
                continue;
            }
            // A single-quoted here-string ends at a line that starts with `'@`: an apostrophe
            // inside it is text.
            '@' if !dq && rest.starts_with("@'") => {
                let m = rest.find("\n'@").map_or(rest.len(), |k| k + 3);
                out.push_str(&rest[..m]);
                i += m;
                continue;
            }
            '\'' if !dq => {
                let m = rest[1..].find('\'').map_or(rest.len(), |k| k + 2);
                out.push_str(&rest[..m]);
                i += m;
                continue;
            }
            '"' if dq => {
                quotes.pop();
            }
            '"' => quotes.push(None),
            '$' if dq && rest.starts_with("$(") => {
                quotes.push(Some(0));
                out.push_str("$(");
                i += 2;
                continue;
            }
            '(' => {
                if let Some(Some(d)) = quotes.last_mut() {
                    *d += 1;
                }
            }
            ')' => match quotes.last_mut() {
                Some(Some(0)) => {
                    quotes.pop();
                }
                Some(Some(d)) => *d -= 1,
                _ => {}
            },
            '$' => {
                let from = if rest.starts_with("${") { 2 } else { 1 };
                let name = rest[from..]
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                let after = &rest[from + name.len()..];
                let scoped = after.starts_with(':') && !after.starts_with("::");
                let kept = |s: &str| scopes.iter().any(|k| k.eq_ignore_ascii_case(s));
                if !name.is_empty() && scoped && !kept(name) {
                    return None;
                }
                if !name.is_empty()
                    && !scoped
                    && !locals.iter().any(|l| l.eq_ignore_ascii_case(name))
                {
                    if assigns(&out, after, &sets) {
                        return None;
                    }
                    // `$using:p.ToLower()` is a parse error: outside a string a member, an
                    // element or a static member is read from `($using:p)`.
                    let close = usize::from(from == 2 && after.starts_with('}'));
                    let next = &after[close..];
                    let wrap = !dq
                        && (next.starts_with('.')
                            || next.starts_with('[')
                            || next.starts_with("::"));
                    if wrap {
                        out.push('(');
                    }
                    if !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                        names.push(name.to_string());
                    }
                    out.push_str(&rest[..from]);
                    out.push_str("using:");
                    out.push_str(name);
                    out.push_str(&after[..close]);
                    if wrap {
                        out.push(')');
                    }
                    i += from + name.len() + close;
                    continue;
                }
            }
            _ => {}
        }
        out.push(ch);
        i += n;
    }
    Some((out, names))
}

/// The PowerShell text `text` assigns the variable `name` (`$name = …`, `${name} += …`, `$name++`,
/// a loop word of `sets` that names it), case ignored.
fn assigned_in(text: &str, name: &str, sets: &[&str]) -> bool {
    text.match_indices('$').any(|(k, _)| {
        let rest = &text[k..];
        let from = if rest.starts_with("${") { 2 } else { 1 };
        let Some(after) = rest
            .get(from..from + name.len())
            .filter(|w| w.eq_ignore_ascii_case(name))
            .map(|_| &rest[from + name.len()..])
        else {
            return false;
        };
        let after = if from == 2 {
            after.strip_prefix('}').unwrap_or("")
        } else {
            after
        };
        let whole = !after.starts_with(|c: char| c.is_alphanumeric() || c == '_');
        whole && assigns(&text[..k], after, sets)
    })
}

/// A PowerShell variable between `before` and `after` is assigned there: `$x = …`, `$x += …`,
/// `$x++`, `++$x`, or a loop word of `sets` names it (`foreach ($x in …)`).
fn assigns(before: &str, after: &str, sets: &[&str]) -> bool {
    let a = after.trim_start_matches([' ', '\t']);
    let set = (a.starts_with('=') && !a.starts_with("=="))
        || ["+=", "-=", "*=", "/=", "%=", "??="]
            .iter()
            .any(|o| a.starts_with(o));
    let b = before.trim_end_matches([' ', '\t']);
    let step = after.starts_with("++")
        || after.starts_with("--")
        || b.ends_with("++")
        || b.ends_with("--");
    let each = b.strip_suffix('(').is_some_and(|b| {
        let b = b.trim_end_matches([' ', '\t']);
        sets.iter().any(|s| {
            b.len()
                .checked_sub(s.len())
                .and_then(|k| b.get(k..))
                .is_some_and(|w| w.eq_ignore_ascii_case(s))
        })
    });
    set || step || each
}

/// Bash text without the blanks and line continuations around it.
fn trim_code(s: &str) -> &str {
    let mut t = s.trim_start();
    loop {
        let u = t.trim_end_matches([' ', '\t']);
        let u = u
            .strip_suffix("\\\n")
            .or_else(|| u.strip_suffix("\\\r\n"))
            .unwrap_or(u);
        if u.len() == t.len() {
            return t;
        }
        t = u;
    }
}

/// The extent of a command's text: its name, words and redirect targets (the Bash lowering gives
/// a command with a redirect the span of its name only).
fn command_extent(c: &SimpleCommand) -> Span {
    let mut r = c.span;
    let mut add = |s: Span| {
        r = Span {
            start: r.start.min(s.start),
            end: r.end.max(s.end),
        };
    };
    add(c.name.span);
    c.args.iter().for_each(|w| add(w.span));
    for rd in &c.redirects {
        if let Redirect::File { target, .. } = rd {
            add(target.span);
        }
    }
    r
}

/// The extent of a pipeline's text, from its first stage to its last.
fn pipeline_extent(p: &Pipeline) -> Option<Span> {
    p.elems
        .iter()
        .map(|e| match e {
            Elem::Cmd(c) => command_extent(c),
            Elem::Method(m) => m.span,
            Elem::Expr(w) => w.span,
        })
        .reduce(|a, b| Span {
            start: a.start.min(b.start),
            end: a.end.max(b.end),
        })
}

/// A command the guard cannot read: its name is not static, or it runs text as code.
fn unreadable(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    let inner = programs::strip_wrappers(c, shell, os);
    inner.opaque || row(c, shell, os).is_some_and(|p| p.is(Kind::Eval))
}

/// The literal text of a word, `None` when any part is not a literal.
fn literal(w: &Word) -> Option<String> {
    let mut s = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(t) => s.push_str(t),
            _ => return None,
        }
    }
    Some(s)
}

/// The body of `bash -c '…'` and the like: a shell row with `loop_body` options, one of them
/// alone or in a cluster of short options (`-lc`), then a literal body.
fn child_body(c: &SimpleCommand, shell: Shell, os: Os) -> Option<String> {
    if c.opaque {
        return None;
    }
    let p = programs::lookup(&c.typed, shell, os).filter(|p| p.is(Kind::Shell))?;
    let options = strings(p, BODY);
    if options.is_empty() {
        return None;
    }
    let mut args = c.args.iter();
    while let Some(w) = args.next() {
        let a = literal(w)?;
        let takes = options.iter().any(|o| {
            a == *o
                || o.strip_prefix('-').is_some_and(|letter| {
                    a.starts_with('-')
                        && !a.starts_with("--")
                        && a[1..].chars().all(|ch| ch.is_ascii_alphabetic())
                        && a[1..].contains(letter)
                })
        });
        if takes {
            return args.next().and_then(literal);
        }
        if !a.starts_with('-') {
            return None;
        }
    }
    None
}

/// Every simple command and .NET call in some statements, inside compound statements and
/// substitutions too.
#[derive(Default)]
struct Calls<'a> {
    cmds: Vec<&'a SimpleCommand>,
    methods: Vec<&'a MethodCall>,
}

fn calls(stmts: &[Stmt]) -> Calls<'_> {
    let mut out = Calls::default();
    for st in stmts {
        collect(st, &mut out);
    }
    out
}

/// Every simple command in `stmts`, inside compound statements and substitutions too.
fn commands(stmts: &[Stmt]) -> Vec<&SimpleCommand> {
    calls(stmts).cmds
}

fn collect<'a>(st: &'a Stmt, out: &mut Calls<'a>) {
    let script = |s: &'a Script, out: &mut Calls<'a>| {
        for st in &s.stmts {
            collect(st, out);
        }
    };
    match st {
        Stmt::Pipeline(p) => {
            for elem in &p.elems {
                match elem {
                    Elem::Cmd(c) => {
                        out.cmds.push(c);
                        for w in std::iter::once(&c.name).chain(&c.args) {
                            word_commands(w, out);
                        }
                        for (_, w) in &c.assigns {
                            word_commands(w, out);
                        }
                    }
                    Elem::Method(m) => {
                        out.methods.push(m);
                        m.args.iter().for_each(|w| word_commands(w, out));
                    }
                    Elem::Expr(w) => word_commands(w, out),
                }
            }
        }
        Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => script(body, out),
        Stmt::Cond { branches, .. } => branches.iter().for_each(|b| script(b, out)),
    }
}

fn word_commands<'a>(w: &'a Word, out: &mut Calls<'a>) {
    for part in &w.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = part {
            for st in &s.stmts {
                collect(st, out);
            }
        }
    }
}

/// The row of a static .NET call (`[Threading.Thread]::Sleep`), named `[type]::method`.
fn method_row(m: &MethodCall, shell: Shell, os: Os) -> Option<&'static Program> {
    if m.type_name.is_empty() {
        return None;
    }
    programs::lookup(&format!("[{}]::{}", m.type_name, m.method), shell, os)
}

/// The .NET call pauses: a `wait` row.
fn method_waits(m: &MethodCall, shell: Shell, os: Os) -> bool {
    method_row(m, shell, os).is_some_and(|p| strings(p, ROLE).contains(&WAIT))
}

/// Something in `stmts` pauses.
fn any_wait(stmts: &[Stmt], shell: Shell, os: Os) -> bool {
    let c = calls(stmts);
    c.cmds.iter().any(|c| waits(c, shell, os))
        || c.methods.iter().any(|m| method_waits(m, shell, os))
}

/// The span from the first to the last of `stmts`, `None` when they hold no span.
fn range(stmts: &[Stmt]) -> Option<Span> {
    let mut r: Option<Span> = None;
    let mut add = |s: Span| {
        if s.end <= s.start && s.start == 0 {
            return;
        }
        r = Some(match r {
            None => s,
            Some(o) => Span {
                start: o.start.min(s.start),
                end: o.end.max(s.end),
            },
        });
    };
    for st in stmts {
        spans(st, &mut add);
    }
    r
}

fn spans(st: &Stmt, add: &mut dyn FnMut(Span)) {
    match st {
        Stmt::Pipeline(p) => {
            for elem in &p.elems {
                match elem {
                    // The Bash lowering gives a command with a redirect the span of its name and
                    // the redirect the whole text: the words carry the command's extent.
                    Elem::Cmd(c) => {
                        add(c.span);
                        add(c.name.span);
                        c.args.iter().for_each(|w| add(w.span));
                        for r in &c.redirects {
                            if let Redirect::File { target, .. } = r {
                                add(target.span);
                            }
                        }
                    }
                    Elem::Method(m) => add(m.span),
                    Elem::Expr(w) => add(w.span),
                }
            }
        }
        Stmt::Loop { span, .. } => add(*span),
        // A Bash `if` keeps the span of its keyword: its branches carry the rest.
        Stmt::Cond { span, branches } => {
            add(*span);
            for st in branches.iter().flat_map(|b| &b.stmts) {
                spans(st, add);
            }
        }
        Stmt::Func { body, .. } | Stmt::Block(body) => {
            for st in &body.stmts {
                spans(st, add);
            }
        }
    }
}

/// A pipeline of one exit command (`break`, `exit 1`).
fn pipeline_exits(p: &Pipeline, exits: &[String], fold: bool) -> bool {
    p.elems.iter().any(|e| match e {
        Elem::Cmd(c) => has_word(exits, &c.typed, fold),
        _ => false,
    })
}

fn has_word(list: &[String], w: &str, fold: bool) -> bool {
    list.iter().any(|x| {
        if fold {
            x.eq_ignore_ascii_case(w)
        } else {
            x == w
        }
    })
}

/// The words of a text: runs of letters, digits, `_` and `-` (`Get-Date`, `SECONDS`).
fn words(t: &str) -> impl Iterator<Item = &str> {
    t.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .map(|w| w.trim_matches('-'))
        .filter(|w| !w.is_empty())
}

/// The whole condition is one of the always-true words (`true`, `:`, `($true)`).
fn is_always(cond: &str, always: &[String]) -> bool {
    let c = cond
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    always.iter().any(|a| a.eq_ignore_ascii_case(c))
}

fn same(a: &str, b: &str, fold: bool) -> bool {
    if fold {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The identifiers of `text` that name a variable: not a property or a static member (`.Count`,
/// `::Now`), not an option (`-s` after a blank).
fn variables(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let b = text.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < b.len() {
            if !(b[i].is_ascii_alphabetic() || b[i] == b'_') || (i > 0 && is_ident(b[i - 1])) {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            let before = &text[..start];
            let member = before.ends_with('.') || before.ends_with("::");
            // `-s`, `(-not`, `--count` are options; `((--n))` is a decrement.
            let option = match before.strip_suffix("--") {
                Some(b) => b.is_empty() || b.ends_with([' ', '\t']),
                None => before
                    .strip_suffix('-')
                    .is_some_and(|b| b.is_empty() || b.ends_with([' ', '\t', '('])),
            };
            if !member && !option {
                return Some((start, &text[start..i]));
            }
        }
        None
    })
}

/// The right side of an assignment that starts at `t`: up to the end of its statement (a Bash
/// assignment word also ends at a blank).
fn assigned_value(t: &str, fold: bool) -> &str {
    let t = t.trim_start_matches([' ', '\t']);
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    for (k, ch) in t.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return &t[..k],
            ')' | ']' | '}' => depth -= 1,
            ';' | '\n' | '|' | '&' if depth == 0 => return &t[..k],
            ' ' | '\t' if depth == 0 && !fold => return &t[..k],
            _ => {}
        }
    }
    t
}

/// Where Bash reads a bare name as a variable: the text inside `(( ))` (also `$(( ))`) and `$[ ]`,
/// as byte ranges of `text`.
fn arithmetic(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for i in 0..b.len().saturating_sub(1) {
        let (open, close) = match (b[i], b[i + 1]) {
            (b'(', b'(') => (b'(', b')'),
            (b'$', b'[') => (b'[', b']'),
            _ => continue,
        };
        let from = if open == b'(' { i } else { i + 1 };
        let mut depth = 0usize;
        let end = b[from..].iter().position(|&c| {
            if c == open {
                depth += 1;
            } else if c == close {
                depth = depth.saturating_sub(1);
                return depth == 0;
            }
            false
        });
        out.push((i, end.map_or(b.len(), |k| from + k)));
    }
    out
}

/// The Bash statement that holds `at` is a `let` command: its words are arithmetic.
fn in_let(text: &str, at: usize) -> bool {
    let from = text[..at]
        .rfind([';', '\n', '|', '&', '(', '{', '`'])
        .map_or(0, |k| k + 1);
    text[from..at]
        .split_whitespace()
        .find(|w| !["do", "then", "else", "!"].contains(w))
        == Some("let")
}

/// The Bash names `stmts` declare integers: the plain words (`n`, `n=0`) of a command whose row
/// lists one of its options in `loop_integer_when` (`declare -i n=0`, `typeset -ix n`).
fn integers(stmts: &[Stmt], shell: Shell, os: Os) -> Vec<String> {
    if !matches!(shell, Shell::Bash(_)) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in commands(stmts) {
        let Some(p) = row(c, shell, os) else { continue };
        let when = strings(p, INTEGER_WHEN);
        let args: Vec<String> = c.args.iter().filter_map(literal).collect();
        if when.is_empty() || !has_opt(&args, &when, false) {
            continue;
        }
        for a in args.iter().filter(|a| !a.starts_with('-')) {
            out.push(a.split_once('=').map_or(a.as_str(), |(n, _)| n).to_string());
        }
    }
    out
}

/// The text before a name refers to it as a variable: `$n`, `${n}`, PowerShell `$script:n`.
fn refers(before: &str, fold: bool) -> bool {
    if before.ends_with('$') || before.ends_with("${") {
        return true;
    }
    fold && before.strip_suffix(':').is_some_and(|b| {
        let scope = b.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
        scope.len() < b.len() && (scope.ends_with('$') || scope.ends_with("${"))
    })
}

/// The counters of a loop's text: variables whose new value reads their old one (`n=$((n+1))`,
/// `((n++))`, `let n++`, `let n=n+1`, `n+=1`, `$i++`, `++$k`, `$i += 1`, `$i = $i + 1`). A
/// variable assigned from a command or an expression that does not read it (`c=$(ls out | wc
/// -l)`) holds a polled value and is no counter (Ruling 135). The read is a reference to the
/// variable (`$n`, `${n}`, a bare name in Bash arithmetic or `let`), never its name as a word of
/// the polled command (`state=$(cat state)`, Ruling 139). On a Bash name of `ints` (`declare -i
/// n`) an assignment is arithmetic too (`n=n+1`).
fn counters(text: &str, fold: bool, ints: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let arith = if fold { Vec::new() } else { arithmetic(text) };
    let inside = |at: usize| arith.iter().any(|&(s, e)| s < at && at < e);
    for (start, name) in variables(text) {
        let before = &text[..start];
        let after = &text[start + name.len()..];
        // A long option (`--count`) is no variable: `variables` leaves it out. PowerShell writes
        // the operator before the `$` (`++$k`).
        let op = if fold {
            before.strip_suffix('$').unwrap_or(before)
        } else {
            before
        };
        let pre = op.ends_with("++") || op.ends_with("--");
        let post = after.starts_with("++") || after.starts_with("--");
        let spaced = after.trim_start_matches([' ', '\t']);
        let compound = ["+=", "-=", "*=", "/="]
            .iter()
            .any(|o| spaced.starts_with(o));
        let assigned =
            spaced.starts_with('=') && !spaced.starts_with("==") && !spaced.starts_with("=~") && {
                let value = assigned_value(&spaced[1..], fold);
                let base = value.as_ptr() as usize - text.as_ptr() as usize;
                // In `let n=n+1` the whole value is arithmetic (in `: $((n=n+1))` it lies inside
                // the `$(( ))` too).
                let bare = !fold && (in_let(text, start) || ints.iter().any(|n| n == name));
                variables(value).any(|(at, v)| {
                    same(v, name, fold)
                        && (bare || refers(&value[..at], fold) || (!fold && inside(base + at)))
                })
            };
        if (pre || post || compound || assigned) && !out.iter().any(|n| same(n, name, fold)) {
            out.push(name.to_string());
        }
    }
    out
}

/// A PowerShell condition split into its tests at the operators outside brackets and quotes that
/// join two tests (a `loop_join` row: `-and`, `-or`), each with the operator before it.
fn pwsh_terms(text: &str, shell: Shell, os: Os) -> Vec<(Option<ChainOp>, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut quote, mut from, mut op) = (0usize, None, 0, None);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            // A join word stands between blanks, a line break among them.
            b' ' | b'\t' | b'\n' if depth == 0 => {
                let word = text[i + 1..]
                    .split([' ', '\t', '\n', '\r', '('])
                    .next()
                    .unwrap_or("");
                let join = word
                    .starts_with('-')
                    .then(|| programs::lookup(word, shell, os))
                    .flatten()
                    .and_then(|p| p.extra.get(LOOP_JOIN))
                    .and_then(|v| v.as_str());
                let next = match join {
                    Some(JOIN_AND) => Some(ChainOp::And),
                    Some(JOIN_OR) => Some(ChainOp::Or),
                    _ => None,
                };
                if next.is_some() {
                    out.push((op, text[from..i].to_string()));
                    op = next;
                    i += 1 + word.len();
                    from = i;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out.push((op, text[from..].to_string()));
    out
}

/// The words of `text` split on blanks outside quotes; a quoted part stays in its word.
fn tokens(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut quote: Option<char> = None;
    for (k, ch) in text.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                out.push(&text[s..k]);
            }
            continue;
        }
        if start.is_none() {
            start = Some(k);
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        }
    }
    if let Some(s) = start {
        out.push(&text[s..]);
    }
    out
}

/// Where the `}` that closes the `{` at the start of `text` stands, braces in PowerShell quotes
/// (`'…'`, `"…"` with its backtick escape) aside; `None` when it is not closed.
fn closing_brace(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, ch) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if let Some(q) = quote {
            if ch == '`' && q == '"' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
        } else {
            match ch {
                '`' => escaped = true,
                '\'' | '"' => quote = Some(ch),
                '{' => depth += 1,
                '}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn balance(parts: &[&str]) -> isize {
    parts
        .iter()
        .flat_map(|p| p.chars())
        .map(|c| match c {
            '(' => 1,
            ')' => -1,
            _ => 0,
        })
        .sum()
}

/// The operands of the comparisons in `test`: the words next to an operator written as a word
/// (`$n -lt 60`, `(Get-Date) -gt $end`, `$(( $(date +%s) - t )) -gt 60`, parentheses kept
/// whole), and the whole of a `(( … ))` that holds a symbolic operator (`((n++>=60))`).
fn operands(test: &str, compares: &[String], fold: bool) -> Vec<String> {
    let toks = tokens(test);
    let mut out = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if !compares.iter().any(|op| same(t, op, fold)) {
            continue;
        }
        let mut first = k;
        while first > 0 {
            first -= 1;
            // Going left, a `)` opens a group and its `(` closes it.
            if balance(&toks[first..k]) >= 0 {
                break;
            }
        }
        let mut last = k;
        while last + 1 < toks.len() {
            last += 1;
            if balance(&toks[k + 1..=last]) <= 0 {
                break;
            }
        }
        if first < k {
            out.push(toks[first..k].join(" "));
        }
        if last > k {
            out.push(toks[k + 1..=last].join(" "));
        }
    }
    let symbols: Vec<&String> = compares.iter().filter(|op| !op.starts_with('-')).collect();
    let mut rest = test;
    while let Some(at) = rest.find("((") {
        let region = &rest[at..];
        let mut depth = 0usize;
        let mut end = region.len();
        for (k, ch) in region.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &region[..end];
        if symbols.iter().any(|op| inner.contains(op.as_str())) {
            out.push(inner.to_string());
        }
        rest = &region[end.max(2)..];
    }
    out
}

/// `text` with the contents of its single-quoted strings removed: a literal is never a clock or a
/// counter.
fn without_literals(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for ch in text.chars() {
        if ch == '\'' {
            inside = !inside;
        } else if !inside {
            out.push(ch);
        }
    }
    out
}

/// A test that bounds the loop (Ruling 135): one side of a comparison in it is a clock or a
/// counter.
fn bounds(test: &str, counters: &[String], fold: bool) -> bool {
    let loops = programs::loops();
    operands(test, &loops.compares, fold).iter().any(|operand| {
        let clock = Clocks {
            words: &loops.clocks,
            fold,
        }
        .read(operand, true, false);
        let operand = without_literals(operand);
        clock || variables(&operand).any(|(_, v)| counters.iter().any(|n| same(n, v, fold)))
    })
}

/// Where a compared operand reads the time (Ruling 140). Outside quotes any clock word counts
/// (`$SECONDS`, `(Get-Date)`, `$sw.Elapsed`); inside double quotes and inside a command
/// substitution only an expansion that is a clock (`"$SECONDS"`, `"${SECONDS}"`, `$((SECONDS -
/// t))`) or a substitution whose command is one (`$(date +%s)`, `$(Get-Date)`): a clock word
/// there is text (`"Already up to date."`, `$(grep -c date log)`). A single-quoted text never is.
struct Clocks<'a> {
    words: &'a [String],
    fold: bool,
}

impl Clocks<'_> {
    fn is(&self, w: &str) -> bool {
        self.words.iter().any(|c| same(c, w, self.fold))
    }

    /// `bare`: a clock word itself counts (outside quotes, in arithmetic); `dq`: inside double
    /// quotes, where a single quote is a plain character.
    fn read(&self, text: &str, bare: bool, dq: bool) -> bool {
        let b = text.as_bytes();
        let escape = if self.fold { b'`' } else { b'\\' };
        let mut plain = String::new();
        let mut i = 0;
        while i < b.len() {
            let rest = &text[i..];
            if b[i] == escape {
                i += 1 + rest[1..].chars().next().map_or(0, char::len_utf8);
                plain.push(' ');
                continue;
            }
            if b[i] == b'\'' && !dq {
                i += 1 + rest[1..].find('\'').map_or(rest.len() - 1, |k| k + 1);
                plain.push(' ');
                continue;
            }
            if b[i] == b'"' {
                let end = closing_quote(text, i, escape);
                if self.read(&text[i + 1..end], false, true) {
                    return true;
                }
                i = (end + 1).min(b.len());
                plain.push(' ');
                continue;
            }
            if rest.starts_with("$((") {
                let end = closing_paren(text, i + 1);
                if self.read(
                    text.get(i + 3..end.saturating_sub(1)).unwrap_or(""),
                    true,
                    false,
                ) {
                    return true;
                }
                i = (end + 1).min(b.len());
                plain.push(' ');
                continue;
            }
            let backtick = b[i] == b'`' && !self.fold;
            if rest.starts_with("$(") || backtick {
                let (from, end) = if backtick {
                    (i + 1, rest[1..].find('`').map_or(b.len(), |k| i + 1 + k))
                } else {
                    (i + 2, closing_paren(text, i + 1))
                };
                let inner = text.get(from..end).unwrap_or("");
                let command = inner.trim_start().split([' ', '\t', ';', '|']).next();
                if command.is_some_and(|c| words(c).any(|w| self.is(w))) {
                    return true;
                }
                if self.read(inner, false, false) {
                    return true;
                }
                i = (end + 1).min(b.len());
                plain.push(' ');
                continue;
            }
            if b[i] == b'$' {
                let braced = rest.starts_with("${");
                let name = rest[if braced { 2 } else { 1 }..]
                    .trim_start_matches(['#', '!'])
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                if !name.is_empty() && self.is(name) {
                    return true;
                }
            }
            let ch = rest.chars().next().map_or(1, char::len_utf8);
            plain.push_str(&rest[..ch]);
            i += ch;
        }
        // A parameter keeps its `-` (`-Seconds`): it never equals a clock word.
        bare && plain
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
            .filter(|w| !w.is_empty())
            .any(|w| self.is(w))
    }
}

/// Where the `"` that closes the one at `open` stands (the text's end when none does): escapes
/// and the `$( )` inside it aside.
fn closing_quote(text: &str, open: usize, escape: u8) -> usize {
    let b = text.as_bytes();
    let mut i = open + 1;
    while i < b.len() {
        match b[i] {
            c if c == escape => i += 2,
            b'"' => return i,
            b'$' if b.get(i + 1) == Some(&b'(') => i = closing_paren(text, i + 1) + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Where the `)` that closes the `(` at `open` stands (the text's end when none does), quoted
/// parentheses aside.
fn closing_paren(text: &str, open: usize) -> usize {
    let b = text.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate().skip(open) {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            b'\'' | b'"' => quote = Some(c),
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    b.len()
}

/// How many rounds the Fix line's loop runs: the budget over the first wait's seconds.
fn attempts(rest: &[Stmt], shell: Shell, os: Os) -> u64 {
    let all = calls(rest);
    let command_secs = all
        .cmds
        .into_iter()
        .filter(|c| waits(c, shell, os))
        .find_map(|c| {
            let p = row(c, shell, os)?;
            let ms = strings(p, WAIT_MS);
            let units = p.extra.get(WAIT_UNITS).and_then(|v| v.as_table());
            let args: Vec<String> = c.args.iter().filter_map(literal).collect();
            let in_ms = args
                .iter()
                .any(|a| ms.iter().any(|o| o.eq_ignore_ascii_case(a)));
            // `sleep 1m`: a number with a unit suffix the row lists, in that unit's seconds.
            let secs = |a: &str| -> Option<f64> {
                if let Ok(v) = a.parse::<f64>() {
                    return Some(v);
                }
                let units = units?;
                let (num, unit) = a.split_at(a.char_indices().last()?.0);
                let factor = units.get(unit)?;
                let factor = factor
                    .as_float()
                    .or(factor.as_integer().map(|i| i as f64))?;
                num.parse::<f64>().ok().map(|v| v * factor)
            };
            args.iter()
                .find_map(|a| secs(a))
                .map(|v| if in_ms { v / 1000.0 } else { v })
        });
    let method_secs = || {
        all.methods.into_iter().find_map(|m| {
            let p = method_row(m, shell, os).filter(|p| strings(p, ROLE).contains(&WAIT))?;
            let v = m
                .args
                .iter()
                .find_map(|w| literal(w)?.parse::<f64>().ok())?;
            Some(if flag(p, WAIT_IN_MS) { v / 1000.0 } else { v })
        })
    };
    let secs = command_secs
        .or_else(method_secs)
        .filter(|s| *s > 0.0)
        .unwrap_or(1.0);
    (FIX_BUDGET_SECS / secs).ceil().max(1.0) as u64
}
