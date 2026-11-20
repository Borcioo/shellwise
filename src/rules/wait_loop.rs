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
//! its body, reads a clock or compares a variable the loop changes; or when the loop runs under a
//! wrapper that bounds its wait (`timeout 600 bash -c '…'`). A loop with no wait whose condition
//! can fail (`while read line`) is no wait loop. A loop whose body runs a command the guard cannot
//! read (a dynamic name, `eval`) is not judged: that command may end it. PowerShell keeps no
//! `break` in the IR, so its guards are the `if` statements whose text holds an exit word.

use super::{Ctx, Rule};
use crate::ir::{
    ChainOp, Elem, LoopHead, Pipeline, Redirect, Script, SimpleCommand, Stmt, Word, WordPart,
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
const BODY: &str = "loop_body";
const BOUNDS: &str = "bounds_wait";
const FOLLOW: &str = "follow";
const FOLLOW_WHEN: &str = "follow_when";
const FOLLOW_SUB: &str = "follow_sub";
const ENDS: &str = "ends_follow";
const ENDS_WHEN: &str = "ends_follow_when";
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
            outer: None,
            mode: Mode::Loops,
        }
        .script(ctx.script, false);
    }
}

/// `follow-unbounded`: a command that follows a file or a stream (`tail -f`, `Get-Content
/// -Wait`, `watch`, `kubectl logs -f`) with no `timeout` and no later pipeline stage that ends it
/// (`| head`, `| grep -m1`, `| Select-Object -First`). Warn: it may be meant to run in the
/// background.
pub struct FollowRule;

impl Rule for FollowRule {
    fn id(&self) -> &'static str {
        FOLLOW_UNBOUNDED
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        Walk {
            src: ctx.input.command,
            shell: ctx.input.shell,
            os: ctx.input.os,
            depth: 0,
            out,
            outer: None,
            mode: Mode::Follow,
        }
        .script(ctx.script, false);
    }
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
    /// A Bash `!` before the condition.
    negated: bool,
}

struct Walk<'a, 'b> {
    mode: Mode,
    /// The text the spans of the script point into.
    src: &'a str,
    shell: Shell,
    os: Os,
    depth: usize,
    out: &'b mut Vec<Finding>,
    /// The span of the command whose child-shell body this is: a finding points at it.
    outer: Option<Span>,
}

impl Walk<'_, '_> {
    /// `bounded`: a wrapper around this script bounds its wait.
    fn script(&mut self, s: &Script, bounded: bool) {
        for st in &s.stmts {
            match st {
                Stmt::Pipeline(p) => self.pipeline(p, bounded),
                Stmt::Loop { body, span, head } => {
                    if !bounded && self.mode == Mode::Loops {
                        self.judge(body, *span, *head);
                    }
                    self.script(body, bounded);
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
        // A wrapper that bounds the wait (`timeout`) as the outermost command bounds what it runs.
        let bounded =
            bounded || programs::lookup(&c.typed, shell, os).is_some_and(|w| flag(w, BOUNDS));
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
            outer: Some(self.outer.unwrap_or(at)),
            mode: self.mode,
        }
        .script(&script, bounded);
    }

    /// A follow command in `p` with no bound: not under `timeout`, and no later stage ends the
    /// pipeline.
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
        for (i, c) in cmds.iter().enumerate() {
            let bounds_it = programs::lookup(&c.typed, shell, os).is_some_and(|w| flag(w, BOUNDS));
            if bounded || bounds_it || !follows(c, shell, os) {
                continue;
            }
            if cmds[i + 1..]
                .iter()
                .any(|later| ends_follow(later, shell, os))
            {
                continue;
            }
            let extent = c.args.iter().fold(c.span, |s, w| Span {
                start: s.start.min(w.span.start),
                end: s.end.max(w.span.end),
            });
            let span = self.outer.unwrap_or(c.span);
            let text = self.slice(extent).trim().to_string();
            let fix = if matches!(shell, Shell::Bash(_)) {
                format!("timeout 60 {text}")
            } else {
                format!("{text} | Select-Object -First 20")
            };
            self.out.push(Finding {
                rule: FOLLOW_UNBOUNDED,
                level: Level::Warn,
                message: format!(
                    "`{}` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout",
                    c.typed
                ),
                fix: Some(fix),
                span,
            });
        }
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
        let loops = programs::loops();
        let cond_text = self.text_of(cond);
        let always = matches!(head, LoopHead::Counted { open: true })
            || (!until && is_always(&cond_text, &loops.always));
        let waits = commands(rest).iter().any(|c| waits(c, shell, os));
        if !waits && !always {
            return;
        }
        let whole = self.slice(span);
        let changed = changed_names(whole);
        let mut tests = vec![self.header(span, rest, at_end)];
        tests.extend(self.guards(rest));
        let fold = !matches!(shell, Shell::Bash(_));
        if tests.iter().any(|t| bounds(t, &changed, fold)) {
            return;
        }
        // `while ! C`: the Bash lowering keeps no `!`; it stands between the keyword and C.
        let negated = range(cond).is_some_and(|r| {
            self.slice(Span {
                start: span.start,
                end: r.start,
            })
            .trim_end()
            .ends_with('!')
        });
        let fix = self.fix_line(
            span,
            self.fix(
                &cond_text,
                rest,
                whole,
                Form {
                    always,
                    until,
                    at_end,
                    negated,
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
    fn fix_line(&self, span: Span, loop_fix: String) -> String {
        let loops = programs::loops();
        let hint = if matches!(self.shell, Shell::Bash(_)) {
            &loops.hint_bash
        } else {
            &loops.hint_pwsh
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

    /// The text from the first to the last of `stmts`.
    fn text_of(&self, stmts: &[Stmt]) -> String {
        match range(stmts) {
            Some(r) => self.slice(r).trim().to_string(),
            None => String::new(),
        }
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
                Stmt::Block(b) => out.extend(self.guards(&b.stmts)),
                _ => {}
            }
        }
        out
    }

    /// The Fix line: the loop rewritten with a counter that ends it after about ten minutes.
    fn fix(&self, cond: &str, rest: &[Stmt], whole: &str, form: Form) -> String {
        let Form {
            always,
            until,
            at_end,
            negated,
        } = form;
        let body = self.text_of(rest);
        let n = attempts(rest, self.shell, self.os);
        let var = if words(whole).any(|w| w == "i") {
            "attempt"
        } else {
            "i"
        };
        let multi = body.contains('\n') || cond.contains('\n');
        if matches!(self.shell, Shell::Bash(_)) {
            // The loop ends when its condition holds (`until C`, `while ! C`) or fails (`while
            // C`, `until ! C`): the Fix breaks on the same.
            let stop = if always {
                String::new()
            } else if until != negated {
                format!("{cond} && break; ")
            } else {
                format!("{cond} || break; ")
            };
            let body = if multi || body.is_empty() {
                "<the loop body>".to_string()
            } else {
                body
            };
            let stop = if multi {
                if always {
                    String::new()
                } else {
                    "<the stop test> && break; ".to_string()
                }
            } else {
                stop
            };
            format!("for {var} in $(seq 1 {n}); do {stop}{body}; done")
        } else {
            let negated = cond
                .get(..5)
                .filter(|p| p.eq_ignore_ascii_case("-not "))
                .map(|_| cond[5..].trim_start());
            let test = if always {
                String::new()
            } else if until {
                format!("if ({cond}) {{ break }}")
            } else if let Some(c) = negated {
                format!("if ({c}) {{ break }}")
            } else {
                format!("if (-not ({cond})) {{ break }}")
            };
            let body = if multi || body.is_empty() {
                "<the loop body>".to_string()
            } else {
                body
            };
            let test = if multi && !always {
                "if (<the stop test>) { break }".to_string()
            } else {
                test
            };
            let inner = match (test.is_empty(), at_end) {
                (true, _) => body,
                (false, true) => format!("{body}; {test}"),
                (false, false) => format!("{test}; {body}"),
            };
            format!("for (${var} = 0; ${var} -lt {n}; ${var}++) {{ {inner} }}")
        }
    }
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

/// `c` follows a file or a stream: a `follow` row, or one of its `follow_when` options; with a
/// `follow_sub` only after that subcommand (`kubectl logs -f`).
fn follows(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    let c = programs::strip_wrappers(c, shell, os);
    let Some(p) = named_row(&c, shell, os) else {
        return false;
    };
    let when = strings(p, FOLLOW_WHEN);
    if !flag(p, FOLLOW) && when.is_empty() {
        return false;
    }
    let args: Vec<String> = c.args.iter().filter_map(literal).collect();
    if args.len() != c.args.len() {
        // A dynamic word might hold the bound.
        return false;
    }
    let sub = p.extra.get(FOLLOW_SUB).and_then(|v| v.as_str());
    let args = match sub {
        Some(s) => match args.iter().position(|a| a == s) {
            Some(at) => args[at + 1..].to_vec(),
            None => return false,
        },
        None => args,
    };
    flag(p, FOLLOW) || has_opt(&args, &when, !matches!(shell, Shell::Bash(_)))
}

/// A later pipeline stage that ends the pipeline: an `ends_follow` row, or one of its
/// `ends_follow_when` options (`grep -m1`, `Select-Object -First 5`).
fn ends_follow(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    let c = programs::strip_wrappers(c, shell, os);
    let Some(p) = named_row(&c, shell, os) else {
        return false;
    };
    if flag(p, ENDS) {
        return true;
    }
    let when = strings(p, ENDS_WHEN);
    let args: Vec<String> = c.args.iter().filter_map(literal).collect();
    !when.is_empty() && has_opt(&args, &when, !matches!(shell, Shell::Bash(_)))
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

/// Every simple command in `stmts`, inside compound statements and substitutions too.
fn commands(stmts: &[Stmt]) -> Vec<&SimpleCommand> {
    let mut out = Vec::new();
    for st in stmts {
        collect(st, &mut out);
    }
    out
}

fn collect<'a>(st: &'a Stmt, out: &mut Vec<&'a SimpleCommand>) {
    let script = |s: &'a Script, out: &mut Vec<&'a SimpleCommand>| {
        for st in &s.stmts {
            collect(st, out);
        }
    };
    match st {
        Stmt::Pipeline(p) => {
            for elem in &p.elems {
                match elem {
                    Elem::Cmd(c) => {
                        out.push(c);
                        for w in std::iter::once(&c.name).chain(&c.args) {
                            word_commands(w, out);
                        }
                        for (_, w) in &c.assigns {
                            word_commands(w, out);
                        }
                    }
                    Elem::Method(m) => m.args.iter().for_each(|w| word_commands(w, out)),
                    Elem::Expr(w) => word_commands(w, out),
                }
            }
        }
        Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => script(body, out),
        Stmt::Cond { branches, .. } => branches.iter().for_each(|b| script(b, out)),
    }
}

fn word_commands<'a>(w: &'a Word, out: &mut Vec<&'a SimpleCommand>) {
    for part in &w.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = part {
            for st in &s.stmts {
                collect(st, out);
            }
        }
    }
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

/// The names the loop's text changes: `n++`, `++n`, `n+=1`, `n-=1`, `n=…` (not `n==`), `$n = …`.
fn changed_names(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        if !(b[i].is_ascii_alphabetic() || b[i] == b'_') || (i > 0 && ident(b[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && ident(b[i]) {
            i += 1;
        }
        let name = &text[start..i];
        let before = &text[..start];
        let pre = before.ends_with("++") || before.ends_with("--");
        let after = text[i..].trim_start_matches([' ', '\t']);
        let op = ["++", "--", "+=", "-=", "*="]
            .iter()
            .any(|o| after.starts_with(o))
            || (after.starts_with('=') && !after.starts_with("==") && !after.starts_with("=~"));
        if (pre || op) && !out.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
            out.push(name.to_string());
        }
    }
    out
}

/// A test that bounds the loop: it reads a clock, or compares a name the loop changes.
fn bounds(test: &str, changed: &[String], fold: bool) -> bool {
    let loops = programs::loops();
    if words(test).any(|w| loops.clocks.iter().any(|c| c.eq_ignore_ascii_case(w))) {
        return true;
    }
    let arith = test.find("((");
    let compares = loops.compares.iter().any(|op| {
        let symbol = !op.starts_with('-');
        test.split_whitespace().any(|t| {
            if fold {
                t.eq_ignore_ascii_case(op)
            } else {
                t == op
            }
        }) || (symbol && arith.is_some_and(|at| test[at..].contains(op.as_str())))
    });
    compares
        && words(test).any(|w| {
            let w = w.trim_start_matches('$');
            changed.iter().any(|n| {
                if fold {
                    n.eq_ignore_ascii_case(w)
                } else {
                    n == w
                }
            })
        })
}

/// How many rounds the Fix line's loop runs: the budget over the first wait's seconds.
fn attempts(rest: &[Stmt], shell: Shell, os: Os) -> u64 {
    let secs = commands(rest)
        .into_iter()
        .filter(|c| waits(c, shell, os))
        .find_map(|c| {
            let ms = row(c, shell, os)
                .map(|p| strings(p, WAIT_MS))
                .unwrap_or_default();
            let args: Vec<String> = c.args.iter().filter_map(literal).collect();
            let in_ms = args
                .iter()
                .any(|a| ms.iter().any(|o| o.eq_ignore_ascii_case(a)));
            args.iter()
                .find_map(|a| a.trim_end_matches('s').parse::<f64>().ok())
                .map(|v| if in_ms { v / 1000.0 } else { v })
        })
        .filter(|s| *s > 0.0)
        .unwrap_or(1.0);
    (FIX_BUDGET_SECS / secs).ceil().max(1.0) as u64
}
