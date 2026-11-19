//! `will-hang`: a command that waits for something nobody can give it in the hook's tool (no
//! terminal answers a prompt, stdin is an open pipe that never ends), and a PowerShell function
//! whose name a built-in alias outranks.
//!
//! The commands are data. A `[[program]]` row with `kind` holding `interactive` says which
//! options start the wait (`hang_when`), which options end or bound it (`hang_unless`), whether
//! feeding the command's stdin ends it (`hang_stdin`), whether only Bash has the wait
//! (`hang_bash_only`), the level (`hang_level`) and the one-step correction (`fix`). A wrapper row
//! with `bounds_wait` (`timeout`) bounds what it wraps. This file holds no program or option name.
//!
//! The rule never blocks an unknown program (Ruling 91a): a dynamic argument might hold the
//! bound, so it ends the check without a finding. It reads command lines only: a script file may
//! run in a terminal, where a prompt is answered.

use super::{Ctx, Rule, Scope};
use crate::ir::{Elem, Pipeline, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::parse::pwsh;
use crate::programs::{self, Program};
use crate::Shell;

pub const WILL_HANG: &str = "will-hang";

/// The fix line when a table row has no `fix`.
const FALLBACK_FIX: &str = "run it with its input given up front, or bound its wait";

/// What the program table says about one interactive program. Every read of a `Program` field
/// for this rule is here, so a change in the table's shape edits one place.
struct Spec<'a> {
    when: &'a [String],
    unless: &'a [String],
    stdin_feeds: bool,
    bash_only: bool,
    level: Level,
    fix: &'a str,
}

impl<'a> Spec<'a> {
    fn of(p: &'a Program) -> Option<Spec<'a>> {
        if !p.kind.iter().any(|k| k == "interactive") {
            return None;
        }
        let level = match p.hang_level.as_deref() {
            Some("break") => Level::Break,
            _ => Level::Warn,
        };
        Some(Spec {
            when: &p.hang_when,
            unless: &p.hang_unless,
            stdin_feeds: p.hang_stdin,
            bash_only: p.hang_bash_only,
            level,
            fix: p.fix.as_deref().unwrap_or(FALLBACK_FIX),
        })
    }
}

pub struct HangRule;

impl Rule for HangRule {
    fn id(&self) -> &'static str {
        WILL_HANG
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        Walker { ctx, out }.script(ctx.script, false);
    }
}

struct Walker<'a, 'b> {
    ctx: &'a Ctx<'a>,
    out: &'b mut Vec<Finding>,
}

impl Walker<'_, '_> {
    /// `nested`: inside a block, a substitution or a function body, where the stdin of the
    /// enclosing pipeline or redirect is not visible in the IR.
    fn script(&mut self, s: &Script, nested: bool) {
        for st in &s.stmts {
            self.stmt(st, nested);
        }
    }

    fn stmt(&mut self, st: &Stmt, nested: bool) {
        match st {
            Stmt::Pipeline(p) => self.pipeline(p, nested),
            Stmt::Loop { body, .. } => self.script(body, true),
            Stmt::Cond { branches, .. } => {
                for b in branches {
                    self.script(b, nested);
                }
            }
            Stmt::Func { name, body } => {
                self.alias_helper(name);
                self.script(body, true);
            }
            Stmt::Block(b) => self.script(b, true),
        }
    }

    fn pipeline(&mut self, p: &Pipeline, nested: bool) {
        for (i, elem) in p.elems.iter().enumerate() {
            match elem {
                Elem::Cmd(c) => {
                    self.command(c, i > 0, nested);
                    self.words(c);
                }
                Elem::Method(m) => {
                    for w in &m.args {
                        self.word(w);
                    }
                }
                Elem::Expr(w) => self.word(w),
            }
        }
    }

    fn words(&mut self, c: &SimpleCommand) {
        self.word(&c.name);
        for w in &c.args {
            self.word(w);
        }
        for r in &c.redirects {
            match r {
                Redirect::File { target, .. } => self.word(target),
                Redirect::Heredoc { body, .. } => self.word(body),
            }
        }
        for (_, w) in &c.assigns {
            self.word(w);
        }
    }

    fn word(&mut self, w: &Word) {
        for part in &w.parts {
            if let WordPart::Subst(s) | WordPart::Block(s) = part {
                self.script(s, true);
            }
        }
    }

    /// One command: its program row says whether it can wait, and the checks below say whether
    /// the command text already ends or bounds the wait.
    fn command(&mut self, c: &SimpleCommand, piped_into: bool, nested: bool) {
        let ctx = self.ctx;
        let (shell, os) = (ctx.input.shell, ctx.input.os);
        let inner = programs::strip_wrappers(c);
        if inner.opaque {
            return;
        }
        let Some(program) = programs::lookup(&inner.typed, shell, os) else {
            return;
        };
        let Some(spec) = Spec::of(program) else {
            return;
        };
        if spec.bash_only && !matches!(shell, Shell::Bash(_)) {
            return;
        }
        // Static text of each argument, lowercased; `None` once one is dynamic.
        let mut args: Vec<String> = Vec::new();
        for w in &inner.args {
            match w.static_value(&ctx.input.env) {
                Some(v) => args.push(v.to_lowercase()),
                None => return,
            }
        }
        let has = |entries: &[String]| {
            entries
                .iter()
                .any(|e| args.iter().any(|a| matches_entry(a, e)))
        };
        if !spec.when.is_empty() && !has(spec.when) {
            return;
        }
        if has(spec.unless) {
            return;
        }
        if spec.stdin_feeds && (piped_into || nested || inner.in_loop || has_input(inner)) {
            return;
        }
        // A wrapper that bounds the wait (`timeout`) as the outermost command.
        if programs::lookup(&c.typed, shell, os).is_some_and(|w| w.bounds_wait) {
            return;
        }
        self.out.push(Finding {
            rule: WILL_HANG,
            level: spec.level,
            message: format!(
                "`{}` can wait without end here: the tool has no terminal, so a prompt or a read of stdin is never answered and nothing bounds the wait",
                inner.typed
            ),
            fix: Some(spec.fix.to_string()),
            span: c.span,
        });
    }

    /// A PowerShell function named like a built-in alias: the alias runs, not the function.
    fn alias_helper(&mut self, name: &str) {
        let ctx = self.ctx;
        let (shell, os) = (ctx.input.shell, ctx.input.os);
        if !matches!(shell, Shell::Pwsh | Shell::Powershell5) {
            return;
        }
        // `global:md` and `script:md` name the same function.
        let bare = name.rsplit_once(':').map_or(name, |(_, n)| n);
        let Some(target) = pwsh::canonical(bare, shell, os) else {
            return;
        };
        if target == bare.to_lowercase() {
            return;
        }
        self.out.push(Finding {
            rule: WILL_HANG,
            level: Level::Warn,
            message: format!(
                "the function `{bare}` is never called by that name: the built-in alias `{bare}` for `{target}` outranks it, and the call runs `{target}` with the function's arguments"
            ),
            fix: Some(format!(
                "rename the function {bare} to a Verb-Noun name and call it by that name"
            )),
            span: Span::default(),
        });
    }
}

/// An argument (already lowercased) names a table entry: equal to it, `<entry>=<value>`, or for
/// an entry that holds `=` also glued to a short option (`-oBatchMode=yes`).
fn matches_entry(arg: &str, entry: &str) -> bool {
    let entry = entry.to_lowercase();
    arg == entry
        || arg
            .strip_prefix(entry.as_str())
            .is_some_and(|rest| rest.starts_with('='))
        || (entry.contains('=') && arg.ends_with(entry.as_str()))
}

/// The command reads its stdin from a file, a here-string or a here-document.
fn has_input(c: &SimpleCommand) -> bool {
    c.redirects.iter().any(|r| match r {
        Redirect::File { op, .. } => op.starts_with('<'),
        Redirect::Heredoc { .. } => true,
    })
}
