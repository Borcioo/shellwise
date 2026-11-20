//! `will-hang`: a command that waits for something nobody can give it in the hook's tool (stdin
//! is an open pipe that never ends, no terminal answers a prompt). `ps-alias-shadow`: a
//! PowerShell function whose name a built-in alias outranks.
//!
//! The commands are data. A `[[program]]` row whose `kind` holds `interactive` says which options
//! start the wait (`hang_when`), which options end or bound it (`hang_unless`), whether feeding
//! the command's stdin ends it (`hang_stdin`), whether only Bash has the wait (`hang_bash_only`),
//! the level (`hang_level`) and the one-step correction (`fix`). A wrapper row with `bounds_wait`
//! (`timeout`) bounds what it wraps. This file holds no program or option name.
//!
//! The rule never blocks an unknown program (Ruling 91a): a dynamic argument might hold the
//! bound, so it ends the check without a finding. It reads command lines only: a script file may
//! run in a terminal, where a prompt is answered.

use super::{Ctx, Rule, Scope};
use crate::Shell;
use crate::ir::{ChainOp, Elem, Pipeline, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::parse::pwsh;
use crate::programs::{self, Kind, Program};

pub const WILL_HANG: &str = "will-hang";
pub const PS_ALIAS_SHADOW: &str = "ps-alias-shadow";

/// The fix line when a table row has no `fix`.
const FALLBACK_FIX: &str = "run it with its input given up front, or bound its wait";

/// The `extra` keys of a program row this rule reads.
const WHEN: &str = "hang_when";
const UNLESS: &str = "hang_unless";
const STDIN: &str = "hang_stdin";
const BASH_ONLY: &str = "hang_bash_only";
const LEVEL: &str = "hang_level";
const BOUNDS: &str = "bounds_wait";

/// What the program table says about one interactive program. Every read of a `Program` for this
/// rule is here, so a change in the table's shape edits one place.
struct Spec<'a> {
    program: &'a Program,
    when: Vec<&'a str>,
    unless: Vec<&'a str>,
    stdin_feeds: bool,
    bash_only: bool,
    level: Level,
    fix: &'a str,
}

fn strings<'a>(p: &'a Program, key: &str) -> Vec<&'a str> {
    p.extra
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

fn flag(p: &Program, key: &str) -> bool {
    p.extra.get(key).and_then(|v| v.as_bool()) == Some(true)
}

impl<'a> Spec<'a> {
    fn of(p: &'a Program) -> Option<Spec<'a>> {
        if !p.is(Kind::Interactive) {
            return None;
        }
        let level = match p.extra.get(LEVEL).and_then(|v| v.as_str()) {
            Some("break") => Level::Break,
            _ => Level::Warn,
        };
        Some(Spec {
            program: p,
            when: strings(p, WHEN),
            unless: strings(p, UNLESS),
            stdin_feeds: flag(p, STDIN),
            bash_only: flag(p, BASH_ONLY),
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
    /// `nested`: inside a compound command, a substitution or a function body. The IR keeps no
    /// pipe or redirect that feeds a compound command (`if read x; then …; fi < f`), so its stdin
    /// is unknown there.
    fn script(&mut self, s: &Script, nested: bool) {
        for st in &s.stmts {
            match st {
                Stmt::Pipeline(p) => self.pipeline(p, nested),
                Stmt::Loop { body, .. } => self.script(body, true),
                Stmt::Cond { branches, .. } => {
                    for b in branches {
                        self.script(b, true);
                    }
                }
                Stmt::Func { body, .. } => self.script(body, true),
                Stmt::Block(b) => self.script(b, true),
            }
        }
    }

    fn pipeline(&mut self, p: &Pipeline, nested: bool) {
        // A background job of a non-interactive shell reads its stdin from /dev/null.
        let background = p.chain == Some(ChainOp::Background);
        for (i, elem) in p.elems.iter().enumerate() {
            match elem {
                Elem::Cmd(c) => {
                    let fed = i > 0 || background;
                    self.command(c, fed, nested);
                    // A substitution in the command's words reads the stdin the command has.
                    let inner = nested || fed;
                    self.word(&c.name, inner);
                    for w in &c.args {
                        self.word(w, inner);
                    }
                    for r in &c.redirects {
                        match r {
                            Redirect::File { target, .. } => self.word(target, inner),
                            Redirect::Heredoc { body, .. } => self.word(body, inner),
                        }
                    }
                    for (_, w) in &c.assigns {
                        self.word(w, inner);
                    }
                }
                Elem::Method(m) => {
                    for w in &m.args {
                        self.word(w, nested);
                    }
                }
                Elem::Expr(w) => self.word(w, nested),
            }
        }
    }

    fn word(&mut self, w: &Word, nested: bool) {
        for part in &w.parts {
            if let WordPart::Subst(s) | WordPart::Block(s) = part {
                self.script(s, nested);
            }
        }
    }

    /// One command: its program row says whether it can wait, and the checks below say whether
    /// the command text already ends or bounds the wait. `fed`: something other than the tool's
    /// stdin feeds it (an earlier pipeline stage, a background job's /dev/null).
    fn command(&mut self, c: &SimpleCommand, fed: bool, nested: bool) {
        let ctx = self.ctx;
        let (shell, os) = (ctx.input.shell, ctx.input.os);
        let inner = programs::strip_wrappers(c, shell, os);
        if inner.opaque {
            return;
        }
        let Some(spec) = programs::lookup(&inner.typed, shell, os).and_then(Spec::of) else {
            return;
        };
        if spec.bash_only && !matches!(shell, Shell::Bash(_)) {
            return;
        }
        // Static text of each argument. A dynamic one might hold a bound, so it ends the check;
        // for a program with no bounding option it is skipped.
        let mut args: Vec<String> = Vec::new();
        for w in &inner.args {
            match w.static_value(&ctx.input.env) {
                Some(v) => args.push(v),
                None if spec.unless.is_empty() => {}
                None => return,
            }
        }
        if !spec.when.is_empty() && !has_option(spec.program, &args, &spec.when) {
            return;
        }
        if has_option(spec.program, &args, &spec.unless) {
            return;
        }
        if spec.stdin_feeds && (fed || nested || has_input(&inner)) {
            return;
        }
        // A wrapper that bounds the wait (`timeout`) as the outermost command.
        if programs::lookup(&c.typed, shell, os).is_some_and(|w| flag(w, BOUNDS)) {
            return;
        }
        self.out.push(Finding {
            rule: WILL_HANG,
            level: spec.level,
            message: format!(
                "`{}` can wait without end here: the tool has no terminal and its stdin never ends, so a prompt or a read of stdin is never answered and nothing bounds the wait",
                inner.typed
            ),
            fix: Some(spec.fix.to_string()),
            span: c.span,
        });
    }
}

/// `ps-alias-shadow`: a PowerShell 7 function named like a built-in alias: the alias runs, not
/// the function. On a command line and in a script file alike.
pub struct AliasShadowRule;

impl Rule for AliasShadowRule {
    fn id(&self) -> &'static str {
        PS_ALIAS_SHADOW
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if ctx.input.shell == Shell::Pwsh {
            functions(ctx, ctx.script, out);
        }
    }
}

/// Every function definition in `s`, nested ones included.
fn functions(ctx: &Ctx, s: &Script, out: &mut Vec<Finding>) {
    let words = |w: &Word, out: &mut Vec<Finding>| {
        for part in &w.parts {
            if let WordPart::Subst(s) | WordPart::Block(s) = part {
                functions(ctx, s, out);
            }
        }
    };
    for st in &s.stmts {
        match st {
            Stmt::Pipeline(p) => {
                for elem in &p.elems {
                    match elem {
                        Elem::Cmd(c) => {
                            for w in std::iter::once(&c.name).chain(&c.args) {
                                words(w, out);
                            }
                        }
                        Elem::Method(m) => m.args.iter().for_each(|w| words(w, out)),
                        Elem::Expr(w) => words(w, out),
                    }
                }
            }
            Stmt::Loop { body, .. } | Stmt::Block(body) => functions(ctx, body, out),
            Stmt::Cond { branches, .. } => {
                for b in branches {
                    functions(ctx, b, out);
                }
            }
            Stmt::Func { name, body } => {
                shadowed(ctx, name, out);
                functions(ctx, body, out);
            }
        }
    }
}

/// The finding for a function `name` a built-in alias outranks.
fn shadowed(ctx: &Ctx, name: &str, out: &mut Vec<Finding>) {
    let (shell, os) = (ctx.input.shell, ctx.input.os);
    // `global:md` and `script:md` name the same function.
    let bare = name.rsplit_once(':').map_or(name, |(_, n)| n);
    let Some(target) = pwsh::canonical(bare, shell, os) else {
        return;
    };
    if target == bare.to_lowercase() {
        return;
    }
    out.push(Finding {
        rule: PS_ALIAS_SHADOW,
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

/// Whether `args` hold one of `options`, read as getopt reads them: a long option exactly; a
/// short `-x` alone or inside a cluster (`-rt 5`), where a letter that takes a value (the row's
/// `value_options`) ends the cluster and, with nothing glued to it, takes the next word
/// (`-p -t`: the prompt is `-t`).
fn has_option(p: &Program, args: &[String], options: &[&str]) -> bool {
    let takes_value = |letter: char| p.value_options.iter().any(|o| *o == format!("-{letter}"));
    let mut i = 0;
    while let Some(a) = args.get(i) {
        i += 1;
        if a.starts_with("--") {
            if options.contains(&a.as_str()) {
                return true;
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            continue;
        };
        for (k, letter) in cluster.char_indices() {
            if !letter.is_ascii_alphabetic() {
                break;
            }
            if options
                .iter()
                .any(|o| o.strip_prefix('-') == Some(&cluster[k..k + 1]))
            {
                return true;
            }
            if takes_value(letter) {
                if k + 1 == cluster.len() {
                    i += 1;
                }
                break;
            }
        }
    }
    false
}

/// The command reads its stdin from a file, a duplicated descriptor, a here-string or a
/// here-document: an input redirect with no descriptor or descriptor 0 (`3< f` feeds fd 3).
fn has_input(c: &SimpleCommand) -> bool {
    c.redirects.iter().any(|r| match r {
        Redirect::File { op, .. } => {
            let rest = op.trim_start_matches(|ch: char| ch.is_ascii_digit());
            let fd = &op[..op.len() - rest.len()];
            rest.starts_with('<') && matches!(fd, "" | "0")
        }
        Redirect::Heredoc { .. } => true,
    })
}
