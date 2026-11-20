//! Names a command gives literal values (Ruling 122, item 2): a top-level `X=build` or
//! `$x = 'C:\tmp\x'` (a pwsh list `'a','b'` too) and a top-level loop over a literal list
//! (`for d in a b`, `foreach ($d in 'a','b')`, `foreach ($d in $list)`). Such a name holds its
//! values where it is still valid; every other assigned name stays dynamic (`mark_assigned`).
//!
//! Validity is decided per name before any value is passed on:
//! - the assignment is a statement of its own at the top level (no prefix `X=a cmd`, no branch,
//!   function, loop body, subshell, substitution, pipeline element or background `&`), written
//!   `X=` or `$x =` (no `+=`, no index), with a value of literals and of names valid at every
//!   use (a value built from a name that is reassigned anywhere is no literal);
//! - no assignment of the name stands before it, and nothing else in the command marks it
//!   (`export`, `read`, a `source` or `eval` that may assign anything);
//! - it holds from the end of its statement up to the next assignment of the name (any kind,
//!   anywhere), never inside a loop that assigns the name again; a loop variable holds inside
//!   its loop only;
//! - it is no name the shell or the guard keeps for itself (`HOME`, `PWD`).
//!
//! A use where the name does not hold sees it dynamic, which the empty-expansion rule reads as
//! empty.

use super::resolve::{is_pwd, mark_assigned_except};
use crate::ir::{ChainOp, Elem, EnvView, Pipeline, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::Span;
use crate::{Os, Shell};

/// `c` is a builtin whose `NAME=value` operand assigns like a plain `NAME=value`: its program
/// row says `assigns_operand` (`export`).
fn assigns_operand(c: &SimpleCommand, shell: Shell, os: Os) -> bool {
    !c.typed.is_empty()
        && crate::programs::lookup(&c.typed, shell, os)
            .is_some_and(|p| p.extra.get("assigns_operand") == Some(&toml::Value::Boolean(true)))
}

/// A name with literal values that holds only in part of the command, or with several values
/// (a pwsh list, a loop variable): a target that uses it where it holds is judged once per
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    pub name: String,
    pub values: Vec<String>,
    /// It holds from this offset (the end of its assignment, or its loop's start)...
    pub from: usize,
    /// ...up to the next assignment of the name.
    pub until: usize,
    /// A loop variable: the loop.
    pub within: Option<Span>,
    /// Loops that assign the name again: a later pass sees another value.
    pub blocked: Vec<Span>,
}

impl Assigned {
    /// The name holds these values for a use at `s`.
    pub fn holds_at(&self, s: Span) -> bool {
        let inside = |l: &Span| s.start >= l.start && s.end <= l.end;
        s.start >= self.from
            && s.start < self.until
            && self.within.as_ref().is_none_or(inside)
            && !self.blocked.iter().any(inside)
    }
}

/// A top-level assignment or literal loop: the name, its values, where it starts to hold, the
/// loop, the offset of its own assignment, and the statement `mark_assigned` skips.
struct Candidate {
    name: String,
    values: Vec<String>,
    from: usize,
    within: Option<Span>,
    at: usize,
    stmt: Option<Span>,
    /// No `&&` or `||` before it: it runs whenever the statements before it ran.
    unconditional: bool,
}

/// More values than this and a name stays dynamic: each value is judged on its own.
const MAX_VALUES: usize = 32;

/// Names the shell sets or the guard reads for itself: never resolved from an assignment.
/// `PWD` too, through `resolve::is_pwd`.
const KEPT: [&str; 5] = ["home", "userprofile", "oldpwd", "cdpath", "ifs"];

/// Mark what `script` assigns in `env` as `mark_assigned` does, except the names the command
/// gives literal values: a name valid at every use with one value is set in `env`; the others
/// that hold somewhere are returned (and stay dynamic in `env`).
pub fn resolve_assigned(
    env: &mut EnvView,
    script: &Script,
    command: &str,
    shell: Shell,
    os: Os,
) -> Vec<Assigned> {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    let declares = |c: &SimpleCommand| assigns_operand(c, shell, os);
    let key = |n: &str| {
        let n = n.trim_start_matches('$');
        if pwsh {
            n.to_ascii_lowercase()
        } else {
            n.to_string()
        }
    };
    // Every assignment of each name anywhere (by offset), every loop, every use.
    let mut events: Vec<(String, usize)> = Vec::new();
    let mut loops: Vec<Span> = Vec::new();
    let mut uses: Vec<(String, Span)> = Vec::new();
    each_command(script, &mut |c| {
        for (n, _) in &c.assigns {
            events.push((key(n), c.span.start));
        }
    });
    each_loop(script, &mut |span| {
        loops.push(span);
        if let Some((n, _)) = loop_header(command, span, pwsh) {
            events.push((key(&n), span.start));
        }
    });
    each_word(script, &mut |w| {
        for p in &w.parts {
            if let WordPart::Var(n) = p {
                uses.push((key(n), w.span));
            }
        }
    });
    // Which names something else marks: a pass with every candidate's literal in sight, so a
    // `Remove-Item $d` with a literal `$d` marks no drive path.
    let mut naive_known = env.clone();
    let naive = candidates(
        script,
        command,
        pwsh,
        &declares,
        &key,
        &mut naive_known,
        &mut |c, known| {
            if let [one] = c.values.as_slice() {
                known.set(&c.name, one);
            }
            c.within.is_none().then(|| Assigned {
                name: c.name.clone(),
                values: c.values.clone(),
                from: c.from,
                until: usize::MAX,
                within: None,
                blocked: Vec::new(),
            })
        },
    );
    let mut probe = env.clone();
    for c in &naive {
        probe.set(&c.name, &c.values[0]);
    }
    let skip: Vec<Span> = naive.iter().filter_map(|c| c.stmt).collect();
    // Plain assignments anywhere are the events above, placed by offset: the probe skips them.
    let mut plain: Vec<Span> = Vec::new();
    each_command(script, &mut |c| {
        let bare = c.typed.is_empty() && c.args.is_empty();
        if (bare || declares(c)) && !c.opaque && !c.assigns.is_empty() {
            plain.push(c.span);
        }
    });
    mark_assigned_except(&mut probe, script, command, &plain);
    // Top-level plain assignments of any value whose statement assigns nothing else: one a later
    // unconditional assignment replaces is skipped by the final marks (`X=$(pwd); X=/`). In
    // PowerShell an expression in the value runs in place and may assign other names.
    let mut top_plain: Vec<(String, usize, Span)> = Vec::new();
    for st in &script.stmts {
        let Stmt::Pipeline(p) = st else { continue };
        let Some((c, name, value)) = plain_assignment(p, command, pwsh, &declares) else {
            continue;
        };
        let only_itself = value.parts.iter().all(|part| match part {
            WordPart::Var(n) => !n.contains('='),
            WordPart::Subst(_) => !pwsh,
            _ => true,
        });
        if only_itself {
            top_plain.push((key(&name), c.span.start, c.span));
        }
    }
    let mut replaced: Vec<Span> = Vec::new();
    // In order, each value built only from names valid at every use.
    let mut everywhere: Vec<String> = Vec::new();
    let mut held: Vec<Assigned> = Vec::new();
    let mut known = env.clone();
    candidates(
        script,
        command,
        pwsh,
        &declares,
        &key,
        &mut known,
        &mut |c, known| {
            let k = key(&c.name);
            let mine: Vec<usize> = events
                .iter()
                .filter(|(n, _)| *n == k)
                .map(|(_, at)| *at)
                .collect();
            // Assignments before it are allowed when each is a top-level one (a literal one or
            // loop, or a `top_plain` statement) and this one runs whatever came before it (no
            // `&&` or `||` in front): the name holds this value from here on. One that may run
            // later (a function body) does not let it hold.
            let earlier_top = mine.iter().filter(|at| **at < c.at).all(|at| {
                naive.iter().any(|n| n.at == *at && key(&n.name) == k)
                    || top_plain.iter().any(|(n, t, _)| *t == *at && *n == k)
            });
            let replaces = c.unconditional && earlier_top;
            if (mine.iter().any(|at| *at < c.at) && !replaces)
                || probe.is_assigned(&c.name)
                || KEPT.contains(&k.to_ascii_lowercase().trim_start_matches("env:"))
                || is_pwd(&c.name, shell)
            {
                return None;
            }
            let later: Vec<usize> = mine.iter().copied().filter(|at| *at > c.at).collect();
            let a = Assigned {
                name: c.name.clone(),
                values: c.values.clone(),
                from: c.from,
                until: later.iter().copied().min().unwrap_or(usize::MAX),
                within: c.within,
                blocked: loops
                    .iter()
                    .filter(|l| Some(**l) != c.within)
                    .filter(|l| later.iter().any(|at| *at >= l.start && *at < l.end))
                    .copied()
                    .collect(),
            };
            let mine_used: Vec<Span> = uses
                .iter()
                .filter(|(n, _)| *n == k)
                .map(|(_, s)| *s)
                .collect();
            if !mine_used.iter().any(|s| a.holds_at(*s)) {
                return None;
            }
            // Set in `env` (and usable in later values) only when never assigned again: `env` is
            // one view for the whole command, so a name reassigned later holds where `holds_at`
            // says and nowhere else.
            if a.values.len() == 1
                && a.within.is_none()
                && a.until == usize::MAX
                && mine_used.iter().all(|s| a.holds_at(*s))
            {
                known.set(&a.name, &a.values[0]);
                replaced.extend(
                    top_plain
                        .iter()
                        .filter(|(n, at, _)| *n == k && *at < c.at)
                        .map(|(_, _, s)| *s),
                );
                everywhere.push(k);
            } else {
                held.push(a.clone());
            }
            Some(a)
        },
    );
    // The final marks, with the literals in sight; then every candidate name that is not valid
    // at every use is dynamic (a held name is a candidate too, so it stays dynamic in `env`).
    for c in &naive {
        env.set(&c.name, &c.values[0]);
    }
    let skip: Vec<Span> = skip.into_iter().chain(replaced).collect();
    mark_assigned_except(env, script, command, &skip);
    for c in &naive {
        if !everywhere.contains(&key(&c.name)) {
            env.mark_dynamic(&c.name);
        }
    }
    held
}

/// The top-level candidates in order, each offered to `accept`, which may update `known` (the
/// names a later value may be built from) and returns the name's reading when it takes it; a
/// loop over `$list` reads a list taken before it, where it holds at the loop.
fn candidates(
    script: &Script,
    command: &str,
    pwsh: bool,
    declares: &dyn Fn(&SimpleCommand) -> bool,
    key: &dyn Fn(&str) -> String,
    known: &mut EnvView,
    accept: &mut dyn FnMut(&Candidate, &mut EnvView) -> Option<Assigned>,
) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut taken: Vec<Assigned> = Vec::new();
    // The operator that joins the statement before to this one.
    let mut after: Option<ChainOp> = None;
    for st in &script.stmts {
        let unconditional = !matches!(after, Some(ChainOp::And | ChainOp::Or));
        // The IR keeps no joiner after a compound statement (`{ …; } && X=v`): it may be one.
        after = match st {
            Stmt::Pipeline(p) => p.chain,
            _ => Some(ChainOp::And),
        };
        let c = match st {
            Stmt::Pipeline(p) => {
                plain_assignment(p, command, pwsh, declares).and_then(|(c, name, value)| {
                    let values: Option<Vec<String>> = value
                        .parts
                        .split(|p| *p == WordPart::ListSep)
                        .map(|parts| {
                            Word {
                                parts: parts.to_vec(),
                                span: value.span,
                                quote: value.quote,
                            }
                            .static_value(known)
                        })
                        .collect();
                    // A pwsh list (`'a','b'`, `@('a', 'b')`) is lowered as an expression: read its
                    // text.
                    let values = values.or_else(|| {
                        let text = command.get(value.span.start..value.span.end)?;
                        (pwsh && (text.contains(',') || text.starts_with("@(")))
                            .then(|| list_values(text, true))
                            .flatten()
                    });
                    values
                        .filter(|v| !v.is_empty() && v.len() <= MAX_VALUES)
                        .map(|values| Candidate {
                            name,
                            values,
                            from: c.span.end,
                            within: None,
                            at: c.span.start,
                            stmt: Some(c.span),
                            unconditional,
                        })
                })
            }
            Stmt::Loop { span, .. } => {
                loop_header(command, *span, pwsh).and_then(|(name, list)| {
                    let at_loop = Span {
                        start: span.start,
                        end: span.start,
                    };
                    let lists = |var: &str| {
                        taken
                            .iter()
                            .rev()
                            .find(|a| key(&a.name) == key(var) && a.holds_at(at_loop))
                            .map(|a| a.values.clone())
                    };
                    loop_values(&list, known, &lists, pwsh).map(|values| Candidate {
                        name,
                        values,
                        from: span.start,
                        within: Some(*span),
                        at: span.start,
                        stmt: None,
                        unconditional,
                    })
                })
            }
            _ => None,
        };
        if let Some(c) = c {
            if let Some(a) = accept(&c, known) {
                taken.push(a);
            }
            out.push(c);
        }
    }
    out
}

/// `X=value` or `$x = value` alone in its statement, or the one operand of a builtin that
/// assigns it (`export X=value`), written so: `(command, name, value)`.
fn plain_assignment<'a>(
    p: &'a Pipeline,
    command: &str,
    pwsh: bool,
    declares: &dyn Fn(&SimpleCommand) -> bool,
) -> Option<(&'a SimpleCommand, String, &'a Word)> {
    let [Elem::Cmd(c)] = p.elems.as_slice() else {
        return None;
    };
    // `export X=v`: one literal operand, the assignment itself (no option such as `-n`).
    let operand = match c.args.as_slice() {
        [w] if declares(c) => Some(w.span),
        _ => None,
    };
    let bare = c.args.is_empty() && c.typed.is_empty();
    if p.chain == Some(ChainOp::Background)
        || c.opaque
        || !(bare || operand.is_some())
        || !c.redirects.is_empty()
    {
        return None;
    }
    let [(name, value)] = c.assigns.as_slice() else {
        return None;
    };
    let name = name.trim_start_matches('$').to_string();
    let span = operand.unwrap_or(c.span);
    let text = command.get(span.start..span.end)?;
    // Written as a plain `=`: no `+=`, no index, no `==`, no Bash array.
    let plain = if pwsh {
        let t = text.strip_prefix('$')?;
        let head = t.get(..name.len())?;
        let after = t[name.len()..].trim_start().strip_prefix('=');
        head.eq_ignore_ascii_case(&name) && after.is_some_and(|a| !a.starts_with('='))
    } else {
        let after = text
            .strip_prefix(name.as_str())
            .and_then(|t| t.strip_prefix('='));
        after.is_some_and(|a| !a.starts_with('('))
    };
    plain.then_some((c, name, value))
}

/// The variable and the list text of a loop's header: `for NAME in …; do` (Bash) or
/// `foreach ($NAME in …)` (PowerShell). `None` for any other loop.
fn loop_header(command: &str, span: Span, pwsh: bool) -> Option<(String, String)> {
    let text = command.get(span.start..span.end)?;
    if pwsh {
        let t = strip_word_ci(text, "foreach")?.trim_start();
        let t = t.strip_prefix('(')?.trim_start().strip_prefix('$')?;
        let (name, t) = ident(t)?;
        let t = strip_word_ci(t.trim_start(), "in")?;
        let close = closing_paren(t)?;
        Some((name, t[..close].trim().to_string()))
    } else {
        let t = text.strip_prefix("for")?;
        if !t.starts_with([' ', '\t']) {
            return None;
        }
        let (name, t) = ident(t.trim_start())?;
        let t = t.trim_start().strip_prefix("in")?;
        if !t.starts_with([' ', '\t']) {
            return None;
        }
        let end = t.find([';', '\n']).unwrap_or(t.len());
        Some((name, t[..end].trim().to_string()))
    }
}

/// A variable name at the start of `s`, and the text after it.
fn ident(s: &str) -> Option<(String, &str)> {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    (end > 0).then(|| (s[..end].to_string(), &s[end..]))
}

/// `text` without its leading `word` (any case), which must end there.
fn strip_word_ci<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let head = text.get(..word.len())?;
    let rest = &text[word.len()..];
    (head.eq_ignore_ascii_case(word)
        && !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(rest)
}

/// The byte offset of the `)` closing a pwsh loop header, outside quotes.
fn closing_paren(t: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut depth = 0usize;
    for (i, c) in t.char_indices() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') if depth == 0 => return Some(i),
            (None, ')') => depth -= 1,
            _ => {}
        }
    }
    None
}

/// The literal values of a loop list: Bash words, a pwsh list of quoted strings (in `@( )` or
/// not), or one pwsh variable resolved before the loop.
fn loop_values(
    list: &str,
    known: &EnvView,
    lists: &dyn Fn(&str) -> Option<Vec<String>>,
    pwsh: bool,
) -> Option<Vec<String>> {
    let list = list.trim();
    if let Some(var) = list.strip_prefix('$') {
        if !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        return lists(var).or_else(|| known.get(var).map(|v| vec![v.to_string()]));
    }
    list_values(list, pwsh)
}

/// The literal items of a list: Bash words, or (`pwsh`) quoted strings, in `@( )` or not,
/// separated by `,`. `None` when an item is anything else.
fn list_values(list: &str, pwsh: bool) -> Option<Vec<String>> {
    let list = list.trim();
    let list = list
        .strip_prefix("@(")
        .and_then(|l| l.strip_suffix(')'))
        .unwrap_or(list);
    let mut values = Vec::new();
    let mut rest = list.trim();
    while !rest.is_empty() {
        let (value, after) = match rest.chars().next()? {
            q @ ('\'' | '"') => {
                let end = rest[1..].find(q)? + 1;
                let v = &rest[1..end];
                if q == '"' && v.contains(['$', '`']) {
                    return None;
                }
                (v.to_string(), &rest[end + 1..])
            }
            // A bare word in a pwsh expression runs a command.
            _ if pwsh => return None,
            _ => {
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == ',')
                    .unwrap_or(rest.len());
                let v = &rest[..end];
                let plain = v
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-/\\:+@%=".contains(c));
                if !plain {
                    return None;
                }
                (v.to_string(), &rest[end..])
            }
        };
        values.push(value);
        rest = after.trim_start();
        rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
    }
    (!values.is_empty() && values.len() <= MAX_VALUES).then_some(values)
}

fn each_command(s: &Script, f: &mut dyn FnMut(&SimpleCommand)) {
    each_word_or_command(s, &mut |_| {}, f, &mut |_| {});
}

fn each_loop(s: &Script, f: &mut dyn FnMut(Span)) {
    each_word_or_command(s, &mut |_| {}, &mut |_| {}, f);
}

fn each_word(s: &Script, f: &mut dyn FnMut(&Word)) {
    each_word_or_command(s, f, &mut |_| {}, &mut |_| {});
}

/// Every word, command and loop of `s`, nested bodies and substitutions included.
fn each_word_or_command(
    s: &Script,
    word: &mut dyn FnMut(&Word),
    cmd: &mut dyn FnMut(&SimpleCommand),
    lp: &mut dyn FnMut(Span),
) {
    fn in_word(
        w: &Word,
        word: &mut dyn FnMut(&Word),
        cmd: &mut dyn FnMut(&SimpleCommand),
        lp: &mut dyn FnMut(Span),
    ) {
        word(w);
        for p in &w.parts {
            if let WordPart::Subst(s) | WordPart::Block(s) = p {
                each_word_or_command(s, word, cmd, lp);
            }
        }
    }
    for st in &s.stmts {
        match st {
            Stmt::Pipeline(p) => {
                for e in &p.elems {
                    match e {
                        Elem::Cmd(c) => {
                            cmd(c);
                            let words = std::iter::once(&c.name)
                                .chain(&c.args)
                                .chain(c.assigns.iter().map(|(_, w)| w))
                                .chain(c.redirects.iter().map(|r| match r {
                                    crate::ir::Redirect::File { target, .. } => target,
                                    crate::ir::Redirect::Heredoc { body, .. } => body,
                                }));
                            for w in words {
                                in_word(w, word, cmd, lp);
                            }
                        }
                        Elem::Method(m) => {
                            for w in &m.args {
                                in_word(w, word, cmd, lp);
                            }
                        }
                        Elem::Expr(w) => in_word(w, word, cmd, lp),
                    }
                }
            }
            Stmt::Loop { body, span } => {
                lp(*span);
                each_word_or_command(body, word, cmd, lp);
            }
            Stmt::Cond { branches, .. } => {
                for b in branches {
                    each_word_or_command(b, word, cmd, lp);
                }
            }
            Stmt::Func { body, .. } | Stmt::Block(body) => {
                each_word_or_command(body, word, cmd, lp);
            }
        }
    }
}
