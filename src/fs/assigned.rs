//! Names a command gives literal values before it uses them (Ruling 122, item 2): a top-level
//! `X=build` or `$x = 'C:\tmp\x'` (a pwsh list `'a','b'` too) and a top-level loop over a
//! literal list (`for d in a b`, `foreach ($d in 'a','b')`, `foreach ($d in $list)`). Such a
//! name resolves to its values; every other assigned name stays dynamic (`mark_assigned`).
//!
//! A name resolves only when all of these hold, else it stays dynamic:
//! - its one assignment is a statement of its own at the top level (no prefix `X=a cmd`, no
//!   branch, function, loop body, substitution, pipeline element or background `&`), written
//!   `X=` or `$x =` (no `+=`, no index), with a value of literals and names resolved before it;
//! - nothing else in the command assigns it (another assignment, `export`, `read`, a loop, a
//!   `source` or `eval` that may assign anything);
//! - every use of it stands after the assignment (for a loop variable: inside the loop);
//! - it is no name the shell or the guard keeps for itself (`HOME`, `PWD`).

use std::collections::BTreeMap;

use super::resolve::{is_pwd, mark_assigned_except};
use crate::Shell;
use crate::ir::{Elem, EnvView, Pipeline, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::Span;

/// A name with several values: a pwsh list or a loop variable. `within`: the loop, which holds
/// every use of a loop variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    pub name: String,
    pub values: Vec<String>,
    pub within: Option<Span>,
}

/// A name, its values, the offset its uses must follow, the loop holding them, and the span of
/// the statement that assigns it.
type Candidate = (String, Vec<String>, usize, Option<Span>, Span);

/// More values than this and a name stays dynamic: each value is judged on its own.
const MAX_VALUES: usize = 32;

/// Names the shell sets or the guard reads for itself: never resolved from an assignment.
/// `PWD` too, through `resolve::is_pwd`.
const KEPT: [&str; 5] = ["home", "userprofile", "oldpwd", "cdpath", "ifs"];

/// Mark what `script` assigns in `env` as `mark_assigned` does, except the names the command
/// gives literal values first: a name with one value is set in `env`; the names with several
/// are returned.
pub fn resolve_assigned(
    env: &mut EnvView,
    script: &Script,
    command: &str,
    shell: Shell,
) -> Vec<Assigned> {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    let key = |n: &str| {
        let n = n.trim_start_matches('$');
        if pwsh {
            n.to_ascii_lowercase()
        } else {
            n.to_string()
        }
    };
    // Candidates, in order: each value is read with the names resolved before it.
    let mut known = env.clone();
    let mut found: Vec<Candidate> = Vec::new();
    for st in &script.stmts {
        match st {
            Stmt::Pipeline(p) => {
                if let Some((c, name, value)) = plain_assignment(p, command, pwsh) {
                    let values: Option<Vec<String>> = value
                        .parts
                        .split(|p| *p == WordPart::ListSep)
                        .map(|parts| {
                            Word {
                                parts: parts.to_vec(),
                                span: value.span,
                                quote: value.quote,
                            }
                            .static_value(&known)
                        })
                        .collect();
                    // A pwsh list (`'a','b'`, `@('a', 'b')`) is lowered as an expression: read
                    // its text.
                    let values = values.or_else(|| {
                        let text = command.get(value.span.start..value.span.end)?;
                        (pwsh && (text.contains(',') || text.starts_with("@(")))
                            .then(|| list_values(text, true))
                            .flatten()
                    });
                    let values = values.filter(|v| !v.is_empty() && v.len() <= MAX_VALUES);
                    if let Some(values) = values {
                        if let [one] = values.as_slice() {
                            known.set(&name, one);
                        }
                        found.push((name, values, c.span.end, None, c.span));
                    }
                }
            }
            Stmt::Loop { span, .. } => {
                if let Some((name, list)) = loop_header(command, *span, pwsh)
                    && let Some(values) = loop_values(&list, &known, &found, &key, pwsh)
                {
                    found.push((name, values, span.start, Some(*span), *span));
                }
            }
            _ => {}
        }
    }
    let skip: Vec<Span> = found
        .iter()
        .filter(|f| f.3.is_none())
        .map(|f| f.4)
        .collect();
    // Marked with the values in sight: `Remove-Item $d` may name a drive path only when `$d`
    // cannot be read, so a resolved `$d` marks nothing (a list or loop name by its first value).
    for (name, values, ..) in &found {
        if let Some(first) = values.first() {
            env.set(name, first);
        }
    }
    mark_assigned_except(env, script, command, &skip);
    // Every assignment of each name anywhere, and the earliest use of each.
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    let mut uses: Vec<(String, Span)> = Vec::new();
    each_command(script, &mut |c| {
        for (n, _) in &c.assigns {
            *count.entry(key(n)).or_default() += 1;
        }
    });
    each_loop(script, &mut |span| {
        if let Some((n, _)) = loop_header(command, span, pwsh) {
            *count.entry(key(&n)).or_default() += 1;
        }
    });
    each_word(script, &mut |w| {
        for p in &w.parts {
            if let WordPart::Var(n) = p {
                uses.push((key(n), w.span));
            }
        }
    });
    let mut multi = Vec::new();
    for (name, values, from, within, _) in found {
        let k = key(&name);
        let ok = count.get(&k) == Some(&1)
            && !env.is_assigned(&name)
            && !KEPT.contains(&k.to_ascii_lowercase().trim_start_matches("env:"))
            && !is_pwd(&name, shell)
            && uses
                .iter()
                .filter(|(n, _)| *n == k)
                .all(|(_, s)| match within {
                    Some(l) => s.start >= l.start && s.end <= l.end,
                    None => s.start >= from,
                });
        if !ok {
            env.mark_dynamic(&name);
            continue;
        }
        match (values.as_slice(), within) {
            ([one], None) => env.set(&name, one),
            // Read only where a target writes it out (`with_value` in the delete rule).
            _ => {
                env.mark_dynamic(&name);
                multi.push(Assigned {
                    name,
                    values,
                    within,
                })
            }
        }
    }
    multi
}

/// `X=value` or `$x = value` alone in its statement, written so: `(command, name, value)`.
fn plain_assignment<'a>(
    p: &'a Pipeline,
    command: &str,
    pwsh: bool,
) -> Option<(&'a SimpleCommand, String, &'a Word)> {
    let [Elem::Cmd(c)] = p.elems.as_slice() else {
        return None;
    };
    if p.chain == Some(crate::ir::ChainOp::Background)
        || c.opaque
        || !c.args.is_empty()
        || !c.redirects.is_empty()
        || !c.typed.is_empty()
    {
        return None;
    }
    let [(name, value)] = c.assigns.as_slice() else {
        return None;
    };
    let name = name.trim_start_matches('$').to_string();
    let text = command.get(c.span.start..c.span.end)?;
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
    found: &[Candidate],
    key: &dyn Fn(&str) -> String,
    pwsh: bool,
) -> Option<Vec<String>> {
    let list = list.trim();
    if let Some(var) = list.strip_prefix('$') {
        if !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        if let Some(f) = found
            .iter()
            .rev()
            .find(|f| f.3.is_none() && key(&f.0) == key(var))
        {
            return Some(f.1.clone());
        }
        return known.get(var).map(|v| vec![v.to_string()]);
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
