//! Walks a lowered script the way the rules will: every simple command, also the ones inside
//! substitutions, heredoc bodies, redirect targets, assignments, loops, branches and functions.

#![allow(dead_code)]

use shellwise::ir::{Elem, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};

/// Every simple command in pre-order: a command, then the commands nested in its words.
pub fn commands(script: &Script) -> Vec<&SimpleCommand> {
    let mut out = Vec::new();
    walk_script(script, &mut out);
    out
}

/// The command names in pre-order; a name that is not static is `<dyn>`, an empty one `<none>`.
pub fn names(script: &Script) -> Vec<String> {
    commands(script).iter().map(|c| name_of(c)).collect()
}

pub fn name_of(c: &SimpleCommand) -> String {
    if c.name.parts.is_empty() {
        "<none>".to_string()
    } else {
        c.canonical.clone().unwrap_or_else(|| "<dyn>".to_string())
    }
}

/// A word as a value shape: literal text as bash sees it, each expansion one marker.
pub fn shape(w: &Word) -> String {
    let mut s = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(t) | WordPart::Glob(t) => s.push_str(t),
            WordPart::Var(_) => s.push('$'),
            WordPart::Subst(_) | WordPart::Block(_) => s.push_str("$()"),
            WordPart::Tilde => s.push('~'),
        }
    }
    s
}

/// One command as `name arg arg …` in value shapes.
pub fn command_shape(c: &SimpleCommand) -> String {
    let mut v = vec![if c.name.parts.is_empty() {
        "<none>".to_string()
    } else {
        shape(&c.name)
    }];
    for (n, w) in &c.assigns {
        v.insert(0, format!("{n}={}", shape(w)));
    }
    v.extend(c.args.iter().map(shape));
    v.join(" ")
}

fn walk_script<'a>(s: &'a Script, out: &mut Vec<&'a SimpleCommand>) {
    for st in &s.stmts {
        walk_stmt(st, out);
    }
}

fn walk_stmt<'a>(st: &'a Stmt, out: &mut Vec<&'a SimpleCommand>) {
    match st {
        Stmt::Pipeline(p) => {
            for e in &p.elems {
                match e {
                    Elem::Cmd(c) => walk_cmd(c, out),
                    Elem::Method(m) => m.args.iter().for_each(|w| walk_word(w, out)),
                    Elem::Expr(w) => walk_word(w, out),
                }
            }
        }
        Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
            walk_script(body, out)
        }
        Stmt::Cond { branches, .. } => branches.iter().for_each(|b| walk_script(b, out)),
    }
}

fn walk_cmd<'a>(c: &'a SimpleCommand, out: &mut Vec<&'a SimpleCommand>) {
    out.push(c);
    for (_, w) in &c.assigns {
        walk_word(w, out);
    }
    walk_word(&c.name, out);
    for w in &c.args {
        walk_word(w, out);
    }
    for r in &c.redirects {
        match r {
            Redirect::File { target, .. } => walk_word(target, out),
            Redirect::Heredoc { body, .. } => walk_word(body, out),
        }
    }
}

fn walk_word<'a>(w: &'a Word, out: &mut Vec<&'a SimpleCommand>) {
    for p in &w.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = p {
            walk_script(s, out);
        }
    }
}
