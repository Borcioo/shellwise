//! The shell-independent IR both parsers lower into. Every node keeps its source span.

use std::collections::{BTreeMap, BTreeSet};

use crate::level::Span;

/// Lowering stops at this nesting depth (blocks, substitutions, nested scripts) and fails closed.
pub const MAX_NESTING: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    pub stmts: Vec<Stmt>,
    pub comments: Vec<Comment>,
    /// `joins[i]`: the operator joining `stmts[i]` to the statement before it (`||` in
    /// `a || { b; }`), for compound statements too. `None` for the first statement, and for any
    /// index past the end: a parser that does not fill it leaves it empty. Read it with `join`.
    pub joins: Vec<Option<ChainOp>>,
}

impl Script {
    /// The operator joining statement `i` to the one before it.
    pub fn join(&self, i: usize) -> Option<ChainOp> {
        self.joins.get(i).copied().flatten()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub text: String,
    pub span: Span,
    /// A comment after code on the same line (the only place the allow marker counts).
    pub trailing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Pipeline(Pipeline),
    Loop {
        body: Script,
        span: Span,
        head: LoopHead,
    },
    Cond {
        branches: Vec<Script>,
        span: Span,
    },
    Func {
        name: String,
        body: Script,
    },
    Block(Script),
}

/// What a loop's header says about when the loop ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopHead {
    /// Once per item of a list, a range or its input (`for x in …`, `foreach`, `switch`).
    Items,
    /// `for ((init; cond; step))`, `for (init; cond; step)`: `open` when the condition is empty.
    Counted { open: bool },
    /// `while`, `until`, `do … while|until`: the first `cond` statements of the body (the last
    /// ones when `at_end`, as in `do … while`) are the condition; `until` ends the loop when the
    /// condition holds.
    Test {
        cond: usize,
        at_end: bool,
        until: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub elems: Vec<Elem>,
    /// The operator joining this pipeline to the next statement, if any.
    pub chain: Option<ChainOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOp {
    /// `;` or a newline
    Seq,
    /// `&&`
    And,
    /// `||`
    Or,
    /// a trailing `&`
    Background,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elem {
    Cmd(SimpleCommand),
    Method(MethodCall),
    Expr(Word),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    pub name: Word,
    /// The name as written (lint rules need the spelling).
    pub typed: String,
    /// The name with aliases resolved for the dialect and OS (`ri` -> `Remove-Item`); `None` when unknown.
    pub canonical: Option<String>,
    pub args: Vec<Word>,
    pub redirects: Vec<Redirect>,
    pub assigns: Vec<(String, Word)>,
    pub span: Span,
    pub in_loop: bool,
    /// The command name is not static (a variable, a substitution, `& $x`).
    pub opaque: bool,
}

/// A .NET method call.
///
/// - Static, `[IO.Directory]::Delete(...)`: `type_name` is the type as written (`IO.Directory`)
///   and `args` are the call's arguments.
/// - Static on an expression, `$t::Delete(...)`: `type_name` is the receiver's text and `args[0]`
///   is the receiver.
/// - Instance, `$x.Delete(...)` or `(Get-Item x).Delete(...)`: `type_name` is empty, since the
///   type is known only at run time, and `args[0]` is the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodCall {
    pub type_name: String,
    pub method: String,
    pub args: Vec<Word>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    File {
        /// The operator as written (`>`, `2>>`, `<`, `*>`, `<<<`).
        op: String,
        target: Word,
        span: Span,
    },
    /// A here-document. An expanding body (unquoted delimiter) holds its `$(…)` as `Subst`
    /// parts; a quoted delimiter gives one literal part.
    Heredoc {
        body: Word,
        expands: bool,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub parts: Vec<WordPart>,
    pub span: Span,
    pub quote: Quote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    None,
    Single,
    Double,
    /// Partly quoted, such as `a"b"`.
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    Literal(String),
    Var(String),
    Subst(Box<Script>),
    Block(Box<Script>),
    Glob(String),
    Tilde,
    /// A separator between the elements of a list argument (PowerShell `a,b`, `'a', $b`,
    /// `-Path:a,b`): the word is one argument PowerShell binds as an array, and the parts between
    /// two separators are one element. Only a real array separator is a `ListSep`; a quoted or
    /// escaped comma (`'a,b'`, `` a`,b ``) stays inside a `Literal`. `Word::quote` describes the
    /// elements' quoting, not whether the word is a list.
    ListSep,
}

impl Word {
    /// The word's text when every part resolves at check time: literals and globs as written,
    /// variables from `env`, `~` from `env`'s home. `None` for a substitution, a script block or
    /// a variable `env` cannot resolve, and for a list (split it on `ListSep` first: its text
    /// is no single value).
    pub fn static_value(&self, env: &EnvView) -> Option<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(s) | WordPart::Glob(s) => out.push_str(s),
                WordPart::Var(name) => out.push_str(env.get(name)?),
                WordPart::Tilde => out.push_str(env.home()?),
                WordPart::Subst(_) | WordPart::Block(_) | WordPart::ListSep => return None,
            }
        }
        Some(out)
    }

    /// True when the word holds a variable, a substitution or a script block.
    pub fn is_dynamic(&self) -> bool {
        self.parts.iter().any(|p| {
            matches!(
                p,
                WordPart::Var(_) | WordPart::Subst(_) | WordPart::Block(_)
            )
        })
    }
}

/// The variables a check may resolve. A name assigned anywhere in the command is dynamic and
/// never resolves, whatever its value in the environment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvView {
    vars: BTreeMap<String, String>,
    dynamic: BTreeSet<String>,
    home: Option<String>,
    /// Names compare ignoring ASCII case (PowerShell).
    fold_case: bool,
    /// Something in the command may have assigned any name (`source`, `eval`, a dynamic name).
    all_dynamic: bool,
}

impl EnvView {
    pub fn new() -> EnvView {
        EnvView::default()
    }

    /// A view whose names compare ignoring ASCII case, as PowerShell's do.
    pub fn case_insensitive() -> EnvView {
        EnvView {
            fold_case: true,
            ..EnvView::default()
        }
    }

    fn key(&self, name: &str) -> String {
        if self.fold_case {
            name.to_ascii_lowercase()
        } else {
            name.to_string()
        }
    }

    pub fn set(&mut self, name: &str, value: &str) {
        self.vars.insert(self.key(name), value.to_string());
    }

    pub fn set_home(&mut self, home: &str) {
        self.home = Some(home.to_string());
    }

    /// Mark a name as assigned in the command: it no longer resolves.
    pub fn mark_dynamic(&mut self, name: &str) {
        self.dynamic.insert(self.key(name));
    }

    /// Mark every name as assigned: nothing resolves any more, `~` included.
    pub fn mark_all_dynamic(&mut self) {
        self.all_dynamic = true;
    }

    /// True when the command may assign `name`.
    pub fn is_assigned(&self, name: &str) -> bool {
        self.all_dynamic || self.dynamic.contains(&self.key(name))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        if self.is_assigned(name) {
            return None;
        }
        self.vars.get(&self.key(name)).map(String::as_str)
    }

    /// The folder `~` stands for; `None` once the command may assign `HOME`.
    pub fn home(&self) -> Option<&str> {
        if self.is_assigned("HOME") {
            return None;
        }
        self.home.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(parts: Vec<WordPart>) -> Word {
        Word {
            parts,
            span: Span::default(),
            quote: Quote::None,
        }
    }

    #[test]
    fn static_value_resolves_literals_vars_and_tilde() {
        let mut env = EnvView::new();
        env.set("D", "build");
        env.set_home("/h");
        let w = word(vec![
            WordPart::Tilde,
            WordPart::Literal("/".into()),
            WordPart::Var("D".into()),
            WordPart::Glob("*".into()),
        ]);
        assert_eq!(w.static_value(&env).as_deref(), Some("/h/build*"));
        assert!(w.is_dynamic());
    }

    #[test]
    fn static_value_refuses_unknown_assigned_and_substituted_parts() {
        let mut env = EnvView::new();
        env.set("D", "build");
        env.mark_dynamic("D");
        let cases = [
            word(vec![WordPart::Var("D".into())]),
            word(vec![WordPart::Var("NOPE".into())]),
            word(vec![WordPart::Tilde]),
            word(vec![WordPart::Subst(Box::default())]),
            word(vec![WordPart::Block(Box::default())]),
        ];
        for w in cases {
            assert_eq!(w.static_value(&env), None, "{w:?}");
            assert!(w.is_dynamic() || w.parts == vec![WordPart::Tilde], "{w:?}");
        }
        assert!(!word(vec![WordPart::Literal("x".into())]).is_dynamic());
    }

    #[test]
    fn a_list_has_no_single_static_value() {
        let w = word(vec![
            WordPart::Literal("C:\\".into()),
            WordPart::ListSep,
            WordPart::Literal("x".into()),
        ]);
        assert_eq!(w.static_value(&EnvView::new()), None);
        assert!(!w.is_dynamic());
    }
}
