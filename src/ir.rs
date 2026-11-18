//! The shell-independent IR both parsers lower into. Every node keeps its source span.

use std::collections::{BTreeMap, BTreeSet};

use crate::level::Span;

/// Lowering stops at this nesting depth (blocks, substitutions, nested scripts) and fails closed.
pub const MAX_NESTING: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    pub stmts: Vec<Stmt>,
    pub comments: Vec<Comment>,
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
    Loop { body: Script, span: Span },
    Cond { branches: Vec<Script>, span: Span },
    Func { name: String, body: Script },
    Block(Script),
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

/// A static .NET call such as `[IO.Directory]::Delete(...)`.
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
}

impl Word {
    /// The word's text when every part resolves at check time: literals and globs as written,
    /// variables from `env`, `~` from `env`'s home. `None` for a substitution, a script block or
    /// a variable `env` cannot resolve.
    pub fn static_value(&self, env: &EnvView) -> Option<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(s) | WordPart::Glob(s) => out.push_str(s),
                WordPart::Var(name) => out.push_str(env.get(name)?),
                WordPart::Tilde => out.push_str(env.home()?),
                WordPart::Subst(_) | WordPart::Block(_) => return None,
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
}

impl EnvView {
    pub fn new() -> EnvView {
        EnvView::default()
    }

    pub fn set(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_string(), value.to_string());
    }

    pub fn set_home(&mut self, home: &str) {
        self.home = Some(home.to_string());
    }

    /// Mark a name as assigned in the command: it no longer resolves.
    pub fn mark_dynamic(&mut self, name: &str) {
        self.dynamic.insert(name.to_string());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        if self.dynamic.contains(name) {
            return None;
        }
        self.vars.get(name).map(String::as_str)
    }

    pub fn home(&self) -> Option<&str> {
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
}
