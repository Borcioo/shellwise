//! Bash: brush-parser's AST lowered to the IR.
//!
//! Every command bash would run becomes a `SimpleCommand`, also the ones inside `$(…)`, backticks,
//! process substitutions, parameter expansions, arithmetic and expanding heredoc bodies (as `Subst`
//! parts of the word that holds them). Text the parser cannot read is an error, never a partial
//! script.
//!
//! brush-parser recurses once per nesting level and a deep input overflows the stack, which aborts
//! the process with no verdict. So the whole parse runs on its own thread whose stack is sized from
//! an upper bound of the nesting the text can hold, and lowering stops at `ir::MAX_NESTING`.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::thread;

use brush_parser::ast::{self, SourceLocation};
use brush_parser::word::{
    self, Parameter, ParameterExpr, TildeExpr, WordPiece, WordPieceWithSource,
};
use brush_parser::{ParserOptions, SourceSpan, Token, TokenizerError};

use super::{ParseError, QuoteKind};
use crate::BashProfile;
use crate::ir::{
    ChainOp, Comment, Elem, EnvView, MAX_NESTING, Pipeline, Quote, Redirect, Script, SimpleCommand,
    Stmt, Word, WordPart,
};
use crate::level::Span;

/// Stack the parser thread starts with, before any nesting.
const BASE_STACK: usize = 2 << 20;

/// Stack per possible nesting level: about three times the most brush-parser and this lowering
/// were measured to use per level (a `case` or `{ …; }` level, unoptimised build).
const STACK_PER_LEVEL: usize = if cfg!(debug_assertions) {
    64 << 10
} else {
    16 << 10
};

/// A text whose bound needs more stack than this is refused as too deeply nested.
const MAX_STACK: usize = 1 << 30;

/// Nested texts are parsed again, each on its own; all of them together may be at most this many
/// times the command's length, so a deep nesting cannot make parsing quadratic.
const REPARSE_FACTOR: usize = 32;

/// Operators the grammar recurses on without opening a bracket or a keyword (`[[ ! ! … ]]`).
const RECURSING_OPERATORS: &[&str] = &["!"];

/// Words that open a nesting level in the grammar.
const OPENING_KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "while", "until", "for", "select", "do", "case", "function",
    "coproc",
];

pub fn parse(src: &str, profile: BashProfile) -> Result<Script, ParseError> {
    let whole = Span {
        start: 0,
        end: src.len(),
    };
    // Each substitution level parses the text inside it again, so a deep nesting costs time
    // quadratic in its depth before lowering reaches the limit. Brackets balanced this deep are
    // refused up front; a deep nesting this count misses still stops at the limit in lowering.
    if bracket_depth(src) > MAX_NESTING {
        return Err(error(
            whole,
            &format!("brackets nested deeper than {MAX_NESTING} levels"),
            None,
        ));
    }
    let stack = BASE_STACK.saturating_add(nesting_bound(src).saturating_mul(STACK_PER_LEVEL));
    if stack > MAX_STACK {
        return Err(error(whole, "nesting too deep to parse safely", None));
    }
    let owned = src.to_string();
    let worker = thread::Builder::new()
        .name("bash-parse".into())
        .stack_size(stack)
        .spawn(move || {
            let lower = Lower {
                profile,
                opts: ParserOptions::default(),
                reparse_budget: Cell::new(owned.len().saturating_mul(REPARSE_FACTOR)),
            };
            let mut script = lower.text(&owned, Origin::Exact(0), 0)?;
            mark_tainted_arithmetic(&mut script);
            Ok(script)
        });
    match worker {
        Err(_) => Err(error(whole, "the parser thread did not start", None)),
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|_| Err(error(whole, "the parser panicked", None))),
    }
}

/// An upper bound of the nesting depth `src` can hold: every bracket, quote, opening keyword and
/// recursing operator counts, whether or not it nests.
fn nesting_bound(src: &str) -> usize {
    let brackets = src
        .bytes()
        .filter(|b| matches!(b, b'(' | b'{' | b'[' | b'`' | b'"'))
        .count();
    let keywords = src
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| OPENING_KEYWORDS.contains(w))
        .count();
    let operators: usize = RECURSING_OPERATORS
        .iter()
        .map(|op| src.matches(op).count())
        .sum();
    // Inside `[[ … ]]` the test grammar nests `&&` and `||` too.
    let test_operators: usize = src
        .split("[[")
        .skip(1)
        .map(|after| {
            let test = after.split("]]").next().unwrap_or_default();
            test.matches("&&").count() + test.matches("||").count()
        })
        .sum();
    brackets + keywords + operators + test_operators
}

/// The deepest run of open brackets, quotes ignored.
fn bracket_depth(src: &str) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    for b in src.bytes() {
        match b {
            b'(' | b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b')' | b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn error(span: Span, message: &str, unclosed: Option<QuoteKind>) -> ParseError {
    ParseError {
        span,
        message: message.to_string(),
        unclosed,
    }
}

/// Where a text being parsed sits in the original command.
#[derive(Clone, Copy)]
enum Origin {
    /// The text is the original's bytes from this offset on.
    Exact(usize),
    /// The text was rewritten (backticks unescaped, an arithmetic expression): every span inside it
    /// is the span of the construct that holds it.
    Inexact(Span),
}

impl Origin {
    fn span(self, start: usize, end: usize) -> Span {
        match self {
            Origin::Exact(base) => Span {
                start: base + start,
                end: base + end,
            },
            Origin::Inexact(s) => s,
        }
    }

    fn shift(self, by: usize) -> Origin {
        match self {
            Origin::Exact(base) => Origin::Exact(base + by),
            inexact => inexact,
        }
    }
}

/// One text being parsed: the source, its origin and the byte offset of each character
/// (brush-parser counts characters).
struct Text<'a> {
    src: &'a str,
    origin: Origin,
    char_bytes: Vec<usize>,
}

impl Text<'_> {
    fn byte(&self, char_index: usize) -> usize {
        self.char_bytes
            .get(char_index)
            .copied()
            .unwrap_or(self.src.len())
    }

    fn span(&self, s: &SourceSpan) -> Span {
        self.origin
            .span(self.byte(s.start.index), self.byte(s.end.index))
    }

    fn whole(&self) -> Span {
        self.origin.span(0, self.src.len())
    }

    /// The local byte offset of a word when its value is the text's bytes at its location.
    fn verbatim_start(&self, value: &str, loc: Option<&SourceSpan>) -> Option<usize> {
        let start = self.byte(loc?.start.index);
        (self.src.get(start..start + value.len()) == Some(value)).then_some(start)
    }
}

#[derive(Clone, Copy)]
struct Cx {
    in_loop: bool,
    depth: usize,
}

impl Cx {
    fn deeper(self, span: Span) -> Result<Cx, ParseError> {
        let depth = self.depth + 1;
        if depth > MAX_NESTING {
            return Err(error(
                span,
                &format!("nesting deeper than {MAX_NESTING} levels"),
                None,
            ));
        }
        Ok(Cx { depth, ..self })
    }

    fn looping(self) -> Cx {
        Cx {
            in_loop: true,
            ..self
        }
    }
}

struct Lower {
    profile: BashProfile,
    opts: ParserOptions,
    /// Bytes of nested text (inside substitutions) still allowed to be parsed again.
    reparse_budget: Cell<usize>,
}

impl Lower {
    /// Take `len` bytes of nested text from the budget.
    fn charge(&self, len: usize, span: Span) -> Result<(), ParseError> {
        let left = self.reparse_budget.get();
        if len > left {
            return Err(error(span, "nested text too large to parse in time", None));
        }
        self.reparse_budget.set(left - len);
        Ok(())
    }

    /// Parse and lower one text (the command, or the inside of a substitution).
    fn text(&self, src: &str, origin: Origin, depth: usize) -> Result<Script, ParseError> {
        let t = Text {
            src,
            origin,
            char_bytes: src
                .char_indices()
                .map(|(b, _)| b)
                .chain([src.len()])
                .collect(),
        };
        // `depth` comes from `Cx::deeper`, which refuses a level past the limit.
        if depth > 0 {
            self.charge(src.len(), t.whole())?;
        }
        let tokens = brush_parser::tokenize_str_with_options(src, &self.opts.tokenizer_options())
            .map_err(|e| tokenizer_error(&t, &e))?;
        let program = brush_parser::parse_tokens(&tokens, &self.opts).map_err(|e| {
            let span = match &e {
                brush_parser::ParseError::ParsingNear(pos) => {
                    let start = t.byte(pos.index);
                    t.origin.span(start, src.len())
                }
                _ => t.origin.span(src.len(), src.len()),
            };
            error(span, &format!("bash: {e}"), None)
        })?;
        let cx = Cx {
            in_loop: false,
            depth,
        };
        let mut out = Acc::default();
        for list in &program.complete_commands {
            self.list(&t, list, cx, &mut out)?;
        }
        Ok(out.finish(comments(&t, &tokens)))
    }

    fn list(
        &self,
        t: &Text,
        list: &ast::CompoundList,
        cx: Cx,
        out: &mut Acc,
    ) -> Result<(), ParseError> {
        for ast::CompoundListItem(and_or, sep) in &list.0 {
            let last = match sep {
                ast::SeparatorOperator::Async => ChainOp::Background,
                ast::SeparatorOperator::Sequence => ChainOp::Seq,
            };
            let mut pipelines = vec![&and_or.first];
            let mut ops = Vec::new();
            for next in &and_or.additional {
                match next {
                    ast::AndOr::And(p) => {
                        ops.push(ChainOp::And);
                        pipelines.push(p);
                    }
                    ast::AndOr::Or(p) => {
                        ops.push(ChainOp::Or);
                        pipelines.push(p);
                    }
                }
            }
            ops.push(last);
            for (p, op) in pipelines.into_iter().zip(ops) {
                out.push(self.pipeline(t, p, op, cx)?, op);
            }
        }
        Ok(())
    }

    /// A body: a list one level deeper.
    fn body(&self, t: &Text, list: &ast::CompoundList, cx: Cx) -> Result<Script, ParseError> {
        let span = list.location().map_or(t.whole(), |l| t.span(&l));
        let mut out = Acc::default();
        self.list(t, list, cx.deeper(span)?, &mut out)?;
        Ok(out.finish(Vec::new()))
    }

    fn pipeline(
        &self,
        t: &Text,
        p: &ast::Pipeline,
        chain: ChainOp,
        cx: Cx,
    ) -> Result<Vec<Stmt>, ParseError> {
        let plain = |c: &ast::Command| {
            matches!(c, ast::Command::Simple(_) | ast::Command::ExtendedTest(..))
        };
        if p.seq.iter().all(plain) {
            let mut elems = Vec::new();
            for c in &p.seq {
                match c {
                    ast::Command::Simple(s) => elems.push(Elem::Cmd(self.simple(t, s, cx)?)),
                    ast::Command::ExtendedTest(test, redirects) => {
                        elems.push(Elem::Cmd(self.test_command(t, test, redirects, cx)?))
                    }
                    _ => {}
                }
            }
            return Ok(vec![Stmt::Pipeline(Pipeline {
                elems,
                chain: Some(chain),
            })]);
        }
        // A compound stage is a statement of its own; `Script::joins` keeps its chain.
        let mut stages = Vec::new();
        for c in &p.seq {
            stages.extend(self.command(t, c, cx)?);
        }
        if p.seq.len() == 1 {
            return Ok(stages);
        }
        Ok(vec![Stmt::Block(script(stages, Vec::new()))])
    }

    fn command(&self, t: &Text, c: &ast::Command, cx: Cx) -> Result<Vec<Stmt>, ParseError> {
        match c {
            ast::Command::Simple(s) => Ok(vec![Stmt::Pipeline(Pipeline {
                elems: vec![Elem::Cmd(self.simple(t, s, cx)?)],
                chain: None,
            })]),
            ast::Command::Compound(cc, redirects) => {
                let mut out = self.redirect_exprs(t, redirects.as_ref(), cx)?;
                out.extend(self.compound(t, cc, cx)?);
                Ok(out)
            }
            ast::Command::Function(f) => {
                let ast::FunctionBody(cc, redirects) = &f.body;
                let pre = script(self.redirect_exprs(t, redirects.as_ref(), cx)?, Vec::new());
                let body = match cc {
                    ast::CompoundCommand::BraceGroup(b) => self.body(t, &b.list, cx)?,
                    other => script(self.compound(t, other, cx)?, Vec::new()),
                };
                Ok(vec![Stmt::Func {
                    name: f.fname.value.clone(),
                    body: concat(pre, body),
                }])
            }
            ast::Command::ExtendedTest(test, redirects) => Ok(vec![Stmt::Pipeline(Pipeline {
                elems: vec![Elem::Cmd(self.test_command(t, test, redirects, cx)?)],
                chain: None,
            })]),
        }
    }

    /// `[[ … ]]` as a command named `[[` whose arguments are the test's words.
    fn test_command(
        &self,
        t: &Text,
        test: &ast::ExtendedTestExprCommand,
        redirects: &Option<ast::RedirectList>,
        cx: Cx,
    ) -> Result<SimpleCommand, ParseError> {
        let span = t.span(&test.loc);
        let mut args = Vec::new();
        self.test_words(t, &test.expr, span, cx, &mut args)?;
        let mut cmd = synthetic("[[", span, cx);
        cmd.args = args;
        for r in redirects.iter().flat_map(|r| r.0.iter()) {
            cmd.redirects.push(self.redirect(t, r, cx)?);
        }
        Ok(cmd)
    }

    fn test_words(
        &self,
        t: &Text,
        e: &ast::ExtendedTestExpr,
        span: Span,
        cx: Cx,
        out: &mut Vec<Word>,
    ) -> Result<(), ParseError> {
        use ast::ExtendedTestExpr as E;
        let cx = cx.deeper(span)?;
        match e {
            E::And(a, b) | E::Or(a, b) => {
                self.test_words(t, a, span, cx, out)?;
                self.test_words(t, b, span, cx, out)
            }
            E::Not(a) | E::Parenthesized(a) => self.test_words(t, a, span, cx, out),
            E::UnaryTest(op, w) => {
                let mut w = self.ast_word(t, w, span, cx)?;
                if matches!(op, ast::UnaryPredicate::ShellVariableIsSetAndAssigned) {
                    self.subscript_substs(&mut w, cx)?;
                }
                out.push(w);
                Ok(())
            }
            E::BinaryTest(op, a, b) => {
                use ast::BinaryPredicate as B;
                let arithmetic = matches!(
                    op,
                    B::ArithmeticEqualTo
                        | B::ArithmeticNotEqualTo
                        | B::ArithmeticLessThan
                        | B::ArithmeticLessThanOrEqualTo
                        | B::ArithmeticGreaterThan
                        | B::ArithmeticGreaterThanOrEqualTo
                );
                for w in [a, b] {
                    let mut w = self.ast_word(t, w, span, cx)?;
                    if arithmetic {
                        self.subscript_substs(&mut w, cx)?;
                    }
                    out.push(w);
                }
                Ok(())
            }
        }
    }

    fn compound(
        &self,
        t: &Text,
        cc: &ast::CompoundCommand,
        cx: Cx,
    ) -> Result<Vec<Stmt>, ParseError> {
        use ast::CompoundCommand as C;
        let span = cc.location().map_or(t.whole(), |l| t.span(&l));
        Ok(match cc {
            C::BraceGroup(b) => vec![Stmt::Block(self.body(t, &b.list, cx)?)],
            C::Subshell(s) => vec![Stmt::Block(self.body(t, &s.list, cx)?)],
            C::ForClause(f) => {
                let mut words = Vec::new();
                for w in f.values.iter().flatten() {
                    words.push(self.ast_word(t, w, span, cx)?);
                }
                let mut out = expr_stmt(words);
                out.push(Stmt::Loop {
                    body: self.body(t, &f.body.list, cx.looping())?,
                    span,
                });
                out
            }
            C::ArithmeticForClause(f) => {
                let mut words = Vec::new();
                for e in [&f.initializer, &f.condition, &f.updater]
                    .into_iter()
                    .flatten()
                {
                    words.push(self.arith_word(&e.value, span, cx)?);
                }
                let mut out = vec![arith_command(words, span, cx)];
                out.push(Stmt::Loop {
                    body: self.body(t, &f.body.list, cx.looping())?,
                    span,
                });
                out
            }
            C::CaseClause(c) => {
                let mut words = vec![self.ast_word(t, &c.value, span, cx)?];
                let mut branches = Vec::new();
                for item in &c.cases {
                    for p in &item.patterns {
                        words.push(self.ast_word(t, p, span, cx)?);
                    }
                    branches.push(match &item.cmd {
                        Some(l) => self.body(t, l, cx)?,
                        None => Script::default(),
                    });
                }
                let mut out = expr_stmt(words);
                out.push(Stmt::Cond { branches, span });
                out
            }
            C::IfClause(i) => {
                let first = concat(self.body(t, &i.condition, cx)?, self.body(t, &i.then, cx)?);
                let mut branches = vec![first];
                for e in i.elses.iter().flatten() {
                    let condition = match &e.condition {
                        Some(c) => self.body(t, c, cx)?,
                        None => Script::default(),
                    };
                    branches.push(concat(condition, self.body(t, &e.body, cx)?));
                }
                vec![Stmt::Cond { branches, span }]
            }
            C::WhileClause(w) | C::UntilClause(w) => {
                let cx = cx.looping();
                let body = concat(self.body(t, &w.0, cx)?, self.body(t, &w.1.list, cx)?);
                vec![Stmt::Loop { body, span }]
            }
            C::Arithmetic(a) => vec![arith_command(
                vec![self.arith_word(&a.expr.value, span, cx)?],
                span,
                cx,
            )],
            C::Coprocess(c) => {
                let inner = self.command(t, &c.body, cx.deeper(span)?)?;
                vec![Stmt::Block(script(inner, Vec::new()))]
            }
        })
    }

    /// The redirect targets of a compound command that run commands, as an expression statement.
    fn redirect_exprs(
        &self,
        t: &Text,
        redirects: Option<&ast::RedirectList>,
        cx: Cx,
    ) -> Result<Vec<Stmt>, ParseError> {
        let mut words = Vec::new();
        for r in redirects.iter().flat_map(|r| r.0.iter()) {
            words.push(match self.redirect(t, r, cx)? {
                Redirect::File { target, .. } => target,
                Redirect::Heredoc { body, .. } => body,
            });
        }
        Ok(expr_stmt(words))
    }

    fn simple(
        &self,
        t: &Text,
        s: &ast::SimpleCommand,
        cx: Cx,
    ) -> Result<SimpleCommand, ParseError> {
        use ast::CommandPrefixOrSuffixItem as I;
        let span = s.location().map_or(t.whole(), |l| t.span(&l));
        let mut cmd = synthetic("", span, cx);
        cmd.name.parts.clear();
        cmd.typed.clear();
        cmd.canonical = None;
        let prefix = s.prefix.iter().flat_map(|p| p.0.iter());
        for item in prefix {
            match item {
                I::IoRedirect(r) => cmd.redirects.push(self.redirect(t, r, cx)?),
                I::AssignmentWord(a, _) => self.assignment(t, a, cx, &mut cmd.assigns)?,
                I::Word(w) => cmd.args.push(self.ast_word(t, w, span, cx)?),
                I::ProcessSubstitution(_, sub) => cmd.args.push(self.process_subst(t, sub, cx)?),
            }
        }
        if let Some(name) = &s.word_or_name {
            cmd.name = self.ast_word(t, name, span, cx)?;
            cmd.typed = name.value.clone();
        }
        for item in s.suffix.iter().flat_map(|p| p.0.iter()) {
            match item {
                I::IoRedirect(r) => cmd.redirects.push(self.redirect(t, r, cx)?),
                // `export x=$(…)`: an argument of the builtin that also assigns `x`.
                I::AssignmentWord(a, w) => {
                    cmd.args.push(self.ast_word(t, w, span, cx)?);
                    // The argument already holds the substitutions; the assignment keeps the
                    // value's shape without them, so each command is found once.
                    let mut assigned = Vec::new();
                    self.assignment(t, a, cx, &mut assigned)?;
                    for (name, mut value) in assigned {
                        for p in &mut value.parts {
                            if matches!(p, WordPart::Subst(_) | WordPart::Block(_)) {
                                *p = WordPart::Var("$(…)".to_string());
                            }
                        }
                        cmd.assigns.push((name, value));
                    }
                }
                I::Word(w) => cmd.args.push(self.ast_word(t, w, span, cx)?),
                I::ProcessSubstitution(_, sub) => cmd.args.push(self.process_subst(t, sub, cx)?),
            }
        }
        let has_glob = cmd
            .name
            .parts
            .iter()
            .any(|p| matches!(p, WordPart::Glob(_)));
        cmd.canonical = if has_glob {
            None
        } else {
            canonical(&cmd.name, self.profile)
        };
        let (target, first_arg, wrapped) = unwrap_builtins(&cmd, self.profile);
        let runs_text = match target.as_deref() {
            Some("eval") => true,
            Some("source" | ".") => wrapped,
            _ => false,
        };
        let runs_dynamic_text = runs_text && cmd.args.iter().skip(first_arg).any(Word::is_dynamic);
        self.evaluated_operands(&mut cmd, target.as_deref(), first_arg, cx)?;
        // A name no rule can match is opaque: a variable, a glob, anything without a canonical name.
        let unknown_name = !cmd.name.parts.is_empty() && cmd.canonical.is_none();
        cmd.opaque = cmd.name.is_dynamic() || has_glob || runs_dynamic_text || unknown_name;
        Ok(cmd)
    }

    /// Operands bash evaluates as arithmetic, where a `name[…]` subscript in a static string runs
    /// its `$(…)` (`let 'a[$(…)]'`, `printf -v`, `read`, `test -v`, `declare`).
    fn evaluated_operands(
        &self,
        cmd: &mut SimpleCommand,
        target: Option<&str>,
        first_arg: usize,
        cx: Cx,
    ) -> Result<(), ParseError> {
        let env = EnvView::new();
        let mut picked = Vec::new();
        match target {
            Some("let" | "read" | "declare" | "typeset" | "local") => {
                picked.extend(first_arg..cmd.args.len())
            }
            Some("printf" | "test" | "[") => {
                for i in first_arg..cmd.args.len() {
                    match cmd.args[i].static_value(&env).as_deref() {
                        Some("-v") => picked.push(i + 1),
                        Some(v) if target == Some("printf") && v.starts_with("-v") => {
                            picked.push(i)
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        for i in picked {
            if let Some(w) = cmd.args.get_mut(i) {
                self.subscript_substs(w, cx)?;
            }
        }
        Ok(())
    }

    /// Append the commands in the `[…]` subscripts of a static word that bash evaluates.
    fn subscript_substs(&self, w: &mut Word, cx: Cx) -> Result<(), ParseError> {
        let Some(value) = w.static_value(&EnvView::new()) else {
            return Ok(());
        };
        for sub in subscripts(&value) {
            if runs_code(sub) {
                self.charge(sub.len(), w.span)?;
                let inner =
                    self.word_text(sub, Origin::Inexact(w.span), w.span, cx.deeper(w.span)?)?;
                w.parts.extend(commands_only(inner));
            }
        }
        Ok(())
    }

    fn assignment(
        &self,
        t: &Text,
        a: &ast::Assignment,
        cx: Cx,
        out: &mut Vec<(String, Word)>,
    ) -> Result<(), ParseError> {
        let span = t.span(&a.loc);
        let local_end = t.byte(a.loc.end.index);
        let name = match &a.name {
            ast::AssignmentName::VariableName(n) => n.clone(),
            ast::AssignmentName::ArrayElementName(n, index) => {
                let w = self.word_text(index, Origin::Inexact(span), span, cx)?;
                // The index is an arithmetic expression: bash expands it again, quotes removed.
                let again = w.static_value(&EnvView::new()).filter(|v| runs_code(v));
                if w.is_dynamic() {
                    out.push((n.clone(), w));
                }
                if let Some(v) = again {
                    self.charge(v.len(), span)?;
                    let inner =
                        self.word_text(&v, Origin::Inexact(span), span, cx.deeper(span)?)?;
                    out.push((
                        n.clone(),
                        Word {
                            parts: commands_only(inner).collect(),
                            span,
                            quote: Quote::None,
                        },
                    ));
                }
                n.clone()
            }
        };
        match &a.value {
            ast::AssignmentValue::Scalar(w) => {
                // The value is the tail of the assignment's text when nothing was rewritten.
                let start = local_end.checked_sub(w.value.len());
                let origin = match start {
                    Some(s) if t.src.get(s..local_end) == Some(w.value.as_str()) => {
                        t.origin.shift(s)
                    }
                    _ => Origin::Inexact(span),
                };
                out.push((name, self.word_text(&w.value, origin, span, cx)?));
            }
            ast::AssignmentValue::Array(items) => {
                for (key, value) in items {
                    if let Some(k) = key {
                        out.push((name.clone(), self.ast_word(t, k, span, cx)?));
                    }
                    out.push((name.clone(), self.ast_word(t, value, span, cx)?));
                }
            }
        }
        Ok(())
    }

    fn process_subst(
        &self,
        t: &Text,
        sub: &ast::SubshellCommand,
        cx: Cx,
    ) -> Result<Word, ParseError> {
        let span = t.span(&sub.loc);
        let inner = self.body(t, &sub.list, cx)?;
        Ok(Word {
            parts: vec![WordPart::Subst(Box::new(inner))],
            span,
            quote: Quote::None,
        })
    }

    fn redirect(&self, t: &Text, r: &ast::IoRedirect, cx: Cx) -> Result<Redirect, ParseError> {
        use ast::IoRedirect as R;
        let span = r.location().map_or(t.whole(), |l| t.span(&l));
        let fd = |fd: &Option<i32>| fd.map(|n| n.to_string()).unwrap_or_default();
        Ok(match r {
            R::File(n, kind, target) => {
                let target = match target {
                    ast::IoFileRedirectTarget::Filename(w)
                    | ast::IoFileRedirectTarget::Duplicate(w) => self.ast_word(t, w, span, cx)?,
                    ast::IoFileRedirectTarget::Fd(n) => literal(&n.to_string(), span),
                    ast::IoFileRedirectTarget::ProcessSubstitution(_, sub) => {
                        self.process_subst(t, sub, cx)?
                    }
                };
                Redirect::File {
                    op: format!("{}{kind}", fd(n)),
                    target,
                    span,
                }
            }
            R::HereDocument(_, h) => {
                let doc = &h.doc;
                let body_span = doc.loc.as_ref().map_or(span, |l| t.span(l));
                let body = if h.requires_expansion {
                    let origin = match t.verbatim_start(&doc.value, doc.loc.as_ref()) {
                        Some(s) => t.origin.shift(s),
                        None => Origin::Inexact(body_span),
                    };
                    let pieces = word::parse_heredoc(&doc.value, &self.opts)
                        .map_err(|e| error(body_span, &format!("heredoc: {e}"), None))?;
                    let mut parts = Vec::new();
                    self.pieces(&doc.value, &pieces, origin, true, cx, &mut parts)?;
                    Word {
                        parts,
                        span: body_span,
                        quote: Quote::Double,
                    }
                } else {
                    Word {
                        parts: vec![WordPart::Literal(doc.value.clone())],
                        span: body_span,
                        quote: Quote::Single,
                    }
                };
                Redirect::Heredoc {
                    body,
                    expands: h.requires_expansion,
                    span,
                }
            }
            R::HereString(n, w) => Redirect::File {
                op: format!("{}<<<", fd(n)),
                target: self.ast_word(t, w, span, cx)?,
                span,
            },
            R::OutputAndError(w, append) => Redirect::File {
                op: if *append { "&>>" } else { "&>" }.to_string(),
                target: self.ast_word(t, w, span, cx)?,
                span,
            },
        })
    }

    /// A word of the AST; `fallback` is its span when the AST has no location for it.
    fn ast_word(
        &self,
        t: &Text,
        w: &ast::Word,
        fallback: Span,
        cx: Cx,
    ) -> Result<Word, ParseError> {
        let span = w.loc.as_ref().map_or(fallback, |l| t.span(l));
        let origin = match t.verbatim_start(&w.value, w.loc.as_ref()) {
            Some(s) => t.origin.shift(s),
            None => Origin::Inexact(span),
        };
        self.word_text(&w.value, origin, span, cx)
    }

    fn word_text(
        &self,
        value: &str,
        origin: Origin,
        span: Span,
        cx: Cx,
    ) -> Result<Word, ParseError> {
        let pieces =
            word::parse(value, &self.opts).map_err(|e| error(span, &format!("word: {e}"), None))?;
        let mut parts = Vec::new();
        self.pieces(value, &pieces, origin, false, cx, &mut parts)?;
        Ok(Word {
            parts,
            span,
            quote: quote_of(&pieces),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn pieces(
        &self,
        value: &str,
        pieces: &[WordPieceWithSource],
        origin: Origin,
        quoted: bool,
        cx: Cx,
        out: &mut Vec<WordPart>,
    ) -> Result<(), ParseError> {
        for p in pieces {
            let (s, e) = (p.start_index, p.end_index);
            let span = origin.span(s, e);
            let raw = value.get(s..e).unwrap_or_default();
            match &p.piece {
                WordPiece::Text(text) => out.push(if !quoted && is_glob(text) {
                    WordPart::Glob(text.clone())
                } else {
                    WordPart::Literal(text.clone())
                }),
                WordPiece::SingleQuotedText(text) => out.push(WordPart::Literal(text.clone())),
                WordPiece::AnsiCQuotedText(text) => out.push(WordPart::Literal(ansi_c(text))),
                WordPiece::DoubleQuotedSequence(inner)
                | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    self.pieces(value, inner, origin, true, cx, out)?
                }
                WordPiece::TildeExpansion(TildeExpr::Home) => out.push(WordPart::Tilde),
                WordPiece::TildeExpansion(_) => out.push(WordPart::Var(raw.to_string())),
                WordPiece::EscapeSequence(esc) => {
                    let ch = esc.strip_prefix('\\').unwrap_or(esc);
                    if ch != "\n" {
                        out.push(WordPart::Literal(ch.to_string()));
                    }
                }
                WordPiece::CommandSubstitution(inner) => {
                    let origin = if value.get(s + 2..e.saturating_sub(1)) == Some(inner.as_str()) {
                        origin.shift(s + 2)
                    } else {
                        Origin::Inexact(span)
                    };
                    let script = self.text(inner, origin, cx.deeper(span)?.depth)?;
                    out.push(WordPart::Subst(Box::new(script)));
                }
                WordPiece::BackquotedCommandSubstitution(inner) => {
                    let origin = if value.get(s + 1..e.saturating_sub(1)) == Some(inner.as_str()) {
                        origin.shift(s + 1)
                    } else {
                        Origin::Inexact(span)
                    };
                    let script = self.text(inner, origin, cx.deeper(span)?.depth)?;
                    out.push(WordPart::Subst(Box::new(script)));
                }
                WordPiece::ParameterExpansion(pe) => {
                    let braced = raw.strip_prefix("${").and_then(|r| r.strip_suffix('}'));
                    match pe {
                        ParameterExpr::Parameter {
                            parameter: Parameter::Named(name),
                            indirect: false,
                        } => out.push(WordPart::Var(name.clone())),
                        ParameterExpr::Parameter {
                            parameter: Parameter::Positional(n),
                            indirect: false,
                        } => out.push(WordPart::Var(n.to_string())),
                        ParameterExpr::Parameter {
                            parameter: Parameter::Special(sp),
                            indirect: false,
                        } => out.push(WordPart::Var(sp.to_string())),
                        _ => {
                            let inner = braced.unwrap_or(raw);
                            // A name that never resolves: the value depends on the operator.
                            out.push(WordPart::Var(inner.to_string()));
                            if inner.contains(['$', '`']) {
                                self.charge(inner.len(), span)?;
                                let origin = match braced {
                                    Some(_) => origin.shift(s + 2),
                                    None => Origin::Inexact(span),
                                };
                                let w = self.word_text(inner, origin, span, cx.deeper(span)?)?;
                                out.extend(commands_only(w));
                            }
                        }
                    }
                }
                WordPiece::ArithmeticExpression(expr) => {
                    out.extend(self.arith_word(&expr.value, span, cx)?.parts)
                }
            }
        }
        Ok(())
    }

    /// An arithmetic expression as a word: a value that never resolves, plus the substitutions it
    /// runs.
    fn arith_word(&self, expr: &str, span: Span, cx: Cx) -> Result<Word, ParseError> {
        let mut parts = vec![WordPart::Var(format!("(({expr}))"))];
        if expr.contains(['$', '`']) {
            self.charge(expr.len(), span)?;
            let w = self.word_text(expr, Origin::Inexact(span), span, cx.deeper(span)?)?;
            parts.extend(commands_only(w));
        }
        Ok(Word {
            parts,
            span,
            quote: Quote::None,
        })
    }
}

fn commands_only(w: Word) -> impl Iterator<Item = WordPart> {
    w.parts
        .into_iter()
        .filter(|p| matches!(p, WordPart::Subst(_) | WordPart::Block(_)))
}

fn script(stmts: Vec<Stmt>, comments: Vec<Comment>) -> Script {
    let mut out = Acc::default();
    out.push(stmts, ChainOp::Seq);
    out.finish(comments)
}

/// `b` run after `a` (a body after its condition), joined by `;`.
fn concat(a: Script, b: Script) -> Script {
    let mut out = Acc {
        stmts: a.stmts,
        joins: a.joins,
        next: Some(ChainOp::Seq),
    };
    if let Some(Stmt::Pipeline(p)) = out.stmts.last_mut()
        && p.chain.is_none()
        && !b.stmts.is_empty()
    {
        p.chain = Some(ChainOp::Seq);
    }
    out.append(b);
    out.finish(a.comments)
}

/// Statements in order, each with the operator joining it to the one before.
#[derive(Default)]
struct Acc {
    stmts: Vec<Stmt>,
    joins: Vec<Option<ChainOp>>,
    /// The operator after the last pipeline pushed.
    next: Option<ChainOp>,
}

impl Acc {
    /// The statements one pipeline lowered to; all of them share its join. `after` is the operator
    /// that follows the pipeline.
    fn push(&mut self, stmts: Vec<Stmt>, after: ChainOp) {
        let join = if self.stmts.is_empty() {
            None
        } else {
            self.next
        };
        self.joins.extend(std::iter::repeat_n(join, stmts.len()));
        self.stmts.extend(stmts);
        self.next = Some(after);
    }

    /// Append a body that runs after the statements so far (an `if` body after its condition).
    fn append(&mut self, body: Script) {
        let first = self.joins.len();
        self.stmts.extend(body.stmts);
        self.joins.extend(body.joins);
        self.joins.resize(self.stmts.len(), None);
        if first < self.joins.len() && first > 0 {
            self.joins[first] = Some(ChainOp::Seq);
        }
        self.next = Some(ChainOp::Seq);
    }

    fn finish(mut self, comments: Vec<Comment>) -> Script {
        // The last statement joins nothing; a trailing `&` stays.
        if let Some(Stmt::Pipeline(p)) = self.stmts.last_mut()
            && p.chain == Some(ChainOp::Seq)
        {
            p.chain = None;
        }
        Script {
            stmts: self.stmts,
            comments,
            joins: self.joins,
        }
    }
}

/// Words that run commands (substitutions), as an expression statement; none when no word does.
fn expr_stmt(words: Vec<Word>) -> Vec<Stmt> {
    let elems: Vec<Elem> = words
        .into_iter()
        .filter(|w| {
            w.parts
                .iter()
                .any(|p| matches!(p, WordPart::Subst(_) | WordPart::Block(_)))
        })
        .map(Elem::Expr)
        .collect();
    if elems.is_empty() {
        return Vec::new();
    }
    vec![Stmt::Pipeline(Pipeline {
        elems,
        chain: Some(ChainOp::Seq),
    })]
}

fn synthetic(name: &str, span: Span, cx: Cx) -> SimpleCommand {
    SimpleCommand {
        name: literal(name, span),
        typed: name.to_string(),
        canonical: Some(name.to_string()),
        args: Vec::new(),
        redirects: Vec::new(),
        assigns: Vec::new(),
        span,
        in_loop: cx.in_loop,
        opaque: false,
    }
}

fn literal(text: &str, span: Span) -> Word {
    Word {
        parts: vec![WordPart::Literal(text.to_string())],
        span,
        quote: Quote::None,
    }
}

/// The command a static name runs: its last path component; Git Bash finds `RM.exe` as `rm`.
fn canonical(name: &Word, profile: BashProfile) -> Option<String> {
    let value = match name.static_value(&EnvView::new()) {
        Some(v) => v,
        // `~/bin/rm`: the home folder is not known here, the command still is.
        None => match &name.parts[..] {
            [WordPart::Tilde, rest @ ..] => {
                let mut tail = String::new();
                for p in rest {
                    match p {
                        WordPart::Literal(s) => tail.push_str(s),
                        _ => return None,
                    }
                }
                if !tail.starts_with('/') {
                    return None;
                }
                tail
            }
            _ => return None,
        },
    };
    let seps: &[char] = match profile {
        BashProfile::GitBash => &['/', '\\'],
        BashProfile::Posix => &['/'],
    };
    let base = value.rsplit(seps).next().unwrap_or_default();
    let base = match profile {
        BashProfile::GitBash => {
            let lower = base.to_lowercase();
            lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
        }
        BashProfile::Posix => base.to_string(),
    };
    (!base.is_empty()).then_some(base)
}

/// Text that runs a command when bash expands it.
fn runs_code(text: &str) -> bool {
    text.contains("$(") || text.contains('`')
}

/// The contents of each outermost `[…]` in `text`.
fn subscripts(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'[' => {
                if depth == 0 {
                    start = i + 1;
                }
                depth += 1;
            }
            b']' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    out.push(&text[start..i]);
                }
            }
            _ => {}
        }
    }
    out
}

/// `(( … ))` (and a `for (( … ))` header) as a command named `((`.
fn arith_command(words: Vec<Word>, span: Span, cx: Cx) -> Stmt {
    let mut cmd = synthetic("((", span, cx);
    cmd.args = words;
    Stmt::Pipeline(Pipeline {
        elems: vec![Elem::Cmd(cmd)],
        chain: None,
    })
}

/// A command that evaluates a variable the script sets to text that runs a command — arithmetic
/// (`x='a[$(…)]'; (( x ))`), `${!x}`, an assignment to a `declare -i` name: whether bash runs it
/// is not known here, so it is opaque.
fn mark_tainted_arithmetic(script: &mut Script) {
    let env = EnvView::new();
    let mut tainted = BTreeSet::new();
    // Names declared integer (`declare -i n`): assigning to one evaluates the value.
    let mut integers = BTreeSet::new();
    visit_commands(script, &mut |c| {
        for (name, w) in &c.assigns {
            if w.static_value(&env).is_some_and(|v| runs_code(&v)) {
                tainted.insert(name.clone());
            }
        }
        if matches!(
            c.canonical.as_deref(),
            Some("declare" | "typeset" | "local")
        ) {
            let values: Vec<String> = c.args.iter().filter_map(|w| w.static_value(&env)).collect();
            let integer = values.iter().any(|v| v.starts_with('-') && v.contains('i'));
            if integer {
                for v in values.iter().filter(|v| !v.starts_with('-')) {
                    integers.insert(v.split('=').next().unwrap_or_default().to_string());
                }
            }
        }
    });
    if tainted.is_empty() {
        return;
    }
    visit_commands(script, &mut |c| {
        let integer_assigned = c.assigns.iter().any(|(name, w)| {
            integers.contains(name) && w.static_value(&env).is_some_and(|v| runs_code(&v))
        });
        if integer_assigned {
            c.opaque = true;
        }
        // `(( … ))` itself holds its expression as a `((…))` part, matched below.
        let arithmetic_command = matches!(c.canonical.as_deref(), Some("let" | "[["));
        let words = std::iter::once(&c.name)
            .chain(c.args.iter())
            .chain(c.assigns.iter().map(|(_, w)| w));
        let mut mentions = false;
        for w in words {
            for p in &w.parts {
                let text = match p {
                    WordPart::Var(v) if v.starts_with("((") => v.as_str(),
                    // `${!y}`: the value of `y` names the variable, subscript included.
                    WordPart::Var(v) if v.starts_with('!') => v.as_str(),
                    WordPart::Var(v) | WordPart::Literal(v) | WordPart::Glob(v)
                        if arithmetic_command =>
                    {
                        v.as_str()
                    }
                    _ => continue,
                };
                mentions |= text
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .any(|id| tainted.contains(id));
            }
        }
        if mentions {
            c.opaque = true;
        }
    });
}

/// Every simple command, also inside bodies and substitutions.
fn visit_commands(script: &mut Script, f: &mut dyn FnMut(&mut SimpleCommand)) {
    for st in &mut script.stmts {
        match st {
            Stmt::Pipeline(p) => {
                for e in &mut p.elems {
                    match e {
                        Elem::Cmd(c) => {
                            f(c);
                            let words = std::iter::once(&mut c.name)
                                .chain(c.args.iter_mut())
                                .chain(c.assigns.iter_mut().map(|(_, w)| w));
                            for w in words {
                                visit_word(w, f);
                            }
                            for r in &mut c.redirects {
                                match r {
                                    Redirect::File { target, .. } => visit_word(target, f),
                                    Redirect::Heredoc { body, .. } => visit_word(body, f),
                                }
                            }
                        }
                        Elem::Method(m) => m.args.iter_mut().for_each(|w| visit_word(w, f)),
                        Elem::Expr(w) => visit_word(w, f),
                    }
                }
            }
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                visit_commands(body, f)
            }
            Stmt::Cond { branches, .. } => branches.iter_mut().for_each(|b| visit_commands(b, f)),
        }
    }
}

fn visit_word(w: &mut Word, f: &mut dyn FnMut(&mut SimpleCommand)) {
    for p in &mut w.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = p {
            visit_commands(s, f);
        }
    }
}

/// Words that run the command named by their first operand.
const WRAPPERS: &[&str] = &["builtin", "command", "exec"];

/// The command `builtin`, `command` and `exec` (with their options) run, the index of its first
/// argument, and whether a wrapper was there. `None` when the wrapped name is not static.
fn unwrap_builtins(cmd: &SimpleCommand, profile: BashProfile) -> (Option<String>, usize, bool) {
    let env = EnvView::new();
    let mut name = cmd.canonical.clone();
    let mut i = 0;
    let mut wrapped = false;
    while let Some(wrapper) = name.as_deref().filter(|n| WRAPPERS.contains(n)) {
        let wrapper = wrapper.to_string();
        wrapped = true;
        while let Some(v) = cmd.args.get(i).and_then(|w| w.static_value(&env)) {
            if v == "--" {
                i += 1;
                break;
            }
            if !v.starts_with('-') || v == "-" {
                break;
            }
            // `exec -a NAME`: the option takes the next word.
            if wrapper == "exec" && v.contains('a') {
                i += 1;
            }
            i += 1;
        }
        name = cmd.args.get(i).and_then(|w| canonical(w, profile));
        i += 1;
    }
    (name, i, wrapped)
}

/// Unquoted text bash expands into file names or several words.
fn is_glob(text: &str) -> bool {
    text.contains(['*', '?'])
        // A `[` without a `]` after it matches only itself (the `[` command).
        || text.find('[').is_some_and(|i| text[i..].contains(']'))
        || (text.contains('{') && (text.contains(',') || text.contains("..")))
        || ["@(", "!(", "+("].iter().any(|x| text.contains(x))
}

fn quote_of(pieces: &[WordPieceWithSource]) -> Quote {
    let (mut single, mut double, mut bare) = (false, false, false);
    for p in pieces {
        match p.piece {
            WordPiece::SingleQuotedText(_) | WordPiece::AnsiCQuotedText(_) => single = true,
            WordPiece::DoubleQuotedSequence(_) | WordPiece::GettextDoubleQuotedSequence(_) => {
                double = true
            }
            WordPiece::EscapeSequence(_) => {
                single = true;
                bare = true;
            }
            _ => bare = true,
        }
    }
    match (single, double, bare) {
        (true, false, false) => Quote::Single,
        (false, true, false) => Quote::Double,
        (false, false, _) => Quote::None,
        _ => Quote::Mixed,
    }
}

fn tokenizer_error(t: &Text, e: &TokenizerError) -> ParseError {
    let (pos, unclosed) = match e {
        TokenizerError::UnterminatedSingleQuote(p) | TokenizerError::UnterminatedAnsiCQuote(p) => {
            (Some(p), Some(QuoteKind::Single))
        }
        TokenizerError::UnterminatedDoubleQuote(p) => (Some(p), Some(QuoteKind::Double)),
        TokenizerError::UnterminatedBackquote(p) => (Some(p), Some(QuoteKind::Backtick)),
        _ => (None, None),
    };
    let span = match pos {
        Some(p) => t.origin.span(t.byte(p.index), t.src.len()),
        None => t.whole(),
    };
    error(span, &format!("bash: {e}"), unclosed)
}

/// `#` comments: the text the tokenizer skipped (between tokens, or before a newline token).
fn comments(t: &Text, tokens: &[Token]) -> Vec<Comment> {
    let mut covered: Vec<(usize, usize)> = tokens
        .iter()
        .filter(|tok| !matches!(tok, Token::Operator(op, _) if op == "\n"))
        .map(|tok| {
            let l = tok.location();
            (t.byte(l.start.index), t.byte(l.end.index))
        })
        .collect();
    covered.sort_unstable();
    let src = t.src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut next = 0;
    while i < src.len() {
        while next < covered.len() && covered[next].1 <= i {
            next += 1;
        }
        if next < covered.len() && covered[next].0 <= i {
            i = covered[next].1.max(i + 1);
            continue;
        }
        if src[i] != b'#' {
            i += 1;
            continue;
        }
        let end = t.src[i..].find('\n').map_or(src.len(), |n| i + n);
        let end = if end > i && src[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        let line_start = t.src[..i].rfind('\n').map_or(0, |n| n + 1);
        out.push(Comment {
            text: t.src[i..end].to_string(),
            span: t.origin.span(i, end),
            trailing: !t.src[line_start..i].trim().is_empty(),
        });
        i = end.max(i + 1);
    }
    out
}

/// The value of `$'…'` as bash decodes it.
fn ansi_c(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = chars.next() else {
            out.push('\\');
            break;
        };
        let mut number = |radix: u32, max: usize, first: Option<char>| {
            let mut v = 0u32;
            let mut n = 0;
            if let Some(f) = first {
                v = f.to_digit(radix).unwrap_or(0);
                n = 1;
            }
            while n < max {
                match chars.peek().and_then(|c| c.to_digit(radix)) {
                    Some(d) => {
                        v = v * radix + d;
                        n += 1;
                        chars.next();
                    }
                    None => break,
                }
            }
            (v, n)
        };
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            '\\' | '\'' | '"' | '?' => out.push(e),
            '0'..='7' => {
                let (v, _) = number(8, 3, Some(e));
                out.push(char::from((v & 0xff) as u8));
            }
            'x' | 'u' | 'U' => {
                let max = match e {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let (v, n) = number(16, max, None);
                if n == 0 {
                    out.push('\\');
                    out.push(e);
                } else if e == 'x' {
                    out.push(char::from(v as u8));
                } else {
                    out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                }
            }
            'c' => match chars.next() {
                Some(x) => out.push(char::from((x as u32 & 0x1f) as u8)),
                None => out.push_str("\\c"),
            },
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}
