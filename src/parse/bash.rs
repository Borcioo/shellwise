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

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::thread;

use brush_parser::ast::{self, SourceLocation};
use brush_parser::word::{
    self, Parameter, ParameterExpr, TildeExpr, WordPiece, WordPieceWithSource,
};
use brush_parser::{ParserOptions, SourceSpan, Token, TokenizerError};

use super::{Failure, ParseError, ParseKind, QuoteKind, internal};
use crate::BashProfile;
use crate::ir::{
    ChainOp, Comment, Elem, EnvView, LoopHead, MAX_NESTING, Pipeline, Quote, Redirect, Script,
    SimpleCommand, Stmt, Word, WordPart,
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
            ParseKind::TooDeep,
        ));
    }
    let stack = BASE_STACK.saturating_add(nesting_bound(src).saturating_mul(STACK_PER_LEVEL));
    if stack > MAX_STACK {
        return Err(error(
            whole,
            "nesting too deep to parse safely",
            ParseKind::TooDeep,
        ));
    }
    let owned = src.to_string();
    let worker = thread::Builder::new()
        .name("bash-parse".into())
        .stack_size(stack)
        .spawn(move || {
            #[cfg(feature = "testhooks")]
            if crate::rules::testhooks::active("parse-panic") {
                panic!("testhook: panic in the bash parser");
            }
            Lower::new(profile, owned.len()).text(&owned, Origin::Exact(0), 0)
        });
    match worker {
        Err(_) => Err(internal(whole, Failure::BashThreadNotStarted)),
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|_| Err(internal(whole, Failure::BashPanicked))),
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

fn error(span: Span, message: &str, kind: ParseKind) -> ParseError {
    ParseError {
        span,
        message: message.to_string(),
        kind,
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

    /// Whether a redirect operator follows the word with no space (`{x}>f`); `None` when the
    /// word's location does not hold its text.
    fn touches_redirect(&self, w: &ast::Word) -> Option<bool> {
        let loc = w.loc.as_ref()?;
        let (start, end) = (self.byte(loc.start.index), self.byte(loc.end.index));
        let held = self.src.get(start..end)? == w.value;
        held.then(|| self.src[end..].starts_with(['<', '>']))
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
                ParseKind::TooDeep,
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

/// Names bash itself declares integer and lets the script assign (`declare -p` in a bare bash
/// 5.1 and 5.2): a value assigned to one is arithmetic.
const SHELL_INTEGERS: &[&str] = &["HISTCMD", "OPTIND", "RANDOM", "SRANDOM"];

struct Lower {
    profile: BashProfile,
    opts: ParserOptions,
    /// Bytes of nested text (inside substitutions) still allowed to be parsed again.
    reparse_budget: Cell<usize>,
    /// Names a declaration so far gave the integer attribute (`declare -i n`).
    integers: RefCell<BTreeSet<String>>,
    /// A write the lowering cannot follow may have made any name integer (a nameref, a declaration
    /// word that is not literal text, an `eval` body).
    any_integer: Cell<bool>,
    /// Since the enclosing command started, a write went to a name the lowering cannot read
    /// (`read "$v"`, `read -k x`, `${x:=…}`, `declare "$n=1"`): that command is opaque.
    unread_write: Cell<bool>,
}

impl Lower {
    fn new(profile: BashProfile, len: usize) -> Lower {
        Lower {
            profile,
            opts: ParserOptions::default(),
            reparse_budget: Cell::new(len.saturating_mul(REPARSE_FACTOR)),
            integers: RefCell::default(),
            any_integer: Cell::new(false),
            unread_write: Cell::new(false),
        }
    }

    /// A name gets a value at run time (`read n`): a name that is not static, or no name (`a b`),
    /// may be any name.
    fn runtime_target(&self, w: Option<&Word>) {
        let name = w.and_then(|w| w.static_value(&EnvView::new()));
        if !name.is_some_and(|v| is_identifier(v.split('[').next().unwrap_or_default())) {
            self.unread_write.set(true);
        }
    }

    /// Whether bash evaluates a value assigned to `name` as arithmetic.
    fn is_integer(&self, name: &str) -> bool {
        self.any_integer.get()
            || SHELL_INTEGERS.contains(&name)
            || self.integers.borrow().contains(name)
    }

    /// Take `len` bytes of nested text from the budget.
    fn charge(&self, len: usize, span: Span) -> Result<(), ParseError> {
        let left = self.reparse_budget.get();
        if len > left {
            return Err(error(
                span,
                "nested text too large to parse in time",
                ParseKind::TooDeep,
            ));
        }
        self.reparse_budget.set(left - len);
        Ok(())
    }

    /// Parse and lower one text (the command, or the inside of a substitution); nested text
    /// (`depth` past 0) is charged to the budget first.
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
            .map_err(|e| tokenizer_error(&t, &e, depth))?;
        let program = brush_parser::parse_tokens(&tokens, &self.opts).map_err(|e| {
            let span = match &e {
                brush_parser::ParseError::ParsingNear(pos) => {
                    let start = t.byte(pos.index);
                    t.origin.span(start, src.len())
                }
                _ => t.origin.span(src.len(), src.len()),
            };
            error(span, &format!("bash: {e}"), ParseKind::Syntax)
        })?;
        let cx = Cx {
            in_loop: false,
            depth,
        };
        let mut out = Acc::default();
        let outer = self.unread_write.replace(false);
        for list in &program.complete_commands {
            self.list(&t, list, cx, &mut out)?;
        }
        // A write outside any command (`case ${x:=a} in`, a `coproc` name): an opaque command.
        if self.unread_write.replace(outer) {
            let mut cmd = synthetic("((", t.whole(), cx);
            cmd.opaque = true;
            out.push(
                vec![Stmt::Pipeline(Pipeline {
                    elems: vec![Elem::Cmd(cmd)],
                    chain: Some(ChainOp::Seq),
                    negated: false,
                })],
                ChainOp::Seq,
            );
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
            // The parser reads `coproc NAME [[ … ]]` as a command NAME followed by the test's
            // words, and ends that command at a `||` or `&&` inside the test: the whole list
            // fails closed. Bash takes NAME as the coprocess name.
            if let Some(c) = pipelines.iter().find_map(|p| misread_coproc(p)) {
                if let ast::Command::Simple(s) = c.body.as_ref()
                    && let Some(name) = &s.word_or_name
                {
                    let w = self.ast_word(t, name, t.span(&c.loc), cx)?;
                    self.runtime_target(Some(&w));
                }
                let mut cmd = synthetic("[[", t.span(&c.loc), cx);
                cmd.opaque = true;
                let stmt = Stmt::Pipeline(Pipeline {
                    elems: vec![Elem::Cmd(cmd)],
                    chain: Some(last),
                    negated: false,
                });
                out.push(vec![stmt], last);
                continue;
            }
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
        // `(( … ))` and `[[ … ]]` are commands of their pipeline, so they keep its chain.
        let plain = |c: &ast::Command| {
            matches!(
                c,
                ast::Command::Simple(_)
                    | ast::Command::ExtendedTest(..)
                    | ast::Command::Compound(ast::CompoundCommand::Arithmetic(_), _)
            )
        };
        if p.seq.iter().all(plain) {
            let mut elems = Vec::new();
            for c in &p.seq {
                match c {
                    ast::Command::Simple(s) => elems.push(Elem::Cmd(self.simple(t, s, cx)?)),
                    ast::Command::ExtendedTest(test, redirects) => {
                        elems.push(Elem::Cmd(self.test_command(t, test, redirects, cx)?))
                    }
                    ast::Command::Compound(ast::CompoundCommand::Arithmetic(a), redirects) => {
                        let span = t.span(&a.loc);
                        elems.push(Elem::Cmd(self.arith_command(
                            t,
                            &[&a.expr.value],
                            span,
                            redirects.as_ref(),
                            cx,
                        )?))
                    }
                    _ => {}
                }
            }
            return Ok(vec![Stmt::Pipeline(Pipeline {
                elems,
                chain: Some(chain),
                negated: p.bang,
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
                negated: false,
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
                negated: false,
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
        let outer = self.unread_write.replace(false);
        let span = t.span(&test.loc);
        let mut args = Vec::new();
        self.test_words(t, &test.expr, span, cx, &mut args)?;
        let mut cmd = synthetic("[[", span, cx);
        cmd.args = args;
        for r in redirects.iter().flat_map(|r| r.0.iter()) {
            cmd.redirects.push(self.redirect(t, r, cx)?);
        }
        cmd.opaque = self.unread_write.replace(outer);
        Ok(cmd)
    }

    /// `(( … ))` (and a `for (( … ))` header) as a command named `((`.
    fn arith_command(
        &self,
        t: &Text,
        exprs: &[&str],
        span: Span,
        redirects: Option<&ast::RedirectList>,
        cx: Cx,
    ) -> Result<SimpleCommand, ParseError> {
        let outer = self.unread_write.replace(false);
        let mut cmd = synthetic("((", span, cx);
        for e in exprs {
            cmd.args.push(self.arith_word(e, span, cx)?);
        }
        for r in redirects.iter().flat_map(|r| r.0.iter()) {
            cmd.redirects.push(self.redirect(t, r, cx)?);
        }
        cmd.opaque = self.unread_write.replace(outer);
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
                    head: LoopHead::Items,
                });
                out
            }
            C::ArithmeticForClause(f) => {
                let exprs: Vec<&str> = [&f.initializer, &f.condition, &f.updater]
                    .into_iter()
                    .flatten()
                    .map(|e| e.value.as_str())
                    .collect();
                // The header runs before the loop: `;` joins them.
                let mut out = vec![Stmt::Pipeline(Pipeline {
                    elems: vec![Elem::Cmd(self.arith_command(t, &exprs, span, None, cx)?)],
                    chain: Some(ChainOp::Seq),
                    negated: false,
                })];
                let open = f
                    .condition
                    .as_ref()
                    .is_none_or(|c| c.value.trim().is_empty());
                out.push(Stmt::Loop {
                    body: self.body(t, &f.body.list, cx.looping())?,
                    span,
                    head: LoopHead::Counted { open },
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
                let cond = self.body(t, &w.0, cx)?;
                let head = LoopHead::Test {
                    cond: cond.stmts.len(),
                    at_end: false,
                    until: matches!(cc, C::UntilClause(_)),
                };
                let body = concat(cond, self.body(t, &w.1.list, cx)?);
                vec![Stmt::Loop { body, span, head }]
            }
            // A pipeline lowers `(( … ))` itself; this is `coproc (( … ))`.
            C::Arithmetic(a) => vec![Stmt::Pipeline(Pipeline {
                elems: vec![Elem::Cmd(self.arith_command(
                    t,
                    &[&a.expr.value],
                    span,
                    None,
                    cx,
                )?)],
                chain: None,
                negated: false,
            })],
            C::Coprocess(c) => {
                // `coproc NAME` writes NAME (bash expands the word). (`list` fails closed on
                // `coproc NAME [[ … ]]`, which the parser misreads.)
                if let Some(name) = &c.name {
                    let w = self.ast_word(t, name, span, cx)?;
                    self.runtime_target(Some(&w));
                }
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
        let outer = self.unread_write.replace(false);
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
        // The command word and its suffix as one list. A `{NAME}` word that touches a redirect
        // operator (`{x}>f`) belongs to that redirect: it leaves the list before the command
        // name, the wrapper target and the operands are picked.
        let head = s.word_or_name.clone().map(I::Word);
        let all: Vec<&I> = head
            .iter()
            .chain(s.suffix.iter().flat_map(|p| p.0.iter()))
            .collect();
        let mut items = Vec::new();
        let mut misread = false;
        for (i, &item) in all.iter().enumerate() {
            if let I::Word(w) = item
                && let Some(I::IoRedirect(_)) = all.get(i + 1)
                && let Some(name) = fd_target(&w.value)
            {
                match t.touches_redirect(w) {
                    Some(true) => {
                        self.descriptor_name(t, w, name, span, cx, &mut cmd.assigns)?;
                        continue;
                    }
                    Some(false) => {}
                    // The location does not hold the word: which word bash runs is not known.
                    None => misread = true,
                }
            }
            items.push((i, item));
        }
        // Before the command word, an assignment is bash's, not an argument (`{x}>f a=1 cmd`).
        let command_word = items
            .iter()
            .position(|(_, item)| matches!(item, I::Word(_) | I::ProcessSubstitution(..)));
        // The arguments the parser reads as `name=value` (an unquoted name and `=`) that bash
        // does not brace-expand.
        let mut assignment_args = Vec::new();
        for (k, &(i, item)) in items.iter().enumerate() {
            let is_name = command_word == Some(k);
            match item {
                I::IoRedirect(r) => cmd.redirects.push(self.redirect(t, r, cx)?),
                I::AssignmentWord(a, _) if command_word.is_none_or(|c| k < c) => {
                    self.assignment(t, a, cx, &mut cmd.assigns)?
                }
                // `export x=$(…)`: an argument of the builtin that also assigns `x`.
                I::AssignmentWord(a, w) => {
                    if !brace_expands(&w.value, &self.opts) {
                        assignment_args.push(cmd.args.len());
                    }
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
                I::Word(w) => {
                    let mut word = self.ast_word(t, w, span, cx)?;
                    self.fd_name(&w.value, &mut word, all.get(i + 1).copied(), cx)?;
                    if is_name {
                        cmd.name = word;
                        cmd.typed = w.value.clone();
                    } else {
                        cmd.args.push(word);
                    }
                }
                I::ProcessSubstitution(_, sub) => {
                    let word = self.process_subst(t, sub, cx)?;
                    if is_name {
                        cmd.name = word;
                    } else {
                        cmd.args.push(word);
                    }
                }
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
        let named = !cmd.name.parts.is_empty();
        // A wrapper is the command word itself, so a wrapped builtin is never bare.
        let bare = target.as_deref() == Some(cmd.typed.as_str());
        let assignments: &[usize] = if bare { &assignment_args } else { &[] };
        self.name_writer_words(&cmd, target.as_deref(), first_arg, assignments);
        let runs_text = match target.as_deref() {
            Some("eval") => true,
            Some("source" | ".") => wrapped,
            _ => false,
        };
        let runs_dynamic_text = runs_text && cmd.args.iter().skip(first_arg).any(Word::is_dynamic);
        // An `eval` body is not lowered here: it may write any name.
        if target.as_deref() == Some("eval") {
            self.any_integer.set(true);
        }
        self.runtime_targets(&cmd, target.as_deref(), first_arg);
        self.declarations(&cmd, target.as_deref(), first_arg);
        self.evaluated_operands(&mut cmd, target.as_deref(), first_arg, cx)?;
        // A name no rule can match is opaque: a variable, a glob, anything without a canonical name.
        let unknown_name = named && cmd.canonical.is_none();
        let unread_write = self.unread_write.replace(outer);
        cmd.opaque = cmd.name.is_dynamic()
            || has_glob
            || runs_dynamic_text
            || unknown_name
            || unread_write
            || misread;
        Ok(cmd)
    }

    /// A builtin that writes a name is read exactly only when each word that may be an option, an
    /// option argument or a name is literal text: an expansion (a variable, a glob, a brace) may
    /// name another option or target. Bash does not split or glob a `name=…` argument (an
    /// unquoted name and `=`) of the bare builtin, unless it brace-expands it, but does behind
    /// `command`/`builtin` or a quoted command word: `assignments` holds the indices of those
    /// arguments when the builtin is bare. (`let` is arithmetic: its words read like the same text
    /// outside it.)
    fn name_writer_words(
        &self,
        cmd: &SimpleCommand,
        target: Option<&str>,
        first_arg: usize,
        assignments: &[usize],
    ) {
        let declaration = matches!(
            target,
            Some("declare" | "typeset" | "local" | "export" | "readonly")
        );
        let first = first_arg.min(cmd.args.len());
        let words = &cmd.args[first..];
        let words = match target {
            _ if declaration => words,
            Some("read" | "mapfile" | "readarray") => words,
            // `getopts OPTSTRING NAME [ARG…]`: the arguments are only parsed.
            Some("getopts") => &words[..words.len().min(2)],
            Some("printf") => &words[..printf_option_words(words)],
            Some("wait") => &words[..wait_option_words(words)],
            _ => return,
        };
        for (i, w) in words.iter().enumerate() {
            let assignment = declaration && assignments.contains(&(first + i));
            if exact(w).is_none() && !assignment {
                // A `declare` word may be `-i` or `-n`: any name may turn integer.
                if matches!(target, Some("declare" | "typeset" | "local")) {
                    self.any_integer.set(true);
                } else {
                    self.runtime_target(None);
                }
                return;
            }
        }
    }

    /// The operands of a declaration builtin (`declare -i n=x`, `local 'x=…'`): the names they
    /// declare integer, so that a value assigned to one later is arithmetic, and a name that is not
    /// static (`declare "$n=1"`, `declare 'x:-y=1'`). A nameref (`-n` in a cluster) writes its
    /// target's name: any name may turn integer.
    fn declarations(&self, cmd: &SimpleCommand, target: Option<&str>, first_arg: usize) {
        if !matches!(
            target,
            Some("declare" | "typeset" | "local" | "export" | "readonly")
        ) {
            return;
        }
        let words: Vec<(String, &Word)> = cmd
            .args
            .iter()
            .skip(first_arg)
            .map(|w| (value_text(w), w))
            .collect();
        if matches!(target, Some("declare" | "typeset" | "local"))
            && words
                .iter()
                .any(|(v, _)| v.starts_with('-') && v[1..].contains('n'))
        {
            self.any_integer.set(true);
        }
        let integer = words
            .iter()
            .any(|(v, _)| v.starts_with('-') && v.contains('i'));
        for (v, w) in words.iter().filter(|(v, _)| !v.starts_with('-')) {
            let (name, value) = match v.split_once('=') {
                Some((n, value)) => (n, Some(value)),
                None => (v.as_str(), None),
            };
            let name = name.split('[').next().unwrap_or_default();
            let name = name.strip_suffix('+').unwrap_or(name);
            if integer {
                self.integers.borrow_mut().insert(name.to_string());
            }
            if value.is_some() {
                match w.parts.first() {
                    Some(WordPart::Literal(first)) if first.contains('=') => {
                        if !is_identifier(name) {
                            self.runtime_target(None);
                        }
                    }
                    // `declare "$n=…"`: the name is not static.
                    _ => self.runtime_target(None),
                }
            }
        }
    }

    /// Names `read`, `mapfile`/`readarray`, `printf -v`, `getopts` and `wait -p` set at run time.
    fn runtime_targets(&self, cmd: &SimpleCommand, target: Option<&str>, first_arg: usize) {
        let env = EnvView::new();
        let args = &cmd.args[first_arg.min(cmd.args.len())..];
        let value = |i: usize| args.get(i).and_then(|w| w.static_value(&env));
        // Options whose argument is the rest of the word or the next word; `read -a NAME` names
        // the target.
        let flags = match target {
            Some("read") => "ers",
            Some("mapfile" | "readarray") => "t",
            Some("wait") => "fn",
            _ => "",
        };
        let with_argument = match target {
            Some("read") => "adinNptu",
            Some("mapfile" | "readarray") => "dnOsuCc",
            Some("wait") => "p",
            Some("printf") => "v",
            Some("getopts") => "",
            _ => return,
        };
        let mut i = 0;
        let mut operands = Vec::new();
        while i < args.len() {
            match value(i) {
                // `printf -vNAME`: the target is glued to the option.
                Some(v) if target == Some("printf") && v.starts_with("-v") && v.len() > 2 => {
                    self.runtime_target(Some(&literal(&v[2..], cmd.span)));
                }
                Some(v) if target == Some("printf") && v == "-v" => {
                    self.runtime_target(args.get(i + 1));
                    i += 1;
                }
                // `wait --`: the words after it are operands.
                Some(v) if target == Some("wait") && v == "--" => break,
                // A `read`/`mapfile`/`wait` cluster, letter by letter as getopts reads it; a
                // letter not listed may write a name the lowering does not see.
                Some(v) if v.len() > 1 && v.starts_with('-') && !flags.is_empty() => {
                    for (k, ch) in v[1..].char_indices() {
                        if with_argument.contains(ch) {
                            let rest = &v[1 + k + ch.len_utf8()..];
                            let argument = if rest.is_empty() {
                                i += 1;
                                args.get(i).cloned()
                            } else {
                                Some(literal(rest, cmd.span))
                            };
                            if (target == Some("read") && ch == 'a')
                                || (target == Some("wait") && ch == 'p')
                            {
                                self.runtime_target(argument.as_ref());
                            }
                            break;
                        }
                        if !flags.contains(ch) {
                            self.runtime_target(None);
                            break;
                        }
                    }
                }
                _ if target == Some("printf") => break,
                _ => operands.push(i),
            }
            i += 1;
        }
        match target {
            Some("read" | "mapfile" | "readarray") => {
                for i in operands {
                    self.runtime_target(args.get(i));
                }
            }
            // `getopts OPTSTRING NAME`
            Some("getopts") => self.runtime_target(operands.get(1).and_then(|&i| args.get(i))),
            _ => {}
        }
    }

    /// Operands bash evaluates as arithmetic, where a `name[…]` subscript in a static string runs
    /// its `$(…)` (`let 'a[$(…)]'`, `printf -v`, `read`, `test -v`, `declare`, `unset`).
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
            // Each operand; `unset` evaluates the subscript of an indexed array, and a nameref
            // target (`declare -n r=v`) is a name whose subscript is evaluated where `$r` expands.
            Some("let" | "read" | "declare" | "typeset" | "local" | "unset") => {
                picked.extend(first_arg..cmd.args.len())
            }
            Some("printf" | "test" | "[") => {
                for (i, arg) in cmd.args.iter().enumerate().skip(first_arg) {
                    match arg.static_value(&env).as_deref() {
                        Some("-v") => picked.push(i + 1),
                        Some(v) if target == Some("printf") && v.starts_with("-v") => {
                            picked.push(i)
                        }
                        _ => {}
                    }
                }
            }
            // `wait -p NAME`, `-pNAME`, `-np NAME`: bash assigns NAME.
            Some("wait") => {
                for (i, arg) in cmd.args.iter().enumerate().skip(first_arg) {
                    match arg.static_value(&env) {
                        Some(v) if v.len() > 1 && v.starts_with('-') && v.contains('p') => {
                            picked.push(if v.ends_with('p') { i + 1 } else { i })
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
        let parts = self.subscript_commands(w, cx)?;
        w.parts.extend(parts);
        Ok(())
    }

    /// The commands in the `[…]` subscripts of a static word, as `Subst` parts.
    fn subscript_commands(&self, w: &Word, cx: Cx) -> Result<Vec<WordPart>, ParseError> {
        let mut out = Vec::new();
        let Some(value) = w.static_value(&EnvView::new()) else {
            return Ok(out);
        };
        for sub in subscripts(&value) {
            if runs_code(sub) {
                self.charge(sub.len(), w.span)?;
                let inner =
                    self.word_text(sub, Origin::Inexact(w.span), w.span, cx.deeper(w.span)?)?;
                out.extend(commands_only(inner));
            }
        }
        Ok(out)
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
                let mut value = self.word_text(&w.value, origin, span, cx)?;
                // A value assigned to an integer name is arithmetic: its quoted subscripts run
                // their `$(…)`.
                if self.is_integer(&name) {
                    self.subscript_substs(&mut value, cx)?;
                }
                out.push((name, value));
            }
            ast::AssignmentValue::Array(items) => {
                for (key, value) in items {
                    if let Some(k) = key {
                        let k = self.ast_word(t, k, span, cx)?;
                        out.push((name.clone(), k));
                    }
                    let value = self.ast_word(t, value, span, cx)?;
                    out.push((name.clone(), value));
                }
            }
        }
        Ok(())
    }

    /// `{NAME} >f`: with a space bash reads `{NAME}` as a word, which the parser also reads before
    /// a redirect. It stays a word, and its subscript is read as `descriptor_name` reads it (an
    /// over-report).
    fn fd_name(
        &self,
        raw: &str,
        w: &mut Word,
        next: Option<&ast::CommandPrefixOrSuffixItem>,
        cx: Cx,
    ) -> Result<(), ParseError> {
        if let Some(ast::CommandPrefixOrSuffixItem::IoRedirect(_)) = next
            && fd_target(raw).is_some()
        {
            self.subscript_substs(w, cx)?;
        }
        Ok(())
    }

    /// `{NAME}>f` stores the new descriptor's number in NAME and evaluates a subscript of it
    /// (`{a[i]}>f`). The commands in the subscript stay in the IR as an assignment.
    fn descriptor_name(
        &self,
        t: &Text,
        w: &ast::Word,
        name: &str,
        span: Span,
        cx: Cx,
        assigns: &mut Vec<(String, Word)>,
    ) -> Result<(), ParseError> {
        let mut word = self.ast_word(t, w, span, cx)?;
        self.subscript_substs(&mut word, cx)?;
        let span = word.span;
        let parts: Vec<WordPart> = commands_only(word).collect();
        if !parts.is_empty() {
            let quote = Quote::None;
            assigns.push((name.to_string(), Word { parts, span, quote }));
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
                    let pieces = word::parse_heredoc(&doc.value, &self.opts).map_err(|e| {
                        error(body_span, &format!("heredoc: {e}"), ParseKind::Syntax)
                    })?;
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
        let pieces = word::parse(value, &self.opts)
            .map_err(|e| error(span, &format!("word: {e}"), ParseKind::Syntax))?;
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
                            // `${x:=…}` assigns `x`, by a route the lowering does not follow.
                            if matches!(pe, ParameterExpr::AssignDefaultValues { .. }) {
                                self.runtime_target(None);
                            }
                            self.parameter_arith(pe, span, cx, out)?;
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

    /// The commands in the quoted subscripts of a `${s:o:l}` offset and length, which bash
    /// evaluates as arithmetic.
    fn parameter_arith(
        &self,
        pe: &ParameterExpr,
        span: Span,
        cx: Cx,
        out: &mut Vec<WordPart>,
    ) -> Result<(), ParseError> {
        if let ParameterExpr::Substring { offset, length, .. } = pe {
            for e in std::iter::once(offset).chain(length) {
                // An unquoted `$(…)` is a part of the expansion already.
                if runs_code(&e.value) && e.value.contains('[') {
                    self.charge(e.value.len(), span)?;
                    let w =
                        self.word_text(&e.value, Origin::Inexact(span), span, cx.deeper(span)?)?;
                    out.extend(self.subscript_commands(&w, cx)?);
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
        negated: false,
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

/// The contents of each outermost `[…]` in `text`. As in bash, a `]` in quotes, after a backslash
/// or in `$(…)`/`${…}` does not close a subscript (and a `[` there opens none: bash evaluates no
/// subscript after such text outside one). An unclosed subscript runs to the end of the text (bash
/// refuses it; reading it whole stays on the safe side).
fn subscripts(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut start, mut i) = (0usize, 0usize, 0usize);
    while i < b.len() {
        match b[i] {
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
            b'\\' => i += 1,
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if q != b'\'' && b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'$' if matches!(b.get(i + 1), Some(b'(' | b'{')) => {
                let (open, close) = if b[i + 1] == b'(' {
                    (b'(', b')')
                } else {
                    (b'{', b'}')
                };
                let mut level = 0usize;
                i += 1;
                while i < b.len() {
                    if b[i] == open {
                        level += 1;
                    } else if b[i] == close {
                        level -= 1;
                        if level == 0 {
                            break;
                        }
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if depth > 0 {
        out.push(&text[start..]);
    }
    out
}

/// A shell variable name.
fn is_identifier(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A word that is literal text only: no expansion, glob or brace.
fn exact(w: &Word) -> Option<String> {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) => out.push_str(s),
            _ => return None,
        }
    }
    Some(out)
}

/// Whether bash brace-expands the word `raw` (`x={$o,2}`, `x=$o{,}`), as the parser splits it;
/// text it cannot split counts as expanded.
fn brace_expands(raw: &str, opts: &ParserOptions) -> bool {
    match word::parse_brace_expansions(raw, opts) {
        Ok(pieces) => pieces
            .iter()
            .flatten()
            .any(|p| matches!(p, word::BraceExpressionOrText::Expr(_))),
        Err(_) => true,
    }
}

/// How many leading words of `printf` may be an option or its target: up to the first word that
/// is no `-v` option (the format, `--`, or a word that is not literal text and may be `-v`).
fn printf_option_words(words: &[Word]) -> usize {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        match exact(w).as_deref() {
            Some("-v") => i += 2,
            Some(v) if v.starts_with("-v") => i += 1,
            _ => return i + 1,
        }
    }
    i.min(words.len())
}

/// How many leading words of `wait` may be an option or the `-p` target: up to the first operand
/// (a pid or job), past `--`, or up to a word that is not literal text and may be an option.
fn wait_option_words(words: &[Word]) -> usize {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        match exact(w).as_deref() {
            Some("--") => return i + 1,
            // `-p NAME`, `-np NAME`: the option takes the next word.
            Some(v) if v.len() > 1 && v.starts_with('-') => i += 1 + usize::from(v.ends_with('p')),
            Some(_) => return i,
            None => return i + 1,
        }
    }
    i.min(words.len())
}

/// The NAME of a `{NAME}` or `{NAME[…]}` word, which before a redirect operator names the
/// descriptor bash opens.
fn fd_target(raw: &str) -> Option<&str> {
    let inner = raw.strip_prefix('{')?.strip_suffix('}')?;
    let name = inner.split('[').next()?;
    is_identifier(name).then_some(name)
}

/// A `coproc` whose body the parser read as a command NAME with the words of a `[[ … ]]` test.
fn misread_coproc(p: &ast::Pipeline) -> Option<&ast::CoprocessCommand> {
    p.seq.iter().find_map(|c| match c {
        ast::Command::Compound(ast::CompoundCommand::Coprocess(c), _) => match c.body.as_ref() {
            ast::Command::Simple(s) => {
                let w0 = s.suffix.as_ref().and_then(|x| x.0.first());
                let test =
                    matches!(w0, Some(ast::CommandPrefixOrSuffixItem::Word(w)) if w.value == "[[");
                test.then_some(c)
            }
            _ => None,
        },
        _ => None,
    })
}

/// A word as the text bash evaluates: literals as written, each variable as `${name}`, an
/// arithmetic expansion as `$((…))`, each substitution's output left out.
fn value_text(w: &Word) -> String {
    rendered(w, |_| String::new())
}

fn rendered(w: &Word, subst: impl Fn(&Script) -> String) -> String {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) | WordPart::Glob(s) => out.push_str(s),
            WordPart::Var(v) if v.starts_with("((") => {
                out.push('$');
                out.push_str(v);
            }
            WordPart::Var(v) => {
                out.push_str("${");
                out.push_str(v);
                out.push('}');
            }
            WordPart::Tilde => out.push('~'),
            WordPart::Subst(s) | WordPart::Block(s) => out.push_str(&subst(s)),
            // Bash never builds a `ListSep`; a list has no single value, so render one as an
            // unread substitution.
            WordPart::ListSep => out.push_str("$(…)"),
        }
    }
    out
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

/// A tokenizer error. An unclosed quote is `UnclosedQuote` only in the command's own text
/// (`depth` 0): text nested in a substitution was already tokenized once as part of the
/// command, so an unclosed quote there is a disagreement between the two readings, not a proven
/// error of the shell.
fn tokenizer_error(t: &Text, e: &TokenizerError, depth: usize) -> ParseError {
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
    let kind = match (unclosed, e) {
        (Some(q), _) if depth == 0 => ParseKind::UnclosedQuote(q),
        (_, TokenizerError::UnterminatedHereDocuments(..)) => ParseKind::UnterminatedHeredoc,
        _ => ParseKind::Syntax,
    };
    error(span, &format!("bash: {e}"), kind)
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
