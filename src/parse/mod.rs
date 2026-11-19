//! Parsers that lower shell text into the IR. A text a parser cannot read fully is an error, never a
//! partial script: the caller turns it into the fail-closed verdict.

use crate::level::Span;

pub mod bash;
pub mod pwsh;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Where the error is; for an unclosed quote, from the opening quote to the end.
    pub span: Span,
    pub message: String,
    pub kind: ParseKind,
}

/// What kind of error the parser found, where it can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseKind {
    /// A quote left open at the end of the text.
    UnclosedQuote(QuoteKind),
    EmptyPipeElement,
    MissingArgument,
    UnexpectedToken,
    /// A heredoc whose end line never comes.
    UnterminatedHeredoc,
    /// Nesting past what the parser reads safely.
    TooDeep,
    /// Text the parser reads but the lowering does not model, or may read differently from the
    /// shell.
    Unmodelled,
    /// Any other syntax error.
    Syntax,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteKind {
    Single,
    Double,
    Backtick,
}
