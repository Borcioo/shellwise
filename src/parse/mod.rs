//! Parsers that lower shell text into the IR. A text a parser cannot read fully is an error, never a
//! partial script: the caller turns it into the fail-closed verdict.

use crate::level::Span;

pub mod bash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub span: Span,
    pub message: String,
    /// The quote left open at the end of the input, when that is the error.
    pub unclosed: Option<QuoteKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteKind {
    Single,
    Double,
    Backtick,
}
