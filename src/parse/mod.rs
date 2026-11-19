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
    /// The parser itself failed: no syntax error is known, so the analysis is incomplete.
    Internal(Failure),
}

/// How a parser failed itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    BashThreadNotStarted,
    BashPanicked,
    PwshNotFinished,
    PwshGrammarNotLoaded,
    PwshNoTree,
}

/// The error of a parser that failed itself, over `span`.
pub(crate) fn internal(span: Span, failure: Failure) -> ParseError {
    ParseError {
        span,
        message: failure.reason().to_string(),
        kind: ParseKind::Internal(failure),
    }
}

impl Failure {
    /// The reason an incomplete verdict names.
    pub fn reason(self) -> &'static str {
        match self {
            Failure::BashThreadNotStarted => "the parser thread did not start",
            Failure::BashPanicked => "the parser panicked",
            Failure::PwshNotFinished => "the PowerShell parser did not finish",
            Failure::PwshGrammarNotLoaded => "the PowerShell grammar did not load",
            Failure::PwshNoTree => "the PowerShell parser gave no tree",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteKind {
    Single,
    Double,
    Backtick,
}
