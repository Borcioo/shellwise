//! PowerShell to the IR, through the vendored tree-sitter grammar (`vendor/tree-sitter-powershell`).
//!
//! Any ERROR or MISSING node in the tree is a `ParseError`, and so is any node kind the lowering
//! does not model: a command the IR drops would be invisible to every rule. Nesting stops at
//! `ir::MAX_NESTING`. Recursion happens only where the text opens a level (a block, a
//! parenthesis, a substitution, an assigned statement); expression ladders, operator chains and
//! prefix operators are walked in loops, so a deep expression cannot overflow the stack.
//!
//! IR conventions (shared with the rules and the file-system layer):
//! - `$env:X` is `Var("env:X")`, `$x` and `${x}` are `Var("x")`, a splat `@x` is `Var("x")`.
//! - A comma list (`a,b`, `'a','b'`, `-Path:a,b`) is one word, as PowerShell binds it: each
//!   array separator is a `WordPart::ListSep` and each element's literal text is one part. A
//!   quoted or escaped comma (`'a,b'`, `` a`,b ``) stays inside a `Literal`. The word's quote is
//!   the elements' quoting (`None` only when every element is plain unquoted text).
//! - An assignment is a command with no name whose `assigns` hold the target names; a value that
//!   is not a plain string or variable is a `Subst` holding the assigned statement.
//! - An expression that is not a literal, a variable or a substitution lowers to one `Subst`
//!   part holding every command, block and static method call inside it, so it is never static.

use std::sync::OnceLock;

use tree_sitter::{Node, Parser, Tree};

use super::{ParseError, QuoteKind};
use crate::ir::{
    ChainOp, Comment, Elem, MAX_NESTING, MethodCall, Pipeline, Quote, Redirect, Script,
    SimpleCommand, Stmt, Word, WordPart,
};
use crate::level::Span;
use crate::{Os, Shell};

/// Stack of the thread that parses and lowers. A reservation: pages are committed when used.
const STACK_BYTES: usize = 256 * 1024 * 1024;

/// Parse `src` as the given PowerShell dialect on `os`. Any syntax error, unmodelled construct
/// or nesting past `ir::MAX_NESTING` is an error: the caller fails closed.
pub fn parse(src: &str, dialect: Shell, os: Os) -> Result<Script, ParseError> {
    let out = parse_lossy(src, dialect, os);
    if let Some(e) = out.tree_error {
        return Err(e);
    }
    match out.lower_error {
        Some(e) => Err(e),
        None => Ok(out.script),
    }
}

/// The result of a lowering that goes on past syntax errors, for the measurement dump only.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct Lossy {
    pub script: Script,
    /// The first ERROR or MISSING node of the tree.
    pub tree_error: Option<ParseError>,
    /// What the lowering refused (an unmodelled node, the nesting cap).
    pub lower_error: Option<ParseError>,
    /// `command` nodes in the tree.
    pub tree_commands: usize,
}

/// Lower `src` even when the tree holds errors, lowering the commands found inside them. Never a
/// basis for a verdict: `parse` refuses every input where this reports an error.
#[doc(hidden)]
pub fn parse_lossy(src: &str, dialect: Shell, os: Os) -> Lossy {
    let whole = Span {
        start: 0,
        end: src.len(),
    };
    if !matches!(dialect, Shell::Pwsh | Shell::Powershell5) {
        let e = error(whole, "not a PowerShell dialect", None);
        return Lossy {
            tree_error: Some(e),
            ..Lossy::default()
        };
    }
    let owned = src.to_string();
    let run = std::thread::Builder::new()
        .name("pwsh-parse".into())
        .stack_size(STACK_BYTES)
        .spawn(move || lossy_on_this_thread(&owned, dialect, os));
    let joined = match run {
        Ok(handle) => handle.join().ok(),
        Err(_) => None,
    };
    joined.unwrap_or_else(|| Lossy {
        tree_error: Some(error(whole, "the PowerShell parser did not finish", None)),
        ..Lossy::default()
    })
}

fn lossy_on_this_thread(src: &str, dialect: Shell, os: Os) -> Lossy {
    let whole = Span {
        start: 0,
        end: src.len(),
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .is_err()
    {
        return Lossy {
            tree_error: Some(error(whole, "the PowerShell grammar did not load", None)),
            ..Lossy::default()
        };
    }
    let Some(tree) = parser.parse(src, None) else {
        return Lossy {
            tree_error: Some(error(whole, "the PowerShell parser gave no tree", None)),
            ..Lossy::default()
        };
    };
    let tree_error = first_tree_error(src, &tree);
    let lower = Lower {
        src,
        dialect,
        os,
        lossy: tree_error.is_some(),
    };
    let root = tree.root_node();
    let (script, lower_error) = if tree_error.is_some() {
        lower.flat(root)
    } else {
        match lower.program(root) {
            Ok(s) => (s, None),
            Err((partial, e)) => (partial, Some(e)),
        }
    };
    let lower_error = match tree_error {
        None => unproven_special_char(src, root)
            .or_else(|| misread_node(src, root))
            .or(lower_error)
            .or_else(|| unglued(src, root)),
        Some(_) => lower_error,
    };
    Lossy {
        script,
        tree_error,
        lower_error,
        tree_commands: count_kind(root, "command"),
    }
}

fn error(span: Span, message: &str, unclosed: Option<QuoteKind>) -> ParseError {
    ParseError {
        span,
        message: message.to_string(),
        unclosed,
    }
}

fn span(n: Node) -> Span {
    Span {
        start: n.start_byte(),
        end: n.end_byte(),
    }
}

/// Children of `n`, in order.
fn kids(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.children(&mut c).collect()
}

fn named_kids(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

fn count_kind(root: Node, kind: &str) -> usize {
    let mut n = 0;
    let mut stack = vec![root];
    while let Some(x) = stack.pop() {
        if x.kind() == kind {
            n += 1;
        }
        stack.extend(kids(x));
    }
    n
}

/// The first ERROR or MISSING node, in text order, as an error.
fn first_tree_error(src: &str, tree: &Tree) -> Option<ParseError> {
    let root = tree.root_node();
    if !root.has_error() {
        return None;
    }
    let mut best: Option<Node> = None;
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.is_error() || n.is_missing() {
            if best.is_none_or(|b| n.start_byte() < b.start_byte()) {
                best = Some(n);
            }
            continue;
        }
        if n.has_error() {
            stack.extend(kids(n));
        }
    }
    let unclosed = unclosed_quote(src);
    let (sp, message) = match best {
        Some(n) if n.is_missing() => (
            span(n),
            format!("PowerShell syntax error: missing `{}`", n.kind()),
        ),
        Some(n) => (span(n), "PowerShell syntax error".to_string()),
        None => (
            Span {
                start: 0,
                end: src.len(),
            },
            "PowerShell syntax error".to_string(),
        ),
    };
    Some(error(sp, &message, unclosed))
}

/// The quote left open at the end of `src`, read the way PowerShell reads quotes: `''` inside
/// single quotes, backtick escapes and `""` inside double quotes, `#` comments outside them.
fn unclosed_quote(src: &str) -> Option<QuoteKind> {
    #[derive(PartialEq)]
    enum S {
        Out,
        Single,
        Double,
        Line,
        Block,
    }
    let b: Vec<char> = src.chars().collect();
    let mut s = S::Out;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match s {
            S::Out => match c {
                '`' => i += 1,
                '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => s = S::Single,
                '"' | '\u{201c}' | '\u{201d}' | '\u{201e}' => s = S::Double,
                '<' if next == Some('#') => {
                    s = S::Block;
                    i += 1;
                }
                '#' => s = S::Line,
                _ => {}
            },
            S::Single => {
                if is_single_quote(c) {
                    if next.is_some_and(is_single_quote) {
                        i += 1;
                    } else {
                        s = S::Out;
                    }
                }
            }
            S::Double => {
                if c == '`' {
                    i += 1;
                } else if is_double_quote(c) {
                    if next.is_some_and(is_double_quote) {
                        i += 1;
                    } else {
                        s = S::Out;
                    }
                }
            }
            S::Line => {
                if c == '\n' || c == '\r' {
                    s = S::Out;
                }
            }
            S::Block => {
                if c == '#' && next == Some('>') {
                    s = S::Out;
                    i += 1;
                }
            }
        }
        i += 1;
    }
    match s {
        S::Single => Some(QuoteKind::Single),
        S::Double => Some(QuoteKind::Double),
        _ => None,
    }
}

fn is_single_quote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}')
}

fn is_double_quote(c: char) -> bool {
    matches!(c, '"' | '\u{201c}' | '\u{201d}' | '\u{201e}')
}

fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

/// A space PowerShell splits words on that the grammar's `\p{Zs}` does not hold.
fn is_unlisted_space(c: char) -> bool {
    matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// The first non-ASCII character PowerShell's tokenizer reads as an ASCII dash or quote, or
/// splits words on (`CharExtensions` in pwsh 7.7.0: `IsDash`, `IsSingleQuote`,
/// `IsDoubleQuote`, `IsWhitespace`), that sits where the grammar is not proven to read it the
/// same way. Proven: a comment, the `--%` text, and every string and here-string token, whose
/// delimiters and doubled escapes take each quote class whole (grammar.js, scanner.c); in a bare
/// word, a quote (its quoted sections take the classes whole) and a dash after the first
/// character (text for PowerShell, as `-` is).
fn unproven_special_char(src: &str, root: Node) -> Option<ParseError> {
    for (i, c) in src.char_indices() {
        let dash = c != '-' && is_dash(c);
        let single = c != '\'' && is_single_quote(c);
        let double = c != '"' && is_double_quote(c);
        if !(dash || single || double || is_unlisted_space(c)) {
            continue;
        }
        let end = i + c.len_utf8();
        let proven = root
            .named_descendant_for_byte_range(i, end)
            // `\u{85}'a'`, `\u{85}# x`: the token's first character is outside its body.
            .filter(|n| !(is_unlisted_space(c) && n.start_byte() == i))
            .is_some_and(|n| match n.kind() {
                // `--%` text: `verbatim_end` checks where it ends, typographic quotes included.
                "comment"
                | "stop_parsing"
                | "verbatim_string_characters"
                | "expandable_string_literal"
                | "verbatim_here_string_characters"
                | "expandable_here_string_literal" => true,
                // A word-start dash is a parameter (`–Recurse`).
                "generic_token" => single || double || (dash && i != n.start_byte()),
                _ => false,
            });
        if !proven {
            return Some(error(
                Span { start: i, end },
                "PowerShell reads this character as an ASCII dash, quote or space here",
                None,
            ));
        }
    }
    None
}

/// A node the grammar reads where PowerShell's tokenizer reads another token: a member access on
/// a number (`1.x` is one generic token, a command name at a statement start) or with a space or
/// line end inside, a number glued to a dot as a command name (`5GB.`), a dot after a variable in
/// a command name (`$m..x`), `++`/`--` after a string (`"a"--` is two arguments), a comment after a backtick line end glued to a word (word text), and a variable
/// glued to a `?` (`$m?` names the variable `m?`).
fn misread_node(src: &str, root: Node) -> Option<ParseError> {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        let misread = match n.kind() {
            "member_access" => {
                let ks = kids(n);
                ks.first()
                    .is_some_and(|r| matches!(r.kind(), "integer_literal" | "real_literal"))
                    || ks.windows(2).any(|w| w[0].end_byte() != w[1].start_byte())
                    // `(ls)<#x#>.ForEach(…)`: what PowerShell names the member is not modelled.
                    || ks.iter().any(|k| k.kind() == "comment")
                    // `$?.{x}`, `$$.(x)`: PowerShell ends the argument at the dot.
                    || (ks.first().is_some_and(|r| {
                        matches!(&src[r.start_byte()..r.end_byte()], "$?" | "$^" | "$$")
                    }) && ks.last().is_some_and(|m| {
                        m.kind() == "member_name" && src[m.start_byte()..].starts_with(['{', '('])
                    }))
            }
            "invokation_expression" | "invokation_foreach_expression" => {
                kids(n).iter().any(|k| k.kind() == "comment")
            }
            // A word the tree ends at a backtick that escapes the line end after it.
            "generic_token" | "command_parameter" => {
                (escaped_at(src.as_bytes(), n.end_byte())
                    && (src[n.end_byte()..].starts_with('\n')
                        || src[n.end_byte()..].starts_with('\r')))
                    // `-a=b: x`: PowerShell takes the next argument as the parameter's value.
                    || (n.kind() == "command_parameter" && {
                        let t = &src[n.start_byte()..n.end_byte()];
                        !t.starts_with("--")
                            && t.ends_with(':')
                            && src[n.end_byte()..].starts_with(char::is_whitespace)
                    })
                    // `a,]b`: a `]` starting a word is a token of its own for PowerShell.
                    || (n.kind() == "generic_token" && {
                        let t = &src[n.start_byte()..n.end_byte()];
                        t.len() > 1 && t.starts_with(']')
                    })
            }
            "command_name" => {
                let t = &src[n.start_byte()..n.end_byte()];
                (t.starts_with(|c: char| c.is_ascii_digit()) && t.ends_with('.'))
                    // `.2#x`, `.2.x`: PowerShell reads the number `.2`, then a comment or a member.
                    || t.strip_prefix('.').is_some_and(|r| {
                        r.starts_with(|c: char| c.is_ascii_digit()) && r.contains(['#', '.'])
                    })
            }
            // `& $x.Name` is a member access for PowerShell too.
            "path_command_name" => kids(n).windows(2).any(|w| {
                // `. $dir\<TAB>.ps1`: a space ends the name for PowerShell.
                w[0].end_byte() != w[1].start_byte()
                    || (w[0].kind() == "variable"
                        && src[w[1].start_byte()..].strip_prefix('.').is_some_and(|r| {
                            !r.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                        }))
            }),
            "post_increment_expression" | "post_decrement_expression" => named_kids(n)
                .first()
                .is_some_and(|r| matches!(r.kind(), "string_literal" | "script_block_expression")),
            // `if<#x#> (…)`: a comment glued to a keyword makes the pair a command name.
            "comment"
                if n.prev_sibling().is_some_and(|k| {
                    !k.is_named()
                        && k.end_byte() == n.start_byte()
                        && src[k.start_byte()..k.end_byte()].ends_with(|c: char| c.is_alphabetic())
                }) =>
            {
                true
            }
            "comment" => {
                let before = src[..n.start_byte()].trim_end_matches([' ', '\t']);
                let before = before
                    .strip_suffix("\r\n")
                    .or_else(|| before.strip_suffix('\n'))
                    .and_then(|b| b.strip_suffix('`'));
                before.is_some_and(|b| b.ends_with(|c: char| !c.is_whitespace()))
            }
            // `${a}?.Name` ends at the brace.
            "variable" => {
                !src[n.start_byte()..].starts_with("${") && src[n.end_byte()..].starts_with('?')
            }
            _ => false,
        };
        if misread {
            return Some(error(
                span(n),
                "PowerShell's tokenizer reads this as another token",
                None,
            ));
        }
        stack.extend(kids(n));
    }
    None
}

/// The first character of a glued pair's right piece, in the classes PowerShell's tokenizer
/// tells apart there (`CharExtensions`: a dash, a single or a double quote of any width) and the
/// characters that open a member, an index, a variable or a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lead {
    Dash,
    Single,
    Double,
    Question,
    Dot,
    Dollar,
    Paren,
    Brace,
    Bracket,
    Other,
}

fn lead(t: &str) -> Lead {
    match t.chars().next() {
        Some(c) if is_dash(c) => Lead::Dash,
        Some(c) if is_single_quote(c) => Lead::Single,
        Some(c) if is_double_quote(c) => Lead::Double,
        Some('?') => Lead::Question,
        Some('.') => Lead::Dot,
        Some('$') => Lead::Dollar,
        Some('(') => Lead::Paren,
        Some('{') => Lead::Brace,
        Some('[') => Lead::Bracket,
        _ => Lead::Other,
    }
}

/// Glued pairs PowerShell reads as the lowering does: left piece kind, right piece kind, the right
/// piece's first character, and the `tests/cases` row that shows PowerShell's reading. A pair
/// that is not here fails the parse (`unglued`).
#[rustfmt::skip]
const GLUE: &[(&str, &str, Lead, &str)] = &[
    ("generic_token", ",", Lead::Other, "glue-word-comma"),
    (",", "generic_token", Lead::Other, "glue-word-comma"),
    (",", "generic_token", Lead::Dot, "glue-comma-dot-word"),
    ("integer_literal", ",", Lead::Other, "glue-number-comma"),
    (",", "integer_literal", Lead::Other, "glue-number-comma"),
    ("expandable_string_literal", ",", Lead::Other, "glue-dquote-comma"),
    (",", "expandable_string_literal", Lead::Double, "glue-dquote-comma"),
    ("verbatim_string_characters", ",", Lead::Other, "glue-squote-comma"),
    (",", "verbatim_string_characters", Lead::Single, "glue-squote-comma"),
    ("hash_literal_expression", ",", Lead::Other, "glue-hash-comma"),
    (",", "hash_literal_expression", Lead::Other, "glue-hash-comma"),
    ("variable", ",", Lead::Other, "glue-variable-comma"),
    (",", "variable", Lead::Dollar, "comma-glued-vars"),
    ("glued_argument_tail", ",", Lead::Other, "comma-glued-vars"),
    ("member_access", ",", Lead::Other, "glue-member-comma"),
    (",", "member_access", Lead::Dollar, "glue-member-comma"),
    ("parenthesized_expression", ",", Lead::Other, "glue-paren-comma"),
    (",", "parenthesized_expression", Lead::Paren, "glue-paren-comma"),
    ("script_block_expression", ",", Lead::Other, "glue-block-comma"),
    ("variable", "glued_argument_tail", Lead::Other, "var-glued-path"),
    ("variable", "glued_argument_tail", Lead::Dash, "glue-variable-dash-tail"),
    ("glued_argument_tail", "variable", Lead::Dollar, "glue-tail-variable"),
    ("variable", "path_command_name_token", Lead::Other, "fix2-i2-variable-path-name-kept"),
    ("variable", "path_command_name_token", Lead::Dot, "glue-path-name-dot"),
    ("command_invokation_operator", "variable", Lead::Dollar, "fix2-i2-member-space-before-dot-kept"),
    ("command_invokation_operator", "verbatim_string_characters", Lead::Single, "fix2-i1-dot-ascii-quote-name"),
    ("command_name", "script_block_expression", Lead::Brace, "glue-name-block"),
    ("command_name", "line_continuation", Lead::Other, "fuzz-backtick-line-end-in-name"),
    ("command_name", "\"", Lead::Double, "glue-quote-name"),
    ("\"", "command_name", Lead::Other, "glue-quote-name"),
    ("\"", "command_name", Lead::Bracket, "glue-quote-name-bracket"),
    ("command_parameter", "command_argument_sep", Lead::Other, "glue-colon-variable"),
    ("command_argument_sep", "variable", Lead::Dollar, "glue-colon-variable"),
    ("command_argument_sep", "verbatim_string_characters", Lead::Single, "glue-colon-squote"),
    ("command_argument_sep", "generic_token", Lead::Other, "fix2-i2-colon-value-dot-kept"),
    ("command_parameter", "expandable_string_literal", Lead::Double, "param-glued-dquote"),
    ("command_parameter", "verbatim_string_characters", Lead::Single, "param-glued-quote"),
    ("command_parameter", "parenthesized_expression", Lead::Paren, "subexpr-in-param"),
    ("generic_token", "argument_list", Lead::Paren, "subexpr-glued-end"),
    ("generic_token", "parenthesized_expression", Lead::Paren, "glue-word-paren"),
    ("member_access", "argument_list", Lead::Paren, "member-call"),
    ("parenthesized_expression", "generic_token", Lead::Other, "glue-escaped-quote-paren"),
    ("script_block_expression", "script_block_expression", Lead::Brace, "glue-block-block"),
    ("expandable_string_literal", "generic_token", Lead::Other, "fix2-r1-closing-quote-then-word"),
    ("expandable_string_literal", "generic_token", Lead::Dash, "fix2-i2-quote-dash-param"),
    ("expandable_string_literal", "parenthesized_expression", Lead::Paren, "glue-dquote-paren"),
    ("expandable_string_literal", "line_continuation", Lead::Other, "fix2-i2-backtick-lf-after-quote-kept"),
    ("expandable_string_literal", "comment", Lead::Other, "glue-dquote-comment"),
    ("verbatim_string_characters", "generic_token", Lead::Other, "glue-squote-word"),
    ("verbatim_string_characters", "generic_token", Lead::Dash, "fix2-i2-quote-two-dash-param"),
    ("verbatim_string_characters", "generic_token", Lead::Question, "fix2-i1-question-word-after-string-kept"),
    ("verbatim_string_characters", "comment", Lead::Other, "fuzz-comment-after-quote"),
    ("parenthesized_expression", "comment", Lead::Other, "glued-paren"),
    ("file_redirection_operator", "variable", Lead::Dollar, "glued-redirect"),
    ("file_redirection_operator", "generic_token", Lead::Other, "fix2-r2-target-same-line"),
    ("file_redirection_operator", "comment", Lead::Other, "fix2-r2-comment-before-target"),
    ("comment", "generic_token", Lead::Other, "fix2-r2-comment-before-target"),
];

/// A piece of a command element (a node, a backtick line end, or text a node holds outside its
/// children), or a separator between two.
#[derive(Clone, Copy)]
enum Piece<'t> {
    Part(&'t str, usize, usize),
    Gap,
}

/// Nodes whose children are the pieces of a command element.
const PIECE_HOLDERS: &[&str] = &[
    "command_name",          // holds: a comment inside a bare name
    "command_name_expr",     // holds: the name after `&` or `.`
    "path_command_name",     // holds: a variable and path text in a name
    "command_elements",      // holds: the arguments, parameters and redirections
    "glued_string_argument", // holds: a string and the words glued after it
    "glued_argument",        // holds: a variable and the text glued after it
    "string_literal",        // holds: the string token
    "redirection",           // holds: a redirect operator and its target
    "redirected_file_name",  // holds: a redirect target's pieces
];

/// The kind of the text a node holds outside its children.
fn text_kind(parent: &str) -> &'static str {
    match parent {
        "command_name" => "command_name",
        "glued_argument" => "glued_argument_tail",
        _ => "text",
    }
}

/// Bytes between pieces, read against the grammar's extras: a space separates, a backtick line
/// end is a piece, and any other byte is the holder's text (a zero-width extra too: PowerShell
/// keeps `a<U+200B>,b` as one word).
fn gap_pieces(src: &str, from: usize, to: usize, parent: &str, out: &mut Vec<Piece<'_>>) {
    let t = &src[from..to];
    let mut i = 0;
    let mut run: Option<usize> = None;
    while i < t.len() {
        let rest = &t[i..];
        let cont = ["`\r\n", "`\n", "`\r"]
            .into_iter()
            .find(|p| rest.starts_with(p));
        let c = rest.chars().next().unwrap_or(' ');
        let sep = c.is_whitespace();
        if (cont.is_some() || sep)
            && let Some(s) = run.take()
        {
            out.push(Piece::Part(text_kind(parent), from + s, from + i));
        }
        if let Some(p) = cont {
            out.push(Piece::Part(
                "line_continuation",
                from + i,
                from + i + p.len(),
            ));
            i += p.len();
        } else if sep {
            out.push(Piece::Gap);
            i += c.len_utf8();
        } else {
            run.get_or_insert(i);
            i += c.len_utf8();
        }
    }
    if let Some(s) = run {
        out.push(Piece::Part(text_kind(parent), from + s, to));
    }
}

/// The pieces of `n` in text order. Holders nest a few levels at most (a command, its elements, a
/// glued word, a string), so the recursion is bounded.
fn flatten<'t>(src: &str, n: Node<'t>, out: &mut Vec<Piece<'t>>) {
    let mut pos = n.start_byte();
    for c in kids(n) {
        if c.start_byte() == c.end_byte() {
            continue;
        }
        gap_pieces(src, pos, c.start_byte(), n.kind(), out);
        let t = &src[c.start_byte()..c.end_byte()];
        if PIECE_HOLDERS.contains(&c.kind()) {
            flatten(src, c, out);
        } else if c.kind() == "command_argument_sep" && !t.contains(':') {
            // Spaces, with any extras the grammar put inside the separator.
            gap_pieces(src, c.start_byte(), c.end_byte(), c.kind(), out);
        } else if t.chars().all(char::is_whitespace) {
            out.push(Piece::Gap);
        } else {
            out.push(Piece::Part(c.kind(), c.start_byte(), c.end_byte()));
        }
        pos = c.end_byte();
    }
    gap_pieces(src, pos, n.end_byte(), n.kind(), out);
}

/// Every glued pair in the tree: two pieces of one command or `redirections` node with nothing
/// between them, as (left kind, right kind, right piece's first character, span of both).
fn glued_pairs<'t>(src: &str, root: Node<'t>) -> Vec<(&'t str, &'t str, Lead, Span)> {
    let mut pairs = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "command" | "redirections") {
            let mut pieces = Vec::new();
            flatten(src, n, &mut pieces);
            // `ls 2>$null<#x#>`: the tree ends the command before a comment glued to its end.
            if let Some(c) = root.named_descendant_for_byte_range(n.end_byte(), n.end_byte() + 1)
                && c.kind() == "comment"
                && c.start_byte() == n.end_byte()
            {
                pieces.push(Piece::Part(c.kind(), c.start_byte(), c.end_byte()));
            }
            for w in pieces.windows(2) {
                if let [Piece::Part(l, s, _), Piece::Part(r, rs, re)] = w {
                    let at = Span {
                        start: *s,
                        end: *re,
                    };
                    pairs.push((*l, *r, lead(&src[*rs..*re]), at));
                }
            }
        }
        stack.extend(kids(n));
    }
    pairs
}

/// The first glued pair that is not in `GLUE`: PowerShell's tokenizer may split or join it
/// differently from the grammar.
fn unglued(src: &str, root: Node) -> Option<ParseError> {
    glued_pairs(src, root)
        .into_iter()
        .find(|(l, r, c, _)| !GLUE.iter().any(|g| g.0 == *l && g.1 == *r && g.2 == *c))
        .map(|(l, r, _, at)| {
            error(
                at,
                &format!("PowerShell may read these glued pieces differently: {l}, {r}"),
                None,
            )
        })
}

/// `GLUE` as `left|right|Lead` keys with the row each cites (the row tests check the citations).
#[doc(hidden)]
pub fn glue_table() -> Vec<(String, &'static str)> {
    GLUE.iter()
        .map(|(l, r, c, row)| (format!("{l}|{r}|{c:?}"), *row))
        .collect()
}

/// The `left|right|Lead` key of every glued pair in `src` (none when the grammar does not load).
#[doc(hidden)]
pub fn glue_keys(src: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(src, None) else {
        return Vec::new();
    };
    glued_pairs(src, tree.root_node())
        .into_iter()
        .map(|(l, r, c, _)| format!("{l}|{r}|{c:?}"))
        .collect()
}

/// A lowering error, with the statements lowered so far (the dump shows them).
type LowerErr = (Script, ParseError);

#[derive(Clone, Copy)]
struct Cx {
    depth: usize,
    in_loop: bool,
}

impl Cx {
    fn deeper(self, at: Span) -> Result<Cx, ParseError> {
        let depth = self.depth + 1;
        if depth > MAX_NESTING {
            return Err(error(
                at,
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

struct Lower<'a> {
    src: &'a str,
    dialect: Shell,
    os: Os,
    /// The tree holds errors: lower what can be found instead of refusing (the dump only).
    lossy: bool,
}

type R<T> = Result<T, ParseError>;

impl<'a> Lower<'a> {
    fn text(&self, n: Node) -> &'a str {
        self.src.get(n.start_byte()..n.end_byte()).unwrap_or("")
    }

    fn unmodelled(&self, n: Node) -> ParseError {
        error(
            span(n),
            &format!("PowerShell construct not modelled: {}", n.kind()),
            None,
        )
    }

    /// A tree with errors, for the dump: every `command` node and static call lowered on its own
    /// (nested scripts are left empty, since their commands are listed themselves), as the parser
    /// spike read such trees.
    fn flat(&self, root: Node) -> (Script, Option<ParseError>) {
        let cx = Cx {
            depth: 0,
            in_loop: false,
        };
        let mut stmts = Vec::new();
        let mut first_error = None;
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            let r = match n.kind() {
                "command" => self.command(n, cx).map(|c| Some(Elem::Cmd(c))),
                "invokation_expression" => self.method_call(n, cx).map(|m| m.map(Elem::Method)),
                _ => Ok(None),
            };
            match r {
                Ok(Some(e)) => stmts.push(single_pipeline(e)),
                Ok(None) => {}
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
            push_kids(&mut stack, n);
        }
        let mut s = script_of(stmts);
        s.comments = self.comments(root);
        (s, first_error)
    }

    fn program(&self, root: Node) -> Result<Script, LowerErr> {
        let cx = Cx {
            depth: 0,
            in_loop: false,
        };
        let mut acc = Acc::default();
        let mut result = Ok(());
        for k in named_kids(root) {
            let r = match k.kind() {
                "statement_list" => self.statement_list_into(k, cx, &mut acc),
                "param_block" => self.collect(k, cx).map(|s| acc.push(s, ChainOp::Seq)),
                "comment" => Ok(()),
                _ => self.other_statement(k, cx, &mut acc),
            };
            if let Err(e) = r {
                result = Err(e);
                if !self.lossy {
                    break;
                }
            }
        }
        let comments = self.comments(root);
        let script = acc.finish(comments);
        match result {
            Ok(()) => Ok(script),
            Err(e) => Err((script, e)),
        }
    }

    /// Every comment in the tree, in text order.
    fn comments(&self, root: Node) -> Vec<Comment> {
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "comment" {
                let start = n.start_byte();
                let line_start = self.src[..start].rfind(['\n', '\r']).map_or(0, |i| i + 1);
                let trailing = !self.src[line_start..start].trim().is_empty();
                out.push(Comment {
                    text: self.text(n).to_string(),
                    span: span(n),
                    trailing,
                });
                continue;
            }
            let mut ks = kids(n);
            ks.reverse();
            stack.extend(ks);
        }
        out
    }

    /// A nested script: one level deeper.
    fn script(&self, list: Option<Node>, at: Span, cx: Cx) -> R<Script> {
        let cx = cx.deeper(at)?;
        if self.lossy {
            return Ok(Script::default());
        }
        let mut acc = Acc::default();
        if let Some(list) = list {
            self.statement_list_into(list, cx, &mut acc)?;
        }
        Ok(acc.finish(Vec::new()))
    }

    fn statement_list_into(&self, list: Node, cx: Cx, acc: &mut Acc) -> R<()> {
        for k in named_kids(list) {
            match k.kind() {
                "comment" | "label" | "empty_statement" => {}
                "background_operator" => acc.background(),
                _ => self.other_statement(k, cx, acc)?,
            }
        }
        Ok(())
    }

    fn other_statement(&self, n: Node, cx: Cx, acc: &mut Acc) -> R<()> {
        match n.kind() {
            "pipeline" => {
                for (stmt, after) in self.pipeline(n, cx)? {
                    acc.push(vec![stmt], after);
                }
                Ok(())
            }
            "statement_list" => self.statement_list_into(n, cx, acc),
            "comment" | "label" | "empty_statement" => Ok(()),
            "background_operator" => {
                acc.background();
                Ok(())
            }
            _ => {
                let stmts = self.statement(n, cx)?;
                acc.push(stmts, ChainOp::Seq);
                Ok(())
            }
        }
    }

    /// A compound statement.
    fn statement(&self, n: Node, cx: Cx) -> R<Vec<Stmt>> {
        let sp = span(n);
        Ok(match n.kind() {
            "if_statement" => {
                let mut branches = Vec::new();
                let mut cond: Option<Script> = None;
                for k in named_kids(n) {
                    match k.kind() {
                        "pipeline" => cond = Some(self.pipeline_script(k, cx)?),
                        "statement_block" => {
                            let body = self.block(k, cx)?;
                            branches.push(concat(cond.take().unwrap_or_default(), body));
                        }
                        "elseif_clauses" => {
                            for clause in named_kids(k) {
                                let mut c: Option<Script> = None;
                                for part in named_kids(clause) {
                                    match part.kind() {
                                        "pipeline" => c = Some(self.pipeline_script(part, cx)?),
                                        "statement_block" => {
                                            let body = self.block(part, cx)?;
                                            branches
                                                .push(concat(c.take().unwrap_or_default(), body));
                                        }
                                        "comment" => {}
                                        _ => return Err(self.unmodelled(part)),
                                    }
                                }
                            }
                        }
                        "else_clause" => {
                            for part in named_kids(k) {
                                match part.kind() {
                                    "statement_block" => branches.push(self.block(part, cx)?),
                                    "comment" => {}
                                    _ => return Err(self.unmodelled(part)),
                                }
                            }
                        }
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                vec![Stmt::Cond { branches, span: sp }]
            }
            "foreach_statement" => {
                let mut out = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "pipeline" => out.extend(self.pipeline_script(k, cx)?.stmts),
                        "statement_block" => out.push(Stmt::Loop {
                            body: self.block(k, cx.looping())?,
                            span: sp,
                        }),
                        "variable" | "foreach_parameter" | "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                out
            }
            "for_statement" => {
                let mut init = Script::default();
                let mut cond = Script::default();
                let mut iter = Script::default();
                let mut body = Script::default();
                let lx = cx.looping();
                for k in named_kids(n) {
                    match k.kind() {
                        "for_initializer" => init = self.only_pipeline(k, cx)?,
                        "for_condition" => cond = self.only_pipeline(k, lx)?,
                        "for_iterator" => iter = self.only_pipeline(k, lx)?,
                        "statement_block" => body = self.block(k, lx)?,
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                let mut out = init.stmts;
                out.push(Stmt::Loop {
                    body: concat(concat(cond, body), iter),
                    span: sp,
                });
                out
            }
            "while_statement" | "do_statement" => {
                let lx = cx.looping();
                let mut cond = Script::default();
                let mut body = Script::default();
                for k in named_kids(n) {
                    match k.kind() {
                        "while_condition" => cond = self.only_pipeline(k, lx)?,
                        "statement_block" => body = self.block(k, lx)?,
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                let body = if n.kind() == "do_statement" {
                    concat(body, cond)
                } else {
                    concat(cond, body)
                };
                vec![Stmt::Loop { body, span: sp }]
            }
            "switch_statement" => {
                let mut out = Vec::new();
                let mut branches = Vec::new();
                let lx = cx.looping();
                for k in named_kids(n) {
                    match k.kind() {
                        "switch_parameters" | "comment" => {}
                        "switch_condition" => out.extend(self.collect(k, cx)?),
                        "switch_body" => {
                            for clauses in named_kids(k) {
                                match clauses.kind() {
                                    "switch_clauses" => {
                                        for clause in named_kids(clauses) {
                                            branches.push(self.switch_clause(clause, lx)?);
                                        }
                                    }
                                    "comment" => {}
                                    _ => return Err(self.unmodelled(clauses)),
                                }
                            }
                        }
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                // Each clause can run once per input element.
                out.push(Stmt::Loop {
                    body: single(Stmt::Cond { branches, span: sp }),
                    span: sp,
                });
                out
            }
            "function_statement" => {
                let mut name = String::new();
                let mut pre = Vec::new();
                let mut body = Script::default();
                for k in named_kids(n) {
                    match k.kind() {
                        "function_name" => name = self.text(k).to_string(),
                        "function_parameter_declaration" => pre.extend(self.collect(k, cx)?),
                        "script_block" => body = self.script_block(k, cx)?,
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                vec![Stmt::Func {
                    name,
                    body: concat(script_of(pre), body),
                }]
            }
            "flow_control_statement" => {
                let mut out = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "pipeline" => out.extend(self.pipeline_script(k, cx)?.stmts),
                        "label_expression" => out.extend(self.collect(k, cx)?),
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                out
            }
            "trap_statement" => {
                let mut branches = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "statement_block" => branches.push(self.block(k, cx)?),
                        "type_literal" | "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                vec![Stmt::Cond { branches, span: sp }]
            }
            "try_statement" => {
                let mut out = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "statement_block" => out.push(Stmt::Block(self.block(k, cx)?)),
                        "catch_clauses" => {
                            let mut branches = Vec::new();
                            for c in named_kids(k) {
                                for part in named_kids(c) {
                                    match part.kind() {
                                        "statement_block" => branches.push(self.block(part, cx)?),
                                        "catch_type_list" | "comment" => {}
                                        _ => return Err(self.unmodelled(part)),
                                    }
                                }
                            }
                            out.push(Stmt::Cond {
                                branches,
                                span: span(k),
                            });
                        }
                        "finally_clause" => {
                            for part in named_kids(k) {
                                match part.kind() {
                                    "statement_block" => {
                                        out.push(Stmt::Block(self.block(part, cx)?))
                                    }
                                    "comment" => {}
                                    _ => return Err(self.unmodelled(part)),
                                }
                            }
                        }
                        "comment" => {}
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                out
            }
            "data_statement"
            | "inlinescript_statement"
            | "parallel_statement"
            | "sequence_statement" => {
                let mut out = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "statement_block" => out.push(Stmt::Block(self.block(k, cx)?)),
                        "data_name" | "comment" => {}
                        "data_commands_allowed" => out.extend(self.collect(k, cx)?),
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                out
            }
            "class_statement" => {
                let mut out = Vec::new();
                for k in named_kids(n) {
                    match k.kind() {
                        "simple_name" | "comment" => {}
                        "class_property_definition" => out.extend(self.collect(k, cx)?),
                        "class_method_definition" => {
                            let mut name = String::new();
                            let mut pre = Vec::new();
                            let mut body = Script::default();
                            for part in named_kids(k) {
                                match part.kind() {
                                    "simple_name" => name = self.text(part).to_string(),
                                    "script_block" => body = self.script_block(part, cx)?,
                                    "attribute"
                                    | "class_attribute"
                                    | "type_literal"
                                    | "class_method_parameter_list" => {
                                        pre.extend(self.collect(part, cx)?)
                                    }
                                    "comment" => {}
                                    _ => return Err(self.unmodelled(part)),
                                }
                            }
                            out.push(Stmt::Func {
                                name,
                                body: concat(script_of(pre), body),
                            });
                        }
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                out
            }
            "enum_statement" => self.collect(n, cx)?,
            "ERROR" if self.lossy => self.collect(n, cx)?,
            _ => return Err(self.unmodelled(n)),
        })
    }

    fn switch_clause(&self, clause: Node, cx: Cx) -> R<Script> {
        let mut cond = Vec::new();
        let mut body = Script::default();
        for k in named_kids(clause) {
            match k.kind() {
                "switch_clause_condition" => cond.extend(self.collect(k, cx)?),
                "statement_block" => body = self.block(k, cx)?,
                "comment" => {}
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(concat(script_of(cond), body))
    }

    /// `{ … }` of a compound statement.
    fn block(&self, n: Node, cx: Cx) -> R<Script> {
        let list = named_kids(n)
            .into_iter()
            .find(|k| k.kind() == "statement_list");
        for k in named_kids(n) {
            if !matches!(k.kind(), "statement_list" | "comment") {
                return Err(self.unmodelled(k));
            }
        }
        self.script(list, span(n), cx)
    }

    /// The body of a script block or function: `param(…)` defaults, then the named blocks or the
    /// statement list.
    fn script_block(&self, n: Node, cx: Cx) -> R<Script> {
        let inner = cx.deeper(span(n))?;
        if self.lossy {
            return Ok(Script::default());
        }
        let mut acc = Acc::default();
        for k in named_kids(n) {
            match k.kind() {
                "param_block" => acc.push(self.collect(k, inner)?, ChainOp::Seq),
                "script_block_body" => {
                    for b in named_kids(k) {
                        match b.kind() {
                            "statement_list" => self.statement_list_into(b, inner, &mut acc)?,
                            "named_block_list" => {
                                for named in named_kids(b) {
                                    for part in named_kids(named) {
                                        match part.kind() {
                                            "block_name" | "comment" => {}
                                            "statement_block" => {
                                                acc.append(self.block(part, inner)?)
                                            }
                                            _ => return Err(self.unmodelled(part)),
                                        }
                                    }
                                }
                            }
                            "comment" => {}
                            _ => return Err(self.unmodelled(b)),
                        }
                    }
                }
                "comment" => {}
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(acc.finish(Vec::new()))
    }

    /// A node holding one pipeline (`for_condition`, `while_condition`).
    fn only_pipeline(&self, n: Node, cx: Cx) -> R<Script> {
        let mut out = Script::default();
        for k in named_kids(n) {
            match k.kind() {
                "pipeline" => out = self.pipeline_script(k, cx)?,
                "comment" => {}
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(out)
    }

    fn pipeline_script(&self, n: Node, cx: Cx) -> R<Script> {
        let mut acc = Acc::default();
        for (stmt, after) in self.pipeline(n, cx)? {
            acc.push(vec![stmt], after);
        }
        Ok(acc.finish(Vec::new()))
    }

    /// One statement per pipeline chain, each with the operator that follows it.
    fn pipeline(&self, n: Node, cx: Cx) -> R<Vec<(Stmt, ChainOp)>> {
        let mut out: Vec<(Stmt, ChainOp)> = Vec::new();
        for k in named_kids(n) {
            match k.kind() {
                "assignment_expression" => out.push((self.assignment(k, cx)?, ChainOp::Seq)),
                "pipeline_chain" => out.push((self.chain(k, cx)?, ChainOp::Seq)),
                "pipeline_chain_tail" => {
                    if self.dialect == Shell::Powershell5 {
                        return Err(error(
                            span(k),
                            "`&&` and `||` are PowerShell 7 syntax; Windows PowerShell 5.1 rejects them",
                            None,
                        ));
                    }
                    let op = if self.text(k) == "&&" {
                        ChainOp::And
                    } else {
                        ChainOp::Or
                    };
                    if let Some((Stmt::Pipeline(p), after)) = out.last_mut() {
                        p.chain = Some(op);
                        *after = op;
                    }
                }
                "comment" => {}
                "ERROR" if self.lossy => {
                    for s in self.collect(k, cx)? {
                        out.push((s, ChainOp::Seq));
                    }
                }
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(out)
    }

    /// `$x = …`: a command with no name that assigns.
    fn assignment(&self, n: Node, cx: Cx) -> R<Stmt> {
        let mut names = Vec::new();
        let mut value: Option<Word> = None;
        let mut extra = Vec::new();
        for k in named_kids(n) {
            match k.kind() {
                "left_assignment_expression" => {
                    let (ns, stmts) = self.assigned_names(k, cx)?;
                    names = ns;
                    extra = stmts;
                }
                "assignement_operator" | "comment" => {}
                _ => {
                    // The assigned statement (`field('value', $._statement)`).
                    let inner = cx.deeper(span(k))?;
                    value = Some(match self.plain_value(k) {
                        Some(w) => self.expr_word(w, inner)?,
                        None => {
                            let mut acc = Acc::default();
                            self.other_statement(k, inner, &mut acc)?;
                            subst_word(acc.finish(Vec::new()), span(k))
                        }
                    });
                }
            }
        }
        let value = value.unwrap_or_else(|| empty_word(span(n)));
        if names.is_empty() {
            // `(Get-Item x).LastWriteTime = …` sets no variable; the value still runs.
            extra.push(single_pipeline(Elem::Expr(value.clone())));
        }
        let mut cmd = nameless(span(n), cx);
        // `$a, $b = …`: the statement runs once; later names hold a piece of its output.
        let rest = subst_word(Script::default(), value.span);
        let mut value = Some(value);
        cmd.assigns = names
            .into_iter()
            .map(|nm| (nm, value.take().unwrap_or_else(|| rest.clone())))
            .collect();
        let mut elems = vec![Elem::Cmd(cmd)];
        if !extra.is_empty() {
            elems.push(Elem::Expr(subst_word(script_of(extra), span(n))));
        }
        Ok(Stmt::Pipeline(Pipeline { elems, chain: None }))
    }

    /// The value of `$x = 'a'` or `$x = $y`: a pipeline of one plain string or variable.
    fn plain_value<'t>(&self, n: Node<'t>) -> Option<Node<'t>> {
        if n.kind() != "pipeline" {
            return None;
        }
        let ks = named_kids(n);
        let [chain] = ks.as_slice() else { return None };
        if chain.kind() != "pipeline_chain" {
            return None;
        }
        let parts = named_kids(*chain);
        let [only] = parts.as_slice() else {
            return None;
        };
        let leaf = peel(*only);
        matches!(
            leaf.kind(),
            "string_literal" | "variable" | "braced_variable" | "integer_literal" | "real_literal"
        )
        .then_some(leaf)
    }

    /// The names an assignment target sets (`$a`, `$a, $b`, `[string]$a`, `$a.b`, `$a[0]`), and
    /// the statements its index or member expressions run.
    fn assigned_names(&self, n: Node, cx: Cx) -> R<(Vec<String>, Vec<Stmt>)> {
        let mut names = Vec::new();
        let mut stack = vec![n];
        let mut runs = Vec::new();
        while let Some(x) = stack.pop() {
            match x.kind() {
                "variable" | "braced_variable" => names.push(var_name(self.text(x))),
                "member_access" | "element_access" => {
                    // The base names the variable; the rest is an expression that runs.
                    let ks = named_kids(x);
                    if let Some((base, rest)) = ks.split_first() {
                        stack.push(*base);
                        for r in rest {
                            runs.extend(self.collect(*r, cx)?);
                        }
                    }
                }
                "type_literal" | "comment" => {}
                k if is_ladder(k)
                    || matches!(k, "cast_expression" | "expression_with_unary_operator") =>
                {
                    let mut ks = named_kids(x);
                    ks.reverse();
                    stack.extend(ks);
                }
                // A base that is not a variable (`(Get-Item x).Prop = …`) runs.
                _ => runs.extend(self.collect(x, cx)?),
            }
        }
        Ok((names, runs))
    }

    /// One pipeline chain: an expression or a command, then `| command`s.
    fn chain(&self, n: Node, cx: Cx) -> R<Stmt> {
        let mut elems = Vec::new();
        for k in named_kids(n) {
            match k.kind() {
                "command" => elems.push(Elem::Cmd(self.command(k, cx)?)),
                "verbatim_command_argument" => {
                    // `--%` stops parsing only before a space or the line end; `--%x` and a
                    // `--%` glued to the previous word are plain text for PowerShell.
                    let after = self.text(k).get(3..).unwrap_or("");
                    if !after.starts_with([' ', '\t'])
                        || self.src[..k.start_byte()].ends_with(|c: char| !c.is_whitespace())
                    {
                        return Err(self.unmodelled(k));
                    }
                    self.verbatim_ends_here(k, k.start_byte() + 3)?;
                    let w = Word {
                        parts: vec![WordPart::Literal(self.text(k).to_string())],
                        span: span(k),
                        quote: Quote::Single,
                    };
                    match elems.last_mut() {
                        Some(Elem::Cmd(c)) => c.args.push(w),
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                "redirections" => {
                    // `2>$null<#x#>`: a comment glued to the target is word text.
                    let (before, rest) = self.src.split_at(k.end_byte());
                    if (rest.starts_with('#') || rest.starts_with("<#"))
                        && before.ends_with(|c: char| !c.is_whitespace())
                    {
                        return Err(self.unmodelled(k));
                    }
                    for r in named_kids(k) {
                        let r = self.redirection(r, cx)?;
                        let t = redirect_target(&r);
                        if t.is_dynamic() {
                            elems.push(Elem::Expr(t.clone()));
                        }
                    }
                }
                "comment" => {}
                "ERROR" if self.lossy => {
                    let stmts = self.collect(k, cx)?;
                    if !stmts.is_empty() {
                        elems.push(Elem::Expr(subst_word(script_of(stmts), span(k))));
                    }
                }
                _ if elems.is_empty() => elems.push(self.head(k, cx)?),
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(Stmt::Pipeline(Pipeline { elems, chain: None }))
    }

    /// An expression at the head of a pipeline: a static method call, or an expression.
    fn head(&self, n: Node, cx: Cx) -> R<Elem> {
        let leaf = peel(n);
        if let Some(m) = self.method_call(leaf, cx)? {
            return Ok(Elem::Method(m));
        }
        Ok(Elem::Expr(self.expr_word(n, cx)?))
    }

    /// `[T]::M(args)`, `$t::M(args)` or the instance call `$x.M(args)`: the method call, spanning
    /// from the receiver.
    fn method_call(&self, n: Node, cx: Cx) -> R<Option<MethodCall>> {
        if n.kind() != "invokation_expression" {
            return Ok(None);
        }
        let mut ks = kids(n);
        // `(x).ForEach({…})` and `(x).ForEach{…}`: the grammar's own node for the same call.
        if let [f] = ks.as_slice()
            && f.kind() == "invokation_foreach_expression"
        {
            ks = kids(*f);
        }
        let is_static = ks.iter().any(|k| k.kind() == "::");
        let mut receiver = None;
        let mut method = String::new();
        let mut args = Vec::new();
        for k in &ks {
            match k.kind() {
                "::" | "." | "comment" => {}
                "member_name" => method = self.text(*k).to_string(),
                "script_block_expression" if receiver.is_some() => {
                    args.push(self.expr_word(*k, cx)?);
                }
                "argument_list" => {
                    for list in named_kids(*k) {
                        if list.kind() != "argument_expression_list" {
                            continue;
                        }
                        for a in named_kids(list) {
                            args.push(self.expr_word(a, cx)?);
                        }
                    }
                }
                _ if receiver.is_none() => receiver = Some(*k),
                _ => return Err(self.unmodelled(*k)),
            }
        }
        let Some(receiver) = receiver else {
            return Ok(None);
        };
        if method.is_empty() {
            // `.ForEach` is a hidden token: the method is the text after the receiver.
            let next = ks
                .iter()
                .find(|k| k.is_named() && k.start_byte() >= receiver.end_byte())
                .map_or(n.end_byte(), |k| k.start_byte());
            let between = &self.src[receiver.end_byte()..next];
            // `(x).ForEach<LF>{…}`: a block after a space or line end is not the call's argument.
            if between.trim() != between {
                return Err(self.unmodelled(n));
            }
            method = between.trim_start_matches('.').to_string();
        }
        let recv = peel(receiver);
        let type_name = if !is_static {
            // An instance call: the receiver is the first argument, and the type is unknown.
            args.insert(0, self.expr_word(receiver, cx)?);
            String::new()
        } else if recv.kind() == "type_literal" {
            named_kids(recv)
                .first()
                .map_or_else(String::new, |t| self.text(*t).to_string())
        } else {
            // A receiver that is not a type literal (`$t::M()`) runs as an expression too.
            args.insert(0, self.expr_word(receiver, cx)?);
            self.text(receiver).to_string()
        };
        Ok(Some(MethodCall {
            type_name,
            method,
            args,
            span: span(n),
        }))
    }

    /// `$x.M(args)` in argument mode, where the tree holds the member and the argument list side
    /// by side.
    fn member_call(&self, member: Node, list: Node, cx: Cx) -> R<MethodCall> {
        let mut args = Vec::new();
        let mut method = String::new();
        for k in named_kids(member) {
            match k.kind() {
                "member_name" => method = self.text(k).to_string(),
                "comment" => {}
                _ if args.is_empty() => args.push(self.expr_word(k, cx)?),
                _ => return Err(self.unmodelled(k)),
            }
        }
        for l in named_kids(list) {
            if l.kind() != "argument_expression_list" {
                continue;
            }
            for a in named_kids(l) {
                args.push(self.expr_word(a, cx)?);
            }
        }
        if args.is_empty() || method.is_empty() {
            return Err(self.unmodelled(member));
        }
        Ok(MethodCall {
            type_name: String::new(),
            method,
            args,
            span: Span {
                start: member.start_byte(),
                end: list.end_byte(),
            },
        })
    }

    fn command(&self, n: Node, cx: Cx) -> R<SimpleCommand> {
        let mut name: Option<Word> = None;
        let mut args = Vec::new();
        let mut redirects = Vec::new();
        let mut last_closes = false;
        for k in named_kids(n) {
            match k.kind() {
                // `.‘x’`: a dot glued to a typographic quote is name text for PowerShell, not
                // the dot-source operator.
                "command_invokation_operator"
                    if self.text(k) == "."
                        && self.src[k.end_byte()..].chars().next().is_some_and(|c| {
                            !c.is_ascii() && (is_single_quote(c) || is_double_quote(c))
                        }) =>
                {
                    return Err(self.unmodelled(k));
                }
                "command_invokation_operator" | "comment" => {}
                "command_name" | "command_name_expr" => name = Some(self.name_word(k, cx)?),
                "command_elements" => {
                    let after = name.as_ref().map_or(k.start_byte(), |w| w.span.end);
                    for el in self.elements(k, after)? {
                        last_closes = matches!(&el, Element::Arg(nodes) if closes(nodes));
                        match el {
                            Element::Arg(nodes)
                                if nodes.len() == 1 && nodes[0].kind() == "stop_parsing" =>
                            {
                                args.extend(self.stop_parsing(nodes[0])?);
                            }
                            Element::Arg(nodes) => args.push(self.element_word(&nodes, cx)?),
                            Element::Redirect(r) => redirects.push(self.redirection(r, cx)?),
                        }
                    }
                    // `ls 2>$null<#x#>`: a comment glued to the last redirect target is word
                    // text for PowerShell; the tree ends the command before it.
                    let rest = &self.src[k.end_byte()..];
                    if self.src[..k.end_byte()].ends_with(|c: char| !c.is_whitespace())
                        && (rest.starts_with('#') || rest.starts_with("<#"))
                        && named_kids(k)
                            .last()
                            .is_some_and(|l| l.kind() == "redirection")
                    {
                        return Err(self.unmodelled(k));
                    }
                }
                "ERROR" if self.lossy => {
                    let stmts = self.collect(k, cx)?;
                    if !stmts.is_empty() {
                        args.push(subst_word(script_of(stmts), span(k)));
                    }
                }
                _ => return Err(self.unmodelled(k)),
            }
        }
        let Some(name) = name else {
            return Err(self.unmodelled(n));
        };
        // A comment glued to the last argument: word text for PowerShell, unless a closing
        // quote or bracket ends that argument (`Write-Output 'a'#x` holds a comment).
        let (before, rest) = self.src.split_at(n.end_byte());
        if (rest.starts_with('#') || rest.starts_with("<#"))
            && before.ends_with(|c: char| !c.is_whitespace())
            && !last_closes
        {
            return Err(self.unmodelled(n));
        }
        let opaque = name.is_dynamic() || name.parts.is_empty();
        let typed = match literal_value(&name) {
            Some(v) if !opaque => v,
            _ => self.src[name.span.start..name.span.end].to_string(),
        };
        let canonical = if opaque {
            None
        } else {
            canonical(&typed, self.dialect, self.os)
        };
        // A script block passed to ForEach-Object runs once per input object.
        let block_cx = if canonical.as_deref() == Some("foreach-object") {
            cx.looping()
        } else {
            cx
        };
        if block_cx.in_loop != cx.in_loop {
            for a in &mut args {
                mark_in_loop(a);
            }
        }
        Ok(SimpleCommand {
            name,
            typed,
            canonical,
            args,
            redirects,
            assigns: Vec::new(),
            span: span(n),
            in_loop: cx.in_loop,
            opaque,
        })
    }

    /// The command name: a bare word, a quoted string, a path or an expression after `&`/`.`.
    fn name_word(&self, n: Node, cx: Cx) -> R<Word> {
        if n.kind() == "command_name_expr" {
            let ks = named_kids(n);
            let [inner] = ks.as_slice() else {
                return Err(self.unmodelled(n));
            };
            return match inner.kind() {
                "command_name" | "path_command_name" => self.name_word(*inner, cx),
                _ => self.expr_word(*inner, cx),
            };
        }
        let w = self.token_word(n, cx)?;
        // ``Foo` -a="$(x)"``: PowerShell reads a bare command name as constant text, so a
        // variable or `$(…)` inside it is not the one a word would expand. Not modelled.
        if n.kind() == "command_name" && w.is_dynamic() {
            return Err(self.unmodelled(n));
        }
        Ok(w)
    }

    /// Group command elements as PowerShell does: one argument is the children between two
    /// separators (`a, b` and `-Name:value` arrive as several children).
    /// `after` is where the command name ends.
    fn elements<'t>(&self, ce: Node<'t>, after: usize) -> R<Vec<Element<'t>>> {
        let b = self.src.as_bytes();
        let mut out = Vec::new();
        let mut group: Vec<Node> = Vec::new();
        let mut colon: Option<Node> = None;
        // End of the previous element node and whether it was a redirection.
        let mut last_end = after;
        let mut last_redirect = false;
        // `"a"b`: a closing quote ends an argument, so the word glued after a string starts the
        // next argument (`glued_string_argument` holds the string and the pieces glued after
        // it); the pieces after that word group as any glued pieces do (`''--a=$$$(x)`).
        let mut kids: Vec<(Node, bool, bool)> = Vec::new();
        for ch in named_kids(ce) {
            if ch.kind() == "glued_string_argument" {
                for (i, k) in named_kids(ch).into_iter().enumerate() {
                    kids.push((k, i == 1, i > 0));
                }
            } else {
                kids.push((ch, false, false));
            }
        }
        for (ch, new_arg, in_tail) in kids {
            let glued_to_last = ch.start_byte() == last_end;
            match ch.kind() {
                "comment" => {
                    // `-First<#x#>`, `2>$null<#x#>`: PowerShell reads a glued comment as word
                    // text unless a closing quote or bracket ends the word before it.
                    if glued_to_last && (last_redirect || !closes(&group)) {
                        return Err(self.unmodelled(ch));
                    }
                    continue;
                }
                "command_argument_sep" => {
                    if self.text(ch) == ":" {
                        if let Some(c) = colon {
                            return Err(self.unmodelled(c));
                        }
                        colon = Some(ch);
                    }
                    continue;
                }
                "redirection" => {
                    out.push(Element::Redirect(ch));
                    last_end = ch.end_byte();
                    last_redirect = true;
                    continue;
                }
                _ => {}
            }
            let was_redirect = std::mem::replace(&mut last_redirect, false);
            let first = last_end == after && out.is_empty() && group.is_empty();
            last_end = ch.end_byte();
            // `\$($p)`, `git-`: text glued to the command name. Only `name(args)` and
            // `name{block}` (`%{ $_ }`) are separate arguments for PowerShell.
            if first
                && glued_to_last
                && (!matches!(
                    ch.kind(),
                    "parenthesized_expression" | "script_block_expression"
                ) || self.src[..after].ends_with('$'))
            {
                return Err(self.unmodelled(ch));
            }
            // `$x.'Delete'()`: a `(…)` glued to a member access is a call for PowerShell. Only
            // `$x.Name(…)` is lowered as one (`member_call`); the glue table refuses the rest.
            if ch.kind() == "argument_list"
                && let Some(p) = group.last()
                && p.end_byte() == ch.start_byte()
                && p.kind() == "member_access"
                && !simple_member_access(*p)
            {
                return Err(self.unmodelled(ch));
            }
            // `a,<#c#>b`, ``a,`<LF>b``: PowerShell continues the list past anything after a
            // comma; the grouping joins a comma and spaces only.
            if let Some(l) = group.last() {
                let gap = &self.src[l.end_byte()..ch.start_byte()];
                if gap.contains(',') && gap.trim() != "," {
                    return Err(self.unmodelled(ch));
                }
            }
            let joins = match (group.first(), group.last()) {
                (Some(first), Some(last)) => {
                    let (s, e) = (first.start_byte(), last.end_byte());
                    let gap = String::from_utf8_lossy(&b[e..ch.start_byte()]);
                    let prev = &b[s..e];
                    let glued = gap.is_empty()
                        && (
                            // `F:\w\$($p[0])`, `--x=$($y)`: a word ending in `$` before `(…)`
                            // holds a subexpression.
                            // (`$$(…)` is the variable `$$`, then a new argument; `$$$(…)` is
                            // `$$` and a subexpression: the `$` run before `(` is odd.)
                            // A one-dash `-name=$` is a parameter: the `(` starts a new argument,
                            // unless a `:` gave the parameter its value (`-name=:$(x)`) or a
                            // quote makes it a word (`-name=''$(x)`).
                            (opens_subexpression(prev)
                                && !((last.kind() == "command_parameter"
                                    || (in_tail && starts_parameter(self.text(*last))))
                                    && !prev.starts_with(b"--")
                                    && !prev.contains(&b':')
                                    && !holds_quote(&String::from_utf8_lossy(prev)))
                                && matches!(ch.kind(), "parenthesized_expression" | "argument_list")
                                && {
                                    // `--name=$(ri C:\x)`: PowerShell reads a statement list
                                    // there; only a variable body is modelled.
                                    let body = self.text(ch);
                                    if !body
                                        .strip_prefix('(')
                                        .and_then(|b| b.strip_suffix(')'))
                                        .is_some_and(simple_variable_body)
                                    {
                                        return Err(self.unmodelled(ch));
                                    }
                                    true
                                })
                            // `''b$(x)c`: after a quote, text glued to a `$(…)` stays in its word.
                            || (in_tail
                                && ch.kind() == "generic_token"
                                && last.kind() == "parenthesized_expression"
                                && group.len() >= 2
                                && opens_subexpression(self.text(group[group.len() - 2]).as_bytes()))
                            // `"a"@(1)`: after a quote, `@(…)` is one array subexpression.
                            || (in_tail
                                && prev == b"@"
                                && ch.kind() == "parenthesized_expression")
                            // `(Get-Date).AddDays(-5)`: a member call keeps its arguments.
                            || (ch.kind() == "argument_list"
                                && last.kind() != "generic_token"
                                && ends_with_member(prev))
                            // `-m'msg'`: a parameter glued to a quoted value.
                            || (group.len() == 1
                                && last.kind() == "command_parameter"
                                && matches!(
                                    ch.kind(),
                                    "verbatim_string_characters" | "expandable_string_literal"
                                ))
                        );
                    glued
                        || gap.trim() == ","
                        || (gap == ":" && prev.starts_with(b"-"))
                        // `-name:(…)` takes its value; `--name:(…)` is two arguments.
                        || (gap.is_empty()
                            && prev.starts_with(b"-")
                            && !prev.starts_with(b"--")
                            && prev.ends_with(b":"))
                }
                _ => false,
            };
            if let Some(c) = colon.take()
                && !(joins && c.start_byte() >= group.last().map_or(0, |l| l.end_byte()))
            {
                // `x :y` and friends: a colon PowerShell keeps as text that the grouping drops.
                return Err(self.unmodelled(c));
            }
            if in_tail {
                // `''2>$null`: a stream redirection glued after a string.
                let t = self.text(ch).as_bytes();
                // `"a"--%x`: what PowerShell stops parsing at is not modelled after a quote.
                if t.starts_with(b"--%") {
                    return Err(self.unmodelled(ch));
                }
                // `'a'?[0]`, `"a"?.Length`: an index or a member of the string for PowerShell.
                if t.starts_with(b"?.") || t.starts_with(b"?[") {
                    return Err(self.unmodelled(ch));
                }
                if t.len() > 1 && (t[0].is_ascii_digit() || t[0] == b'*') && t[1] == b'>' {
                    return Err(self.unmodelled(ch));
                }
                if let Some(c) = colon.take() {
                    return Err(self.unmodelled(c));
                }
                if new_arg {
                    out.push(Element::Arg(std::mem::take(&mut group)));
                    group.push(ch);
                    continue;
                }
            }
            // `git-`, `-5-`, `2>$null-`: text glued to the previous element that the tree
            // split off (a bare dash, `--%`) is one word for PowerShell.
            if !joins
                && glued_to_last
                && (was_redirect || matches!(ch.kind(), "command_parameter" | "stop_parsing"))
            {
                return Err(self.unmodelled(ch));
            }
            if !joins && !group.is_empty() {
                out.push(Element::Arg(std::mem::take(&mut group)));
            }
            group.push(ch);
        }
        if let Some(c) = colon {
            return Err(self.unmodelled(c));
        }
        if !group.is_empty() {
            out.push(Element::Arg(group));
        }
        Ok(out)
    }

    /// One argument from its nodes: a parameter with its value, a comma list, or one word.
    fn element_word(&self, nodes: &[Node], cx: Cx) -> R<Word> {
        let first = nodes[0];
        let last = nodes[nodes.len() - 1];
        let whole = Span {
            start: first.start_byte(),
            end: last.end_byte(),
        };
        // ``a'b'`⏎``, ``-S"x"`⏎``: a backtick line end glued to a word that ends in a quote is
        // word text for PowerShell (after a whole string it continues the line).
        let text = &self.src[whole.start..whole.end];
        let rest = &self.src[whole.end..];
        if (rest.starts_with("`\n") || rest.starts_with("`\r\n"))
            && text.ends_with(|c| is_single_quote(c) || is_double_quote(c))
            && !text.starts_with(|c| is_single_quote(c) || is_double_quote(c))
        {
            return Err(self.unmodelled(first));
        }
        let mut items: Vec<Item> = Vec::new();
        let mut quotes: Vec<Quote> = Vec::new();
        let mut prev_end: Option<usize> = None;
        let mut call_args: Option<Node> = None;
        for (i, n) in nodes.iter().enumerate() {
            if call_args.take().is_some() {
                continue;
            }
            // `a,.$m`: the same after a comma.
            if n.kind() == "generic_token" && dot_opens_expression(self.text(*n)) {
                return Err(self.unmodelled(*n));
            }
            if let Some(e) = prev_end {
                let gap = &self.src[e..n.start_byte()];
                if gap.is_empty()
                    && matches!(n.kind(), "parenthesized_expression" | "argument_list")
                    && let Some(Item::Part(WordPart::Literal(s))) = items.last_mut()
                    && s.chars().rev().take_while(|c| *c == '$').count() % 2 == 1
                {
                    // `x\$(…)`: the `$` opens the subexpression.
                    s.pop();
                    if s.is_empty() {
                        items.pop();
                    }
                }
                if gap.trim() == "," {
                    items.push(Item::Sep);
                } else if !gap.is_empty() {
                    items.push(Item::Part(WordPart::Literal(gap.to_string())));
                }
            }
            prev_end = Some(n.end_byte());
            // `$x.Delete()`: a member glued to an argument list is an instance method call.
            if n.kind() == "member_access"
                && let Some(list) = nodes.get(i + 1)
                && list.kind() == "argument_list"
                && list.start_byte() == n.end_byte()
            {
                let m = self.member_call(*n, *list, cx)?;
                quotes.push(Quote::None);
                items.push(Item::Part(WordPart::Subst(Box::new(script_of(vec![
                    single_pipeline(Elem::Method(m)),
                ])))));
                prev_end = Some(list.end_byte());
                call_args = Some(*list);
                continue;
            }
            match n.kind() {
                "command_parameter" => {
                    // A one-dash parameter keeps a backtick as a plain character only as far as
                    // the grammar can tell; what PowerShell names it is not proven, so it fails
                    // closed. A value (`--a=$x`) expands like any word.
                    let t = self.text(*n);
                    if parameter_text_unproven(t) {
                        return Err(self.unmodelled(*n));
                    }
                    let w = self.decode(n.start_byte(), n.end_byte(), &[], Mode::Bare, cx)?;
                    // ``--`%``: an escaped `--%` still stops parsing for PowerShell.
                    if t.contains('`')
                        && matches!(w.parts.first(), Some(WordPart::Literal(v)) if v.starts_with("--%"))
                    {
                        return Err(self.unmodelled(*n));
                    }
                    quotes.push(w.quote);
                    items.extend(w.parts.into_iter().map(Item::Part));
                }
                "stop_parsing" => {
                    quotes.push(Quote::None);
                    items.push(Item::Part(WordPart::Literal(self.text(*n).to_string())));
                }
                // ``"a"--`%``: an escaped `--%` still stops parsing for PowerShell.
                "generic_token" if self.text(*n).replace('`', "").starts_with("--%") => {
                    return Err(self.unmodelled(*n));
                }
                // `''-a.b`: a word glued after a quote that starts with a dash is a parameter
                // for PowerShell, so the parameter checks apply to it.
                "generic_token"
                    if i == 0
                        && starts_parameter(self.text(*n))
                        && parameter_text_unproven(self.text(*n)) =>
                {
                    return Err(self.unmodelled(*n));
                }
                "generic_token" => {
                    let w = self.token_word(*n, cx)?;
                    quotes.push(w.quote);
                    items.extend(w.parts.into_iter().map(Item::Part));
                }
                // `$a=b`: PowerShell ends the variable at `=`, which starts the next argument.
                "glued_argument"
                    if named_kids(*n)
                        .first()
                        .is_some_and(|v| self.src[v.end_byte()..n.end_byte()].starts_with('=')) =>
                {
                    return Err(self.unmodelled(*n));
                }
                // `$env::TEMP\a`: PowerShell ends the argument after the static member access.
                "glued_argument" if static_member_on_variable(self.text(*n)) => {
                    return Err(self.unmodelled(*n));
                }
                _ => self.items(*n, cx, &mut items, &mut quotes)?,
            }
        }
        let has_sep = items.iter().any(|i| matches!(i, Item::Sep));
        let quote = if quotes.len() == 1 && !has_sep && nodes.len() == 1 {
            quotes[0]
        } else if quotes.iter().all(|q| *q == Quote::None) {
            Quote::None
        } else {
            Quote::Mixed
        };
        Ok(Word {
            parts: merge(items),
            span: whole,
            quote,
        })
    }

    /// `--% rest`: the rest of the line passes to the program as written.
    fn stop_parsing(&self, n: Node) -> R<Vec<Word>> {
        let t = self.text(n);
        // The token may start with the separator before `--%`.
        let at = t.find("--%").unwrap_or(0);
        self.verbatim_ends_here(n, n.start_byte() + at + 3)?;
        let rest = t
            .get(at + 3..)
            .unwrap_or("")
            .trim_start_matches(char::is_whitespace);
        let mut out = vec![Word {
            parts: vec![WordPart::Literal("--%".to_string())],
            span: Span {
                start: n.start_byte() + at,
                end: n.start_byte() + at + 3,
            },
            quote: Quote::None,
        }];
        // `--% ` with only spaces after it still passes one (empty) argument.
        if !rest.is_empty() || t.len() > at + 3 {
            out.push(Word {
                parts: vec![WordPart::Literal(rest.to_string())],
                span: Span {
                    start: n.end_byte() - rest.len(),
                    end: n.end_byte(),
                },
                quote: Quote::Single,
            });
        }
        Ok(out)
    }

    /// The tree's `--%` text (from `start` to the end of `n`) must end where PowerShell ends it.
    fn verbatim_ends_here(&self, n: Node, start: usize) -> R<()> {
        let rest = self.src.get(start..).unwrap_or("");
        if start + verbatim_end(rest) != n.end_byte() {
            return Err(self.unmodelled(n));
        }
        Ok(())
    }

    fn redirection(&self, n: Node, cx: Cx) -> R<Redirect> {
        let mut op = String::new();
        let mut target: Option<Word> = None;
        for k in named_kids(n) {
            match k.kind() {
                "merging_redirection_operator" => {
                    let t = self.text(k);
                    // `2>&1`: the stream joins another, as bash writes `2>&1`.
                    let (o, fd) = t.split_at(t.len() - 1);
                    op = o.to_string();
                    target = Some(Word {
                        parts: vec![WordPart::Literal(fd.to_string())],
                        span: Span {
                            start: k.end_byte() - 1,
                            end: k.end_byte(),
                        },
                        quote: Quote::None,
                    });
                }
                "file_redirection_operator" => op = self.text(k).to_string(),
                "redirected_file_name" => {
                    let parts: Vec<Node> = named_kids(k)
                        .into_iter()
                        .filter(|c| c.kind() != "command_argument_sep")
                        .collect();
                    // `ls 2>$null<` then a line end: PowerShell ends the statement there, so a
                    // target past a line end is the next command, and no target is an error.
                    let Some(first) = parts.first() else {
                        return Err(self.unmodelled(k));
                    };
                    if self.src[n.start_byte()..first.start_byte()].contains(['\n', '\r']) {
                        return Err(self.unmodelled(k));
                    }
                    // `*> 'x'out.txt`: the word after the quoted target is another argument.
                    if let Some(g) = parts.iter().find(|c| c.kind() == "glued_string_argument") {
                        return Err(self.unmodelled(*g));
                    }
                    target = Some(self.element_word(&parts, cx)?);
                }
                "comment" => {}
                _ => return Err(self.unmodelled(k)),
            }
        }
        let target = target.unwrap_or_else(|| empty_word(span(n)));
        Ok(make_redirect(op, target, span(n)))
    }

    /// A word from an expression node in argument position.
    fn expr_word(&self, n: Node, cx: Cx) -> R<Word> {
        let leaf = peel(n);
        let sp = span(n);
        match leaf.kind() {
            "string_literal" => {
                let ks = named_kids(leaf);
                match ks.as_slice() {
                    [s] => self.expr_word(*s, cx),
                    _ => Err(self.unmodelled(leaf)),
                }
            }
            "verbatim_string_characters"
            | "expandable_string_literal"
            | "generic_token"
            | "variable"
            | "braced_variable"
            | "command_name"
            | "path_command_name"
            | "glued_argument" => self.token_word(leaf, cx),
            "verbatim_here_string_characters" => Ok(self.verbatim_here(leaf)),
            "expandable_here_string_literal" => self.expandable_here(leaf, cx),
            "integer_literal"
            | "real_literal"
            | "decimal_integer_literal"
            | "hexadecimal_integer_literal" => Ok(Word {
                parts: vec![WordPart::Literal(self.text(leaf).to_string())],
                span: sp,
                quote: Quote::None,
            }),
            "script_block_expression" => Ok(Word {
                parts: vec![WordPart::Block(Box::new(self.script_block_expr(leaf, cx)?))],
                span: sp,
                quote: Quote::None,
            }),
            "sub_expression" | "array_expression" => {
                let list = named_kids(leaf)
                    .into_iter()
                    .find(|k| k.kind() == "statement_list");
                Ok(subst_word(self.script(list, span(leaf), cx)?, sp))
            }
            "parenthesized_expression" => {
                let inner = cx.deeper(span(leaf))?;
                if self.lossy {
                    return Ok(subst_word(Script::default(), sp));
                }
                let mut acc = Acc::default();
                for k in named_kids(leaf) {
                    match k.kind() {
                        "pipeline" => {
                            for (s, after) in self.pipeline(k, inner)? {
                                acc.push(vec![s], after);
                            }
                        }
                        "comment" => {}
                        "ERROR" if self.lossy => acc.push(self.collect(k, inner)?, ChainOp::Seq),
                        _ => return Err(self.unmodelled(k)),
                    }
                }
                Ok(subst_word(acc.finish(Vec::new()), sp))
            }
            "array_literal_expression" => {
                let mut items = Vec::new();
                let mut quotes = Vec::new();
                self.items(leaf, cx, &mut items, &mut quotes)?;
                let quote = if quotes.iter().all(|q| *q == Quote::None) {
                    Quote::None
                } else {
                    Quote::Mixed
                };
                Ok(Word {
                    parts: merge(items),
                    span: sp,
                    quote,
                })
            }
            _ => Ok(subst_word(script_of(self.collect(leaf, cx)?), sp)),
        }
    }

    /// The items of one expression node: a comma list (`'a','b'` is one
    /// array_literal_expression) gives its elements with separators between them.
    fn items(&self, n: Node, cx: Cx, items: &mut Vec<Item>, quotes: &mut Vec<Quote>) -> R<()> {
        let leaf = peel(n);
        if leaf.kind() == "array_literal_expression" {
            for (i, el) in named_kids(leaf).into_iter().enumerate() {
                if i > 0 {
                    items.push(Item::Sep);
                }
                let w = self.expr_word(el, cx)?;
                quotes.push(w.quote);
                items.extend(w.parts.into_iter().map(Item::Part));
            }
            return Ok(());
        }
        let w = self.expr_word(n, cx)?;
        quotes.push(w.quote);
        items.extend(w.parts.into_iter().map(Item::Part));
        Ok(())
    }

    fn script_block_expr(&self, n: Node, cx: Cx) -> R<Script> {
        let mut acc = Acc::default();
        let inner = cx.deeper(span(n))?;
        if self.lossy {
            return Ok(Script::default());
        }
        for k in named_kids(n) {
            match k.kind() {
                "param_block" => acc.push(self.collect(k, inner)?, ChainOp::Seq),
                "script_block" => acc.append(self.script_block(k, cx)?),
                "comment" => {}
                "ERROR" if self.lossy => acc.push(self.collect(k, inner)?, ChainOp::Seq),
                _ => return Err(self.unmodelled(k)),
            }
        }
        Ok(acc.finish(Vec::new()))
    }

    /// Every command, block and static call inside an expression, without recursing on the
    /// expression's own structure.
    fn collect(&self, n: Node, cx: Cx) -> R<Vec<Stmt>> {
        let mut out = Vec::new();
        if self.lossy {
            return Ok(out);
        }
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            match x.kind() {
                "pipeline" => {
                    let inner = cx.deeper(span(x))?;
                    out.extend(self.pipeline(x, inner)?.into_iter().map(|(s, _)| s));
                }
                "statement_list" => {
                    out.push(Stmt::Block(self.script(Some(x), span(x), cx)?));
                }
                "command" => {
                    let inner = cx.deeper(span(x))?;
                    out.push(single_pipeline(Elem::Cmd(self.command(x, inner)?)));
                }
                "script_block_expression" => {
                    out.push(Stmt::Block(self.script_block_expr(x, cx)?));
                }
                "script_block" => out.push(Stmt::Block(self.script_block(x, cx)?)),
                "statement_block" => out.push(Stmt::Block(self.block(x, cx)?)),
                "invokation_expression" => {
                    let inner = cx.deeper(span(x))?;
                    match self.method_call(x, inner)? {
                        Some(m) => out.push(single_pipeline(Elem::Method(m))),
                        None => push_kids(&mut stack, x),
                    }
                }
                "if_statement"
                | "foreach_statement"
                | "for_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "function_statement"
                | "flow_control_statement"
                | "trap_statement"
                | "try_statement"
                | "data_statement"
                | "inlinescript_statement"
                | "parallel_statement"
                | "sequence_statement"
                | "class_statement" => {
                    let inner = cx.deeper(span(x))?;
                    out.extend(self.statement(x, inner)?);
                }
                "assignment_expression" => {
                    let inner = cx.deeper(span(x))?;
                    out.push(self.assignment(x, inner)?);
                }
                "ERROR" if !self.lossy => return Err(self.unmodelled(x)),
                _ => push_kids(&mut stack, x),
            }
        }
        Ok(out)
    }

    /// A token-shaped word (a bare word, a quoted string, a variable, a command name): its text
    /// read with PowerShell's quoting, with the variables and substitutions the tree found inside
    /// it as holes.
    fn token_word(&self, n: Node, cx: Cx) -> R<Word> {
        let mut holes = Vec::new();
        let mut stack = named_kids(n);
        while let Some(h) = stack.pop() {
            match h.kind() {
                "variable" | "braced_variable" | "sub_expression" => holes.push(h),
                _ => stack.extend(named_kids(h)),
            }
        }
        holes.sort_by_key(|h| h.start_byte());
        // `$(a)b`: PowerShell ends the argument after a leading subexpression, so the text glued
        // after it is the next argument.
        if n.kind() == "glued_argument"
            && holes
                .first()
                .is_some_and(|h| h.kind() == "sub_expression" && h.start_byte() == n.start_byte())
        {
            return Err(self.unmodelled(n));
        }
        if matches!(n.kind(), "variable" | "braced_variable") {
            holes.clear();
            return Ok(Word {
                parts: vec![WordPart::Var(var_name(self.text(n)))],
                span: span(n),
                quote: Quote::None,
            });
        }
        self.decode(n.start_byte(), n.end_byte(), &holes, Mode::Bare, cx)
    }

    fn verbatim_here(&self, n: Node) -> Word {
        let t = self.text(n);
        let body = t
            .find('\n')
            .map(|i| &t[i + 1..])
            .and_then(|rest| rest.rfind(['\n']).map(|j| &rest[..j]))
            .unwrap_or("");
        Word {
            parts: vec![WordPart::Literal(
                body.strip_suffix('\r').unwrap_or(body).to_string(),
            )],
            span: span(n),
            quote: Quote::Single,
        }
    }

    fn expandable_here(&self, n: Node, cx: Cx) -> R<Word> {
        let t = self.text(n);
        let first = t.find('\n').map_or(t.len(), |i| i + 1);
        let last = t.rfind('\n').filter(|l| *l >= first).unwrap_or(first);
        let last = if last > first && t.as_bytes()[last - 1] == b'\r' {
            last - 1
        } else {
            last
        };
        let (start, end) = (n.start_byte() + first, n.start_byte() + last);
        let mut holes: Vec<Node> = Vec::new();
        let mut stack = named_kids(n);
        while let Some(h) = stack.pop() {
            match h.kind() {
                "variable" | "braced_variable" | "sub_expression" => holes.push(h),
                _ => stack.extend(named_kids(h)),
            }
        }
        holes.sort_by_key(|h| h.start_byte());
        let mut w = self.decode(start, end, &holes, Mode::Here, cx)?;
        w.span = span(n);
        w.quote = Quote::Double;
        Ok(w)
    }

    /// Read `src[start..end]` the way PowerShell reads a token: quotes, backtick escapes and
    /// `$name` variables, with tree nodes as holes.
    fn decode(&self, start: usize, end: usize, holes: &[Node], mode: Mode, cx: Cx) -> R<Word> {
        let text = &self.src[start..end];
        let mut parts: Vec<WordPart> = Vec::new();
        let mut lit = String::new();
        let mut state = if mode == Mode::Here {
            QState::Double
        } else {
            QState::Out
        };
        let (mut unquoted, mut single, mut double, mut escaped) = (false, false, false, false);
        let mut hole = 0;
        let mut i = 0;
        let flush = |lit: &mut String, parts: &mut Vec<WordPart>| {
            if !lit.is_empty() {
                parts.push(WordPart::Literal(std::mem::take(lit)));
            }
        };
        while i < text.len() {
            let at = start + i;
            if let Some(h) = holes.get(hole)
                && h.start_byte() == at
            {
                flush(&mut lit, &mut parts);
                match h.kind() {
                    "sub_expression" => {
                        let list = named_kids(*h)
                            .into_iter()
                            .find(|k| k.kind() == "statement_list");
                        parts.push(WordPart::Subst(Box::new(self.script(
                            list,
                            span(*h),
                            cx,
                        )?)));
                    }
                    _ => parts.push(WordPart::Var(var_name(self.text(*h)))),
                }
                match state {
                    QState::Out => unquoted = true,
                    QState::Single => single = true,
                    QState::Double => double = true,
                }
                i = h.end_byte() - start;
                hole += 1;
                continue;
            }
            let c = text[i..].chars().next().unwrap_or('\0');
            let len = c.len_utf8();
            let next = text[i + len..].chars().next();
            match state {
                QState::Out => {
                    if c == '`' {
                        escaped = true;
                        if let Some(nc) = next {
                            lit.push(nc);
                            i += len + nc.len_utf8();
                        } else {
                            i += len;
                        }
                        continue;
                    } else if is_single_quote(c) {
                        state = QState::Single;
                        single = true;
                    } else if is_double_quote(c) {
                        state = QState::Double;
                        double = true;
                    // No bare `$(` reaches here: no word token of the grammar holds an
                    // unescaped `(` outside quotes, so the tree reads it as a subexpression.
                    } else if c == '$'
                        && let Some(vlen) = var_len(&text[i..])
                    {
                        flush(&mut lit, &mut parts);
                        parts.push(WordPart::Var(var_name(&text[i..i + vlen])));
                        unquoted = true;
                        i += vlen;
                        continue;
                    } else {
                        unquoted = true;
                        lit.push(c);
                    }
                }
                QState::Single => {
                    if is_single_quote(c) {
                        if next.is_some_and(is_single_quote) {
                            lit.push('\'');
                            i += len + next.map_or(0, char::len_utf8);
                            continue;
                        }
                        state = QState::Out;
                    } else {
                        lit.push(c);
                    }
                }
                QState::Double => {
                    if c == '`' {
                        escaped = true;
                        let (decoded, used) = escape(&text[i + len..]);
                        lit.push_str(&decoded);
                        i += len + used;
                        continue;
                    } else if mode != Mode::Here && is_double_quote(c) {
                        if next.is_some_and(is_double_quote) {
                            lit.push('"');
                            i += len + next.map_or(0, char::len_utf8);
                            continue;
                        }
                        state = QState::Out;
                    } else if c == '$' && next == Some('(') && !self.lossy {
                        return Err(error(
                            Span {
                                start: at,
                                end: at + 2,
                            },
                            "a subexpression inside a word that the parser did not read",
                            None,
                        ));
                    } else if c == '$'
                        && let Some(vlen) = var_len(&text[i..])
                    {
                        flush(&mut lit, &mut parts);
                        parts.push(WordPart::Var(var_name(&text[i..i + vlen])));
                        i += vlen;
                        continue;
                    } else {
                        lit.push(c);
                    }
                }
            }
            i += len;
        }
        flush(&mut lit, &mut parts);
        let quote = match (unquoted || escaped, single, double) {
            (false, true, false) => Quote::Single,
            (false, false, true) => Quote::Double,
            (_, false, false) if !escaped => Quote::None,
            _ => Quote::Mixed,
        };
        let parts = if parts.is_empty() && (single || double) {
            vec![WordPart::Literal(String::new())]
        } else {
            parts
        };
        Ok(Word {
            parts,
            span: Span { start, end },
            quote,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bare,
    Here,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QState {
    Out,
    Single,
    Double,
}

enum Element<'t> {
    Arg(Vec<Node<'t>>),
    Redirect(Node<'t>),
}

enum Item {
    Part(WordPart),
    Sep,
}

/// `….Name` at the end of `prev`: a member name a call's argument list belongs to.
/// Where PowerShell ends the verbatim text after `--%`, as `Parser::ParseInput` does (probed over
/// every ASCII character and the typographic quotes, single, doubled and inside double quotes):
/// at CR or LF, or at a `|` or `&&` outside double quotes. A double quote (`"` or U+201C to
/// U+201E) runs to the next one or to the line end. grammar.js `stop_parsing` mirrors this table.
fn verbatim_end(t: &str) -> usize {
    let mut quoted = false;
    let mut chars = t.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\r' | '\n' => return i,
            '"' | '\u{201C}'..='\u{201E}' => quoted = !quoted,
            '|' if !quoted => return i,
            '&' if !quoted && chars.peek().is_some_and(|(_, d)| *d == '&') => return i,
            _ => {}
        }
    }
    t.len()
}

/// `$name::` in argument text: a static member access on a variable.
fn static_member_on_variable(t: &str) -> bool {
    t.match_indices('$').any(|(i, _)| {
        let rest = &t[i + 1..];
        let n = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        n > 0 && rest[n..].starts_with("::")
    })
}

/// An argument of one node that a closing quote or bracket ends: a comment glued after it is a
/// comment for PowerShell (`'a'#x`, `(1)<#x#>`, `$a.b<#x#>`), not word text.
fn closes(nodes: &[Node]) -> bool {
    matches!(
        nodes,
        [n] if matches!(
            n.kind(),
            "parenthesized_expression"
                | "array_expression"
                | "script_block_expression"
                | "hash_literal_expression"
                | "string_literal"
                | "member_access"
        )
    )
}

/// `.$m`, `.'x'`: a dot before a variable, a subexpression or a quote, which PowerShell passes as
/// an argument of its own.
fn dot_opens_expression(t: &str) -> bool {
    t.strip_prefix('.')
        .and_then(|r| r.chars().next())
        .is_some_and(|c| c == '$' || is_single_quote(c) || is_double_quote(c))
}

/// A parameter token PowerShell ends at a dot: any dot in a one-dash parameter (`-a=x.m`,
/// `-a.b`), and a dot before a variable or a quote after the `=` or a comma in a two-dash one
/// (`--a=.$m`, `--a=b,.$m`).
fn param_value_splits_at_dot(t: &str) -> bool {
    if !t.starts_with("--") {
        return t.contains('.');
    }
    t.char_indices()
        .any(|(i, c)| c == '.' && dot_opens_expression(&t[i..]) && t[..i].ends_with(['=', ',']))
}

/// Text ending in a `$` that opens a `$(…)` glued after it: an odd run of unescaped `$`
/// (`$$` is a variable; ``$$`$`` ends in an escaped `$`).
fn opens_subexpression(t: &[u8]) -> bool {
    let run = t.iter().rev().take_while(|c| **c == b'$').count();
    let escaped = run > 0 && escaped_at(t, t.len() - run);
    (run - usize::from(escaped)) % 2 == 1
}

/// The character at byte `at` of `t` is escaped: the run of backticks right before it is odd
/// (``a``$`` ends in an escaped backtick and a plain `$`).
fn escaped_at(t: &[u8], at: usize) -> bool {
    t[..at].iter().rev().take_while(|c| **c == b'`').count() % 2 == 1
}

/// `$p[0]`, `$m.p`: a variable with member names and indexes only, on one line.
fn simple_variable_body(b: &str) -> bool {
    let Some(r) = b.strip_prefix('$') else {
        return false;
    };
    let name = |s: &str| {
        s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(s.len())
    };
    let mut r = &r[name(r)..];
    while !r.is_empty() {
        if let Some(m) = r.strip_prefix('.') {
            let k = name(m);
            if k == 0 {
                return false;
            }
            r = &m[k..];
        } else if let Some(m) = r.strip_prefix('[') {
            let Some(k) = m.find(']') else {
                return false;
            };
            // A nested `[` leaves a `]` the loop refuses; `)` and `}` need their opener.
            if m[..k].contains(['(', '{', '\r', '\n', '#']) {
                return false;
            }
            r = &m[k + 1..];
        } else {
            return false;
        }
    }
    true
}

/// Text holding a single or a double quote of either class.
fn holds_quote(t: &str) -> bool {
    t.chars().any(|c| is_single_quote(c) || is_double_quote(c))
}

/// A word PowerShell reads as a parameter: a dash, then a letter, `_`, `?` or a second dash
/// (`-5` is a number, `-#x` a word).
fn starts_parameter(t: &str) -> bool {
    t.strip_prefix('-')
        .and_then(|r| r.chars().next())
        .is_some_and(|c| c.is_alphabetic() || matches!(c, '_' | '?' | '-'))
}

/// Parameter text whose PowerShell reading is not proven: a comma list going on past a space
/// (`--name=a, b`), a dot where PowerShell ends the parameter (`-a=x.m`, `--a=.$m`), a comment
/// inside the token (`-name=a<#x#>b`), or a backtick or a `[` (where PowerShell ends it) in a
/// one-dash parameter.
fn parameter_text_unproven(t: &str) -> bool {
    (t.ends_with(',') && !t.ends_with("`,"))
        || param_value_splits_at_dot(t)
        || t.contains("<#")
        || (!t.starts_with("--") && t.contains('`'))
        || (!t.starts_with("--") && t.contains('['))
}

/// `$x.Name`: a member access whose member is a plain name.
fn simple_member_access(n: Node) -> bool {
    n.kind() == "member_access"
        && named_kids(n).last().is_some_and(|m| {
            m.kind() == "member_name"
                && named_kids(*m)
                    .first()
                    .is_some_and(|s| s.kind() == "simple_name")
        })
}

fn ends_with_member(prev: &[u8]) -> bool {
    let name = prev
        .iter()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
        .count();
    name > 0 && prev.len() > name && prev[prev.len() - name - 1] == b'.'
}

/// Word parts from items: adjacent literals of one element join; each separator is a `ListSep`.
fn merge(items: Vec<Item>) -> Vec<WordPart> {
    let mut out: Vec<WordPart> = Vec::new();
    let mut joinable = false;
    for it in items {
        match it {
            Item::Sep => {
                out.push(WordPart::ListSep);
                joinable = false;
            }
            Item::Part(WordPart::Literal(s)) => {
                if joinable && let Some(WordPart::Literal(prev)) = out.last_mut() {
                    prev.push_str(&s);
                } else {
                    out.push(WordPart::Literal(s));
                }
                joinable = true;
            }
            Item::Part(p) => {
                out.push(p);
                joinable = false;
            }
        }
    }
    out
}

/// A backtick escape inside double quotes: the decoded text and the bytes it used after the
/// backtick.
fn escape(rest: &str) -> (String, usize) {
    let Some(c) = rest.chars().next() else {
        return (String::new(), 0);
    };
    let one = |s: &str| (s.to_string(), c.len_utf8());
    match c {
        '0' => one("\0"),
        'a' => one("\u{7}"),
        'b' => one("\u{8}"),
        'e' => one("\u{1b}"),
        'f' => one("\u{c}"),
        'n' => one("\n"),
        'r' => one("\r"),
        't' => one("\t"),
        'v' => one("\u{b}"),
        'u' if rest[1..].starts_with('{') => match rest[2..].find('}') {
            Some(close) => {
                let hex = &rest[2..2 + close];
                match u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => (ch.to_string(), 3 + close),
                    None => one("u"),
                }
            }
            None => one("u"),
        },
        other => (other.to_string(), other.len_utf8()),
    }
}

/// The length of the variable reference at the start of `s` (which starts with `$`), as the
/// PowerShell tokenizer reads one; `None` when the `$` is literal.
fn var_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() < 2 {
        return None;
    }
    if b[1] == b'{' {
        return s[2..].find('}').map(|i| i + 3);
    }
    if matches!(b[1], b'$' | b'^' | b'?') {
        return Some(2);
    }
    let name = |from: usize| {
        b[from..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
            .count()
    };
    let n = name(1);
    if n == 0 {
        return None;
    }
    let mut len = 1 + n;
    // `$scope:name` / `$env:NAME`: a colon followed by a name joins.
    if b.get(len) == Some(&b':') {
        let m = name(len + 1);
        if m > 0 {
            len += 1 + m;
        }
    }
    Some(len)
}

/// The IR name of a variable reference: no sigil, no braces.
fn var_name(t: &str) -> String {
    let t = t.trim_start_matches(['$', '@']);
    let t = t
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(t);
    t.to_string()
}

/// Descend through nodes that only wrap one other node (expression precedence ladders).
fn is_ladder(kind: &str) -> bool {
    matches!(
        kind,
        "logical_expression"
            | "bitwise_expression"
            | "comparison_expression"
            | "additive_expression"
            | "multiplicative_expression"
            | "format_expression"
            | "range_expression"
            | "array_literal_expression"
            | "unary_expression"
            | "argument_expression"
            | "logical_argument_expression"
            | "bitwise_argument_expression"
            | "comparison_argument_expression"
            | "additive_argument_expression"
            | "multiplicative_argument_expression"
            | "format_argument_expression"
            | "range_argument_expression"
            | "left_assignment_expression"
            | "key_expression"
    )
}

fn peel(mut n: Node) -> Node {
    loop {
        if !is_ladder(n.kind()) || n.child_count() != 1 {
            return n;
        }
        match n.child(0) {
            Some(c) if c.is_named() => n = c,
            _ => return n,
        }
    }
}

fn push_kids<'t>(stack: &mut Vec<Node<'t>>, n: Node<'t>) {
    let mut ks = kids(n);
    ks.reverse();
    stack.extend(ks);
}

fn literal_value(w: &Word) -> Option<String> {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) => out.push_str(s),
            _ => return None,
        }
    }
    Some(out)
}

fn empty_word(at: Span) -> Word {
    Word {
        parts: Vec::new(),
        span: at,
        quote: Quote::None,
    }
}

fn subst_word(script: Script, at: Span) -> Word {
    Word {
        parts: vec![WordPart::Subst(Box::new(script))],
        span: at,
        quote: Quote::None,
    }
}

fn make_redirect(op: String, target: Word, at: Span) -> Redirect {
    Redirect {
        op,
        target,
        span: at,
    }
}

fn redirect_target(r: &Redirect) -> &Word {
    &r.target
}

fn nameless(at: Span, cx: Cx) -> SimpleCommand {
    SimpleCommand {
        name: empty_word(Span {
            start: at.start,
            end: at.start,
        }),
        typed: String::new(),
        canonical: None,
        args: Vec::new(),
        redirects: Vec::new(),
        assigns: Vec::new(),
        span: at,
        in_loop: cx.in_loop,
        opaque: false,
    }
}

fn single_pipeline(e: Elem) -> Stmt {
    Stmt::Pipeline(Pipeline {
        elems: vec![e],
        chain: None,
    })
}

fn single(s: Stmt) -> Script {
    script_of(vec![s])
}

fn script_of(stmts: Vec<Stmt>) -> Script {
    let mut acc = Acc::default();
    acc.push(stmts, ChainOp::Seq);
    acc.finish(Vec::new())
}

/// `b` run after `a` (a body after its condition), joined by `;`.
fn concat(a: Script, b: Script) -> Script {
    let mut acc = Acc {
        stmts: a.stmts,
        joins: a.joins,
        next: Some(ChainOp::Seq),
    };
    if let Some(Stmt::Pipeline(p)) = acc.stmts.last_mut()
        && p.chain.is_none()
        && !b.stmts.is_empty()
    {
        p.chain = Some(ChainOp::Seq);
    }
    acc.append(b);
    acc.finish(a.comments)
}

/// Every command inside the word's blocks runs in a loop (a ForEach-Object script block).
fn mark_in_loop(w: &mut Word) {
    for p in &mut w.parts {
        if let WordPart::Block(s) = p {
            mark_script_in_loop(s);
        }
    }
}

fn mark_script_in_loop(s: &mut Script) {
    let mut stack: Vec<&mut Script> = vec![s];
    while let Some(s) = stack.pop() {
        for st in &mut s.stmts {
            match st {
                Stmt::Pipeline(p) => {
                    for e in &mut p.elems {
                        if let Elem::Cmd(c) = e {
                            c.in_loop = true;
                        }
                    }
                }
                Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                    stack.push(body)
                }
                Stmt::Cond { branches, .. } => stack.extend(branches.iter_mut()),
            }
        }
    }
}

/// Statements in order, each with the operator joining it to the one before (as Task 6 does).
#[derive(Default)]
struct Acc {
    stmts: Vec<Stmt>,
    joins: Vec<Option<ChainOp>>,
    next: Option<ChainOp>,
}

impl Acc {
    fn push(&mut self, stmts: Vec<Stmt>, after: ChainOp) {
        if stmts.is_empty() {
            return;
        }
        let join = if self.stmts.is_empty() {
            None
        } else {
            self.next
        };
        if let (Some(Stmt::Pipeline(p)), Some(j)) = (self.stmts.last_mut(), join)
            && p.chain.is_none()
        {
            p.chain = Some(j);
        }
        self.joins.extend(std::iter::repeat_n(join, stmts.len()));
        self.stmts.extend(stmts);
        self.next = Some(after);
    }

    /// `&` after the last pipeline: it runs as a background job.
    fn background(&mut self) {
        if let Some(Stmt::Pipeline(p)) = self.stmts.last_mut() {
            p.chain = Some(ChainOp::Background);
        }
        self.next = Some(ChainOp::Background);
    }

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

/// The command names of each dialect: aliases and the commands of the default modules.
struct Names {
    pwsh_aliases: Vec<(String, String)>,
    windows_only: Vec<String>,
    ps5_aliases: Vec<(String, String)>,
    pwsh_commands: Vec<String>,
    ps5_commands: Vec<String>,
}

fn names() -> &'static Names {
    static NAMES: OnceLock<Names> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut n = Names {
            pwsh_aliases: Vec::new(),
            windows_only: Vec::new(),
            ps5_aliases: Vec::new(),
            pwsh_commands: Vec::new(),
            ps5_commands: Vec::new(),
        };
        let mut section = "";
        for line in include_str!("pwsh_names.txt").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = match s {
                    "pwsh-aliases"
                    | "pwsh-windows-only-aliases"
                    | "powershell5-aliases"
                    | "pwsh-commands"
                    | "powershell5-commands" => s,
                    _ => "",
                };
                continue;
            }
            let pair = || {
                line.split_once('=')
                    .map(|(a, t)| (a.to_string(), t.to_string()))
            };
            match section {
                "pwsh-aliases" => n.pwsh_aliases.extend(pair()),
                "powershell5-aliases" => n.ps5_aliases.extend(pair()),
                "pwsh-windows-only-aliases" => n.windows_only.push(line.to_string()),
                "pwsh-commands" => n.pwsh_commands.push(line.to_string()),
                "powershell5-commands" => n.ps5_commands.push(line.to_string()),
                _ => {}
            }
        }
        n
    })
}

/// The command a name runs for the dialect and OS, lowercase: the alias target, or the name of
/// a default-module command; `None` for anything else (a native program, a function, a path).
pub fn canonical(typed: &str, dialect: Shell, os: Os) -> Option<String> {
    let lower = typed.to_lowercase();
    // `Microsoft.PowerShell.Management\Remove-Item`: a module-qualified name.
    let name = match lower.rsplit_once('\\') {
        Some((module, name))
            if !module.is_empty()
                && module
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
                && module.starts_with(|c: char| c.is_ascii_alphabetic()) =>
        {
            name.to_string()
        }
        Some(_) => return None,
        None => lower,
    };
    let n = names();
    let (aliases, commands) = match dialect {
        Shell::Powershell5 => (&n.ps5_aliases, &n.ps5_commands),
        _ => (&n.pwsh_aliases, &n.pwsh_commands),
    };
    let posix = os == Os::Posix && dialect != Shell::Powershell5;
    if let Some((_, target)) = aliases.iter().find(|(a, _)| *a == name)
        && !(posix && n.windows_only.contains(&name))
    {
        return Some(target.clone());
    }
    commands.contains(&name).then_some(name)
}

/// What a script holds, in the shape `Parser::ParseInput` reports it: every named command as its
/// name and argument texts as written (in source order), every comment, and every static method
/// call as `Receiver::Method` and every instance call as `Receiver.Method`. Measurement and oracle
/// tests compare it with PowerShell's answer.
#[doc(hidden)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub cmds: Vec<Vec<String>>,
    pub comments: Vec<String>,
    pub methods: Vec<String>,
}

/// `Seen` for `script`, parsed from `src`.
#[doc(hidden)]
pub fn seen(src: &str, script: &Script) -> Seen {
    let mut cmds: Vec<(usize, Vec<String>)> = Vec::new();
    let mut methods: Vec<(usize, String)> = Vec::new();
    let text = |w: &Word| src.get(w.span.start..w.span.end).unwrap_or("").to_string();
    let mut scripts = vec![script];
    let mut words: Vec<&Word> = Vec::new();
    while !scripts.is_empty() || !words.is_empty() {
        if let Some(w) = words.pop() {
            for p in &w.parts {
                if let WordPart::Subst(s) | WordPart::Block(s) = p {
                    scripts.push(s);
                }
            }
            continue;
        }
        let Some(s) = scripts.pop() else { break };
        for st in &s.stmts {
            match st {
                Stmt::Pipeline(p) => {
                    for e in &p.elems {
                        match e {
                            Elem::Cmd(c) => {
                                if !c.typed.is_empty() || !c.name.parts.is_empty() {
                                    let mut el = vec![text(&c.name)];
                                    el.extend(c.args.iter().map(text));
                                    cmds.push((c.span.start, el));
                                }
                                words.push(&c.name);
                                words.extend(c.args.iter());
                                words.extend(c.redirects.iter().map(redirect_target));
                                words.extend(c.assigns.iter().map(|(_, v)| v));
                            }
                            Elem::Method(m) => {
                                let called = match m.args.first() {
                                    // An instance call: the receiver is the first argument.
                                    Some(r) if m.type_name.is_empty() => {
                                        format!("{}.{}", text(r), m.method)
                                    }
                                    _ => {
                                        let end = src[m.span.start..]
                                            .find("::")
                                            .map_or(m.span.start, |i| m.span.start + i);
                                        format!("{}::{}", &src[m.span.start..end], m.method)
                                    }
                                };
                                methods.push((m.span.start, called));
                                words.extend(m.args.iter());
                            }
                            Elem::Expr(w) => words.push(w),
                        }
                    }
                }
                Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                    scripts.push(body)
                }
                Stmt::Cond { branches, .. } => scripts.extend(branches.iter()),
            }
        }
    }
    cmds.sort_by_key(|c| c.0);
    // `a.B().C()`: calls that start at one offset sort by their text (ordinal).
    methods.sort();
    Seen {
        cmds: cmds.into_iter().map(|c| c.1).collect(),
        comments: script.comments.iter().map(|c| c.text.clone()).collect(),
        methods: methods.into_iter().map(|m| m.1).collect(),
    }
}
