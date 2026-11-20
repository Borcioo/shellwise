//! `ps-var-colon`: `"$name: text"`. Inside a PowerShell double-quoted string `$name:` starts a
//! drive or scope reference (`$env:TEMP`); with no name after the colon PowerShell refuses the
//! whole string and runs nothing. The rule reads each double-quoted word through its span in the
//! raw text, because the parser keeps the variable and the text after it apart.

use super::{Ctx, Rule};
use crate::Shell;
use crate::ir::{Elem, Pipeline, Quote, Redirect, Script, Stmt, Word, WordPart};
use crate::level::{Finding, Level, Span};

pub const PS_VAR_COLON: &str = "ps-var-colon";

pub struct PsVarColon;

impl Rule for PsVarColon {
    fn id(&self) -> &'static str {
        PS_VAR_COLON
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !matches!(ctx.input.shell, Shell::Pwsh | Shell::Powershell5) {
            return;
        }
        let command = ctx.input.command;
        visit_script(ctx.script, &mut |word| {
            if !matches!(word.quote, Quote::Double | Quote::Mixed) {
                return;
            }
            let Some(text) = command.get(word.span.start..word.span.end) else {
                return;
            };
            for (at, name) in colon_variables(text) {
                let start = word.span.start + at;
                out.push(Finding {
                    rule: PS_VAR_COLON,
                    level: Level::Break,
                    message: format!(
                        "in a double-quoted string PowerShell reads ${name}: as a variable on a drive called {name}, and refuses the whole command"
                    ),
                    fix: Some(format!("write \"${{{name}}}:\" instead of \"${name}:\"")),
                    span: Span {
                        start,
                        end: start + 1 + name.len() + 1,
                    },
                });
            }
        });
    }
}

/// A character of a PowerShell variable name: a letter or digit of any script, `_` or `?`.
fn is_name(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '?'
}

/// The byte offset just past the variable name starting at `start`.
fn name_end(text: &str, start: usize) -> usize {
    text[start..]
        .char_indices()
        .find(|&(_, c)| !is_name(c))
        .map_or(text.len(), |(k, _)| start + k)
}

/// The `$name:` references in the double-quoted parts of `text` (one word as written), as the
/// byte offset of the `$` and the name. A `:` followed by a name character is a drive or scope
/// reference (`$env:TEMP`, `$script:x`) and one followed by `:` a static member (`$t::Now`); both
/// are skipped. `${…}`, `$(…)` and single-quoted text are not read.
fn colon_variables(text: &str) -> Vec<(usize, &str)> {
    let b = text.as_bytes();
    let mut found = Vec::new();
    let (mut double, mut single) = (false, false);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'`' && !single {
            i += 2;
            continue;
        }
        if single {
            single = c != b'\'';
        } else if !double {
            match c {
                b'"' => double = true,
                b'\'' => single = true,
                _ => {}
            }
        } else if c == b'"' {
            if b.get(i + 1) == Some(&b'"') {
                i += 1;
            } else {
                double = false;
            }
        } else if c == b'$' {
            match b.get(i + 1).copied() {
                Some(b'(') => {
                    i = skip_group(b, i + 1, b'(', b')');
                    continue;
                }
                Some(b'{') => {
                    i = skip_group(b, i + 1, b'{', b'}');
                    continue;
                }
                Some(b'$' | b'?' | b'^') => {
                    i += 2;
                    continue;
                }
                _ => {
                    let end = name_end(text, i + 1);
                    if end > i + 1 {
                        let after = text[end..].strip_prefix(':').map(|t| t.chars().next());
                        if let Some(next) = after
                            && !next.is_some_and(|n| is_name(n) || n == ':')
                        {
                            found.push((i, &text[i + 1..end]));
                        }
                        i = end;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    found
}

/// The index just past the group whose opener is at `open`, counting nesting; the end of the text
/// when it never closes.
fn skip_group(b: &[u8], open: usize, up: u8, down: u8) -> usize {
    let mut depth = 0usize;
    for (j, &c) in b.iter().enumerate().skip(open) {
        if c == up {
            depth += 1;
        } else if c == down {
            depth -= 1;
            if depth == 0 {
                return j + 1;
            }
        }
    }
    b.len()
}

fn visit_script(script: &Script, f: &mut dyn FnMut(&Word)) {
    for stmt in &script.stmts {
        match stmt {
            Stmt::Pipeline(p) => visit_pipeline(p, f),
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                visit_script(body, f)
            }
            Stmt::Cond { branches, .. } => branches.iter().for_each(|b| visit_script(b, f)),
        }
    }
}

fn visit_pipeline(p: &Pipeline, f: &mut dyn FnMut(&Word)) {
    for elem in &p.elems {
        match elem {
            Elem::Cmd(c) => {
                visit_word(&c.name, f);
                c.args.iter().for_each(|w| visit_word(w, f));
                c.assigns.iter().for_each(|(_, w)| visit_word(w, f));
                for r in &c.redirects {
                    match r {
                        Redirect::File { target, .. } => visit_word(target, f),
                        Redirect::Heredoc { body, .. } => visit_word(body, f),
                    }
                }
            }
            Elem::Method(m) => m.args.iter().for_each(|w| visit_word(w, f)),
            Elem::Expr(w) => visit_word(w, f),
        }
    }
}

/// The word, then the scripts inside it. A nested script's own strings are separate words: the
/// scan of the outer word skips `$(…)`.
fn visit_word(word: &Word, f: &mut dyn FnMut(&Word)) {
    f(word);
    for part in &word.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = part {
            visit_script(s, f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<&str> {
        colon_variables(text).into_iter().map(|(_, n)| n).collect()
    }

    #[test]
    fn a_name_then_a_colon_and_no_name_is_a_finding() {
        assert_eq!(names("\"$n: done\""), ["n"]);
        assert_eq!(names("\"$f:$l\""), ["f"]);
        assert_eq!(names("\"$LASTEXITCODE: x\""), ["LASTEXITCODE"]);
        assert_eq!(names("\"at $h:\""), ["h"]);
        assert_eq!(colon_variables("\"$n: x\"")[0].0, 1);
    }

    #[test]
    fn a_name_after_the_colon_a_group_or_single_quotes_are_not() {
        for text in [
            "\"${n}: done\"",
            "\"$env:TEMP x\"",
            "\"$($n): x\"",
            "'$n: x'",
            "\"$script:x\"",
            "\"$global:x\"",
            "\"cost $5 and $: x\"",
            "\"`$n: x\"",
        ] {
            assert!(names(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn single_quoted_text_beside_a_double_quoted_part_is_skipped() {
        assert_eq!(names("'$a: '\"$b: \""), ["b"]);
        // Double quotes inside single-quoted text open no string.
        assert!(names("x'\"$n: y\"'").is_empty());
    }
}
