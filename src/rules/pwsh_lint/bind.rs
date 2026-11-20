//! Parameter binding as PowerShell's binder does it, against the pwsh 7 table: which parameter a
//! `-name` token binds, and which words are values and which are positional.

use super::table::{Cmdlet, Param};
use super::text;
use crate::ir::{Quote, SimpleCommand, Word, WordPart};

/// How PowerShell binds a parameter name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Param(&'static Param),
    Ambiguous(Vec<&'static str>),
    Missing,
}

/// Bind `typed` (the name after the dash) as PowerShell does: an exact name, then an exact alias,
/// then a unique prefix of a name or an alias; when several parameters match, a single one that
/// is not a common parameter wins. Dynamic parameters are tried only when no other one matches
/// (`Get-ChildItem -fo` binds `-Force`, not `-FollowSymlink`). Checked against real calls in
/// pwsh 7.7.
pub fn bind(c: &Cmdlet, typed: &str) -> Bound {
    match bind_among(c, typed, false) {
        Bound::Missing => bind_among(c, typed, true),
        found => found,
    }
}

fn bind_among(c: &Cmdlet, typed: &str, dynamic: bool) -> Bound {
    let n = typed.to_lowercase();
    let pool: Vec<(&'static Param, bool)> = c
        .all_params()
        .filter(|(p, _)| p.dynamic == dynamic)
        .collect();
    if let Some((p, _)) = pool.iter().find(|(p, _)| p.name == n) {
        return Bound::Param(p);
    }
    if let Some((p, _)) = pool.iter().find(|(p, _)| p.aliases.contains(&n.as_str())) {
        return Bound::Param(p);
    }
    let hits: Vec<(&'static Param, bool)> = pool
        .into_iter()
        .filter(|(p, _)| p.name.starts_with(&n) || p.aliases.iter().any(|a| a.starts_with(&n)))
        .collect();
    match hits.as_slice() {
        [] => Bound::Missing,
        [(one, _)] => Bound::Param(one),
        _ => {
            let own: Vec<&'static Param> = hits
                .iter()
                .filter(|(_, common)| !common)
                .map(|(p, _)| *p)
                .collect();
            match own.as_slice() {
                [one] => Bound::Param(one),
                _ => Bound::Ambiguous(hits.iter().map(|(p, _)| p.name).collect()),
            }
        }
    }
}

/// A dash PowerShell reads as the start of a parameter: ASCII `-` and the en, em and horizontal
/// bar dashes.
pub fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

/// A parameter token as written: the name after the dash, and the value after `:` when one is
/// attached (`-Path:x`). `-Path:` alone (`attached` empty) takes the next word as its value.
pub struct ParamToken<'a> {
    pub name: &'a str,
    pub attached: Option<&'a str>,
}

/// The parameter token `w` is, or `None` for an argument: an unquoted dash then a letter, `_` or
/// `?` (a negative number is an argument; `--name` binds to no parameter).
pub fn param_token<'a>(src: &'a str, w: &Word) -> Option<ParamToken<'a>> {
    if matches!(w.quote, Quote::Single | Quote::Double) {
        return None;
    }
    if !matches!(w.parts.first(), Some(WordPart::Literal(_))) {
        return None;
    }
    let raw = text(src, w.span);
    let mut chars = raw.char_indices();
    let (_, first) = chars.next()?;
    if !is_dash(first) {
        return None;
    }
    let (at, second) = chars.next()?;
    if !(second.is_alphabetic() || second == '_' || second == '?') {
        return None;
    }
    let body = &raw[at..];
    Some(match body.split_once(':') {
        Some((name, value)) => ParamToken {
            name,
            attached: Some(value),
        },
        None => ParamToken {
            name: body,
            attached: None,
        },
    })
}

/// `--`: the end of parameters, after which every word is an argument.
pub fn ends_parameters(src: &str, w: &Word) -> bool {
    w.quote == Quote::None && text(src, w.span) == "--"
}

/// `--%`: stop parsing; the rest of the line goes to the program as written.
pub fn stops_parsing(src: &str, w: &Word) -> bool {
    text(src, w.span).starts_with("--%")
}

/// Each argument of a cmdlet call with what binding makes of it.
pub enum Arg<'w> {
    /// A parameter token and what it binds to; `value` is the separate word it takes.
    Named {
        word: &'w Word,
        attached: Option<String>,
        bound: Option<&'static str>,
        problem: Option<Problem>,
        value: Option<&'w Word>,
    },
    Positional(&'w Word),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    Missing,
    Ambiguous(Vec<&'static str>),
    NoValue(&'static str),
}

/// Whether `w` is a parameter token that names a static parameter of `cmd`, alone or among
/// several. Only then does it end the previous parameter's value: pwsh takes `-a` (no static
/// match), `-File` (a dynamic one) or `-NoProfile` (none) as the value itself (probed: `-l -a`
/// lists the path `-a`, `-l -Force` is "Missing an argument").
fn names_static(src: &str, w: &Word, cmd: &Cmdlet) -> bool {
    param_token(src, w).is_some_and(|t| bind_among(cmd, t.name, false) != Bound::Missing)
}

/// The arguments of `c` bound against `cmd`, as PowerShell's binder reads them; `None` after
/// `--%`, which hands the rest to the program as text.
pub fn bind_args<'w>(src: &str, c: &'w SimpleCommand, cmd: &Cmdlet) -> Option<Vec<Arg<'w>>> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut params_over = false;
    while i < c.args.len() {
        let w = &c.args[i];
        if stops_parsing(src, w) {
            return None;
        }
        if !params_over && ends_parameters(src, w) {
            params_over = true;
            i += 1;
            continue;
        }
        let token = if params_over {
            None
        } else {
            param_token(src, w)
        };
        let Some(t) = token else {
            out.push(Arg::Positional(w));
            i += 1;
            continue;
        };
        let (bound, mut problem, switch) = match bind(cmd, t.name) {
            Bound::Param(p) => (Some(p.name), None, p.switch),
            Bound::Ambiguous(names) => (None, Some(Problem::Ambiguous(names)), true),
            Bound::Missing => (None, Some(Problem::Missing), true),
        };
        // `-Name:` with nothing attached takes the next word, a switch too (`-Force: $false`).
        let colon_alone = t.attached == Some("");
        let mut value = None;
        if (!switch && t.attached.is_none()) || (colon_alone && bound.is_some()) {
            match c.args.get(i + 1) {
                Some(next) if !stops_parsing(src, next) && !names_static(src, next, cmd) => {
                    value = Some(next);
                    i += 1;
                }
                _ => problem = bound.map(Problem::NoValue),
            }
        }
        out.push(Arg::Named {
            word: w,
            attached: t.attached.filter(|a| !a.is_empty()).map(str::to_string),
            bound,
            problem,
            value,
        });
        i += 1;
    }
    Some(out)
}

/// The bound parameter `param` of the call, with its separate value word or attached text.
pub fn named<'a, 'w>(args: &'a [Arg<'w>], param: &str) -> Option<&'a Arg<'w>> {
    args.iter()
        .find(|a| matches!(a, Arg::Named { bound: Some(b), .. } if *b == param))
}

/// A switch given and not turned off with `:$false`.
pub fn switch_on(src: &str, args: &[Arg], param: &str) -> bool {
    let off = |v: &str| v.eq_ignore_ascii_case("$false");
    match named(args, param) {
        Some(Arg::Named {
            attached, value, ..
        }) => {
            !attached.as_deref().is_some_and(off) && !value.is_some_and(|v| off(text(src, v.span)))
        }
        _ => false,
    }
}

pub fn positional<'w>(args: &[Arg<'w>]) -> Vec<&'w Word> {
    args.iter()
        .filter_map(|a| match a {
            Arg::Positional(w) => Some(*w),
            _ => None,
        })
        .collect()
}
