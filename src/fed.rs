//! The program a local shell reads on its stdin when the command fixes that text: the shell's own
//! heredoc or here-string, or what a literal producer before it in the pipeline writes
//! (`echo '…' | bash`, `'…' | pwsh -Command -`). The delete rule's raw scan and the wait-loop and follow walks read it
//! as they read the same shell's `-c` / `-Command` body, so the two forms read alike. A shell
//! that runs a script, a `-c` body or a file on stdin reads its stdin as data, and a shell on
//! another machine or in a container (`ssh host bash`, `docker exec -i c bash`) is no local shell:
//! neither has a body here.

use crate::Os;
use crate::Shell;
use crate::ir::{Elem, Quote, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::programs::{self, Kind, Program};
use crate::rules::delete::{self, leading_literal, literal};
use crate::scan;

/// The `extra` keys of a shell row this reader reads (`data/programs.toml`).
const LOOP_BODY: &str = "loop_body";
const STDIN_VALUE_OPTIONS: &str = "stdin_value_options";
const STDIN_POSITIONAL: &str = "stdin_positional";
const STDIN_CLUSTER_VALUE: &str = "stdin_value_in_cluster";
const CLUSTER_VALUE_REST: &str = "rest";
const STDIN_PROGRAM_PARAMS: &str = "stdin_program_params";
const STDIN_ENCODED_PARAMS: &str = "stdin_encoded_params";
const STDIN_SWITCH_PARAMS: &str = "stdin_switch_params";
const STDIN_AFTER_PARAMS: &str = "stdin_after_params";
const STDIN_DROPS_EMPTY: &str = "stdin_drops_empty_arguments";
/// The `extra` key of a producer row and its values (`data/programs.toml`).
const FEEDS: &str = "feeds";
const FEEDS_WORDS: &str = "words";
const FEEDS_FORMAT: &str = "format";
const FEEDS_STDIN: &str = "stdin";
const FEEDS_ONE: &str = "one";
/// Paths that name the process's own stdin, as a shell's script operand.
const STDIN_PATHS: [&str; 3] = ["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

/// A body a shell reads on stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fed {
    /// The body as the raw scan reads a `-c` body: its text with expansions as written.
    pub text: String,
    /// The body the wait-loop and follow walks read: set for a shell whose `-c` body they read
    /// (bash, sh, zsh), when every part of the body is literal.
    pub script: Option<String>,
}

/// The body `c` reads on stdin as its program. `prev` is the pipeline element before `c`, and
/// `src` the text the spans point into.
pub(crate) fn body(
    c: &SimpleCommand,
    prev: Option<&Elem>,
    src: &str,
    shell: Shell,
    os: Os,
) -> Option<Fed> {
    // Cheap first: a command with no stdin of its own and no producer is read no further. Its
    // own stdin redirect, the last one, comes after the pipe.
    let stdin = c.redirects.iter().rev().find(|r| r.replaces_stdin());
    if stdin.is_none() && prev.is_none() {
        return None;
    }
    let run = programs::strip_wrappers(c, shell, os);
    if run.opaque {
        return None;
    }
    let name = literal(&run.name).unwrap_or_else(|| run.typed.clone());
    let row = programs::lookup(&name, shell, os).filter(|p| p.is(Kind::Shell))?;
    let loops = strings(row, LOOP_BODY);
    let program = strings(row, STDIN_PROGRAM_PARAMS);
    // A Bash-family shell reads a `-c` body; PowerShell names its program parameters; any other
    // shell (`cmd`) is not read.
    let plain = if !loops.is_empty() {
        bash_reads_stdin(&run.args, src, delete::is_pwsh(shell), row, &loops)?
    } else if !program.is_empty() {
        pwsh_reads_stdin(&run.args, src, delete::is_pwsh(shell), row, &program).then_some(false)?
    } else {
        return None;
    };
    let (text, script) = match (stdin, prev) {
        (Some(r), _) => redirected(r, src)?,
        (None, Some(p)) => produced(p, src, shell, os)?,
        (None, None) => return None,
    };
    Some(Fed {
        script: script.filter(|_| plain),
        text,
    })
}

/// The text a stdin redirect feeds, and that text when every part of it is literal: a heredoc
/// or a here-string. A file or a descriptor holds text the guard does not have.
fn redirected(r: &Redirect, src: &str) -> Option<(String, Option<String>)> {
    match r {
        Redirect::Heredoc { body, .. } => Some((heredoc_text(body, src), literal(body))),
        Redirect::File { op, target, .. } if is_here_string(op) => {
            Some((here_string_text(target, src), literal(target)))
        }
        Redirect::File { .. } => None,
    }
}

/// What a literal producer writes into the pipe, as `redirected` gives it, by its row's `feeds`;
/// a PowerShell string or here-string writes itself. A word that the writer may still expand is
/// no static text, and any other producer (a download, a file, a variable) is not read.
fn produced(prev: &Elem, src: &str, shell: Shell, os: Os) -> Option<(String, Option<String>)> {
    let fixed = |w: &Word| literal(w).filter(|t| !t.contains(scan::EXPANDS));
    let p = match prev {
        Elem::Expr(w) => return fixed(w).map(|t| (t.clone(), Some(t))),
        Elem::Cmd(p) if !p.opaque => p,
        _ => return None,
    };
    let name = match (&p.canonical, delete::is_pwsh(shell)) {
        (Some(cmdlet), true) => cmdlet.to_lowercase(),
        _ => literal(&p.name)?,
    };
    let row = programs::lookup(&name, shell, os)?;
    let feeds = row.extra.get(FEEDS).and_then(|v| v.as_str())?;
    if feeds == FEEDS_STDIN {
        // `cat <<'EOF' | bash`: its own heredoc, nothing written to a file. (The raw scan reads a
        // heredoc there and no here-string, so neither does this.)
        let operands = p.args.iter().map(literal).collect::<Option<Vec<_>>>()?;
        if !(operands.is_empty() || operands == ["-"]) || p.redirects.iter().any(moves_output) {
            return None;
        }
        return match p.redirects.iter().rev().find(|r| r.replaces_stdin())? {
            r @ Redirect::Heredoc { .. } => redirected(r, src),
            Redirect::File { .. } => None,
        };
    }
    // A redirect may send the output elsewhere.
    if !p.redirects.is_empty() {
        return None;
    }
    if let (FEEDS_FORMAT, [format, arg]) = (feeds, p.args.as_slice()) {
        let format = literal(format)?;
        return scan::PRINTF_ARG_FORMATS
            .contains(&format.as_str())
            .then(|| fixed(arg))
            .flatten()
            .map(|t| (t.clone(), Some(t)));
    }
    let args = p.args.iter().map(fixed).collect::<Option<Vec<_>>>()?;
    let text = match (feeds, args.as_slice()) {
        (FEEDS_WORDS, [first, ..]) if !first.starts_with('-') => args.join(" "),
        (FEEDS_ONE | FEEDS_FORMAT, [one]) => one.clone(),
        _ => return None,
    };
    Some((text.clone(), Some(text)))
}

/// A list of strings a row holds under `key`; empty when it holds none.
fn strings<'a>(row: &'a Program, key: &str) -> Vec<&'a str> {
    row.extra
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

/// A redirect that may change what a producer writes on stdout: its stdout to a file or a copied
/// descriptor (`>out`, `&>out`, `>&2`, `2>&1`). A heredoc or a file on another descriptor
/// (`3<<X`, `2>/dev/null`) does not, and stdin's last redirect is read on its own.
fn moves_output(r: &Redirect) -> bool {
    let (fd, op) = r.fd_op();
    matches!(r, Redirect::File { .. })
        && (op.contains('&') || (op.contains('>') && matches!(fd, "" | "1")))
}

fn is_here_string(op: &str) -> bool {
    op.trim_start_matches(|ch: char| ch.is_ascii_digit()) == "<<<"
}

/// A word that may expand to no argument at all or to several, options among them, so the guard
/// cannot tell it from none: every part an unquoted expansion (`$OPTS`, `$A$B`, `$(opts)`,
/// PowerShell `$script`, `@args`, `$x.Path`, `(Get-Script)`), or a quoted all-arguments expansion
/// (`"$@"`, `"${x[@]}"`); with `quoted_vanish` (Windows PowerShell drops an empty argument) any
/// quoted expansion with no literal text. A word with literal or tilde text, any other quoted
/// expansion, a process substitution and a PowerShell parenthesised expression that holds a literal
/// argument (`(Join-Path $PSScriptRoot x.ps1)`) are one argument: the script.
fn may_vanish(w: &Word, src: &str, pwsh: bool, quoted_vanish: bool) -> bool {
    let expansion = |p: &WordPart| match p {
        WordPart::Var(_) => true,
        WordPart::Subst(s) | WordPart::Block(s) => !(pwsh && holds_literal_argument(s)),
        _ => false,
    };
    let all_expansions = !w.parts.is_empty() && w.parts.iter().all(expansion);
    let procsub = src
        .get(w.span.start..w.span.end)
        .is_some_and(|t| t.starts_with("<(") || t.starts_with(">("));
    match w.quote {
        _ if procsub => false,
        Quote::None => all_expansions,
        Quote::Double if quoted_vanish => all_expansions,
        Quote::Double => {
            matches!(w.parts.as_slice(), [WordPart::Var(n)] if n == "@" || n.ends_with("[@]"))
        }
        _ => false,
    }
}

/// Whether a substitution runs a command with a literal argument (`Join-Path $PSScriptRoot x.ps1`).
fn holds_literal_argument(s: &Script) -> bool {
    s.stmts.iter().any(|st| match st {
        Stmt::Pipeline(p) => p.elems.iter().any(|e| match e {
            Elem::Cmd(c) => c
                .args
                .iter()
                .any(|a| a.parts.iter().any(|p| matches!(p, WordPart::Literal(_)))),
            _ => false,
        }),
        _ => false,
    })
}

/// Whether a bash-family shell with these arguments runs its stdin: no `-c` body and no script
/// operand. A short option stands alone or in a cluster (`-ec`). A letter that takes a value
/// takes the next word and the letters after it still count (bash: `-ox pipefail`), or, where
/// the row says so, takes the rest of its word, or the next word as the last letter (zsh:
/// `-oerrexit`, `-eo errexit`). With `-s` the words after the options are positional parameters;
/// without it the first is the script, which is stdin only as `/dev/stdin`. A word the guard
/// cannot read is the script, unless it may vanish or hold options (`may_vanish`, `-o$x`).
/// `Some(plain)` when stdin is the
/// program, `plain` when no option took a value (the walks read a `-c` body only then).
fn bash_reads_stdin(
    args: &[Word],
    src: &str,
    pwsh: bool,
    row: &Program,
    loops: &[&str],
) -> Option<bool> {
    let values = strings(row, STDIN_VALUE_OPTIONS);
    let positional = strings(row, STDIN_POSITIONAL);
    // `sign` and `letter` spell one of the short options in `list` (`-o`, `+O`).
    let spells = |list: &[&str], sign: char, letter: char| {
        list.iter().any(|o| {
            let mut ch = o.chars();
            ch.next() == Some(sign) && ch.next() == Some(letter) && ch.next().is_none()
        })
    };
    // Whether the first operand `w` leaves stdin the program: none, `/dev/stdin`, or an unquoted
    // expansion standing alone, which may vanish (`$OPTS`). Any other word is the script.
    let no_script = |w: Option<&Word>| {
        w.is_none_or(|w| match literal(w) {
            Some(s) => STDIN_PATHS.contains(&s.as_str()),
            None => may_vanish(w, src, pwsh, false),
        })
    };
    // Bash takes the value of each value letter in a cluster from the next words and reads the
    // letters after it (`-ox pipefail`); zsh takes the rest of the word (`-oerrexit`).
    let rest_is_value =
        row.extra.get(STDIN_CLUSTER_VALUE).and_then(|v| v.as_str()) == Some(CLUSTER_VALUE_REST);
    let mut stdin_flag = false;
    let mut plain = true;
    let mut k = 0;
    while let Some(w) = args.get(k) {
        k += 1;
        let script = |w: Option<&Word>| stdin_flag || no_script(w);
        let Some(a) = literal(w) else {
            // A word that may vanish or hold options (`$OPTS`, `"$@"`), and one that starts as
            // an option (`-o$x`): read on past it. Any other word (`~/x.sh`, `"$HOME/x.sh"`,
            // `./run*.sh`, `<(…)`) is the script.
            if may_vanish(w, src, pwsh, false)
                || leading_literal(w).is_some_and(|l| l.starts_with(['-', '+']))
            {
                plain = false;
                continue;
            }
            return script(Some(w)).then_some(plain);
        };
        if a == "--" || a == "-" {
            return script(args.get(k)).then_some(plain);
        }
        if a.starts_with("--") {
            if values.contains(&a.as_str()) {
                k += 1;
                plain = false;
            }
            continue;
        }
        let sign = a.chars().next().unwrap_or(' ');
        if !(a.len() > 1 && (sign == '-' || sign == '+')) {
            return script(Some(w)).then_some(plain);
        }
        let letters = &a[1..];
        for (j, letter) in letters.char_indices() {
            if !letter.is_ascii_alphabetic() {
                break;
            }
            if sign == '-' && spells(loops, '-', letter) {
                return None;
            }
            stdin_flag |= sign == '-' && spells(&positional, '-', letter);
            if spells(&values, sign, letter) {
                plain = false;
                if !rest_is_value {
                    k += 1;
                    continue;
                }
                if j + 1 == letters.len() {
                    k += 1;
                }
                break;
            }
        }
    }
    Some(plain)
}

/// Whether PowerShell with these arguments runs its stdin as the program: `-Command -`, `-File -`,
/// a lone `-`, or no command and no file at all. A command, a file or an encoded command is no
/// stdin program, unless `-NoExit` comes before it: then stdin is read after it. A parameter is
/// any unambiguous prefix of its name (`-ex` for `-ExecutionPolicy`). A word the guard cannot
/// read is the file or the command, unless it is a splat.
fn pwsh_reads_stdin(args: &[Word], src: &str, pwsh: bool, row: &Program, program: &[&str]) -> bool {
    let encoded = strings(row, STDIN_ENCODED_PARAMS);
    let switches = strings(row, STDIN_SWITCH_PARAMS);
    let after = strings(row, STDIN_AFTER_PARAMS);
    let values: Vec<&str> = row.value_options.iter().map(String::as_str).collect();
    // `p` (lowercase, no dash) spells one of the parameters.
    let spells = |list: &[&str], p: &str| {
        list.iter()
            .any(|n| n.trim_start_matches('-').to_lowercase().starts_with(p))
    };
    // `-NoExit` reads stdin after the command or the file too.
    let mut keeps = false;
    let mut k = 0;
    while let Some(w) = args.get(k) {
        let Some(a) = literal(w) else {
            // A word that may vanish or spread (`$script`, `@args`, `(Get-Script)`) may hold any
            // parameters: read on past it. Any other word the guard cannot read
            // (`./x.ps1`-like text, `"$script"`, `(Join-Path $PSScriptRoot x.ps1)`) is the file
            // or the command.
            if may_vanish(w, src, pwsh, row.extra.contains_key(STDIN_DROPS_EMPTY)) {
                k += 1;
                continue;
            }
            return keeps;
        };
        let lower = a.to_lowercase();
        let Some(p) = ["--", "-", "/", "\u{2013}", "\u{2014}", "\u{2015}"]
            .iter()
            .find_map(|d| lower.strip_prefix(d))
        else {
            // A positional: the file or the command.
            return keeps;
        };
        if p.is_empty() {
            return keeps || a == "-";
        }
        let next_is_dash = || args.get(k + 1).and_then(literal).as_deref() == Some("-");
        if spells(program, p) {
            return keeps || next_is_dash();
        }
        if spells(&encoded, p) {
            return keeps;
        }
        keeps |= spells(&after, p);
        // A prefix a switch shares with a value parameter is the switch (`-i` is `-Interactive`,
        // not `-InputFormat`); a value parameter's own alias stays the value parameter.
        let value = values
            .iter()
            .any(|n| n.trim_start_matches('-').eq_ignore_ascii_case(p))
            || (spells(&values, p) && !spells(&switches, p));
        k += if value { 2 } else { 1 };
    }
    true
}

/// `text` when the word's literal parts are all in it, in order: the word as written. `None`
/// when it does not hold the word (an inexact location).
fn written<'s>(w: &Word, text: &'s str) -> Option<&'s str> {
    let mut rest = text;
    for p in &w.parts {
        if let WordPart::Literal(s) = p {
            let at = rest.find(s.as_str())?;
            rest = &rest[at + s.len()..];
        }
    }
    Some(text)
}

/// A word with each variable as `${name}` and each substitution as `$(…)`: the shape of the text
/// when its span does not hold it.
fn rendered(w: &Word) -> String {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) | WordPart::Glob(s) => out.push_str(s),
            WordPart::Var(v) => {
                out.push_str("${");
                out.push_str(v);
                out.push('}');
            }
            WordPart::Tilde => out.push('~'),
            WordPart::Subst(_) | WordPart::Block(_) | WordPart::ListSep => out.push_str("$(…)"),
        }
    }
    out
}

/// A heredoc body as the shell gets it: a quoted delimiter's body as is, an expanding one as
/// written (its expansions as `bash -c "…"` holds them).
fn heredoc_text(body: &Word, src: &str) -> String {
    if let Some(s) = literal(body) {
        return s;
    }
    // The body's span runs through its delimiter line.
    let lines = src
        .get(body.span.start..body.span.end)
        .map(|t| t.strip_suffix('\n').unwrap_or(t))
        .map(|t| t.rfind('\n').map_or("", |k| &t[..=k]));
    lines
        .and_then(|t| written(body, t))
        .map_or_else(|| rendered(body), str::to_string)
}

/// A here-string's word without its quotes, as the raw scan reads a quoted `-c` body.
fn here_string_text(w: &Word, src: &str) -> String {
    let Some(text) = src
        .get(w.span.start..w.span.end)
        .and_then(|t| written(w, t))
    else {
        return rendered(w);
    };
    let q = match w.quote {
        Quote::Single => '\'',
        Quote::Double => '"',
        _ => return text.to_string(),
    };
    text.strip_prefix(q)
        .and_then(|t| t.strip_suffix(q))
        .unwrap_or(text)
        .to_string()
}

/// The fed bodies of every command of a script, inside compound statements and substitutions
/// too, keyed by the command (the delete rule reads them by its command).
pub(crate) struct Index<'s> {
    bodies: Vec<(&'s SimpleCommand, String)>,
}

impl<'s> Index<'s> {
    pub(crate) fn of(script: &'s Script, src: &str, shell: Shell, os: Os) -> Index<'s> {
        let mut bodies = Vec::new();
        visit(script, &mut |c, prev| {
            if let Some(f) = body(c, prev, src, shell, os) {
                bodies.push((c, f.text));
            }
        });
        Index { bodies }
    }

    /// The text `c` reads on stdin as its program, if any.
    pub(crate) fn text(&self, c: &SimpleCommand) -> Option<&str> {
        self.bodies
            .iter()
            .find(|(k, _)| std::ptr::eq(*k, c))
            .map(|(_, t)| t.as_str())
    }
}

/// Every simple command of `s` with the pipeline element before it, inside compound statements,
/// substitutions and script blocks too.
fn visit<'s>(s: &'s Script, f: &mut dyn FnMut(&'s SimpleCommand, Option<&'s Elem>)) {
    for st in &s.stmts {
        match st {
            Stmt::Pipeline(p) => {
                for (k, e) in p.elems.iter().enumerate() {
                    let words: Vec<&Word> = match e {
                        Elem::Cmd(c) => {
                            f(c, k.checked_sub(1).and_then(|j| p.elems.get(j)));
                            std::iter::once(&c.name)
                                .chain(&c.args)
                                .chain(c.assigns.iter().map(|(_, w)| w))
                                .chain(c.redirects.iter().map(|r| match r {
                                    Redirect::File { target, .. } => target,
                                    Redirect::Heredoc { body, .. } => body,
                                }))
                                .collect()
                        }
                        Elem::Method(m) => m.args.iter().collect(),
                        Elem::Expr(w) => vec![w],
                    };
                    for w in words {
                        for part in &w.parts {
                            if let WordPart::Subst(inner) | WordPart::Block(inner) = part {
                                visit(inner, f);
                            }
                        }
                    }
                }
            }
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => visit(body, f),
            Stmt::Cond { branches, .. } => branches.iter().for_each(|b| visit(b, f)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BashProfile;
    use crate::parse::bash;

    const BASH: Shell = Shell::Bash(BashProfile::Posix);

    /// The text of every fed body in a Bash command, in order.
    fn texts(src: &str) -> Vec<String> {
        let script = bash::parse(src, BashProfile::Posix).expect("parses");
        let mut out = Vec::new();
        visit(&script, &mut |c, prev| {
            out.extend(body(c, prev, src, BASH, Os::Posix).map(|f| f.text));
        });
        out
    }

    /// The body is the text between the operator's line and the delimiter line, its expansions as
    /// written, wherever the heredoc stands: after a non-ASCII word, beside a second heredoc on
    /// its line, inside a substitution.
    #[test]
    fn a_heredoc_body_is_its_own_text() {
        let cases: [(&str, &[&str]); 10] = [
            ("bash <<'EOF'\nrm -rf ~\nEOF", &["rm -rf ~"]),
            ("bash <<EOF\nrm -rf $HOME/x\nEOF", &["rm -rf $HOME/x"]),
            (
                "bash <<EOF\nrm -rf $HOME/x\nEOF\necho next",
                &["rm -rf $HOME/x"],
            ),
            ("bash <<EOF 2>&1\n$(id)\nEOF", &["$(id)"]),
            ("bash <<EOF\nEOF\nrm -rf $D", &[""]),
            (
                "echo zażółć; bash <<EOF\nrm -rf \"${D}\"\nEOF",
                &["rm -rf \"${D}\""],
            ),
            (
                "cat <<A; bash <<EOF\nnot this\nA\nrm -rf $D\nEOF",
                &["rm -rf $D"],
            ),
            ("x=$(bash <<EOF\necho $(id)\nEOF\n)", &["echo $(id)"]),
            ("bash <<-EOF\n\trm -rf $D\n\tEOF", &["rm -rf $D"]),
            (
                "bash <<< \"rm -rf $D\"; sh <<< 'rm -rf ~'",
                &["rm -rf $D", "rm -rf ~"],
            ),
        ];
        for (src, want) in cases {
            let got = texts(src);
            let got: Vec<&str> = got.iter().map(|t| t.trim()).collect();
            assert_eq!(got, want, "{src:?}");
        }
    }

    #[test]
    fn stdin_that_is_data_has_no_body() {
        for src in [
            "bash -c 'echo hi' <<'EOF'\nrm -rf ~\nEOF",
            "bash -lc 'echo hi' <<< 'rm -rf ~'",
            "bash run.sh <<'EOF'\nrm -rf ~\nEOF",
            "bash <<'EOF' < run.sh\nrm -rf ~\nEOF",
            "bash <<'EOF' <&3\nrm -rf ~\nEOF",
            "bash <<'EOF' 0</dev/null\nrm -rf ~\nEOF",
            "bash 0< run.sh",
            "bash 3<<< 'rm -rf ~'",
            "bash 3<<'EOF' run.sh\nrm -rf ~\nEOF",
            "bash 3<<'EOF'\nrm -rf ~\nEOF",
            "bash -o pipefail run.sh <<< 'rm -rf ~'",
            "bash <(echo hi) <<< 'rm -rf ~'",
            "bash -- <(echo hi) <<< 'rm -rf ~'",
            "bash ~/x.sh <<< 'rm -rf ~'",
            "bash ~deploy/x.sh <<< 'rm -rf ~'",
            "bash ./run*.sh <<< 'rm -rf ~'",
            "bash x{1,2}.sh <<< 'rm -rf ~'",
            "bash \"$HOME/x.sh\" <<< 'rm -rf ~'",
            "bash ${HOME}/x.sh <<< 'rm -rf ~'",
            "bash $HOME/x.sh <<< 'rm -rf ~'",
            "bash \"$(dirname \"$0\")/x.sh\" <<< 'rm -rf ~'",
            "bash \"$script\" <<< 'rm -rf ~'",
            "bash -- \"$script\" <<< 'rm -rf ~'",
            "bash $OPTS x.sh <<< 'rm -rf ~'",
            "sudo bash ~/bin/setup.sh <<< 'rm -rf ~'",
            "bash -e ~/scripts/install.sh <<< 'rm -rf ~'",
            "pwsh \"$script\" <<< 'rm -rf ~'",
            "bash *.sh <<< 'rm -rf ~'",
            "bash \"$*\" <<< 'rm -rf ~'",
            "bash \"$(opts)\" <<< 'rm -rf ~'",
            "bash -eo pipefail run.sh <<< 'rm -rf ~'",
            "bash -euo pipefail run.sh <<< 'rm -rf ~'",
            "bash -xO extglob run.sh <<< 'rm -rf ~'",
            "bash -ec 'echo hi' <<< 'rm -rf ~'",
            "bash -oo errexit xtrace run.sh <<< 'rm -rf ~'",
            "bash -oc errexit 'echo hi' <<< 'rm -rf ~'",
            "bash -oxtrace <<< 'rm -rf ~'",
            "zsh -oerrexit run.sh <<< 'rm -rf ~'",
            "zsh -O extglob <<< 'rm -rf ~'",
            "zsh --emulate sh run.sh <<< 'rm -rf ~'",
            "cat <<'EOF'\nrm -rf ~\nEOF",
            "cat <<'EOF' >out.txt | bash\nrm -rf ~\nEOF",
            "cat <<'EOF' 2>&1 | bash\nrm -rf ~\nEOF",
            "cat <<'EOF' &>out.txt | bash\nrm -rf ~\nEOF",
            "cat <<'EOF' 0<&3 | bash\nrm -rf ~\nEOF",
            "cat 3<<'X' | bash\nrm -rf ~\nX",
            "cmd <<< 'rd /s /q x'",
            "pwsh -File run.ps1 <<< 'Remove-Item -Recurse x'",
            "pwsh -Command 'Get-Date' <<< 'Remove-Item -Recurse x'",
            "pwsh -EncodedCommand AAAA <<< 'Remove-Item -Recurse x'",
            "pwsh -NoProfile run.ps1 <<< 'Remove-Item -Recurse x'",
            "pwsh -ex Bypass run.ps1 <<< 'Remove-Item -Recurse x'",
            "pwsh -wo C:/x run.ps1 <<< 'Remove-Item -Recurse x'",
            "pwsh -i run.ps1 <<< 'Remove-Item -Recurse x'",
            "pwsh -in run.ps1 <<< 'Remove-Item -Recurse x'",
            "sudo --weird x bash <<< 'rm -rf ~'",
        ] {
            assert_eq!(texts(src), Vec::<String>::new(), "{src:?}");
        }
    }

    /// `-s` and `/dev/stdin` read stdin with words after them; a value option's value is no
    /// script; `-` and `--` end the options.
    #[test]
    fn a_shell_with_no_script_reads_stdin() {
        for src in [
            "bash -s <<< 'rm -rf ~'",
            "bash -s -- a b <<< 'rm -rf ~'",
            "bash -xs a <<< 'rm -rf ~'",
            "bash -s \"$X\" <<< 'rm -rf ~'",
            "bash /dev/stdin a <<< 'rm -rf ~'",
            "bash -- /dev/stdin <<< 'rm -rf ~'",
            "bash - <<< 'rm -rf ~'",
            "bash -o pipefail -e <<< 'rm -rf ~'",
            "bash -eo pipefail <<< 'rm -rf ~'",
            "bash -euo pipefail <<< 'rm -rf ~'",
            "bash -xO extglob <<< 'rm -rf ~'",
            "bash -opipefail <<< 'rm -rf ~'",
            "bash -ox errexit <<< 'rm -rf ~'",
            "bash -os errexit run.sh <<< 'rm -rf ~'",
            "bash -so errexit run.sh <<< 'rm -rf ~'",
            "bash -oo errexit xtrace <<< 'rm -rf ~'",
            "zsh -oerrexit <<< 'rm -rf ~'",
            "zsh -eo errexit <<< 'rm -rf ~'",
            "zsh --emulate sh <<< 'rm -rf ~'",
            "zsh -Os extglob run.sh <<< 'rm -rf ~'",
            "cat <<'EOF' 3<<'X' | bash\nrm -rf ~\nEOF\nhi\nX",
            "cat 3<<'X' <<'EOF' 2>/dev/null | bash\nhi\nX\nrm -rf ~\nEOF",
            "bash --rcfile x.rc <<< 'rm -rf ~'",
            "bash --norc --login <<< 'rm -rf ~'",
            "bash < run.sh <<< 'rm -rf ~'",
            "bash 0<<'EOF'\nrm -rf ~\nEOF",
            "bash $OPTS <<< 'rm -rf ~'",
            "bash $(opts) <<< 'rm -rf ~'",
            "bash $A$B <<< 'rm -rf ~'",
            "bash \"$@\" <<< 'rm -rf ~'",
            "bash ${arr[@]} <<< 'rm -rf ~'",
            "bash \"${arr[@]}\" <<< 'rm -rf ~'",
            "pwsh $script <<< 'rm -rf ~'",
            "bash -- $S <<< 'rm -rf ~'",
            "bash -o$X <<< 'rm -rf ~'",
            "bash -s \"$script\" <<< 'rm -rf ~'",
            "pwsh -NoProfile -ExecutionPolicy Bypass -Command - <<< 'rm -rf ~'",
            "pwsh -ex Bypass <<< 'rm -rf ~'",
            "pwsh -ep Bypass -c - <<< 'rm -rf ~'",
            "pwsh -wo C:/x <<< 'rm -rf ~'",
            "pwsh -WorkingDir C:/x -Command - <<< 'rm -rf ~'",
            "pwsh -File - <<< 'rm -rf ~'",
            "pwsh -f - <<< 'rm -rf ~'",
            "pwsh - <<< 'rm -rf ~'",
            "powershell -NoProfile <<< 'rm -rf ~'",
            "powershell -wo C:/x <<< 'rm -rf ~'",
            "pwsh -i <<< 'rm -rf ~'",
            "pwsh -if Text <<< 'rm -rf ~'",
            "pwsh -NoExit -File run.ps1 <<< 'rm -rf ~'",
            "pwsh -noe run.ps1 <<< 'rm -rf ~'",
            "powershell -NoExit -Command Get-Date <<< 'rm -rf ~'",
        ] {
            let got = texts(src);
            let got: Vec<&str> = got.iter().map(|t| t.trim_end()).collect();
            assert_eq!(got, ["rm -rf ~"], "{src:?}");
        }
    }

    /// The loop and follow walks read the body only where they read a `-c` body: a Bash-family
    /// shell whose options take no value, and a literal body.
    #[test]
    fn the_walks_read_a_literal_body_after_plain_options() {
        let script = |src: &str| {
            let s = bash::parse(src, BashProfile::Posix).expect("parses");
            let mut out = Vec::new();
            visit(&s, &mut |c, prev| {
                out.extend(body(c, prev, src, BASH, Os::Posix).map(|f| f.script));
            });
            out
        };
        let loop_text = Some("sleep 1".to_string());
        for src in [
            "bash <<< 'sleep 1'",
            "bash -xs a <<< 'sleep 1'",
            "echo 'sleep 1' | sh",
        ] {
            assert_eq!(script(src), std::slice::from_ref(&loop_text), "{src:?}");
        }
        for src in [
            "bash -o pipefail <<< 'sleep 1'",
            "bash -eo pipefail <<< 'sleep 1'",
            "bash <<< \"sleep $N\"",
            "pwsh -Command - <<< 'sleep 1'",
        ] {
            assert_eq!(script(src), [None], "{src:?}");
        }
    }
}
