//! What cmd.exe does to one argument PowerShell hands to a `.bat` or `.cmd` launcher. PowerShell
//! starts such a file through `cmd.exe /c`, so cmd.exe parses the command line again: an
//! operator character outside double quotes splits the line or vanishes, and `%NAME%` expands
//! anywhere, quoted or not.

/// The characters cmd.exe treats as operators outside double quotes: `|`, `&`, `<` and `>` split
/// the line, and `^` escapes the next character and disappears itself.
const OPERATORS: [char; 5] = ['|', '&', '<', '>', '^'];

/// What cmd.exe re-reads in one argument.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatReparse {
    /// Every operator character outside double quotes, in order.
    pub metachars: Vec<char>,
    /// The name inside every `%NAME%`, in order, quoted or not; whether cmd.exe replaces it
    /// depends on the environment, which the caller checks.
    pub percent_vars: Vec<String>,
}

/// How cmd.exe re-reads `arg`, the argument's value as PowerShell passes it on. `ps_quoted` says
/// whether PowerShell wraps it in double quotes on the command line (it does for an empty value
/// and for one with whitespace outside its own double quotes). Every `"` of the line opens or
/// closes cmd.exe's quoting, the wrapping pair included.
pub fn reparse_bat_arg(arg: &str, ps_quoted: bool) -> BatReparse {
    let mut out = BatReparse::default();
    let mut quoted = ps_quoted;
    for c in arg.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted && OPERATORS.contains(&c) {
            out.metachars.push(c);
        }
    }
    out.percent_vars = percent_names(arg);
    out
}

/// The names of `%NAME%` spans, read left to right as cmd.exe pairs the percent signs: a name
/// holds no whitespace, `=` or `%`; a `%` that opens no valid name is skipped.
fn percent_names(arg: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = arg;
    while let Some(open) = rest.find('%') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('%') else { break };
        let name = &after[..close];
        if !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c == '=') {
            names.push(name.to_string());
            rest = &after[close + 1..];
        } else {
            rest = after;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metachars(arg: &str, ps_quoted: bool) -> String {
        reparse_bat_arg(arg, ps_quoted)
            .metachars
            .into_iter()
            .collect()
    }

    #[test]
    fn operators_outside_quotes_are_reparsed() {
        let table = [
            ("A|B", false, "|"),
            ("pkg:^5.3", false, "^"),
            ("uptime&&df", false, "&&"),
            ("x>y<z", false, "><"),
            ("plain", false, ""),
            // Inside the argument's own double quotes cmd.exe leaves them alone.
            ("\"a|b\"", false, ""),
            ("SELECT \"a|b\" FROM t", true, "|"),
            // PowerShell's wrapping quotes protect the whole value.
            ("A B|C", true, ""),
            // An inner quote closes the wrapping pair: the rest is outside.
            ("\"a b\"|c", true, ""),
            ("x\"a b\"y>c", false, ">"),
        ];
        for (arg, wrapped, want) in table {
            assert_eq!(metachars(arg, wrapped), want, "{arg:?} wrapped={wrapped}");
        }
    }

    #[test]
    fn percent_names_are_found_quoted_or_not() {
        let table: [(&str, &[&str]); 6] = [
            ("%PATH%", &["PATH"]),
            ("LIKE '%x%'", &["x"]),
            ("\"%A%\" and %B%", &["A", "B"]),
            ("100% sure", &[]),
            // `%a b%` holds a space, so its closing `%` may open the next name.
            ("%a b%C%", &["C"]),
            ("%=x% %y%", &["y"]),
        ];
        for (arg, want) in table {
            let got = reparse_bat_arg(arg, false).percent_vars;
            assert_eq!(got, want, "{arg:?}");
        }
    }
}
