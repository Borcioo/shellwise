//! The raw-text destructive scan used on every fail-closed path. It needs no parser: it splits the
//! text into simple commands leniently, once in the bash and once in the PowerShell reading, and
//! matches the names and flags of `data/destructive.toml` from every shell. Over-matching is the
//! safe side here: the scan only runs when the real analysis could not finish.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::level::Span;

const TABLE_TEXT: &str = include_str!("../data/destructive.toml");
const SHELLS: [&str; 3] = ["bash", "pwsh", "cmd"];
/// `bash -c "…"` inside `pwsh -c "…"` …: deeper bodies are not scanned.
const MAX_DEPTH: usize = 4;

/// One `[[command]]` row of `data/destructive.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Each name split into lowercase words (`git reset` -> `["git", "reset"]`).
    pub names: Vec<Vec<String>>,
    pub shells: Vec<String>,
    pub requires_any: Vec<String>,
    pub unless_any: Vec<String>,
}

/// A table row that matched, and the span of the simple command it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    /// The table row, or `None` for a nested body the scan cannot read (an encoded command).
    pub row: Option<usize>,
    pub span: Span,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    command: Vec<RawRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRow {
    names: Vec<String>,
    shells: Vec<String>,
    requires_any: Vec<String>,
    #[serde(default)]
    unless_any: Vec<String>,
}

/// Parse and validate a destructive table.
pub fn load(text: &str) -> Result<Vec<Entry>, String> {
    let raw: RawTable = toml::from_str(text).map_err(|e| e.to_string())?;
    if raw.command.is_empty() {
        return Err("no [[command]] rows".to_string());
    }
    let mut out = Vec::new();
    for (k, row) in raw.command.into_iter().enumerate() {
        let n = k + 1;
        let lists = [
            ("names", &row.names),
            ("shells", &row.shells),
            ("requires_any", &row.requires_any),
            ("unless_any", &row.unless_any),
        ];
        for (key, list) in lists {
            if list.iter().any(|s| s.trim().is_empty()) {
                return Err(format!("row {n}: {key} holds an empty string"));
            }
        }
        if row.names.is_empty() || row.shells.is_empty() {
            return Err(format!("row {n}: names and shells must be non-empty"));
        }
        if let Some(s) = row.shells.iter().find(|s| !SHELLS.contains(&s.as_str())) {
            return Err(format!("row {n}: unknown shell {s:?}"));
        }
        out.push(Entry {
            names: row
                .names
                .iter()
                .map(|n| n.split_whitespace().map(str::to_lowercase).collect())
                .collect(),
            shells: row.shells,
            requires_any: row.requires_any,
            unless_any: row.unless_any,
        });
    }
    Ok(out)
}

/// The embedded `data/destructive.toml`.
pub fn table() -> &'static [Entry] {
    static TABLE: OnceLock<Vec<Entry>> = OnceLock::new();
    TABLE.get_or_init(|| load(TABLE_TEXT).expect("data/destructive.toml is valid"))
}

/// Every simple command of `cmd` that a row of `table` names.
pub fn hits(table: &[Entry], cmd: &str) -> Vec<Hit> {
    hits_at(table, cmd, 0)
}

/// The span of the first simple command in `cmd` that the destructive table names.
pub fn raw_destructive(cmd: &str) -> Option<Span> {
    hits(table(), cmd)
        .into_iter()
        .map(|h| h.span)
        .min_by_key(|s| (s.start, s.end))
}

/// Whether a table flag entry matches one word, as the table header defines it.
pub fn flag_matches(entry: &str, word: &str) -> bool {
    // Git Bash turns `//MIR` into `/MIR`.
    let word = if word.starts_with("//") {
        &word[1..]
    } else {
        word
    };
    if entry.len() > 2 && entry.starts_with("--") {
        return word == entry || word.starts_with(&format!("{entry}="));
    }
    let e = entry.as_bytes();
    if e.len() == 2 && e[0] == b'-' && e[1].is_ascii_alphabetic() {
        let rest = word.strip_prefix('-').unwrap_or("");
        return !word.starts_with("--")
            && !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_alphabetic())
            && rest.as_bytes().contains(&e[1]);
    }
    if entry.starts_with('/') {
        return word.eq_ignore_ascii_case(entry);
    }
    word == entry
}

fn hits_at(table: &[Entry], cmd: &str, depth: usize) -> Vec<Hit> {
    let mut out = Vec::new();
    if depth > MAX_DEPTH {
        return out;
    }
    for mode in [Mode::Bash, Mode::Pwsh] {
        let (segs, embedded) = segments(cmd, mode);
        for seg in segs {
            segment_hits(table, strip_prefix(&seg), depth, &mut out);
        }
        for (span, body) in embedded {
            for h in hits_at(table, &body, depth + 1) {
                out.push(Hit { row: h.row, span });
            }
        }
    }
    // Both readings usually find the same command.
    out.sort_by_key(|h| (h.span.start, h.span.end, h.row));
    out.dedup();
    out
}

fn segment_hits(table: &[Entry], words: &[Tok], depth: usize, out: &mut Vec<Hit>) {
    let Some(first) = words.first() else { return };
    let span = Span {
        start: first.span.start,
        end: words[words.len() - 1].span.end,
    };
    let name = base_name(&first.value);
    match nested_body(&name, words) {
        Some(Nested::Body(body)) => {
            for h in hits_at(table, &body, depth + 1) {
                out.push(Hit { row: h.row, span });
            }
            return;
        }
        Some(Nested::Opaque) => {
            out.push(Hit { row: None, span });
            return;
        }
        None => {}
    }
    if name == "find" {
        for (k, w) in words.iter().enumerate() {
            if FIND_EXEC.contains(&w.value.as_str()) {
                let rest = &words[k + 1..];
                let end = rest
                    .iter()
                    .position(|w| matches!(w.value.as_str(), ";" | "+" | "\\;"))
                    .unwrap_or(rest.len());
                segment_hits(table, strip_prefix(&rest[..end]), depth, out);
            }
        }
    }
    for (row, entry) in table.iter().enumerate() {
        for name_words in &entry.names {
            let Some(end) = match_name(name_words, words) else {
                continue;
            };
            let args = &words[end..];
            let any = |flags: &[String]| {
                flags
                    .iter()
                    .any(|f| args.iter().any(|a| flag_matches(f, &a.value)))
            };
            if (entry.requires_any.is_empty() || any(&entry.requires_any))
                && !any(&entry.unless_any)
            {
                out.push(Hit {
                    row: Some(row),
                    span,
                });
            }
        }
    }
}

const FIND_EXEC: [&str; 4] = ["-exec", "-execdir", "-ok", "-okdir"];
const PREFIX_WORDS: [&str; 16] = [
    "sudo", "command", "exec", "nohup", "time", "xargs", "env", "&", "!", "then", "do", "else",
    "elif", "if", "while", "until",
];
const GIT_VALUE_OPTS: [&str; 7] = [
    "-c",
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
];

enum Nested {
    /// The text of the nested command.
    Body(String),
    /// A nested command the scan cannot read (`pwsh -EncodedCommand`).
    Opaque,
}

#[derive(PartialEq, Eq)]
enum Flag {
    Command,
    Encoded,
}

/// The body of `bash -c …`, `pwsh -Command …`, `cmd /c …` or `Invoke-Expression …`, if any.
fn nested_body(name: &str, words: &[Tok]) -> Option<Nested> {
    let join = |rest: &[Tok]| {
        rest.iter()
            .map(|w| w.value.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    match name {
        "invoke-expression" | "iex" => Some(Nested::Body(join(&words[1..]))),
        "bash" | "sh" | "pwsh" | "powershell" | "cmd" => {
            let (k, flag) = words[1..].iter().enumerate().find_map(|(k, w)| {
                if w.quoted {
                    return None;
                }
                nested_flag(name, &w.value).map(|f| (k, f))
            })?;
            Some(match flag {
                Flag::Encoded => Nested::Opaque,
                Flag::Command => Nested::Body(join(&words[k + 2..])),
            })
        }
        _ => None,
    }
}

fn nested_flag(shell: &str, v: &str) -> Option<Flag> {
    let v = v.to_ascii_lowercase();
    if matches!(v.as_str(), "/c" | "/k" | "//c" | "//k") {
        return Some(Flag::Command);
    }
    if matches!(shell, "pwsh" | "powershell") {
        // PowerShell accepts `-x`, `--x`, `/x` and dash-like characters before any unambiguous
        // prefix of a parameter name.
        let rest = ["--", "-", "/", "\u{2013}", "\u{2014}", "\u{2015}"]
            .iter()
            .find_map(|p| v.strip_prefix(p))
            .filter(|r| !r.is_empty())?;
        if rest == "ec" || (rest.starts_with('e') && "encodedcommand".starts_with(rest)) {
            return Some(Flag::Encoded);
        }
        if "command".starts_with(rest) || "commandwithargs".starts_with(rest) || rest == "cwa" {
            return Some(Flag::Command);
        }
        return None;
    }
    // bash -c, -lc, -ec: a cluster of short options ending in c.
    let rest = v.strip_prefix('-').filter(|r| !r.is_empty())?;
    (rest.bytes().all(|b| b.is_ascii_lowercase()) && rest.ends_with('c')).then_some(Flag::Command)
}

/// The command name without a directory or `.exe`, lowercased.
fn base_name(word: &str) -> String {
    let lower = word.to_lowercase();
    let name = lower.rsplit(['\\', '/']).next().unwrap_or("");
    name.strip_suffix(".exe").unwrap_or(name).to_string()
}

/// The index after the matched name in `words`, or `None`. git global options are skipped.
fn match_name(name_words: &[String], words: &[Tok]) -> Option<usize> {
    if base_name(&words[0].value) != name_words[0] {
        return None;
    }
    let mut k = 1;
    if name_words[0] == "git" {
        while k < words.len() && words[k].value.starts_with('-') {
            k += if GIT_VALUE_OPTS.contains(&words[k].value.as_str()) {
                2
            } else {
                1
            };
        }
    }
    for part in &name_words[1..] {
        if words.get(k)?.value.to_lowercase() != *part {
            return None;
        }
        k += 1;
    }
    Some(k)
}

/// Drop leading words that only prefix the real command: `sudo`, `env`, assignments, casts.
fn strip_prefix(words: &[Tok]) -> &[Tok] {
    let mut k = 0;
    while k < words.len() {
        let w = &words[k];
        if w.quoted {
            break;
        }
        let v = w.value.as_str();
        let after_xargs = k > 0 && v.starts_with('-') && words[k - 1].value == "xargs";
        if PREFIX_WORDS.contains(&v.to_lowercase().as_str()) || is_assignment(v) || after_xargs {
            k += 1;
        } else if is_ps_var(v)
            && words
                .get(k + 1)
                .is_some_and(|n| n.value == "=" || n.value == "+=")
        {
            k += 2;
        } else if v.starts_with('[') && v.ends_with(']') && !v.contains("::") {
            k += 1;
        } else {
            break;
        }
    }
    &words[k..]
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

/// `NAME=value`
fn is_assignment(v: &str) -> bool {
    let Some((name, _)) = v.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(is_ident_start) && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `$name`, `$env:name`, `[int]$name`
fn is_ps_var(v: &str) -> bool {
    let mut rest = v;
    while rest.starts_with('[') {
        match rest.find(']') {
            Some(k) => rest = &rest[k + 1..],
            None => return false,
        }
    }
    let Some(name) = rest.strip_prefix('$') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bash,
    Pwsh,
}

#[derive(Debug, Clone)]
struct Tok {
    value: String,
    quoted: bool,
    span: Span,
}

type Segments = (Vec<Vec<Tok>>, Vec<(Span, String)>);

fn char_len_at(text: &str, i: usize) -> usize {
    text[i..].chars().next().map_or(1, char::len_utf8)
}

/// Simple commands of `text` as words: split at `; | & ( ) { }` and newlines, quotes joined into
/// their word, comments dropped. Lenient: an unclosed quote or comment runs to the end.
/// Also returns quoted text that may run as code (a substitution in `"…"`, an unclosed quote),
/// with its span, for the caller to scan as a nested command.
fn segments(text: &str, mode: Mode) -> Segments {
    let b = text.as_bytes();
    let n = text.len();
    let mut out = Vec::new();
    let mut embedded = Vec::new();
    let mut words: Vec<Tok> = Vec::new();
    let mut cur: Option<Tok> = None;
    let mut i = 0;

    fn push(cur: &mut Option<Tok>, start: usize, end: usize, s: &str, quoted: bool) {
        let t = cur.get_or_insert_with(|| Tok {
            value: String::new(),
            quoted: false,
            span: Span { start, end },
        });
        t.value.push_str(s);
        t.quoted |= quoted;
        t.span.end = end;
    }
    let end_word = |cur: &mut Option<Tok>, words: &mut Vec<Tok>| {
        if let Some(t) = cur.take() {
            words.push(t);
        }
    };

    // $ written as a plain character just before this one (\$'…' is not an ANSI-C quote).
    let mut plain_dollar = false;
    while i < n {
        let c = b[i];
        let after_dollar = std::mem::take(&mut plain_dollar);
        let escape = match mode {
            Mode::Bash => b'\\',
            Mode::Pwsh => b'`',
        };
        if matches!(c, b' ' | b'\t' | b'\r') {
            end_word(&mut cur, &mut words);
            i += 1;
        } else if matches!(c, b'\n' | b';' | b'|' | b'&' | b'(' | b')' | b'{' | b'}')
            || (c == b'`' && mode == Mode::Bash)
        {
            end_word(&mut cur, &mut words);
            if !words.is_empty() {
                out.push(std::mem::take(&mut words));
            }
            i += 1;
        } else if cur.is_none() && mode == Mode::Pwsh && text[i..].starts_with("<#") {
            i = text[i + 2..].find("#>").map_or(n, |k| i + 2 + k + 2);
        } else if c == b'#' && cur.is_none() {
            i = text[i..].find('\n').map_or(n, |k| i + k);
        } else if c == b'\'' || c == b'"' {
            // bash `$'…'` takes backslash escapes; `"…"` takes the shell's escape character.
            let ansi_c = c == b'\'' && mode == Mode::Bash && after_dollar;
            let esc = if c == b'"' || ansi_c {
                Some(escape)
            } else {
                None
            };
            let j = close_quote(text, i + 1, c, esc);
            let body = &text[i + 1..j];
            let span = Span {
                start: i,
                end: (j + 1).min(n),
            };
            if j >= n || (ansi_c && body.contains("\\'")) {
                // Unclosed, or an ANSI-C body whose `\'` another reading closes on: the shell
                // may read the rest as code, so scan it as code too.
                embedded.push((span, body.to_string()));
            } else if c == b'"'
                && (body.contains("$(") || (mode == Mode::Bash && body.contains('`')))
            {
                // A substitution inside a double-quoted word runs: scan the whole body as code.
                embedded.push((span, body.to_string()));
            }
            push(&mut cur, i, span.end, body, true);
            i = j + 1;
        } else if c == escape {
            if text[i + 1..].starts_with('\n') {
                i += 2;
            } else if text[i + 1..].starts_with("\r\n") {
                i += 3;
            } else if i + 1 < n {
                let l = char_len_at(text, i + 1);
                push(&mut cur, i, i + 1 + l, &text[i + 1..i + 1 + l], false);
                i += 1 + l;
            } else {
                i += 1;
            }
        } else {
            let l = char_len_at(text, i);
            push(&mut cur, i, i + l, &text[i..i + l], false);
            plain_dollar = c == b'$';
            i += l;
        }
    }
    end_word(&mut cur, &mut words);
    if !words.is_empty() {
        out.push(words);
    }
    (out, embedded)
}

/// The index of the quote closing a string that starts at `from`, or `text.len()` when unclosed.
fn close_quote(text: &str, from: usize, quote: u8, escape: Option<u8>) -> usize {
    let b = text.as_bytes();
    let n = text.len();
    let mut j = from;
    while j < n && b[j] != quote {
        if Some(b[j]) == escape {
            j += 1;
            if j >= n {
                break;
            }
        }
        j += char_len_at(text, j);
    }
    j.min(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One command per name of every row, plus the spellings the scan must see through.
    const DESTRUCTIVE: &[&str] = &[
        // bash delete family
        "rm x",
        "rmdir x",
        "unlink x",
        "shred x",
        // pwsh delete family
        "Remove-Item x",
        "ri x",
        "rd x",
        "del x",
        "erase x",
        "Clear-Content x",
        "[IO.Directory]::Delete('x', $true)",
        "[System.IO.Directory]::Delete('x')",
        "[IO.File]::Delete('x')",
        "[System.IO.File]::Delete('x')",
        // cmd bodies
        "cmd /c rd /s /q x",
        "cmd.exe /c del x",
        // robocopy
        "robocopy a b /MIR",
        "robocopy a b /purge",
        "robocopy a b //MIR",
        // git discard family
        "git clean -fd",
        "git clean --force",
        "git reset --hard",
        "git reset --merge",
        "git reset --keep=HEAD",
        "git checkout -- x",
        "git checkout .",
        "git checkout -f main",
        "git checkout --force main",
        "git restore x",
        "git restore --staged --worktree x",
        "git restore -SW x",
        "git switch -f main",
        "git switch --force main",
        "git switch --discard-changes main",
        "find . -name '*.tmp' -delete",
        // a heredoc body that a shell runs
        "bash <<'EOF'\nrm -rf x\nEOF",
        "sh <<EOF\ngit reset --hard\nEOF",
        "git worktree remove x",
        "git stash drop",
        "git stash clear",
        // spellings
        "REMOVE-ITEM x",
        "ri -r x",
        "rd /s x",
        "git.exe clean -fd",
        "GIT -C repo clean -f",
        "git -c core.x=1 --git-dir=.git reset --hard",
        "& 'C:\\x\\git.exe' clean -fd",
        "/usr/bin/rm -rf x",
        "sudo rm x",
        "X=1 rm x",
        "$r = Remove-Item x",
        "[void](Remove-Item x)",
        "echo hi; rm x",
        "echo hi && rm x",
        "if true; then rm x; fi",
        "<# note #> Remove-Item x",
        "find . -exec rm -rf {} +",
        "bash -c \"rm -rf x\"",
        "pwsh -NoProfile -Command \"Remove-Item x\"",
        "powershell -c 'ri x'",
        "iex 'Remove-Item x'",
        "'rm' -rf x",
        "r\\m -rf x",
        "Remove-`Item x",
        "[void] Remove-Item x",
        "Get-ChildItem x | Remove-Item",
        // command substitution inside a double-quoted word
        "echo \"$(rm -rf x)\"",
        "echo \"a `rm -rf x` b\"",
        "Write-Output \"now $(Remove-Item x)\"",
        // quotes the lenient reader may close in the wrong place
        "echo $'it\\'s'; rm -rf x",
        "echo $'a\\'b' ; rm -rf x ; echo 'c'",
        "echo 'never closed; rm -rf x",
        // every prefix of -Command, and bodies the scan cannot read
        "pwsh -co \"Remove-Item x\"",
        "pwsh -Comm 'ri x'",
        "pwsh -EncodedCommand AAAA",
        "powershell -e AAAA",
        "pwsh.exe -enc AAAA",
        "pwsh -ec AAAA",
        "pwsh /enc AAAA",
        "pwsh --EncodedCommand AAAA",
        "pwsh /Command 'Remove-Item x'",
        "pwsh \u{2013}c 'ri x'",
        // `\$'` is a literal dollar before a plain quote, not an ANSI-C string
        "echo \\$'a\\' <# ; rm -rf x ; echo '",
    ];

    const HARMLESS: &[&str] = &[
        "Get-Date",
        "ls -rf",
        "echo rm -rf x",
        "echo \"rm -rf x\"",
        "# rm -rf x",
        "git status",
        "git reset --soft HEAD~1",
        "git clean -n",
        "git clean -fn",
        "git clean -f --dry-run",
        "git restore --staged x",
        "git restore -S x",
        "git switch main",
        "find . -name '*.tmp'",
        "git checkout main",
        "git stash list",
        "robocopy a b /E",
        "Get-ChildItem x | Measure-Object",
        "format x",
        "echo hi # ; rm -rf x",
        "bash -e script.sh",
        "echo \"$(Get-Date)\"",
    ];

    #[test]
    fn embedded_table_loads() {
        assert!(table().len() >= 9, "{} rows", table().len());
    }

    #[test]
    fn every_destructive_spelling_is_caught() {
        for cmd in DESTRUCTIVE {
            assert!(raw_destructive(cmd).is_some(), "missed: {cmd}");
        }
    }

    #[test]
    fn every_table_row_has_a_destructive_case() {
        let mut seen = vec![false; table().len()];
        for cmd in DESTRUCTIVE {
            for hit in hits(table(), cmd) {
                if let Some(row) = hit.row {
                    seen[row] = true;
                }
            }
        }
        let missing: Vec<usize> = (0..seen.len()).filter(|&k| !seen[k]).collect();
        assert!(
            missing.is_empty(),
            "rows without a case in DESTRUCTIVE: {missing:?}"
        );
    }

    #[test]
    fn harmless_commands_pass() {
        for cmd in HARMLESS {
            assert_eq!(raw_destructive(cmd), None, "flagged: {cmd}");
        }
    }

    #[test]
    fn span_covers_the_destructive_simple_command() {
        let cmd = "echo hi; rm -rf x";
        assert_eq!(raw_destructive(cmd), Some(Span { start: 9, end: 17 }));
        // The first destructive command wins.
        let cmd = "rm a; git reset --hard";
        assert_eq!(raw_destructive(cmd), Some(Span { start: 0, end: 4 }));
    }

    #[test]
    fn unless_any_flag_makes_a_command_harmless() {
        let t = load(
            "[[command]]\nnames = [\"git clean\"]\nshells = [\"bash\"]\nrequires_any = []\nunless_any = [\"-n\", \"--dry-run\"]\n",
        )
        .unwrap();
        assert_eq!(hits(&t, "git clean -fd").len(), 1);
        assert_eq!(hits(&t, "git clean -nfd").len(), 0);
        assert_eq!(hits(&t, "git clean -f --dry-run").len(), 0);
    }

    #[test]
    fn load_rejects_malformed_tables() {
        let bad = [
            "",
            "command = []\n",
            "[[command]]\nnames = []\nshells = [\"bash\"]\nrequires_any = []\n",
            "[[command]]\nnames = [\"rm\"]\nshells = []\nrequires_any = []\n",
            "[[command]]\nnames = [\"rm\"]\nshells = [\"zsh\"]\nrequires_any = []\n",
            "[[command]]\nnames = [\"rm\"]\nshells = [\"bash\"]\n",
            "[[command]]\nnames = [\"rm\"]\nshells = [\"bash\"]\nrequires_any = []\nextra = 1\n",
            "[[command]]\nnames = \"rm\"\nshells = [\"bash\"]\nrequires_any = []\n",
            "[[command]]\nnames = [\"\"]\nshells = [\"bash\"]\nrequires_any = []\n",
            "[[command]]\nnames = [\"rm\"]\nshells = [\"bash\"]\nrequires_any = [1]\n",
            "other = 1\n[[command]]\nnames = [\"rm\"]\nshells = [\"bash\"]\nrequires_any = []\n",
        ];
        for text in bad {
            assert!(load(text).is_err(), "accepted: {text:?}");
        }
    }

    #[test]
    fn scan_is_linear_on_hostile_input() {
        let mut cmd = "(".repeat(200 * 1024);
        cmd.push_str("rm -rf x");
        let start = std::time::Instant::now();
        assert!(raw_destructive(&cmd).is_some());
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
    }
}
