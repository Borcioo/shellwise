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

/// `--hard` also matches git's abbreviation `--har` (git accepts any unambiguous prefix).
fn requires_matches(entry: &str, word: &str, git: bool) -> bool {
    if flag_matches(entry, word) {
        return true;
    }
    if git && entry.len() > 2 && entry.starts_with("--") && word.starts_with("--") {
        let name = word.split('=').next().unwrap_or(word);
        return name.len() > 2 && entry.starts_with(name);
    }
    false
}

/// The words `unless_any` may look at: before `--`, without the values of options that take one
/// (`git clean -e -n` excludes the pattern `-n`, it is not a dry run).
fn option_words(args: &[Tok]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut k = 0;
    while k < args.len() {
        let v = args[k].value.as_str();
        if v == "--" {
            break;
        }
        if VALUE_OPTS.contains(&v) {
            k += 2;
            continue;
        }
        out.push(v);
        k += 1;
    }
    out
}

const VALUE_OPTS: [&str; 4] = ["-e", "--exclude", "-s", "--source"];

fn hits_at(table: &[Entry], cmd: &str, depth: usize) -> Vec<Hit> {
    if depth > MAX_DEPTH {
        // Too deep to read: nothing proves it harmless.
        return vec![Hit {
            row: None,
            span: Span {
                start: 0,
                end: cmd.len(),
            },
        }];
    }
    let mut out = Vec::new();
    for mode in [Mode::Bash, Mode::Pwsh] {
        let seg = segments(cmd, mode);
        for (k, s) in seg.segs.iter().enumerate() {
            let words = normalize(&s.words);
            segment_hits(table, &words, depth, false, &mut out);
            for start in wrapper_suffixes(&s.words) {
                segment_hits(table, &normalize(&s.words[start..]), depth, false, &mut out);
            }
            // `iex('…')`, `[scriptblock]::Create('…')`: the argument is the next segment.
            if words.len() == 1
                && EVAL_NAMES.contains(&base_name(&words[0].value).as_str())
                && let Some(next) = seg.segs.get(k + 1)
            {
                let span = seg_span(&words);
                for h in hits_at(table, &join(&next.words), depth + 1) {
                    out.push(Hit { row: h.row, span });
                }
            }
            if s.piped
                && let Some(next) = seg.segs.get(k + 1)
                && !words.is_empty()
                && reads_stdin_as_code(&normalize(&next.words))
            {
                let span = seg_span(&words);
                for h in hits_at(table, &piped_text(&words), depth + 1) {
                    out.push(Hit { row: h.row, span });
                }
            }
        }
        for (span, body) in seg.embedded {
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

fn seg_span(words: &[Tok]) -> Span {
    Span {
        start: words[0].span.start,
        end: words[words.len() - 1].span.end,
    }
}

fn join(words: &[Tok]) -> String {
    words
        .iter()
        .map(|w| w.value.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn segment_hits(table: &[Entry], words: &[Tok], depth: usize, in_exec: bool, out: &mut Vec<Hit>) {
    if words.is_empty() {
        return;
    }
    let span = seg_span(words);
    let name = base_name(&words[0].value);
    // `(Get-Item x).Delete()`, `$d.Delete($true)`: a .NET delete on an object.
    if name.ends_with(".delete") && (name.starts_with('.') || name.starts_with('$')) {
        out.push(Hit { row: None, span });
        return;
    }
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
    if !in_exec && name == "find" {
        // Each clause runs its own command; a `find` inside a clause is not expanded again.
        for (k, w) in words.iter().enumerate() {
            if FIND_EXEC.contains(&w.value.as_str()) {
                let rest = &words[k + 1..];
                let end = rest
                    .iter()
                    .position(|w| matches!(w.value.as_str(), ";" | "+" | "\\;"))
                    .unwrap_or(rest.len());
                segment_hits(table, &normalize(&rest[..end]), depth, true, out);
            }
        }
    }
    for (row, entry) in table.iter().enumerate() {
        for name_words in &entry.names {
            let Some(end) = match_name(name_words, &name, words) else {
                continue;
            };
            let args = &words[end..];
            let git = name_words[0] == "git";
            let required = entry.requires_any.is_empty()
                || entry
                    .requires_any
                    .iter()
                    .any(|f| args.iter().any(|a| requires_matches(f, &a.value, git)));
            let opts = option_words(args);
            let cleared = entry
                .unless_any
                .iter()
                .any(|f| opts.iter().any(|a| flag_matches(f, a)));
            if required && !cleared {
                out.push(Hit {
                    row: Some(row),
                    span,
                });
            }
        }
    }
}

const FIND_EXEC: [&str; 4] = ["-exec", "-execdir", "-ok", "-okdir"];
const PREFIX_WORDS: [&str; 10] = [
    "&", "!", ".", "then", "do", "else", "elif", "if", "while", "until",
];
/// Commands that run the rest of their words as a command: (name, options that take a value,
/// positional words before the command).
const WRAPPERS: [(&str, &[&str], usize); 13] = [
    (
        "sudo",
        &[
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-D",
            "-r",
            "-t",
            "-U",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--chdir",
            "--role",
            "--type",
            "--other-user",
            "--close-from",
        ],
        0,
    ),
    ("doas", &["-u", "-C"], 0),
    ("env", &["-u", "-C", "-S", "--unset", "--chdir"], 0),
    ("timeout", &["-s", "-k", "--signal", "--kill-after"], 1),
    ("nice", &["-n", "--adjustment"], 0),
    ("ionice", &["-c", "-n", "-p"], 0),
    ("time", &["-f", "-o", "--format", "--output"], 0),
    (
        "xargs",
        &[
            "-n",
            "-I",
            "-L",
            "-P",
            "-s",
            "-d",
            "-E",
            "-a",
            "--max-args",
            "--max-procs",
            "--delimiter",
            "--arg-file",
            "--replace",
            "--max-lines",
            "--eof",
        ],
        0,
    ),
    ("nohup", &[], 0),
    ("command", &[], 0),
    ("exec", &["-a"], 0),
    (
        "stdbuf",
        &["-i", "-o", "-e", "--input", "--output", "--error"],
        0,
    ),
    (
        "wsl",
        &[
            "-d",
            "--distribution",
            "-u",
            "--user",
            "--cd",
            "--shell-type",
        ],
        0,
    ),
];
/// Commands that run their argument text as code.
const EVAL_NAMES: [&str; 5] = [
    "eval",
    "invoke-expression",
    "iex",
    "[scriptblock]::create",
    "[system.management.automation.scriptblock]::create",
];
const BASH_SHELLS: [&str; 5] = ["bash", "sh", "zsh", "dash", "ksh"];
const ECHO_NAMES: [&str; 4] = ["echo", "printf", "write-output", "write-host"];
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

/// The body of `bash -c …`, `pwsh -Command …`, `cmd /c …`, `eval …`, `Invoke-Expression …`,
/// `[scriptblock]::Create(…)` or `Start-Process`, if any.
fn nested_body(name: &str, words: &[Tok]) -> Option<Nested> {
    match name {
        _ if EVAL_NAMES.contains(&name) => Some(Nested::Body(join(&words[1..]))),
        "start-process" | "start" | "saps" => start_process_body(words).map(Nested::Body),
        "cmd" => {
            for (k, w) in words.iter().enumerate().skip(1) {
                let v = w.value.to_ascii_lowercase();
                let glued = ["/c", "/k", "//c", "//k"]
                    .iter()
                    .find_map(|p| v.strip_prefix(p).map(|rest| (p.len(), rest.is_empty())));
                if let Some((len, alone)) = glued {
                    // `cmd /c"del x"` glues the body to the switch.
                    let first = if alone {
                        String::new()
                    } else {
                        w.value[len..].to_string()
                    };
                    let body = format!("{first} {}", join(&words[k + 1..]));
                    // cmd switches may touch the name: `rd/s/q x`.
                    return Some(Nested::Body(body.replace('/', " /")));
                }
            }
            None
        }
        _ if BASH_SHELLS.contains(&name) || name == "pwsh" || name == "powershell" => {
            let (k, flag) = words[1..]
                .iter()
                .enumerate()
                .find_map(|(k, w)| nested_flag(name, &w.value).map(|f| (k + 1, f)))?;
            Some(match flag {
                Flag::Encoded => Nested::Opaque,
                Flag::Command => {
                    let rest = &words[k + 1..];
                    let rest = if rest.first().is_some_and(|w| w.value == "--") {
                        &rest[1..]
                    } else {
                        rest
                    };
                    Nested::Body(join(rest))
                }
            })
        }
        _ => None,
    }
}

/// `Start-Process -FilePath git -ArgumentList 'clean','-fd'` as the command `git clean -fd`.
fn start_process_body(words: &[Tok]) -> Option<String> {
    const VALUE_PARAMS: [&str; 7] = [
        "workingdirectory",
        "verb",
        "windowstyle",
        "redirectstandardinput",
        "redirectstandardoutput",
        "redirectstandarderror",
        "credential",
    ];
    let (mut file, mut args, mut positional) = (None, None, Vec::new());
    let mut k = 1;
    while k < words.len() {
        let v = words[k].value.to_ascii_lowercase();
        match v
            .strip_prefix('-')
            .filter(|p| !p.is_empty() && !words[k].quoted)
        {
            Some(p) if p.starts_with('f') && "filepath".starts_with(p) => {
                file = words.get(k + 1);
                k += 2;
            }
            Some(p) if p.len() >= 2 && "argumentlist".starts_with(p) => {
                args = words.get(k + 1);
                k += 2;
            }
            Some(p) if p.len() >= 2 && VALUE_PARAMS.iter().any(|n| n.starts_with(p)) => k += 2,
            Some(_) => k += 1,
            None => {
                positional.push(&words[k]);
                k += 1;
            }
        }
    }
    let file = file.or(positional.first().copied())?;
    let args = args.or(positional.get(1).copied());
    Some(format!(
        "{} {}",
        file.value,
        args.map_or(String::new(), |a| a.value.replace(',', " "))
    ))
}

/// The segment after a pipe runs its stdin as code: a shell with no command argument, or
/// `pwsh -Command -`.
fn reads_stdin_as_code(words: &[Tok]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    let name = base_name(&first.value);
    if !(BASH_SHELLS.contains(&name.as_str())
        || matches!(name.as_str(), "pwsh" | "powershell" | "cmd"))
    {
        return false;
    }
    match nested_body(&name, words) {
        None => true,
        Some(Nested::Body(b)) => b.trim() == "-",
        Some(Nested::Opaque) => false,
    }
}

/// The text a segment writes into a pipe: the words after `echo`/`printf`, or the whole segment.
fn piped_text(words: &[Tok]) -> String {
    if ECHO_NAMES.contains(&base_name(&words[0].value).as_str()) {
        join(&words[1..])
    } else {
        join(words)
    }
}

fn nested_flag(shell: &str, v: &str) -> Option<Flag> {
    let v = v.to_ascii_lowercase();
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
    // bash -c, -lc, -cx: a cluster of short options holding c.
    let rest = v.strip_prefix('-').filter(|r| !r.is_empty())?;
    (rest.bytes().all(|b| b.is_ascii_lowercase()) && rest.contains('c')).then_some(Flag::Command)
}

/// The command name without a directory or an executable extension, lowercased.
fn base_name(word: &str) -> String {
    let lower = word.to_lowercase();
    let name = lower.rsplit(['\\', '/']).next().unwrap_or("");
    [".exe", ".cmd", ".bat", ".com"]
        .iter()
        .find_map(|ext| name.strip_suffix(ext))
        .unwrap_or(name)
        .to_string()
}

/// The index after the matched name in `words`, or `None`. git global options are skipped.
fn match_name(name_words: &[String], base: &str, words: &[Tok]) -> Option<usize> {
    if base != name_words[0] {
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

/// The simple command without the words that only prefix it: wrappers and their options
/// (`sudo -u root`, `timeout 5`, `wsl -e`), assignments, casts, leading redirects.
fn normalize(words: &[Tok]) -> Vec<Tok> {
    let mut k = 0;
    let mut first: Option<Tok> = None;
    while k < words.len() {
        let w = &words[k];
        if w.quoted {
            break;
        }
        let v = w.value.as_str();
        let lower = v.to_lowercase();
        if PREFIX_WORDS.contains(&lower.as_str()) || is_assignment(v) {
            k += 1;
        } else if let Some((_, opts, positional)) =
            WRAPPERS.iter().find(|(n, _, _)| *n == base_name(v))
        {
            k += 1;
            // A quoted option is still an option (`--split-string='rm x'`, `'-u' root`).
            while k < words.len() && words[k].value.starts_with('-') {
                let o = words[k].value.as_str();
                if o == "--" {
                    k += 1;
                    break;
                }
                if base_name(v) == "env"
                    && let Some(body) = split_string(o, words.get(k + 1))
                {
                    // `env -S 'cmd args'`: the value is the command.
                    let span = words[k].span;
                    let mut out: Vec<Tok> = body
                        .split_whitespace()
                        .map(|s| Tok {
                            value: s.to_string(),
                            quoted: false,
                            span,
                        })
                        .collect();
                    let skip = if o.contains('=') || o.len() > 2 && !o.starts_with("--") {
                        1
                    } else {
                        2
                    };
                    out.extend(words[(k + skip).min(words.len())..].iter().cloned());
                    return out;
                }
                // `--opt=value` carries its value; a known option takes the next word.
                k += if !o.contains('=') && opts.contains(&o) {
                    2
                } else {
                    1
                };
            }
            k += positional;
        } else if is_redirect(v) {
            // `2>/dev/null rm`; a bare `2>` takes the next word as its target.
            k += if v
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .trim_start_matches(['<', '>', '&'])
                .is_empty()
            {
                2
            } else {
                1
            };
        } else if is_ps_var(v)
            && words
                .get(k + 1)
                .is_some_and(|n| n.value == "=" || n.value == "+=")
        {
            k += 2;
        } else if let Some(rest) = ps_glued_assignment(v) {
            // `$r=Remove-Item x`: the command starts inside the word.
            if rest.is_empty() {
                k += 1;
            } else {
                let mut t = w.clone();
                t.value = rest.to_string();
                first = Some(t);
                k += 1;
                break;
            }
        } else if v.starts_with('[') && v.ends_with(']') && !v.contains("::") {
            k += 1;
        } else {
            break;
        }
    }
    let mut out: Vec<Tok> = first.into_iter().collect();
    out.extend(words[k.min(words.len())..].iter().cloned());
    out
}

/// The value of `env -S`/`--split-string`, glued or in the next word.
fn split_string(o: &str, next: Option<&Tok>) -> Option<String> {
    if o == "-S" || o == "--split-string" {
        return next.map(|w| w.value.clone());
    }
    if let Some(v) = o.strip_prefix("--split-string=") {
        return Some(v.to_string());
    }
    o.strip_prefix("-S")
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// After a wrapper, every later word that is not an option may start the command: an option the
/// wrapper table does not know may take a value (`sudo -X foo rm`).
fn wrapper_suffixes(words: &[Tok]) -> Vec<usize> {
    let Some(w) = words
        .iter()
        .take(4)
        .position(|t| !t.quoted && WRAPPERS.iter().any(|(n, _, _)| *n == base_name(&t.value)))
    else {
        return Vec::new();
    };
    (w + 1..words.len().min(w + 9))
        .filter(|&k| !words[k].value.starts_with('-'))
        .collect()
}

/// `2>/dev/null`, `>out`, `2>&1`, `<in`
fn is_redirect(v: &str) -> bool {
    let rest = v.trim_start_matches(|c: char| c.is_ascii_digit());
    rest.starts_with('>') || rest.starts_with('<') || rest.starts_with("&>")
}

/// The text after `=` in `$name=…`, if the word is such an assignment.
fn ps_glued_assignment(v: &str) -> Option<&str> {
    let (name, rest) = v.split_once('=')?;
    is_ps_var(name).then_some(rest)
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

struct Segment {
    words: Vec<Tok>,
    /// Ended by a pipe (`|`, `|&`), so its output is the next segment's stdin.
    piped: bool,
}

struct Segments {
    segs: Vec<Segment>,
    /// Text that may run as code (a substitution in `"…"`, an unclosed quote, a heredoc or
    /// here-string a shell reads), with its span, for the caller to scan as a nested command.
    embedded: Vec<(Span, String)>,
}

fn is_single_quote(mode: Mode, c: char) -> bool {
    c == '\'' || (mode == Mode::Pwsh && matches!(c, '\u{2018}'..='\u{201b}'))
}

fn is_double_quote(mode: Mode, c: char) -> bool {
    c == '"' || (mode == Mode::Pwsh && matches!(c, '\u{201c}'..='\u{201e}'))
}

fn is_blank(mode: Mode, c: char) -> bool {
    match c {
        ' ' | '\t' => true,
        '\r' => mode == Mode::Bash,
        '\u{a0}' | '\u{2000}'..='\u{200a}' | '\u{3000}' | '\u{c}' => mode == Mode::Pwsh,
        _ => false,
    }
}

fn is_separator(mode: Mode, c: char) -> bool {
    match c {
        '\n' | ';' | '|' | '&' | '(' | ')' | '{' | '}' => true,
        '`' => mode == Mode::Bash,
        '\r' => mode == Mode::Pwsh,
        _ => false,
    }
}

/// The byte index of the character closing a string that starts at `from`, or `text.len()` when
/// unclosed; `escape` skips the character after it.
fn close_quote(
    text: &str,
    from: usize,
    close: impl Fn(char) -> bool,
    escape: Option<char>,
) -> usize {
    let mut it = text[from..].char_indices();
    while let Some((k, c)) = it.next() {
        if Some(c) == escape {
            if it.next().is_none() {
                break;
            }
        } else if close(c) {
            return from + k;
        }
    }
    text.len()
}

fn char_at(text: &str, i: usize) -> char {
    text[i..].chars().next().unwrap_or('\0')
}

/// A pending bash heredoc: its delimiter, `<<-` (strip leading tabs), and whether the delimiter
/// was quoted (the body is then never expanded).
struct Heredoc {
    delim: String,
    strip_tabs: bool,
    quoted: bool,
}

/// Simple commands of `text` as words: split at `; | & ( ) { }` and newlines, quotes joined into
/// their word, comments dropped, heredoc and here-string bodies kept out of the code. Lenient: an
/// unclosed quote or comment runs to the end.
fn segments(text: &str, mode: Mode) -> Segments {
    let n = text.len();
    let mut out = Segments {
        segs: Vec::new(),
        embedded: Vec::new(),
    };
    let mut words: Vec<Tok> = Vec::new();
    let mut cur: Option<Tok> = None;
    let mut heredocs: Vec<Heredoc> = Vec::new();
    let escape = match mode {
        Mode::Bash => '\\',
        Mode::Pwsh => '`',
    };
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
    fn end_word(cur: &mut Option<Tok>, words: &mut Vec<Tok>) {
        if let Some(t) = cur.take() {
            words.push(t);
        }
    }
    fn end_segment(out: &mut Segments, cur: &mut Option<Tok>, words: &mut Vec<Tok>, piped: bool) {
        end_word(cur, words);
        if !words.is_empty() {
            out.segs.push(Segment {
                words: std::mem::take(words),
                piped,
            });
        }
    }
    // Whether the segment so far runs a shell, wrappers (sudo bash) included.
    let segment_is_shell = |words: &[Tok], cur: &Option<Tok>| {
        let mut all = words.to_vec();
        all.extend(cur.iter().cloned());
        normalize(&all).first().is_some_and(|w| {
            let n = base_name(&w.value);
            BASH_SHELLS.contains(&n.as_str()) || matches!(n.as_str(), "pwsh" | "powershell" | "cmd")
        })
    };

    // `$` written as a plain character just before this one (`\$'…'` is not an ANSI-C quote).
    let mut plain_dollar = false;
    while i < n {
        let c = char_at(text, i);
        let cl = c.len_utf8();
        let after_dollar = std::mem::take(&mut plain_dollar);
        if c == '\n' && mode == Mode::Bash && !heredocs.is_empty() {
            // The heredoc bodies start on the next line and end at their delimiter lines.
            let shell = segment_is_shell(&words, &cur);
            let mut j = i + 1;
            for h in std::mem::take(&mut heredocs) {
                let body_start = j;
                let mut body_end = n;
                let mut next = n;
                let mut found = false;
                while j < n {
                    let line_end = text[j..].find('\n').map_or(n, |k| j + k);
                    let mut line = &text[j..line_end];
                    if h.strip_tabs {
                        line = line.trim_start_matches('\t');
                    }
                    if line.trim_end_matches('\r') == h.delim {
                        found = true;
                        body_end = j;
                        next = (line_end + 1).min(n);
                        j = next;
                        break;
                    }
                    j = (line_end + 1).min(n);
                }
                let body = &text[body_start..body_end.max(body_start)];
                let expands = !h.quoted && (body.contains("$(") || body.contains('`'));
                // No delimiter line: maybe not a heredoc at all (`1<<2`), so the rest is code.
                if shell || expands || !found {
                    let span = Span {
                        start: body_start,
                        end: body_end.max(body_start),
                    };
                    out.embedded.push((span, body.to_string()));
                }
                j = next.max(j);
            }
            end_segment(&mut out, &mut cur, &mut words, false);
            i = j;
        } else if mode == Mode::Bash && text[i..].starts_with("<<<") {
            // A here-string: its word is the stdin of the command.
            let shell = segment_is_shell(&words, &cur);
            let mut j = i + 3;
            while j < n && matches!(char_at(text, j), ' ' | '\t') {
                j += 1;
            }
            let q = char_at(text, j);
            let (body, end) = if q == '\'' || q == '"' {
                let k = close_quote(text, j + 1, |c| c == q, (q == '"').then_some('\\'));
                (&text[(j + 1).min(n)..k], (k + 1).min(n))
            } else {
                let k = text[j..]
                    .find(|c: char| is_blank(mode, c) || is_separator(mode, c))
                    .map_or(n, |k| j + k);
                (&text[j..k], k)
            };
            if shell {
                out.embedded
                    .push((Span { start: i, end }, body.to_string()));
            }
            i = end;
        } else if mode == Mode::Bash && text[i..].starts_with("<<") {
            // A heredoc: read its delimiter now, its body at the end of the line.
            let mut j = i + 2;
            let strip_tabs = text[j..].starts_with('-');
            if strip_tabs {
                j += 1;
            }
            while j < n && matches!(char_at(text, j), ' ' | '\t') {
                j += 1;
            }
            let k = text[j..]
                .find(|c: char| is_blank(mode, c) || is_separator(mode, c) || c == '<' || c == '>')
                .map_or(n, |k| j + k);
            let raw = &text[j..k];
            let delim: String = raw
                .chars()
                .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            if !delim.is_empty() {
                heredocs.push(Heredoc {
                    delim,
                    strip_tabs,
                    quoted: raw.len()
                        != raw
                            .chars()
                            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                            .count(),
                });
            }
            i = k;
        } else if mode == Mode::Pwsh
            && cur.is_none()
            && (text[i..].starts_with("@'") || text[i..].starts_with("@\""))
            && text[i + 2..]
                .trim_start_matches([' ', '\t', '\r'])
                .starts_with('\n')
        {
            // A here-string: the body runs to a line that starts with the closing quote and `@`.
            let q = char_at(text, i + 1);
            let body_start = i + 2 + text[i + 2..].find('\n').map_or(0, |k| k + 1);
            let close = format!("\n{q}@");
            let (body, end, closed) = match text[body_start.saturating_sub(1)..].find(&close) {
                Some(k) => {
                    let at = body_start.saturating_sub(1) + k;
                    (&text[body_start.min(at)..at], at + close.len(), true)
                }
                None => (&text[body_start.min(n)..], n, false),
            };
            let span = Span { start: i, end };
            // Unclosed: scan the rest as code; `@"…"@` expands `$(…)`.
            if !closed || (q == '"' && body.contains("$(")) {
                out.embedded.push((span, body.to_string()));
            }
            push(&mut cur, i, end, body, true);
            i = end;
        } else if is_blank(mode, c) {
            end_word(&mut cur, &mut words);
            i += cl;
        } else if is_separator(mode, c) {
            let pipe = c == '|' && !text[i + 1..].starts_with('|') && !text[..i].ends_with('|');
            end_segment(&mut out, &mut cur, &mut words, pipe);
            i += cl;
        } else if cur.is_none() && mode == Mode::Pwsh && text[i..].starts_with("<#") {
            i = text[i + 2..].find("#>").map_or(n, |k| i + 2 + k + 2);
        } else if c == '#' && cur.is_none() {
            i = text[i..].find('\n').map_or(n, |k| i + k);
        } else if is_single_quote(mode, c) || is_double_quote(mode, c) {
            let double = is_double_quote(mode, c);
            // bash `$'…'` takes backslash escapes; `"…"` takes the shell's escape character.
            let ansi_c = c == '\'' && mode == Mode::Bash && after_dollar;
            let esc = (double || ansi_c).then_some(escape);
            let j = if double {
                close_quote(text, i + cl, |x| is_double_quote(mode, x), esc)
            } else {
                close_quote(text, i + cl, |x| is_single_quote(mode, x), esc)
            };
            let body = &text[i + cl..j];
            let end = if j < n {
                j + char_at(text, j).len_utf8()
            } else {
                n
            };
            let span = Span { start: i, end };
            if j >= n || (ansi_c && body.contains("\\'")) {
                // Unclosed, or an ANSI-C body whose `\'` another reading closes on: the shell
                // may read the rest as code, so scan it as code too.
                out.embedded.push((span, body.to_string()));
            } else if double && (body.contains("$(") || (mode == Mode::Bash && body.contains('`')))
            {
                // A substitution inside a double-quoted word runs: scan the whole body as code.
                out.embedded.push((span, body.to_string()));
            }
            push(&mut cur, i, end, body, true);
            i = end;
        } else if c == escape {
            if text[i + 1..].starts_with('\n') {
                i += 2;
            } else if text[i + 1..].starts_with("\r\n") {
                i += 3;
            } else if i + 1 < n {
                let l = char_at(text, i + 1).len_utf8();
                push(&mut cur, i, i + 1 + l, &text[i + 1..i + 1 + l], false);
                i += 1 + l;
            } else {
                i += 1;
            }
        } else {
            push(&mut cur, i, i + cl, &text[i..i + cl], false);
            plain_dollar = c == '$';
            i += cl;
        }
    }
    end_segment(&mut out, &mut cur, &mut words, false);
    out
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
        // I1: nesting at and past the depth limit
        "pwsh -c pwsh -c pwsh -c pwsh -c Remove-Item x",
        "pwsh -c pwsh -c pwsh -c pwsh -c pwsh -c Remove-Item x",
        // I3: heredoc bodies are literal and the command resumes after the delimiter line
        "cat <<'EOF'\nit's done\nEOF\nrm -rf x\necho 'ok'",
        "git commit -F - <<'EOF'\nDon't keep the cache\nEOF\nrm -rf build && echo 'done'",
        "cat <<-EOF\n\tit's\n\tEOF\nrm -rf x\necho 'ok'",
        "cat <<EOF\n$(rm -rf x)\nEOF",
        "cat <<EOF\nit's $(rm -rf x)\nEOF\necho 'z'",
        // a pwsh-only quote hides the line from the pwsh reading; the bash reading must see it
        "echo \u{2018}a; sudo bash <<'EOF'\nrm -rf x\nEOF\necho \u{2019}",
        "echo \u{2018}a; echo $((1<<2))\nrm -rf x\necho \u{2019}",
        // wrapper options: long names, glued values, a nested -S body, unknown options
        "sudo --user root rm -rf x",
        "timeout --signal KILL 5 rm -rf x",
        "env -S 'rm -rf x'",
        "env --split-string='rm -rf x'",
        "sudo -X foo rm -rf x",
        // I3: PowerShell here-strings, CR-only lines, Unicode blanks and quotes
        "@'\na'\n'@; Remove-Item x; echo '\n'",
        "@\"\na\"\n\"@; Remove-Item x; echo \"\n\"",
        "echo hi\rRemove-Item x",
        "Remove-Item\u{a0}x",
        "echo\u{2003}hi;\u{3000}Remove-Item x",
        "echo hi\u{c}; Remove-Item\u{c}x",
        "echo 'a\u{2019}; Remove-Item x; echo \u{2018}b'",
        "echo \"a\u{201d}; Remove-Item x; echo \u{201c}b\"",
        // I4: wrappers, shells and forms
        "eval 'rm -rf x'",
        "eval \"rm -rf x\"",
        "echo 'rm -rf x' | bash",
        "bash <<< 'rm -rf x'",
        "'Remove-Item x' | pwsh -Command -",
        "wsl rm -rf x",
        "wsl -e rm -rf x",
        "wsl -d Ubuntu -u root -- rm -rf x",
        "wsl bash -c 'rm -rf x'",
        "zsh -c 'rm -rf x'",
        "dash -c 'rm -rf x'",
        "env -i rm -rf x",
        "sudo -u root rm -rf x",
        "timeout 5 rm -rf x",
        "nice -n 5 rm -rf x",
        "time -p rm -rf x",
        "find . -name '*.o' | xargs -n 1 rm",
        "Start-Process -FilePath git -ArgumentList 'clean','-fd'",
        "Start-Process cmd -ArgumentList '/c','rd /s /q x'",
        "2>/dev/null rm -rf x",
        "bash \"-c\" \"rm -rf x\"",
        "pwsh '-c' 'Remove-Item x'",
        "bash -c -- 'rm -rf x'",
        "bash -cx 'rm -rf x'",
        "git.cmd reset --hard",
        ". Remove-Item x",
        "$r=Remove-Item x",
        "& ([scriptblock]::Create('Remove-Item x'))",
        // M1: abbreviated git long options
        "git reset --har",
        "git clean --forc -d",
        "git clean -fd -e -n",
        "git clean -fd -- -n",
        // M5: cmd switches glued to the name or the quote
        "cmd /c rd/s/q x",
        "cmd /c\"del x\"",
        // M8: Clear-Content alias and the .Delete() method form
        "clc x",
        "(Get-Item x).Delete()",
        "(Get-Item x).Delete($true)",
        "$d.Delete()",
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
        // nesting below the limit stays harmless
        "pwsh -c pwsh -c pwsh -c Get-Date",
        // a here-string body is text (a heredoc body still over-matches in the pwsh reading)
        "$m = @'\nRemove-Item x\n'@",
        "echo 'rm -rf x' | grep rm",
        "eval echo hi",
        "Start-Process -FilePath notepad -ArgumentList 'a.txt'",
        "git branch --delete topic",
    ];

    #[test]
    fn embedded_table_loads() {
        assert!(table().len() >= 9, "{} rows", table().len());
    }

    #[test]
    fn every_destructive_spelling_is_caught() {
        let missed: Vec<&&str> = DESTRUCTIVE
            .iter()
            .filter(|cmd| raw_destructive(cmd).is_none())
            .collect();
        assert!(missed.is_empty(), "missed: {missed:?}");
    }

    #[test]
    fn find_exec_chains_stay_linear() {
        let cmd = format!("find . {}-exec rm -rf x", "-exec find . ".repeat(22));
        let start = std::time::Instant::now();
        assert!(raw_destructive(&cmd).is_some());
        assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
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
        let flagged: Vec<&&str> = HARMLESS
            .iter()
            .filter(|cmd| raw_destructive(cmd).is_some())
            .collect();
        assert!(flagged.is_empty(), "flagged: {flagged:?}");
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
