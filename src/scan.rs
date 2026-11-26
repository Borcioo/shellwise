//! The raw-text destructive scan used on every fail-closed path. It needs no parser: it splits the
//! text into simple commands leniently, once in the bash and once in the PowerShell reading, and
//! matches the names and flags of `data/destructive.toml` from every shell. On an incomplete
//! analysis or a parse error a hit on a table row, or a .NET `Delete()` call, makes the verdict
//! `danger` and names the command; a region the scan cannot read does not.

use std::borrow::Cow;
use std::cell::Cell;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::level::Span;

const TABLE_TEXT: &str = include_str!("../data/destructive.toml");
const SHELLS: [&str; 3] = ["bash", "pwsh", "cmd"];
/// Nested bodies (`bash -c "…"` inside `pwsh -c "…"`, `env -S '…'`) and wrappers (`sudo`,
/// `timeout 5`) each cost one level; past this the scan stops reading the command.
const MAX_DEPTH: usize = 4;
/// The scan's work for one input, in steps (a character segmented, a word examined): this many
/// per input byte, plus a base. Once it is spent the scan stops, with the hits found so far.
const BUDGET_PER_BYTE: usize = 16;
const BUDGET_BASE: usize = 1 << 18;
/// The cost of one word-level step (a walk step, a reading tried), in byte steps.
const WORD: usize = 8;

/// What the scan does with a reading of a producer piped into a shell whose text it cannot read
/// (`root printf …` in `sudo -u root printf '…' | bash`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unreadable {
    /// Pass over it and read the later readings: the fail-closed paths take the stricter
    /// reading, at the cost of reading static text that is only an argument of another command
    /// (`sudo cat f printf '…' | bash`) as fed.
    PassOver,
    /// Stop reading the producer: on a command that parses, that cost would be a false
    /// `opaque-destructive` warn.
    Stop,
}

/// The work left for one scan. Every loop over the input spends from it, so on hostile nesting
/// the scan stops instead of hanging or overflowing the stack.
struct Budget {
    left: Cell<usize>,
    spent: Cell<bool>,
    unreadable: Unreadable,
}

impl Budget {
    fn for_input(len: usize, unreadable: Unreadable) -> Budget {
        Budget {
            left: Cell::new(
                len.saturating_mul(BUDGET_PER_BYTE)
                    .saturating_add(BUDGET_BASE),
            ),
            spent: Cell::new(false),
            unreadable,
        }
    }

    /// Take `n` steps; false, from now on, once fewer remain.
    fn spend(&self, n: usize) -> bool {
        match self.left.get().checked_sub(n) {
            Some(left) if !self.spent.get() => {
                self.left.set(left);
                true
            }
            _ => {
                self.spent.set(true);
                false
            }
        }
    }

    fn spent(&self) -> bool {
        self.spent.get()
    }
}

/// One `[[command]]` row of `data/destructive.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Each name split into lowercase words (`git reset` -> `["git", "reset"]`).
    pub names: Vec<Vec<String>>,
    pub shells: Vec<String>,
    pub requires_any: Vec<String>,
    pub unless_any: Vec<String>,
}

/// What a hit stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The index of the table row that matched.
    Row(usize),
    /// A .NET `Delete()` call on an object (`(Get-Item x).Delete()`), which no row names.
    DeleteMethod,
}

/// A match, and the span of the simple command it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub kind: Kind,
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

/// Every simple command of `cmd` that a row of `table` names, as a fail-closed path reads it.
pub fn hits(table: &[Entry], cmd: &str) -> Vec<Hit> {
    let b = Budget::for_input(cmd.len(), Unreadable::PassOver);
    hits_at(table, cmd, 0, &b)
}

/// The hits of the embedded table in code the guard does not read in a command that parses
/// (`opaque-destructive`): a producer piped into a shell is read only up to its first reading
/// the scan cannot read.
pub fn parsed_hits(cmd: &str) -> Vec<Hit> {
    let b = Budget::for_input(cmd.len(), Unreadable::Stop);
    hits_at(table(), cmd, 0, &b)
}

/// The span of the first simple command in `cmd` that a row of the destructive table names, or
/// that calls a .NET `Delete()`. A region the scan cannot read (a spent budget, nesting past
/// `MAX_DEPTH`, a pipe into a shell) is neither.
pub fn destructive_row(cmd: &str) -> Option<Span> {
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

fn hits_at(table: &[Entry], cmd: &str, depth: usize, b: &Budget) -> Vec<Hit> {
    if depth > MAX_DEPTH {
        // Too deep to read.
        return Vec::new();
    }
    // Two readings of the text.
    if !b.spend(cmd.len().saturating_mul(2)) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for mode in [Mode::Bash, Mode::Pwsh] {
        let seg = segments(cmd, mode, b);
        for (k, s) in seg.segs.iter().enumerate() {
            if b.spent() {
                break;
            }
            // Every reading's command is what may print into a pipe.
            let mut producers: Vec<Cow<[Tok]>> = Vec::new();
            let mut eval_alone = false;
            each_reading(&s.words, depth, b, |start, w| {
                let words = &s.words[start..];
                scan_walk(table, words, w, false, b, &mut out);
                let cmd = command_words(words, w, b);
                eval_alone |=
                    cmd.len() == 1 && EVAL_NAMES.contains(&base_name(&cmd[0].value).as_str());
                producers.push(cmd);
                false
            });
            // `iex('…')`, `[scriptblock]::Create('…')`: the argument is the next segment.
            if eval_alone
                && let Some(next) = seg.segs.get(k + 1)
                && b.spend(text_len(&next.words))
            {
                let span = seg_span(&s.words);
                for h in hits_at(table, &join(&next.words), depth + 1, b) {
                    out.push(Hit { kind: h.kind, span });
                }
            }
            // `… | bash`, `… | iex`: what the segment prints runs as code.
            if s.piped
                && let Some(next) = seg.segs.get(k + 1)
                && reads_stdin_as_code(&next.words, depth, b)
            {
                let span = seg_span(&s.words);
                feed(table, &s.words, &producers, span, depth, b, &mut out);
            }
            // `bash <(…)`, `. <(…)`: the substitution's output is a file the command runs.
            if s.procsub
                && let Some(next) = seg.segs.get(k + 1)
            {
                // The `<` before `(` reads as a redirect, so the command is found as usual.
                if runs_file_as_code(&s.words, depth, b) {
                    let mut producers: Vec<Cow<[Tok]>> = Vec::new();
                    each_reading(&next.words, depth, b, |start, w| {
                        producers.push(command_words(&next.words[start..], w, b));
                        false
                    });
                    let span = seg_span(&s.words);
                    feed(table, &next.words, &producers, span, depth, b, &mut out);
                }
            }
        }
        for (span, body) in seg.embedded {
            for h in hits_at(table, &body, depth + 1, b) {
                out.push(Hit { kind: h.kind, span });
            }
        }
    }
    // Both readings usually find the same command.
    out.sort_by_key(|h| (h.span.start, h.span.end, h.kind));
    out.dedup();
    out
}

/// Scan what the producer prints as the code an interpreter runs, in every reading of where its
/// command starts. A reading whose text is not static (a file, a download, a variable, a command
/// the scan cannot read) is passed over or ends the producer, as `b.unreadable` says: passed
/// over, `sudo -u root printf '…' | bash` still scans the `printf` reading.
///
/// `producers` are the readings of `words`: each one's words after its first are a tail of
/// `words`, so what those tails hold is read once, and a rejected reading costs nothing more.
fn feed(
    table: &[Entry],
    words: &[Tok],
    producers: &[Cow<[Tok]>],
    span: Span,
    depth: usize,
    b: &Budget,
    out: &mut Vec<Hit>,
) {
    let Some(tails) = Tails::of(words, b) else {
        return;
    };
    for producer in producers {
        let Some(text) = piped_text(producer, &tails, b) else {
            match b.unreadable {
                Unreadable::PassOver => continue,
                Unreadable::Stop => return,
            }
        };
        for h in hits_at(table, &text, depth + 1, b) {
            out.push(Hit { kind: h.kind, span });
        }
    }
}

/// Every reading of where a segment's command starts: the walk from its first word and, after a
/// wrapper, a walk from each later word that is not an option (an option the wrapper table does
/// not know may take a value: `sudo -X foo rm`). Walks run on the raw slice, with no copy per
/// start. `f` gets the start index and its walk; true stops the readings and is returned.
fn each_reading(
    words: &[Tok],
    depth: usize,
    b: &Budget,
    mut f: impl FnMut(usize, &Walk) -> bool,
) -> bool {
    let main = walk(words, depth, b);
    if f(0, &main) {
        return true;
    }
    let main_at = match main {
        Walk::Cmd { at, .. } => Some(at),
        _ => None,
    };
    for start in wrapper_suffixes(words, b) {
        if Some(start) != main_at && f(start, &walk(&words[start..], depth, b)) {
            return true;
        }
    }
    false
}

/// The bytes of the words joined with blanks.
fn text_len(words: &[Tok]) -> usize {
    words.iter().map(|w| w.value.len() + 1).sum()
}

/// Scan the command a walk found: its words or an `env -S` body.
fn scan_walk(
    table: &[Entry],
    words: &[Tok],
    w: &Walk,
    in_exec: bool,
    b: &Budget,
    out: &mut Vec<Hit>,
) {
    match w {
        Walk::Cmd { at, glued, depth } => {
            segment_hits(table, &view(words, *at, glued, b), *depth, in_exec, b, out);
        }
        Walk::Split { body, depth } => {
            let span = seg_span(words);
            for h in hits_at(table, body, *depth, b) {
                out.push(Hit { kind: h.kind, span });
            }
        }
        Walk::Opaque | Walk::Bare { .. } => {}
    }
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

fn segment_hits(
    table: &[Entry],
    words: &[Tok],
    depth: usize,
    in_exec: bool,
    b: &Budget,
    out: &mut Vec<Hit>,
) {
    if words.is_empty() || !b.spend(WORD + table.len()) {
        return;
    }
    let span = seg_span(words);
    let name = base_name(&words[0].value);
    // `(Get-Item x).Delete()`, `$d.Delete($true)`: a .NET delete on an object.
    if name.ends_with(".delete") && (name.starts_with('.') || name.starts_with('$')) {
        out.push(Hit {
            kind: Kind::DeleteMethod,
            span,
        });
        return;
    }
    match nested_body(&name, words, b) {
        Some(Nested::Body(body)) => {
            for h in hits_at(table, &body, depth + 1, b) {
                out.push(Hit { kind: h.kind, span });
            }
            return;
        }
        Some(Nested::Opaque) => return,
        None => {}
    }
    if !in_exec && name == "find" && b.spend(words.len() * WORD) {
        // Each clause runs its own command; a `find` inside a clause is not expanded again.
        for (k, w) in words.iter().enumerate() {
            if FIND_EXEC.contains(&w.value.as_str()) {
                let rest = &words[k + 1..];
                if !b.spend(rest.len() * WORD) {
                    return;
                }
                let end = rest
                    .iter()
                    .position(|w| matches!(w.value.as_str(), ";" | "+" | "\\;"))
                    .unwrap_or(rest.len());
                // Every reading of the clause, bounded by its terminator: the segment's own
                // readings run past it, where `-name` reads as git's `-n`.
                let clause = &rest[..end];
                each_reading(clause, depth, b, |start, w| {
                    scan_walk(table, &clause[start..], w, true, b, out);
                    false
                });
            }
        }
    }
    for (row, entry) in table.iter().enumerate() {
        for name_words in &entry.names {
            let Some(end) = match_name(name_words, &name, words, b) else {
                continue;
            };
            let args = &words[end..];
            let checks = 2 + entry.requires_any.len() + entry.unless_any.len();
            if !b.spend(args.len().saturating_mul(checks)) {
                return;
            }
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
                    kind: Kind::Row(row),
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
/// Commands that run the rest of their words as a command, with their options that take a value.
/// Every later word after a wrapper is also read as the command (`each_reading`), so a value
/// option is listed only where the walk would otherwise reach another command: env's value before
/// `-S`, and wsl with no command (it runs the default shell on the same stdin).
const WRAPPERS: [(&str, &[&str]); 14] = [
    ("sudo", &[]),
    ("doas", &[]),
    // `-S`/`--split-string` is read by `walk` (its value is the command).
    ("env", &["-u", "-C", "-a", "--unset", "--chdir", "--argv0"]),
    ("timeout", &[]),
    ("nice", &[]),
    ("ionice", &[]),
    ("time", &[]),
    ("xargs", &[]),
    ("nohup", &[]),
    ("command", &[]),
    ("builtin", &[]),
    ("exec", &[]),
    ("stdbuf", &[]),
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
/// The other shells a command may run its text in.
const OTHER_SHELLS: [&str; 3] = ["pwsh", "powershell", "cmd"];
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
fn nested_body(name: &str, words: &[Tok], b: &Budget) -> Option<Nested> {
    let reads_words = EVAL_NAMES.contains(&name)
        || BASH_SHELLS.contains(&name)
        || matches!(
            name,
            "start-process" | "start" | "saps" | "cmd" | "pwsh" | "powershell"
        );
    if reads_words && !b.spend(text_len(words)) {
        return None;
    }
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

/// Paths that name the process's own stdin.
const STDIN_PATHS: [&str; 3] = ["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

/// Whether a segment runs its stdin as code, in any reading of where its command starts: a shell
/// with no command argument (or `pwsh -Command -`), `iex`/`Invoke-Expression`, `wsl` with no
/// command, `source /dev/stdin`, `. /dev/stdin`. A command the walk cannot read counts too.
fn reads_stdin_as_code(words: &[Tok], depth: usize, b: &Budget) -> bool {
    each_reading(words, depth, b, |start, w| match w {
        Walk::Cmd { at, glued, .. } => {
            command_reads_stdin(&view(&words[start..], *at, glued, b), b)
        }
        // `wsl` alone starts the default shell on the same stdin.
        Walk::Bare { wrapper } => *wrapper == Some("wsl"),
        Walk::Split { .. } | Walk::Opaque => true,
    })
}

/// Whether a segment runs a file argument as code (`bash <(…)`, `source <(…)`, `. <(…)`), in any
/// reading of where its command starts.
fn runs_file_as_code(words: &[Tok], depth: usize, b: &Budget) -> bool {
    // `.` is a prefix word to the walk (PowerShell dot-sourcing): here it is the command.
    if words.first().is_some_and(|w| w.value == "." && !w.quoted) {
        return true;
    }
    each_reading(words, depth, b, |start, w| match w {
        Walk::Cmd { at, glued, .. } => {
            let words = view(&words[start..], *at, glued, b);
            let name = base_name(&words[0].value);
            name == "source" || (is_shell(&name) && nested_body(&name, &words, b).is_none())
        }
        Walk::Bare { .. } => false,
        Walk::Split { .. } | Walk::Opaque => true,
    })
}

fn is_shell(name: &str) -> bool {
    BASH_SHELLS.contains(&name) || OTHER_SHELLS.contains(&name)
}

/// Whether the command (its own words) runs its stdin as code.
fn command_reads_stdin(words: &[Tok], b: &Budget) -> bool {
    let first = words[0].value.as_str();
    let name = base_name(first);
    if matches!(name.as_str(), "iex" | "invoke-expression") || STDIN_PATHS.contains(&first) {
        return true;
    }
    if name == "source" {
        return words
            .get(1)
            .is_some_and(|w| STDIN_PATHS.contains(&w.value.as_str()));
    }
    if !is_shell(&name) {
        return false;
    }
    match nested_body(&name, words, b) {
        None => true,
        Some(Nested::Body(body)) => body.trim() == "-",
        Some(Nested::Opaque) => false,
    }
}

/// What a writer may still expand in its text: `$`, a backtick, a backslash or a printf `%` escape.
const EXPANDS: [char; 4] = ['$', '`', '\\', '%'];

/// For each start in a segment's words, whether the words from there to the end hold one that is
/// not quoted, and one with text the writer may still expand.
struct Tails {
    unquoted: Vec<bool>,
    expands: Vec<bool>,
}

impl Tails {
    fn of(words: &[Tok], b: &Budget) -> Option<Tails> {
        if !b.spend(text_len(words)) {
            return None;
        }
        let mut tails = Tails {
            unquoted: vec![false; words.len() + 1],
            expands: vec![false; words.len() + 1],
        };
        for (k, w) in words.iter().enumerate().rev() {
            tails.unquoted[k] = tails.unquoted[k + 1] || !w.quoted;
            tails.expands[k] = tails.expands[k + 1] || w.value.contains(EXPANDS);
        }
        Some(tails)
    }
}

/// The text a segment writes into a pipe when it is static: the words after `echo`/`printf`, or
/// a segment of string literals. `None` for anything else, or text the writer may still expand.
/// `tails` are those of the segment whose tail the words after the first are.
fn piped_text(words: &[Tok], tails: &Tails, b: &Budget) -> Option<String> {
    let (first, rest) = words.split_first()?;
    let at = tails.expands.len() - 1 - rest.len();
    let echo = ECHO_NAMES.contains(&base_name(&first.value).as_str());
    let literals = !echo && first.quoted && !tails.unquoted[at];
    if !(echo || literals) || tails.expands[at] || (literals && first.value.contains(EXPANDS)) {
        return None;
    }
    let text = if echo { rest } else { words };
    if !b.spend(text_len(text)) {
        return None;
    }
    Some(join(text))
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
fn match_name(name_words: &[String], base: &str, words: &[Tok], b: &Budget) -> Option<usize> {
    if base != name_words[0] {
        return None;
    }
    let mut k = 1;
    if name_words[0] == "git" {
        while k < words.len() && words[k].value.starts_with('-') {
            if !b.spend(WORD) {
                return None;
            }
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

/// Where a simple command's own command starts, once the words that only prefix it are past:
/// wrappers and their options (`sudo -u root`, `timeout 5`, `wsl -e`), assignments, casts,
/// leading redirects.
enum Walk {
    /// The command is `words[at..]`; `glued` replaces `words[at]` when the command starts inside
    /// it (`$r=Remove-Item x`). `depth` counts the wrappers stripped.
    Cmd {
        at: usize,
        glued: Option<Tok>,
        depth: usize,
    },
    /// `env -S 'cmd args' rest…`: the command is this text, read as a nested command.
    Split { body: String, depth: usize },
    /// Only prefix words: no command (`wsl` alone runs the default shell). Also the walk's
    /// answer once the budget is spent.
    Bare { wrapper: Option<&'static str> },
    /// More wrappers than `MAX_DEPTH`.
    Opaque,
}

/// One pass over the word indices: no recursion and no copy of the words. Each wrapper costs one
/// level of `depth`.
fn walk(words: &[Tok], depth: usize, b: &Budget) -> Walk {
    const SPENT: Walk = Walk::Bare { wrapper: None };
    let mut depth = depth;
    let mut wrapper = None;
    let mut k = 0;
    while k < words.len() {
        if !b.spend(WORD) {
            return SPENT;
        }
        let w = &words[k];
        if w.quoted {
            break;
        }
        let v = w.value.as_str();
        let lower = v.to_lowercase();
        if PREFIX_WORDS.contains(&lower.as_str()) || is_assignment(v) {
            k += 1;
        } else if let Some(&(name, opts)) = WRAPPERS.iter().find(|(n, _)| *n == base_name(v)) {
            depth += 1;
            if depth > MAX_DEPTH {
                return Walk::Opaque;
            }
            wrapper = Some(name);
            k += 1;
            // A quoted option is still an option (`--split-string='rm x'`, `'-u' root`).
            while k < words.len() && words[k].value.starts_with('-') {
                if !b.spend(WORD) {
                    return SPENT;
                }
                let o = words[k].value.as_str();
                if o == "--" {
                    k += 1;
                    break;
                }
                if name == "env"
                    && let Some((value, used)) = split_string(o, words.get(k + 1))
                {
                    // `env -S 'cmd args' rest`: env splits the value (`\_` is a blank) and runs
                    // it with the rest appended.
                    let rest = &words[(k + used).min(words.len())..];
                    if !b.spend(value.len() + text_len(rest)) {
                        return SPENT;
                    }
                    let mut body = value.replace("\\_", " ");
                    for r in rest {
                        body.push(' ');
                        body.push_str(&r.value);
                    }
                    return Walk::Split { body, depth };
                }
                // `--opt=value` carries its value; a known option, or getopt's unambiguous
                // abbreviation of a long one, takes the next word.
                let takes_value = opts.contains(&o)
                    || (o.starts_with("--")
                        && o.len() >= 3
                        && opts.iter().any(|x| x.starts_with("--") && x.starts_with(o)));
                k += if !o.contains('=') && takes_value {
                    2
                } else {
                    1
                };
            }
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
                return Walk::Cmd {
                    at: k,
                    glued: Some(t),
                    depth,
                };
            }
        } else if v.starts_with('[') && v.ends_with(']') && !v.contains("::") {
            k += 1;
        } else {
            break;
        }
    }
    if k >= words.len() {
        return Walk::Bare { wrapper };
    }
    Walk::Cmd {
        at: k,
        glued: None,
        depth,
    }
}

/// The words of a command a walk found (`words[at..]`, `glued` in front).
fn view<'a>(words: &'a [Tok], at: usize, glued: &Option<Tok>, b: &Budget) -> Cow<'a, [Tok]> {
    match glued {
        None => Cow::Borrowed(&words[at..]),
        Some(t) => {
            b.spend((words.len() - at) * WORD);
            let mut v = vec![t.clone()];
            v.extend(words[at + 1..].iter().cloned());
            Cow::Owned(v)
        }
    }
}

/// The command's words when the walk found plain words, else none.
fn command_words<'a>(words: &'a [Tok], w: &Walk, b: &Budget) -> Cow<'a, [Tok]> {
    match w {
        Walk::Cmd { at, glued, .. } => view(words, *at, glued, b),
        _ => Cow::Borrowed(&[]),
    }
}

/// The body of `env -S`/`--split-string` (any getopt abbreviation, or `S` inside a short option
/// cluster such as `-iS`), glued or in the next word, and how many words it used.
fn split_string(o: &str, next: Option<&Tok>) -> Option<(String, usize)> {
    let from_next = || next.map(|w| (w.value.clone(), 2));
    if let Some(long) = o.strip_prefix("--") {
        let (name, value) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (long, None),
        };
        if name.is_empty() || !"split-string".starts_with(name) {
            return None;
        }
        return match value {
            Some(v) => Some((v.to_string(), 1)),
            None => from_next(),
        };
    }
    let cluster = o.strip_prefix('-')?;
    let at = cluster.find('S')?;
    if !cluster[..at].bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let rest = &cluster[at + 1..];
    if rest.is_empty() {
        from_next()
    } else {
        Some((rest.to_string(), 1))
    }
}

/// After a wrapper anywhere in the segment, every later word that is not an option may start
/// the command: an option the wrapper table does not know may take a value (`sudo -X foo rm`).
fn wrapper_suffixes(words: &[Tok], b: &Budget) -> Vec<usize> {
    if !b.spend(words.len() * WORD) {
        return Vec::new();
    }
    let Some(w) = words
        .iter()
        .position(|t| !t.quoted && WRAPPERS.iter().any(|(n, _)| *n == base_name(&t.value)))
    else {
        return Vec::new();
    };
    (w + 1..words.len())
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
    /// Ended by `<(` (bash): the next segment's output is a file this command reads.
    procsub: bool,
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
fn segments(text: &str, mode: Mode, b: &Budget) -> Segments {
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
    fn end_segment(
        out: &mut Segments,
        cur: &mut Option<Tok>,
        words: &mut Vec<Tok>,
        piped: bool,
        procsub: bool,
    ) {
        end_word(cur, words);
        if !words.is_empty() {
            out.segs.push(Segment {
                words: std::mem::take(words),
                piped,
                procsub,
            });
        }
    }
    // Whether the segment so far feeds its stdin to code: a shell (sudo bash included) or any
    // command that reads stdin as code.
    let segment_is_shell = |words: &[Tok], cur: &Option<Tok>| {
        let all: Cow<[Tok]> = match cur {
            None => Cow::Borrowed(words),
            Some(c) => {
                if !b.spend(words.len() * WORD) {
                    return true;
                }
                let mut all = words.to_vec();
                all.push(c.clone());
                Cow::Owned(all)
            }
        };
        each_reading(&all, 0, b, |start, w| match w {
            Walk::Cmd { at, glued, .. } => {
                let words = view(&all[start..], *at, glued, b);
                is_shell(&base_name(&words[0].value)) || command_reads_stdin(&words, b)
            }
            Walk::Bare { wrapper } => *wrapper == Some("wsl"),
            Walk::Split { .. } | Walk::Opaque => true,
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
                    // bash compares byte for byte, but a reader that drops CR ends the body at a
                    // line that matches once `\r` is trimmed: the earliest end of the two leaves
                    // the most text to scan as code. (The trimmed compare also holds every
                    // byte-for-byte match.)
                    if line.trim_end_matches('\r') == h.delim.trim_end_matches('\r') {
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
            end_segment(&mut out, &mut cur, &mut words, false, false);
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
            // After a delimiter the reader cannot resolve, nothing shows where the body ends:
            // the rest of the input is scanned as code.
            match heredoc_word(text, j) {
                Some((delim, quoted, end)) => {
                    if quoted || !delim.is_empty() {
                        heredocs.push(Heredoc {
                            delim,
                            strip_tabs,
                            quoted,
                        });
                    }
                    i = end;
                }
                None => i = j,
            }
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
            let procsub = c == '('
                && mode == Mode::Bash
                && cur.as_ref().is_some_and(|t| t.value == "<" && !t.quoted);
            end_segment(&mut out, &mut cur, &mut words, pipe, procsub);
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
    end_segment(&mut out, &mut cur, &mut words, false, false);
    out
}

/// The heredoc delimiter word at `j`, read as bash reads it: quotes removed, backslash escapes
/// resolved, `\r` a plain character. Returns the word, whether any part of it was quoted, and
/// the index after it; `None` when it cannot be read exactly (an unclosed quote, `$'…'` or
/// `$"…"`). A word holding a newline never matches a line, so its body runs to the end and is
/// scanned as code.
fn heredoc_word(text: &str, j: usize) -> Option<(String, bool, usize)> {
    let n = text.len();
    let mut word = String::new();
    let mut quoted = false;
    let mut exact = true;
    let mut k = j;
    while k < n {
        let c = char_at(text, k);
        match c {
            ' ' | '\t' | '\n' | ';' | '|' | '&' | '(' | ')' | '<' | '>' => break,
            '\'' => {
                quoted = true;
                let e = k + 1 + text[k + 1..].find('\'')?;
                word.push_str(&text[k + 1..e]);
                k = e + 1;
            }
            '"' => {
                quoted = true;
                let mut e = k + 1;
                loop {
                    let d = text[e..].chars().next()?;
                    if d == '"' {
                        break;
                    }
                    let x = char_at(text, e + d.len_utf8());
                    if d == '\\' && matches!(x, '$' | '`' | '"' | '\\' | '\n') {
                        word.push(x);
                        e += 2;
                    } else {
                        word.push(d);
                        e += d.len_utf8();
                    }
                }
                k = e + 1;
            }
            '\\' => {
                quoted = true;
                let x = text[k + 1..].chars().next()?;
                word.push(x);
                k += 1 + x.len_utf8();
            }
            '$' if matches!(char_at(text, k + 1), '\'' | '"') => {
                exact = false;
                word.push(c);
                k += 1;
            }
            _ => {
                word.push(c);
                k += c.len_utf8();
            }
        }
    }
    exact.then_some((word, quoted, k))
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
        // every prefix of -Command
        "pwsh -co \"Remove-Item x\"",
        "pwsh -Comm 'ri x'",
        "pwsh /Command 'Remove-Item x'",
        "pwsh \u{2013}c 'ri x'",
        // `\$'` is a literal dollar before a plain quote, not an ANSI-C string
        "echo \\$'a\\' <# ; rm -rf x ; echo '",
        // I1: nesting at and past the depth limit
        "pwsh -c pwsh -c pwsh -c pwsh -c Remove-Item x",
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
        "env -iS 'rm -rf x'",
        "env --split-str='rm -rf x'",
        "env -S 'X=1 rm -rf x'",
        "X=1 Y=2 Z=3 W=4 sudo -X a b c d e f g h i rm -rf x",
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
        "$d = Get-Item x; $d.Delete($true)",
        "gci x -Recurse | % { $_.Delete() }",
        // I-2: the env -S body is a nested command (quotes, `\_`, wrappers, nested -S)
        "sudo -X foo env -S 'rm -rf x'",
        "sudo -X foo env -iS 'rm -rf x'",
        "sudo -X foo env -S 'git reset --hard'",
        "sudo -X foo env -S 'X=1 rm -rf x'",
        "sudo -c default env -S 'rm -rf x'",
        "env -a foo -S 'rm -rf x'",
        "env -S '\"rm\" -rf x'",
        "env -S 'env -S \"rm -rf x\"'",
        "env -S 'rm\\_-rf\\_x'",
        "env -S 'sudo -X foo rm -rf x'",
        // I-1: the heredoc delimiter is a bash word (`\r` is a plain character, quotes hold blanks)
        "echo \u{2018}a; cat <<A\rB\nhello\nA\rB\nrm -rf x\nA\necho \u{2019}",
        "echo \u{2018}a; cat <<'A B'\nhello\nA B\nrm -rf x\nA\necho '\n'\necho \u{2019}",
        "echo \u{2018}a; cat <<A\\ B\nhello\nA B\nrm -rf x\nA\necho \u{2019}",
        "echo \u{2018}a; cat <<\"A B\"\nhello\nA B\nrm -rf x\nA\necho \"\n\"\necho \u{2019}",
        // bash takes `A` as the delimiter of `<<$'A'`; the reader does not resolve `$'…'`
        "echo \u{2018}a; cat <<$'A'\nhello\nA\nrm -rf x\n$A\necho \u{2019}",
        // I-3: forms whose reading has no other row
        "sudo -u root env -S 'rm -rf x'",
        "echo \u{2018}a; sudo -u root bash <<'EOF'\nrm -rf x\nEOF\necho \u{2019}",
        "env -S'rm -rf x'",
        "env -iS'rm -rf x'",
        "Start-Process git 'clean','-fd'",
        "echo 'rm -rf x' | sudo -u root bash",
        "echo 'rm -rf x' | nice -n 5 bash",
        "echo 'rm -rf x' | timeout 5 bash",
        "@'\nRemove-Item x",
        "$m = @\"\n$(Remove-Item x)\n\"@",
        // I-4: text an interpreter reads from a pipe or a process substitution
        "'Remove-Item x' | iex",
        "'Remove-Item x' | Invoke-Expression",
        "echo 'rm -rf x' | wsl",
        "echo 'rm -rf x' | source /dev/stdin",
        "echo 'rm -rf x' | . /dev/stdin",
        "bash <(echo 'rm -rf x')",
        "sh <(echo 'rm -rf x')",
        "bash < <(echo 'rm -rf x')",
        // the consumer behind a wrapper option the table does not know
        "echo 'rm -rf x' | sudo -X foo bash",
        "echo \u{2018}a; sudo -X foo bash <<'EOF'\nrm -rf x\nEOF\necho \u{2019}",
        "source <(echo 'rm -rf x')",
        ". <(echo 'rm -rf x')",
        // every consumer reads every command start, and an env -S consumer counts
        "find . -exec sudo -u root rm -rf {} +",
        // a clause ends at its terminator: words after it (`-name`) are not the command's
        "find . -exec sudo -u root git clean -fdx \\; -name x",
        "find . -exec sudo -u root git clean -fdx ';' -name x",
        "find . -exec env -S 'rm -rf x' \\;",
        "sudo -X foo iex('Remove-Item x')",
        "echo \u{2018}a; wsl <<'EOF'\nrm -rf x\nEOF\necho \u{2019}",
        "echo 'rm -rf x' | env -S'bash -x'",
        "env -S'bash' <(echo 'rm -rf x')",
        "echo \u{2018}a; env -S'bash' <<'EOF'\nrm -rf x\nEOF\necho \u{2019}",
        // automated note 1: every reading of the producer is what may print the code
        "sudo -u echo printf 'rm -rf x' | bash",
        "bash <(sudo -u echo printf 'rm -rf x')",
        // a reading of the producer the scan cannot read (`root …`, `$u …`, `5 …` as the command)
        // is passed over: a later reading's static text is still scanned
        "sudo -u root printf 'rm -rf x' | bash",
        "sudo -u $u printf 'rm -rf x' | bash",
        "timeout 5 printf 'rm -rf x' | bash",
        "bash <(sudo -u root printf 'rm -rf x')",
        // a producer whose command starts inside its first word (`$r=echo`)
        "$r=echo 'rm -rf x' | bash",
        // automated note 2: a delimiter with `\r` that no line matches byte for byte
        "cat <<EOF\r\nEOF\nrm -rf x",
        "cat <<EOF\nEOF\r\nrm -rf x",
        // a line that matches the delimiter only once `\r` is trimmed ends the body (a reader
        // that drops CR stops there): the earliest end is the safe side
        "echo \u{2018}a; cat <<EOF\nhello\nEOF\r\nrm -rf x\nEOF\necho \u{2019}",
        "echo \u{2018}a; cat <<EOF\r\nhello\r\nEOF\nrm -rf x\r\nEOF\r\necho \u{2019}",
        // a consumer behind more wrappers than MAX_DEPTH counts as one that runs its input as
        // code (its four-wrapper twin in HARMLESS does not)
        "echo 'rm -rf x' | sudo sudo sudo sudo sudo cat",
        "sudo sudo sudo sudo sudo cat <(echo 'rm -rf x')",
        // a shell with no command runs the pipe (the twin of the encoded rows below)
        "echo 'rm -rf x' | pwsh",
        "echo 'rm -rf x' | powershell",
    ];

    /// Destructive spellings the scan cannot read, with the unreadable class each is in: no row
    /// and no `Delete()` call is seen.
    const UNREADABLE_DESTRUCTIVE: &[(&str, &str)] = &[
        // A shell given an encoded command runs that command, not the pipe.
        (
            "echo 'rm -rf x' | pwsh -EncodedCommand AAAA",
            "an encoded body",
        ),
        ("echo 'rm -rf x' | powershell -e AAAA", "an encoded body"),
        ("echo 'rm -rf x' | pwsh.exe -enc AAAA", "an encoded body"),
        ("echo 'rm -rf x' | pwsh -ec AAAA", "an encoded body"),
        ("echo 'rm -rf x' | pwsh /enc AAAA", "an encoded body"),
        (
            "echo 'rm -rf x' | pwsh --EncodedCommand AAAA",
            "an encoded body",
        ),
        // Text the writer may still expand, after `printf` or in a string literal.
        ("printf 'rm -rf x %s' | bash", "an expanding producer"),
        ("'rm -rf $x' | bash", "an expanding producer"),
        (
            "pwsh -c pwsh -c pwsh -c pwsh -c pwsh -c Remove-Item x",
            "nesting past MAX_DEPTH",
        ),
    ];

    /// Every wrapper name: the shell after it reads the pipe.
    const WRAPPER_NAMES: &[&str] = &[
        "sudo", "doas", "env", "timeout", "nice", "ionice", "time", "xargs", "nohup", "command",
        "exec", "stdbuf", "wsl",
    ];

    /// env options that take a value, as `env --help` lists them: the value is not the `-S`.
    const ENV_VALUE_OPTIONS: &[&str] = &["-u", "--unset", "-C", "--chdir", "-a", "--argv0", "--un"];

    /// wsl options that take a value, as `wsl --help` lists them: `wsl -d Ubuntu` alone runs the
    /// default shell.
    const WSL_VALUE_OPTIONS: &[&str] = &[
        "-d",
        "--distribution",
        "-u",
        "--user",
        "--cd",
        "--shell-type",
        "--distrib",
    ];

    /// `Start-Process` parameters that take a value: the value is not the file to start.
    const START_PROCESS_VALUE_PARAMS: &[&str] = &[
        "-WorkingDirectory",
        "-Verb",
        "-WindowStyle",
        "-RedirectStandardInput",
        "-RedirectStandardOutput",
        "-RedirectStandardError",
        "-Credential",
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
        // a CRLF heredoc ends at its own delimiter line: its body is text
        "echo \u{2018}a; cat <<EOF\r\nrm -rf x\r\nEOF\r\necho \u{2019}",
        // static text an interpreter reads is scanned, not taken as unreadable
        "'Get-Date' | iex",
        "echo hi | bash",
        // a string literal before an unquoted word is the name of a command, not text it prints
        "'rm -rf x' foo | bash",
        // four wrappers are readable: `cat` runs no code
        "echo 'rm -rf x' | sudo sudo sudo sudo cat",
        "sudo sudo sudo sudo cat <(echo 'rm -rf x')",
    ];

    #[test]
    fn embedded_table_loads() {
        assert!(table().len() >= 9, "{} rows", table().len());
    }

    #[test]
    fn every_destructive_spelling_is_caught() {
        let missed: Vec<&&str> = DESTRUCTIVE
            .iter()
            .filter(|cmd| destructive_row(cmd).is_none())
            .collect();
        assert!(missed.is_empty(), "missed: {missed:?}");
    }

    #[test]
    fn unreadable_destructive_spellings_are_no_row() {
        let read: Vec<&(&str, &str)> = UNREADABLE_DESTRUCTIVE
            .iter()
            .filter(|(cmd, _)| destructive_row(cmd).is_some())
            .collect();
        assert!(read.is_empty(), "read as a row: {read:?}");
    }

    #[test]
    fn the_parsed_reading_stops_at_an_unreadable_producer() {
        // A fail-closed path passes over the producer's first reading (`$u …`, `cat …`) and
        // feeds the `printf` text; in a command that parses the producer ends there.
        for cmd in [
            "sudo -u $u printf 'rm -rf x' | bash",
            "sudo cat f printf 'rm -rf x' | bash",
        ] {
            assert!(!hits(table(), cmd).is_empty(), "fail path: {cmd}");
            assert!(parsed_hits(cmd).is_empty(), "parsed: {cmd}");
        }
        // A readable first reading is fed in both.
        assert!(!parsed_hits("printf 'rm -rf x' | bash").is_empty());
    }

    #[test]
    fn wrapper_option_values_are_not_the_command() {
        let mut rows = Vec::new();
        for wrapper in WRAPPER_NAMES {
            rows.push(format!("echo 'rm -rf x' | {wrapper} bash"));
        }
        for opt in ENV_VALUE_OPTIONS {
            rows.push(format!("env {opt} v -S 'rm -rf x'"));
        }
        for opt in WSL_VALUE_OPTIONS {
            rows.push(format!("echo 'rm -rf x' | wsl {opt} v"));
        }
        for param in START_PROCESS_VALUE_PARAMS {
            rows.push(format!("Start-Process {param} v git 'clean','-fd'"));
        }
        let missed: Vec<&String> = rows
            .iter()
            .filter(|cmd| destructive_row(cmd).is_none())
            .collect();
        assert!(missed.is_empty(), "missed: {missed:?}");
    }

    #[test]
    fn chained_env_split_strings_stay_bounded() {
        // 64 KiB of `env -S` links: a wrapper reading still finds a destructive tail, and a
        // harmless one names no row.
        for (tail, row) in [("rm -rf x", true), ("echo hi", false)] {
            let cmd = format!("{}{tail}", "env -S ".repeat(64 * 1024 / 7));
            let start = std::time::Instant::now();
            assert_eq!(destructive_row(&cmd).is_some(), row, "{tail}");
            assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
        }
    }

    #[test]
    fn nested_bodies_behind_wrappers_stay_bounded() {
        // Every word after a wrapper is a reading, and each `eval`/`bash -c` reading nests a body.
        for unit in ["sudo eval ", "sudo bash -c "] {
            let cmd = format!("{}echo hi", unit.repeat(64 * 1024 / unit.len()));
            let start = std::time::Instant::now();
            assert!(destructive_row(&cmd).is_none(), "{unit}");
            assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
        }
    }

    #[test]
    fn unreadable_producer_readings_stay_linear() {
        // Every word after a wrapper is a reading of the producer; one the scan cannot read (a
        // command word, an `echo` whose text expands, a quoted word before an unquoted one) costs
        // a step, not its text, so the `printf` reading after them and the command after the
        // segment are still read.
        for unit in ["a ", "$a ", "echo $a ", "'a' "] {
            let chain = unit.repeat(5000);
            for (cmd, at) in [
                (format!("sudo {chain}printf 'rm -rf x' | bash"), 0),
                (
                    format!("sudo {chain}echo $a | bash; rm -rf y"),
                    5 + chain.len() + "echo $a | bash; ".len(),
                ),
            ] {
                let start = std::time::Instant::now();
                let row = destructive_row(&cmd);
                assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
                assert_eq!(row.map(|s| s.start), Some(at), "{unit:?}");
            }
        }
    }

    #[test]
    fn a_spent_budget_ends_the_scan() {
        // The first segment spends the budget without nesting deeper than one body; the `rm`
        // after it is never read.
        let cmd = format!("sudo x {}; rm -rf x", "bash -c 'echo hi' ".repeat(1000));
        let hits = hits(table(), &cmd);
        assert!(hits.is_empty(), "the rm was read: {hits:?}");
    }

    #[test]
    fn long_wrapper_segments_stay_linear() {
        let cmd = format!("sudo {}rm -rf x", "a ".repeat(20_000));
        let start = std::time::Instant::now();
        assert!(destructive_row(&cmd).is_some());
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
    }

    #[test]
    fn find_exec_chains_stay_linear() {
        let cmd = format!("find . {}-exec rm -rf x", "-exec find . ".repeat(22));
        let start = std::time::Instant::now();
        assert!(destructive_row(&cmd).is_some());
        assert!(start.elapsed().as_millis() < 1000, "{:?}", start.elapsed());
    }

    #[test]
    fn every_table_row_has_a_destructive_case() {
        let mut seen = vec![false; table().len()];
        for cmd in DESTRUCTIVE {
            for hit in hits(table(), cmd) {
                if let Kind::Row(row) = hit.kind {
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
            .filter(|cmd| destructive_row(cmd).is_some())
            .collect();
        assert!(flagged.is_empty(), "flagged: {flagged:?}");
    }

    #[test]
    fn span_covers_the_destructive_simple_command() {
        let cmd = "echo hi; rm -rf x";
        assert_eq!(destructive_row(cmd), Some(Span { start: 9, end: 17 }));
        // The first destructive command wins.
        let cmd = "rm a; git reset --hard";
        assert_eq!(destructive_row(cmd), Some(Span { start: 0, end: 4 }));
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
        assert!(destructive_row(&cmd).is_some());
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
    }
}
