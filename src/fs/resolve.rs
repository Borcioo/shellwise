//! Delete-target resolution: which folders a word names, as the shell would resolve it, from
//! the location `cd` and friends left, the event's `cwd` and the variables the hook can trust.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use globset::GlobBuilder;

use super::walk::is_within;
use super::{Fs, SharedFs, TimedOut, bounded};
use crate::ir::ChainOp;
use crate::ir::{Elem, EnvView, Pipeline, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::Span;
use crate::{Deadline, Os, Shell};

// ------------------------------------------------------------------ canonical paths

/// A path split into its root (`C:`, `\\srv\share`, `\\?\Volume{…}`, `/`, or empty for a
/// root-relative `\x`) and its components, with `.`, `..` and repeated separators resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Canon {
    prefix: String,
    /// The path starts at a root (`C:\`, `\`, `/`); false for a relative path.
    rooted: bool,
    comps: Vec<String>,
    os: Os,
}

impl Canon {
    fn parse(p: &str, os: Os) -> Canon {
        match os {
            Os::Windows => Canon::parse_windows(p),
            Os::Posix => Canon::parse_posix(p),
        }
    }

    fn parse_posix(p: &str) -> Canon {
        let rooted = p.starts_with('/');
        Canon {
            prefix: if rooted {
                "/".to_string()
            } else {
                String::new()
            },
            rooted,
            comps: resolve_dots(p.split('/'), rooted, false),
            os: Os::Posix,
        }
    }

    fn parse_windows(p: &str) -> Canon {
        let s = p.replace('/', "\\");
        let verbatim = ["\\\\?\\", "\\\\.\\", "\\??\\"]
            .iter()
            .find(|v| s.starts_with(**v))
            .map(|v| &s[v.len()..]);
        let (prefix, rest, rooted): (String, &str, bool) = if let Some(after) = verbatim {
            if after.len() >= 4 && after[..4].eq_ignore_ascii_case("UNC\\") {
                unc(&after[4..])
            } else if is_drive(after) {
                (after[..2].to_string(), &after[2..], true)
            } else {
                let (vol, rest) = after.split_once('\\').unwrap_or((after, ""));
                (format!("\\\\?\\{vol}"), rest, true)
            }
        } else if let Some(after) = s.strip_prefix("\\\\") {
            unc(after)
        } else if is_drive(&s) {
            let rest = &s[2..];
            (s[..2].to_string(), rest, rest.starts_with('\\'))
        } else if s.starts_with('\\') {
            (String::new(), &s[..], true)
        } else {
            (String::new(), &s[..], false)
        };
        Canon {
            prefix,
            rooted,
            comps: resolve_dots(rest.split('\\'), rooted, true),
            os: Os::Windows,
        }
    }

    fn sep(&self) -> char {
        if self.os == Os::Windows { '\\' } else { '/' }
    }

    fn render(&self) -> String {
        let sep = self.sep().to_string();
        let mut out = self.prefix.clone();
        if self.os == Os::Windows && self.rooted {
            out.push('\\');
        }
        out.push_str(&self.comps.join(&sep));
        out
    }

    fn is_root(&self) -> bool {
        self.rooted && self.comps.is_empty()
    }
}

fn is_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// `srv\share\rest` → (`\\srv\share`, `rest`).
fn unc(after: &str) -> (String, &str, bool) {
    let mut it = after.splitn(3, '\\');
    let server = it.next().unwrap_or("");
    let share = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");
    let prefix = if share.is_empty() {
        format!("\\\\{server}")
    } else {
        format!("\\\\{server}\\{share}")
    };
    (prefix, rest, true)
}

/// Resolve `.` and `..` lexically; on Windows also drop the trailing dots and spaces Win32
/// strips from every component.
fn resolve_dots<'a>(comps: impl Iterator<Item = &'a str>, rooted: bool, win: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in comps {
        let c = if win && c != "." && c != ".." {
            c.trim_end_matches(['.', ' '])
        } else {
            c
        };
        match c {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..".to_string());
                }
            }
            _ => out.push(c.to_string()),
        }
    }
    out
}

/// `p` with separators, `\\?\`, `.`, `..` and (on Windows) trailing dots and spaces resolved.
pub fn canonical(p: &str, os: Os) -> String {
    Canon::parse(p, os).render()
}

/// The text two paths are compared by: `canonical`, lowercased on Windows.
pub fn path_key(p: &str, os: Os) -> String {
    let c = canonical(p, os);
    if os == Os::Windows {
        c.to_lowercase()
    } else {
        c
    }
}

// ------------------------------------------------------------------ critical folders

/// Why deleting `p` (recursively) is critical, or `None`. `home` is the profile folder from
/// the hook's environment, not `EnvView::home` (which a command can make dynamic);
/// `cwd_repo` is the root of the repo holding the event's `cwd`. Compared on the host's
/// rules: ignoring case on Windows, after canonicalising separators and `\\?\`.
pub fn critical_reason(
    p: &Path,
    cwd_repo: Option<&Path>,
    home: Option<&Path>,
    protected: &[PathBuf],
) -> Option<&'static str> {
    let os = Os::host();
    let text = p.to_string_lossy();
    let canon = Canon::parse(&text, os);
    if canon.is_root() {
        return Some(if canon.prefix.is_empty() || canon.prefix == "/" {
            "file-system root"
        } else {
            "drive root"
        });
    }
    // macOS volumes ignore case by default.
    let key_of = |t: &str| {
        let k = path_key(t, os);
        if cfg!(target_os = "macos") {
            k.to_lowercase()
        } else {
            k
        }
    };
    let key = key_of(&text);
    let named: Vec<(&Path, &'static str, &'static str)> = home
        .map(|h| (h, "home folder", "ancestor of the home folder"))
        .into_iter()
        .chain(cwd_repo.map(|r| (r, "repo root", "ancestor of the repo root")))
        .chain(protected.iter().map(|p| {
            (
                p.as_path(),
                "protected path",
                "ancestor of a protected path",
            )
        }))
        .collect();
    let keys: Vec<(String, &'static str, &'static str)> = named
        .iter()
        .map(|(p, exact, above)| (key_of(&p.to_string_lossy()), *exact, *above))
        .collect();
    if let Some((_, exact, _)) = keys.iter().find(|(k, _, _)| *k == key) {
        return Some(exact);
    }
    keys.iter()
        .find(|(k, _, _)| is_within(k, &key, os))
        .map(|(_, _, above)| *above)
}

/// `critical_reason`, then the same match by file identity for any spelling it misses: a
/// junction or symlink on the way, a drive made by `subst` before the command, an 8.3 name.
/// `p` is critical when it is the same file as home, the repo root or a protected path, or the
/// same file as one of their ancestors. Runs on a worker bounded by `deadline`.
pub fn critical_by_identity(
    p: &Path,
    cwd_repo: Option<&Path>,
    home: Option<&Path>,
    protected: &[PathBuf],
    fs: &SharedFs,
    deadline: &Deadline,
) -> Result<Option<&'static str>, TimedOut> {
    if let Some(r) = critical_reason(p, cwd_repo, home, protected) {
        return Ok(Some(r));
    }
    let p = p.to_path_buf();
    let mut named: Vec<(PathBuf, &'static str, &'static str)> = Vec::new();
    if let Some(h) = home {
        named.push((
            h.to_path_buf(),
            "home folder",
            "ancestor of the home folder",
        ));
    }
    if let Some(r) = cwd_repo {
        named.push((r.to_path_buf(), "repo root", "ancestor of the repo root"));
    }
    for x in protected {
        named.push((x.clone(), "protected path", "ancestor of a protected path"));
    }
    let fs = Arc::clone(fs);
    let d = *deadline;
    bounded(deadline, move || {
        let Ok(Some(target)) = fs.file_id(&p) else {
            return Ok(None);
        };
        let same = |q: &Path| matches!(fs.file_id(q), Ok(Some(id)) if id == target);
        for (path, exact, _) in &named {
            if d.expired() {
                return Err(TimedOut);
            }
            if same(path) {
                return Ok(Some(*exact));
            }
        }
        for (path, _, above) in &named {
            for a in path.ancestors().skip(1) {
                if d.expired() {
                    return Err(TimedOut);
                }
                if same(a) {
                    return Ok(Some(*above));
                }
            }
        }
        Ok(None)
    })?
}

/// The root of the repo holding `cwd`: the nearest folder with a `.git` folder or file.
pub fn repo_root(
    cwd: &Path,
    fs: &SharedFs,
    deadline: &Deadline,
) -> Result<Option<PathBuf>, TimedOut> {
    let cwd = cwd.to_path_buf();
    let fs = Arc::clone(fs);
    let d = *deadline;
    bounded(deadline, move || {
        for a in cwd.ancestors() {
            if d.expired() {
                return Err(TimedOut);
            }
            if fs.lstat(&a.join(".git")).is_ok() {
                return Ok(Some(a.to_path_buf()));
            }
        }
        Ok(None)
    })?
}

// ------------------------------------------------------------------ PowerShell parameters

/// The parameter a written PowerShell parameter name binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamMatch {
    /// The parameter's full name.
    Exact(&'static str),
    /// The name fits several parameters: PowerShell refuses the command.
    Ambiguous,
    /// No parameter fits, or the cmdlet is not modelled.
    Unknown,
}

struct Param {
    name: &'static str,
    aliases: &'static [&'static str],
    switch: bool,
}

const fn value(name: &'static str, aliases: &'static [&'static str]) -> Param {
    Param {
        name,
        aliases,
        switch: false,
    }
}

const fn switch(name: &'static str, aliases: &'static [&'static str]) -> Param {
    Param {
        name,
        aliases,
        switch: true,
    }
}

// Parameter lists from pwsh 7.7: `(Get-Command <cmdlet>).Parameters.Values | ForEach-Object {
// $_.Name, $_.Aliases, $_.SwitchParameter }`, split into the cmdlet's own and the common ones by
// `[System.Management.Automation.Cmdlet]::CommonParameters` and `::OptionalCommonParameters`.

/// `New-Item` (`ni`).
const NEW_ITEM: &[Param] = &[
    value("Path", &[]),
    value("Name", &[]),
    value("ItemType", &["Type"]),
    value("Value", &["Target"]),
    switch("Force", &[]),
    value("Credential", &[]),
];

/// `Set-Location` (`cd`, `chdir`, `sl`) and `Push-Location` (`pushd`): the same list.
const SET_LOCATION: &[Param] = &[
    value("Path", &[]),
    value("LiteralPath", &["PSPath", "LP"]),
    switch("PassThru", &[]),
    value("StackName", &[]),
];

/// The common parameters of every cmdlet.
const COMMON: &[Param] = &[
    switch("Verbose", &["vb"]),
    switch("Debug", &["db"]),
    value("ErrorAction", &["ea"]),
    value("WarningAction", &["wa"]),
    value("InformationAction", &["infa"]),
    value("ProgressAction", &["proga"]),
    value("ErrorVariable", &["ev"]),
    value("WarningVariable", &["wv"]),
    value("InformationVariable", &["iv"]),
    value("OutVariable", &["ov"]),
    value("OutBuffer", &["ob"]),
    value("PipelineVariable", &["pv"]),
];

/// The common parameters of a cmdlet that supports `-WhatIf` (`New-Item` does).
const SHOULD_PROCESS: &[Param] = &[switch("WhatIf", &["wi"]), switch("Confirm", &["cf"])];

/// The cmdlet's own parameters and its common ones; `None` for a cmdlet not modelled.
fn cmdlet_params(cmdlet: &str) -> Option<(&'static [Param], Vec<&'static Param>)> {
    let lower = cmdlet.to_ascii_lowercase();
    let (own, should_process) = match lower.as_str() {
        "new-item" | "ni" => (NEW_ITEM, true),
        "set-location" | "sl" | "cd" | "chdir" | "push-location" | "pushd" => (SET_LOCATION, false),
        _ => return None,
    };
    let mut common: Vec<&'static Param> = COMMON.iter().collect();
    if should_process {
        common.extend(SHOULD_PROCESS.iter());
    }
    Some((own, common))
}

/// The dashes PowerShell starts a parameter with.
const DASHES: [char; 4] = ['-', '\u{2013}', '\u{2014}', '\u{2015}'];

/// A written word as PowerShell reads it: `-Name` or `-Name:value` is a parameter (a dash, then
/// a letter, `_` or `?`); `(name, inline value)`, the value `Some("")` for `-Name:` alone, which
/// takes the next word.
fn param_token(t: &str) -> Option<(&str, Option<&str>)> {
    let rest = t.strip_prefix(DASHES)?;
    if !rest.starts_with(|c: char| c.is_alphabetic() || c == '_' || c == '?') {
        return None;
    }
    Some(match rest.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    })
}

/// How PowerShell binds `written` (`-Ty`, `-ItemType:Junction`) for `cmdlet`: ignoring case, a
/// full name or alias first, then any prefix of a name or alias; when the prefix fits several
/// parameters and exactly one of them is the cmdlet's own (not a common one), that one.
pub fn pwsh_param(cmdlet: &str, written: &str) -> ParamMatch {
    match bind(cmdlet, written) {
        Bound::One(p) => ParamMatch::Exact(p.name),
        Bound::Ambiguous => ParamMatch::Ambiguous,
        Bound::None => ParamMatch::Unknown,
    }
}

enum Bound {
    One(&'static Param),
    Ambiguous,
    None,
}

fn bind(cmdlet: &str, written: &str) -> Bound {
    let Some((name, _)) = param_token(written) else {
        return Bound::None;
    };
    let Some((own, common)) = cmdlet_params(cmdlet) else {
        return Bound::None;
    };
    let lower = name.to_lowercase();
    let all: Vec<(&'static Param, bool)> = own
        .iter()
        .map(|p| (p, false))
        .chain(common.into_iter().map(|p| (p, true)))
        .collect();
    let spellings = |p: &'static Param| {
        std::iter::once(p.name)
            .chain(p.aliases.iter().copied())
            .map(str::to_lowercase)
    };
    if let Some((p, _)) = all.iter().find(|(p, _)| spellings(p).any(|s| s == lower)) {
        return Bound::One(p);
    }
    let fits: Vec<(&'static Param, bool)> = all
        .iter()
        .filter(|(p, _)| spellings(p).any(|s| s.starts_with(&lower)))
        .copied()
        .collect();
    match fits.as_slice() {
        [] => Bound::None,
        [(p, _)] => Bound::One(p),
        _ => match fits
            .iter()
            .filter(|(_, common)| !common)
            .collect::<Vec<_>>()[..]
        {
            [(p, _)] => Bound::One(p),
            _ => Bound::Ambiguous,
        },
    }
}

/// One argument of a PowerShell command, as the binder sees it.
enum PwshArg<'a> {
    /// `-Name value`, `-Name:value`, a switch: the parameter, its value (`None` for a switch
    /// written without one) and the index of the next argument.
    Param {
        name: &'static str,
        value: Option<PwshValue<'a>>,
        next: usize,
    },
    /// A positional value.
    Positional(&'a Word),
    /// A splat, or a variable or substitution where a parameter name may be: it may carry any
    /// parameter the command does not name itself.
    Opaque,
    /// An ambiguous or unknown parameter, or one without its value: PowerShell refuses the
    /// command, and the hook cannot tell how the rest binds.
    Unbound,
}

enum PwshValue<'a> {
    Word(&'a Word),
    /// The text after `-Name:`.
    Inline(String),
}

/// The argument at `i` of `cmdlet`'s `args`.
fn pwsh_arg<'a>(cmdlet: &str, args: &'a [Word], i: usize) -> PwshArg<'a> {
    let w = &args[i];
    let Some(t) = literal(w) else {
        return PwshArg::Opaque;
    };
    if w.quote == crate::ir::Quote::None && t.len() > 1 && t.starts_with('@') {
        return PwshArg::Opaque;
    }
    let Some((_, inline)) = param_token(&t) else {
        return PwshArg::Positional(w);
    };
    let Bound::One(p) = bind(cmdlet, &t) else {
        return PwshArg::Unbound;
    };
    match inline {
        Some(v) if !v.is_empty() => PwshArg::Param {
            name: p.name,
            value: Some(PwshValue::Inline(v.to_string())),
            next: i + 1,
        },
        None if p.switch => PwshArg::Param {
            name: p.name,
            value: None,
            next: i + 1,
        },
        // `-Name value`, and `-Name: value` (a switch too: `-Force: $false`).
        _ => match args.get(i + 1) {
            Some(v) => PwshArg::Param {
                name: p.name,
                value: Some(PwshValue::Word(v)),
                next: i + 2,
            },
            None => PwshArg::Unbound,
        },
    }
}

// ------------------------------------------------------------------ location

/// Candidate folders: the command may be in any of `known`, or somewhere unknown.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Dirs {
    known: Vec<String>,
    /// The command may be somewhere unknown, and why.
    unknown: Option<UnknownKind>,
}

impl Dirs {
    fn unknown(kind: UnknownKind) -> Dirs {
        Dirs {
            known: Vec::new(),
            unknown: Some(kind),
        }
    }

    fn union(&mut self, other: &Dirs) {
        for d in &other.known {
            if !self.known.contains(d) {
                self.known.push(d.clone());
            }
        }
        self.unknown = self.unknown.max(other.unknown);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pushed {
    dirs: Dirs,
    /// The push surely ran when the command reaches the matching pop.
    certain: bool,
}

/// Where the shell is while a command runs: tracks `cd`, `Set-Location`, `Push-Location`,
/// `Pop-Location` (and `git -C` through `for_git`). Feed it every statement in order with
/// `after`, after judging the statement's own commands; a body that runs later or more than
/// once starts from `inner`; a substitution starts from a clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    shell: Shell,
    os: Os,
    dirs: Dirs,
    /// Folders the command is back in when the current `&&` chain after a `cd` breaks.
    fallback: Dirs,
    stack: Vec<Pushed>,
    prev: Option<ChainOp>,
    /// A drive letter may have been mapped elsewhere (`subst`, `New-PSDrive`, `net use`).
    remapped: bool,
    /// Links an earlier statement creates: the walk cannot see them before the command runs.
    new_links: Vec<String>,
    /// An earlier statement creates a link at a place the hook cannot tell.
    new_link_unknown: bool,
}

/// The path a link-creating command makes: `mklink`, `New-Item -ItemType Junction|SymbolicLink|
/// HardLink`, `ln -s`. `Some(None)`: a link at a place the hook cannot tell.
fn created_link(c: &SimpleCommand) -> Option<Option<Word>> {
    match unwrap(c) {
        Run::Cmd { name, args, .. } => link_made(&name, args),
        Run::Nothing => None,
        run => run.may_be(&LINK_COMMANDS).then_some(None),
    }
}

const LINK_COMMANDS: [&str; 4] = ["mklink", "ln", "new-item", "ni"];

/// `created_link` for the command `name` run with `args`.
fn link_made(name: &str, args: &[Word]) -> Option<Option<Word>> {
    let lit_args: Vec<Option<String>> = args.iter().map(literal).collect();
    match name {
        "mklink" => Some(
            args.iter()
                .zip(&lit_args)
                .find(|(_, t)| !t.as_deref().is_some_and(|t| t.starts_with('/')))
                .map(|(w, _)| w.clone()),
        ),
        "ln" => {
            let long = |t: &str, full: &str| t.len() > 2 && full.starts_with(t);
            let short = |t: &str| t.starts_with('-') && !t.starts_with("--") && t.len() > 1;
            // A variable, substitution or glob may carry `-s` and `-t`; `~` cannot.
            if args.iter().any(|w| {
                w.parts
                    .iter()
                    .any(|p| !matches!(p, WordPart::Literal(_) | WordPart::Tilde))
            }) {
                return Some(None);
            }
            let symbolic = lit_args
                .iter()
                .flatten()
                .any(|t| long(t, "--symbolic") || (short(t) && t.contains('s')));
            if !symbolic {
                return None;
            }
            // Options beyond these (`-t`, `--target-directory`, `--suffix`, …) put the link
            // somewhere this code does not follow.
            let modelled = |t: &str| {
                t == "--"
                    || (short(t) && t[1..].chars().all(|c| "sfnvi".contains(c)))
                    || [
                        "--symbolic",
                        "--force",
                        "--no-dereference",
                        "--verbose",
                        "--interactive",
                    ]
                    .iter()
                    .any(|full| long(t, full))
            };
            if lit_args
                .iter()
                .flatten()
                .any(|t| t.starts_with('-') && t != "-" && !modelled(t))
            {
                return Some(None);
            }
            let names: Vec<&Word> = args
                .iter()
                .zip(&lit_args)
                .filter(|(_, t)| !t.as_deref().is_some_and(|t| t.starts_with('-')))
                .map(|(w, _)| w)
                .collect();
            Some(if names.len() >= 2 {
                names.last().map(|w| (*w).clone())
            } else {
                None
            })
        }
        "new-item" | "ni" => new_item_link(args),
        _ => None,
    }
}

/// `created_link` for `New-Item`, its parameters bound as PowerShell binds them.
fn new_item_link(args: &[Word]) -> Option<Option<Word>> {
    // The item type: `None` when not given, `Some(None)` when not static.
    let mut kind: Option<Option<String>> = None;
    let mut path: Option<Word> = None;
    // `-Name`, an extra positional value: the link is not where `path` says.
    let mut elsewhere = false;
    // A splat or a variable may carry `-ItemType Junction` or `-Path`.
    let mut opaque = false;
    // A parameter the hook cannot bind: it cannot tell what the rest means.
    let mut unbound = false;
    let mut i = 0;
    while i < args.len() {
        match pwsh_arg("new-item", args, i) {
            PwshArg::Param { name, value, next } => {
                let text = |v: &Option<PwshValue>| match v {
                    Some(PwshValue::Inline(t)) => Some(t.clone()),
                    Some(PwshValue::Word(w)) => literal(w),
                    None => None,
                };
                match name {
                    "ItemType" => kind = Some(text(&value).map(|k| k.to_ascii_lowercase())),
                    "Path" => {
                        path = match value {
                            Some(PwshValue::Word(w)) => Some(w.clone()),
                            Some(PwshValue::Inline(t)) => Some(Word {
                                parts: vec![WordPart::Literal(t)],
                                span: args[i].span,
                                quote: args[i].quote,
                            }),
                            None => None,
                        }
                    }
                    "Name" => elsewhere = true,
                    _ => {}
                }
                i = next;
            }
            PwshArg::Positional(w) => {
                if path.is_some() {
                    elsewhere = true;
                }
                path.get_or_insert_with(|| w.clone());
                i += 1;
            }
            PwshArg::Opaque => {
                opaque = true;
                i += 1;
            }
            PwshArg::Unbound => {
                unbound = true;
                i += 1;
            }
        }
    }
    if unbound {
        return Some(None);
    }
    match &kind {
        // A second `-ItemType` from a splat would be a binding error.
        Some(Some(k)) if is_folder_or_file_type(k) => None,
        _ if opaque || elsewhere => Some(None),
        Some(_) => Some(path),
        // No `-ItemType`: a file.
        None => None,
    }
}

/// An `-ItemType` value (lowercased) that is provably `Directory` or `File`: the provider takes
/// any prefix, so `dir` and `f` count; anything else (a wildcard included) may be a link type.
fn is_folder_or_file_type(t: &str) -> bool {
    !t.is_empty() && ("directory".starts_with(t) || "file".starts_with(t))
}

/// `subst`, `New-PSDrive`, `net use`: after them a drive letter may name another folder.
fn remaps_drives(c: &SimpleCommand) -> bool {
    let (name, args) = match unwrap(c) {
        Run::Cmd { name, args, .. } => (name, args),
        Run::Nothing => return false,
        run => return run.may_be(&REMAP_COMMANDS),
    };
    match name.as_str() {
        "net" | "net1" => args
            .first()
            .and_then(literal)
            .is_some_and(|a| a.eq_ignore_ascii_case("use")),
        n => REMAP_COMMANDS.contains(&n),
    }
}

/// The commands that map a drive letter (`net` and `net1` only with `use`).
const REMAP_COMMANDS: [&str; 9] = [
    "subst",
    "new-psdrive",
    "ndr",
    "mount",
    "mountvol",
    "new-smbmapping",
    "diskpart",
    "net",
    "net1",
];

impl Location {
    pub fn new(shell: Shell, os: Os, cwd: Option<&Path>) -> Location {
        let dirs = match cwd.map(|c| Canon::parse(&c.to_string_lossy(), os)) {
            Some(c) if c.rooted && (os == Os::Posix || !c.prefix.is_empty()) => Dirs {
                known: vec![c.render()],
                unknown: None,
            },
            _ => Dirs::unknown(UnknownKind::MayBeCritical),
        };
        Location {
            shell,
            os,
            dirs,
            fallback: Dirs::default(),
            stack: Vec::new(),
            prev: None,
            remapped: false,
            new_links: Vec::new(),
            new_link_unknown: false,
        }
    }

    pub fn shell(&self) -> Shell {
        self.shell
    }

    pub fn os(&self) -> Os {
        self.os
    }

    /// The candidate folders, `None` when one of them is unknown.
    pub fn dirs(&self) -> Option<Vec<PathBuf>> {
        if self.dirs.unknown.is_some() {
            return None;
        }
        Some(self.dirs.known.iter().map(PathBuf::from).collect())
    }

    /// The kind of an unknown `fail` gives, read in this location.
    fn kind_of(&self, fail: Fail) -> UnknownKind {
        match fail {
            Fail::Dynamic => UnknownKind::Dynamic,
            Fail::Unknown | Fail::NotAFile => UnknownKind::MayBeCritical,
            // A known candidate is dropped with the unknown one (`cd $x; rm -rf ..` from the
            // repo root), and it may be critical.
            Fail::NoLocation if !self.dirs.known.is_empty() => UnknownKind::MayBeCritical,
            Fail::NoLocation => self.dirs.unknown.unwrap_or(UnknownKind::MayBeCritical),
        }
    }

    fn with_dirs(&self, dirs: Dirs) -> Location {
        Location {
            dirs,
            fallback: Dirs::default(),
            prev: None,
            ..self.clone()
        }
    }

    /// Advance past `stmt`.
    pub fn after(&mut self, stmt: &Stmt, env: &EnvView) {
        let mut remap = false;
        let mut links: Vec<Option<Word>> = Vec::new();
        visit_stmt(stmt, &mut |n| match n {
            Node::Cmd(c) => {
                remap |= remaps_drives(c);
                links.extend(created_link(c));
            }
            Node::Method(m) => {
                let method = m.method.to_ascii_lowercase();
                if method.starts_with("createsymboliclink") || method == "createjunction" {
                    links.push(None);
                }
            }
            Node::Loop(_) => {}
        });
        self.remapped |= remap;
        for l in links {
            let d = match l {
                Some(w) => self.dir_from_word(&w, env),
                None => Dirs::unknown(UnknownKind::MayBeCritical),
            };
            self.new_link_unknown |= d.unknown.is_some();
            self.new_links.extend(d.known);
        }
        match stmt {
            Stmt::Pipeline(p) => self.after_pipeline(p, env),
            Stmt::Loop { body, .. } | Stmt::Func { body, .. } | Stmt::Block(body) => {
                self.after_nested(changes_location(body))
            }
            Stmt::Cond { branches, .. } => self.after_nested(branches.iter().any(changes_location)),
        }
    }

    fn after_nested(&mut self, changes: bool) {
        if changes {
            self.dirs = Dirs::unknown(UnknownKind::MayBeCritical);
        }
        self.end_chain(Some(ChainOp::Seq));
    }

    fn end_chain(&mut self, op: Option<ChainOp>) {
        if op != Some(ChainOp::And) {
            let fb = std::mem::take(&mut self.fallback);
            self.dirs.union(&fb);
        }
        self.prev = op;
    }

    fn after_pipeline(&mut self, p: &Pipeline, env: &EnvView) {
        let before = self.dirs.clone();
        let single = p.elems.len() == 1;
        let certain = single && p.chain == Some(ChainOp::And) && self.prev != Some(ChainOp::Or);
        let mut changed: Option<Dirs> = None;
        for e in &p.elems {
            if let Elem::Cmd(c) = e
                && let Some(d) = self.apply(c, env, certain)
            {
                changed.get_or_insert_with(Dirs::default).union(&d);
            }
        }
        if p.elems.iter().any(elem_nests_location_change) {
            changed = Some(Dirs::unknown(UnknownKind::MayBeCritical));
        }
        if let Some(new) = changed {
            if certain {
                self.fallback.union(&before);
                self.dirs = new;
            } else {
                self.dirs = new;
                self.dirs.union(&before);
            }
        }
        self.end_chain(p.chain);
    }

    /// The location a nested body starts at: unknown for a function (it runs later) and for
    /// a loop whose body moves (the next pass starts where the last one ended).
    pub fn inner(&self, stmt: &Stmt) -> Location {
        match stmt {
            Stmt::Func { .. } => self.with_dirs(Dirs::unknown(UnknownKind::MayBeCritical)),
            Stmt::Loop { body, .. } if changes_location(body) => {
                self.with_dirs(Dirs::unknown(UnknownKind::MayBeCritical))
            }
            _ => self.with_dirs(self.dirs.clone()),
        }
    }

    /// The location `git` runs in, after its `-C` options.
    pub fn for_git(&self, cmd: &SimpleCommand, env: &EnvView) -> Location {
        let mut loc = self.with_dirs(self.dirs.clone());
        let args = &cmd.args;
        let mut i = 0;
        while i < args.len() {
            let Some(t) = literal(&args[i]) else {
                return loc.with_dirs(Dirs::unknown(UnknownKind::Dynamic));
            };
            if !t.starts_with('-') {
                break;
            }
            match t.as_str() {
                "-C" => {
                    let d = match args.get(i + 1) {
                        Some(w) => loc.dir_from_word(w, env),
                        None => Dirs::unknown(UnknownKind::MayBeCritical),
                    };
                    loc.dirs = d;
                    i += 2;
                }
                "-c" | "--namespace" | "--config-env" => i += 2,
                "--git-dir" | "--work-tree" => {
                    return loc.with_dirs(Dirs::unknown(UnknownKind::MayBeCritical));
                }
                _ if t.starts_with("--git-dir=") || t.starts_with("--work-tree=") => {
                    return loc.with_dirs(Dirs::unknown(UnknownKind::MayBeCritical));
                }
                _ => i += 1,
            }
        }
        loc
    }

    /// The folders after `c` when it changes the location, else `None`.
    fn apply(&mut self, c: &SimpleCommand, env: &EnvView, certain: bool) -> Option<Dirs> {
        if c.opaque {
            return Some(Dirs::unknown(UnknownKind::Dynamic));
        }
        let unknown = Some(Dirs::unknown(UnknownKind::MayBeCritical));
        let run = unwrap(c);
        let (name, args) = match run {
            Run::Nothing => return None,
            // A wrapper that runs something unread in this shell may move it.
            Run::Unread { in_shell, .. } => {
                return if in_shell && run.may_be(&LOCATION_COMMANDS) {
                    unknown
                } else {
                    None
                };
            }
            Run::Cmd {
                name,
                raw,
                args,
                wrapped,
                in_shell,
            } => {
                if !LOCATION_COMMANDS.contains(&name.as_str()) {
                    return None;
                }
                let pwsh = matches!(self.shell, Shell::Pwsh | Shell::Powershell5);
                // `.\cd.exe`, `/usr/bin/cd`, `env cd`: not the builtin, but nothing proves
                // what it does.
                if raw != name || (wrapped && (pwsh || !in_shell)) {
                    return unknown;
                }
                (name, args)
            }
        };
        match name.as_str() {
            "cd" | "chdir" | "sl" | "set-location" => {
                Some(self.set_location(&name, args, env, false))
            }
            "pushd" | "push-location" => {
                let to = self.set_location(&name, args, env, true);
                self.stack.push(Pushed {
                    dirs: self.dirs.clone(),
                    certain,
                });
                Some(to)
            }
            "popd" | "pop-location" => Some(match (args.is_empty(), self.stack.pop()) {
                (
                    true,
                    Some(Pushed {
                        dirs,
                        certain: true,
                    }),
                ) => dirs,
                _ => Dirs::unknown(UnknownKind::MayBeCritical),
            }),
            "source" | "." | "eval" | "invoke-expression" | "iex" => {
                Some(Dirs::unknown(UnknownKind::MayBeCritical))
            }
            _ => None,
        }
    }

    fn set_location(&self, name: &str, args: &[Word], env: &EnvView, push: bool) -> Dirs {
        let pwsh = matches!(self.shell, Shell::Pwsh | Shell::Powershell5);
        let path = if pwsh {
            pwsh_location_arg(name, args)
        } else {
            bash_location_arg(args, push)
        };
        match path {
            LocArg::Word(w) => {
                let wild = w.parts.iter().any(|p| match p {
                    WordPart::Glob(_) => true,
                    WordPart::Literal(s) => pwsh && s.contains(['*', '?', '[']),
                    _ => false,
                });
                // Bash looks a relative name up in CDPATH first.
                let searched =
                    !pwsh && !w.parts.first().is_some_and(|p| *p == WordPart::Tilde) && {
                        // The literal text the word starts with, and whether anything follows it.
                        let lits = w
                            .parts
                            .iter()
                            .take_while(|p| matches!(p, WordPart::Literal(_)))
                            .count();
                        let head: String = w.parts[..lits]
                            .iter()
                            .map(|p| match p {
                                WordPart::Literal(s) => s.as_str(),
                                _ => "",
                            })
                            .collect();
                        let whole = lits == w.parts.len();
                        !(head.starts_with('/')
                            || head.starts_with("./")
                            || head.starts_with("../")
                            || (whole && (head == "." || head == "..")))
                    };
                let cdpath = env.get(CDPATH_SEEN).is_some() || env.is_assigned("CDPATH");
                if wild || (searched && cdpath) {
                    Dirs::unknown(UnknownKind::MayBeCritical)
                } else {
                    self.dir_from_word(w, env)
                }
            }
            LocArg::Text(t) => {
                if pwsh && t.contains(['*', '?', '[']) {
                    Dirs::unknown(UnknownKind::MayBeCritical)
                } else {
                    self.dir_from_segs(&[Seg::lit(&t)], env)
                }
            }
            LocArg::LiteralText(t) => self.dir_from_segs(&[Seg::lit(&t)], env),
            LocArg::Home => match env.home() {
                Some(h) => self.dir_from_segs(&[Seg::lit(h)], env),
                // `HOME` is assigned in the command.
                None => Dirs::unknown(UnknownKind::Dynamic),
            },
            LocArg::Unknown => Dirs::unknown(UnknownKind::MayBeCritical),
        }
    }

    fn dir_from_word(&self, w: &Word, env: &EnvView) -> Dirs {
        let mut out = Dirs::default();
        for base in self.bases() {
            match expand(w, env, self.shell, base) {
                Ok(segs) => {
                    let text: String = segs.iter().map(|s| s.text.as_str()).collect();
                    match absolutize(&text, base, self.shell, self.os, env) {
                        Ok(p) => out.union(&Dirs {
                            known: vec![p],
                            unknown: None,
                        }),
                        Err(f) => return Dirs::unknown(self.kind_of(f)),
                    }
                }
                Err(f) => return Dirs::unknown(self.kind_of(f)),
            }
        }
        out
    }

    fn dir_from_segs(&self, segs: &[Seg], env: &EnvView) -> Dirs {
        let text: String = segs.iter().map(|s| s.text.as_str()).collect();
        let mut out = Dirs::default();
        for base in self.bases() {
            match absolutize(&text, base, self.shell, self.os, env) {
                Ok(p) => out.union(&Dirs {
                    known: vec![p],
                    unknown: None,
                }),
                Err(f) => return Dirs::unknown(self.kind_of(f)),
            }
        }
        out
    }

    /// Every candidate folder; `None` stands for the unknown one.
    fn bases(&self) -> Vec<Option<&str>> {
        let mut v: Vec<Option<&str>> = self.dirs.known.iter().map(|d| Some(d.as_str())).collect();
        if self.dirs.unknown.is_some() {
            v.push(None);
        }
        v
    }
}

enum LocArg<'a> {
    Word(&'a Word),
    /// An inline `-Path:value`.
    Text(String),
    /// An inline `-LiteralPath:value`.
    LiteralText(String),
    Home,
    Unknown,
}

fn bash_location_arg(args: &[Word], push: bool) -> LocArg<'_> {
    let mut rest = args;
    while let Some(first) = rest.first() {
        let Some(t) = literal(first) else { break };
        if t == "--" {
            rest = &rest[1..];
            break;
        }
        // `-P` is left out: `cd -P` resolves `..` after links, so it falls to Unknown below.
        if t.len() > 1 && t.starts_with('-') && t[1..].chars().all(|c| "Le@".contains(c)) && !push {
            rest = &rest[1..];
            continue;
        }
        break;
    }
    match rest {
        [] if !push => LocArg::Home,
        [w] => match literal(w) {
            Some(t) if t == "-" || t.starts_with('-') || t.starts_with('+') => LocArg::Unknown,
            _ => LocArg::Word(w),
        },
        _ => LocArg::Unknown,
    }
}

/// The folder `Set-Location`/`Push-Location` (as `cmdlet`) goes to, its parameters bound as
/// PowerShell binds them; any parameter but these four makes it unknown.
fn pwsh_location_arg<'a>(cmdlet: &str, args: &'a [Word]) -> LocArg<'a> {
    let mut found: Option<LocArg> = None;
    let mut i = 0;
    while i < args.len() {
        let value = match pwsh_arg(cmdlet, args, i) {
            PwshArg::Param { name, value, next } => {
                i = next;
                match (name, value) {
                    ("PassThru" | "StackName", _) => continue,
                    ("Path", Some(PwshValue::Inline(t))) => LocArg::Text(t),
                    ("LiteralPath", Some(PwshValue::Inline(t))) => LocArg::LiteralText(t),
                    ("Path" | "LiteralPath", Some(PwshValue::Word(w))) => LocArg::Word(w),
                    _ => return LocArg::Unknown,
                }
            }
            PwshArg::Positional(w) => {
                i += 1;
                match literal(w).as_deref() {
                    Some("-") | Some("+") => return LocArg::Unknown,
                    _ => LocArg::Word(w),
                }
            }
            // A variable is a positional value: it resolves as a dynamic word.
            PwshArg::Opaque if literal(&args[i]).is_none() => {
                i += 1;
                LocArg::Word(&args[i - 1])
            }
            PwshArg::Opaque | PwshArg::Unbound => return LocArg::Unknown,
        };
        if found.replace(value).is_some() {
            return LocArg::Unknown;
        }
    }
    found.unwrap_or(LocArg::Unknown)
}

/// The command name as the dialect resolves it, lowercased, without its folder and without
/// `.exe` / `.com` (`C:\Windows\System32\SUBST.EXE` → `subst`).
fn command_name(c: &SimpleCommand) -> String {
    base_name(&raw_name(c))
}

/// The command name as the dialect resolves it, lowercased, with its folder.
fn raw_name(c: &SimpleCommand) -> String {
    c.canonical
        .as_deref()
        .unwrap_or(&c.typed)
        .to_ascii_lowercase()
}

/// `raw` (lowercased) without its folder and without `.exe` / `.com`.
fn base_name(raw: &str) -> String {
    let name = raw.to_string();
    let base = name.rsplit(['\\', '/']).next().unwrap_or(&name);
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".com"))
        .unwrap_or(base);
    if base.is_empty() {
        name
    } else {
        base.to_string()
    }
}

/// The word's text when it is one literal.
fn literal(w: &Word) -> Option<String> {
    let mut out = String::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) => out.push_str(s),
            _ => return None,
        }
    }
    Some(out)
}

// ------------------------------------------------------------------ wrappers

/// What a command runs once the wrappers in front of it are read (the delete guard's list plus
/// `builtin`): `builtin`, `command` and `time` run it in this shell, `env`, `sudo`, `nohup` and
/// `exec` start it as a program; `Start-Process` is never read, only its words.
enum Run<'a> {
    Cmd {
        /// `command_name` of the command run.
        name: String,
        /// Its name as written, lowercased (`raw_name`).
        raw: String,
        args: &'a [Word],
        /// A wrapper was in front of it.
        wrapped: bool,
        /// Every wrapper in front runs it in this shell.
        in_shell: bool,
    },
    /// `command -v X`: describes X and runs nothing.
    Nothing,
    /// A wrapper whose command the hook cannot read (an option it does not model, a name that
    /// is not a literal): any word of `rest` may be that command or its arguments; with `any`,
    /// it may be any command.
    Unread {
        rest: &'a [Word],
        in_shell: bool,
        any: bool,
    },
}

const WRAPPERS: [&str; 7] = ["builtin", "command", "time", "env", "sudo", "nohup", "exec"];

/// `Start-Process` and its aliases, the delete guard's last wrapper.
const START_PROCESS: [&str; 3] = ["start-process", "saps", "start"];

/// `c` with its wrappers read.
fn unwrap(c: &SimpleCommand) -> Run<'_> {
    let mut name = command_name(c);
    let mut raw = raw_name(c);
    let mut args: &[Word] = &c.args;
    let mut wrapped = false;
    let mut in_shell = true;
    // `Start-Process ln -ArgumentList '…'`: a program with arguments the reader does not parse.
    if START_PROCESS.contains(&name.as_str()) {
        return Run::Unread {
            rest: args,
            in_shell: false,
            any: false,
        };
    }
    while WRAPPERS.contains(&name.as_str()) {
        let wrapper = std::mem::take(&mut name);
        wrapped = true;
        // `/usr/bin/command` is a program, not the builtin.
        in_shell &= raw == wrapper && matches!(wrapper.as_str(), "builtin" | "command" | "time");
        let start = args;
        // Skip the wrapper's options (and `env`'s and `sudo`'s `NAME=value` words).
        loop {
            let Some(first) = args.first() else {
                return Run::Nothing;
            };
            let Some(t) = literal(first) else { break };
            if t == "--" {
                args = &args[1..];
                break;
            }
            let assigns = matches!(wrapper.as_str(), "env" | "sudo");
            if assigns && !t.starts_with('-') && t.contains('=') {
                args = &args[1..];
                continue;
            }
            if !t.starts_with('-') {
                break;
            }
            let flags = &t[1..];
            let short = |set: &str| !flags.is_empty() && flags.chars().all(|f| set.contains(f));
            match wrapper.as_str() {
                "command" if short("pvV") => {
                    if flags.contains(['v', 'V']) {
                        return Run::Nothing;
                    }
                    args = &args[1..];
                }
                "time" if t == "-p" => args = &args[1..],
                // `exec -a NAME` takes the next word.
                "exec" if short("cla") => {
                    let skip = if flags.contains('a') { 2 } else { 1 };
                    args = args.get(skip..).unwrap_or(&[]);
                }
                "env" if t == "-" || t == "-i" || t == "--ignore-environment" => args = &args[1..],
                "env" if t == "-u" => args = args.get(2..).unwrap_or(&[]),
                "env" if t.starts_with("--unset=") => args = &args[1..],
                // `env -S 'cd ..'`, `--split-string=…`, `--chdir`: env may run anything.
                _ => {
                    return Run::Unread {
                        rest: start,
                        in_shell,
                        any: wrapper == "env",
                    };
                }
            }
        }
        let Some(first) = args.first() else {
            return Run::Nothing;
        };
        let Some(t) = literal(first) else {
            return Run::Unread {
                rest: args,
                in_shell,
                any: false,
            };
        };
        raw = t.to_ascii_lowercase();
        name = base_name(&raw);
        args = &args[1..];
    }
    Run::Cmd {
        name,
        raw,
        args,
        wrapped,
        in_shell,
    }
}

impl Run<'_> {
    /// The command run is named `names`, or may be one of them (a word the hook cannot read
    /// counts).
    fn may_be(&self, names: &[&str]) -> bool {
        match self {
            Run::Cmd { name, .. } => names.contains(&name.as_str()),
            Run::Nothing => false,
            Run::Unread { any: true, .. } => true,
            // A word may hold a whole command (`sh -c 'ln -s …'`).
            Run::Unread { rest, .. } => rest.iter().any(|w| match literal(w) {
                Some(t) => t
                    .split_whitespace()
                    .any(|t| names.contains(&base_name(&t.to_ascii_lowercase()).as_str())),
                None => true,
            }),
        }
    }
}

const LOCATION_COMMANDS: [&str; 13] = [
    "cd",
    "chdir",
    "sl",
    "set-location",
    "pushd",
    "push-location",
    "popd",
    "pop-location",
    "source",
    ".",
    "eval",
    "invoke-expression",
    "iex",
];

fn is_location_command(c: &SimpleCommand) -> bool {
    c.opaque || unwrap(c).may_be(&LOCATION_COMMANDS)
}

/// True when anything in `s` (nested bodies and substitutions included) may move.
fn changes_location(s: &Script) -> bool {
    let mut hit = false;
    visit_script(s, &mut |n| {
        if let Node::Cmd(c) = n {
            hit |= is_location_command(c);
        }
    });
    hit
}

fn elem_nests_location_change(e: &Elem) -> bool {
    let words: Vec<&Word> = match e {
        Elem::Cmd(c) => cmd_words(c),
        Elem::Method(m) => m.args.iter().collect(),
        Elem::Expr(w) => vec![w],
    };
    words
        .iter()
        .flat_map(|w| word_scripts(w))
        .any(changes_location)
}

// ------------------------------------------------------------------ IR visiting

enum Node<'a> {
    Cmd(&'a SimpleCommand),
    Method(&'a crate::ir::MethodCall),
    Loop(Span),
}

fn cmd_words(c: &SimpleCommand) -> Vec<&Word> {
    std::iter::once(&c.name)
        .chain(c.args.iter())
        .chain(c.redirects.iter().map(|r| &r.target))
        .chain(c.assigns.iter().map(|(_, w)| w))
        .collect()
}

fn word_scripts(w: &Word) -> impl Iterator<Item = &Script> {
    w.parts.iter().filter_map(|p| match p {
        WordPart::Subst(s) | WordPart::Block(s) => Some(s.as_ref()),
        _ => None,
    })
}

fn visit_script<'a>(s: &'a Script, f: &mut dyn FnMut(Node<'a>)) {
    for st in &s.stmts {
        visit_stmt(st, f);
    }
}

fn visit_stmt<'a>(st: &'a Stmt, f: &mut dyn FnMut(Node<'a>)) {
    match st {
        Stmt::Pipeline(p) => {
            for e in &p.elems {
                let words: Vec<&Word> = match e {
                    Elem::Cmd(c) => {
                        f(Node::Cmd(c));
                        cmd_words(c)
                    }
                    Elem::Method(m) => {
                        f(Node::Method(m));
                        m.args.iter().collect()
                    }
                    Elem::Expr(w) => vec![w],
                };
                for w in words {
                    for s in word_scripts(w) {
                        visit_script(s, f);
                    }
                }
            }
        }
        Stmt::Loop { body, span } => {
            f(Node::Loop(*span));
            visit_script(body, f);
        }
        Stmt::Cond { branches, .. } => {
            for b in branches {
                visit_script(b, f);
            }
        }
        Stmt::Func { body, .. } | Stmt::Block(body) => visit_script(body, f),
    }
}

// ------------------------------------------------------------------ environment

/// A key no shell variable can have: set when the hook's environment holds `CDPATH`.
const CDPATH_SEEN: &str = "\0cdpath";

/// The names the hook-vs-tool spike showed both tools see with the hook's value; any other
/// name stays dynamic until a spike row covers it.
const PLAIN_NAMES: [&str; 3] = ["USERPROFILE", "TEMP", "TMP"];

/// The variables a check may resolve, from the hook's own environment. On Windows `~` and
/// `$HOME` come from `USERPROFILE`, never from the hook's `HOME` (which neither tool shares);
/// `TMPDIR` exists only inside the Bash tool and never resolves. PowerShell environment
/// variables are named `env:NAME` and compare ignoring case.
pub fn env_view(shell: Shell, os: Os, vars: impl IntoIterator<Item = (String, String)>) -> EnvView {
    let vars: Vec<(String, String)> = vars.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let lookup = |name: &str| {
        vars.iter()
            .find(|(k, _)| {
                if os == Os::Windows {
                    k.eq_ignore_ascii_case(name)
                } else {
                    k == name
                }
            })
            .map(|(_, v)| v.as_str())
    };
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    let mut env = if pwsh {
        EnvView::case_insensitive()
    } else {
        EnvView::new()
    };
    let env_name = |n: &str| {
        if pwsh {
            format!("env:{n}")
        } else {
            n.to_string()
        }
    };
    let home = match os {
        Os::Windows => lookup("USERPROFILE"),
        Os::Posix => lookup("HOME"),
    };
    if let Some(h) = home {
        env.set_home(h);
        env.set("HOME", h);
        if os == Os::Posix {
            env.set(&env_name("HOME"), h);
        }
    }
    for n in PLAIN_NAMES {
        if let Some(v) = lookup(n) {
            env.set(&env_name(n), v);
        }
    }
    // Only so a relative `cd` knows bash may search it; `$CDPATH` itself never resolves.
    if !pwsh && lookup("CDPATH").is_some() {
        env.set(CDPATH_SEEN, "1");
    }
    env
}

/// Names the loop heuristic looks for in a loop's text.
const LOOP_NAMES: [&str; 7] = [
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
    "PWD",
];

/// Commands that write a PowerShell drive path (`env:X`, `variable:X`) they are given.
const PS_ITEM_WRITERS: [&str; 30] = [
    "set-item",
    "si",
    "new-item",
    "ni",
    "remove-item",
    "ri",
    "del",
    "erase",
    "rm",
    "rd",
    "rmdir",
    "clear-item",
    "cli",
    "set-content",
    "sc",
    "add-content",
    "ac",
    "clear-content",
    "clc",
    "rename-item",
    "rni",
    "ren",
    "move-item",
    "mi",
    "move",
    "mv",
    "copy-item",
    "cpi",
    "copy",
    "cp",
];

/// Mark every name the command may assign as dynamic: assignments, `env X=`, `export`,
/// `unset`, `read`, `$env:X =`, `Set-Item env:`, `[Environment]::SetEnvironmentVariable`, a
/// loop variable (found by name in the loop's text in `command`); `source`, `eval`, an opaque
/// command or a script call (PowerShell) may assign anything.
pub fn mark_assigned(env: &mut EnvView, script: &Script, command: &str) {
    visit_script(script, &mut |n| match n {
        Node::Cmd(c) => mark_command(env, c),
        Node::Method(m) => {
            let ty = m.type_name.to_ascii_lowercase();
            let ty = ty.strip_prefix("system.").unwrap_or(&ty);
            if ty == "environment" && m.method.eq_ignore_ascii_case("SetEnvironmentVariable") {
                match m.args.first().and_then(literal) {
                    Some(name) => {
                        env.mark_dynamic(&format!("env:{name}"));
                        env.mark_dynamic(&name);
                    }
                    None => env.mark_all_dynamic(),
                }
            }
        }
        Node::Loop(span) => match command.get(span.start..span.end) {
            Some(text) if !text.is_empty() => {
                let lower = text.to_ascii_lowercase();
                let mut names: Vec<String> = LOOP_NAMES.iter().map(|n| n.to_string()).collect();
                names.extend(xdg_names(text));
                for name in names {
                    if contains_word(&lower, &name.to_ascii_lowercase()) {
                        env.mark_dynamic(&name);
                        env.mark_dynamic(&format!("env:{name}"));
                    }
                }
            }
            _ => env.mark_all_dynamic(),
        },
    });
}

fn xdg_names(text: &str) -> Vec<String> {
    let upper = text.to_ascii_uppercase();
    let mut out = Vec::new();
    let mut rest = upper.as_str();
    while let Some(i) = rest.find("XDG_") {
        let tail = &rest[i..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

fn contains_word(hay: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    hay.match_indices(word).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + word.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

fn mark_command(env: &mut EnvView, c: &SimpleCommand) {
    for (name, _) in &c.assigns {
        env.mark_dynamic(name.trim_start_matches('$'));
    }
    // The command run, after wrappers (`builtin export X=…`); the names below are read from
    // every argument, the wrapper's included, which can only mark more of them.
    let name = match unwrap(c) {
        Run::Cmd { name, .. } => name,
        Run::Nothing => String::new(),
        Run::Unread { in_shell, .. } => {
            if in_shell {
                env.mark_all_dynamic();
                return;
            }
            String::new()
        }
    };
    if c.opaque
        || matches!(
            name.as_str(),
            "source" | "." | "eval" | "invoke-expression" | "iex"
        )
        || name.ends_with(".ps1")
    {
        env.mark_all_dynamic();
        return;
    }
    let args: Vec<Option<String>> = c.args.iter().map(literal).collect();
    let mark_names = |env: &mut EnvView, with_eq_only: bool| {
        for a in &args {
            match a {
                Some(t) if t.starts_with('-') => {}
                Some(t) => match t.split_once('=') {
                    Some((n, _)) => env.mark_dynamic(n),
                    None if !with_eq_only => env.mark_dynamic(t),
                    None => {}
                },
                None => env.mark_all_dynamic(),
            }
        }
    };
    match name.as_str() {
        "export" | "declare" | "typeset" | "local" | "readonly" | "unset" | "read" | "mapfile"
        | "readarray" | "getopts" | "printf" | "let" | "set-variable" | "sv" | "new-variable"
        | "nv" | "remove-variable" | "rv" | "clear-variable" | "clv" => mark_names(env, false),
        _ => {}
    }
    if command_name(c) == "env" {
        for (i, a) in args.iter().enumerate() {
            match a.as_deref() {
                Some("-u") | Some("--unset") => {
                    if let Some(Some(n)) = args.get(i + 1) {
                        env.mark_dynamic(n);
                    }
                }
                Some(t) if t.starts_with("--unset=") => env.mark_dynamic(&t[8..]),
                Some(t) if !t.starts_with('-') && t.contains('=') => {
                    env.mark_dynamic(t.split_once('=').map_or(t, |(n, _)| n));
                }
                _ => {}
            }
        }
    }
    let writer = PS_ITEM_WRITERS.contains(&name.as_str());
    for a in &args {
        match a {
            Some(t) => mark_drive_path(env, t),
            None if writer => env.mark_all_dynamic(),
            None => {}
        }
    }
}

/// `env:X`, `Env:\X`, `Environment::X`, `variable:X` as a PowerShell path argument.
fn mark_drive_path(env: &mut EnvView, t: &str) {
    let lower = t.to_ascii_lowercase();
    let lower = lower
        .strip_prefix("microsoft.powershell.core\\")
        .unwrap_or(&lower);
    let (kind, rest) = if let Some(r) = lower.strip_prefix("env:") {
        ("env:", r)
    } else if let Some(r) = lower.strip_prefix("environment::") {
        ("env:", r)
    } else if let Some(r) = lower.strip_prefix("variable:") {
        ("", r)
    } else {
        return;
    };
    let name = rest.trim_start_matches(['\\', '/']);
    if name.is_empty() || name.contains(['*', '?', '[']) {
        env.mark_all_dynamic();
    } else {
        env.mark_dynamic(&format!("{kind}{name}"));
    }
}

// ------------------------------------------------------------------ targets

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The absolute paths the word names (globs expanded; empty when nothing matches).
    Paths(Vec<PathBuf>),
    /// A part of the word cannot be known before the command runs.
    Dynamic(Span),
    /// A relative path where the location is unknown, or a path form the hook cannot place.
    UnknownLocation(UnknownKind),
    /// A path on a built-in PowerShell drive that is no file system (`Env:FOO`, `HKCU:\x`):
    /// no file target, so the delete rule leaves it to other rules.
    NotAFile,
    /// The deadline passed while expanding the word.
    Timeout,
}

/// Why a target is unknown, which decides its level. Ordered: where both apply,
/// `MayBeCritical` wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnknownKind {
    /// The location comes from a variable or substitution (`cd $x`): `dynamic-target`, like a
    /// dynamic word.
    Dynamic,
    /// The hook cannot tell which folder the path names, and it may be a drive root, the home
    /// folder or the repo root under another name: a share or volume path, a remapped drive, a
    /// tree an earlier statement links, a location the hook cannot follow. Reported as
    /// critical, so the allow marker cannot lower it.
    MayBeCritical,
}

#[derive(Debug, Clone)]
struct Seg {
    text: String,
    glob: bool,
}

impl Seg {
    fn lit(s: &str) -> Seg {
        Seg {
            text: s.to_string(),
            glob: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    Dynamic,
    /// A path the hook cannot place or compare.
    Unknown,
    /// A relative path, and the folder it is relative to is unknown: as unknown as that folder.
    NoLocation,
    /// A path on a built-in PowerShell drive that is no file system.
    NotAFile,
}

/// The built-in PowerShell drives whose provider is no file system.
const NON_FS_DRIVES: [&str; 8] = [
    "env", "variable", "function", "alias", "cert", "hkcu", "hklm", "wsman",
];

/// `text` is a path on one of `NON_FS_DRIVES` (`Env:FOO`, `hkcu:\x`).
fn on_non_fs_drive(text: &str) -> bool {
    text.split_once(':')
        .is_some_and(|(drive, _)| NON_FS_DRIVES.iter().any(|d| drive.eq_ignore_ascii_case(d)))
}

fn is_pwd(name: &str, shell: Shell) -> bool {
    match shell {
        Shell::Pwsh | Shell::Powershell5 => name.eq_ignore_ascii_case("PWD"),
        Shell::Bash(_) => name == "PWD",
    }
}

/// The word's segments; `PWD` is `pwd` (the candidate folder).
fn expand(w: &Word, env: &EnvView, shell: Shell, pwd: Option<&str>) -> Result<Vec<Seg>, Fail> {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    let mut out = Vec::new();
    for p in &w.parts {
        match p {
            WordPart::Literal(s) => {
                // PowerShell's -Path reads `*` and `?` as wildcards whatever the quoting.
                // The `?` of a `\\?\` prefix is no wildcard.
                let verbatim =
                    out.is_empty() && (s.starts_with("\\\\?\\") || s.starts_with("//?/"));
                let mut cur = String::new();
                for (i, ch) in s.chars().enumerate() {
                    if pwsh && matches!(ch, '*' | '?' | '[' | ']') && !(verbatim && i == 2) {
                        if !cur.is_empty() {
                            out.push(Seg::lit(&std::mem::take(&mut cur)));
                        }
                        out.push(Seg {
                            text: ch.to_string(),
                            glob: true,
                        });
                    } else {
                        cur.push(ch);
                    }
                }
                if !cur.is_empty() {
                    out.push(Seg::lit(&cur));
                }
            }
            WordPart::Glob(s) => out.push(Seg {
                text: s.clone(),
                glob: true,
            }),
            WordPart::Var(name) if is_pwd(name, shell) => {
                if env.is_assigned(name) {
                    return Err(Fail::Dynamic);
                }
                out.push(Seg::lit(pwd.ok_or(Fail::NoLocation)?));
            }
            WordPart::Var(name) => out.push(Seg::lit(env.get(name).ok_or(Fail::Dynamic)?)),
            WordPart::Tilde => out.push(Seg::lit(env.home().ok_or(Fail::Dynamic)?)),
            WordPart::Subst(_) | WordPart::Block(_) => return Err(Fail::Dynamic),
        }
    }
    Ok(out)
}

/// `text` as an absolute canonical path, resolved against `base` the way `shell` would.
fn absolutize(
    text: &str,
    base: Option<&str>,
    shell: Shell,
    os: Os,
    env: &EnvView,
) -> Result<String, Fail> {
    let pwsh = matches!(shell, Shell::Pwsh | Shell::Powershell5);
    let mut s = text.to_string();
    if pwsh {
        let lower = s.to_ascii_lowercase();
        for p in ["microsoft.powershell.core\\filesystem::", "filesystem::"] {
            if lower.starts_with(p) {
                s = s[p.len()..].to_string();
                break;
            }
        }
        if s == "~" || s.starts_with("~\\") || s.starts_with("~/") {
            s = format!("{}{}", env.home().ok_or(Fail::Dynamic)?, &s[1..]);
        }
    }
    let join = |base: Option<&str>, rel: &str| -> Result<String, Fail> {
        let b = base.ok_or(Fail::NoLocation)?;
        let sep = if os == Os::Windows { '\\' } else { '/' };
        Ok(canonical(&format!("{b}{sep}{rel}"), os))
    };
    if os == Os::Posix {
        return if s.starts_with('/') {
            Ok(canonical(&s, os))
        } else {
            join(base, &s)
        };
    }
    if matches!(shell, Shell::Bash(_)) && s.starts_with('/') && !s.starts_with("//") {
        let rest = s.trim_start_matches('/');
        if rest.is_empty() {
            return Ok("/".to_string());
        }
        let (first, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if first.len() == 1 && first.as_bytes()[0].is_ascii_alphabetic() {
            return Ok(canonical(
                &format!("{}:\\{tail}", first.to_ascii_uppercase()),
                os,
            ));
        }
        if first == "tmp" {
            let t = env.get("TEMP").ok_or(Fail::Unknown)?;
            return Ok(canonical(&format!("{t}\\{tail}"), os));
        }
        return Err(Fail::Unknown);
    }
    let c = Canon::parse(&s, os);
    if !c.prefix.is_empty() && c.rooted {
        return Ok(c.render());
    }
    if !c.prefix.is_empty() {
        // `C:x`: relative to the drive's own current folder.
        return Err(Fail::Unknown);
    }
    if c.rooted {
        // `\x`: the root of the current drive.
        let b = Canon::parse(base.ok_or(Fail::Unknown)?, os);
        return Ok(canonical(&format!("{}{s}", b.prefix), os));
    }
    // `HKCU:\x`, `Temp:\x`: a PowerShell drive.
    if let Some((drive, rest)) = s.split_once(':')
        && drive.len() > 1
        && drive.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        if pwsh && drive.eq_ignore_ascii_case("temp") {
            let t = env.get("env:TEMP").ok_or(Fail::Unknown)?;
            return Ok(canonical(&format!("{t}\\{rest}"), os));
        }
        return Err(Fail::Unknown);
    }
    join(base, &s)
}

/// What is left to do on the file system for one candidate.
#[derive(Debug, Clone)]
struct Plan {
    /// The absolute folder the glob components start from, or the whole path.
    base: String,
    /// Components after `base`, each a list of segments.
    comps: Vec<Vec<Seg>>,
    /// Folders none of whose ancestors may be a link: the text a bash `..` steps out of, which
    /// the system resolves after links, not lexically.
    link_free: Vec<String>,
}

/// Why a plan could not finish on the file system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanErr {
    Timeout,
    Unknown,
}

/// A path the hook cannot compare with the folders it protects: a mapped drive letter, any
/// UNC, volume or device path (a share may be this machine under any of its names), or an
/// NTFS stream form (`dir::$INDEX_ALLOCATION` is the folder itself).
fn is_alias(p: &str, loc: &Location) -> bool {
    if loc.os != Os::Windows || p == "/" {
        return false;
    }
    let c = Canon::parse(p, Os::Windows);
    loc.remapped || c.prefix.starts_with("\\\\") || c.comps.iter().any(|x| x.contains(':'))
}

/// The resolved folders each bash `..` in `text` steps out of.
fn dotdot_prefixes(
    text: &str,
    base: Option<&str>,
    loc: &Location,
    env: &EnvView,
) -> Result<Vec<String>, Fail> {
    if !matches!(loc.shell, Shell::Bash(_)) {
        return Ok(Vec::new());
    }
    let seps: &[char] = if loc.os == Os::Windows {
        &['\\', '/']
    } else {
        &['/']
    };
    let mut out = Vec::new();
    let mut start = 0;
    for piece in text.split(seps) {
        if piece == ".." {
            let prefix = &text[..start];
            let prefix = if prefix.is_empty() { "." } else { prefix };
            out.push(absolutize(prefix, base, loc.shell, loc.os, env)?);
        }
        start += piece.len() + 1;
    }
    Ok(out)
}

fn split_comps(segs: &[Seg], os: Os) -> Vec<Vec<Seg>> {
    let seps: &[char] = if os == Os::Windows {
        &['\\', '/']
    } else {
        &['/']
    };
    let mut comps: Vec<Vec<Seg>> = vec![Vec::new()];
    for s in segs {
        for (i, piece) in s.text.split(seps).enumerate() {
            if i > 0 {
                comps.push(Vec::new());
            }
            if !piece.is_empty() {
                comps.last_mut().expect("starts non-empty").push(Seg {
                    text: piece.to_string(),
                    glob: s.glob,
                });
            }
        }
    }
    comps
}

fn plan(segs: &[Seg], base: Option<&str>, loc: &Location, env: &EnvView) -> Result<Plan, Fail> {
    let text: String = segs.iter().map(|s| s.text.as_str()).collect();
    if matches!(loc.shell, Shell::Pwsh | Shell::Powershell5) && on_non_fs_drive(&text) {
        return Err(Fail::NotAFile);
    }
    let link_free = dotdot_prefixes(&text, base, loc, env)?;
    if !segs.iter().any(|s| s.glob) {
        let whole = absolutize(&text, base, loc.shell, loc.os, env)?;
        if is_alias(&whole, loc) {
            return Err(Fail::Unknown);
        }
        return Ok(Plan {
            base: whole,
            comps: Vec::new(),
            link_free,
        });
    }
    // The literal text before the component holding the first glob is resolved as a path.
    let comps = split_comps(segs, loc.os);
    let first = comps
        .iter()
        .position(|c| c.iter().any(|s| s.glob))
        .unwrap_or(0);
    let seps: &[char] = if loc.os == Os::Windows {
        &['\\', '/']
    } else {
        &['/']
    };
    let mut prefix = String::new();
    let mut count = 0;
    for ch in text.chars() {
        if count == first {
            break;
        }
        prefix.push(ch);
        if seps.contains(&ch) {
            count += 1;
        }
    }
    let prefix = if prefix.is_empty() {
        ".".to_string()
    } else {
        prefix
    };
    let start = absolutize(&prefix, base, loc.shell, loc.os, env)?;
    let stream = loc.os == Os::Windows
        && comps[first..]
            .iter()
            .any(|c| c.iter().any(|s| s.text.contains(':')));
    if (start == "/" && loc.os == Os::Windows) || is_alias(&start, loc) || stream {
        return Err(Fail::Unknown);
    }
    Ok(Plan {
        base: start,
        comps: comps[first..]
            .iter()
            .filter(|c| !c.is_empty())
            .cloned()
            .collect(),
        link_free,
    })
}

fn looks_short(p: &str) -> bool {
    p.split(['\\', '/']).any(|c| {
        c.find('~')
            .is_some_and(|i| c[i + 1..].starts_with(|ch: char| ch.is_ascii_digit()))
    })
}

fn run_plan(fs: &dyn Fs, p: &Plan, os: Os, deadline: &Deadline) -> Result<Vec<String>, PlanErr> {
    let sep = if os == Os::Windows { '\\' } else { '/' };
    for folder in &p.link_free {
        for a in Path::new(folder).ancestors() {
            if deadline.expired() {
                return Err(PlanErr::Timeout);
            }
            match fs.lstat(a) {
                Ok(m) if m.is_symlink => return Err(PlanErr::Unknown),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(PlanErr::Unknown),
            }
        }
    }
    let mut cur = vec![p.base.clone()];
    for comp in &p.comps {
        if deadline.expired() {
            return Err(PlanErr::Timeout);
        }
        let text: String = comp.iter().map(|s| s.text.as_str()).collect();
        if !comp.iter().any(|s| s.glob) {
            cur = cur.into_iter().map(|d| format!("{d}{sep}{text}")).collect();
            continue;
        }
        let pattern: String = comp
            .iter()
            .map(|s| {
                if s.glob {
                    s.text.clone()
                } else {
                    globset::escape(&s.text)
                }
            })
            .collect();
        let matcher = GlobBuilder::new(&pattern)
            .case_insensitive(os == Os::Windows)
            .literal_separator(true)
            .backslash_escape(false)
            .build()
            .map(|g| g.compile_matcher())
            .map_err(|_| PlanErr::Unknown)?;
        let mut next = Vec::new();
        for d in &cur {
            let entries = match fs.read_dir(Path::new(d)) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    Vec::new()
                }
                Err(_) => return Err(PlanErr::Unknown),
            };
            for e in entries {
                let Some(name) = e.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                    continue;
                };
                if matcher.is_match(&name) {
                    next.push(format!("{d}{sep}{name}"));
                }
            }
        }
        cur = next;
    }
    let mut out = Vec::new();
    for c in cur {
        let mut c = canonical(&c, os);
        if os == Os::Windows && looks_short(&c) {
            if deadline.expired() {
                return Err(PlanErr::Timeout);
            }
            if let Ok(long) = fs.long_path(Path::new(&c)) {
                c = canonical(&long.to_string_lossy(), os);
            }
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}

/// The paths `word` names for a delete, from every folder the command may be in.
pub fn target(
    word: &Word,
    loc: &Location,
    env: &EnvView,
    fs: &SharedFs,
    deadline: &Deadline,
) -> Target {
    let mut plans = Vec::new();
    for base in loc.bases() {
        let segs = match expand(word, env, loc.shell, base) {
            Ok(s) => s,
            Err(Fail::Dynamic) => return Target::Dynamic(word.span),
            Err(f) => return Target::UnknownLocation(loc.kind_of(f)),
        };
        if segs.iter().all(|s| s.text.is_empty()) {
            return Target::Paths(Vec::new());
        }
        match plan(&segs, base, loc, env) {
            Ok(p) => plans.push(p),
            Err(Fail::Dynamic) => return Target::Dynamic(word.span),
            // `New-PSDrive Env -PSProvider FileSystem` may have mapped the name to a folder.
            Err(Fail::NotAFile) if !loc.remapped => return Target::NotAFile,
            Err(f) => return Target::UnknownLocation(loc.kind_of(f)),
        }
    }
    let os = loc.os;
    let needs_fs = plans.iter().any(|p| {
        !p.comps.is_empty()
            || !p.link_free.is_empty()
            || (os == Os::Windows && looks_short(&p.base))
    });
    let paths = if needs_fs {
        let fs = Arc::clone(fs);
        let d = *deadline;
        let run = move || -> Result<Vec<String>, PlanErr> {
            let mut all = Vec::new();
            for p in &plans {
                for x in run_plan(fs.as_ref(), p, os, &d)? {
                    if !all.contains(&x) {
                        all.push(x);
                    }
                }
            }
            Ok(all)
        };
        match bounded(deadline, run) {
            Ok(Ok(v)) => v,
            Ok(Err(PlanErr::Unknown)) => {
                return Target::UnknownLocation(UnknownKind::MayBeCritical);
            }
            _ => return Target::Timeout,
        }
    } else {
        let mut all: Vec<String> = Vec::new();
        for p in plans {
            if !all.contains(&p.base) {
                all.push(p.base);
            }
        }
        all
    };
    if paths.iter().any(|p| loc.near_new_link(p)) {
        return Target::UnknownLocation(UnknownKind::MayBeCritical);
    }
    Target::Paths(paths.into_iter().map(PathBuf::from).collect())
}

impl Location {
    /// `p` holds a link an earlier statement creates, or lies beside one.
    fn near_new_link(&self, p: &str) -> bool {
        if self.new_link_unknown {
            return true;
        }
        let key = path_key(p, self.os);
        self.new_links.iter().any(|l| {
            let lk = path_key(l, self.os);
            let mut c = Canon::parse(l, self.os);
            let parent = c.comps.pop().map(|_| path_key(&c.render(), self.os));
            is_within(&lk, &key, self.os) || parent.is_some_and(|pk| is_within(&key, &pk, self.os))
        })
    }
}
