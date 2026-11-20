//! The program table (`data/programs.toml`) and the one walker the rules read it through.
//!
//! - `lookup` finds the row a typed name runs in a shell.
//! - `strip_wrappers` reads past `timeout`, `nice`, `env NAME=…`, `sudo`, `command` and `nohup` to
//!   the command they run.
//! - `commands` lists every simple command of a script, nested ones included.
//!
//! Rule code names no program and no option: it asks the table (`tests/shape.rs`).

use std::borrow::Cow;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::ir::{Elem, EnvView, Redirect, Script, SimpleCommand, Stmt, Word, WordPart};
use crate::level::Span;
use crate::{BashProfile, Os, Shell};

#[cfg(test)]
const TABLE_TEXT: &str = include_str!("../data/programs.toml");

/// The most wrappers `strip_wrappers` reads through (`sudo timeout 5 nice …`).
const MAX_WRAPPERS: usize = 16;

/// What a program is to the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Runs the rest of its words as a command.
    Wrapper,
    /// A native Windows program that takes Linux paths, which Git Bash rewrites.
    NativeMsys,
    /// Deletes or discards data.
    Delete,
    /// Runs its argument text as code.
    Eval,
    /// A shell.
    Shell,
    /// Waits on a prompt, a pager, stdin, a tty or a server.
    Interactive,
    /// A launcher script (`.bat`) that runs another program.
    Launcher,
}

/// How a program reads backslashes in its own arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Escapes {
    /// Always (`printf`).
    Always,
    /// Only with one of `escape_options` (`echo -e`).
    Option,
}

/// Further names of a program, per shell.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aliases {
    #[serde(default)]
    pub bash: Vec<String>,
    #[serde(default)]
    pub pwsh_windows: Vec<String>,
    #[serde(default)]
    pub pwsh_posix: Vec<String>,
}

/// One `[[program]]` row.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Program {
    pub name: String,
    /// `"bash"`, `"pwsh"`; empty means both.
    #[serde(default)]
    pub shells: Vec<String>,
    #[serde(default)]
    pub aliases: Aliases,
    #[serde(default)]
    pub kind: Vec<Kind>,
    /// Options that take the next word as their value.
    #[serde(default)]
    pub value_options: Vec<String>,
    /// The Fix line text a rule about this program prints.
    #[serde(default)]
    pub fix: Option<String>,
    /// Wrapper: words before the wrapped command that are not options (`timeout DURATION`).
    #[serde(default)]
    pub operands: usize,
    /// Wrapper: `NAME=value` words before the command are assignments to it (`env`, `sudo`).
    #[serde(default)]
    pub assignments: bool,
    /// Wrapper: with one of these it runs nothing (`command -v x`).
    #[serde(default)]
    pub no_run_options: Vec<String>,
    #[serde(default)]
    pub escapes: Option<Escapes>,
    /// For `Escapes::Option`: the options that turn escapes on.
    #[serde(default)]
    pub escape_options: Vec<String>,
    /// cmd.exe spellings of options that break in this shell (`cd /d`).
    #[serde(default)]
    pub cmd_options: Vec<String>,
    /// Every key this reader does not know, for the task that reads it.
    #[serde(flatten)]
    pub extra: toml::Table,
}

impl Program {
    pub fn is(&self, kind: Kind) -> bool {
        self.kind.contains(&kind)
    }

    /// Whether the row applies in `shell`.
    pub fn applies(&self, shell: Shell) -> bool {
        self.shells.is_empty() || self.shells.iter().any(|s| s == family(shell))
    }

    /// The row's name and its aliases for `shell` and `os`.
    pub fn names(&self, shell: Shell, os: Os) -> impl Iterator<Item = &str> {
        let aliases = match shell {
            Shell::Bash(_) => &self.aliases.bash,
            Shell::Pwsh | Shell::Powershell5 if os == Os::Windows => &self.aliases.pwsh_windows,
            Shell::Pwsh | Shell::Powershell5 => &self.aliases.pwsh_posix,
        };
        std::iter::once(self.name.as_str()).chain(aliases.iter().map(String::as_str))
    }

    /// Whether `word` (a static argument) is `option` or, for a one-letter `-x`, a short cluster
    /// holding its letter (`-ne` for `-e`).
    pub fn option_matches(word: &str, option: &str) -> bool {
        if word == option {
            return true;
        }
        let Some(letter) = option.strip_prefix('-').filter(|l| l.len() == 1) else {
            return false;
        };
        word.strip_prefix('-').is_some_and(|cluster| {
            !cluster.is_empty()
                && !cluster.starts_with('-')
                && cluster.chars().all(|c| c.is_ascii_alphabetic())
                && cluster.contains(letter)
        })
    }
}

/// The Git Bash path conversion facts (`[msys]`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msys {
    /// First path segments Git Bash rewrites (`/var/…`).
    pub roots: Vec<String>,
    /// Environment names that turn the conversion off.
    pub opt_out: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub programs: Vec<Program>,
    pub msys: Msys,
}

#[derive(Deserialize)]
struct RawTable {
    program: Vec<Program>,
    #[serde(default)]
    msys: Msys,
}

const SHELLS: [&str; 2] = ["bash", "pwsh"];

/// Parse and validate a program table.
pub fn load(text: &str) -> Result<Table, String> {
    let raw: RawTable = toml::from_str(text).map_err(|e| e.to_string())?;
    if raw.program.is_empty() {
        return Err("no [[program]] rows".to_string());
    }
    for (k, p) in raw.program.iter().enumerate() {
        let row = format!("row {} ({:?})", k + 1, p.name);
        if p.name.trim().is_empty() || p.name != p.name.to_lowercase() {
            return Err(format!("{row}: name must be non-empty and lowercase"));
        }
        if let Some(s) = p.shells.iter().find(|s| !SHELLS.contains(&s.as_str())) {
            return Err(format!("{row}: unknown shell {s:?}"));
        }
        let lists = [
            &p.value_options,
            &p.no_run_options,
            &p.escape_options,
            &p.cmd_options,
            &p.aliases.bash,
            &p.aliases.pwsh_windows,
            &p.aliases.pwsh_posix,
        ];
        if lists.iter().any(|l| l.iter().any(|s| s.trim().is_empty())) {
            return Err(format!("{row}: a list holds an empty string"));
        }
        let wrapper_facts = p.operands > 0 || p.assignments || !p.no_run_options.is_empty();
        if wrapper_facts && !p.is(Kind::Wrapper) {
            return Err(format!(
                "{row}: wrapper facts on a row that is not a wrapper"
            ));
        }
        if p.escapes == Some(Escapes::Option) && p.escape_options.is_empty() {
            return Err(format!("{row}: escapes = \"option\" needs escape_options"));
        }
        if p.fix.as_deref().is_some_and(|f| f.trim().is_empty()) {
            return Err(format!("{row}: an empty fix"));
        }
    }
    // A name may name one row per shell.
    for shell in [Shell::Bash(BashProfile::GitBash), Shell::Pwsh] {
        for os in [Os::Windows, Os::Posix] {
            let mut seen: Vec<String> = Vec::new();
            for p in raw.program.iter().filter(|p| p.applies(shell)) {
                for n in p.names(shell, os) {
                    let n = n.to_lowercase();
                    if seen.contains(&n) {
                        return Err(format!("{n:?} names two rows in {shell:?} on {os:?}"));
                    }
                    seen.push(n);
                }
            }
        }
    }
    if raw
        .msys
        .roots
        .iter()
        .any(|r| r.is_empty() || r.contains('/'))
    {
        return Err("msys.roots: a root is empty or holds a /".to_string());
    }
    Ok(Table {
        programs: raw.program,
        msys: raw.msys,
    })
}

// `fn generated() -> Table`: `build.rs` writes `data/programs.toml` as code, so a hook call builds
// the table without parsing text. `load` stays the validator; a test pins the two together.
include!(concat!(env!("OUT_DIR"), "/programs_table.rs"));

fn embedded() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(generated)
}

/// The embedded `data/programs.toml` rows.
pub fn table() -> &'static [Program] {
    &embedded().programs
}

/// The embedded `[msys]` facts.
pub fn msys() -> &'static Msys {
    &embedded().msys
}

fn family(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash(_) => SHELLS[0],
        Shell::Pwsh | Shell::Powershell5 => SHELLS[1],
    }
}

/// Windows file names: `\` separates, case does not count, `.exe` may be left off.
fn windows_names(shell: Shell, os: Os) -> bool {
    os == Os::Windows || shell == Shell::Bash(BashProfile::GitBash)
}

/// Whether names compare ignoring case: Windows file names, and PowerShell command names on
/// every OS (`Remove-Item` is `remove-item` on Linux too).
fn folds_case(shell: Shell, os: Os) -> bool {
    windows_names(shell, os) || matches!(shell, Shell::Pwsh | Shell::Powershell5)
}

/// `typed` without its folder and, for Windows names, without `.exe` and lowercased.
fn base_name(typed: &str, shell: Shell, os: Os) -> String {
    let windows = windows_names(shell, os);
    let base = if windows {
        typed.rsplit(['/', '\\']).next()
    } else {
        typed.rsplit('/').next()
    }
    .unwrap_or_default();
    if !windows {
        return base.to_string();
    }
    let lower = base.to_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// The row `typed` (a command name as written, or its static value) runs in `shell` on `os`:
/// one strip of the folder and of `.exe` for Windows names; case is ignored for Windows names
/// and for PowerShell.
pub fn lookup(typed: &str, shell: Shell, os: Os) -> Option<&'static Program> {
    let base = base_name(typed, shell, os);
    if base.is_empty() {
        return None;
    }
    let fold = folds_case(shell, os);
    table().iter().find(|p| {
        p.applies(shell)
            && p.names(shell, os).any(|n| {
                if fold {
                    n.eq_ignore_ascii_case(&base)
                } else {
                    n == base
                }
            })
    })
}

/// The command `cmd` runs once its wrappers are read: `timeout 60 rm x` reads as `rm x`, with the
/// assignments of `env A=1 …` and `sudo A=1 …` added to the command's own. `cmd` itself when its
/// name is no wrapper, when a wrapper runs nothing (`command -v rm`, `nohup` alone) or when its
/// name is not static. A wrapped name that is not static gives an opaque command.
pub fn strip_wrappers(cmd: &SimpleCommand, shell: Shell, os: Os) -> Cow<'_, SimpleCommand> {
    let env = EnvView::new();
    let mut current = Cow::Borrowed(cmd);
    for _ in 0..MAX_WRAPPERS {
        let Some(name) = current.name.static_value(&env) else {
            break;
        };
        let Some(wrapper) = lookup(&name, shell, os).filter(|p| p.is(Kind::Wrapper)) else {
            break;
        };
        match unwrap_once(&current, wrapper, shell, os) {
            Some(next) => current = Cow::Owned(next),
            None => break,
        }
    }
    current
}

/// The command one wrapper runs, or `None` when it runs none.
fn unwrap_once(
    cmd: &SimpleCommand,
    wrapper: &Program,
    shell: Shell,
    os: Os,
) -> Option<SimpleCommand> {
    let env = EnvView::new();
    let mut assigns = cmd.assigns.clone();
    let mut operands = wrapper.operands;
    let mut options = true;
    let mut i = 0;
    while let Some(w) = cmd.args.get(i) {
        let Some(v) = w.static_value(&env) else {
            // `timeout "$T" rm x`: a word that is not static still fills an operand slot.
            if operands > 0 {
                operands -= 1;
                options = false;
                i += 1;
                continue;
            }
            break;
        };
        if options && v == "--" {
            options = false;
            i += 1;
        } else if options && v.len() > 1 && v.starts_with('-') {
            if wrapper
                .no_run_options
                .iter()
                .any(|o| Program::option_matches(&v, o))
            {
                return None;
            }
            i += if wrapper.value_options.contains(&v) {
                2
            } else {
                1
            };
        } else if let Some((name, value)) = assignment(&v).filter(|_| wrapper.assignments) {
            // The parser may already hold an argument that looks like an assignment as one.
            if !assigns.iter().any(|(n, _)| n == name) {
                assigns.push((
                    name.to_string(),
                    Word {
                        parts: vec![WordPart::Literal(value.to_string())],
                        span: w.span,
                        quote: w.quote,
                    },
                ));
            }
            i += 1;
        } else if operands > 0 {
            operands -= 1;
            options = false;
            i += 1;
        } else {
            break;
        }
    }
    let name = cmd.args.get(i)?.clone();
    let has_glob = name.parts.iter().any(|p| matches!(p, WordPart::Glob(_)));
    let typed = name.static_value(&env).unwrap_or_default();
    let canonical = if typed.is_empty() || has_glob {
        None
    } else {
        canonical(&typed, shell, os)
    };
    let opaque = cmd.opaque || name.is_dynamic() || canonical.is_none();
    Some(SimpleCommand {
        span: Span {
            start: name.span.start,
            end: cmd.span.end.max(name.span.end),
        },
        name,
        typed,
        canonical,
        args: cmd.args[i + 1..].to_vec(),
        redirects: cmd.redirects.clone(),
        assigns,
        in_loop: cmd.in_loop,
        opaque,
    })
}

/// The canonical name the parsers give `typed` in `shell`.
fn canonical(typed: &str, shell: Shell, os: Os) -> Option<String> {
    match shell {
        Shell::Bash(_) => Some(base_name(typed, shell, os)).filter(|b| !b.is_empty()),
        Shell::Pwsh | Shell::Powershell5 => crate::parse::pwsh::canonical(typed, shell, os),
    }
}

/// `NAME=value` with a shell variable name, split.
fn assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    (first.is_ascii_alphabetic() || first == '_')
        .then_some(())
        .filter(|_| chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .map(|_| (name, value))
}

/// Every simple command of `script` in source order, each before the commands nested in its
/// words: substitutions, script blocks, loop and condition bodies, functions, blocks, redirect
/// targets and expanding heredoc bodies.
pub fn commands(script: &Script) -> Vec<&SimpleCommand> {
    let mut out = Vec::new();
    walk_script(script, &mut out);
    out
}

fn walk_script<'a>(script: &'a Script, out: &mut Vec<&'a SimpleCommand>) {
    for stmt in &script.stmts {
        match stmt {
            Stmt::Pipeline(p) => {
                for elem in &p.elems {
                    match elem {
                        Elem::Cmd(c) => {
                            out.push(c);
                            walk_word(&c.name, out);
                            for w in &c.args {
                                walk_word(w, out);
                            }
                            for (_, w) in &c.assigns {
                                walk_word(w, out);
                            }
                            for r in &c.redirects {
                                match r {
                                    Redirect::File { target, .. } => walk_word(target, out),
                                    Redirect::Heredoc { body, .. } => walk_word(body, out),
                                }
                            }
                        }
                        Elem::Method(m) => {
                            for w in &m.args {
                                walk_word(w, out);
                            }
                        }
                        Elem::Expr(w) => walk_word(w, out),
                    }
                }
            }
            Stmt::Loop { body, .. } => walk_script(body, out),
            Stmt::Cond { branches, .. } => {
                for b in branches {
                    walk_script(b, out);
                }
            }
            Stmt::Func { body, .. } => walk_script(body, out),
            Stmt::Block(s) => walk_script(s, out),
        }
    }
}

fn walk_word<'a>(word: &'a Word, out: &mut Vec<&'a SimpleCommand>) {
    for part in &word.parts {
        if let WordPart::Subst(s) | WordPart::Block(s) = part {
            walk_script(s, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT_BASH: Shell = Shell::Bash(BashProfile::GitBash);
    const POSIX: Shell = Shell::Bash(BashProfile::Posix);

    fn parse(src: &str) -> Script {
        crate::parse::bash::parse(src, BashProfile::GitBash).expect("parses")
    }

    fn first(script: &Script) -> &SimpleCommand {
        commands(script).into_iter().next().expect("a command")
    }

    fn args(c: &SimpleCommand) -> Vec<String> {
        c.args
            .iter()
            .map(|w| w.static_value(&EnvView::new()).unwrap_or_default())
            .collect()
    }

    /// The code `build.rs` writes is the table `load` reads from the same text: every field, every
    /// `extra` key and value kind, the msys facts.
    #[test]
    fn the_generated_table_equals_the_loaded_text() {
        let loaded = load(TABLE_TEXT).expect("data/programs.toml is valid");
        let built = generated();
        assert_eq!(built.programs.len(), loaded.programs.len());
        for (b, l) in built.programs.iter().zip(&loaded.programs) {
            assert_eq!(b, l, "row {:?}", l.name);
        }
        assert_eq!(built.msys, loaded.msys);
        assert!(loaded.programs.iter().any(|p| !p.extra.is_empty()));
    }

    #[test]
    fn the_embedded_table_loads_with_every_kind_spelling() {
        assert!(!table().is_empty());
        assert!(!msys().roots.is_empty() && !msys().opt_out.is_empty());
        let kinds = "[[program]]\nname = \"a\"\nkind = [\"wrapper\", \"native-msys\", \"delete\", \"eval\", \"shell\", \"interactive\", \"launcher\"]\n";
        let t = load(kinds).expect("every plan kind loads");
        assert_eq!(t.programs[0].kind.len(), 7);
    }

    #[test]
    fn load_refuses_bad_rows_and_keeps_unknown_keys() {
        let bad = [
            "[[program]]\nname = \"\"\n",
            "[[program]]\nname = \"Ab\"\n",
            "[[program]]\nname = \"a\"\nkind = [\"nope\"]\n",
            "[[program]]\nname = \"a\"\nshells = [\"cmd\"]\n",
            "[[program]]\nname = \"a\"\n[[program]]\nname = \"a\"\n",
            "[[program]]\nname = \"a\"\n[[program]]\nname = \"b\"\naliases = { bash = [\"a\"] }\n",
            "[[program]]\nname = \"a\"\noperands = 1\n",
            "[[program]]\nname = \"a\"\nescapes = \"option\"\n",
            "[[program]]\nname = \"a\"\nfix = \" \"\n",
            "[[program]]\nname = \"a\"\nvalue_options = [\" \"]\n",
            "[[program]]\nname = \"a\"\n[msys]\nroots = [\"a/b\"]\nopt_out = []\n",
            "program = []\n",
        ];
        for text in bad {
            assert!(load(text).is_err(), "{text:?}");
        }
        let t = load("[[program]]\nname = \"a\"\nhang_unless = [\"-y\"]\n").unwrap();
        assert!(t.programs[0].extra.contains_key("hang_unless"));
        // The same name in two shells is two rows, not a clash.
        assert!(load("[[program]]\nname = \"a\"\nshells = [\"bash\"]\n[[program]]\nname = \"a\"\nshells = [\"pwsh\"]\n").is_ok());
    }

    #[test]
    fn lookup_strips_one_folder_and_exe_and_folds_case_for_windows_names() {
        for typed in [
            "timeout",
            "/usr/bin/timeout",
            "TIMEOUT.EXE",
            "C:\\x\\timeout.exe",
        ] {
            assert_eq!(
                lookup(typed, GIT_BASH, Os::Windows).map(|p| p.name.as_str()),
                Some("timeout"),
                "{typed}"
            );
        }
        assert_eq!(
            lookup("/usr/bin/timeout", POSIX, Os::Posix).map(|p| p.name.as_str()),
            Some("timeout")
        );
        assert!(lookup("TIMEOUT", POSIX, Os::Posix).is_none());
        // On POSIX a backslash is part of the file name, not a separator.
        assert!(lookup("x\\timeout", POSIX, Os::Posix).is_none());
        // Git Bash names are Windows names on any host (the WSL leg runs them as Os::Posix).
        assert_eq!(
            lookup("C:\\x\\TIMEOUT.EXE", GIT_BASH, Os::Posix).map(|p| p.name.as_str()),
            Some("timeout")
        );
        assert!(lookup("timeout.exe", POSIX, Os::Posix).is_none());
        // A bash-only row is not a pwsh program: there `timeout` is timeout.exe.
        assert!(lookup("timeout", Shell::Pwsh, Os::Windows).is_none());
        assert!(lookup("newtool", GIT_BASH, Os::Windows).is_none());
        assert!(lookup("", GIT_BASH, Os::Windows).is_none());
    }

    #[test]
    fn strip_wrappers_reads_to_the_wrapped_command() {
        let rows: &[(&str, &str, &[&str])] = &[
            ("timeout 60 rm -rf x", "rm", &["-rf", "x"]),
            ("timeout -s KILL 5 rm x", "rm", &["x"]),
            ("timeout \"$T\" rm -rf x", "rm", &["-rf", "x"]),
            ("timeout ${T:-60} rm x", "rm", &["x"]),
            ("timeout --signal=KILL 5 rm x", "rm", &["x"]),
            // Ruling 111: an unknown wrapper option does not hide the command.
            ("timeout --weird 60 rm -rf x", "rm", &["-rf", "x"]),
            ("sudo -E rm x", "rm", &["x"]),
            // After `--` a word with a dash is the command.
            ("nohup -- -x y", "-x", &["y"]),
            // nice takes no assignments: `A=1` is the program it runs.
            ("nice A=1 x", "A=1", &["x"]),
            ("nice -n 5 rm x", "rm", &["x"]),
            ("sudo -u root nice rm x", "rm", &["x"]),
            ("nohup rm x", "rm", &["x"]),
            ("command rm x", "rm", &["x"]),
            ("env -- rm x", "rm", &["x"]),
            ("env -u HOME rm x", "rm", &["x"]),
            ("/usr/bin/env A=1 docker ps", "docker", &["ps"]),
        ];
        for (src, name, want) in rows {
            let script = parse(src);
            let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
            assert_eq!(c.typed, *name, "{src}");
            assert_eq!(args(&c), *want, "{src}");
            assert!(!c.opaque, "{src}");
            assert!(matches!(c, Cow::Owned(_)), "{src}");
        }
    }

    #[test]
    fn strip_wrappers_moves_env_assignments_onto_the_command() {
        let script = parse("env A=1 B=2 docker ps");
        let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
        let names: Vec<&str> = c.assigns.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["A", "B"]);
        assert_eq!(c.typed, "docker");
        // The wrapper's redirects belong to the command it runs.
        let script = parse("timeout 5 rm x > log.txt");
        let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
        assert_eq!(c.redirects.len(), 1);
    }

    #[test]
    fn strip_wrappers_keeps_a_command_that_runs_nothing_or_is_no_wrapper() {
        for src in [
            "command -v rm",
            "nohup",
            "timeout 5",
            "printf x",
            "rm -rf x",
        ] {
            let script = parse(src);
            let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
            assert!(matches!(c, Cow::Borrowed(_)), "{src}");
        }
    }

    #[test]
    fn a_wrapped_name_that_is_not_static_is_opaque() {
        let script = parse("timeout 5 $x -y");
        let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
        assert!(c.opaque);
        assert!(c.canonical.is_none());
        assert_eq!(args(&c), ["-y"]);
        // A glob as the name: which program runs depends on the folder.
        let script = parse("timeout 5 ./r*m -y");
        let c = strip_wrappers(first(&script), GIT_BASH, Os::Windows);
        assert!(c.opaque && c.canonical.is_none());
    }

    #[test]
    fn wrappers_are_bash_only() {
        let script = crate::parse::pwsh::parse("timeout /t 5", Shell::Pwsh, Os::Windows).unwrap();
        let c = strip_wrappers(first(&script), Shell::Pwsh, Os::Windows);
        assert!(matches!(c, Cow::Borrowed(_)));
    }

    #[test]
    fn commands_finds_nested_commands_in_order() {
        let script = parse("echo $(rm x) | cat; for f in a; do sed s/a/b/ f; done; g() { ls; }");
        let names: Vec<&str> = commands(&script).iter().map(|c| c.typed.as_str()).collect();
        assert_eq!(names, ["echo", "rm", "cat", "sed", "ls"]);
    }

    /// One command nested at each place the walker reads: the name, an argument, an assignment,
    /// a redirect target, an expanding heredoc body, a condition, a block, and in PowerShell a
    /// method argument and an expression.
    #[test]
    fn commands_reads_every_nesting_point() {
        let bash: &[(&str, &[&str])] = &[
            ("$(echo n) a", &["$(echo n)", "echo"]),
            ("ls $(echo a)", &["ls", "echo"]),
            ("A=$(echo a) ls", &["ls", "echo"]),
            ("ls > $(echo f)", &["ls", "echo"]),
            ("cat <<EOF\n$(echo a)\nEOF", &["cat", "echo"]),
            ("if true; then echo a; fi", &["true", "echo"]),
            ("{ echo a; }", &["echo"]),
            ("(echo a)", &["echo"]),
        ];
        for (src, want) in bash {
            let script = parse(src);
            let names: Vec<&str> = commands(&script).iter().map(|c| c.typed.as_str()).collect();
            assert_eq!(names, *want, "{src:?}");
        }
        let pwsh: &[(&str, &[&str])] = &[
            ("[IO.File]::Delete((Get-Item x))", &["Get-Item"]),
            ("\"x$(Get-Item a)\" | Out-Null", &["Get-Item", "Out-Null"]),
            (
                "Invoke-Command { Get-Item x }",
                &["Invoke-Command", "Get-Item"],
            ),
        ];
        for (src, want) in pwsh {
            let script = crate::parse::pwsh::parse(src, Shell::Pwsh, Os::Windows).unwrap();
            let names: Vec<&str> = commands(&script).iter().map(|c| c.typed.as_str()).collect();
            assert_eq!(names, *want, "{src:?}");
        }
    }

    #[test]
    fn lookup_folds_case_for_powershell_on_every_os() {
        for os in [Os::Windows, Os::Posix] {
            let p = lookup("Remove-Item", Shell::Pwsh, os).map(|p| p.name.as_str());
            assert_eq!(p, Some("remove-item"), "{os:?}");
        }
        assert!(lookup("RM", POSIX, Os::Posix).is_none());
    }

    /// The facts Tasks 30–33 read from `extra`, each through `lookup` in the shell it is for.
    #[test]
    fn the_rows_other_tasks_need_keep_their_keys() {
        let key = |typed: &str, shell: Shell, path: &[&str]| -> Option<toml::Value> {
            let p = lookup(typed, shell, Os::Windows)?;
            let (first, rest) = path.split_first()?;
            let mut v = p.extra.get(*first)?.clone();
            for k in rest {
                v = v.get(*k)?.clone();
            }
            Some(v)
        };
        let int = |v: Option<toml::Value>| v.and_then(|v| v.as_integer());
        let yes = |v: Option<toml::Value>| v.and_then(|v| v.as_bool()) == Some(true);
        // Task 31: the cmd.exe line limit, in both shells.
        assert_eq!(
            int(key("cmd.exe", Shell::Pwsh, &["line_limit"])),
            Some(8191)
        );
        assert_eq!(int(key("cmd", GIT_BASH, &["line_limit"])), Some(8191));
        // Task 33: wait facts.
        assert!(yes(key("timeout", GIT_BASH, &["bounds_wait"])));
        assert!(yes(key("read", GIT_BASH, &["hang_stdin"])));
        // Ruling 110: Read-Host fails fast in the tool, so it has no wait facts.
        assert!(key("Read-Host", Shell::Pwsh, &["hang_level"]).is_none());
        assert!(key("read", Shell::Pwsh, &["hang_stdin"]).is_none());
        // Task 32: delete and discard tables.
        assert!(key("rm", GIT_BASH, &["delete", "recursive"]).is_some());
        assert!(yes(key("xargs", Shell::Pwsh, &["delete", "runner"])));
        assert!(key("git", GIT_BASH, &["discard", "subcommands"]).is_some());
        // Task 30: lint tables, merged into the rows above where both name the program.
        assert!(key("git", Shell::Pwsh, &["discard", "subcommands"]).is_some());
        assert!(key("git", Shell::Pwsh, &["lint", "tags"]).is_some());
        assert!(key("Remove-Item", Shell::Pwsh, &["delete", "recursive"]).is_some());
        assert!(key("remove-item", Shell::Pwsh, &["lint", "flag_hints"]).is_some());
        assert!(key("claude", Shell::Pwsh, &["lint", "config_env"]).is_some());
        assert!(key("claude", GIT_BASH, &["hang_when"]).is_some());
        assert!(key("xargs", Shell::Pwsh, &["lint", "tags"]).is_some());
        assert!(key("xargs", GIT_BASH, &["lint"]).is_none());
        // A pwsh-only Fix line stays out of bash.
        let fix = |typed: &str, shell: Shell| lookup(typed, shell, Os::Windows)?.fix.clone();
        assert!(fix("bash", Shell::Pwsh).is_some());
        assert_eq!(fix("bash", GIT_BASH), None);
        assert_eq!(
            lookup("py", Shell::Pwsh, Os::Windows).map(|p| p.name.as_str()),
            Some("python")
        );
    }

    #[test]
    fn option_matches_exact_and_short_clusters() {
        assert!(Program::option_matches("-e", "-e"));
        assert!(Program::option_matches("-ne", "-e"));
        assert!(!Program::option_matches("-n", "-e"));
        assert!(!Program::option_matches("--e", "-e"));
        assert!(!Program::option_matches("-e1", "-e"));
        assert!(Program::option_matches("--expression", "--expression"));
        assert!(!Program::option_matches("--expressions", "--expression"));
    }
}
