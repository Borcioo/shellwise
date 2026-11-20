//! `bat-metachar`: an argument to a `.bat`/`.cmd` launcher that cmd.exe re-parses.

use std::path::{Path, PathBuf};

use super::bind::stops_parsing;
use super::{Ctx, Rule, finding, has_folder, is_pwsh, literal, text};
use crate::fs;
use crate::ir::SimpleCommand;
use crate::level::{Finding, Level, Span};
use crate::parse::cmd::reparse_bat_arg;
use crate::Os;

pub const BAT_METACHAR: &str = "bat-metachar";

/// An argument to a `.bat`/`.cmd` launcher that cmd.exe re-parses: an operator character outside
/// double quotes, or a `%NAME%` of a defined variable (expanded even inside quotes). Launchers are
/// the names in `cfg.bat_launchers`, or any name ending in `.bat` or `.cmd`; a launcher name is
/// checked to reach cmd.exe the way PowerShell finds it (each PATH folder in order, and in each
/// `.ps1` first, then the PATHEXT extensions).
pub struct BatMetachar;

impl Rule for BatMetachar {
    fn id(&self) -> &'static str {
        BAT_METACHAR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        let src = ctx.input.command;
        for site in super::walk(ctx.script).sites {
            let c = site.cmd;
            if c.opaque || c.typed.is_empty() || c.canonical.is_some() {
                continue;
            }
            let explicit = has_bat_extension(&c.typed);
            // The launcher patterns compile globs: matched only once an argument needs it.
            let mut launcher: Option<bool> = explicit.then_some(true);
            for (k, arg) in c.args.iter().enumerate() {
                if stops_parsing(src, arg) {
                    break;
                }
                let Some(value) = literal(arg) else { continue };
                let r = reparse_bat_arg(&value, ps_wraps(&value));
                let defined = r.percent_vars.iter().find(|n| env_defined(ctx, n));
                if r.metachars.is_empty() && defined.is_none() {
                    continue;
                }
                let named_launcher = *launcher
                    .get_or_insert_with(|| launcher_named(&c.typed, &ctx.cfg.bat_launchers));
                if !named_launcher || (!explicit && !reaches_cmd(ctx, &c.typed)) {
                    break;
                }
                let raw = text(src, arg.span);
                let fix = bat_fix(ctx, c, k, defined.is_some());
                let message = match defined {
                    Some(name) => format!(
                        "`{}` is a .bat launcher, so cmd.exe replaces `%{name}%` in the argument {raw} with that variable's value before the program sees it, even inside quotes",
                        c.typed
                    ),
                    None => format!(
                        "`{}` is a .bat launcher, so cmd.exe re-parses the argument {raw} and treats its `{}` as an operator (\"... is not recognized as an internal or external command\", or the character vanishes)",
                        c.typed, r.metachars[0]
                    ),
                };
                out.push(finding(BAT_METACHAR, Level::Break, arg.span, message, fix));
                break;
            }
        }
    }
}

fn has_bat_extension(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// `name` matches a `bat_launchers` pattern: on its file name when the pattern has no folder, on
/// its path (folders `/` or `\`, any leading folders) otherwise; `*` and `[...]` as in a glob.
pub(super) fn launcher_named(name: &str, patterns: &[String]) -> bool {
    let norm = name.replace('\\', "/").to_lowercase();
    let norm = norm.trim_start_matches("./").to_string();
    let base = norm.rsplit('/').next().unwrap_or(&norm).to_string();
    let base = base
        .strip_suffix(".bat")
        .or_else(|| base.strip_suffix(".cmd"))
        .unwrap_or(&base)
        .to_string();
    let path = norm
        .strip_suffix(".bat")
        .or_else(|| norm.strip_suffix(".cmd"))
        .unwrap_or(&norm)
        .to_string();
    patterns.iter().any(|p| {
        let p = p.replace('\\', "/").to_lowercase();
        let (subject, globs) = if p.contains('/') {
            (path.as_str(), vec![p.clone(), format!("*/{p}")])
        } else {
            (base.as_str(), vec![p.clone()])
        };
        globs.iter().any(|g| {
            globset::GlobBuilder::new(g)
                .literal_separator(false)
                .backslash_escape(false)
                .build()
                .is_ok_and(|m| m.compile_matcher().is_match(subject))
        })
    })
}

/// PowerShell's rule for a native argument to a batch file: it wraps the value in double quotes
/// when it is empty or holds whitespace outside its own double quotes (a `"` after `\` does not
/// count).
fn ps_wraps(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut quotes = 0;
    let mut prev = '\0';
    for ch in value.chars() {
        if ch == '"' && prev != '\\' {
            quotes += 1;
        } else if ch.is_whitespace() && quotes % 2 == 0 {
            return true;
        }
        prev = ch;
    }
    false
}

/// A variable of the command's environment, else of this process (the hook runs in the
/// environment the command inherits).
fn env_value(ctx: &Ctx, name: &str) -> Option<String> {
    ctx.input
        .env
        .get(name)
        .map(str::to_string)
        .or_else(|| std::env::var(name).ok())
}

/// cmd.exe expands `%NAME%` only for a defined variable (names ignore case on Windows).
fn env_defined(ctx: &Ctx, name: &str) -> bool {
    env_value(ctx, name).is_some()
        || std::env::vars_os().any(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
}

/// A path the lookup may `lstat`: an absolute path on a local drive letter (`C:\x`, `C:/x`). A
/// UNC path (`\\server\share`, `//server/share`), a device path (`\\?\`, `\\.\`) or anything
/// else is never touched: a stat there can hang the hook and sends credentials to the server.
fn local_drive_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
}

/// Whether PowerShell starts `name` through cmd.exe: the first match in its folder (or in each
/// PATH folder, in order) with `.ps1` first, then each PATHEXT extension, then the bare name,
/// is a `.bat` or `.cmd`. A name with a folder that resolves to nothing counts as one: the
/// launchers are batch files and the check cannot follow every `cd`; so does a lookup the
/// deadline stops. A bare name found nowhere is no program.
fn reaches_cmd(ctx: &Ctx, name: &str) -> bool {
    let pathext = env_value(ctx, "PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut exts: Vec<String> = vec![".ps1".to_string()];
    exts.extend(pathext.split(';').filter(|e| !e.is_empty()).map(str::to_string));
    exts.push(String::new());
    let (folders, base): (Vec<PathBuf>, String) = if has_folder(name) {
        let p = Path::new(name);
        let full = if local_drive_path(p) {
            p.to_path_buf()
        } else if is_relative(name) {
            match &ctx.input.cwd {
                Some(cwd) => cwd.join(p),
                None => return true,
            }
        } else {
            // A UNC, device or root-relative name: unresolved, without a lookup.
            return true;
        };
        let base = full
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_default();
        (full.parent().map(Path::to_path_buf).into_iter().collect(), base)
    } else {
        let path = env_value(ctx, "PATH").unwrap_or_default();
        (
            std::env::split_paths(&path)
                .filter(|d| !d.as_os_str().is_empty())
                .collect(),
            name.to_string(),
        )
    };
    let candidates: Vec<PathBuf> = folders
        .iter()
        .flat_map(|folder| {
            exts.iter()
                .map(|ext| folder.join(format!("{base}{ext}")))
                .collect::<Vec<_>>()
        })
        .filter(|c| local_drive_path(c))
        .collect();
    let shared = std::sync::Arc::clone(ctx.fs);
    let found = fs::bounded(ctx.deadline, move || {
        candidates
            .into_iter()
            .find(|c| shared.lstat(c).is_ok_and(|m| m.is_file))
    });
    match found {
        Ok(Some(hit)) => has_bat_extension(&hit.to_string_lossy()),
        Ok(None) => has_folder(name),
        Err(fs::TimedOut) => true,
    }
}

/// A relative name PowerShell resolves against the current location (`tools\x`, `.\x`): no drive,
/// no leading separator.
fn is_relative(name: &str) -> bool {
    let b = name.as_bytes();
    !(matches!(b.first(), Some(b'\\' | b'/')) || (b.len() >= 2 && b[1] == b':'))
}

/// The Fix line: the program by its path when `cfg.tool_paths` names one for the launcher;
/// otherwise, for an operator, the same call after `--%` with the argument in double quotes,
/// which cmd.exe leaves alone.
fn bat_fix(ctx: &Ctx, c: &SimpleCommand, bad: usize, percent: bool) -> String {
    let src = ctx.input.command;
    let base = c
        .typed
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let base = base
        .strip_suffix(".bat")
        .or_else(|| base.strip_suffix(".cmd"))
        .unwrap_or(&base)
        .to_string();
    let rest = text(
        src,
        Span {
            start: c.name.span.end,
            end: c.span.end,
        },
    )
    .trim();
    if let Some(path) = ctx.cfg.tool_paths.get(&base) {
        return format!("call the program directly: & \"{}\" {rest}", path.display());
    }
    let by_path = format!(
        "call the program `{}` starts by its own path (its .exe), not through the .bat",
        c.typed
    );
    if percent {
        return format!("{by_path}, or keep %NAME% out of the argument");
    }
    let mut words = Vec::new();
    for (k, a) in c.args.iter().enumerate() {
        let Some(v) = literal(a) else {
            return by_path;
        };
        if k == bad {
            if v.contains('"') {
                return by_path;
            }
            words.push(format!("\"{v}\""));
        } else {
            words.push(v);
        }
    }
    format!("{} --% {}", c.typed, words.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::fs::{Meta, Fs, SharedFs};
    use crate::ir::EnvView;
    use crate::{CheckInput, Deadline, Origin, Shell};
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Records every `lstat`; the paths in `files` exist as files.
    struct Recording {
        calls: Mutex<Vec<PathBuf>>,
        files: Vec<PathBuf>,
    }

    impl Fs for Recording {
        fn lstat(&self, p: &Path) -> io::Result<Meta> {
            self.calls.lock().unwrap().push(p.to_path_buf());
            // Windows file names ignore case, as the real file system does.
            let key = p.to_string_lossy().to_lowercase();
            if self
                .files
                .iter()
                .any(|f| f.to_string_lossy().to_lowercase() == key)
            {
                Ok(Meta {
                    is_dir: false,
                    is_file: true,
                    is_symlink: false,
                })
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }
        }
        fn read_dir(&self, _p: &Path) -> io::Result<Vec<PathBuf>> {
            Ok(Vec::new())
        }
        fn link_target(&self, _p: &Path) -> io::Result<Option<PathBuf>> {
            Ok(None)
        }
    }

    /// The rule's findings on `command`, parsed by the real pwsh parser, with PATH and PATHEXT
    /// pinned, and every `lstat` it made.
    fn run(command: &str, path: &str, cwd: Option<&str>, files: &[&str]) -> (Vec<Finding>, Vec<PathBuf>) {
        let script = crate::parse::pwsh::parse(command, Shell::Pwsh, Os::Windows).unwrap();
        let mut env = EnvView::case_insensitive();
        env.set("PATH", path);
        env.set("PATHEXT", ".COM;.EXE;.BAT;.CMD");
        let input = CheckInput {
            shell: Shell::Pwsh,
            os: Os::Windows,
            command,
            cwd: cwd.map(PathBuf::from),
            env,
            origin: Origin::CommandLine,
        };
        let rec = Arc::new(Recording {
            calls: Mutex::new(Vec::new()),
            files: files.iter().map(PathBuf::from).collect(),
        });
        let fs: SharedFs = rec.clone();
        let cfg = Config::default();
        let deadline = Deadline::new(Instant::now(), 5000);
        let ctx = Ctx {
            input: &input,
            script: &script,
            parse_error: None,
            cfg: &cfg,
            fs: &fs,
            deadline: &deadline,
        };
        let mut out = Vec::new();
        BatMetachar.check(&ctx, &mut out);
        let calls = rec.calls.lock().unwrap().clone();
        (out, calls)
    }

    const ARG: &str = " --filter 'A|B'";

    #[test]
    fn a_unc_device_or_rooted_name_is_never_looked_up() {
        for name in [
            r"\\srv\share\php",
            "& '//srv/share/php'",
            r"\\?\C:\tools\php",
            r"\\.\C:\tools\php",
            r"\tools\php",
        ] {
            let (found, calls) = run(&format!("{name}{ARG}"), r"C:\bin", None, &[]);
            assert!(calls.is_empty(), "{name}: {calls:?}");
            assert_eq!(found.len(), 1, "{name}: an unresolved launcher with a folder counts");
        }
    }

    #[test]
    fn a_unc_cwd_or_path_folder_is_never_looked_up() {
        let (_, calls) = run(&format!(r"tools\php{ARG}"), r"C:\bin", Some(r"\\srv\share\repo"), &[]);
        assert!(calls.is_empty(), "{calls:?}");
        let (found, calls) = run(&format!("php{ARG}"), r"\\srv\share\bin;//srv/b", None, &[]);
        assert!(calls.is_empty(), "{calls:?}");
        assert!(found.is_empty(), "a bare name found nowhere is no program");
    }

    #[test]
    fn a_local_lookup_follows_powershell_s_order() {
        // The control: a local drive is looked up, folder by folder, `.ps1` first.
        let (found, calls) = run(&format!("php{ARG}"), r"C:\a;C:\b", None, &[r"C:\b\php.bat"]);
        assert_eq!(found.len(), 1, "{calls:?}");
        assert_eq!(calls.first(), Some(&PathBuf::from(r"C:\a\php.ps1")));
        assert_eq!(calls.get(1), Some(&PathBuf::from(r"C:\a\php.COM")));
        assert_eq!(calls.last(), Some(&PathBuf::from(r"C:\b\php.BAT")));
        // An .exe before the .bat in the same folder, or in an earlier folder, wins.
        for files in [&[r"C:\a\php.exe", r"C:\a\php.bat"][..], &[r"C:\a\php.exe", r"C:\b\php.bat"]] {
            let (found, _) = run(&format!("php{ARG}"), r"C:\a;C:\b", None, files);
            assert!(found.is_empty(), "{files:?}");
        }
        // A .bat in an earlier folder wins over an .exe in a later one.
        let (found, _) = run(&format!("php{ARG}"), r"C:\a;C:\b", None, &[r"C:\a\php.bat", r"C:\b\php.exe"]);
        assert_eq!(found.len(), 1);
        // A script wins over the .bat in its folder.
        let (found, _) = run(&format!("php{ARG}"), r"C:\a", None, &[r"C:\a\php.ps1", r"C:\a\php.bat"]);
        assert!(found.is_empty());
        // A relative name is looked up under a local cwd.
        let (found, calls) = run(&format!(r"tools\php{ARG}"), r"C:\x", Some(r"C:\repo"), &[r"C:\repo\tools\php.exe"]);
        assert!(found.is_empty());
        assert_eq!(calls.last(), Some(&PathBuf::from(r"C:\repo\tools\php.EXE")), "{calls:?}");
    }

    #[test]
    fn launcher_patterns_match_names_and_paths() {
        let pats: Vec<String> = ["php", "php8[0-9]", r"vendor\bin\*", "composer"]
            .map(String::from)
            .to_vec();
        for n in [
            "php",
            "PHP.bat",
            "php84",
            r"vendor\bin\phpunit",
            r".\vendor\bin\phpunit",
            "./vendor/bin/phpcs",
            r"tools\composer.bat",
        ] {
            assert!(launcher_named(n, &pats), "{n}");
        }
        for n in ["php7", "phpx", r"vendor\phpunit", "rg"] {
            assert!(!launcher_named(n, &pats), "{n}");
        }
    }

    #[test]
    fn powershell_wraps_a_native_argument_with_whitespace() {
        assert!(ps_wraps(""));
        assert!(ps_wraps("a b"));
        assert!(!ps_wraps("a|b"));
        assert!(!ps_wraps("x\"a b\"y"));
        assert!(ps_wraps("a\\\" b"));
    }
}
