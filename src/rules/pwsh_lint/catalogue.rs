//! The rules from the trap catalogue: `ps-unix-command`, `pwsh-file-list-arg` and
//! `ps-kill-wrapper` by the landing rule, and the warn rules.

use super::bind::{bind_args, named, param_token};
use super::table::{Facts, VarKind};
use super::{
    Ctx, ENV_SCOPE, Rule, command_tagged, finding, has_folder, is_native, is_pwsh, lint, literal,
    program_of, replaced, table_name, text, walk,
};
use crate::ir::{Quote, WordPart};
use crate::level::{Finding, Level};
use crate::Os;

pub const PS_UNIX_COMMAND: &str = "ps-unix-command";

/// A Unix tool PowerShell does not have here (`tail`, `grep`, `sed`, `export`): the row tagged
/// `unix-only` names the PowerShell way in its `fix`. Warn: with coreutils on PATH some of them
/// run.
pub struct UnixCommand;

impl Rule for UnixCommand {
    fn id(&self) -> &'static str {
        PS_UNIX_COMMAND
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if c.opaque || c.canonical.is_some() || has_folder(&c.typed) {
                continue;
            }
            if w.functions.contains(&c.typed.to_lowercase()) {
                continue;
            }
            let Some(p) = command_tagged(ctx, c, "unix-only") else {
                continue;
            };
            let instead = p.fix.as_deref().unwrap_or("the PowerShell cmdlet");
            out.push(finding(
                PS_UNIX_COMMAND,
                Level::Warn,
                c.name.span,
                format!(
                    "`{}` is a Unix tool that PowerShell does not have unless coreutils is on PATH",
                    c.typed
                ),
                format!("use {instead} in PowerShell, or run the command with the Bash tool"),
            ));
            return;
        }
    }
}

pub const PWSH_FILE_LIST_ARG: &str = "pwsh-file-list-arg";

/// `pwsh -File x.ps1 -Exclude a,b`: through `-File` a comma list reaches the script as one
/// string, not as an array. The host row lists its `lint.script_flags`.
pub struct FileListArg;

impl Rule for FileListArg {
    fn id(&self) -> &'static str {
        PWSH_FILE_LIST_ARG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(host) = program_of(ctx, c).filter(|p| !lint(p, "script_flags").is_empty())
            else {
                continue;
            };
            let flags = lint(host, "script_flags");
            let Some(at) = c.args.iter().position(|a| {
                literal(a).is_some_and(|v| flags.iter().any(|f| f.eq_ignore_ascii_case(&v)))
            }) else {
                continue;
            };
            let Some(list) = c
                .args
                .iter()
                .skip(at + 2)
                .find(|a| a.parts.iter().any(|p| matches!(p, WordPart::ListSep)))
            else {
                continue;
            };
            out.push(finding(
                PWSH_FILE_LIST_ARG,
                Level::Warn,
                list.span,
                format!(
                    "`{}` passes `{}` to the script as one string through -File, not as a list, so a parameter that takes several values gets one",
                    c.typed,
                    text(ctx.input.command, list.span)
                ),
                "pass the list as one quoted value, or use -Command".to_string(),
            ));
            return;
        }
    }
}

pub const PS_KILL_WRAPPER: &str = "ps-kill-wrapper";

/// Stopping a process by name (`Stop-Process -Name node`, `taskkill /IM`, `pkill`): it stops
/// other sessions' runs, and stopping a `npm`/`pnpm` wrapper leaves its `node` child holding the
/// port. Rows tagged `process-stop`: `lint.name_params` (bound cmdlet parameters), `lint.name_flags`
/// (`/IM`), `lint.always = ["yes"]` for a tool that only kills by name.
pub struct KillWrapper;

impl Rule for KillWrapper {
    fn id(&self) -> &'static str {
        PS_KILL_WRAPPER
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        let facts = Facts::for_shell(ctx.input.shell);
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "process-stop") else {
                continue;
            };
            let by_name = !lint(row, "always").is_empty()
                || lint(row, "name_flags").iter().any(|f| {
                    c.args
                        .iter()
                        .any(|a| literal(a).is_some_and(|v| v.eq_ignore_ascii_case(f)))
                })
                || facts
                    .and_then(|t| table_name(c, t, ctx.input.os, &w))
                    .and_then(|cmd| bind_args(src, c, cmd))
                    .is_some_and(|args| {
                        lint(row, "name_params")
                            .iter()
                            .any(|p| named(&args, p).is_some())
                    });
            if !by_name {
                continue;
            }
            out.push(finding(
                PS_KILL_WRAPPER,
                Level::Warn,
                c.span,
                format!(
                    "`{}` stops processes by name: that also stops other sessions' runs, and stopping an npm/pnpm wrapper leaves its node child holding the port",
                    c.typed
                ),
                "stop the process that owns the port: Get-NetTCPConnection -LocalPort <p> | % OwningProcess | Stop-Process".to_string(),
            ));
            return;
        }
    }
}

pub const PS_AUTO_VARIABLE: &str = "ps-auto-variable";

/// An assignment to an automatic variable (Specter AvoidAssignmentToAutomaticVariable):
/// read-only and constant ones (`$HOME`, `$PID`, `$Host`) fail, the others (`$input`, `$args`,
/// `$matches`, `$PWD`) are overwritten by PowerShell. Names and kinds come from the table's
/// `variable` rows; names ignore case.
pub struct AutoVariable;

impl Rule for AutoVariable {
    fn id(&self) -> &'static str {
        PS_AUTO_VARIABLE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        for site in walk(ctx.script).sites {
            for (name, _) in &site.cmd.assigns {
                if name.contains(':') {
                    continue;
                }
                let what = match t.variable_kind(name) {
                    Some(VarKind::Constant | VarKind::Readonly) => {
                        "is read-only, so the assignment fails"
                    }
                    Some(VarKind::Automatic) => {
                        "is set by PowerShell itself, which overwrites the value"
                    }
                    _ => continue,
                };
                out.push(finding(
                    PS_AUTO_VARIABLE,
                    Level::Warn,
                    site.cmd.span,
                    format!("`${name}` is an automatic variable: it {what}"),
                    format!("rename the variable, for example ${name}Value"),
                ));
                return;
            }
        }
    }
}

pub const PS_REMOVE_ITEM_STAR: &str = "ps-remove-item-star";

/// `Remove-Item <dir>\*`: the host's tool guard refuses a delete of a path ending in `\*`, and
/// the folder stays full. Rows tagged `children-delete` (Remove-Item).
pub struct RemoveItemStar;

impl Rule for RemoveItemStar {
    fn id(&self) -> &'static str {
        PS_REMOVE_ITEM_STAR
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if command_tagged(ctx, c, "children-delete").is_none() {
                continue;
            }
            for a in &c.args {
                if param_token(src, a).is_some() {
                    continue;
                }
                let raw = text(src, a.span).trim_matches(['\'', '"']);
                let Some(dir) = raw.strip_suffix("\\*").or_else(|| raw.strip_suffix("/*")) else {
                    continue;
                };
                if dir.is_empty() {
                    continue;
                }
                out.push(finding(
                    PS_REMOVE_ITEM_STAR,
                    Level::Warn,
                    a.span,
                    format!(
                        "`{}` on `{raw}`: the tool guard refuses a delete of a path ending in `\\*`, so the folder is not emptied",
                        c.typed
                    ),
                    format!("Get-ChildItem -LiteralPath {dir} -Force | Remove-Item -Recurse -Force"),
                ));
                return;
            }
        }
    }
}

pub const PS_STDIN_SCRIPT: &str = "ps-stdin-script";

/// Script text piped into an interpreter's stdin (`$code | python -`): PowerShell re-encodes it
/// and non-ASCII characters arrive as U+FFFD. Rows tagged `interpreter`; `lint.stdin_args` are
/// the arguments that read the script from stdin (`-`); no argument at all reads it too.
pub struct StdinScript;

impl Rule for StdinScript {
    fn id(&self) -> &'static str {
        PS_STDIN_SCRIPT
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if site.index == 0 {
                continue;
            }
            let Some(row) = command_tagged(ctx, c, "interpreter") else {
                continue;
            };
            let stdin = lint(row, "stdin_args");
            let reads = c.args.is_empty()
                || c
                    .args
                    .iter()
                    .any(|a| literal(a).is_some_and(|v| stdin.contains(&v.as_str())));
            if !reads {
                continue;
            }
            out.push(finding(
                PS_STDIN_SCRIPT,
                Level::Warn,
                c.span,
                format!(
                    "script text piped into `{}` through PowerShell's stdin loses its non-ASCII characters (they arrive as U+FFFD)",
                    c.typed
                ),
                format!(
                    "write the script to a UTF-8 file with the Write tool and run {} <file>",
                    c.typed
                ),
            ));
            return;
        }
    }
}

pub const PS_EMPTY_ARG: &str = "ps-empty-arg";

/// `'""'` as a native argument passes two quote characters, not an empty value
/// (`ssh-keygen -N '""'` sets the passphrase to `""`).
pub struct EmptyArg;

impl Rule for EmptyArg {
    fn id(&self) -> &'static str {
        PS_EMPTY_ARG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if !is_native(c, t, ctx.input.os, &w) {
                continue;
            }
            let Some(a) = c
                .args
                .iter()
                .find(|a| a.quote == Quote::Single && literal(a).as_deref() == Some("\"\""))
            else {
                continue;
            };
            out.push(finding(
                PS_EMPTY_ARG,
                Level::Warn,
                a.span,
                format!(
                    "`'\"\"'` reaches `{}` as two quote characters, not as an empty value",
                    c.typed
                ),
                "write an empty native argument as ''".to_string(),
            ));
            return;
        }
    }
}

pub const RG_FOLLOW_L: &str = "rg-follow-L";

/// `rg -L` is `--follow` (follow symlinks), not grep's "files without a match". The rg row's
/// `lint.follow_flags` holds the spelling and its `fix` the right option.
pub struct RgFollow;

impl Rule for RgFollow {
    fn id(&self) -> &'static str {
        RG_FOLLOW_L
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = program_of(ctx, c).filter(|p| !lint(p, "follow_flags").is_empty())
            else {
                continue;
            };
            let flags = lint(row, "follow_flags");
            let Some(a) = c.args.iter().find(|a| flags.contains(&text(src, a.span))) else {
                continue;
            };
            let instead = row.fix.as_deref().unwrap_or("the long option name");
            out.push(finding(
                RG_FOLLOW_L,
                Level::Warn,
                a.span,
                format!(
                    "`{} {}` follows symbolic links; it does not list the files without a match",
                    c.typed,
                    text(src, a.span)
                ),
                format!(
                    "for files without a match use {instead}: {}",
                    replaced(src, c.span, a.span, instead)
                ),
            ));
            return;
        }
    }
}

pub const WSL_ARGV_REJOIN: &str = "wsl-argv-rejoin";

/// `wsl <command> <args>` joins its arguments into one line that the Linux shell parses again,
/// so quotes, `$` and spaces inside an argument change meaning. `--exec` passes them as they are.
/// The row tagged `wsl-launcher`: `lint.exec_flags` (`-e`, `--exec`), `value_options` (`-d`, `-u`).
pub struct WslArgvRejoin;

impl Rule for WslArgvRejoin {
    fn id(&self) -> &'static str {
        WSL_ARGV_REJOIN
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "wsl-launcher") else {
                continue;
            };
            let exec = lint(row, "exec_flags");
            let values: Vec<Option<String>> = c.args.iter().map(literal).collect();
            let mut k = 0;
            let mut runs = None;
            while k < values.len() {
                let Some(v) = values[k].as_deref() else {
                    runs = Some(k);
                    break;
                };
                if exec.iter().any(|e| e.eq_ignore_ascii_case(v)) {
                    runs = None;
                    break;
                }
                if v == "--" {
                    runs = Some(k + 1);
                    break;
                }
                if v.starts_with('-') {
                    let takes = row.value_options.iter().any(|o| o.eq_ignore_ascii_case(v));
                    k += if takes { 2 } else { 1 };
                    continue;
                }
                runs = Some(k);
                break;
            }
            let Some(start) = runs else { continue };
            let reparsed = c.args.iter().skip(start).find(|a| {
                literal(a).is_none_or(|v| {
                    v.chars().any(|ch| {
                        ch.is_whitespace()
                            || matches!(
                                ch,
                                '$' | '`'
                                    | '"'
                                    | '\''
                                    | '\\'
                                    | ';'
                                    | '|'
                                    | '&'
                                    | '<'
                                    | '>'
                                    | '*'
                                    | '?'
                                    | '('
                                    | ')'
                            )
                    })
                })
            });
            let Some(a) = reparsed else { continue };
            out.push(finding(
                WSL_ARGV_REJOIN,
                Level::Warn,
                a.span,
                format!(
                    "`{}` joins its arguments into one line that the Linux shell parses again, so `{}` may not arrive as written",
                    c.typed,
                    text(ctx.input.command, a.span)
                ),
                "run it as wsl.exe --exec <shell> -c '<command>'".to_string(),
            ));
            return;
        }
    }
}

pub const CLAUDE_CMD_LIVE_CONFIG: &str = "claude-cmd-live-config";

/// A `claude` CLI command run against the live config dir: it writes `.claude.json`, `backups/`
/// and the like there. The row tagged `claude-cli`: `lint.config_env` (the variable that moves the
/// config dir) and `lint.harmless` (arguments that write nothing).
pub struct ClaudeLiveConfig;

impl Rule for ClaudeLiveConfig {
    fn id(&self) -> &'static str {
        CLAUDE_CMD_LIVE_CONFIG
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "claude-cli") else {
                continue;
            };
            let env_names = lint(row, "config_env");
            let set_here = env_names.iter().any(|n| {
                let key = format!("{ENV_SCOPE}{}", n.to_lowercase());
                w.assigned.contains(&key)
            });
            let set_before = env_names.iter().any(|n| ctx.input.env.get(n).is_some());
            if set_here || set_before {
                continue;
            }
            let harmless = lint(row, "harmless");
            let writes = c
                .args
                .iter()
                .any(|a| literal(a).is_none_or(|v| !harmless.contains(&v.as_str())));
            if !writes {
                continue;
            }
            let Some(var) = env_names.first().copied() else {
                continue;
            };
            out.push(finding(
                CLAUDE_CMD_LIVE_CONFIG,
                Level::Warn,
                c.span,
                format!(
                    "`{}` writes into the live config dir (.claude.json, backups/) unless ${var} points elsewhere",
                    c.typed
                ),
                format!(
                    "$env:{var} = Join-Path $env:TEMP 'claude-scratch'; {}",
                    text(ctx.input.command, c.span)
                ),
            ));
            return;
        }
    }
}
