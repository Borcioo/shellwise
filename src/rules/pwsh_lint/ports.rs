//! The installed baseline guard PowerShell rules, except `bat-metachar` (`bat.rs`). They are
//! break, as in the baseline guard, except `gate-truncated-pipeline`, `ps-bare-bash` and
//! `ps-dotnet-relative-path`: warn, because in the corpus each also fired on runs that worked.

use tree_sitter::{Node, Parser};

use super::bind::{
    Arg, Bound, Problem, bind, bind_args, ends_parameters, named, positional, switch_on,
};
use super::table::{ALL_SETS, Cmdlet, Facts};
use super::{
    Ctx, ENV_SCOPE, Rule, Site, Walk, command_tagged, elem_span, finding, has_folder, is_native,
    is_pwsh, lint, literal, plain_var, program, replaced, table_name, text, upstream, walk,
};
use crate::Os;
use crate::ir::{Elem, Quote, SimpleCommand, Stmt, WordPart};
use crate::level::{Finding, Level, Span};
use crate::rules::Scope;

// ---------------------------------------------------------------------------------------------
// gate-truncated-pipeline
// ---------------------------------------------------------------------------------------------

pub const GATE_TRUNCATED_PIPELINE: &str = "gate-truncated-pipeline";

/// A gate, test run or tee'd log piped into a truncator (`Select-Object -First`, `head`): the
/// truncator stops the producer once it has its lines, so the exit code reads as success and the
/// log is cut off. A producer is a gate when its name matches `cfg.gate_commands` or a script
/// host runs a script that does; behind a `Tee-Object` (Bash: `tee`) any producer counts. Every
/// shell: the Bash tools carry the same tags in `data/programs.toml`.
pub struct GateTruncatedPipeline;

impl Rule for GateTruncatedPipeline {
    fn id(&self) -> &'static str {
        GATE_TRUNCATED_PIPELINE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let pwsh = is_pwsh(ctx);
        let src = ctx.input.command;
        let w = walk(ctx.script);
        for site in &w.sites {
            if site.index == 0 || !truncates(ctx, site.cmd, &w) {
                continue;
            }
            let Some(blamed) = gate_upstream(ctx, site) else {
                continue;
            };
            let first = &site.pipe.elems[0];
            let producer_end = elem_span(&site.pipe.elems[site.index - 1]).end;
            let producer = text(
                src,
                Span {
                    start: elem_span(first).start,
                    end: producer_end,
                },
            )
            .trim();
            // Bash: `tail` reads the whole stream, and `pipefail` in a subshell keeps the
            // producer's exit code without changing the caller's shell options.
            let (whole, fix) = if pwsh {
                (
                    "Select-Object -Last N",
                    format!("$out = {producer} 2>&1; $out | Select-Object -Last 20"),
                )
            } else {
                (
                    "tail -n N",
                    format!("(set -o pipefail; {producer} | tail -n 20)"),
                )
            };
            out.push(finding(
                GATE_TRUNCATED_PIPELINE,
                Level::Warn,
                site.cmd.span,
                format!(
                    "`{blamed}` is piped into `{}`, which stops the producer as soon as it has its lines: the exit code then reads as success and the log is cut off; `{whole}` reads the whole stream and is fine",
                    site.cmd.typed
                ),
                fix,
            ));
            return;
        }
    }
}

/// `Select-Object -First` (a row tagged `truncator` whose `lint.truncate_params` names the
/// bound parameter, read through the pwsh 7 table), or a truncator with no such list (`head`).
fn truncates(ctx: &Ctx, c: &SimpleCommand, w: &Walk) -> bool {
    let Some(p) = command_tagged(ctx, c, "truncator") else {
        return false;
    };
    let params = lint(p, "truncate_params");
    if params.is_empty() {
        return true;
    }
    let Some(t) = Facts::for_shell(ctx.input.shell) else {
        return false;
    };
    let Some(cmd) = table_name(c, t, ctx.input.os, w) else {
        return false;
    };
    let Some(args) = bind_args(ctx.input.command, c, cmd) else {
        return false;
    };
    params.iter().any(|p| named(&args, p).is_some())
}

/// The producer to blame, nearest first: behind a tee, the command feeding it; a gate itself.
fn gate_upstream(ctx: &Ctx, site: &Site) -> Option<String> {
    let mut chain: Vec<&SimpleCommand> = Vec::new();
    for e in site.pipe.elems[..site.index].iter().rev() {
        if let Elem::Cmd(c) = e {
            chain.push(c);
        }
    }
    for (k, c) in chain.iter().enumerate() {
        if command_tagged(ctx, c, "tee-cmdlet").is_some() {
            let feeder = chain[k + 1..]
                .iter()
                .find(|u| command_tagged(ctx, u, "tee-cmdlet").is_none());
            return Some(feeder.map_or(c.typed.clone(), |u| u.typed.clone()));
        }
        if is_gate(ctx, c) {
            return Some(c.typed.clone());
        }
    }
    None
}

fn gate_named(ctx: &Ctx, name: &str) -> bool {
    !ctx.cfg.gate_commands.is_empty() && super::bat::launcher_named(name, &ctx.cfg.gate_commands)
}

/// A gate by its name, or a script host (`lint.script_flags`, `lint.command_flags`, else the
/// first positional word) running one.
fn is_gate(ctx: &Ctx, c: &SimpleCommand) -> bool {
    if c.opaque {
        return false;
    }
    if gate_named(ctx, &c.typed) {
        return true;
    }
    let Some(host) = program(ctx, &c.typed).filter(|p| !lint(p, "script_flags").is_empty()) else {
        return false;
    };
    let script_flags = lint(host, "script_flags");
    let command_flags = lint(host, "command_flags");
    let values: Vec<Option<String>> = c.args.iter().map(literal).collect();
    let mut k = 0;
    while k < values.len() {
        let Some(v) = values[k].as_deref() else {
            return false;
        };
        if script_flags.iter().any(|f| f.eq_ignore_ascii_case(v)) {
            return values
                .get(k + 1)
                .and_then(|x| x.as_deref())
                .is_some_and(|s| gate_named(ctx, s));
        }
        if command_flags.iter().any(|f| f.eq_ignore_ascii_case(v)) {
            let body: Vec<String> = values[k + 1..].iter().flatten().cloned().collect();
            return body
                .join(" ")
                .split(|ch: char| ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '\'' | '"'))
                .any(|t| !t.is_empty() && gate_named(ctx, t));
        }
        if v.starts_with(['-', '+']) {
            let takes = host.value_options.iter().any(|o| o.eq_ignore_ascii_case(v));
            k += if takes { 2 } else { 1 };
            continue;
        }
        return gate_named(ctx, v);
    }
    false
}

// ---------------------------------------------------------------------------------------------
// ps-bad-parameter
// ---------------------------------------------------------------------------------------------

pub const PS_BAD_PARAMETER: &str = "ps-bad-parameter";

/// A parameter the cmdlet does not have, a prefix that matches several, a parameter that needs a
/// value and gets none, or one positional argument too many: PowerShell refuses the call. Bound
/// against the pwsh 7 table. A row's `lint.flag_hints` (`"-la=-Force"`; a key ending in `#`
/// fires only before a number, `"-A#=-Context 0,"`) gives the replacement for a bash spelling,
/// including one that binds (`Select-String -A 2` binds `-AllMatches`).
pub struct BadParameter;

impl Rule for BadParameter {
    fn id(&self) -> &'static str {
        PS_BAD_PARAMETER
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        let src = ctx.input.command;
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            let Some(cmd) = table_name(c, t, ctx.input.os, &w) else {
                continue;
            };
            if let Some(f) = hint_finding(ctx, c, cmd) {
                out.push(f);
                continue;
            }
            if cmd.takes_remaining() {
                continue;
            }
            let Some(args) = bind_args(src, c, cmd) else {
                continue;
            };
            let other_provider = on_another_provider(c, cmd);
            let before = out.len();
            for a in &args {
                let Arg::Named {
                    word,
                    problem: Some(problem),
                    ..
                } = a
                else {
                    continue;
                };
                // Another provider (`Cert:`, `HKLM:`) has other dynamic parameters.
                if other_provider && *problem == Problem::Missing {
                    continue;
                }
                let typed = text(src, word.span);
                let (message, fix) = match problem {
                    Problem::Missing => (
                        format!(
                            "`{}` has no parameter `{typed}`, so PowerShell refuses the call (\"A parameter cannot be found that matches parameter name\")",
                            cmd.name
                        ),
                        format!("remove `{typed}`: {}", replaced(src, c.span, word.span, "")),
                    ),
                    Problem::Ambiguous(names) => {
                        let list = names
                            .iter()
                            .map(|n| format!("-{n}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        (
                            format!(
                                "`{typed}` matches several parameters of `{}` ({list}), so PowerShell refuses the call",
                                cmd.name
                            ),
                            format!("write the full parameter name, one of {list}"),
                        )
                    }
                    Problem::NoValue(p) => (
                        format!(
                            "`{typed}` binds `-{p}` of `{}`, which needs a value, and none follows, so PowerShell refuses the call (\"Missing an argument for parameter\")",
                            cmd.name
                        ),
                        format!(
                            "give -{p} a value or remove it: {}",
                            replaced(src, c.span, word.span, "")
                        ),
                    ),
                };
                out.push(finding(
                    PS_BAD_PARAMETER,
                    Level::Break,
                    word.span,
                    message,
                    fix,
                ));
                break;
            }
            if out.len() == before && !other_provider {
                out.extend(extra_positional(src, c, cmd, &args));
            }
        }
    }
}

/// A provider cmdlet (one with dynamic parameters) given a path on a drive of another provider
/// (`Cert:`, `HKLM:`, `Env:`: a drive name longer than one letter): its dynamic parameters are
/// not the FileSystem ones the table lists.
fn on_another_provider(c: &SimpleCommand, cmd: &Cmdlet) -> bool {
    if !cmd.params.iter().any(|p| p.dynamic) {
        return false;
    }
    c.args.iter().filter_map(literal).any(|v| {
        v.split_once(':').is_some_and(|(drive, _)| {
            drive.len() > 1
                && drive
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                && drive
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphabetic())
        })
    })
}

/// A `lint.flag_hints` spelling on the cmdlet's row, as typed (case counts, as in bash).
fn hint_finding(ctx: &Ctx, c: &SimpleCommand, cmd: &Cmdlet) -> Option<Finding> {
    let src = ctx.input.command;
    let row = program(ctx, cmd.name)?;
    let hints = lint(row, "flag_hints");
    // After `--` every word is an argument (`Get-ChildItem -- -la` lists the path `-la`).
    let over = c.args.iter().position(|w| ends_parameters(src, w));
    for (k, a) in c.args.iter().enumerate() {
        if over.is_some_and(|o| k > o) {
            break;
        }
        if a.quote != Quote::None {
            continue;
        }
        let typed = text(src, a.span);
        for h in &hints {
            let Some((key, replacement)) = h.split_once('=') else {
                continue;
            };
            let (spelling, before_number) = match key.strip_suffix('#') {
                Some(s) => (s, true),
                None => (key, false),
            };
            if typed != spelling {
                continue;
            }
            if before_number {
                let Some(next) = c.args.get(k + 1) else {
                    continue;
                };
                let Some(n) = literal(next)
                    .filter(|v| !v.is_empty() && v.chars().all(|d| d.is_ascii_digit()))
                else {
                    continue;
                };
                // A spelling that binds no parameter (`Select-Object -n 5`) is refused whatever
                // the number binds to.
                if bind(cmd, spelling.trim_start_matches('-')) != Bound::Missing
                    && number_takes_the_first_position(src, c, cmd, next)
                {
                    continue;
                }
                let cut = Span {
                    start: a.span.start,
                    end: next.span.end,
                };
                return Some(finding(
                    PS_BAD_PARAMETER,
                    Level::Break,
                    cut,
                    format!(
                        "`{typed} {n}` is a bash flag: `{}` reads `{typed}` as another parameter and refuses `{n}`",
                        cmd.name
                    ),
                    format!(
                        "use {replacement}{n}: {}",
                        replaced(src, c.span, cut, &format!("{replacement}{n}"))
                    ),
                ));
            }
            let (message, fix) = if replacement.is_empty() {
                (
                    format!(
                        "`{typed}` is cmd.exe or bash syntax that `{}` refuses",
                        cmd.name
                    ),
                    format!("remove `{typed}`: {}", replaced(src, c.span, a.span, "")),
                )
            } else {
                (
                    format!(
                        "`{typed}` is a bash flag that `{}` refuses; PowerShell's spelling is {replacement}",
                        cmd.name
                    ),
                    format!(
                        "use {replacement}: {}",
                        replaced(src, c.span, a.span, replacement)
                    ),
                )
            };
            return Some(finding(
                PS_BAD_PARAMETER,
                Level::Break,
                a.span,
                message,
                fix,
            ));
        }
    }
    None
}

/// The number after a hinted flag is the call's only positional word and the parameter at
/// position 0 is not named: the call binds (`Select-String -A 1 -Path f` searches for `1`), so
/// PowerShell does not refuse it (probed in pwsh 7.7).
fn number_takes_the_first_position(
    src: &str,
    c: &SimpleCommand,
    cmd: &Cmdlet,
    number: &crate::ir::Word,
) -> bool {
    let Some(args) = bind_args(src, c, cmd) else {
        return false;
    };
    let given = positional(&args);
    if !(given.len() == 1 && given[0].span == number.span) {
        return false;
    }
    !cmd.params
        .iter()
        .filter(|p| p.sets.iter().any(|m| m.position == 0))
        .any(|p| named(&args, p.name).is_some())
}

/// More positional arguments than any parameter set has positions for: PowerShell refuses the
/// call ("A positional parameter cannot be found that accepts argument"). Not judged with a
/// splat, which may bind any parameter.
fn extra_positional(src: &str, c: &SimpleCommand, cmd: &Cmdlet, args: &[Arg]) -> Option<Finding> {
    if c.args.iter().any(|a| text(src, a.span).starts_with('@')) {
        return None;
    }
    let given = positional(args);
    let max = max_positional(cmd);
    let extra = given.get(max)?;
    Some(finding(
        PS_BAD_PARAMETER,
        Level::Break,
        extra.span,
        format!(
            "`{}` takes at most {max} positional argument(s) and `{}` is one more, so PowerShell refuses the call (\"A positional parameter cannot be found that accepts argument\")",
            cmd.name,
            text(src, extra.span)
        ),
        format!(
            "name the parameter for `{}` or remove it: {}",
            text(src, extra.span),
            replaced(src, c.span, extra.span, "")
        ),
    ))
}

/// The most positions one parameter set offers (its own parameters and those in every set).
fn max_positional(cmd: &Cmdlet) -> usize {
    let mut sets: Vec<&str> = cmd
        .params
        .iter()
        .flat_map(|p| p.sets.iter().map(|m| m.set))
        .filter(|s| *s != ALL_SETS)
        .collect();
    sets.sort_unstable();
    sets.dedup();
    if sets.is_empty() {
        sets.push(ALL_SETS);
    }
    sets.iter()
        .map(|set| {
            cmd.params
                .iter()
                .filter(|p| {
                    p.sets
                        .iter()
                        .any(|m| m.position >= 0 && (m.set == *set || m.set == ALL_SETS))
                })
                .count()
        })
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// ps-bare-bash
// ---------------------------------------------------------------------------------------------

pub const PS_BARE_BASH: &str = "ps-bare-bash";

/// `bash` typed in PowerShell on Windows runs System32's `bash.exe`, which is WSL, not Git Bash.
/// The row tagged `wsl-bash` holds the name and the replacement call (`fix`).
pub struct BareBash;

impl Rule for BareBash {
    fn id(&self) -> &'static str {
        PS_BARE_BASH
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) || ctx.input.os != Os::Windows {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if c.opaque || has_folder(&c.typed) {
                continue;
            }
            let Some(p) = command_tagged(ctx, c, "wsl-bash") else {
                continue;
            };
            let call = p.fix.as_deref().unwrap_or("the Bash tool");
            let rest = text(
                src,
                Span {
                    start: c.name.span.end,
                    end: c.span.end,
                },
            )
            .trim();
            out.push(finding(
                PS_BARE_BASH,
                Level::Warn,
                c.name.span,
                format!(
                    "`{}` typed in PowerShell runs the System32 bash.exe, which is WSL, not Git Bash: Windows paths and CRLF scripts break there; use the Bash tool, or call wsl on purpose",
                    c.typed
                ),
                format!("{call} {rest}").trim().to_string(),
            ));
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ps-native-nonewline
// ---------------------------------------------------------------------------------------------

pub const PS_NATIVE_NONEWLINE: &str = "ps-native-nonewline";

/// A native program piped into a writer (`lint.tags = ["file-writer"]`) with `-NoNewline`: the
/// output arrives as lines and `-NoNewline` joins them into one line.
pub struct NativeNonewline;

impl Rule for NativeNonewline {
    fn id(&self) -> &'static str {
        PS_NATIVE_NONEWLINE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        let src = ctx.input.command;
        let os = ctx.input.os;
        let w = walk(ctx.script);
        for site in &w.sites {
            let c = site.cmd;
            if command_tagged(ctx, c, "file-writer").is_none() {
                continue;
            }
            let Some(cmd) = table_name(c, t, os, &w) else {
                continue;
            };
            let Some(args) = bind_args(src, c, cmd) else {
                continue;
            };
            if !switch_on(src, &args, "nonewline") {
                continue;
            }
            let Some(native) = upstream(site).and_then(|e| native_producer(e, t, os, &w)) else {
                continue;
            };
            let Some(Arg::Named { word, value, .. }) = named(&args, "nonewline") else {
                continue;
            };
            let cut = Span {
                start: word.span.start,
                end: value.map_or(word.span.end, |v| v.span.end),
            };
            out.push(finding(
                PS_NATIVE_NONEWLINE,
                Level::Break,
                c.span,
                format!(
                    "`{native}` output reaches `{}` as separate lines, and -NoNewline joins them into one line, so every line break is lost",
                    c.typed
                ),
                format!("drop -NoNewline: {}", replaced(src, c.span, cut, "")),
            ));
            return;
        }
    }
}

/// The native program an upstream element runs: a native command, or a parenthesised one.
fn native_producer(e: &Elem, t: Facts, os: Os, w: &Walk) -> Option<String> {
    match e {
        Elem::Cmd(c) if is_native(c, t, os, w) => Some(c.typed.clone()),
        Elem::Expr(word) => match word.parts.as_slice() {
            [WordPart::Subst(s)] => match s.stmts.as_slice() {
                [Stmt::Pipeline(p)] => p
                    .elems
                    .last()
                    .and_then(|last| native_producer(last, t, os, w)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// ps-dotnet-relative-path
// ---------------------------------------------------------------------------------------------

pub const PS_DOTNET_RELATIVE_PATH: &str = "ps-dotnet-relative-path";

/// `[IO.File]::ReadAllText('rel\x')`, `[IO.Directory]::CreateDirectory('rel')`: a relative
/// literal path is resolved against `[Environment]::CurrentDirectory`, which `cd` and
/// Set-Location never move, so the call reads or writes in another folder. The calls and their
/// path positions are the table's `dotnet` rows.
pub struct DotnetRelativePath;

impl Rule for DotnetRelativePath {
    fn id(&self) -> &'static str {
        PS_DOTNET_RELATIVE_PATH
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        let src = ctx.input.command;
        for m in walk(ctx.script).methods {
            let Some(indexes) = t.dotnet_path_args(&m.type_name, &m.method) else {
                continue;
            };
            for &k in indexes {
                let Some(arg) = m.args.get(k) else { continue };
                let raw = text(src, arg.span).trim();
                let Some(head) = literal_path_head(raw) else {
                    continue;
                };
                if head.is_empty() || is_rooted(&head) {
                    continue;
                }
                let call = format!("[{}]::{}", m.type_name, m.method);
                out.push(finding(
                    PS_DOTNET_RELATIVE_PATH,
                    Level::Warn,
                    arg.span,
                    format!(
                        "`{call}` resolves the relative path `{head}` against the process directory, not the location `cd` / Set-Location set, so it reads or writes a file in another folder"
                    ),
                    format!(
                        "pass an absolute path: {}",
                        replaced(src, m.span, arg.span, &format!("(Join-Path $PWD {raw})"))
                    ),
                ));
                return;
            }
        }
    }
}

/// The literal text a path argument starts with: all of a `'...'` string, a `"..."` string up to
/// its first `$` or backtick; `None` for a variable, a call or an expression.
fn literal_path_head(raw: &str) -> Option<String> {
    let inner = |q: char| raw.strip_prefix(q).and_then(|r| r.strip_suffix(q));
    if raw.len() >= 2 {
        if let Some(s) = inner('\'') {
            return Some(s.replace("''", "'"));
        }
        if let Some(s) = inner('"') {
            return Some(s.split(['$', '`']).next().unwrap_or("").to_string());
        }
    }
    None
}

fn is_rooted(path: &str) -> bool {
    let b = path.as_bytes();
    matches!(b.first(), Some(b'\\' | b'/'))
        || (b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/'))
}

// ---------------------------------------------------------------------------------------------
// stale-write-var
// ---------------------------------------------------------------------------------------------

pub const STALE_WRITE_VAR: &str = "stale-write-var";

/// A variable written into a file that this command never assigns. Shell state does not survive
/// between tool calls, so it reads as `$null` and the write empties the file. Writers are the rows
/// tagged `file-writer` (their content: the bound content parameters, the positional word at
/// `lint.content_position`, or a bare expression piped in; `lint.append_params` skips an append)
/// and `[IO.File]::WriteAll*`. Bound names: assignments, the common parameters that name a
/// variable, a row's `lint.variable_params` (`Tee-Object -Variable`, `Set-Variable -Name`, named or
/// at its position), `foreach` variables and parameters. A dot-sourced script may set any
/// variable, so a write after one is not judged. A command line only: a script file keeps its
/// state from line to line.
pub struct StaleWriteVar;

/// `[IO.File]::WriteAll*`: (type, method prefix).
const WRITE_ALL: &[(&str, &str)] = &[("io.file", "writeall"), ("system.io.file", "writeall")];

/// Common parameters that bind a variable by name.
const VARIABLE_PARAMS: &[&str] = &[
    "outvariable",
    "pipelinevariable",
    "errorvariable",
    "warningvariable",
    "informationvariable",
];

/// The parameters that carry a writer's content, and those that name its file.
const CONTENT_PARAMS: &[&str] = &["value", "inputobject"];
const PATH_PARAMS: &[&str] = &["path", "literalpath", "filepath"];

impl Rule for StaleWriteVar {
    fn id(&self) -> &'static str {
        STALE_WRITE_VAR
    }

    fn scope(&self) -> Scope {
        Scope::CommandLine
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let Some(t) = Facts::for_shell(ctx.input.shell) else {
            return;
        };
        let src = ctx.input.command;
        let w = walk(ctx.script);
        let mut contents: Vec<(Span, String)> = Vec::new();
        for m in &w.methods {
            let ty = m.type_name.to_lowercase();
            let method = m.method.to_lowercase();
            if WRITE_ALL
                .iter()
                .any(|(t, p)| *t == ty && method.starts_with(p))
                && let Some(a) = m.args.get(1)
            {
                contents.push((a.span, text(src, a.span).to_string()));
            }
        }
        let mut bound: Vec<String> = w.assigned.clone();
        // Where the first dot-source starts: `. .\vars.ps1` runs the script in this scope.
        let dot_sourced = w
            .sites
            .iter()
            .map(|s| s.cmd)
            .filter(|c| c.name.span.start > c.span.start && src[c.span.start..].starts_with('.'))
            .map(|c| c.span.start)
            .min();
        for site in &w.sites {
            let c = site.cmd;
            let Some(cmd) = table_name(c, t, ctx.input.os, &w) else {
                continue;
            };
            let Some(args) = bind_args(src, c, cmd) else {
                continue;
            };
            for p in VARIABLE_PARAMS {
                if let Some(v) = named_value(src, &args, p) {
                    bound.push(v.trim_start_matches('+').to_lowercase());
                }
            }
            if let Some(row) = program(ctx, cmd.name) {
                for p in lint(row, "variable_params") {
                    if let Some(v) =
                        named_value(src, &args, p).or_else(|| at_position(&args, cmd, p))
                    {
                        bound.push(v.to_lowercase());
                    }
                }
            }
            let Some(row) = command_tagged(ctx, c, "file-writer") else {
                continue;
            };
            if lint(row, "append_params")
                .iter()
                .any(|p| switch_on(src, &args, p))
            {
                continue;
            }
            for p in CONTENT_PARAMS {
                if let Some(Arg::Named {
                    word,
                    value,
                    attached,
                    ..
                }) = named(&args, p)
                {
                    match (value, attached) {
                        (Some(v), _) => contents.push((v.span, text(src, v.span).to_string())),
                        (None, Some(a)) => contents.push((word.span, a.clone())),
                        _ => {}
                    }
                }
            }
            let path_named = PATH_PARAMS.iter().any(|p| named(&args, p).is_some());
            let content_named = CONTENT_PARAMS.iter().any(|p| named(&args, p).is_some());
            if !content_named
                && let Some(pos) = lint(row, "content_position")
                    .first()
                    .and_then(|s| s.parse::<usize>().ok())
            {
                let pos = if path_named {
                    pos.saturating_sub(1)
                } else {
                    pos
                };
                if let Some(word) = positional(&args).get(pos) {
                    contents.push((word.span, text(src, word.span).to_string()));
                }
            }
            if let Some(Elem::Expr(x)) = upstream(site) {
                contents.push((x.span, text(src, x.span).to_string()));
            }
        }
        if contents.is_empty() {
            return;
        }
        // The second parse runs only for a command that writes a variable.
        bound.extend(tree_bound_names(src));
        for (span, expr) in contents {
            if dot_sourced.is_some_and(|at| span.start > at) {
                continue;
            }
            if let Some(name) = stale_var(&expr, &bound, t) {
                out.push(finding(
                    STALE_WRITE_VAR,
                    Level::Break,
                    span,
                    format!(
                        "`${name}` is written into the file but never assigned in this command, and shell state does not survive between tool calls: it reads as $null and overwrites the file with nothing"
                    ),
                    format!(
                        "assign ${name} in this same command before the write (${name} = <value>; ...), or append with Add-Content"
                    ),
                ));
                return;
            }
        }
    }
}

/// The value given to a bound parameter: its separate word or its attached text.
fn named_value(src: &str, args: &[Arg], param: &str) -> Option<String> {
    match named(args, param)? {
        Arg::Named { value: Some(v), .. } => {
            Some(literal(v).unwrap_or_else(|| text(src, v.span).to_string()))
        }
        Arg::Named {
            attached: Some(a), ..
        } => Some(a.trim_matches(['\'', '"']).to_string()),
        _ => None,
    }
}

/// The literal positional word that binds `param`: the one at the position `param` holds in a
/// parameter set, when `param` is not given by name.
fn at_position(args: &[Arg], cmd: &Cmdlet, param: &str) -> Option<String> {
    let p = cmd.params.iter().find(|p| p.name == param)?;
    let k = p.sets.iter().find(|m| m.position >= 0)?.position;
    positional(args)
        .get(usize::try_from(k).ok()?)
        .and_then(|w| literal(w))
}

/// Names bound without an assignment: `foreach ($x in …)` and parameters (`param($a)`,
/// `function f($a)`), read from the tree-sitter tree, which keeps them where the IR does not.
fn tree_bound_names(src: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(src, None) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut stack: Vec<Node> = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        if matches!(n.kind(), "foreach_statement" | "script_parameter") {
            if let Some(k) = n
                .named_children(&mut cursor)
                .find(|k| k.kind() == "variable")
            {
                let name = src.get(k.start_byte()..k.end_byte()).unwrap_or("");
                names.push(plain_var(name.trim_start_matches('$')));
            }
            cursor = n.walk();
        }
        stack.extend(n.children(&mut cursor));
    }
    names
}

/// The first variable `expr` expands that is neither bound nor a variable the session sets.
fn stale_var(expr: &str, bound: &[String], t: Facts) -> Option<String> {
    let code = expandable(expr);
    let b = code.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' || (i > 0 && b[i - 1] == b'`') {
            i += 1;
            continue;
        }
        let rest = &code[i + 1..];
        let take = |s: &str| -> usize {
            s.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .count()
        };
        let first = rest.chars().next();
        if !first.is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
            i += 1;
            continue;
        }
        let mut name_len = take(rest);
        let mut name = &rest[..name_len];
        if rest[name_len..].starts_with(':') {
            if rest[..name_len + 1].eq_ignore_ascii_case(ENV_SCOPE) {
                i += 1 + name_len;
                continue;
            }
            let after = &rest[name_len + 1..];
            let n2 = take(after);
            if n2 > 0 {
                name = &after[..n2];
                name_len += 1 + n2;
            }
        }
        let low = name.to_lowercase();
        if t.variable_kind(&low).is_none() && !bound.contains(&low) {
            return Some(name.to_string());
        }
        i += 1 + name_len;
    }
    None
}

/// `expr` without the text that expands nothing: single-quoted strings and verbatim
/// here-strings.
fn expandable(expr: &str) -> String {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut dq = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            out.extend(chars[i..(i + 2).min(chars.len())].iter());
            i += 2;
            continue;
        }
        if c == '@' && !dq && chars.get(i + 1) == Some(&'\'') {
            let rest: String = chars[i..].iter().collect();
            match rest.find("\n'@") {
                Some(j) => i += rest[..j + 3].chars().count(),
                None => i = chars.len(),
            }
            continue;
        }
        if c == '"' {
            dq = !dq;
        } else if c == '\'' && !dq {
            let mut j = i + 1;
            while j < chars.len() {
                if chars[j] == '\'' {
                    if chars.get(j + 1) == Some(&'\'') {
                        j += 2;
                        continue;
                    }
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------------------------
// ps-git-commit-stdin
// ---------------------------------------------------------------------------------------------

pub const PS_GIT_COMMIT_STDIN: &str = "ps-git-commit-stdin";

/// `git commit -F -` with nothing piped in: PowerShell passes the here-string after it as a
/// pathspec, and no commit is made. The row tagged `git-cli` lists in `lint`:
/// `global_value_options` (git's own options that take a value), `stdin_commit` (the
/// subcommand), `file_long` (`--file`) and `file_short` (`F`).
pub struct GitCommitStdin;

impl Rule for GitCommitStdin {
    fn id(&self) -> &'static str {
        PS_GIT_COMMIT_STDIN
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            if site.index > 0 {
                continue;
            }
            let Some(git) = command_tagged(ctx, c, "git-cli") else {
                continue;
            };
            let values: Vec<String> = c
                .args
                .iter()
                .map(|a| literal(a).unwrap_or_default())
                .collect();
            let globals = lint(git, "global_value_options");
            let mut k = 0;
            while k < values.len() && values[k].starts_with('-') {
                k += if globals.contains(&values[k].as_str()) {
                    2
                } else {
                    1
                };
            }
            let commit = lint(git, "stdin_commit");
            if !values.get(k).is_some_and(|s| commit.contains(&s.as_str())) {
                continue;
            }
            if reads_stdin(
                &values[k + 1..],
                &lint(git, "file_long"),
                &lint(git, "file_short"),
            ) {
                out.push(finding(
                    PS_GIT_COMMIT_STDIN,
                    Level::Break,
                    c.span,
                    "`git commit -F -` reads the message from stdin, but nothing is piped into it: PowerShell passes the here-string after it as a pathspec (\"error: pathspec ...\"), so no commit is made".to_string(),
                    "replace `-F -` with `-m` and keep the here-string after it (closing '@ at column 0), or write the message to a file and run git commit -F <file>".to_string(),
                ));
                return;
            }
        }
    }
}

fn reads_stdin(args: &[String], long: &[&str], short: &[&str]) -> bool {
    for (i, v) in args.iter().enumerate() {
        if v == "--" {
            return false;
        }
        let next = args.get(i + 1).map(String::as_str);
        if long
            .iter()
            .any(|l| *v == format!("{l}=-") || (v.as_str() == *l && next == Some("-")))
        {
            return true;
        }
        let Some(cluster) = v.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        for s in short {
            let letters_then = |tail: &str| {
                cluster
                    .strip_suffix(tail)
                    .is_some_and(|head| head.chars().all(|c| c.is_ascii_alphabetic()))
            };
            if (letters_then(s) && next == Some("-")) || letters_then(&format!("{s}-")) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------------------------
// cli-inline-prose (Specter AvoidSmartQuotes, for the strings PowerShell tears)
// ---------------------------------------------------------------------------------------------

pub const CLI_INLINE_PROSE: &str = "cli-inline-prose";

/// The typographic quotes that end a string opened by each straight quote.
const TORN_BY: [(char, &[char]); 2] = [
    ('"', &['\u{201e}', '\u{201c}', '\u{201d}']),
    ('\'', &['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}']),
];

/// `gh pr create --body "it „works”"`: PowerShell ends a string at a typographic quote of its own
/// family, so the text reaches gh torn into pieces. The row tagged `prose-cli` lists the
/// subcommands (`lint.prose_subcommands`) and the flags (`lint.prose_flags`, `"--body=--body-file"`
/// when a file form exists).
pub struct InlineProse;

impl Rule for InlineProse {
    fn id(&self) -> &'static str {
        CLI_INLINE_PROSE
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        if !is_pwsh(ctx) {
            return;
        }
        let src = ctx.input.command;
        for site in walk(ctx.script).sites {
            let c = site.cmd;
            let Some(row) = command_tagged(ctx, c, "prose-cli") else {
                continue;
            };
            let subs = lint(row, "prose_subcommands");
            let first_positional = c
                .args
                .iter()
                .filter_map(literal)
                .find(|v| !v.starts_with('-'));
            if !first_positional.is_some_and(|v| subs.contains(&v.as_str())) {
                continue;
            }
            let flags: Vec<(&str, Option<&str>)> = lint(row, "prose_flags")
                .into_iter()
                .map(|f| match f.split_once('=') {
                    Some((a, b)) => (a, Some(b)),
                    None => (f, None),
                })
                .collect();
            for (i, a) in c.args.iter().enumerate() {
                let raw = text(src, a.span);
                let mut hit: Option<(&str, Option<&str>, usize)> = None;
                for (flag, file) in &flags {
                    if raw == *flag {
                        if let Some(next) = c.args.get(i + 1) {
                            hit = Some((*flag, *file, next.span.start));
                        }
                    } else if let Some(rest) = raw.strip_prefix(flag) {
                        let attached =
                            rest.starts_with('=') || (!flag.starts_with("--") && !rest.is_empty());
                        if attached {
                            let skip = usize::from(rest.starts_with('='));
                            hit = Some((*flag, *file, a.span.start + flag.len() + skip));
                        }
                    }
                    if hit.is_some() {
                        break;
                    }
                }
                let Some((flag, file, at)) = hit else {
                    continue;
                };
                let tail = text(
                    src,
                    Span {
                        start: at,
                        end: c.span.end,
                    },
                );
                let Some((open, typographic)) = torn_quote(tail) else {
                    continue;
                };
                let (other_open, other) = if open == '"' {
                    ('\'', "'...'")
                } else {
                    ('"', "\"...\" (mind `$` in it)")
                };
                // The text holds quotes of both families: the other quote is torn too.
                let fix = match (torn_by_both(tail, other_open), file) {
                    (false, Some(f)) => format!(
                        "quote the {flag} text with {other} instead, or write the text with the Write tool and pass {f} <file>"
                    ),
                    (false, None) => format!("quote the {flag} text with {other} instead"),
                    (true, Some(f)) => {
                        format!("write the {flag} text with the Write tool and pass {f} <file>")
                    }
                    (true, None) => format!(
                        "pass the {flag} text in a here-string: @' at the end of the line before the text, '@ at the start of the line after it"
                    ),
                };
                out.push(finding(
                    CLI_INLINE_PROSE,
                    Level::Break,
                    a.span,
                    format!(
                        "PowerShell ends a string opened by `{open}` at a typographic `{typographic}` too, so the text after {flag} reaches {} torn into pieces or stripped of its quotes",
                        c.typed
                    ),
                    fix,
                ));
                return;
            }
        }
    }
}

/// Whether the string at the start of `raw` (to its closing straight quote) also holds a
/// typographic quote of `other`'s family, which would tear it quoted with `other` too.
fn torn_by_both(raw: &str, other: char) -> bool {
    let Some((_, family)) = TORN_BY.iter().find(|(open, _)| *open == other) else {
        return false;
    };
    let mut chars = raw.chars();
    let Some(q) = chars.next() else { return false };
    chars.take_while(|c| *c != q).any(|c| family.contains(&c))
}

/// (opening quote, typographic quote) for the first string at the start of `raw` that holds a
/// quote of its own family. A here-string ends only at its closing line, so it is never torn.
fn torn_quote(raw: &str) -> Option<(char, char)> {
    if raw.starts_with("@'") || raw.starts_with("@\"") {
        return None;
    }
    let chars: Vec<char> = raw.chars().collect();
    let q = *chars.first()?;
    let (_, family) = TORN_BY.iter().find(|(open, _)| *open == q)?;
    let mut j = 1;
    while j < chars.len() && chars[j] != q {
        if family.contains(&chars[j]) {
            return Some((q, chars[j]));
        }
        j += if chars[j] == '`' && q == '"' { 2 } else { 1 };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::bind::{Bound, bind};
    use super::*;

    #[test]
    fn a_stale_variable_is_one_the_command_does_not_bind() {
        let t = Facts::for_shell(crate::Shell::Pwsh).unwrap();
        let bound = vec!["report".to_string()];
        assert_eq!(stale_var("$text", &bound, t).as_deref(), Some("text"));
        assert_eq!(stale_var("$report", &bound, t), None);
        assert_eq!(stale_var("'$text'", &bound, t), None);
        assert_eq!(stale_var("$env:TEXT", &bound, t), None);
        assert_eq!(stale_var("$null", &bound, t), None);
        assert_eq!(stale_var("\"say `$x\"", &bound, t), None);
        assert_eq!(stale_var("($t + 'x')", &bound, t).as_deref(), Some("t"));
        assert_eq!(stale_var("$script:report", &bound, t), None);
    }

    #[test]
    fn a_torn_string_holds_a_quote_of_its_own_family() {
        assert_eq!(
            torn_quote("\"Zmiana \u{201e}x\u{201d} gotowa\""),
            Some(('"', '\u{201e}'))
        );
        assert_eq!(
            torn_quote("'Fix \u{2018}x\u{2019} now'"),
            Some(('\'', '\u{2018}'))
        );
        assert_eq!(torn_quote("'Zmiana \u{201e}x\u{201d}'"), None);
        assert_eq!(torn_quote("@'\n\u{201e}x\u{201d}\n'@"), None);
    }

    #[test]
    fn rooted_paths() {
        for p in ["C:\\x", "c:/x", "\\\\srv\\s", "/x"] {
            assert!(is_rooted(p), "{p}");
        }
        for p in ["tools\\x.php", "~/.claude/x", "x", "C:x"] {
            assert!(!is_rooted(p), "{p}");
        }
    }

    /// Known answers from real calls in pwsh 7.7 (`Get-Command <cmd>` and the error each call
    /// gives in an empty folder).
    #[test]
    fn binding_follows_powershell() {
        let t = Facts::for_shell(crate::Shell::Pwsh).unwrap();
        let bound = |cmd: &str, typed: &str| match bind(t.cmdlet(cmd).unwrap(), typed) {
            Bound::Param(p) => p.name.to_string(),
            Bound::Ambiguous(_) => "ambiguous".to_string(),
            Bound::Missing => "missing".to_string(),
        };
        let table = [
            ("select-string", "C", "ambiguous"),
            ("select-string", "Context", "context"),
            ("select-string", "A", "allmatches"),
            ("select-string", "i", "ambiguous"),
            ("select-string", "Recurse", "missing"),
            ("get-childitem", "la", "missing"),
            ("get-childitem", "l", "literalpath"),
            // A dynamic parameter loses to a static one (`-fo`: -Force, not -FollowSymlink) and is
            // tried when no static one matches (`-a`: -Attributes and the -ad/-af/... aliases).
            ("get-childitem", "fo", "force"),
            ("get-childitem", "a", "ambiguous"),
            ("get-childitem", "fi", "filter"),
            ("get-childitem", "h", "hidden"),
            ("get-content", "e", "exclude"),
            ("get-content", "w", "ambiguous"),
            ("set-content", "n", "nonewline"),
            ("get-childitem", "ea", "erroraction"),
            ("get-childitem", "File", "file"),
            // An alias prefix counts (`-psp` → `-PSPath`, an alias of `-LiteralPath`).
            ("get-childitem", "psp", "literalpath"),
            // A single non-common match beats common ones (`-e`: Exclude, ErrorAction, ...).
            ("get-childitem", "e", "exclude"),
            // ShouldProcess parameters only on cmdlets that support them.
            ("get-childitem", "whatif", "missing"),
            ("remove-item", "whatif", "whatif"),
            // An exact name or alias wins over the longer ones it is a prefix of (`-Skip` and
            // -SkipLast; `-type`, an alias of -MemberType, and -TypeName).
            ("select-object", "Skip", "skip"),
            ("add-member", "type", "membertype"),
        ];
        for (cmd, typed, want) in table {
            assert_eq!(bound(cmd, typed), want, "{cmd} -{typed}");
        }
    }
}
