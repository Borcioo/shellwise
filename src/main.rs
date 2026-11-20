//! The `shellwise` command line.

// The fail-closed verdict depends on catching panics.
#[cfg(not(panic = "unwind"))]
compile_error!("shellwise must be built with panic = \"unwind\"");

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::panic;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

use shellwise::adapter::check_json;
use shellwise::adapter::claude_code::{self, Event};
use shellwise::config::{Config, HOOK_MARGIN_MS, MIN_HOOK_TIMEOUT_MS};
use shellwise::ir::EnvView;
use shellwise::level::{Finding, Verdict, exit_code};
use shellwise::{
    AnalyseInput, BashProfile, Deadline, MAX_READ_BYTES, Origin, Os, Shell, analyse, unread,
};

/// Exit code for usage errors.
const EXIT_USAGE: i32 = 64;
/// Exit code when the input cannot be read.
const EXIT_IO: i32 = 74;
/// The config load ends this long after the process start, inside the one deadline
/// (`hook_timeout_ms` is at least `MIN_HOOK_TIMEOUT_MS`).
const CONFIG_LOAD_MS: u64 = 1000;
/// The hook reads its event before the config (the config needs the event's `cwd`), under a
/// bound no config can undercut.
const HOOK_READ_MS: u64 = MIN_HOOK_TIMEOUT_MS - HOOK_MARGIN_MS;

#[derive(Parser)]
#[command(
    name = "shellwise",
    version,
    about = "Command guard and lint for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check one command; exit 0 ok/warn, 1 break, 2 danger, 3 critical.
    Check(CheckArgs),
    /// Run as an agent host's hook; always exits 0.
    #[command(subcommand)]
    Hook(HookCmd),
}

#[derive(Subcommand)]
enum HookCmd {
    /// Claude Code PreToolUse: the event on stdin, the host's JSON reply on stdout.
    ClaudeCode(HookArgs),
}

#[derive(clap::Args)]
struct HookArgs {
    /// An integration config file; the user file overrides it, the repo file only raises.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
struct CheckArgs {
    /// The shell that runs the command.
    #[arg(long, value_enum)]
    shell: ShellArg,
    /// The working directory the command runs in.
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Print the verdict as JSON.
    #[arg(long)]
    json: bool,
    /// An integration config file; the user file overrides it, the repo file only raises.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// The command (after `--`); read from stdin when absent.
    #[arg(last = true)]
    command: Vec<OsString>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ShellArg {
    Pwsh,
    Powershell5,
    Bash,
    Gitbash,
}

impl ShellArg {
    fn shell(self) -> Shell {
        match self {
            ShellArg::Pwsh => Shell::Pwsh,
            ShellArg::Powershell5 => Shell::Powershell5,
            ShellArg::Bash => Shell::Bash(BashProfile::Posix),
            ShellArg::Gitbash => Shell::Bash(BashProfile::GitBash),
        }
    }
}

fn main() {
    let start = Instant::now();
    std::process::exit(run(start));
}

fn run(start: Instant) -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { EXIT_USAGE } else { 0 };
        }
    };
    match cli.cmd {
        Cmd::Check(args) => run_check(start, args),
        Cmd::Hook(HookCmd::ClaudeCode(args)) => run_hook(start, args),
    }
}

/// `hook claude-code`: read the event, ignore a tool that is not a shell, load the config from
/// the event's `cwd`, analyse, print the reply. Every path exits 0; an unread input denies.
fn run_hook(start: Instant, args: HookArgs) -> i32 {
    let bytes = match read_stdin(Deadline::new(start, HOOK_READ_MS)) {
        Input::Bytes(bytes) if bytes.len() > MAX_READ_BYTES => {
            return emit(claude_code::reply(
                &unread("input over the hard size cap"),
                &Config::default(),
            ));
        }
        Input::Bytes(bytes) => bytes,
        Input::Unread(reason) => {
            return emit(claude_code::reply(&unread(reason), &Config::default()));
        }
        Input::Error(e) => {
            eprintln!("shellwise: cannot read stdin: {e}");
            return emit(claude_code::reply(
                &unread("stdin could not be read"),
                &Config::default(),
            ));
        }
    };
    let os = Os::host();
    let (shell, command, cwd) = match claude_code::parse_event(&bytes, os) {
        Event::Ignored => return 0,
        Event::Malformed(reason) => return emit(claude_code::malformed(&bytes, reason)),
        Event::Command {
            shell,
            command,
            cwd,
        } => (shell, command, cwd),
    };
    let (cfg, cfg_findings, cfg_problem) = match load_config(start, args.config, cwd.clone()) {
        Ok((cfg, findings)) => (cfg, findings, None),
        Err(reason) => (Config::default(), Vec::new(), Some(reason)),
    };
    let deadline = test_deadline(start).unwrap_or_else(|| Deadline::for_config(start, &cfg));
    if let Some(reason) = cfg_problem {
        eprintln!("shellwise: analysis incomplete ({reason})");
    }
    let input = AnalyseInput {
        bytes: command.as_bytes(),
        shell,
        os,
        cwd,
        env: claude_code::hook_env(shell, os),
        origin: Origin::CommandLine,
        problem: cfg_problem,
    };
    let mut findings = analyse(&input, &cfg, &deadline).findings;
    findings.extend(cfg_findings);
    emit(claude_code::reply(&Verdict::new(findings), &cfg))
}

/// Print the hook's reply, if any, as one LF-terminated line; exit 0.
fn emit(reply: Option<String>) -> i32 {
    if let Some(mut text) = reply {
        text.push('\n');
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(text.as_bytes());
        let _ = stdout.flush();
    }
    0
}

fn run_check(start: Instant, args: CheckArgs) -> i32 {
    // The config comes first: the one deadline (and the stdin read under it) takes its budget. A
    // config that does not load leaves the defaults and fails the analysis closed below.
    let (cfg, cfg_findings, cfg_problem) =
        match load_config(start, args.config.clone(), args.cwd.clone()) {
            Ok((cfg, findings)) => (cfg, findings, None),
            Err(reason) => (Config::default(), Vec::new(), Some(reason)),
        };
    let deadline = test_deadline(start).unwrap_or_else(|| Deadline::for_config(start, &cfg));

    let bytes = if args.command.is_empty() {
        match read_stdin(deadline) {
            Input::Bytes(bytes) => bytes,
            Input::Unread(reason) => return finish(unread(reason), cfg_findings, &args),
            Input::Error(e) => {
                eprintln!("shellwise: cannot read stdin: {e}");
                return EXIT_IO;
            }
        }
    } else {
        // Text that is not valid Unicode keeps its invalid bytes, so `analyse` refuses it.
        let words: Vec<&[u8]> = args.command.iter().map(|a| a.as_encoded_bytes()).collect();
        words.join(&b' ')
    };
    if let Some(reason) = cfg_problem {
        eprintln!("shellwise: analysis incomplete ({reason})");
    }
    let input = AnalyseInput {
        bytes: &bytes,
        shell: args.shell.shell(),
        os: Os::host(),
        cwd: args.cwd.clone(),
        env: EnvView::new(),
        origin: Origin::CommandLine,
        problem: cfg_problem,
    };
    finish(analyse(&input, &cfg, &deadline), cfg_findings, &args)
}

/// Load the config layers (`Config::discover`) on a worker thread, waiting at most
/// `CONFIG_LOAD_MS` from the process start. `check` passes `--config` and `--cwd`; the
/// `hook claude-code` adapter passes its `--config` and the event's `cwd`. `Err` is a fail-closed
/// reason.
fn load_config(
    start: Instant,
    integration: Option<PathBuf>,
    cwd: Option<PathBuf>,
) -> Result<(Config, Vec<Finding>), &'static str> {
    let budget = Deadline::new(start, CONFIG_LOAD_MS);
    let (tx, rx) = mpsc::channel();
    let job = move || {
        if testhook_is("config-sleep") {
            thread::sleep(std::time::Duration::from_secs(60));
        }
        let cwd = cwd.or_else(|| std::env::current_dir().ok());
        let result = panic::catch_unwind(|| {
            if testhook_is("config-panic") {
                panic!("testhook: panic in the config load");
            }
            Config::discover(integration.as_deref(), cwd.as_deref())
        });
        let _ = tx.send(result);
    };
    let spawned = if testhook_is("config-spawn-fail") {
        Err(io::Error::other("testhook: config-spawn-fail"))
    } else {
        thread::Builder::new().name("config".into()).spawn(job)
    };
    if spawned.is_err() {
        return Err("the config thread did not start");
    }
    match rx.recv_timeout(budget.remaining()) {
        Ok(Ok(loaded)) => Ok(loaded),
        Ok(Err(_)) => Err("internal error while loading the config"),
        Err(_) => Err("the config did not load before the deadline"),
    }
}

enum Input {
    Bytes(Vec<u8>),
    /// Too big or still open at the deadline: danger without scanning.
    Unread(&'static str),
    Error(io::Error),
}

/// Read stdin on a thread, at most `MAX_READ_BYTES + 1` bytes, waiting only until the deadline.
fn read_stdin(deadline: Deadline) -> Input {
    let (tx, rx) = mpsc::channel();
    let reader = thread::Builder::new().name("stdin".into()).spawn(move || {
        let mut buf = Vec::new();
        let r = io::stdin()
            .lock()
            .take(MAX_READ_BYTES as u64 + 1)
            .read_to_end(&mut buf);
        let _ = tx.send(r.map(|_| buf));
    });
    if reader.is_err() {
        return Input::Unread("the stdin reader did not start");
    }
    match rx.recv_timeout(deadline.remaining()) {
        // More than MAX_READ_BYTES is refused by the caller.
        Ok(Ok(buf)) => Input::Bytes(buf),
        Ok(Err(e)) => Input::Error(e),
        Err(_) => Input::Unread("stdin still open at the deadline"),
    }
}

/// Print the verdict and return the exit code.
fn finish(verdict: Verdict, cfg_findings: Vec<Finding>, args: &CheckArgs) -> i32 {
    let mut findings = verdict.findings;
    findings.extend(cfg_findings);
    let verdict = Verdict::new(findings);
    let mut out = String::new();
    if args.json {
        out.push_str(&check_json::render(&verdict));
        out.push('\n');
    } else if verdict.findings.is_empty() {
        out.push_str("ok\n");
    } else {
        for f in &verdict.findings {
            let level = f.level.as_str();
            out.push_str(&format!(
                "{level} {} [{}..{}]: {}\n",
                f.rule, f.span.start, f.span.end, f.message
            ));
            if let Some(line) = f.fix_line() {
                out.push_str(&format!("  {line}\n"));
            }
        }
    }
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(out.as_bytes());
    let _ = stdout.flush();
    exit_code(verdict.level)
}

#[cfg(feature = "testhooks")]
fn testhook_is(mode: &str) -> bool {
    shellwise::rules::testhooks::active(mode)
}

#[cfg(not(feature = "testhooks"))]
fn testhook_is(_mode: &str) -> bool {
    false
}

/// With the `testhooks` feature, `SHELLWISE_TESTHOOK_DEADLINE_MS` shortens the deadline.
#[cfg(feature = "testhooks")]
fn test_deadline(start: Instant) -> Option<Deadline> {
    let ms = std::env::var("SHELLWISE_TESTHOOK_DEADLINE_MS").ok()?;
    Some(Deadline::new(start, ms.parse().ok()?))
}

#[cfg(not(feature = "testhooks"))]
fn test_deadline(_start: Instant) -> Option<Deadline> {
    None
}
