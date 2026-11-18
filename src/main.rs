//! The `shellwise` command line.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

use shellwise::adapter::check_json;
use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::{Finding, Verdict, exit_code};
use shellwise::{
    BashProfile, CheckInput, Deadline, MAX_INPUT_BYTES, Os, Shell, check, fail_closed,
};

/// Exit code for usage errors.
const EXIT_USAGE: i32 = 64;
/// Exit code when the input cannot be read.
const EXIT_IO: i32 = 74;
const WORKER_STACK: usize = 64 * 1024 * 1024;
/// The config load ends this long after the process start, inside the one deadline
/// (`hook_timeout_ms` is at least `MIN_HOOK_TIMEOUT_MS`).
const CONFIG_LOAD_MS: u64 = 1000;

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
    }
}

fn run_check(start: Instant, args: CheckArgs) -> i32 {
    let bytes = if args.command.is_empty() {
        let mut buf = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut buf) {
            eprintln!("shellwise: cannot read stdin: {e}");
            return EXIT_IO;
        }
        buf
    } else {
        let joined = args.command.join(&OsString::from(" "));
        match joined.into_string() {
            Ok(s) => s.into_bytes(),
            Err(os) => {
                // Not valid Unicode: the lossy text is still scanned, then fails closed below.
                let lossy = os.to_string_lossy().into_owned();
                let reason = "invalid UTF-8";
                return finish(fail_closed(&lossy, reason), Vec::new(), &args, reason);
            }
        }
    };

    let command = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            let lossy = String::from_utf8_lossy(e.as_bytes()).into_owned();
            let reason = "invalid UTF-8";
            return finish(fail_closed(&lossy, reason), Vec::new(), &args, reason);
        }
    };
    if command.len() > MAX_INPUT_BYTES {
        let reason = "input over the size cap";
        return finish(fail_closed(&command, reason), Vec::new(), &args, reason);
    }

    let (cfg, cfg_findings) = match load_config(start, args.config.clone(), args.cwd.clone()) {
        Ok(loaded) => loaded,
        Err(reason) => return finish(fail_closed(&command, reason), Vec::new(), &args, reason),
    };
    let deadline = test_deadline(start).unwrap_or_else(|| Deadline::for_config(start, &cfg));

    let verdict = match analyse(
        &command,
        args.shell.shell(),
        args.cwd.clone(),
        &cfg,
        deadline,
    ) {
        Ok(v) => v,
        Err(reason) => {
            return finish(fail_closed(&command, reason), cfg_findings, &args, reason);
        }
    };
    finish(verdict, cfg_findings, &args, "")
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

/// Run `check` on a big-stack worker inside `catch_unwind`; wait only until the deadline.
fn analyse(
    command: &str,
    shell: Shell,
    cwd: Option<PathBuf>,
    cfg: &Config,
    deadline: Deadline,
) -> Result<Verdict, &'static str> {
    let (tx, rx) = mpsc::channel();
    let owned = command.to_string();
    let cfg = cfg.clone();
    let job = move || {
        let input = CheckInput {
            shell,
            os: Os::host(),
            command: &owned,
            cwd,
            env: EnvView::new(),
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| check(&input, &cfg, &deadline)));
        if testhook_is("dead-worker") {
            return;
        }
        let _ = tx.send(result);
    };
    let spawned = if testhook_is("spawn-fail") {
        Err(io::Error::other("testhook: spawn-fail"))
    } else {
        thread::Builder::new()
            .name("check".into())
            .stack_size(WORKER_STACK)
            .spawn(job)
    };
    if spawned.is_err() {
        return Err("the worker thread did not start");
    }
    match rx.recv_timeout(deadline.remaining()) {
        Ok(Ok(verdict)) => Ok(verdict),
        Ok(Err(_)) => Err("internal error"),
        Err(mpsc::RecvTimeoutError::Timeout) => Err("deadline"),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("the worker ended without a result"),
    }
}

/// Print the verdict and return the exit code. A fail-closed `ok` names its reason on stderr.
fn finish(verdict: Verdict, cfg_findings: Vec<Finding>, args: &CheckArgs, failed: &str) -> i32 {
    if !failed.is_empty() && verdict.findings.is_empty() {
        eprintln!("shellwise: analysis failed ({failed}); no destructive command in the raw text");
    }
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
            if let Some(fix) = &f.fix {
                out.push_str(&format!("  fix: {fix}\n"));
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
    shellwise::rules::testhooks::mode() == mode
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
