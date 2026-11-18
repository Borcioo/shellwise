//! The `shellwise` command line.

// The fail-closed verdict depends on catching panics.
#[cfg(not(panic = "unwind"))]
compile_error!("shellwise must be built with panic = \"unwind\"");

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

use shellwise::adapter::check_json;
use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::{Finding, Verdict, exit_code};
use shellwise::scan::raw_destructive;
use shellwise::{
    BashProfile, CheckInput, Deadline, MAX_INPUT_BYTES, MAX_READ_BYTES, Os, Shell, check,
    fail_closed_unread, scan_verdict,
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
    // The config comes first: the one deadline (and the stdin read under it) takes its budget. A
    // config that does not load leaves the defaults and fails the analysis closed below.
    let (cfg, cfg_findings, cfg_problem) =
        match load_config(start, args.config.clone(), args.cwd.clone()) {
            Ok((cfg, findings)) => (cfg, findings, None),
            Err(reason) => (Config::default(), Vec::new(), Some(reason)),
        };
    let deadline = test_deadline(start).unwrap_or_else(|| Deadline::for_config(start, &cfg));

    let (command, problem) = if args.command.is_empty() {
        match read_stdin(deadline) {
            Input::Bytes(bytes) => match String::from_utf8(bytes) {
                Ok(s) => (s, None),
                Err(e) => (
                    String::from_utf8_lossy(e.as_bytes()).into_owned(),
                    Some("invalid UTF-8"),
                ),
            },
            Input::Unread(reason) => {
                return finish(fail_closed_unread(reason), cfg_findings, &args, reason);
            }
            Input::Error(e) => {
                eprintln!("shellwise: cannot read stdin: {e}");
                return EXIT_IO;
            }
        }
    } else {
        let joined = args.command.join(&OsString::from(" "));
        match joined.into_string() {
            Ok(s) => (s, None),
            // Not valid Unicode: the lossy text is still scanned.
            Err(os) => (os.to_string_lossy().into_owned(), Some("invalid UTF-8")),
        }
    };
    if command.len() > MAX_READ_BYTES {
        let reason = "input over the hard size cap";
        return finish(fail_closed_unread(reason), cfg_findings, &args, reason);
    }
    let problem = problem
        .or(cfg_problem)
        .or((command.len() > MAX_INPUT_BYTES).then_some("input over the size cap"));
    let (verdict, failed) = analyse(
        command,
        problem,
        args.shell.shell(),
        args.cwd.clone(),
        &cfg,
        deadline,
    );
    finish(verdict, cfg_findings, &args, failed)
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

/// Run `check` on a big-stack worker inside `catch_unwind` and the raw-text scan on a second
/// worker, both under the deadline. When `check` cannot finish (or `problem` says it must not
/// run), the verdict is danger unless the text is a harmless simple command; the scan only names
/// the destructive command. Returns the verdict and the reason the analysis failed ("" when it
/// did not).
fn analyse(
    command: String,
    problem: Option<&'static str>,
    shell: Shell,
    cwd: Option<PathBuf>,
    cfg: &Config,
    deadline: Deadline,
) -> (Verdict, &'static str) {
    let command = Arc::new(command);
    let (scan_tx, scan_rx) = mpsc::channel();
    let text = Arc::clone(&command);
    let scan = thread::Builder::new()
        .name("scan".into())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            if testhook_is("panic-scan-sleep") {
                thread::sleep(std::time::Duration::from_secs(60));
            }
            let _ = scan_tx.send(panic::catch_unwind(|| raw_destructive(&text)));
        });

    let reason = match problem {
        Some(reason) => reason,
        None => match run_checker(Arc::clone(&command), shell, cwd, cfg, deadline) {
            Ok(verdict) => return (verdict, ""),
            Err(reason) => reason,
        },
    };
    let hit = match (scan, scan_rx.recv_timeout(deadline.remaining())) {
        (Ok(_), Ok(Ok(hit))) => Some(hit),
        _ => None,
    };
    (scan_verdict(hit, &command, reason), reason)
}

fn run_checker(
    command: Arc<String>,
    shell: Shell,
    cwd: Option<PathBuf>,
    cfg: &Config,
    deadline: Deadline,
) -> Result<Verdict, &'static str> {
    let (tx, rx) = mpsc::channel();
    let cfg = cfg.clone();
    let job = move || {
        let input = CheckInput {
            shell,
            os: Os::host(),
            command: &command,
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
        eprintln!("shellwise: analysis failed ({failed}); the text is a simple read-only command");
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
