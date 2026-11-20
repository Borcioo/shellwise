//! The `shellwise` command line.

// The fail-closed verdict depends on catching panics.
#[cfg(not(panic = "unwind"))]
compile_error!("shellwise must be built with panic = \"unwind\"");

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::panic;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};

use shellwise::adapter::check_json;
use shellwise::adapter::claude_code::{self, Event};
use shellwise::config::{Config, HOOK_MARGIN_MS, MIN_HOOK_TIMEOUT_MS};
use shellwise::level::{Finding, Verdict, exit_code};
use shellwise::{
    AnalyseInput, BashProfile, Deadline, MAX_READ_BYTES, Origin, Os, Shell, analyse, unread,
};

mod bench;
mod shellcheck;

/// Exit code for usage errors.
const EXIT_USAGE: i32 = 64;
/// Exit code when the input cannot be read.
const EXIT_IO: i32 = 74;
/// The config load ends this long after it starts (the process start; for the hook, the end of
/// the event read), inside the one deadline (`hook_timeout_ms` is at least `MIN_HOOK_TIMEOUT_MS`).
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
    /// Replay the corpus through the analysis and report the meters; exit 1 when it cannot measure.
    Bench(bench::BenchArgs),
    /// Print the documentation of one rule; exit 64 for an unknown id.
    Explain {
        /// The rule id, as a finding names it.
        id: String,
    },
    /// Lint a .ps1, .sh or .bash file; exit 0 clean or warn, 1 break or worse, 64 refused, 74 unreadable.
    Lint(LintArgs),
}

use shellwise::RULE_DOCS;

/// `explain <id>`: the rule's doc, embedded at build time.
fn run_explain(id: &str) -> i32 {
    match RULE_DOCS.binary_search_by(|(k, _)| (*k).cmp(id)) {
        Ok(i) => {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(RULE_DOCS[i].1.as_bytes());
            let _ = stdout.flush();
            0
        }
        // Any other rule id is a ShellCheck code, which `lint` reports for a Bash file.
        Err(_) if shellwise::is_rule_id(id) => {
            let mut stdout = io::stdout().lock();
            let _ = writeln!(
                stdout,
                "# {id}\n\nA ShellCheck check that `shellwise lint` runs on a Bash file (`warn`; a parse error is `break` when the shellwise parser also fails on the file). \
                 Its page: https://www.shellcheck.net/wiki/{id}"
            );
            let _ = stdout.flush();
            0
        }
        Err(_) => {
            eprintln!("shellwise: no rule {id:?}");
            EXIT_USAGE
        }
    }
}

#[derive(clap::Args)]
struct LintArgs {
    /// The script file.
    file: PathBuf,
    /// An integration config file; the user file overrides it, the repo file only raises.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
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
        Cmd::Bench(args) => bench::run(args),
        Cmd::Explain { id } => run_explain(&id),
        Cmd::Lint(args) => run_lint(start, args),
    }
}

/// `lint <file>`: the shellwise rules for a file (`lint_file`), and ShellCheck's for a Bash one.
/// The config loads from the current directory; one that does not load refuses the run.
fn run_lint(start: Instant, args: LintArgs) -> i32 {
    let cfg = match load_config(Deadline::new(start, CONFIG_LOAD_MS), args.config, None) {
        Ok((cfg, findings)) => {
            for f in findings {
                eprintln!(
                    "shellwise: config: {} {}: {}",
                    f.level.as_str(),
                    f.rule,
                    f.message
                );
            }
            cfg
        }
        Err(reason) => {
            eprintln!("shellwise: the config did not load ({reason}); nothing was linted");
            return EXIT_IO;
        }
    };
    let deadline = shellwise::lint_file::deadline(start, &cfg);
    let file = &args.file;
    let external = |text: &str, shell: Shell| match shellcheck::findings(text, shell, &deadline) {
        Some(found) => found,
        None => {
            if matches!(shell, Shell::Bash(_)) {
                eprintln!(
                    "{}: ShellCheck skipped: the file is over {} bytes",
                    file.display(),
                    shellcheck::MAX_BYTES
                );
            }
            Vec::new()
        }
    };
    match shellwise::lint_file::lint_with(file, &cfg, &deadline, &external) {
        Ok(report) => {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(report.render(file).as_bytes());
            let _ = stdout.flush();
            report.exit_code()
        }
        Err(refusal) => {
            eprintln!("{}", refusal.render(file));
            refusal.exit_code()
        }
    }
}

/// `hook claude-code`: read the event, ignore a tool that is not a shell, load the config from
/// the event's `cwd`, analyse, print the reply. Every path exits 0; an unread input denies.
fn run_hook(start: Instant, args: HookArgs) -> i32 {
    // Before the event is read: an unread or malformed event is let through too.
    if shellwise::turned_off() {
        return 0;
    }
    let os = Os::host();
    let bytes = match read_stdin(Deadline::new(start, HOOK_READ_MS)) {
        Input::Bytes(bytes) if bytes.len() > MAX_READ_BYTES => {
            return unread_reply("input over the hard size cap", &bytes, os);
        }
        Input::Bytes(bytes) => bytes,
        Input::Unread(reason, partial) => return unread_reply(reason, &partial, os),
        Input::Error(e, partial) => {
            eprintln!("shellwise: cannot read stdin: {e}");
            return unread_reply("stdin could not be read", &partial, os);
        }
    };
    let (shell, command, cwd) = match claude_code::parse_event(&bytes, os) {
        Event::Ignored => return 0,
        Event::Malformed(reason) => {
            let deadline = Deadline::new(start, HOOK_READ_MS);
            return emit(claude_code::malformed(&bytes, reason, &deadline));
        }
        Event::Command {
            shell,
            command,
            cwd,
        } => (shell, command, cwd),
    };
    let budget = hook_config_budget(start, Instant::now());
    let (cfg, cfg_findings, cfg_problem) = match load_config(budget, args.config, cwd.clone()) {
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

/// The hook's reply to an event not read whole: no output when the bytes read name a tool that
/// is not a shell, otherwise the unread deny.
fn unread_reply(reason: &'static str, partial: &[u8], os: Os) -> i32 {
    if claude_code::names_another_tool(partial, os) {
        return 0;
    }
    emit(claude_code::reply(&unread(reason), &Config::default()))
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
    let budget = Deadline::new(start, CONFIG_LOAD_MS);
    let (cfg, cfg_findings, cfg_problem) =
        match load_config(budget, args.config.clone(), args.cwd.clone()) {
            Ok((cfg, findings)) => (cfg, findings, None),
            Err(reason) => (Config::default(), Vec::new(), Some(reason)),
        };
    let deadline = test_deadline(start).unwrap_or_else(|| Deadline::for_config(start, &cfg));

    let bytes = if args.command.is_empty() {
        match read_stdin(deadline) {
            Input::Bytes(bytes) => bytes,
            Input::Unread(reason, _) => return finish(unread(reason), cfg_findings, &args),
            Input::Error(e, _) => {
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
        env: claude_code::hook_env(args.shell.shell(), Os::host()),
        origin: Origin::CommandLine,
        problem: cfg_problem,
    };
    finish(analyse(&input, &cfg, &deadline), cfg_findings, &args)
}

/// The hook's config budget: `CONFIG_LOAD_MS` from the end of the event read (`read_done`), so an
/// event that arrives late is not a config that did not load, but never past `HOOK_READ_MS` from
/// the process start, the earliest deadline any config can set.
fn hook_config_budget(start: Instant, read_done: Instant) -> Deadline {
    let end = (read_done + Duration::from_millis(CONFIG_LOAD_MS))
        .min(start + Duration::from_millis(HOOK_READ_MS));
    let ms = end.saturating_duration_since(start).as_millis();
    Deadline::new(start, u64::try_from(ms).unwrap_or(HOOK_READ_MS))
}

/// Load the config layers (`Config::discover`) on a worker thread, waiting at most until
/// `budget`. `check` passes `--config` and `--cwd`; the `hook claude-code` adapter passes its
/// `--config` and the event's `cwd`. `Err` is a fail-closed reason.
fn load_config(
    budget: Deadline,
    integration: Option<PathBuf>,
    cwd: Option<PathBuf>,
) -> Result<(Config, Vec<Finding>), &'static str> {
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
    /// Still open at the deadline, or no reader: danger without scanning. Holds the bytes read
    /// so far.
    Unread(&'static str, Vec<u8>),
    /// A read error, with the bytes read before it.
    Error(io::Error, Vec<u8>),
}

/// Read stdin on a thread, at most `MAX_READ_BYTES + 1` bytes, waiting only until the deadline.
/// Each chunk is shared as it arrives, so a read that does not finish still shows its start.
fn read_stdin(deadline: Deadline) -> Input {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&shared);
    let reader = thread::Builder::new().name("stdin".into()).spawn(move || {
        let mut input = io::stdin().lock().take(MAX_READ_BYTES as u64 + 1);
        let mut chunk = vec![0u8; 64 * 1024];
        let result = loop {
            match input.read(&mut chunk) {
                Ok(0) => break Ok(()),
                Ok(n) => match sink.lock() {
                    Ok(mut buf) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break Err(io::Error::other("the stdin buffer is poisoned")),
                },
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        let _ = tx.send(result);
    });
    let read_so_far = || {
        shared
            .lock()
            .map(|mut b| std::mem::take(&mut *b))
            .unwrap_or_default()
    };
    if reader.is_err() {
        return Input::Unread("the stdin reader did not start", Vec::new());
    }
    match rx.recv_timeout(deadline.remaining()) {
        // More than MAX_READ_BYTES is refused by the caller.
        Ok(Ok(())) => Input::Bytes(read_so_far()),
        Ok(Err(e)) => Input::Error(e, read_so_far()),
        Err(_) => Input::Unread("stdin still open at the deadline", read_so_far()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_config_budget_starts_at_the_read_and_ends_by_the_read_bound() {
        let start = Instant::now();
        // (event read after ms, budget from the process start)
        for (read_ms, want) in [
            (0, 1000),
            (300, 1300),
            (499, 1499),
            (1200, 1500),
            (1500, 1500),
        ] {
            let budget = hook_config_budget(start, start + Duration::from_millis(read_ms));
            let left = budget.remaining().as_millis() as i64;
            let want_left = want as i64 - start.elapsed().as_millis() as i64;
            assert!(
                (left - want_left).abs() <= 20,
                "read {read_ms}: {left} ms left, want about {want_left}"
            );
        }
    }
}
