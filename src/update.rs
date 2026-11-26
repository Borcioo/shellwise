//! `shellwise update`: runs the install script embedded at build time (`sh` on macOS and Linux,
//! PowerShell on Windows) with the install folder set to the running binary's own folder. The
//! binary has no HTTP client; the script downloads and verifies. Only `Cmd::Update` reaches this
//! module: the hooks and `check` never do.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
const SCRIPT: &str = include_str!("../install.sh");
#[cfg(windows)]
const SCRIPT: &str = include_str!("../install.ps1");

const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// `--check` and the check before `update` wait this long for the latest version.
const CHECK_WAIT: Duration = Duration::from_secs(10);
/// `--notify` gives the script this long from the process start; the cleanup after a kill fits in
/// the rest of the 3 s bound.
const NOTIFY_SCRIPT_MS: u64 = 2300;
/// The cleanup after a bound (the killer and both output readers together) ends this long after it.
const CLEANUP_WAIT: Duration = Duration::from_millis(400);
/// `--notify` checks at most once in this many seconds.
const NOTIFY_EVERY_S: u64 = 24 * 3600;

/// Reads the script from stdin as one text and runs it, so the exit code is 0 or 1 and a refusal
/// is the script's one message line. (`-Command -` runs stdin line by line: a block with blank
/// lines does not run, and an uncaught throw prints a multi-line error record.)
#[cfg(windows)]
const PS_BOOTSTRAP: &str = "try { & ([scriptblock]::Create([Console]::In.ReadToEnd())); exit 0 } \
     catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";

#[derive(clap::Args)]
pub struct UpdateArgs {
    /// Print the installed and the latest version; exit 0 same, 1 newer exists, 2 not readable.
    #[arg(long, conflicts_with = "notify")]
    check: bool,
    /// Print one line when a newer release exists, at most once a day, within 3 s; always exit 0.
    #[arg(long)]
    notify: bool,
}

pub fn run(start: Instant, args: UpdateArgs) -> i32 {
    if args.notify {
        // Nothing reaches stderr, and nothing fails: a session-start hook runs this.
        std::panic::set_hook(Box::new(|_| {}));
        let _ = std::panic::catch_unwind(|| notify(start));
        0
    } else if args.check {
        check()
    } else {
        update()
    }
}

/// The script's result. `code` is `None` when the child was killed at its bound.
struct ScriptRun {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl ScriptRun {
    /// The line that says why the script failed: its own refusal line, else its last line.
    fn reason(&self) -> String {
        let lines: Vec<&str> = self
            .stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        lines
            .iter()
            .rev()
            .find(|l| l.starts_with("shellwise install: "))
            .or(lines.last())
            .map(|l| l.to_string())
            .unwrap_or_else(|| match self.code {
                None => "the script did not finish in time".to_string(),
                Some(code) => format!("the install script exited {code}"),
            })
    }
}

/// `--check`: exit 0 same, 1 newer exists, 2 latest not readable.
fn check() -> i32 {
    match latest(Some(Instant::now() + CHECK_WAIT)) {
        Ok(latest) => {
            println!("installed {CURRENT}, latest {}", latest.text);
            if latest.parts > parse_version(CURRENT).unwrap_or_default() {
                1
            } else {
                0
            }
        }
        Err(reason) => {
            eprintln!("shellwise update: the latest version could not be read: {reason}");
            2
        }
    }
}

/// `update`: install the latest release (or `SHELLWISE_VERSION`) over the running binary.
fn update() -> i32 {
    let dir = match install_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("shellwise update: cannot find the running binary's folder: {e}");
            return 1;
        }
    };
    if let Err(e) = probe_writable(&dir) {
        eprintln!(
            "shellwise update: cannot write to {} ({e}); update this copy the way it was installed",
            dir.display()
        );
        return 1;
    }
    let pinned = std::env::var("SHELLWISE_VERSION")
        .ok()
        .filter(|v| !v.is_empty());
    let target = match pinned {
        Some(v) => v.trim_start_matches('v').to_string(),
        None => match latest(Some(Instant::now() + CHECK_WAIT)) {
            Ok(latest) => {
                // A build newer than the latest release is not replaced by an older one.
                if latest.parts < parse_version(CURRENT).unwrap_or_default() {
                    println!(
                        "shellwise {CURRENT} is current (the latest release is {})",
                        latest.text
                    );
                    return 0;
                }
                latest.text
            }
            Err(reason) => {
                eprintln!("shellwise update: the latest version could not be read: {reason}");
                return 1;
            }
        },
    };
    if target == CURRENT {
        println!("shellwise {CURRENT} is current");
        return 0;
    }
    match run_script("install", Some(&dir), Some(&target), None) {
        Ok(run) if run.code == Some(0) => {
            let _ = io::stderr().write_all(run.stderr.as_bytes());
            0
        }
        Ok(run) => {
            eprintln!("{}", run.reason());
            1
        }
        Err(e) => {
            eprintln!("shellwise update: could not start the install script: {e}");
            1
        }
    }
}

/// `--notify`: at most one check a day, written down before it runs; one line when newer.
fn notify(start: Instant) {
    let Some(stamp) =
        shellwise::config::user_file().and_then(|f| f.parent().map(|d| d.join("update-check")))
    else {
        return;
    };
    let now = unix_now();
    if let Some(last) = std::fs::read_to_string(&stamp)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        && last <= now
        && now - last < NOTIFY_EVERY_S
    {
        return;
    }
    // Without the stamp every session would check; then no check at all.
    if write_atomically(&stamp, &now.to_string()).is_err() {
        return;
    }
    let bound = start + Duration::from_millis(NOTIFY_SCRIPT_MS);
    if let Ok(latest) = latest(Some(bound))
        && latest.parts > parse_version(CURRENT).unwrap_or_default()
    {
        let line = format!(
            "shellwise {} is available (installed {CURRENT}): run shellwise update\n",
            latest.text
        );
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(line.as_bytes());
        let _ = stdout.flush();
    }
}

struct Latest {
    text: String,
    parts: Vec<u64>,
}

/// The latest version, as the script's check mode prints it, until `deadline`.
fn latest(deadline: Option<Instant>) -> Result<Latest, String> {
    let wait = deadline.map(|d| d.saturating_duration_since(Instant::now()));
    let run = run_script("check", None, None, wait).map_err(|e| format!("cannot start: {e}"))?;
    if run.code != Some(0) {
        return Err(run.reason());
    }
    let text = run.stdout.trim().to_string();
    match parse_version(&text) {
        Some(parts) => Ok(Latest { text, parts }),
        None => Err(format!("{text:?} is not a version like 1.2.3")),
    }
}

/// Dotted integers (`1.2.3`); anything else is `None`.
fn parse_version(text: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = text
        .split('.')
        .map(|p| {
            if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                p.parse().ok()
            } else {
                None
            }
        })
        .collect();
    let mut parts = parts?;
    // 1.2 and 1.2.0 compare equal.
    while parts.len() > 1 && parts.last() == Some(&0) {
        parts.pop();
    }
    Some(parts)
}

/// The running binary's folder: symlinks resolved on POSIX; on Windows the path as started, with
/// no `\\?\` prefix (the script and the messages need a plain path).
fn install_dir() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    #[cfg(unix)]
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    #[cfg(windows)]
    let exe = strip_verbatim(exe);
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("the binary's path has no folder"))
}

#[cfg(windows)]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

/// Creates and removes a file in `dir`: the mode bits alone do not say what this user may write.
fn probe_writable(dir: &Path) -> io::Result<()> {
    let probe = dir.join(format!(".shellwise-update-{}", std::process::id()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    std::fs::remove_file(&probe)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes `text` to a temp file next to `path`, then renames it over `path`.
fn write_atomically(path: &Path, text: &str) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::other("no folder"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".update-check.{}.tmp", std::process::id()));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Runs the embedded script in `mode` (`install` or `check`) with the script's environment:
/// `SHELLWISE_MODE`, and for `install` `SHELLWISE_INSTALL_DIR`, `SHELLWISE_VERSION` and
/// `SHELLWISE_NO_PATH=1`; the caller's `SHELLWISE_BASE_URL` passes through. With `wait`, stdout
/// is captured and the child's process tree is killed at the bound; without it, stdout goes
/// straight through. Stderr is always captured.
fn run_script(
    mode: &str,
    install_dir: Option<&Path>,
    version: Option<&str>,
    wait: Option<Duration>,
) -> io::Result<ScriptRun> {
    let deadline = wait.map(|w| Instant::now() + w);
    // One end for the whole cleanup (the killer and both readers), so the bound adds up.
    let cleanup_end = deadline.map(|d| d + CLEANUP_WAIT);
    let mut child = spawn_interpreter(wait.is_some(), |cmd| {
        cmd.env("SHELLWISE_MODE", mode)
            .env_remove("SHELLWISE_INSTALL_DIR")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(if wait.is_some() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            });
        if let Some(dir) = install_dir {
            cmd.env("SHELLWISE_INSTALL_DIR", dir)
                .env("SHELLWISE_NO_PATH", "1");
        }
        if let Some(v) = version {
            cmd.env("SHELLWISE_VERSION", v);
        }
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        thread::spawn(move || {
            let _ = stdin.write_all(SCRIPT.as_bytes());
        });
    }
    let stdout = child.stdout.take().map(read_on_thread);
    let stderr = child.stderr.take().map(read_on_thread);
    let status = wait_until(&mut child, deadline.zip(cleanup_end))?;
    // A grandchild left holding a pipe must not hold this process: the readers get a bound.
    let collect = |rx: Option<mpsc::Receiver<String>>| match (rx, cleanup_end) {
        (Some(rx), Some(end)) => rx
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .unwrap_or_default(),
        (Some(rx), None) => rx.recv().unwrap_or_default(),
        (None, _) => String::new(),
    };
    Ok(ScriptRun {
        code: status.and_then(|s| s.code()),
        stdout: collect(stdout).replace("\r\n", "\n"),
        stderr: collect(stderr).replace("\r\n", "\n"),
    })
}

fn read_on_thread(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    rx
}

/// Waits for the child; at the deadline kills its process tree, waiting for the killer until the
/// cleanup end, and returns `None`.
fn wait_until(
    child: &mut Child,
    bound: Option<(Instant, Instant)>,
) -> io::Result<Option<ExitStatus>> {
    let Some((deadline, cleanup_end)) = bound else {
        return child.wait().map(Some);
    };
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            kill_tree(child, cleanup_end);
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// A bounded run gets its own process group, so the kill at the bound reaches a `curl` it
/// started. An unbounded one (`update`) stays in the terminal's group, so Ctrl-C stops the script
/// with shellwise.
#[cfg(unix)]
fn spawn_interpreter(bounded: bool, set: impl Fn(&mut Command)) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("sh");
    cmd.arg("-s");
    if bounded {
        cmd.process_group(0);
    }
    set(&mut cmd);
    cmd.spawn()
}

/// PowerShell 7 when installed, else Windows PowerShell.
#[cfg(windows)]
fn spawn_interpreter(_bounded: bool, set: impl Fn(&mut Command)) -> io::Result<Child> {
    for program in ["pwsh", "powershell"] {
        let mut cmd = Command::new(program);
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            PS_BOOTSTRAP,
        ]);
        set(&mut cmd);
        match cmd.spawn() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            other => return other,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "neither pwsh nor powershell is on PATH",
    ))
}

/// A bounded child runs in its own process group (`spawn_interpreter`): kill the whole group, so
/// a `curl` it started dies with it.
#[cfg(unix)]
fn kill_tree(child: &mut Child, _end: Instant) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: `kill` takes plain integers; a negative pid names the child's own group.
        unsafe {
            kill(-pid, SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// `taskkill /T` while the child still runs (it walks the tree from the parent), bounded; then
/// the child itself.
#[cfg(windows)]
fn kill_tree(child: &mut Child, end: Instant) {
    let taskkill = std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("System32").join("taskkill.exe"))
        .unwrap_or_else(|| PathBuf::from("taskkill.exe"));
    if let Ok(mut killer) = Command::new(taskkill)
        .args(["/T", "/F", "/PID", &child.id().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        while matches!(killer.try_wait(), Ok(None)) && Instant::now() < end {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = killer.kill();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_dotted_integers() {
        let v = |t| parse_version(t).unwrap();
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("0.1.10") > v("0.1.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("0.1.1"), v("0.1.1"));
    }

    #[test]
    fn anything_but_dotted_integers_is_not_a_version() {
        for text in [
            "",
            "9.9.9-rc1",
            "v1.2.3",
            "1..2",
            "1.2.",
            "<html>",
            "1.2.x",
            " 1.2.3",
            "+1.2",
        ] {
            assert_eq!(parse_version(text), None, "{text:?}");
        }
    }
}
