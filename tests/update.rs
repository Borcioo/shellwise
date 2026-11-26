//! `shellwise update` against a fake release in a local folder (or a local listener that never
//! answers). The binary under test is a copy of the test binary in a temp folder; the config
//! homes and the default install folders point into that temp folder, and `SHELLWISE_NO_PATH=1`
//! is set on every run, so no test touches this machine's PATH, config or real install folder.

mod common;

use common::release::{Release, bin_name, fake_binary, host_target, temp_folder};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CURRENT: &str = env!("CARGO_PKG_VERSION");
const LATEST: &str = "9.9.9";
const RUN_LIMIT: Duration = Duration::from_secs(120);

/// The runs start interpreters and are timed: one at a time, so a bound is not measured under the
/// load of the other tests in this file.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Writes past the test harness's output capture, so a SKIP shows on a passing run too.
fn shown(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Out {
    fn context(&self) -> String {
        format!(
            "exit {} after {:?}\nstdout {:?}\nstderr {:?}",
            self.code, self.elapsed, self.stdout, self.stderr
        )
    }

    fn stderr_lines(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect()
    }
}

/// A fake release, a copy of the binary in `<root>/bin` and a fake home, in a temp folder
/// removed at the end.
struct Fixture {
    root: PathBuf,
    release: Release,
    bin_dir: PathBuf,
    home: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = temp_folder(&format!("update-{label}"));
        let release = Release::new(&root);
        let bin_dir = root.join("bin");
        let home = root.join("home");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let original = std::fs::read(env!("CARGO_BIN_EXE_shellwise")).unwrap();
        let f = Fixture {
            root,
            release,
            bin_dir,
            home,
            original,
        };
        std::fs::write(f.exe(), &f.original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f.exe(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        f
    }

    fn exe(&self) -> PathBuf {
        self.bin_dir.join(bin_name())
    }

    /// Only `latest/download/SHA256SUMS`, naming `version`: enough for a check, nothing to
    /// download.
    fn latest_sums_only(&self, version: &str) {
        let path = self.release.latest_sums_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let line = format!(
            "{}  shellwise-v{version}-{}.{}\n",
            "ab".repeat(32),
            host_target(),
            if cfg!(windows) { "zip" } else { "tar.gz" }
        );
        std::fs::write(path, line).unwrap();
    }

    fn publish_latest(&self, version: &str) {
        self.release.publish(version, &[host_target()]);
        self.release.mark_latest(version);
    }

    /// The notify timestamp file, where the user config file's folder is under the fake home.
    fn stamp(&self) -> PathBuf {
        let config = if cfg!(windows) {
            self.home.clone()
        } else if cfg!(target_os = "macos") {
            self.home.join("Library").join("Application Support")
        } else {
            self.home.clone()
        };
        config.join("shellwise").join("update-check")
    }

    /// The default install folders the scripts would use without `SHELLWISE_INSTALL_DIR`.
    fn default_install_dirs(&self) -> [PathBuf; 2] {
        [
            self.home.join("Programs").join("shellwise"),
            self.home.join(".local").join("bin"),
        ]
    }

    fn run(&self, args: &[&str], base: &OsStr) -> Out {
        self.run_env(args, base, &[])
    }

    fn run_env(&self, args: &[&str], base: &OsStr, env: &[(&str, &OsStr)]) -> Out {
        // The guard every run relies on: the binary that updates itself is the temp copy.
        assert!(
            self.exe().starts_with(std::env::temp_dir()),
            "{:?}",
            self.exe()
        );
        let mut cmd = Command::new(self.exe());
        cmd.args(args)
            .current_dir(&self.root)
            .env_remove("SHELLWISE")
            .env_remove("SHELLWISE_VERSION")
            .env_remove("SHELLWISE_MODE")
            .env_remove("SHELLWISE_TARGET")
            .env_remove("SHELLWISE_INSTALL_DIR")
            .env_remove("SHELLWISE_TESTHOOK")
            .env("SHELLWISE_BASE_URL", base)
            .env("SHELLWISE_NO_PATH", "1")
            .env("APPDATA", &self.home)
            .env("LOCALAPPDATA", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("HOME", &self.home)
            .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let start = Instant::now();
        let mut child = cmd.spawn().expect("spawn the shellwise copy");
        let read = |mut r: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = r.read_to_end(&mut buf);
                String::from_utf8_lossy(&buf).replace("\r\n", "\n")
            })
        };
        let out = read(Box::new(child.stdout.take().unwrap()));
        let err = read(Box::new(child.stderr.take().unwrap()));
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > RUN_LIMIT {
                let _ = child.kill();
                panic!("shellwise ran past {RUN_LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let elapsed = start.elapsed();
        Out {
            code: status.code().expect("exit code"),
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
            elapsed,
        }
    }

    fn base(&self) -> &OsStr {
        self.release.base.as_os_str()
    }

    fn listing(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.bin_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn exe_is_original(&self) -> bool {
        std::fs::read(self.exe()).ok().as_deref() == Some(&self.original[..])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.bin_dir, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn notice(latest: &str) -> String {
    format!("shellwise {latest} is available (installed {CURRENT}): run shellwise update\n")
}

#[test]
fn check_reports_a_newer_release() {
    let _s = serial();
    let f = Fixture::new("check-newer");
    f.latest_sums_only(LATEST);
    let out = f.run(&["update", "--check"], f.base());
    assert_eq!(out.code, 1, "{}", out.context());
    assert_eq!(
        out.stdout,
        format!("installed {CURRENT}, latest {LATEST}\n"),
        "{}",
        out.context()
    );
    assert!(f.exe_is_original(), "a check installs nothing");
}

#[test]
fn check_reports_current() {
    let _s = serial();
    let f = Fixture::new("check-current");
    f.latest_sums_only(CURRENT);
    let out = f.run(&["update", "--check"], f.base());
    assert_eq!(out.code, 0, "{}", out.context());
    assert_eq!(
        out.stdout,
        format!("installed {CURRENT}, latest {CURRENT}\n"),
        "{}",
        out.context()
    );
}

#[test]
fn check_exits_2_when_the_release_is_unreadable() {
    let _s = serial();
    // An empty folder, and a latest version that is not dotted integers.
    for latest in [None, Some("9.9.9-rc1")] {
        let f = Fixture::new("check-unreadable");
        std::fs::create_dir_all(&f.release.base).unwrap();
        if let Some(v) = latest {
            f.latest_sums_only(v);
        }
        let out = f.run(&["update", "--check"], f.base());
        assert_eq!(out.code, 2, "{latest:?}: {}", out.context());
        assert_eq!(out.stdout, "", "{latest:?}: {}", out.context());
        let lines = out.stderr_lines();
        assert_eq!(
            lines.len(),
            1,
            "{latest:?}: one stderr line\n{}",
            out.context()
        );
        assert!(
            lines[0].starts_with("shellwise update: "),
            "{latest:?}: {}",
            out.context()
        );
    }
}

#[test]
fn update_replaces_the_running_binary_in_its_own_folder() {
    let _s = serial();
    let f = Fixture::new("replace");
    f.publish_latest(LATEST);
    let out = f.run(&["update"], f.base());
    assert_eq!(out.code, 0, "folder {:?}\n{}", f.listing(), out.context());
    let want = fake_binary(LATEST, host_target());
    assert!(
        std::fs::read(f.exe()).ok() == Some(want),
        "the binary next to the copy is the fake {LATEST}; folder {:?}\n{}",
        f.listing(),
        out.context()
    );
    // On Windows the running binary was renamed aside and stays while it was locked.
    let mut allowed = vec![bin_name().to_string()];
    if cfg!(windows) {
        allowed.push(format!("{}.old", bin_name()));
    }
    for name in f.listing() {
        assert!(
            allowed.contains(&name),
            "left over: {name}\n{}",
            out.context()
        );
    }
    for dir in f.default_install_dirs() {
        assert!(!dir.exists(), "installed into the default folder {dir:?}");
    }
    assert!(out.stdout.contains(LATEST), "{}", out.context());
}

#[test]
fn update_when_current_says_so_and_downloads_nothing() {
    let _s = serial();
    let f = Fixture::new("current");
    // No archive in the release: a download would fail.
    f.latest_sums_only(CURRENT);
    let out = f.run(&["update"], f.base());
    assert_eq!(out.code, 0, "{}", out.context());
    assert_eq!(
        out.stdout,
        format!("shellwise {CURRENT} is current\n"),
        "{}",
        out.context()
    );
    assert!(f.exe_is_original());
    assert_eq!(f.listing(), vec![bin_name().to_string()]);
}

#[test]
fn update_with_a_wrong_checksum_refuses_and_keeps_the_binary() {
    let _s = serial();
    let f = Fixture::new("wrongsum");
    f.publish_latest(LATEST);
    let sums = f.release.sums(LATEST);
    let swapped = if sums.starts_with('0') { '1' } else { '0' };
    f.release
        .write_sums(LATEST, &format!("{swapped}{}", &sums[1..]));
    let out = f.run(&["update"], f.base());
    assert_eq!(out.code, 1, "{}", out.context());
    let lines = out.stderr_lines();
    assert_eq!(lines.len(), 1, "one stderr line\n{}", out.context());
    assert!(
        lines[0].starts_with("shellwise install: ") && lines[0].contains("checksum"),
        "{}",
        out.context()
    );
    assert!(f.exe_is_original(), "the binary is unchanged");
    assert_eq!(f.listing(), vec![bin_name().to_string()]);
}

/// Without `pwsh` on PATH the script runs under Windows PowerShell 5.1.
#[cfg(windows)]
#[test]
fn windows_powershell_runs_the_script_when_pwsh_is_missing() {
    let _s = serial();
    let path = std::env::var_os("PATH").expect("PATH");
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|d| !d.join("pwsh.exe").is_file())
        .collect();
    if !kept.iter().any(|d| d.join("powershell.exe").is_file()) {
        shown(
            "SKIP windows_powershell_runs_the_script_when_pwsh_is_missing: \
             powershell.exe is not on PATH",
        );
        return;
    }
    let path = std::env::join_paths(&kept).unwrap();
    let env = [("PATH", path.as_os_str())];
    let f = Fixture::new("ps51");
    f.publish_latest(LATEST);
    let check = f.run_env(&["update", "--check"], f.base(), &env);
    assert_eq!(check.code, 1, "{}", check.context());
    assert_eq!(
        check.stdout,
        format!("installed {CURRENT}, latest {LATEST}\n"),
        "{}",
        check.context()
    );
    let out = f.run_env(&["update"], f.base(), &env);
    assert_eq!(out.code, 0, "{}", out.context());
    assert!(
        std::fs::read(f.exe()).ok() == Some(fake_binary(LATEST, host_target())),
        "folder {:?}\n{}",
        f.listing(),
        out.context()
    );
}

#[test]
fn update_in_a_read_only_folder_refuses_and_keeps_the_binary() {
    let _s = serial();
    #[cfg(not(unix))]
    {
        shown(
            "SKIP update_in_a_read_only_folder_refuses_and_keeps_the_binary: \
             a read-only folder attribute does not stop writes on Windows",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("readonly");
        f.publish_latest(LATEST);
        std::fs::set_permissions(&f.bin_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let probe = f.bin_dir.join("probe");
        if std::fs::write(&probe, b"x").is_ok() {
            let _ = std::fs::remove_file(&probe);
            shown(
                "SKIP update_in_a_read_only_folder_refuses_and_keeps_the_binary: \
                 this user writes into a mode-555 folder (root)",
            );
            return;
        }
        let out = f.run(&["update"], f.base());
        assert_eq!(out.code, 1, "{}", out.context());
        let lines = out.stderr_lines();
        assert_eq!(lines.len(), 1, "one stderr line\n{}", out.context());
        assert!(
            lines[0].starts_with("shellwise update: "),
            "{}",
            out.context()
        );
        assert!(f.exe_is_original(), "the binary is unchanged");
        assert_eq!(f.listing(), vec![bin_name().to_string()]);
    }
}

#[test]
fn notify_prints_one_line_when_newer() {
    let _s = serial();
    let f = Fixture::new("notify-newer");
    f.latest_sums_only(LATEST);
    let out = f.run(&["update", "--notify"], f.base());
    assert_eq!(out.code, 0, "{}", out.context());
    assert_eq!(out.stdout, notice(LATEST), "{}", out.context());
    assert_eq!(out.stderr, "", "{}", out.context());
    assert!(f.exe_is_original(), "a notify installs nothing");
}

#[test]
fn notify_is_silent_when_current_or_unreachable() {
    let _s = serial();
    for current in [true, false] {
        let f = Fixture::new("notify-silent");
        std::fs::create_dir_all(&f.release.base).unwrap();
        if current {
            f.latest_sums_only(CURRENT);
        }
        let out = f.run(&["update", "--notify"], f.base());
        assert_eq!(out.code, 0, "current {current}: {}", out.context());
        assert_eq!(out.stdout, "", "current {current}: {}", out.context());
        assert_eq!(out.stderr, "", "current {current}: {}", out.context());
    }
}

#[test]
fn notify_checks_at_most_once_a_day() {
    let _s = serial();
    let f = Fixture::new("notify-daily");
    f.latest_sums_only(LATEST);
    let first = f.run(&["update", "--notify"], f.base());
    assert_eq!(first.stdout, notice(LATEST), "{}", first.context());
    let stamp: u64 = std::fs::read_to_string(f.stamp())
        .unwrap_or_else(|e| panic!("no stamp at {:?}: {e}", f.stamp()))
        .trim()
        .parse()
        .expect("the stamp is a Unix time");
    assert!(unix_now().abs_diff(stamp) < 60, "stamp {stamp}");
    // The newer release is still there: the second run inside the day says nothing.
    let second = f.run(&["update", "--notify"], f.base());
    assert_eq!(second.code, 0, "{}", second.context());
    assert_eq!(second.stdout, "", "{}", second.context());
    // A stamp older than a day checks again.
    std::fs::write(f.stamp(), (unix_now() - 25 * 3600).to_string()).unwrap();
    let third = f.run(&["update", "--notify"], f.base());
    assert_eq!(third.stdout, notice(LATEST), "{}", third.context());
}

#[test]
fn notify_returns_within_the_bound() {
    let _s = serial();
    let f = Fixture::new("notify-bound");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accepts every connection and never answers; the streams stay open until the test ends.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    let base = format!("http://127.0.0.1:{port}");
    // The first start of a freshly written exe waits for the virus scan (1.7 s measured on
    // Windows), which is before `main` and not the bound under test.
    let warm = f.run(&["--version"], OsStr::new(&base));
    assert_eq!(warm.code, 0, "{}", warm.context());
    let out = f.run(&["update", "--notify"], OsStr::new(&base));
    assert_eq!(out.code, 0, "{}", out.context());
    assert_eq!(out.stdout, "", "{}", out.context());
    assert_eq!(out.stderr, "", "{}", out.context());
    // The 3 s bound runs inside the process; starting and ending the process on a busy runner
    // adds to what is measured here (3.29 s seen on Windows CI). The plugin's session-start hook
    // gives the command 5 s, and a run without the bound waits 10 s for this silent server.
    assert!(
        out.elapsed < Duration::from_secs(4),
        "back within 4 s: {}",
        out.context()
    );
}

/// The interpreter gets the script on stdin: it must be ASCII, so no code page can change it.
#[test]
fn the_embedded_scripts_are_ascii() {
    for name in ["install.sh", "install.ps1"] {
        let text = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap();
        assert!(!text.is_empty(), "{name} is empty");
        assert!(text.is_ascii(), "{name} holds a non-ASCII byte");
    }
}
