//! The install scripts against a fake release in a local folder: `install.ps1` under PowerShell 7
//! and Windows PowerShell 5.1 on Windows, `install.sh` under `sh` elsewhere. Every run sets
//! `SHELLWISE_NO_PATH=1` and a temp `SHELLWISE_INSTALL_DIR`, so no test touches this machine's PATH
//! or the real install folder, and nothing reaches the network.

mod common;

use common::release::{self, Release, bin_name, fake_binary, host_target, temp_folder};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const LATEST: &str = "9.9.9";
const OLDER: &str = "9.9.8";
const RUN_LIMIT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy)]
struct Interp {
    name: &'static str,
    program: &'static str,
    /// Arguments before the script path.
    args: &'static [&'static str],
    /// The major version the interpreter must report, when the test claims one.
    major: Option<&'static str>,
}

const PWSH: Interp = Interp {
    name: "pwsh",
    program: "pwsh",
    args: &["-NoProfile", "-NonInteractive", "-File"],
    major: None,
};
const PS51: Interp = Interp {
    name: "powershell 5.1",
    program: "powershell",
    args: &[
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ],
    major: Some("5"),
};
const SH: Interp = Interp {
    name: "sh",
    program: "sh",
    args: &[],
    major: None,
};

fn candidates() -> &'static [Interp] {
    if cfg!(windows) { &[PWSH, PS51] } else { &[SH] }
}

fn script() -> PathBuf {
    let name = if cfg!(windows) {
        "install.ps1"
    } else {
        "install.sh"
    };
    Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

fn is_powershell(i: Interp) -> bool {
    i.program != "sh"
}

/// The interpreter's version, or `None` when it is not installed, probed once per process. Any
/// other failure to start it fails the test instead of skipping it.
fn probe(i: Interp) -> Option<String> {
    static SEEN: OnceLock<Mutex<HashMap<&'static str, Option<String>>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashMap::new()));
    let mut seen = seen.lock().unwrap();
    seen.entry(i.name)
        .or_insert_with(|| {
            let mut cmd = Command::new(i.program);
            if is_powershell(i) {
                cmd.args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$PSVersionTable.PSVersion.ToString()",
                ])
                .env("POWERSHELL_TELEMETRY_OPTOUT", "1");
            } else {
                cmd.args(["-c", "exit"]);
            }
            let out = match cmd.stdin(Stdio::null()).output() {
                Ok(out) => out,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
                Err(e) => panic!("{} cannot be started: {e}", i.program),
            };
            assert!(
                out.status.success(),
                "{} exits {} on its version probe: {}",
                i.program,
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Some(major) = i.major {
                assert!(
                    version.starts_with(&format!("{major}.")),
                    "{} reports version {version:?}",
                    i.name
                );
            }
            shown(&format!("using {} {version}", i.name));
            Some(version)
        })
        .clone()
}

/// The interpreters `test` runs under; each missing one prints a SKIP line.
fn interps(test: &str) -> Vec<Interp> {
    let mut found = Vec::new();
    for &i in candidates() {
        if probe(i).is_some() {
            found.push(i);
        } else {
            shown(&format!(
                "SKIP {test}: {} is not installed ({})",
                i.program, i.name
            ));
        }
    }
    found
}

/// Writes past the test harness's output capture, so a SKIP shows on a passing run too.
fn shown(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn context(&self) -> String {
        format!(
            "exit {}\nstdout {:?}\nstderr {:?}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Runs `cmd` with `stdin` bytes, killing it at `RUN_LIMIT`.
fn run_bounded(mut cmd: Command, stdin: &[u8]) -> Out {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn the interpreter");
    let mut pipe = child.stdin.take().unwrap();
    let _ = pipe.write_all(stdin);
    drop(pipe);
    let read = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            String::from_utf8(buf).expect("output is UTF-8")
        })
    };
    let out = read(Box::new(child.stdout.take().unwrap()));
    let err = read(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            panic!("the script ran past {RUN_LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code: status.code().expect("exit code"),
        stdout: out.join().unwrap().replace("\r\n", "\n"),
        stderr: err.join().unwrap().replace("\r\n", "\n"),
    }
}

/// A fake release and an install folder in a temp folder removed at the end.
struct Fixture {
    root: PathBuf,
    release: Release,
    dir: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self::with_dir(label, "bin")
    }

    fn with_dir(label: &str, dir_name: &str) -> Self {
        let root = temp_folder(label);
        let release = Release::new(&root);
        let dir = root.join(dir_name);
        Fixture { root, release, dir }
    }

    fn installed(&self) -> PathBuf {
        self.dir.join(bin_name())
    }

    fn place_old(&self) -> Vec<u8> {
        std::fs::create_dir_all(&self.dir).unwrap();
        let old = fake_binary("1.0.0", host_target());
        std::fs::write(self.installed(), &old).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(self.installed(), mode).unwrap();
        }
        old
    }

    fn command(&self, i: Interp, env: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(i.program);
        cmd.args(i.args);
        self.set_env(&mut cmd, env);
        cmd
    }

    fn set_env(&self, cmd: &mut Command, env: &[(&str, &str)]) {
        // The guard every run relies on: never install outside a temp folder.
        assert!(self.dir.starts_with(std::env::temp_dir()), "{:?}", self.dir);
        cmd.current_dir(&self.root)
            .env_remove("SHELLWISE")
            .env_remove("SHELLWISE_VERSION")
            .env_remove("SHELLWISE_MODE")
            .env_remove("SHELLWISE_TARGET")
            .env("SHELLWISE_BASE_URL", &self.release.base)
            .env("SHELLWISE_INSTALL_DIR", &self.dir)
            .env("SHELLWISE_NO_PATH", "1")
            .env("POWERSHELL_TELEMETRY_OPTOUT", "1");
        for (k, v) in env {
            cmd.env(k, v);
        }
    }

    fn run(&self, i: Interp, env: &[(&str, &str)]) -> Out {
        let mut cmd = self.command(i, env);
        cmd.arg(script());
        run_bounded(cmd, b"")
    }

    fn listing(&self) -> Vec<String> {
        let mut names: Vec<String> = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    fn installed_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.installed()).ok()
    }

    /// The install folder holds `want` as the binary and nothing else.
    fn assert_holds(&self, want: &[u8], out: &Out, what: &str) {
        let got = self.installed_bytes();
        assert!(
            got.as_deref() == Some(want),
            "{what}: the binary is not the expected one (len {:?}, want {}); folder {:?}\n{}",
            got.as_ref().map(Vec::len),
            want.len(),
            self.listing(),
            out.context()
        );
        assert_eq!(
            self.listing(),
            vec![bin_name().to_string()],
            "{what}: {}",
            out.context()
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn runs(binary: &Path) -> bool {
    Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success() && o.stdout.starts_with(b"shellwise "))
}

fn assert_success(out: &Out) {
    assert_eq!(out.code, 0, "{}", out.context());
    assert!(
        out.stdout.contains("Next: shellwise agent-setup"),
        "{}",
        out.context()
    );
}

/// Exit 1 and exactly one stderr line, starting `shellwise install: ` and naming `needle`.
fn assert_refusal(out: &Out, needle: &str) {
    assert_eq!(out.code, 1, "{}", out.context());
    let lines: Vec<&str> = out
        .stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "one stderr line\n{}", out.context());
    assert!(
        lines[0].starts_with("shellwise install: "),
        "{}",
        out.context()
    );
    assert!(
        lines[0].to_lowercase().contains(needle),
        "the refusal names {needle:?}\n{}",
        out.context()
    );
}

fn publish_latest(f: &Fixture) {
    f.release.publish(LATEST, &[host_target()]);
    f.release.mark_latest(LATEST);
}

#[test]
fn a_fresh_install_places_a_runnable_binary() {
    for i in interps("a_fresh_install_places_a_runnable_binary") {
        let f = Fixture::new("fresh");
        publish_latest(&f);
        let out = f.run(i, &[]);
        assert_success(&out);
        assert!(out.stdout.contains(LATEST), "{}", out.context());
        f.assert_holds(&fake_binary(LATEST, host_target()), &out, i.name);
        assert!(
            runs(&f.installed()),
            "{}: the installed binary runs",
            i.name
        );
    }
}

#[test]
fn a_second_run_replaces_the_binary() {
    for i in interps("a_second_run_replaces_the_binary") {
        let f = Fixture::new("second");
        publish_latest(&f);
        let old = f.place_old();
        let out = f.run(i, &[]);
        let old_intact = f.installed_bytes().as_deref() == Some(&old[..]);
        assert_eq!(
            out.code,
            0,
            "{}: old binary intact: {old_intact}; folder {:?}\n{}",
            i.name,
            f.listing(),
            out.context()
        );
        f.assert_holds(&fake_binary(LATEST, host_target()), &out, i.name);
    }
}

#[test]
fn a_wrong_checksum_leaves_the_old_binary() {
    for i in interps("a_wrong_checksum_leaves_the_old_binary") {
        let f = Fixture::new("wrongsum");
        publish_latest(&f);
        let sums = f.release.sums(LATEST);
        let first = sums.chars().next().unwrap();
        let swapped = if first == '0' { '1' } else { '0' };
        f.release
            .write_sums(LATEST, &format!("{swapped}{}", &sums[1..]));
        let old = f.place_old();
        let out = f.run(i, &[]);
        assert_refusal(&out, "checksum");
        f.assert_holds(&old, &out, i.name);
        assert!(runs(&f.installed()), "{}: the old binary runs", i.name);
    }
}

#[test]
fn a_missing_checksum_line_refuses() {
    for i in interps("a_missing_checksum_line_refuses") {
        let f = Fixture::new("noline");
        publish_latest(&f);
        // Only a line for another target (and no gnu fallback on Linux).
        let other = format!(
            "{}  {}\n",
            "ab".repeat(32),
            release::archive_name(LATEST, "aarch64-apple-darwin")
        );
        f.release.write_sums(LATEST, &other);
        let old = f.place_old();
        let out = f.run(i, &[]);
        assert_refusal(&out, "sha256sums");
        f.assert_holds(&old, &out, i.name);
    }
}

#[test]
fn a_duplicate_checksum_line_refuses() {
    for i in interps("a_duplicate_checksum_line_refuses") {
        let f = Fixture::new("twolines");
        publish_latest(&f);
        // The right line first, a second one for the same archive after it.
        let sums = f.release.sums(LATEST);
        let wrong = format!("{}{}", "ab".repeat(32), &sums[64..]);
        f.release.write_sums(LATEST, &format!("{sums}{wrong}"));
        let old = f.place_old();
        let out = f.run(i, &[]);
        assert_refusal(&out, "more than one line");
        f.assert_holds(&old, &out, i.name);
    }
}

/// `install.sh` with a PATH that holds every tool it uses except `sha256sum` and `shasum`.
#[cfg(unix)]
#[test]
fn a_missing_hash_tool_refuses() {
    let tools = [
        "sh", "mktemp", "rm", "tr", "sed", "head", "awk", "cp", "uname", "cut", "grep", "tar",
        "gzip", "mkdir", "chmod", "mv",
    ];
    let path = std::env::var_os("PATH").expect("PATH");
    for i in interps("a_missing_hash_tool_refuses") {
        let f = Fixture::new("nohash");
        publish_latest(&f);
        let bin = f.root.join("tools");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in tools {
            let found = std::env::split_paths(&path)
                .map(|d| d.join(tool))
                .find(|p| p.is_file())
                .unwrap_or_else(|| panic!("{tool} is not on PATH"));
            std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
        }
        let old = f.place_old();
        let out = f.run(i, &[("PATH", bin.to_str().unwrap())]);
        assert_refusal(&out, "sha256sum");
        f.assert_holds(&old, &out, i.name);
    }
}

#[test]
fn an_html_error_page_as_sums_refuses() {
    for i in interps("an_html_error_page_as_sums_refuses") {
        let f = Fixture::new("html");
        publish_latest(&f);
        f.release.write_sums(LATEST, "<html>Not Found</html>\n");
        let old = f.place_old();
        // The latest release cannot be read, and a pinned one has no line for the archive.
        for (env, needle) in [
            (vec![], "latest"),
            (vec![("SHELLWISE_VERSION", LATEST)], "sha256sums"),
        ] {
            let out = f.run(i, &env);
            assert_refusal(&out, needle);
            f.assert_holds(&old, &out, i.name);
        }
    }
}

#[test]
fn a_cut_archive_refuses() {
    for i in interps("a_cut_archive_refuses") {
        let f = Fixture::new("cut");
        publish_latest(&f);
        let archive = f.release.archive_path(LATEST, host_target());
        let bytes = std::fs::read(&archive).unwrap();
        std::fs::write(&archive, &bytes[..bytes.len() / 2]).unwrap();
        let old = f.place_old();
        let out = f.run(i, &[]);
        assert_refusal(&out, "checksum");
        f.assert_holds(&old, &out, i.name);
        assert!(runs(&f.installed()), "{}: the old binary runs", i.name);
    }
}

#[test]
fn a_pinned_version_is_used() {
    for i in interps("a_pinned_version_is_used") {
        for pin in [OLDER, "v9.9.8"] {
            let f = Fixture::new("pinned");
            f.release.publish(OLDER, &[host_target()]);
            publish_latest(&f);
            let out = f.run(i, &[("SHELLWISE_VERSION", pin)]);
            assert_success(&out);
            f.assert_holds(&fake_binary(OLDER, host_target()), &out, i.name);
        }
    }
}

#[test]
fn check_mode_prints_the_latest_version_only() {
    for i in interps("check_mode_prints_the_latest_version_only") {
        let f = Fixture::new("check");
        f.release.publish(OLDER, &[host_target()]);
        publish_latest(&f);
        let old = f.place_old();
        let out = f.run(i, &[("SHELLWISE_MODE", "check")]);
        assert_eq!(out.code, 0, "{}", out.context());
        assert_eq!(out.stdout, format!("{LATEST}\n"), "{}", out.context());
        f.assert_holds(&old, &out, i.name);
    }
}

#[test]
fn an_install_dir_with_a_space_and_a_non_ascii_letter_works() {
    let letter = char::from_u32(0xEB).unwrap();
    let dir_name = format!("Zo{letter} Q");
    for i in interps("an_install_dir_with_a_space_and_a_non_ascii_letter_works") {
        let f = Fixture::with_dir("nonascii", &dir_name);
        publish_latest(&f);
        let out = f.run(i, &[]);
        assert_success(&out);
        f.assert_holds(&fake_binary(LATEST, host_target()), &out, i.name);
        assert!(runs(&f.installed()), "{}: the binary runs", i.name);
        // The script prints the path it installed to; a short 8.3 temp folder (GitHub's Windows
        // runners) may come back in its long spelling, so the file is compared by identity and
        // the install folder's own name as text.
        let prefix = format!("Installed shellwise {LATEST} at ");
        let printed = out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("{}: no {prefix:?} line\n{}", i.name, out.context()));
        let printed = Path::new(printed);
        assert!(
            printed.ends_with(Path::new(&dir_name).join(bin_name())),
            "{}: {printed:?} ends with {dir_name:?}\n{}",
            i.name,
            out.context()
        );
        let same = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(
            same(printed),
            same(&f.installed()),
            "{}: the printed path is the installed file\n{}",
            i.name,
            out.context()
        );
    }
}

#[test]
fn an_unsupported_target_refuses() {
    let supported: &[&str] = if cfg!(windows) {
        &["x86_64-pc-windows-msvc"]
    } else {
        &[
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ]
    };
    for i in interps("an_unsupported_target_refuses") {
        let f = Fixture::new("target");
        publish_latest(&f);
        let old = f.place_old();
        let out = f.run(i, &[("SHELLWISE_TARGET", "riscv64-unknown-none")]);
        assert_refusal(&out, "riscv64-unknown-none");
        for name in supported {
            assert!(out.stderr.contains(name), "lists {name}\n{}", out.context());
        }
        f.assert_holds(&old, &out, i.name);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn linux_falls_back_to_gnu_when_no_musl_line() {
    let gnu = "x86_64-unknown-linux-gnu";
    for i in interps("linux_falls_back_to_gnu_when_no_musl_line") {
        let f = Fixture::new("gnu");
        f.release.publish(LATEST, &[gnu]);
        f.release.mark_latest(LATEST);
        let out = f.run(i, &[]);
        assert_success(&out);
        f.assert_holds(&fake_binary(LATEST, gnu), &out, i.name);
    }
}

/// `Get-Content -Raw <script> | Invoke-Expression` on stdin, then `after`, as `irm <url> | iex` runs it.
#[cfg(windows)]
fn run_through_iex(f: &Fixture, i: Interp, env: &[(&str, &str)], after: &str) -> Out {
    let mut cmd = Command::new(i.program);
    cmd.args(["-NoProfile", "-NonInteractive"]);
    if i.major.is_some() {
        cmd.args(["-ExecutionPolicy", "Bypass"]);
    }
    cmd.args(["-Command", "-"]);
    f.set_env(&mut cmd, env);
    let text = format!(
        "Get-Content -Raw -LiteralPath '{}' | Invoke-Expression\n{after}\n",
        script().display()
    );
    run_bounded(cmd, text.as_bytes())
}

#[cfg(windows)]
#[test]
fn the_script_works_through_iex() {
    for i in interps("the_script_works_through_iex") {
        let f = Fixture::new("iex");
        publish_latest(&f);
        // Under a leaked Set-StrictMode the unset variable would be an error.
        let out = run_through_iex(&f, i, &[], "'session:' + [string]($null -eq $unsetName)");
        assert_eq!(out.code, 0, "{}: {}", i.name, out.context());
        assert!(
            out.stdout.contains("Next: shellwise agent-setup"),
            "{}",
            out.context()
        );
        assert!(out.stdout.contains("session:True"), "{}", out.context());
        assert!(out.stderr.trim().is_empty(), "{}", out.context());
        f.assert_holds(&fake_binary(LATEST, host_target()), &out, i.name);
    }
}

#[cfg(windows)]
#[test]
fn a_refusal_through_iex_keeps_the_session() {
    for i in interps("a_refusal_through_iex_keeps_the_session") {
        let f = Fixture::new("iexrefuse");
        publish_latest(&f);
        let old = f.place_old();
        let env = [("SHELLWISE_TARGET", "riscv64-unknown-none")];
        let out = run_through_iex(&f, i, &env, "'session:alive'");
        assert!(
            out.stdout.contains("session:alive"),
            "{}: {}",
            i.name,
            out.context()
        );
        assert!(
            out.stderr.contains("shellwise install: "),
            "{}",
            out.context()
        );
        f.assert_holds(&old, &out, i.name);
    }
}
