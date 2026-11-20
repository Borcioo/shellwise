//! Ruling 114(f) through `analyse`: the delete guard makes no file-system call on a share or
//! device spelling, also where the lexical match makes it critical. `SHELLWISE_TESTHOOK=fs-record`
//! swaps in a file system that records every path it is asked about. One test in its own binary:
//! the hook mode is process-wide.
#![cfg(all(windows, feature = "testhooks"))]

use std::path::{Path, PathBuf};
use std::time::Instant;

use shellwise::config::Config;
use shellwise::fs::resolve::{env_view, path_key};
use shellwise::level::Level;
use shellwise::testhooks::FS_CALLS;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let root = std::env::temp_dir().join(format!("shellwise-delete-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["repo/.git", "repo/build", "home"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("repo/build/x.o"), b"x").unwrap();
        Fixture { root }
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel.replace('/', "\\"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The verdict level and the paths the rules asked the file system about.
fn run(fx: &Fixture, shell: Shell, command: &str, cwd: &Path) -> (Level, Vec<PathBuf>) {
    FS_CALLS.lock().unwrap().clear();
    let home = fx.at("home").to_string_lossy().into_owned();
    let env = env_view(shell, Os::Windows, [("USERPROFILE".to_string(), home)]);
    let input = AnalyseInput {
        bytes: command.as_bytes(),
        shell,
        os: Os::Windows,
        cwd: Some(cwd.to_path_buf()),
        env,
        origin: Origin::CommandLine,
        problem: None,
    };
    let v = analyse(
        &input,
        &Config::default(),
        &Deadline::new(Instant::now(), 8000),
    );
    (v.level, FS_CALLS.lock().unwrap().clone())
}

/// `call` is `target` or below it, compared as the guard compares paths (`\\?\` stripped).
fn under(call: &Path, target: &str) -> bool {
    let c = path_key(&call.to_string_lossy(), Os::Windows);
    let t = path_key(target, Os::Windows);
    let t = t.trim_end_matches('\\');
    c == t || c.starts_with(&format!("{t}\\"))
}

#[test]
fn no_file_system_call_on_a_share_or_device_spelling() {
    // SAFETY of the global: this binary holds this one test.
    unsafe { std::env::set_var("SHELLWISE_TESTHOOK", "fs-record") };
    let fx = Fixture::new();
    let repo = fx.at("repo");
    let home = fx.at("home").to_string_lossy().into_owned();
    let git = fx.at("repo/.git").to_string_lossy().into_owned();
    let pwsh = Shell::Pwsh;
    let bash = Shell::Bash(BashProfile::GitBash);
    // The repo lookup probes `<folder>\.git` above the cwd: a call on the local cwd, not on
    // the spelling under test.
    let probe = |c: &Path| {
        c.file_name().is_some_and(|n| n == ".git") && repo.starts_with(c.parent().unwrap())
    };

    // Positive control: a local recursive delete walks its tree.
    let (level, calls) = run(&fx, pwsh, "Remove-Item -Recurse -Force build", &repo);
    assert_eq!(level, Level::Ok);
    let build = fx.at("repo/build").to_string_lossy().into_owned();
    assert!(calls.iter().any(|c| under(c, &build)), "control: {calls:?}");

    let rows: [(Shell, String, &Path, Level, &str); 7] = [
        (
            pwsh,
            r"Remove-Item -Recurse -Force \\?\C:\".into(),
            &repo,
            Level::Critical,
            r"C:\",
        ),
        (
            pwsh,
            r"Remove-Item -Recurse -Force \\?\C:\Windows\Temp\sometool".into(),
            &repo,
            Level::Critical,
            r"C:\Windows",
        ),
        (
            pwsh,
            format!(r"Remove-Item -Recurse -Force \\?\{home}"),
            &repo,
            Level::Critical,
            &home,
        ),
        (
            pwsh,
            format!(r"Remove-Item -Recurse -Force \\?\{git}"),
            &repo,
            Level::Critical,
            &git,
        ),
        (
            pwsh,
            r"Remove-Item -Recurse -Force \\localhost\C$".into(),
            &repo,
            Level::Critical,
            r"C:\",
        ),
        (
            bash,
            "git clean -fdx".into(),
            Path::new(r"\\localhost\C$"),
            Level::Critical,
            r"C:\",
        ),
        // The twin: a share path that names nothing protected.
        (
            pwsh,
            r"Remove-Item -Recurse -Force \\localhost\C$\sometool-build".into(),
            &repo,
            Level::Danger,
            r"C:\sometool-build",
        ),
    ];
    let mut wrong = Vec::new();
    for (shell, command, cwd, want, local) in &rows {
        let (level, calls) = run(&fx, *shell, command, cwd);
        if level != *want {
            wrong.push(format!("{command}: level {level:?}, want {want:?}"));
        }
        let bad: Vec<&PathBuf> = calls
            .iter()
            .filter(|c| c.to_string_lossy().starts_with(r"\\") || (under(c, local) && !probe(c)))
            .collect();
        if !bad.is_empty() {
            wrong.push(format!("{command}: file-system calls {bad:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
