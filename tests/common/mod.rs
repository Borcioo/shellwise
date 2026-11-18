//! Runs the built `shellwise` binary.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub elapsed: Duration,
}

impl Run {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim_end())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }
}

/// An empty folder outside any repo: the default user config dir and working directory of every
/// run, so the machine's own config files never reach a test.
fn isolated_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("shellwise-tests-empty");
    std::fs::create_dir_all(&dir).expect("create the isolated folder");
    if let Some(repo) = dir.ancestors().find(|d| d.join(".git").exists()) {
        panic!("the isolated folder {dir:?} is inside the repo {repo:?}");
    }
    dir
}

/// Run `shellwise <args>` with `stdin` bytes and extra environment variables. `env` may override
/// `APPDATA`, `XDG_CONFIG_HOME` and `HOME`, which point at an empty folder by default.
pub fn run(args: &[&str], stdin: Option<&[u8]>, env: &[(&str, &str)]) -> Run {
    let empty = isolated_dir();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellwise"));
    cmd.args(args)
        .current_dir(&empty)
        .env("APPDATA", &empty)
        .env("XDG_CONFIG_HOME", &empty)
        .env("HOME", &empty)
        .env_remove("SHELLWISE_TESTHOOK")
        .env_remove("SHELLWISE_TESTHOOK_DEADLINE_MS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let start = Instant::now();
    let mut child = cmd.spawn().expect("spawn shellwise");
    {
        let mut pipe = child.stdin.take().unwrap();
        if let Some(bytes) = stdin {
            // The binary may exit before reading everything; a broken pipe is not a test failure.
            let _ = pipe.write_all(bytes);
        }
    }
    let out = child.wait_with_output().expect("wait for shellwise");
    Run {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        elapsed: start.elapsed(),
    }
}

/// Assert a fail-closed `danger` verdict whose span covers `needle` in `command`.
pub fn assert_failclosed_danger(r: &Run, command: &str, needle: &str) {
    assert_eq!(r.code, 2, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    let v = r.json();
    assert_eq!(v["level"], "danger", "{v}");
    let f = &v["findings"][0];
    assert_eq!(f["rule"], "analysis-failed", "{v}");
    assert_eq!(f["level"], "danger", "{v}");
    let start = f["span"]["start"].as_u64().unwrap() as usize;
    let end = f["span"]["end"].as_u64().unwrap() as usize;
    assert!(
        command.get(start..end).is_some_and(|s| s.contains(needle)),
        "span {start}..{end} misses {needle:?}"
    );
}

/// Assert the plain `ok` verdict.
pub fn assert_ok(r: &Run) {
    assert_eq!(r.code, 0, "stdout {:?} stderr {:?}", r.stdout, r.stderr);
    assert_eq!(
        r.stdout,
        "{\"version\":1,\"level\":\"ok\",\"findings\":[]}\n"
    );
}
