mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{assert_ok, run};

#[test]
fn check_argv_form_prints_ok_json() {
    let r = run(
        &["check", "--shell", "pwsh", "--json", "--", "Get-Date"],
        None,
        &[],
    );
    assert_ok(&r);
}

#[test]
fn check_stdin_form_prints_ok_json() {
    let r = run(
        &["check", "--shell", "pwsh", "--json"],
        Some(b"Get-Date"),
        &[],
    );
    assert_ok(&r);
}

#[test]
fn every_shell_name_is_accepted() {
    for shell in ["pwsh", "powershell5", "bash", "gitbash"] {
        let r = run(
            &["check", "--shell", shell, "--json", "--", "ls"],
            None,
            &[],
        );
        assert_ok(&r);
    }
}

#[test]
fn usage_errors_exit_64() {
    let cases: &[&[&str]] = &[
        &["check", "--shell", "nope", "--", "ls"],
        &["check", "--", "ls"],
        &["check", "--shell", "pwsh", "--bogus", "--", "ls"],
        &["nope"],
        &[],
    ];
    for args in cases {
        let r = run(args, Some(b""), &[]);
        assert_eq!(r.code, 64, "{args:?}: {:?}", r.stderr);
        assert!(!r.stderr.is_empty(), "{args:?}: no usage message");
    }
}

#[test]
fn text_form_names_the_level() {
    let r = run(&["check", "--shell", "bash", "--", "ls"], None, &[]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "ok\n");
}

#[test]
fn text_form_prints_the_fix_line() {
    let r = run(&["check", "--shell", "bash"], Some(b"echo 'abc"), &[]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", r.stdout);
    assert!(
        lines[0].starts_with("break parse-error [5..9]: "),
        "{}",
        r.stdout
    );
    assert_eq!(
        lines[1],
        "  Fix: close the ' opened at column 6, or write the text to a file and pass the file"
    );
}

/// The setup text as committed, read from disk.
fn setup_text() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/agent-setup.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// The body of the one fenced block tagged `tag`, without its final newline.
fn fenced(text: &str, tag: &str) -> String {
    let open = format!("```{tag}\n");
    let found: Vec<usize> = text.match_indices(&open).map(|(i, _)| i).collect();
    assert_eq!(found.len(), 1, "the text holds one block tagged {tag}");
    let body = &text[found[0] + open.len()..];
    let end = body
        .find("\n```")
        .unwrap_or_else(|| panic!("{tag}: block not closed"));
    body[..end].to_string()
}

#[test]
fn agent_setup_prints_the_embedded_text() {
    let want = setup_text();
    let r = run(&["agent-setup"], None, &[]);
    assert_eq!(r.code, 0, "stderr {:?}", r.stderr);
    assert_eq!(r.stdout, want, "stdout is not the file byte for byte");
    assert!(!want.contains('\r'), "the text has a CR");
    assert!(want.is_ascii(), "the text is not ASCII");
    assert!(want.lines().count() < 200, "{} lines", want.lines().count());
}

#[test]
fn the_setup_text_names_every_contract_item() {
    let text = setup_text();
    for item in [
        "shellwise hook generic",
        "--shell",
        "exit code 2",
        "SHELLWISE=off",
        "# shellwise: allow",
        "shellwise check",
        "--json",
        "shellwise update",
        "back up",
        "10 seconds",
    ] {
        assert!(text.contains(item), "the text does not name {item:?}");
    }
}

/// Each proof command is refused at `break`: `check` exits 1 on it (stdin, no trailing newline),
/// and `hook generic` exits 2 with a `shellwise: break` line on stderr.
#[test]
fn the_proof_commands_are_refused_at_break() {
    let text = setup_text();
    for (tag, shell) in [("proof-bash", "bash"), ("proof-pwsh", "pwsh")] {
        let command = fenced(&text, tag);
        let r = run(&["check", "--shell", shell], Some(command.as_bytes()), &[]);
        assert_eq!(r.code, 1, "{tag}: check said {:?}", r.stdout);
        let event = serde_json::json!({ "command": command }).to_string();
        let r = run(
            &["hook", "generic", "--shell", shell],
            Some(event.as_bytes()),
            &[("SHELLWISE", "")],
        );
        assert_eq!(r.code, 2, "{tag}: hook stderr {:?}", r.stderr);
        assert!(
            r.stderr.lines().any(|l| l.starts_with("shellwise: break")),
            "{tag}: hook stderr {:?}",
            r.stderr
        );
    }
}

/// Git Bash `sh` on Windows (never the `bash` on PATH, which is WSL), `sh` elsewhere.
fn posix_sh() -> Option<PathBuf> {
    if cfg!(windows) {
        let git = PathBuf::from(std::env::var_os("ProgramFiles")?).join("Git");
        let sh = git.join("bin").join("sh.exe");
        sh.is_file().then_some(sh)
    } else {
        Some(PathBuf::from("sh"))
    }
}

/// Run `program <args> <script>` with `stdin` written and closed; the config homes are isolated
/// and `SHELLWISE`, `DIR` and the test hooks removed. `None` when the program does not start.
fn run_script(program: &Path, args: &[&str], script: &Path, stdin: &[u8]) -> Option<(i32, String)> {
    let empty = std::env::temp_dir().join("shellwise-tests-empty");
    std::fs::create_dir_all(&empty).expect("create the isolated folder");
    let mut child = Command::new(program)
        .args(args)
        .arg(script)
        .current_dir(&empty)
        .env("APPDATA", &empty)
        .env("XDG_CONFIG_HOME", &empty)
        .env("HOME", &empty)
        .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
        .env_remove("SHELLWISE")
        .env_remove("DIR")
        .env_remove("SHELLWISE_TESTHOOK")
        .env_remove("SHELLWISE_TESTHOOK_DEADLINE_MS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(stdin);
    }
    let out = child.wait_with_output().expect("wait for the interpreter");
    let code = out.status.code().expect("exit code");
    Some((
        code,
        String::from_utf8_lossy(&out.stderr).replace("\r\n", "\n"),
    ))
}

/// Run one guard block from the text through `program`: with the placeholder replaced by the test
/// binary a refused event exits 2 with the findings on stderr and a harmless one exits 0; with a
/// binary that does not exist both exit 0 with nothing on stderr. Returns false when `program`
/// does not start.
fn guard_rows(
    tag: &str,
    placeholder: &str,
    program: &Path,
    args: &[&str],
    ext: &str,
    slashes: bool,
    events: [&str; 2],
) -> bool {
    let block = fenced(&setup_text(), tag);
    assert_eq!(
        block.matches(placeholder).count(),
        1,
        "{tag}: one placeholder"
    );
    let path_text = |p: PathBuf| {
        let s = p.to_str().expect("a Unicode path").to_string();
        if slashes { s.replace('\\', "/") } else { s }
    };
    let missing = std::env::temp_dir().join("shellwise-no-such-binary.exe");
    assert!(!missing.exists());
    let dir = std::env::temp_dir().join("shellwise-tests-guard");
    std::fs::create_dir_all(&dir).expect("create the script folder");
    let label = program.file_stem().unwrap().to_string_lossy().into_owned();
    let refused = serde_json::json!({ "command": events[0] }).to_string();
    let harmless = serde_json::json!({ "command": events[1] }).to_string();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_shellwise"));
    let rows = [
        ("binary", bin.clone(), &refused, 2),
        ("binary", bin, &harmless, 0),
        ("missing", missing.clone(), &refused, 0),
        ("missing", missing, &harmless, 0),
    ];
    for (i, (case, binary, event, want)) in rows.into_iter().enumerate() {
        let script_text = block.replace(placeholder, &path_text(binary));
        assert!(!script_text.contains(placeholder));
        let script = dir.join(format!("{tag}-{label}-{i}-{}.{ext}", std::process::id()));
        std::fs::write(&script, format!("{script_text}\n")).expect("write the script");
        let Some((code, stderr)) = run_script(program, args, &script, event.as_bytes()) else {
            return false;
        };
        let _ = std::fs::remove_file(&script);
        assert_eq!(
            code, want,
            "{tag} via {label}, {case}, {event}: stderr {stderr:?}"
        );
        if want == 2 {
            assert!(
                stderr.lines().any(|l| l.starts_with("shellwise: break")),
                "{tag} via {label}: stderr {stderr:?}"
            );
        } else {
            assert_eq!(stderr, "", "{tag} via {label}, {case}, {event}");
        }
    }
    true
}

#[test]
fn the_sh_guard_line_passes_only_a_block() {
    let Some(sh) = posix_sh() else {
        println!("SKIP the_sh_guard_line_passes_only_a_block: no Git Bash sh");
        return;
    };
    let ran = guard_rows(
        "guard-sh",
        "/full/path/to/shellwise",
        &sh,
        &[],
        "sh",
        cfg!(windows),
        ["echo 'abc", "echo shellwise-proof-ok"],
    );
    if !ran {
        println!("SKIP the_sh_guard_line_passes_only_a_block: {sh:?} did not start");
    }
}

#[test]
fn the_powershell_guard_line_passes_only_a_block() {
    let mut programs = vec!["pwsh"];
    if cfg!(windows) {
        programs.push("powershell");
    }
    for program in programs {
        let ran = guard_rows(
            "guard-pwsh",
            r"C:\full\path\to\shellwise.exe",
            Path::new(program),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ],
            "ps1",
            false,
            [
                r#"Write-Output "$name: done""#,
                "Write-Output shellwise-proof-ok",
            ],
        );
        if !ran {
            println!("SKIP the_powershell_guard_line_passes_only_a_block: {program} did not start");
        }
    }
}
