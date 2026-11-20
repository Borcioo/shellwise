mod common;

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
