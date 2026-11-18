//! The three config layers: integration (`--config`), user (overrides it), repo (raise only).

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use shellwise::config::{CONFIG_INVALID, CONFIG_REPO_IGNORED, Config, REPO_FILE, repo_file};
use shellwise::level::{Finding, Level};

/// A fresh, empty folder for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("config")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, text).unwrap();
    p
}

fn rules(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().map(|f| f.rule).collect()
}

#[test]
fn defaults_without_any_layer() {
    let (cfg, findings) = Config::load(None, None, None);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg.dynamic_target, Level::Danger);
    assert_eq!(cfg.walk_budget_ms, 8000);
    assert_eq!(cfg.hook_timeout_ms, 10000);
    assert!(cfg.gate_commands.is_empty());
    assert!(!cfg.policies.git_no_verify);
    let want = [
        "php",
        "php8[0-9]",
        "composer",
        "wp",
        "phpcs",
        "phpcbf",
        "phpstan",
        r"vendor\bin\*",
    ];
    assert_eq!(cfg.bat_launchers, want);
}

#[test]
fn integration_layer_applies_when_the_user_file_is_unset() {
    let d = scratch("integration_only");
    let integ = write(
        &d,
        "integ.toml",
        "gate_commands = ['my-tool.ps1', 'cargo test']\n[policies]\ngit_no_verify = true\n",
    );
    let (cfg, findings) = Config::load(Some(&integ), None, None);
    assert!(findings.is_empty(), "{findings:?}");
    assert!(cfg.policies.git_no_verify);
    assert_eq!(cfg.gate_commands, ["my-tool.ps1", "cargo test"]);
}

#[test]
fn user_layer_overrides_the_integration_layer() {
    let d = scratch("user_overrides");
    let integ = write(
        &d,
        "integ.toml",
        "gate_commands = ['a']\ndynamic_target = 'critical'\nask_instead_of_deny = ['x']\n\
         [levels]\nr1 = 'danger'\nr2 = 'break'\n[policies]\ngit_no_verify = true\n\
         [tool_paths]\nmy-tool = 'x/my-tool.ps1'\n",
    );
    let user = write(
        &d,
        "user.toml",
        "gate_commands = ['b']\ndynamic_target = 'break'\nask_instead_of_deny = []\n\
         [levels]\nr1 = 'warn'\n[policies]\ngit_no_verify = false\n\
         [tool_paths]\nmy-tool = 'y/my-tool.ps1'\n",
    );
    let (cfg, findings) = Config::load(Some(&integ), Some(&user), None);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg.gate_commands, ["b"]);
    assert_eq!(cfg.dynamic_target, Level::Break);
    assert!(cfg.ask_instead_of_deny.is_empty());
    assert!(!cfg.policies.git_no_verify);
    assert_eq!(cfg.tool_paths["my-tool"], d.join("y/my-tool.ps1"));
    // The user lowers r1 (allowed) and leaves the integration's r2 in place.
    assert_eq!(cfg.level("r1", Level::Danger), Level::Warn);
    assert_eq!(cfg.level("r2", Level::Warn), Level::Break);
}

#[test]
fn repo_layer_raises_levels() {
    let d = scratch("repo_raises");
    let user = write(&d, "user.toml", "[levels]\nset = 'warn'\n");
    let repo = write(
        &d,
        REPO_FILE,
        "[levels]\nset = 'danger'\nunset = 'critical'\n",
    );
    let (cfg, findings) = Config::load(None, Some(&user), Some(&repo));
    assert!(findings.is_empty(), "{findings:?}");
    // Over a user setting, and over a rule default no other layer set.
    assert_eq!(cfg.level("set", Level::Break), Level::Danger);
    assert_eq!(cfg.level("unset", Level::Break), Level::Critical);
}

#[test]
fn repo_layer_cannot_lower_levels() {
    let d = scratch("repo_lowers");
    let user = write(&d, "user.toml", "[levels]\nr = 'danger'\n");
    let rows = [
        ("r = 'warn'", "levels.r", "r", Level::Danger, Level::Danger),
        // `ok` only switches a rule off, whatever its default.
        (
            "fresh = 'ok'",
            "levels.fresh",
            "fresh",
            Level::Break,
            Level::Break,
        ),
    ];
    for (line, key, rule, default, want) in rows {
        let repo = write(&d, REPO_FILE, &format!("[levels]\n{line}\n"));
        let (cfg, findings) = Config::load(None, Some(&user), Some(&repo));
        assert_eq!(
            rules(&findings),
            [CONFIG_REPO_IGNORED],
            "{line}: {findings:?}"
        );
        assert!(
            findings[0].message.contains(&format!("`{key}`")),
            "{line}: {}",
            findings[0].message
        );
        assert_eq!(findings[0].level, Level::Warn, "{line}");
        assert_eq!(cfg.level(rule, default), want, "{line}");
    }
}

#[test]
fn repo_layer_adds_protected_paths() {
    let d = scratch("repo_protected");
    let user = write(&d, "user.toml", "protected = ['keep']\n");
    let repo = write(&d, REPO_FILE, "protected = ['also']\n");
    let (cfg, findings) = Config::load(None, Some(&user), Some(&repo));
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg.protected, [d.join("keep"), d.join("also")]);
}

#[test]
fn repo_layer_ignores_every_other_key() {
    let d = scratch("repo_ignored");
    let user = write(
        &d,
        "user.toml",
        "ask_instead_of_deny = ['u']\ngate_commands = ['g']\n",
    );
    let (baseline, none) = Config::load(None, Some(&user), None);
    assert!(none.is_empty(), "{none:?}");
    let rows = [
        ("dynamic_target", "dynamic_target = 'warn'"),
        ("ask_instead_of_deny", "ask_instead_of_deny = ['delete']"),
        ("tool_paths", "[tool_paths]\ngit = 'evil.exe'"),
        ("gate_commands", "gate_commands = []"),
        ("bat_launchers", "bat_launchers = []"),
        ("walk_budget_ms", "walk_budget_ms = 1"),
        ("hook_timeout_ms", "hook_timeout_ms = 999999"),
        ("policies", "[policies]\ngit_no_verify = true"),
        ("unknown_key", "unknown_key = 1"),
    ];
    for (key, text) in rows {
        let repo = write(&d, REPO_FILE, &format!("{text}\n"));
        let (cfg, findings) = Config::load(None, Some(&user), Some(&repo));
        assert_eq!(cfg, baseline, "{key}: the repo file changed the config");
        assert_eq!(
            rules(&findings),
            [CONFIG_REPO_IGNORED],
            "{key}: {findings:?}"
        );
        assert_eq!(findings[0].level, Level::Warn, "{key}");
        assert!(
            findings[0].message.contains(&format!("`{key}`")),
            "{key}: {}",
            findings[0].message
        );
    }
}

#[test]
fn malformed_toml_ignores_only_that_layer() {
    let d = scratch("malformed");
    let bad = "gate_commands = ['unterminated\n";
    let integ_ok = "[policies]\ngit_no_verify = true\n";
    let user_ok = "gate_commands = ['g']\n";
    let repo_ok = "[levels]\nr = 'critical'\n";
    // (broken layer, integration, user, repo)
    let rows = [
        ("integration", bad, user_ok, repo_ok),
        ("user", integ_ok, bad, repo_ok),
        ("repo", integ_ok, user_ok, bad),
    ];
    for (broken, i, u, r) in rows {
        let integ = write(&d, "integ.toml", i);
        let user = write(&d, "user.toml", u);
        let repo = write(&d, REPO_FILE, r);
        let (cfg, findings) = Config::load(Some(&integ), Some(&user), Some(&repo));
        assert_eq!(rules(&findings), [CONFIG_INVALID], "{broken}: {findings:?}");
        assert_eq!(findings[0].level, Level::Warn, "{broken}");
        assert!(
            findings[0]
                .message
                .contains(&format!("{broken} config file")),
            "{broken}: {}",
            findings[0].message
        );
        assert_eq!(
            cfg.policies.git_no_verify,
            broken != "integration",
            "{broken}"
        );
        assert_eq!(cfg.gate_commands.is_empty(), broken == "user", "{broken}");
        let want = if broken == "repo" {
            Level::Warn
        } else {
            Level::Critical
        };
        assert_eq!(cfg.level("r", Level::Warn), want, "{broken}");
    }
}

#[test]
fn a_bad_value_ignores_only_that_key() {
    let d = scratch("bad_value");
    let rows = [
        ("walk_budget_ms", "walk_budget_ms = -5"),
        ("hook_timeout_ms", "hook_timeout_ms = 'soon'"),
        ("dynamic_target", "dynamic_target = 'severe'"),
        ("gate_commands", "gate_commands = 'one'"),
        ("bat_launchers", "bat_launchers = [1]"),
        ("ask_instead_of_deny", "ask_instead_of_deny = {}"),
        ("protected", "protected = [true]"),
        ("levels", "levels = 'all'"),
        ("levels.r", "levels.r = 'high'"),
        ("tool_paths.git", "tool_paths.git = 3"),
        ("policies.git_no_verify", "policies.git_no_verify = 'yes'"),
        ("policies.other", "policies.other = true"),
        ("unknown", "unknown = 1"),
    ];
    for (key, text) in rows {
        let user = write(&d, "user.toml", &format!("{text}\n"));
        let integ = write(&d, "integ.toml", "[policies]\ngit_no_verify = true\n");
        let (cfg, findings) = Config::load(Some(&integ), Some(&user), None);
        assert_eq!(rules(&findings), [CONFIG_INVALID], "{key}: {findings:?}");
        assert!(
            findings[0].message.contains(&format!("`{key}`")),
            "{key}: {}",
            findings[0].message
        );
        // Only the integration's setting is left.
        let mut want = Config::default();
        want.policies.git_no_verify = true;
        assert_eq!(cfg, want, "{key}: the bad value changed the config");
    }
}

#[test]
fn missing_files() {
    let d = scratch("missing");
    let gone = d.join("absent.toml");
    // A missing user or repo file is normal; a missing --config file is a finding.
    let (cfg, findings) = Config::load(None, Some(&gone), Some(&gone));
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg, Config::default());
    let (cfg, findings) = Config::load(Some(&gone), None, None);
    assert_eq!(rules(&findings), [CONFIG_INVALID], "{findings:?}");
    assert_eq!(cfg, Config::default());
}

#[test]
fn walk_budget_is_clamped_under_the_hook_timeout() {
    let d = scratch("clamp");
    let rows = [
        ("walk_budget_ms = 9500", 8500),
        ("walk_budget_ms = 3000", 3000),
        ("hook_timeout_ms = 3000", 1500),
        ("hook_timeout_ms = 1000", 0),
        ("walk_budget_ms = 8500", 8500),
    ];
    for (text, want) in rows {
        let user = write(&d, "user.toml", &format!("{text}\n"));
        let (cfg, findings) = Config::load(None, Some(&user), None);
        assert!(findings.is_empty(), "{text}: {findings:?}");
        assert_eq!(cfg.walk_budget_ms, want, "{text}");
    }
}

#[test]
fn relative_paths_resolve_against_the_file_folder() {
    let d = scratch("relative");
    let repo = write(&d, REPO_FILE, "protected = ['vendor']\n");
    let user = write(
        &d,
        "user.toml",
        "[tool_paths]\nmy-tool = 'tools/my-tool.ps1'\n",
    );
    let (cfg, findings) = Config::load(None, Some(&user), Some(&repo));
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg.protected, [d.join("vendor")]);
    assert_eq!(cfg.tool_paths["my-tool"], d.join("tools/my-tool.ps1"));
}

#[test]
fn a_bom_does_not_make_a_file_invalid() {
    let d = scratch("bom");
    let user = d.join("user.toml");
    fs::write(&user, b"\xef\xbb\xbfgate_commands = ['g']\n").unwrap();
    let (cfg, findings) = Config::load(None, Some(&user), None);
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(cfg.gate_commands, ["g"]);
}

#[test]
fn repo_file_is_at_the_root_of_the_repo_holding_cwd() {
    let d = scratch("discover");
    let nested = d.join("repo").join("a").join("b");
    fs::create_dir_all(&nested).unwrap();
    // Outside a repo there is no repo file.
    let outside = repo_file(&nested);
    assert!(
        outside.as_ref().is_none_or(|p| !p.starts_with(&d)),
        "{outside:?}"
    );
    // A `.git` file (a worktree) marks the root as a `.git` folder does.
    fs::write(d.join("repo").join(".git"), "gitdir: x\n").unwrap();
    assert_eq!(repo_file(&nested), Some(d.join("repo").join(REPO_FILE)));
    fs::create_dir(d.join("repo").join("a").join(".git")).unwrap();
    assert_eq!(
        repo_file(&nested),
        Some(d.join("repo").join("a").join(REPO_FILE))
    );
}

// --- The `check` command loads the layers. ---

/// Run `check` with the user config dir pointing into `home`.
fn check(home: &Path, extra: &[&str], command: &str, env: &[(&str, &str)]) -> common::Run {
    let home_s = home.to_str().unwrap();
    let mut args = vec!["check", "--shell", "pwsh", "--json"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", command]);
    let mut all = vec![
        ("APPDATA", home_s),
        ("XDG_CONFIG_HOME", home_s),
        ("HOME", home_s),
    ];
    all.extend_from_slice(env);
    common::run(&args, None, &all)
}

fn finding_rules(r: &common::Run) -> Vec<String> {
    let v = r.json();
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect()
}

/// A user config file under `home` as `user_file()` finds it on this OS.
fn user_config(home: &Path, text: &str) {
    let dir = if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        home.to_path_buf()
    };
    let dir = dir.join("shellwise");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), text).unwrap();
}

#[test]
fn check_reports_config_findings() {
    let d = scratch("cli_findings");
    let bad = write(&d, "integ.toml", "nope = [\n");
    let r = check(&d, &["--config", bad.to_str().unwrap()], "Get-Date", &[]);
    assert_eq!(r.code, 0, "{r:?}", r = r.stderr);
    assert_eq!(finding_rules(&r), [CONFIG_INVALID]);
    assert_eq!(r.json()["level"], "warn");

    let repo = d.join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    write(&repo, REPO_FILE, "dynamic_target = 'ok'\n");
    let r = check(&d, &["--cwd", repo.to_str().unwrap()], "Get-Date", &[]);
    assert_eq!(finding_rules(&r), [CONFIG_REPO_IGNORED], "{}", r.stdout);
}

/// The `slow` test hook sleeps 1 s inside the analysis; a 2000 ms hook timeout leaves a 500 ms
/// deadline, so the analysis fails closed instead of finishing.
#[cfg(feature = "testhooks")]
#[test]
fn check_takes_the_deadline_from_each_layer() {
    let slow = [("SHELLWISE_TESTHOOK", "slow")];
    let short = "hook_timeout_ms = 2000\n";
    let cmd = "rm -rf x";

    // Integration file.
    let d = scratch("cli_deadline_integration");
    let integ = write(&d, "integ.toml", short);
    let r = check(&d, &["--config", integ.to_str().unwrap()], cmd, &slow);
    common::assert_failclosed_danger(&r, cmd, "rm -rf x");

    // User file.
    let d = scratch("cli_deadline_user");
    user_config(&d, short);
    let r = check(&d, &[], cmd, &slow);
    common::assert_failclosed_danger(&r, cmd, "rm -rf x");

    // Repo file: ignored, so the analysis finishes.
    let d = scratch("cli_deadline_repo");
    let repo = d.join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    write(&repo, REPO_FILE, short);
    let r = check(&d, &["--cwd", repo.to_str().unwrap()], cmd, &slow);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(
        finding_rules(&r),
        ["testhook-done", CONFIG_REPO_IGNORED],
        "{}",
        r.stdout
    );
}

#[cfg(feature = "testhooks")]
#[test]
fn check_fails_closed_when_the_config_does_not_load_in_time() {
    let d = scratch("cli_config_sleep");
    let env = [
        ("SHELLWISE_TESTHOOK", "config-sleep"),
        ("SHELLWISE_TESTHOOK_DEADLINE_MS", "300"),
    ];
    let cmd = "rm -rf x";
    let r = check(&d, &[], cmd, &env);
    common::assert_failclosed_danger(&r, cmd, "rm -rf x");
    // The wait ends at the deadline, not when the stuck load would finish (60 s).
    assert!(r.elapsed.as_secs() < 10, "took {:?}", r.elapsed);
    let r = check(&d, &[], "Get-Date", &env);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json()["level"], "ok");
}
