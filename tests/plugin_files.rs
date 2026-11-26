//! The Claude Code plugin and marketplace manifests in the repo: they parse, name the plugin and
//! its version as the crate does, register the hooks the plugin promises, and hold no absolute
//! path (the plugin is copied to other machines as it is).

use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn plugin_dir() -> PathBuf {
    root().join("plugins").join("shellwise")
}

fn json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The one handler of the one matcher group `event` registers.
fn only_handler<'a>(hooks: &'a Value, event: &str) -> (&'a Value, &'a Value) {
    let groups = hooks["hooks"][event]
        .as_array()
        .unwrap_or_else(|| panic!("hooks.{event} is not a list: {hooks}"));
    assert_eq!(groups.len(), 1, "hooks.{event}: {groups:?}");
    let handlers = groups[0]["hooks"]
        .as_array()
        .unwrap_or_else(|| panic!("hooks.{event}[0].hooks is not a list"));
    assert_eq!(handlers.len(), 1, "hooks.{event}[0].hooks: {handlers:?}");
    (&groups[0], &handlers[0])
}

#[test]
fn the_marketplace_lists_the_plugin_in_the_repo() {
    let market = json(&root().join(".claude-plugin").join("marketplace.json"));
    assert_eq!(market["name"], "shellwise");
    assert!(
        market["owner"]["name"]
            .as_str()
            .is_some_and(|n| !n.is_empty()),
        "owner.name is required: {market}"
    );
    let plugins = market["plugins"].as_array().expect("plugins is a list");
    assert_eq!(plugins.len(), 1, "{plugins:?}");
    assert_eq!(plugins[0]["name"], "shellwise");
    let source = plugins[0]["source"]
        .as_str()
        .expect("source is a relative path");
    assert_eq!(source, "./plugins/shellwise");
    assert!(
        root()
            .join(source)
            .join(".claude-plugin")
            .join("plugin.json")
            .is_file(),
        "{source} has no .claude-plugin/plugin.json"
    );
}

#[test]
fn the_plugin_has_the_crate_name_and_version() {
    let manifest = json(&plugin_dir().join(".claude-plugin").join("plugin.json"));
    assert_eq!(manifest["name"], "shellwise");
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_plugin_checks_bash_and_powershell_through_path() {
    let hooks = json(&plugin_dir().join("hooks").join("hooks.json"));
    let (group, handler) = only_handler(&hooks, "PreToolUse");
    assert_eq!(group["matcher"], "Bash|PowerShell");
    assert_eq!(handler["type"], "command");
    assert_eq!(handler["command"], "shellwise");
    assert_eq!(handler["args"], serde_json::json!(["hook", "claude-code"]));
    assert_eq!(handler["timeout"], 10);
    // A missing binary must let the command through (the plugin ships no binary).
    assert!(handler.get("onFailure").is_none(), "{handler}");
}

#[test]
fn the_plugin_checks_for_updates_at_session_start() {
    let hooks = json(&plugin_dir().join("hooks").join("hooks.json"));
    let (_, handler) = only_handler(&hooks, "SessionStart");
    assert_eq!(handler["type"], "command");
    assert_eq!(handler["command"], "shellwise");
    assert_eq!(handler["args"], serde_json::json!(["update", "--notify"]));
    assert_eq!(handler["timeout"], 5);
}

/// A Windows drive path (`C:\`, `c:/`), a UNC path, or a POSIX home or system folder.
fn absolute_path_in(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if before_ok
            && bytes[i].is_ascii_alphabetic()
            && bytes.get(i + 1) == Some(&b':')
            && matches!(bytes.get(i + 2), Some(b'\\' | b'/'))
        {
            return Some(text[i..].chars().take(40).collect());
        }
    }
    let posix = [
        "\\\\", "/home/", "/Users/", "/usr/", "/opt/", "/tmp/", "/etc/", "/root/", "/mnt/", "~/",
    ];
    posix
        .iter()
        .filter_map(|p| text.find(p))
        .filter(|&i| {
            // A URL path (`https://host/usr/…`) is not a file path.
            !text[..i]
                .rsplit(char::is_whitespace)
                .next()
                .is_some_and(|w| w.contains("://"))
        })
        .map(|i| text[i..].chars().take(40).collect())
        .next()
}

#[test]
fn the_absolute_path_check_knows_its_cases() {
    for hit in [
        "C:\\Users\\x\\bin",
        "run d:/tools/x",
        "\\\\server\\share",
        "/home/x/bin",
        "\"/usr/local/bin/shellwise\"",
        "~/bin",
    ] {
        assert!(absolute_path_in(hit).is_some(), "missed {hit:?}");
    }
    for miss in [
        "https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh",
        "./plugins/shellwise",
        "shellwise hook claude-code",
        "Bash|PowerShell",
    ] {
        assert_eq!(absolute_path_in(miss), None, "flagged {miss:?}");
    }
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn no_plugin_file_holds_an_absolute_path() {
    let mut files = vec![root().join(".claude-plugin").join("marketplace.json")];
    files_under(&root().join("plugins"), &mut files);
    // marketplace.json, plugin.json, hooks.json, README.md: a scan of fewer files proves nothing.
    assert!(files.len() >= 4, "read only {files:?}");
    for file in &files {
        let text =
            std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        assert_eq!(absolute_path_in(&text), None, "{}", file.display());
    }
}
