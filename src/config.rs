//! Configuration in three layers: an integration file (`--config`), the user file, which
//! overrides it, and the repo file `.shellwise.toml`, which may only raise levels and add
//! protected paths, so a cloned repo cannot weaken the guard.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::level::{Finding, Level, Span};

/// A layer, or one key of it, that could not be read; the layer or key is ignored.
pub const CONFIG_INVALID: &str = "config-invalid";
/// A repo-file key that may not be set there, or a level it would lower; it is ignored.
pub const CONFIG_REPO_IGNORED: &str = "config-repo-ignored";
/// The repo file's name, at the root of the repo holding the working directory.
pub const REPO_FILE: &str = ".shellwise.toml";
/// The analysis ends this long before the host's hook timeout.
pub const HOOK_MARGIN_MS: u64 = 1500;
/// A smaller `hook_timeout_ms` is `config-invalid`: the config load (1000 ms) and the margin must
/// leave time for the analysis.
pub const MIN_HOOK_TIMEOUT_MS: u64 = 3000;
/// A config file larger than this is ignored (`config-invalid`).
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policies {
    /// Enables the `git-no-verify` rule.
    pub git_no_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Rule id → level, from the integration and user files (raised or lowered).
    pub levels: HashMap<String, Level>,
    /// Rule ids whose deny the hook turns into an ask. Integration and user files only.
    pub ask_instead_of_deny: Vec<String>,
    /// Level of `dynamic-target` and `walk-timeout`.
    pub dynamic_target: Level,
    /// Upper bound for the whole analysis, folder walks included.
    pub walk_budget_ms: u64,
    /// The host's hook timeout; the analysis ends `HOOK_MARGIN_MS` before it.
    pub hook_timeout_ms: u64,
    /// Paths treated like a repo root by the delete guard.
    pub protected: Vec<PathBuf>,
    /// Commands whose output must not be truncated.
    pub gate_commands: Vec<String>,
    /// Windows `.bat` launcher names (`*` matches any run of characters).
    pub bat_launchers: Vec<String>,
    /// Optional tool paths named in fixes.
    pub tool_paths: HashMap<String, PathBuf>,
    pub policies: Policies,
    /// Levels the repo file raised: a floor under `levels` and the rule's default. Read rule
    /// levels through `Config::level`, never from `levels` alone.
    pub repo_floor: HashMap<String, Level>,
    /// Where the `too-long` Fix line says to write the command; else a per-user temp folder.
    pub scratch_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            levels: HashMap::new(),
            ask_instead_of_deny: Vec::new(),
            dynamic_target: Level::Danger,
            walk_budget_ms: 8000,
            hook_timeout_ms: 10000,
            protected: Vec::new(),
            gate_commands: Vec::new(),
            bat_launchers: [
                "php",
                "php8[0-9]",
                "composer",
                "wp",
                "phpcs",
                "phpcbf",
                "phpstan",
                r"vendor\bin\*",
            ]
            .map(String::from)
            .to_vec(),
            tool_paths: HashMap::new(),
            policies: Policies::default(),
            repo_floor: HashMap::new(),
            scratch_dir: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Layer {
    Integration,
    User,
    Repo,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Layer::Integration => "integration",
            Layer::User => "user",
            Layer::Repo => "repo",
        }
    }
}

impl Config {
    /// The level of `rule`: the integration/user setting or `default`, never below what the repo
    /// file raised it to.
    pub fn level(&self, rule: &str, default: Level) -> Level {
        let base = self.levels.get(rule).copied().unwrap_or(default);
        match self.repo_floor.get(rule) {
            Some(&floor) => base.max(floor),
            None => base,
        }
    }

    /// Merge the layers over the defaults. A missing user or repo file is no finding; every
    /// problem is a `warn` finding and never stops the check.
    pub fn load(
        integration: Option<&Path>,
        user: Option<&Path>,
        repo: Option<&Path>,
    ) -> (Config, Vec<Finding>) {
        let mut cfg = Config::default();
        let mut out = Vec::new();
        for (path, layer) in [
            (integration, Layer::Integration),
            (user, Layer::User),
            (repo, Layer::Repo),
        ] {
            let Some(path) = path else { continue };
            let Some(table) = read_layer(path, layer, &mut out) else {
                continue;
            };
            let dir = path.parent().unwrap_or(Path::new(""));
            match layer {
                Layer::Repo => cfg.apply_repo(&table, dir, &mut out),
                _ => cfg.apply_full(&table, dir, layer, &mut out),
            }
        }
        cfg.walk_budget_ms = cfg
            .walk_budget_ms
            .min(cfg.hook_timeout_ms.saturating_sub(HOOK_MARGIN_MS));
        (cfg, out)
    }

    /// `load` with the user file from the OS config dir and the repo file at the root of the
    /// repo holding `cwd`. Every caller (`check`, the hook adapters) loads the config this way.
    pub fn discover(integration: Option<&Path>, cwd: Option<&Path>) -> (Config, Vec<Finding>) {
        let user = user_file();
        let repo = cwd.and_then(repo_file);
        Config::load(integration, user.as_deref(), repo.as_deref())
    }

    /// The integration and user layers: every key, in either direction.
    fn apply_full(&mut self, t: &toml::Table, dir: &Path, layer: Layer, out: &mut Vec<Finding>) {
        for (key, value) in t {
            let result = match key.as_str() {
                "levels" => {
                    self.apply_levels(value, layer, out);
                    Ok(())
                }
                "ask_instead_of_deny" => strings(value).map(|v| self.ask_instead_of_deny = v),
                "dynamic_target" => level(value).map(|v| self.dynamic_target = v),
                "walk_budget_ms" => millis(value).map(|v| self.walk_budget_ms = v),
                "hook_timeout_ms" => match millis(value) {
                    Ok(v) if v < MIN_HOOK_TIMEOUT_MS => {
                        Err(format!("below the minimum {MIN_HOOK_TIMEOUT_MS}"))
                    }
                    other => other.map(|v| self.hook_timeout_ms = v),
                },
                "protected" => paths(value, dir).map(|v| self.protected = v),
                "gate_commands" => strings(value).map(|v| self.gate_commands = v),
                "bat_launchers" => strings(value).map(|v| self.bat_launchers = v),
                "scratch_dir" => value
                    .as_str()
                    .map(|s| self.scratch_dir = Some(dir.join(s)))
                    .ok_or_else(|| "expected a string".to_string()),
                "tool_paths" => {
                    self.apply_tool_paths(value, dir, layer, out);
                    Ok(())
                }
                "policies" => {
                    self.apply_policies(value, layer, out);
                    Ok(())
                }
                _ => Err("unknown key".to_string()),
            };
            if let Err(why) = result {
                out.push(invalid_key(layer, key, &why));
            }
        }
    }

    fn apply_levels(&mut self, value: &toml::Value, layer: Layer, out: &mut Vec<Finding>) {
        let Some(t) = value.as_table() else {
            out.push(invalid_key(layer, "levels", "expected a table"));
            return;
        };
        for (rule, v) in t {
            match level(v) {
                Ok(l) => {
                    self.levels.insert(rule.clone(), l);
                }
                Err(why) => out.push(invalid_key(layer, &format!("levels.{rule}"), &why)),
            }
        }
    }

    fn apply_tool_paths(
        &mut self,
        value: &toml::Value,
        dir: &Path,
        layer: Layer,
        out: &mut Vec<Finding>,
    ) {
        let Some(t) = value.as_table() else {
            out.push(invalid_key(layer, "tool_paths", "expected a table"));
            return;
        };
        for (tool, v) in t {
            match v.as_str() {
                Some(s) => {
                    self.tool_paths.insert(tool.clone(), dir.join(s));
                }
                None => out.push(invalid_key(
                    layer,
                    &format!("tool_paths.{tool}"),
                    "expected a string",
                )),
            }
        }
    }

    fn apply_policies(&mut self, value: &toml::Value, layer: Layer, out: &mut Vec<Finding>) {
        let Some(t) = value.as_table() else {
            out.push(invalid_key(layer, "policies", "expected a table"));
            return;
        };
        for (name, v) in t {
            let key = format!("policies.{name}");
            match (name.as_str(), v.as_bool()) {
                ("git_no_verify", Some(b)) => self.policies.git_no_verify = b,
                ("git_no_verify", None) => out.push(invalid_key(layer, &key, "expected a boolean")),
                _ => out.push(invalid_key(layer, &key, "unknown key")),
            }
        }
    }

    /// The repo layer: `levels` may only raise, `protected` may only add; anything else is
    /// ignored with a finding naming the key.
    fn apply_repo(&mut self, t: &toml::Table, dir: &Path, out: &mut Vec<Finding>) {
        for (key, value) in t {
            match key.as_str() {
                "levels" => self.apply_repo_levels(value, out),
                "protected" => match paths(value, dir) {
                    Ok(v) => self.protected.extend(v),
                    Err(why) => out.push(invalid_key(Layer::Repo, key, &why)),
                },
                _ => out.push(repo_ignored(
                    key,
                    "a repo file may only raise levels and add protected paths",
                )),
            }
        }
    }

    fn apply_repo_levels(&mut self, value: &toml::Value, out: &mut Vec<Finding>) {
        let Some(t) = value.as_table() else {
            out.push(invalid_key(Layer::Repo, "levels", "expected a table"));
            return;
        };
        for (rule, v) in t {
            let key = format!("levels.{rule}");
            let l = match level(v) {
                Ok(l) => l,
                Err(why) => {
                    out.push(invalid_key(Layer::Repo, &key, &why));
                    continue;
                }
            };
            // `ok` can only switch a rule off: no rule reports at `ok`.
            let lowers = l == Level::Ok || self.levels.get(rule).is_some_and(|&cur| l < cur);
            if lowers {
                out.push(repo_ignored(&key, "a repo file may only raise levels"));
                continue;
            }
            let floor = self.repo_floor.entry(rule.clone()).or_insert(l);
            *floor = (*floor).max(l);
        }
    }
}

/// `<OS config dir>/shellwise/config.toml`: `%APPDATA%` on Windows, `~/Library/Application
/// Support` on macOS, `$XDG_CONFIG_HOME` (else `~/.config`) elsewhere.
pub fn user_file() -> Option<PathBuf> {
    let env = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if cfg!(windows) {
        env("APPDATA")?
    } else if cfg!(target_os = "macos") {
        env("HOME")?.join("Library").join("Application Support")
    } else {
        match env("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
            Some(p) => p,
            None => env("HOME")?.join(".config"),
        }
    };
    Some(dir.join("shellwise").join("config.toml"))
}

/// `.shellwise.toml` at the root of the repo holding `cwd` (the nearest ancestor with a `.git`
/// folder or file); `None` outside a repo.
pub fn repo_file(cwd: &Path) -> Option<PathBuf> {
    let cwd = std::path::absolute(cwd).ok()?;
    cwd.ancestors()
        .find(|dir| dir.join(".git").symlink_metadata().is_ok())
        .map(|root| root.join(REPO_FILE))
}

/// Read and parse one layer; `None` (with a finding, except a missing user or repo file) when
/// it cannot be used.
fn read_layer(path: &Path, layer: Layer, out: &mut Vec<Finding>) -> Option<toml::Table> {
    // A repo could ship a FIFO, a device or a link there: reading it could block until the
    // deadline and fail the whole check closed, which only the raw scan survives.
    if matches!(layer, Layer::Repo) {
        match path.symlink_metadata() {
            Ok(m) if m.file_type().is_file() => {}
            Ok(_) => {
                out.push(invalid_layer(layer, path, "is not a regular file"));
                return None;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                out.push(invalid_layer(layer, path, &format!("cannot be read: {e}")));
                return None;
            }
        }
    }
    let text = match read_capped(path) {
        Ok(Some(text)) => text,
        Ok(None) => {
            let why = format!("is larger than {MAX_CONFIG_BYTES} bytes");
            out.push(invalid_layer(layer, path, &why));
            return None;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !matches!(layer, Layer::Integration) => {
            return None;
        }
        Err(e) => {
            out.push(invalid_layer(layer, path, &format!("cannot be read: {e}")));
            return None;
        }
    };
    match text.parse::<toml::Table>() {
        Ok(t) => Some(t),
        Err(e) => {
            let first = e.message().lines().next().unwrap_or("").to_string();
            out.push(invalid_layer(
                layer,
                path,
                &format!("is not valid TOML: {first}"),
            ));
            None
        }
    }
}

/// The file's text, or `None` when it is larger than `MAX_CONFIG_BYTES`.
fn read_capped(path: &Path) -> io::Result<Option<String>> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CONFIG_BYTES {
        return Ok(None);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}

fn level(v: &toml::Value) -> Result<Level, String> {
    let all = [
        Level::Ok,
        Level::Warn,
        Level::Break,
        Level::Danger,
        Level::Critical,
    ];
    let s = v.as_str().ok_or("expected a level name")?;
    all.into_iter()
        .find(|l| l.as_str() == s)
        .ok_or_else(|| format!("unknown level {s:?}"))
}

fn millis(v: &toml::Value) -> Result<u64, String> {
    v.as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| "expected a non-negative integer".to_string())
}

fn strings(v: &toml::Value) -> Result<Vec<String>, String> {
    let arr = v.as_array().ok_or("expected an array of strings")?;
    arr.iter()
        .map(|x| x.as_str().map(String::from))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "expected an array of strings".to_string())
}

fn paths(v: &toml::Value, dir: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(strings(v)?.into_iter().map(|s| dir.join(s)).collect())
}

fn warn(rule: &'static str, message: String) -> Finding {
    Finding {
        rule,
        level: Level::Warn,
        message,
        fix: None,
        span: Span::default(),
    }
}

fn invalid_layer(layer: Layer, path: &Path, why: &str) -> Finding {
    warn(
        CONFIG_INVALID,
        format!(
            "the {} config file {} {why}; the file is ignored",
            layer.name(),
            path.display()
        ),
    )
}

fn invalid_key(layer: Layer, key: &str, why: &str) -> Finding {
    warn(
        CONFIG_INVALID,
        format!(
            "{} config key `{key}`: {why}; the key is ignored",
            layer.name()
        ),
    )
}

fn repo_ignored(key: &str, why: &str) -> Finding {
    warn(
        CONFIG_REPO_IGNORED,
        format!("repo config key `{key}` is ignored: {why}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of this test's own under the temp dir, holding `name` with `text`.
    fn file(tag: &str, name: &str, text: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("shellwise-config-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn scratch_dir_is_read_from_the_user_file_relative_to_it() {
        let user = file("scratch-user", "config.toml", "scratch_dir = 'work'\n");
        let (cfg, out) = Config::load(None, Some(&user), None);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(cfg.scratch_dir, Some(user.parent().unwrap().join("work")));

        let bad = file("scratch-bad", "config.toml", "scratch_dir = 1\n");
        let (cfg, out) = Config::load(None, Some(&bad), None);
        assert_eq!(cfg.scratch_dir, None);
        assert!(out.iter().any(|f| f.rule == CONFIG_INVALID), "{out:?}");
    }

    #[test]
    fn a_repo_file_cannot_set_scratch_dir() {
        let repo = file("scratch-repo", REPO_FILE, "scratch_dir = 'work'\n");
        let (cfg, out) = Config::load(None, None, Some(&repo));
        assert_eq!(cfg.scratch_dir, None);
        assert!(out.iter().any(|f| f.rule == CONFIG_REPO_IGNORED), "{out:?}");
    }
}
