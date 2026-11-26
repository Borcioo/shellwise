---
title: Configuration
description: The user config file, the repo file .shellwise.toml, the --config option and the environment variables shellwise reads.
---

shellwise works without any config. A config file is TOML, at most 64 KiB, UTF-8.

## Layers

| Layer | Where | May set |
|---|---|---|
| integration | the file given with `--config FILE` (`check`, `lint`, both hooks) | every key |
| user | the user config file below | every key; overrides the integration file |
| repo | `.shellwise.toml` at the root of the repo | raise `levels`, add `protected` paths |

The layers are read in this order. A missing user or repo file is silent; a missing `--config`
file is a `config-invalid` warning. Relative paths in a file are read from that file's folder.

## The user config file

| System | Path |
|---|---|
| Windows | `%APPDATA%\shellwise\config.toml` |
| macOS | `~/Library/Application Support/shellwise/config.toml` |
| Linux and others | `$XDG_CONFIG_HOME/shellwise/config.toml` (absolute values only), else `~/.config/shellwise/config.toml` |

## Keys

| Key | Type | Default | Effect |
|---|---|---|---|
| `levels.<rule-id>` | level name | the rule's own level | Sets the level of the rule's findings. `<rule-id>` is a [rule](/shellwise/docs/rules/) id or a ShellCheck code such as `SC2086`. |
| `ask_instead_of_deny` | array of rule ids | `[]` | `hook claude-code` answers `ask` instead of `deny` when every finding at `break` or above is a `danger` of a listed rule. No effect elsewhere. |
| `dynamic_target` | level name | `"danger"` | Accepted, but has no effect in this version. Use `levels.dynamic-target` instead. |
| `walk_budget_ms` | non-negative integer | `8000` | Upper bound for the whole analysis, folder walks included. Capped at `hook_timeout_ms - 1500`. |
| `hook_timeout_ms` | integer, at least `3000` | `10000` | The host's hook timeout. The analysis ends 1500 ms before it. |
| `protected` | array of paths | `[]` | Paths the delete guard treats like a repo root. |
| `allowed_roots` | array of paths | the system temp folder | Folders a delete may clear freely; deleting one itself is a `warn` (`delete-allowed-root`). Setting it replaces the default. |
| `scratch_dir` | path | none | Where the `too-long` Fix line says to write the command; also an allowed root. Without it, `shellwise-<user>` in the temp folder. |
| `gate_commands` | array of names | `[]` | Commands whose output must not be cut by a pipe into `head` or `Select-Object -First` (`gate-truncated-pipeline`). `*` matches any run of characters. |
| `bat_launchers` | array of names | see below | Windows `.bat` launcher names for `bat-metachar`. `*` matches any run of characters. Setting it replaces the default. |
| `tool_paths.<tool>` | path | none | A tool's full path, named in the Fix lines of `bash-versioned-php` and `bat-metachar`. |
| `policies.git_no_verify` | boolean | `false` | Turns on the `git-no-verify` rule. |
| `limits.git_bash_command` | positive integer | `7500` | The escaped length from which `too-long` denies a Git Bash command line. |

A level name is `"ok"`, `"warn"`, `"break"`, `"danger"` or `"critical"`. A rule set to `"ok"`
still prints its findings in `check`, at `ok`, and never blocks or warns.

The default `bat_launchers`:

```toml
bat_launchers = ["php", "php8[0-9]", "composer", "wp", "phpcs", "phpcbf", "phpstan", 'vendor\bin\*']
```

An example user file:

```toml
hook_timeout_ms = 5000
ask_instead_of_deny = ["delete-empty-expansion"]
protected = ["C:/Users/me/notes"]

[levels]
follow-unbounded = "break"

[policies]
git_no_verify = true
```

## The repo file

`.shellwise.toml` is read from the root of the repo that holds the working directory: the
nearest folder upward with a `.git` folder or file. The working directory is the event's `cwd`
for the hooks, `--cwd` (else the current directory) for `check`, and the current directory for
`lint`. It is not looked for outside a repo or on a network share or device path. When it is not
a regular file (a link, for example), it is ignored with a `config-invalid` warning.

It may set only:

| Key | Rule |
|---|---|
| `levels.<rule-id>` | Only raises. A level below the user or integration setting, or `"ok"`, is ignored with a warning. A level below the rule's default has no effect. |
| `protected` | Adds to the list; it never removes a path. |

Every other key is ignored with a `config-repo-ignored` warning. A cloned repo therefore cannot
weaken the guard.

## Config warnings

Config problems never stop a check. Each is a `warn` finding with span `[0..0]`:

| Finding | Meaning |
|---|---|
| `config-invalid` | A file that cannot be read, is over 64 KiB or is not valid TOML (the file is ignored), or a key that is unknown, has the wrong type or names no rule (the key is ignored). |
| `config-repo-ignored` | A repo-file key it may not set, or a level it would lower. |

These two ids have no rule page; `shellwise explain` does not know them. Example:

```text
warn config-invalid [0..0]: integration config key `hook_timeout_ms`: below the minimum 3000; the key is ignored
warn config-invalid [0..0]: integration config key `levels.parse_error`: no rule has this id; the key is ignored
warn config-repo-ignored [0..0]: repo config key `scratch_dir` is ignored: a repo file may only raise levels and add protected paths
```

When the config does not load within 1 second, `check` and the hooks use the defaults and the
analysis is incomplete (`analysis-incomplete`); `lint` exits 74.

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `SHELLWISE` | every command that analyses | `off` turns shellwise off: the hooks exit 0 with no output, `check` reports no findings (config warnings still print), `lint` runs only ShellCheck. Any other value leaves it on. |
| `SHELLWISE_VERSION` | `update`, install scripts | The version to install instead of the latest. |
| `SHELLWISE_INSTALL_DIR` | install scripts | The install folder. `update` always sets it to the binary's own folder. |
| `SHELLWISE_BASE_URL` | install scripts, passed on by `update` | The release URL, or a local folder with the same layout. |
| `APPDATA` (Windows), `HOME`, `XDG_CONFIG_HOME` | config | The user config file location. |
| `HOME` (`USERPROFILE` on Windows), `TEMP`, `TMP` | analysis | Resolved where a command uses them, so the guard can read paths such as `~/x` or `$env:TEMP\x`. |
| `CDPATH` | analysis (bash) | When set, a relative `cd` counts as one bash may resolve elsewhere; its value is not read. |
| `USERNAME`, `USER` | `too-long` | The `<user>` in the default scratch folder. |
| `TEMP`, `TMP` (Windows), `TMPDIR` (elsewhere) | config | The system temp folder: the default `allowed_roots` and the default scratch folder. |
| `SystemRoot` | `update` (Windows) | Where `taskkill.exe` is found to stop a script that ran past its time bound. |

On a Windows launcher check (`bat-metachar`), a `%NAME%` in the command is read from the
environment shellwise runs in.
