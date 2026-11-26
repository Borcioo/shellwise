---
title: Claude Code
description: The shellwise plugin for Claude Code, the manual hook entry, the timeout, switching off.
---

Claude Code is one of the two hosts tested live with shellwise. You can wire it in two ways: the
plugin, or a hook entry you add to your settings by hand. Use one of them, not both.

## The plugin

The plugin ships no binary: it runs the `shellwise` found on `PATH`. Without it the hook fails and
every command runs unchecked, so [install the binary](/shellwise/docs/install/) first and check
that `shellwise --version` runs in a new terminal.

Then add the marketplace and install the plugin, from your shell:

```sh
claude plugin marketplace add Borcioo/shellwise
claude plugin install shellwise@shellwise
```

or inside a Claude Code session: `/plugin marketplace add Borcioo/shellwise`, then
`/plugin install shellwise@shellwise`.

The plugin registers two hooks:

| Event | Matcher | Runs | Timeout |
|---|---|---|---|
| `PreToolUse` | `Bash\|PowerShell` | `shellwise hook claude-code` | 10 s |
| `SessionStart` | none | `shellwise update --notify` | 5 s |

If your `PATH` contains `.` or another relative entry, a file named `shellwise` in a project
folder can run instead of the installed one. Remove such entries.

:::caution
Enable only one plugin that registers this hook, or every command is checked twice.
:::

### The update notice

At session start, `shellwise update --notify` checks for a newer release at most once a day. When
one exists, it prints one line of the form `shellwise <latest> is available (installed
<current>): run shellwise update`, which the session receives, so the agent can tell you.
It returns within 3 seconds, writes nothing to stderr and always exits 0. It records the time of
the check in an `update-check` file next to your user config file. The binary never updates
itself: run `shellwise update` when you choose. The marketplace keeps the plugin's own files
current.

## What the agent sees

`hook claude-code` reads the `PreToolUse` event on stdin and always exits 0. Its reply is one JSON
line on stdout. A `Bash` tool command is read as Git Bash on Windows and as bash elsewhere; a
`PowerShell` tool command as PowerShell 7. Other tools are ignored.

- `ok`: no output; the command runs.
- `warn`: the findings go to the model as context; the command runs.
- `break`, `danger`, `critical`: a deny, with the findings and their `Fix:` lines as the reason.

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"shellwise: danger delete-empty-expansion: if the variable or substitution in `\"$DIR/\"` is empty, this deletes `/`, the file-system root\nFix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf \"${X:?}/build\"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end"}}
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"shellwise: warn follow-unbounded: `tail` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout\nFix: timeout 60 tail -f app.log"}}
```

A config can turn the deny of chosen `danger` rules into an ask; see
[Configuration](/shellwise/docs/configuration/).

## The manual hook entry

Without the plugin, add a `PreToolUse` hook to your user `settings.json`
(`~/.claude/settings.json`), with the full path of the binary. Find it with `command -v shellwise`,
or `(Get-Command shellwise).Source` in PowerShell.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          { "type": "command", "command": "/full/path/to/shellwise", "args": ["hook", "claude-code"], "timeout": 5 }
        ]
      }
    ]
  }
}
```

Merge the entry into your existing file; do not replace the file. In JSON, write each `\` in a
Windows path as `\\`.

## Hook timeout

shellwise ends its analysis by itself before the host stops waiting. The analysis gets
`walk_budget_ms` (8000 by default) or `hook_timeout_ms` minus 1500 ms, whichever is shorter.
`hook_timeout_ms` is 10000 by default, which fits the plugin's 10 second timeout.

When you give the hook a shorter timeout, as the 5 seconds above, give shellwise the same limit in
`<config dir>/shellwise/config.toml` (`%APPDATA%` on Windows, `~/Library/Application Support` on
macOS, `$XDG_CONFIG_HOME` or `~/.config` elsewhere):

```toml
hook_timeout_ms = 5000
```

The analysis then ends after 3.5 seconds, and shellwise answers before the host gives up. The
smallest value is 3000; a smaller one is ignored with a `config-invalid` warning. The plugin keeps
the default because it cannot write your config file. All keys are on
[Configuration](/shellwise/docs/configuration/).

## Switch off

- For one session: start Claude Code with `SHELLWISE=off` in its environment. The hook then lets
  every command through.
- For good, with the plugin: `claude plugin disable shellwise@shellwise`, or
  `/plugin disable shellwise@shellwise` in a session.
- For good, with the manual entry: remove the entry from `settings.json`.

To check by hand what the hook would say, see [Quick start](/shellwise/docs/quick-start/) and
[`hook`](/shellwise/docs/commands/hook/).
