---
title: Other hosts
description: Let your agent wire shellwise into its host, the generic hook, and the known hosts.
---

For a host other than Claude Code, the agent can do the wiring itself. shellwise has been tested
live on Claude Code and Codex CLI only (Codex on Windows with PowerShell 7). Every other host
below is described from its own documentation and has not been run.

## The agent-setup flow

Run:

```sh
shellwise agent-setup
```

It prints the setup text built into the binary, so the text matches your version and works
offline. Paste the output to your agent. The full text is also on
[Setup text](/shellwise/docs/agents/setup-text/).

The agent then:

1. Finds its host's hook that runs before a shell command, at user level, in the hosts table or
   in the host's documentation. If there is none, it tells you so and stops.
2. Finds the full path of the binary and uses it in the entry, never a bare `shellwise`.
3. Finds out which shell its shell tool runs, which decides `--shell`.
4. Backs up the config file next to itself, with `.shellwise-backup` appended to its name, never
   over an existing backup. If the file does not exist, it notes that; the undo is then deleting
   it.
5. Merges one entry into the file, registered for the shell tool only. Where the host runs the
   entry through PowerShell, or the table says "guard line", it uses a guard line.
6. Sets the hook timeout to 10 seconds or more, in the host's own unit.
7. Runs the proof and reports to you what it changed and what the host showed.

The proof runs in this order, so nothing runs unguarded before the hook is known to work:

1. `shellwise check` on a proof command with a syntax error must print `break` and exit 1.
2. The same proof command through the shell tool must be blocked, with `shellwise: break` in the
   host's message. If the shell's own syntax error appears instead, the hook is not wired.
3. A harmless command (`echo shellwise-proof-ok`) must run. If it is blocked, the agent undoes
   the change.

Undo: remove the entry and restore the backup, or delete the file if the agent created it. To
switch shellwise off without removing the entry, set `SHELLWISE=off` in the host's environment.

Some hosts need an extra step from you, such as approving the hook in Codex CLI. The agent tells
you; the proof cannot pass before that.

## The generic hook

`shellwise hook generic [--shell pwsh|powershell5|bash|gitbash]` serves hosts that block a
command on exit code 2.

- It reads the host's hook event (JSON) on stdin and finds the command in it.
- It exits 0 to let the command run; a `warn` note goes to stderr.
- It exits 2 to block it, with the findings and their `Fix:` lines on stderr.
- A usage error or an internal failure exits 0, so a broken entry never blocks your shell tool.
- Without `--shell`, a tool name of `PowerShell` in the event means `pwsh`; otherwise it is `pwsh`
  on Windows and `bash` elsewhere. On Windows always pass `--shell`: several hosts name their
  shell tool "Bash" even when it runs PowerShell.

```text
$ printf '%s' '{"tool_name":"Bash","tool_input":{"command":"echo '"'"'abc"}}' | shellwise hook generic --shell bash
shellwise: break parse-error: bash: unterminated single quote at 1,6: the ' opened at column 6 is never closed, so the shell refuses the whole command and runs none of it
Fix: close the ' opened at column 6, or write the text to a file and pass the file
```

The exit code of that run is 2. More on [`hook`](/shellwise/docs/commands/hook/).

## Guard lines

Some hosts block the command when the hook program is missing or exits with any code other than
0. On a host that runs the entry through PowerShell, a bare command exits 1 instead of 2, and the
host lets the command run. On those hosts the entry is a guard line instead of the bare
command: it runs the
hook, passes exit code 2 and its stderr through, and turns a missing binary and every other exit
code into 0.

There are two: `guard-sh` for a host that runs the entry with `sh` or `bash`, and `guard-pwsh` for
one that runs it with PowerShell (7 or 5.1). Both are on
[Setup text](/shellwise/docs/agents/setup-text/), under "The guard line".

## Hosts

Each row is marked `tested` (run live) or `from the host's documentation` (not run by us).
"Reason shown" says whether the host is documented to show the block reason (stderr) to the model.
Paths start at the user's home folder (`%USERPROFILE%` on Windows) unless they say otherwise.

| Host | Mark | Config file | Event | Matcher | Timeout | Entry | Reason shown |
|---|---|---|---|---|---|---|---|
| Claude Code | tested | `.claude/settings.json` | `PreToolUse` | `Bash` or `PowerShell` (one regex, below) | `timeout`, seconds | `hook claude-code` (below), or the shellwise plugin | yes |
| Codex CLI | tested on Windows (PowerShell 7) | `.codex/hooks.json` | `PreToolUse` | `^Bash$` | `timeout`, seconds | bare command; `guard-pwsh` line on Windows | yes |
| Cursor | from the host's documentation | `.cursor/hooks.json` | `beforeShellExecution` | none | `timeout`, seconds | bare command; `guard-pwsh` line on Windows | not documented |
| Gemini CLI | from the host's documentation | `.gemini/settings.json` | `BeforeTool` | `run_shell_command` | `timeout`, milliseconds | `guard-sh` line on macOS and Linux; `guard-pwsh` line on Windows | yes |
| Copilot CLI | from the host's documentation | own file `.copilot/hooks/shellwise.json` | `preToolUse` | `bash` or `powershell` (one regex, below) | `timeoutSec`, seconds | guard line | not documented |
| Devin | from the host's documentation | `.config/devin/config.json` (`%APPDATA%\devin\config.json` on Windows) | `PreToolUse` | `exec` | `timeout`, seconds | bare command | not documented |

"Below" in the table refers to the notes per host in the setup text. In short:

- Claude Code: see [Claude Code](/shellwise/docs/agents/claude-code/). With the plugin installed,
  add nothing.
- Codex CLI: see [Codex CLI](/shellwise/docs/agents/codex/).
- Cursor: it already runs a Claude Code hook found in `.claude/settings.json`; if one for
  shellwise is there, add nothing. Give no matcher: here it filters the command text.
- Gemini CLI: the timeout is in milliseconds (`10000`).
- Copilot CLI: it blocks when the hook program fails, so always use the guard lines; the matcher
  is `bash|powershell`.
- Devin: a `PreToolUse` group with the matcher `exec`.

The exact entry for each host is in the [setup text](/shellwise/docs/agents/setup-text/).

## Hosts with no hook

A host that has no hook running before a shell command cannot be guarded by shellwise. You can
still run `shellwise check` by hand on a command before you run it; see
[Quick start](/shellwise/docs/quick-start/).
