---
title: Limits
description: What shellwise is not, how it fails closed, what it does not catch yet, and what has not been tested.
---

shellwise guards against the careless mistakes of an agent that means well. It is not a security
boundary: a command written to get around it can get past it. It is not a permission system: it
does not decide which tools an agent may use. It is not a replacement for backups, version
control or reading the diff.

## When the analysis cannot finish

The analysis may not finish: the deadline passes, the command is over 64 KiB, it is not valid
UTF-8, the config did not load, or an internal error occurs. shellwise then fails closed with an
`analysis-incomplete` finding, decided by a scan of the raw text:

| Case | Level |
|---|---|
| The raw text names a destructive command (a delete, a discard) | `danger` |
| The raw text names none, or the scan does not finish | `warn` |
| Input over 1 MiB, or stdin still open at the deadline | `danger`, unread, in `check` and `hook claude-code`; `hook generic` scans the bytes it read and blocks only when they name a destructive command |
| A hook event that is not valid JSON, and the scan does not finish | `danger` |

The allow marker has no effect on these findings. See the
[analysis-incomplete](/shellwise/docs/rules/analysis-incomplete/) rule.

A hook event that is not valid JSON shows no command: `hook claude-code` denies only when the raw
text holds a destructive command or the scan gives no answer, and prints nothing otherwise.
`hook generic` blocks in the same cases and otherwise lets the command run with a line on stderr.

`hook generic` never blocks because of its own failure: a usage error or an internal error exits
0. Wrap it in a guard line where a host blocks on a missing program; see
[Setup text](/shellwise/docs/agents/setup-text/).

## Known limits

- Interactive programs (an editor, `git rebase -i`) are not flagged yet.
- Bash arithmetic: a `$(…)` written in single quotes inside `(( ))`, `$(( ))` or `$[ ]` is not
  read, nor one that only a variable's value carries into an array subscript
  (`x='a[$(cmd)]'; (( x ))`). One written in a static subscript that bash evaluates
  (`let 'a[$(cmd)]'`, `declare -i n; n='a[$(cmd)]'`) is read when the integer name is declared
  earlier in the text than the assignment.
- `CDPATH` set by a shell profile the hook cannot see is not modelled.
- `check` without `--cwd` does not resolve relative paths in a delete; it warns that it cannot
  tell the folder.
- `lint` does not resolve environment variables in a script.
- The `dynamic_target` config key has no effect; set `levels.dynamic-target` instead.

## Speed

Measured on one Windows 11 developer machine:

| What | Result |
|---|---|
| Whole hook call, process start included | median 15 ms, 99th percentile 22 ms |
| Analysis alone, inside the process | median 0.3 ms (Bash), 0.6 ms (PowerShell); 99th percentile under 6 ms |

Known gap: `lint` on a whole script is slower than its target of 50 ms per 500 lines.

## Untested platforms and hosts

| Platform | What has run on it |
|---|---|
| Windows x64 | the full test suite in CI |
| Linux x64 (`x86_64-unknown-linux-gnu`) | the full test suite in CI |
| Linux x64 static (`x86_64-unknown-linux-musl`, what `install.sh` installs) | CI builds on `main` and manual runs: `--version` and one `check` proof command |
| Linux arm64 (static) | CI builds on `main` and manual runs: `--version` and one `check` proof command; nobody has run it beyond that |
| macOS (Apple silicon, Intel) | CI runs a debug build only in the install-script and `shellwise update` tests; the release binaries are never run, in CI or anywhere else |

| Host | Status |
|---|---|
| Claude Code | tested live |
| Codex CLI | tested live, on Windows with PowerShell 7 |
| Cursor, Gemini CLI, Copilot CLI, Devin | described from their documentation, not run |

## Reporting a wrong verdict

A good command that was blocked and a careless destructive command that passed are both ordinary
bugs. Open a public issue from the
[issue chooser](https://github.com/Borcioo/shellwise/issues/new/choose) with:

- the command, exactly as the agent wrote it (remove anything private first);
- the shell (`bash`, `gitbash`, `pwsh`, `powershell5`) and the operating system;
- what shellwise answered: `shellwise check --shell <shell> -- '<command>'`;
- what really happens when the command runs.

Report privately, through GitHub's private vulnerability reporting on the repository (Security,
then Report a vulnerability), when shellwise itself does harm (writes or deletes files, runs the
command it checks, sends data anywhere), when a crash or hang of the hook lets every later command
through unchecked, or for a problem in a release binary or the release workflow. Include
`shellwise --version`, the operating system and the steps to reproduce.

## FAQ

### Does shellwise send my commands anywhere?

No. Checking needs no service and no network. Only `shellwise update` reaches the network.

### Will it block a command it does not know?

No. An unknown command is never blocked for being unknown.

### How do I run a `danger` command on purpose?

Repeat it with ` # shellwise: allow` at its end. `critical` commands never run through the hook;
run them yourself.

### How do I switch it off for a while?

Set `SHELLWISE=off` in the environment the host runs the hook in.

### Can a repo I clone make shellwise weaker?

No. Its `.shellwise.toml` can only raise levels and add protected paths; see
[Configuration](/shellwise/docs/configuration/).

### Why did my hook deny a command with `analysis-incomplete`?

The analysis hit its deadline, or the event could not be read, and the raw text holds a
destructive command. Set `hook_timeout_ms` to the host's hook timeout; see
[shellwise hook](/shellwise/docs/commands/hook/).
