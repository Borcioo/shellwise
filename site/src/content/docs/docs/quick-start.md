---
title: Quick start
description: Check a command by hand, read a finding, confirm a delete, then wire up your agent.
---

This page assumes the binary is on your `PATH`. If it is not, see
[Install](/shellwise/docs/install/).

## Check one command

Pass the shell with `--shell` (`pwsh`, `powershell5`, `bash` or `gitbash`) and the command after
`--`, in single quotes:

```text
$ shellwise check --shell pwsh -- 'Write-Output "$name: done"'
break ps-var-colon [14..20]: in a double-quoted string PowerShell reads $name: as a variable on a drive called name, and refuses the whole command
  Fix: write "${name}:" instead of "$name:"
```

Without `--`, `check` reads the command from stdin. In PowerShell:

```powershell
'Write-Output "$name: done"' | shellwise check --shell pwsh
```

A command with nothing to report prints `ok`:

```text
$ shellwise check --shell bash -- 'git status'
ok
```

`--cwd DIR` names the folder the command runs in; give its full path. The delete rules use it to
tell a folder inside the project from one outside it.

## Read a finding

```text
warn follow-unbounded [0..15]: `tail` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout
  Fix: timeout 60 tail -f app.log
```

| Part | Here | Meaning |
|---|---|---|
| Level | `warn` | `ok`, `warn`, `break`, `danger` or `critical` |
| Rule id | `follow-unbounded` | The rule that fired; `shellwise explain <id>` documents it |
| Span | `[0..15]` | Byte offsets of the part of the command the finding is about (end not included) |
| Message | after the `:` | What is wrong and why |
| Fix line | `Fix: …` | A corrected command, or a sentence when no command fits |

A finding may have no Fix line. `--json` prints the same verdict as one JSON object:

```text
$ shellwise check --shell bash --json -- 'tail -f app.log'
{"version":1,"level":"warn","findings":[{"rule":"follow-unbounded","level":"warn","message":"`tail` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout","fix":"timeout 60 tail -f app.log","span":{"start":0,"end":15}}]}
```

Exit codes: 0 ok or warn, 1 break, 2 danger, 3 critical, 64 usage error, 74 stdin could not be
read. The full list and the JSON shape are in
[Exit codes and JSON](/shellwise/docs/reference/exit-codes-and-json/).

## Confirm a delete with the allow marker

A `danger` command runs when it is repeated with ` # shellwise: allow` at its very end:

```text
$ shellwise check --shell bash -- 'rm -rf "$DIR/"'
danger delete-empty-expansion [0..14]: if the variable or substitution in `"$DIR/"` is empty, this deletes `/`, the file-system root
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
$ shellwise check --shell bash -- 'rm -rf "$DIR/" # shellwise: allow'
ok delete-empty-expansion [0..14]: if the variable or substitution in `"$DIR/"` is empty, this deletes `/`, the file-system root (confirmed by the trailing allow marker)
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
```

The marker has no effect on `critical`:

```text
$ shellwise check --shell pwsh -- 'Remove-Item -Recurse -Force C:\Windows\Temp\.. # shellwise: allow'
critical delete-critical [0..47]: deleting `C:\Windows\Temp\..` is blocked: it is the system folder, and the allow marker cannot confirm it
  Fix: do not delete in a system folder; if it must go, ask the user to run the command themselves
```

What counts as the marker:

- It must be a real trailing comment at the very end of the command. The same text inside a
  string or a heredoc is not a comment.
- It turns `danger` and `break` findings into `ok`. It never changes `critical`, and it has no
  effect on `parse-error`, `parse-error-destructive`, `too-long`, `inline-script-too-long` and
  `analysis-incomplete`.

Add the marker only after reading the finding, never by habit.

## Explain a rule

`shellwise explain <id>` prints the rule's page, the same text as under
[Rules](/shellwise/docs/rules/). The start of one:

```text
$ shellwise explain ps-var-colon
# ps-var-colon

In a PowerShell double-quoted string, `$name:` is read as a variable on a drive or scope named
`name` (`$env:TEMP`, `$script:x`). When the colon is not followed by a name, PowerShell refuses the
whole string (`InvalidVariableReferenceWithDrive`) and runs nothing.
```

An unknown id exits 64 with `shellwise: no rule "<id>"`. See
[`explain`](/shellwise/docs/commands/explain/).

## Lint a script

`shellwise lint FILE` checks a `.ps1`, `.sh` or `.bash` file. A Bash file also gets ShellCheck's
checks (ids like `SC2115`), built into the binary. For a `clean.sh` that holds:

```sh
set -eu
rm -rf "$OUT/"
```

```text
$ shellwise lint clean.sh
clean.sh:2:1: danger delete-empty-expansion: if the variable or substitution in `"$OUT/"` is empty, this deletes `/`, the file-system root
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
clean.sh:2:8: warn SC2115: Use "${var:?}" to ensure this never expands to / .
```

`lint` exits 0 for clean or warn, 1 for break or worse, 64 when it refuses the file (another
extension) and 74 when it cannot read it. See [`lint`](/shellwise/docs/commands/lint/).

## Wire it into your agent

- [Claude Code](/shellwise/docs/agents/claude-code/): install the plugin, or add the hook entry
  by hand.
- [Codex CLI](/shellwise/docs/agents/codex/): a `PreToolUse` entry in `hooks.json`.
- [Other hosts](/shellwise/docs/agents/other/): run `shellwise agent-setup` and paste the output
  to your agent.

To switch shellwise off without removing the hook, set `SHELLWISE=off`.
