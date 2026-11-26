---
title: Codex CLI
description: Register shellwise as a PreToolUse hook in Codex CLI, approve it, and prove it blocks.
---

Codex CLI runs shellwise through `shellwise hook generic`, which blocks a command with exit code 2.
It has been tested live on Windows with PowerShell 7 only. On macOS and Linux the steps below come
from the host's documentation.

## Before you start

- [Install the binary](/shellwise/docs/install/) and find its full path: `command -v shellwise`,
  or `(Get-Command shellwise).Source` in PowerShell. Use the full path in the entry, never a bare
  `shellwise`.
- Back up the config file before you edit it, for example as `hooks.json.shellwise-backup`.

## The entry

| Setting | Value |
|---|---|
| Config file | `.codex/hooks.json` in your home folder (`%USERPROFILE%` on Windows) |
| Event | `PreToolUse` |
| Matcher | `^Bash$` |
| Handler | `{"type": "command", "command": "<entry>", "timeout": 10}` |
| Timeout | `timeout`, in seconds: 10 or more |

The handler goes in a `PreToolUse` group with the matcher. Merge it into the existing file; do
not replace the file.

Codex names its shell tool `Bash` on every system, also when it runs PowerShell on Windows. So the
event does not tell shellwise the shell: pass `--shell` to match what the shell tool runs (`pwsh`,
`powershell5`, `bash` or `gitbash`).

### Windows

On Windows Codex runs the entry through PowerShell. A bare command there exits 1 instead of 2,
and Codex lets the command run. Use the `guard-pwsh` line as `<entry>`:

```powershell
$p = 'C:\full\path\to\shellwise.exe'; if (Test-Path -LiteralPath $p -PathType Leaf) { & $p hook generic --shell pwsh; if ($LASTEXITCODE -eq 2) { exit 2 } }; exit 0
```

It runs the hook, passes exit code 2 and its stderr through, and turns a missing binary and every
other exit code into 0. Replace the path, and the `--shell` value when your shell tool runs
another shell. Keep the line as written: the event must reach shellwise on its inherited stdin.

In `hooks.json`, escape each `\` as `\\`. The handler then reads:

```json
{"type": "command", "command": "$p = 'C:\\full\\path\\to\\shellwise.exe'; if (Test-Path -LiteralPath $p -PathType Leaf) { & $p hook generic --shell pwsh; if ($LASTEXITCODE -eq 2) { exit 2 } }; exit 0", "timeout": 10}
```

### macOS and Linux

Use the bare command with the path quoted:

```sh
'/full/path/to/shellwise' hook generic --shell bash
```

This form has not been run on Codex.

## Approve the hook

Codex runs a hook only after you approve it, and again after every change to the entry. Approve
it in the host's hook settings (`/hooks` in the CLI). An unapproved hook is skipped without a
message, so nothing is checked and the proof below cannot pass.

## Prove it

Do these in order, so nothing runs unguarded before the hook is known to work.

1. Check the proof command by hand. Its output must start with `break` and exit 1:

   ```text
   PS> 'Write-Output "$name: done"' | shellwise check --shell pwsh
   break ps-var-colon [14..20]: in a double-quoted string PowerShell reads $name: as a variable on a drive called name, and refuses the whole command
     Fix: write "${name}:" instead of "$name:"
   ```

2. Ask Codex to run `Write-Output "$name: done"`. It is blocked when the command does not run and
   the host's message contains `shellwise: break` or says a hook blocked the command. If
   PowerShell's own parser error appears as the command's output, the hook is not wired: fix the
   entry and repeat.
3. Ask Codex to run `Write-Output shellwise-proof-ok`. It must run and print its text. If it is
   blocked, your shell tool no longer works: restore the backup.

On macOS and Linux use `echo 'abc` as the proof command (`--shell bash`) and
`echo shellwise-proof-ok` as the harmless one.

## What the agent sees

On a block, the findings and their `Fix:` lines go to stderr, and Codex shows them to the model.
A `warn` note also goes to stderr, with exit 0. A usage error or an internal failure exits 0, so
a broken entry never blocks your shell tool. The contract is on
[`hook`](/shellwise/docs/commands/hook/).

## Switch off and undo

- Switch off without removing the entry: set `SHELLWISE=off` in the host's environment.
- Undo: remove the entry and restore the backup, or delete the file if you created it.
