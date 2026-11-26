# Wire shellwise into your agent host

You are the AI coding agent reading this. Follow these steps to make your host run shellwise
before every shell command you run. Report to the user what you changed and what the proof showed.

## What shellwise is

shellwise reads a Bash or PowerShell command before the shell runs it and stops the careless ones:
a command that will not run, one that will hang, one that deletes the wrong thing. Each finding
carries a `Fix:` line. It guards against mistakes; it is not a security boundary.

## The contract

- `shellwise hook generic --shell <shell>` reads the host's hook event (JSON) on stdin. It exits 0
  to let the command run (a `warn` note may be on stderr) and exits with exit code 2 to block it,
  with the findings and their `Fix:` lines on stderr. A usage error or an internal failure exits 0,
  so a broken entry never blocks your shell tool.
- `--shell` is `pwsh`, `powershell5`, `bash` or `gitbash`: the shell your shell tool runs. On
  Windows ALWAYS pass it. Several hosts name their shell tool "Bash" even when it runs PowerShell,
  and without the flag a command is read as PowerShell on Windows and as bash elsewhere. Use
  `gitbash` for Git Bash on Windows, `powershell5` for Windows PowerShell 5.1.
- `shellwise check --shell <shell> [--json] [-- COMMAND]` checks one command by hand; without
  `-- COMMAND` it reads the command from stdin. Exit codes: 0 ok or warn, 1 break, 2 danger,
  3 critical, 64 usage error. `--json` prints the verdict as JSON.
- `SHELLWISE=off` in the environment switches shellwise off without removing the hook.
- A `danger` command runs when repeated with ` # shellwise: allow` at its end; `critical` never
  runs. Add the marker only after reading the finding, never by habit.
- `shellwise update` installs the latest release.

## The steps

1. Find your host's hook that runs before a shell command, at user level (the table below). If
   your host is not in the table, look for the same thing in its documentation. If it has none,
   go to "No hook on this host".
2. Find the full path of the binary (`command -v shellwise`, or `(Get-Command shellwise).Source`
   in PowerShell). Use that full path in the entry, never a bare `shellwise`.
3. Find out which shell your shell tool runs. That decides `--shell`.
4. Before editing, back up the config file: copy it next to itself with `.shellwise-backup`
   appended to its name. If the file does not exist, note that; the undo is then deleting it.
5. Add one entry, keeping everything already in the file. Register it for your host's shell tool
   only, never for every tool. Where the host offers a form that spawns the program directly
   (a command plus a list of arguments), use it. Where the host runs the entry through `sh` or
   `bash`, quote the path: `'/full/path/to/shellwise' hook generic --shell bash`. Where the host
   runs the entry through PowerShell, always use the `guard-pwsh` line below: a bare command there
   exits 1 instead of 2, and the host lets the command run. Where the table says "guard line",
   use the guard line. In a JSON file, escape each `\` and `"`. Below, `"<entry>"` stands for
   this command or guard line.
6. Set the hook timeout to 10 seconds or more, in the host's own unit. shellwise ends its analysis
   by itself after 8.5 seconds, so the host never has to cut it off.
7. Run the proof.

## The guard line

Some hosts block the command when the hook program is missing or exits with any code other than
0. On those, and on every host that runs the entry through PowerShell, register this line instead
of the bare command. It runs the hook, passes exit code 2
and its stderr through, and turns a missing binary and every other exit code into 0. Replace the
path, and replace the `--shell` value when your shell tool runs another shell.

For a host that runs the entry with `sh` or `bash`:

```guard-sh
p='/full/path/to/shellwise'; if [ -x "$p" ]; then "$p" hook generic --shell bash; [ $? -eq 2 ] && exit 2; fi; exit 0
```

For a host that runs the entry with PowerShell (7 or 5.1):

```guard-pwsh
$p = 'C:\full\path\to\shellwise.exe'; if (Test-Path -LiteralPath $p -PathType Leaf) { & $p hook generic --shell pwsh; if ($LASTEXITCODE -eq 2) { exit 2 } }; exit 0
```

Keep the PowerShell form as written: the event must reach shellwise on its inherited stdin. Do
not pipe `$input` into it; Windows PowerShell 5.1 then changes the bytes.

## Hosts

Each row is marked `tested` (run live) or `from the host's documentation` (not run by us).
"Reason shown" says whether the host is documented to show the block reason (stderr) to the model.
Paths start at the user's home folder (`%USERPROFILE%` on Windows) unless they say otherwise.

| Host | Mark | Config file | Event | Matcher | Timeout | Entry | Reason shown |
|---|---|---|---|---|---|---|---|
| Claude Code | tested | `.claude/settings.json` | `PreToolUse` | `Bash` or `PowerShell` (one regex, below) | `timeout`, seconds | `hook claude-code` (below), or the shellwise plugin | yes |
| Codex CLI | from the host's documentation | `.codex/hooks.json` | `PreToolUse` | `^Bash$` | `timeout`, seconds | bare command; `guard-pwsh` line on Windows | yes |
| Cursor | from the host's documentation | `.cursor/hooks.json` | `beforeShellExecution` | none | `timeout`, seconds | bare command; `guard-pwsh` line on Windows | not documented |
| Gemini CLI | from the host's documentation | `.gemini/settings.json` | `BeforeTool` | `run_shell_command` | `timeout`, milliseconds | `guard-sh` line on macOS and Linux; `guard-pwsh` line on Windows | yes |
| Copilot CLI | from the host's documentation | own file `.copilot/hooks/shellwise.json` | `preToolUse` | `bash` or `powershell` (one regex, below) | `timeoutSec`, seconds | guard line | not documented |
| Devin | from the host's documentation | `.config/devin/config.json` (`%APPDATA%\devin\config.json` on Windows) | `PreToolUse` | `exec` | `timeout`, seconds | bare command | not documented |

Notes per host:

- Claude Code: if the shellwise plugin is installed, it already registers the hook; add nothing.
  Otherwise use `hook claude-code`, not `hook generic`: it reads the tool name, so it needs no
  `--shell`, and its `warn` notes reach the model. The entry:
  `{"matcher": "Bash|PowerShell", "hooks": [{"type": "command", "command": "/full/path/to/shellwise", "args": ["hook", "claude-code"], "timeout": 10}]}`
  under `"hooks"` -> `"PreToolUse"`.
- Codex CLI: the shell tool is `Bash` on every system, also when it runs PowerShell on Windows, so
  pass `--shell` to match what it runs. The entry is a `{"type": "command", "command": "<entry>",
  "timeout": 10}` handler in a `PreToolUse` group with the matcher. On Windows the host runs the
  entry through PowerShell: use the `guard-pwsh` line. The user must approve the hook in the host's
  hook settings (`/hooks` in the CLI) before it runs, and again after every change to the entry.
  Tell the user; the proof cannot pass before that.
- Cursor: it already runs a Claude Code hook found in the user's Claude settings
  (`.claude/settings.json`). If one for shellwise is there, add nothing. Add an entry only when
  there is none: `{"version": 1, "hooks": {"beforeShellExecution": [{"command": "<entry>", "timeout": 10}]}}`.
  Give no matcher: here it filters the command text. On Windows the desktop app runs the entry
  through PowerShell: use the `guard-pwsh` line.
- Gemini CLI: the entry is `{"name": "shellwise", "type": "command", "command": "<entry>", "timeout":
  10000}` in a `BeforeTool` group with the matcher, under `"hooks"`. On macOS and Linux the host
  runs it with `bash -c` and blocks on a missing program: use the `guard-sh` line. On Windows it
  runs it through PowerShell: use the `guard-pwsh` line.
- Copilot CLI: it blocks when the hook program fails, so always use the guard line. Write the
  file `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "matcher": "bash|powershell",
  "bash": <guard-sh line>, "powershell": <guard-pwsh line>, "timeoutSec": 10}]}}`.
- Devin: the entry is `{"type": "command", "command": "<entry>", "timeout": 10}` in a `PreToolUse` group
  with the matcher `exec`.

## The proof

Do these in this order, so nothing runs unguarded before the hook is known to work. The proof
commands only print a shell syntax error if they do run.

For bash (`proof-bash`):

```proof-bash
echo 'abc
```

For PowerShell (`proof-pwsh`):

```proof-pwsh
Write-Output "$name: done"
```

1. Run `shellwise check` on the proof command for your shell, with the command on stdin and
   without a trailing newline (or after `--`): `printf '%s' "echo 'abc" | shellwise check --shell bash`,
   or `'Write-Output "$name: done"' | shellwise check --shell pwsh` in PowerShell. Its output must
   start with `break` (exit code 1; read `$LASTEXITCODE` in PowerShell). If not, stop and report.
2. Run the proof command itself through your own shell tool. A block shows a line starting
   `shellwise: break`. An unguarded run shows the shell's own syntax error instead: the hook is
   not wired. Fix the entry and repeat.
3. Run one harmless command through your shell tool: `echo shellwise-proof-ok` (bash) or
   `Write-Output shellwise-proof-ok` (PowerShell). It must run and print its text. If it is
   blocked, your shell tool no longer works: undo the change with your file-editing tool (see
   "Undo") and report what the host showed.
4. Report to the user what the host showed for each of the three.

## No hook on this host

Tell the user: this host has no hook that runs before a shell command, so shellwise cannot guard
it. `shellwise check` can still be run by hand on a command before running it.

## Undo

Remove the entry you added and restore the backup (or delete the file if you created it). To
switch shellwise off without removing the entry, set `SHELLWISE=off` in the host's environment.
