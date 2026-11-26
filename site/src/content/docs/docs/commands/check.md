---
title: shellwise check
description: Check one shell command by hand and read its verdict as text or JSON.
---

`shellwise check` runs the same analysis as the hooks on one command and prints the verdict.
Use it to try a command before you run it, or to see what a hook would say.

## Usage

```text
shellwise check --shell <SHELL> [--cwd DIR] [--json] [--config FILE] [-- COMMAND...]
```

## Flags

| Flag | Value | Effect |
|---|---|---|
| `--shell` | `pwsh`, `powershell5`, `bash`, `gitbash` | Required. The shell that will run the command. |
| `--cwd` | a folder | The working directory the command runs in. |
| `--json` | none | Print the verdict as one line of JSON. |
| `--config` | a TOML file | An integration config file; see [Configuration](/shellwise/docs/configuration/). |
| `-- COMMAND...` | the command | Everything after `--`, joined with single spaces. |

The `--shell` values:

| Value | Shell |
|---|---|
| `pwsh` | PowerShell 7 |
| `powershell5` | Windows PowerShell 5.1 |
| `bash` | bash on Linux or macOS |
| `gitbash` | Git Bash on Windows |

Without `-- COMMAND`, `check` reads the command from stdin. In PowerShell, put the command in
single quotes so PowerShell does not expand it first.

`--cwd` matters for deletes. Without it, a relative path in the command is not resolved and the
delete guard reports that it cannot tell which folder is meant. Pass an absolute path: a relative
`--cwd` such as `.` leaves relative paths unresolved too. The repo file `.shellwise.toml`
is looked for from `--cwd`, or from the current directory when `--cwd` is not given.

## Output

With no findings, `check` prints `ok`. Otherwise it prints one line per finding:

```text
<level> <rule> [<start>..<end>]: <message>
  Fix: <correction>
```

- `<level>` is `ok`, `warn`, `break`, `danger` or `critical`.
- `<rule>` is the rule id. `shellwise explain <rule>` prints its documentation; see
  [the rules](/shellwise/docs/rules/).
- `<start>..<end>` are byte offsets into the command text.
- The `Fix:` line is there only when the finding has a correction.

A finding at `ok` is still printed. That happens when the allow marker confirmed it, or when your
config set the rule's level to `ok`.

Problems in a config file are printed as `warn` findings with the rule `config-invalid` or
`config-repo-ignored` and the span `[0..0]`.

For the JSON shape, see [Exit codes and JSON](/shellwise/docs/reference/exit-codes-and-json/).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `ok` or `warn` |
| 1 | `break`: the command will fail or hang as written |
| 2 | `danger`: the command may destroy work |
| 3 | `critical`: system files or the repository itself |
| 64 | usage error (missing `--shell`, an unknown value, an unknown flag) |
| 74 | stdin could not be read |

The verdict is the highest level among the findings. Stdin that is still open at the deadline is
not an exit 74: the command counts as unread and the verdict is `danger` (exit 2).

## Examples

A bash wait loop with no bound:

```sh
shellwise check --shell bash -- 'until grep -q done build.log; do sleep 15; done'
```

```text
break wait-loop-unbounded [0..47]: the loop polls and nothing bounds it: no counter, deadline or timeout ends it, so when what it waits for never comes it runs forever
  Fix: for i in $(seq 1 40); do grep -q done build.log && break; sleep 15; [ "$i" -lt 40 ]; done  # when you wait for a process, wait on the process (timeout 600 tail --pid=<pid> -f /dev/null) rather than on a line in its log
```

Exit code 1.

A delete whose variable may be empty, then the same command confirmed with the allow marker:

```sh
shellwise check --shell bash -- 'rm -rf "$DIR/"'
shellwise check --shell bash -- 'rm -rf "$DIR/" # shellwise: allow'
```

```text
danger delete-empty-expansion [0..14]: if the variable or substitution in `"$DIR/"` is empty, this deletes `/`, the file-system root
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
ok delete-empty-expansion [0..14]: if the variable or substitution in `"$DIR/"` is empty, this deletes `/`, the file-system root (confirmed by the trailing allow marker)
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
```

Exit codes 2, then 0.

A PowerShell string that PowerShell refuses:

```powershell
shellwise check --shell pwsh -- 'Write-Output "$name: done"'
```

```text
break ps-var-colon [14..20]: in a double-quoted string PowerShell reads $name: as a variable on a drive called name, and refuses the whole command
  Fix: write "${name}:" instead of "$name:"
```

Exit code 1.

A PowerShell delete of a system folder:

```powershell
shellwise check --shell pwsh -- 'Remove-Item -Recurse -Force C:\Windows\Temp\..'
```

```text
critical delete-critical [0..46]: deleting `C:\Windows\Temp\..` is blocked: it is the system folder, and the allow marker cannot confirm it
  Fix: do not delete in a system folder; if it must go, ask the user to run the command themselves
```

Exit code 3, also with ` # shellwise: allow` at its end.

A relative delete without `--cwd`:

```sh
shellwise check --shell bash -- 'rm -rf build'
```

```text
warn delete-unknown-location [0..12]: the guard could not read which folder `build` deletes: the command moves to a folder the guard cannot follow, defines a function or alias, maps a drive, runs a script or makes a link before it
  Fix: use the full path of the folder so the guard can check it
```

Exit code 0. With `--cwd` set to the absolute path of a folder inside a repo, the same command
prints `ok`, and `rm -rf ..` from a folder just below the repo root is `critical` (it deletes the
repo root).

The command on stdin:

```sh
printf '%s' "echo 'abc" | shellwise check --shell bash
```

```text
break parse-error [5..9]: bash: unterminated single quote at 1,6: the ' opened at column 6 is never closed, so the shell refuses the whole command and runs none of it
  Fix: close the ' opened at column 6, or write the text to a file and pass the file
```

Exit code 1.

## The allow marker

A command that ends with the comment `# shellwise: allow` has its `break` and `danger` findings
lowered to `ok`. The marker has no effect on `critical`, on the length rules `too-long` and
`inline-script-too-long`, on `parse-error`, `parse-error-destructive` and `analysis-incomplete`.
It must be a real trailing comment: text inside a string or a heredoc does not count. Add it only
after you have read the finding.
