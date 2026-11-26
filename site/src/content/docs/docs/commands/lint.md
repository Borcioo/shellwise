---
title: shellwise lint
description: Lint a PowerShell or Bash script file with the shellwise rules and, for Bash, ShellCheck.
---

`shellwise lint` runs the shellwise rules over a whole script file. On a Bash file it also runs a
built-in port of ShellCheck.

## Usage

```text
shellwise lint [--config FILE] FILE
```

| Argument | Effect |
|---|---|
| `FILE` | Required. The script to lint. |
| `--config FILE` | An integration config file; see [Configuration](/shellwise/docs/configuration/). |

## Accepted files

| File name ends in | Shell |
|---|---|
| `.ps1` | PowerShell 7 (`pwsh`) |
| `.sh`, `.bash` | Git Bash on Windows, bash elsewhere |

The ending is compared without case. Any other name is refused: the shell is chosen from the
name only, never from a shebang line.

The file must be UTF-8. A UTF-8 byte-order mark is accepted and dropped. A file that starts with
a UTF-16 byte-order mark, holds invalid UTF-8 or is over 1 MiB (1,048,576 bytes) is refused.

On Windows, a `.sh` file with CRLF line ends gets a `bash-crlf` warning and is then read with LF
line ends, as Git Bash reads it.

## What runs

- The shellwise rules, except the ones about a command line a host is about to run (the length
  rules and the rules about what a host does to a command line).
- ShellCheck, on `.sh` and `.bash` files. SC2164 is left out.

Both run on files up to 64 KiB (65,536 bytes). On a bigger file no rule runs: it gets only a scan
for destructive commands, reported as `analysis-incomplete` (`danger` when the scan finds one,
else `warn`), and a Bash file also gets a line on stderr,
`<path>: ShellCheck skipped: the file is over 65536 bytes`.

ShellCheck findings carry their code as the rule id, such as `SC2086`. They are `warn`. A
ShellCheck parse error is `break` only when the shellwise parser also fails at the same place.
`shellwise explain SC2086` prints a short note with a link to the ShellCheck wiki page for that
code; see [shellwise explain](/shellwise/docs/commands/explain/).

The config is loaded from the current directory: the repo file is the `.shellwise.toml` of the
repo you run `lint` in. Config problems are printed to stderr as
`shellwise: config: <level> <rule>: <message>`. Environment variables in the script are not
resolved.

## Output

With no findings:

```text
<path>: ok
```

Otherwise one line per finding, sorted by line and column, with the `Fix:` line under it:

```text
<path>:<line>:<column>: <level> <rule>: <message>
  Fix: <correction>
```

Lines and columns count from 1; the column counts characters.

A refused or unreadable file prints one line to stderr, `<path>: <reason>`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings, or only `warn` (and `ok`) |
| 1 | a finding at `break` or worse |
| 64 | the file is refused: unknown name, over 1 MiB, not UTF-8, UTF-16; or a usage error |
| 74 | the file cannot be opened or read; or the config did not load |

The config load gets 1 second. When it does not finish, `lint` prints
`shellwise: the config did not load (<reason>); nothing was linted` and exits 74.

## Examples

A Bash script with a risky delete and an unquoted argument, `build.sh`:

```sh
#!/bin/sh
set -e
rm -rf "$OUT/"
cp $1 dist/
```

```sh
shellwise lint build.sh
```

```text
build.sh:3:1: danger delete-empty-expansion: if the variable or substitution in `"$OUT/"` is empty, this deletes `/`, the file-system root
  Fix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf "${X:?}/build"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end
build.sh:3:8: warn SC2115: Use "${var:?}" to ensure this never expands to / .
build.sh:4:4: warn SC2086: Double quote to prevent globbing and word splitting.
```

Exit code 1.

A PowerShell script, `bad.ps1`:

```powershell
Write-Output "$name: done"
tail -f x
```

```powershell
shellwise lint bad.ps1
```

```text
bad.ps1:1:15: break ps-var-colon: in a double-quoted string PowerShell reads $name: as a variable on a drive called name, and refuses the whole command
  Fix: write "${name}:" instead of "$name:"
bad.ps1:2:1: warn ps-unix-command: `tail` is a Unix tool that PowerShell does not have unless coreutils is on PATH
  Fix: use Select-Object -Last N in PowerShell, or run the command with the Bash tool
```

Exit code 1.

Refused files:

```text
x.txt: cannot tell the shell: the file name must end in .ps1, .sh or .bash
u16.ps1: the file starts with a UTF-16 byte-order mark; save it as UTF-8
nu.sh: the file is not valid UTF-8 (first invalid byte at offset 5); save it as UTF-8
```

Each exits 64. A missing file prints `<path>: cannot read the file: <system error>` and exits 74.

## Speed

`lint` on a whole script is slower than its target of 50 ms per 500 lines. This is a known gap;
see [Limits](/shellwise/docs/limits/).
