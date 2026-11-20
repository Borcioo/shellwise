# inline-script-too-long

A command holds a long script. It would run, but a script written inline in a command is never
linted before it runs, and the long ones are where syntax slips and host limits are met. The fix
routes the text to a file that `shellwise lint` reads.

The rule is `break`, for command lines only (a file is never "too long"). It is measured on the
whole command text, before the parse, and the allow marker has no effect on it. It fires when the
command has **more than** either value:

| Shell | Lines | Characters |
|---|---:|---:|
| PowerShell (`pwsh`, Windows PowerShell 5.1) | 80 | 6,000 |
| Bash (Git Bash, POSIX) | 100 | 8,000 |

A line is a `\n`-separated line (a command of one line has 1, and a trailing newline starts one
more); a character is a Unicode character. The pair for each shell is the one of the grid (40, 60,
80, 100, 150 lines by 4,000, 6,000, 8,000 characters) that catches the most `failed` corpus rows
while at most 0.5 % of that shell's `ok` rows fire; a tie goes to the lower lines, then the lower
characters. On the corpus of 2026-11-19 PowerShell fires on 106 of 25,004 `ok` rows (0.42 %) and 17
of 3,227 `failed` rows. Bash fires on 101 of 21,628 `ok` rows (0.47 %) and 3 of 402 `failed`
rows; the Bash rows at or over Git Bash's escaped limit (`limits.git_bash_command`, 7500) are
`too-long`'s and are not counted here. At that limit every Git Bash command over 8,000 characters
is `too-long`, so for Git Bash the line count is what decides. The count of non-destructive `ok`
rows is reported on its own line, outside meter 1; a destructive `ok` row it denies counts on
meter 2.

When `too-long` fires on the same command, this rule says nothing: the hard limit is the sharper
message and the fix is the same.

The Fix line is `too-long`'s: a new script file on each call, `command-<pid>-<time>-<n>.ps1` (or
`.sh`), in `scratch_dir` from the config, else in `shellwise-<user>` under the OS temp directory,
with forward slashes, single-quoted where a shell reads it when it holds a space. With
`scratch_dir = "D:/work/scratch"`:

`Fix: write the command to D:/work/scratch/command-1f2c-6243b1d0e8a10-0.ps1 with the Write tool, run shellwise lint D:/work/scratch/command-1f2c-6243b1d0e8a10-0.ps1, then run pwsh -NoProfile -File D:/work/scratch/command-1f2c-6243b1d0e8a10-0.ps1`

For Bash the last step is `bash <file>`; for Windows PowerShell 5.1 it is
`powershell -NoProfile -File <file>`.

## Deny

A PowerShell command of 81 lines, or of 6,001 characters on one line.

A Bash command of 101 lines, or (POSIX) of 8,001 characters.

## Allow

The same commands one line or one character shorter. The same text as a file:
`shellwise lint script.sh` does not apply this rule, because it checks what is in the file and a
file has no command line.
