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
| Bash (Git Bash, POSIX) | 150 | 6,000 |

A line is a `\n`-separated line (a command of one line has 1); a character is a Unicode character.
The pair for each shell is the one of the grid (40, 60, 80, 100, 150 lines by 4,000, 6,000, 8,000
characters) that catches the most `failed` corpus rows while at most 0.5 % of that shell's `ok`
rows fire. On the corpus of 2026-11-18 PowerShell fires on 106 of 25,004 `ok` rows (0.42 %) and 17
of 3,227 `failed` rows. Bash fires on 69 of 21,590 `ok` rows (0.32 %) and 1 of 402 `failed` rows;
the Bash rows over Git Bash's escaped limit are `too-long`'s, not counted here. This count is
reported on its own line and is not part of the false-positive meter.

When `too-long` fires on the same command, this rule says nothing: the hard limit is the sharper
message and the fix is the same.

`Fix: write the command to <scratch>/script.ps1 with the Write tool, run shellwise lint
<scratch>/script.ps1, then run pwsh -NoProfile -File <scratch>/script.ps1`

For Bash the file is `<scratch>/script.sh` and the last step is `bash <scratch>/script.sh`; for
Windows PowerShell 5.1 the runner is `powershell -NoProfile -File`. `<scratch>` is `scratch_dir`
from the config, else the OS temp folder plus `shellwise`. The path has forward slashes and is
double-quoted when it holds a space.

## Deny

A PowerShell command of 81 lines, or of 6,001 characters on one line.

A Bash command of 151 lines, or of 6,001 characters.

## Allow

The same commands one line or one character shorter. The same text as a file:
`shellwise lint script.sh` does not apply this rule, because it checks what is in the file and a
file has no command line.

## Host limits (`too-long`)

On Windows, a command that the host cannot start at all is `too-long` (`break`), with the same fix:

- a PowerShell command over 32,767 UTF-16 code units (the `CreateProcess` command-line limit);
- a command that starts with a program that has a line limit in `data/programs.toml` (`cmd`,
  8,191) and is longer than that limit.

Git Bash's escaped limit is in `too-long.md`.
