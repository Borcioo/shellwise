# bash-ps-call-operator

A command in the Bash tool that starts with the PowerShell call operator: `& "C:/path/tool.exe"
args`. Bash reads a `&` at the start of a command as a syntax error and runs none of that line
(`bash -c '& "x"'` exits 2). The program runs in bash by its path alone.

| Case | Level |
|---|---|
| a command, or a pipeline or list segment, starting with `&` and an operand (`& "x.exe"`, `& 'x.exe'`, `& $tool`, `& path\tool.exe`) | `break` |
| a background job (`cmd &`, `cmd & other`, `a & b & wait`), `a && b` | no finding |
| a redirect (`&>file`, `&>>file`, `2>&1`, `\|&`, `<&3`), a `&` in quotes or a heredoc body | no finding |
| a leading `&&` or a lone `&` | no finding here: see `parse-error` |

The finding takes the place of the parser's `parse-error` warn for that error; a
`parse-error-destructive` on the same text stays. The Fix is the text with each `&` taken out and
its operand as bash runs it: a quoted path as written, `$name` in double quotes, a bare path with
forward slashes. A PowerShell-only operand (a script block, `$env:X`, an expression) or a
PowerShell assignment in the text gets a sentence instead, and a `.ps1` script is sent to the
PowerShell tool. The Fix parses the text again once per `&` and gives the sentence once those
parses would read more than 16 KiB. In `shellwise lint` the Fix holds only the corrected lines.
Both Bash profiles (Git Bash and POSIX bash).

## Deny

```bash
& "C:/path/tool.exe" args
```

`break`: `Fix: "C:/path/tool.exe" args`

## Allow

```bash
"C:/path/tool.exe" args
```

`ok`.
