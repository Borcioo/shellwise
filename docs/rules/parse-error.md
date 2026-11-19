# parse-error

The command does not parse. The level depends on the kind of error the parser found.

| Kind | Level | Why |
|---|---|---|
| An unclosed quote (`'`, `"`, or a Bash backtick) | `break` | The shell refuses the whole text and runs none of it. This is the only finding. |
| An unclosed quote in a PowerShell text that holds `@'` or `@"` | `warn` | The parser reads some PowerShell here-strings passed as arguments as an unclosed quote where PowerShell accepts them. |
| An unclosed quote in a PowerShell text that holds a backslash before a double quote (`\"`) | `warn` | The PowerShell host ran such texts although `ParseInput` refuses them as written, so the refusal is not proven. |
| An unclosed quote inside a Bash backtick substitution | `warn` | `bash -n` does not parse inside backticks, so the refusal is not proven. |
| Any other kind | `warn` | Context only: the shell may still accept and run it. |

Any other kind whose raw text names a command of the destructive table is `danger` under its own
rule, `parse-error-destructive`, so a level configured here does not lower it.

Inside a PowerShell double-quoted string, `$(…)` is code with its own quotes: the `'` in
`"$("it's")"` is closed.

A parser that fails itself (a panic, a thread that did not start, a grammar that did not load) is
no parse error: the analysis is incomplete (`analysis-incomplete`).

The message names the parser's reason and the position (`column <n>`, or `line <l>, column <n>`
after the first line).

## Deny

```powershell
Write-Output "abc
```

`break`: `Fix: close the " opened at column 14, or write the text to a file and pass the file`

```bash
rm -rf "x
```

`break`, and no other finding: the shell refuses the text, so the delete never runs.

## Allow

```powershell
Get-Date
```

`ok`. `Get-Date (` alone is `warn`, which the hook passes on as context.
