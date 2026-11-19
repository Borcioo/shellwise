# parse-error

The command does not parse. The level depends on the kind of error the parser found.

| Kind | Level | Why |
|---|---|---|
| An unclosed quote (`'`, `"`, or a Bash backtick) | `break` | The shell refuses the whole text and runs none of it. This is the only finding. |
| An unclosed quote in a PowerShell text that holds `@'` or `@"` | `warn` | The parser reads some here-strings passed as arguments as an unclosed quote where PowerShell accepts them. |
| Any other kind, and the raw text names a command that deletes or discards data | `danger` | Nothing proves the shell refuses the text, and part of it may delete. |
| Any other kind | `warn` | Context only: the shell may still accept and run it. |

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

```powershell
Get-Date ( ; rm -rf x
```

`danger`: `Fix: correct the syntax at column 10 (…)`

## Allow

```powershell
Get-Date
```

`ok`. `Get-Date (` alone is `warn`, which the hook passes on as context.
