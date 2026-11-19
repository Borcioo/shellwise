# ps-unix-command

A Unix tool name (`tail`, `head`, `grep`, `export`, …) that PowerShell does not have unless coreutils is on PATH. The names and the PowerShell equivalents are the `unix-only` rows of `data/programs.toml`.

| Case | Level | Why |
|---|---|---|
| A Unix-only name as a command | `warn` | It may not exist. |
| The same word inside a string, for example an ssh command line | `ok` |  |

## Deny

```powershell
npm test 2>&1 | tail -20
```

`warn`: `Fix: use Select-Object -Last N in PowerShell, or run the command with the Bash tool`

## Allow

```powershell
npm test 2>&1 | Select-Object -Last 20
```

`ok`
