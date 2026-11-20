# stale-write-var

Shell state does not survive between tool calls. A variable written into a file but never assigned in the same command reads as `$null`, and the file is overwritten with nothing.

| Case | Level | Why |
|---|---|---|
| A variable used as the content of Set-Content, Out-File, `[IO.File]::WriteAll*` or piped into them, never assigned in the command | `break` | The file is emptied. |
| Assigned earlier in the command, an append, `$env:`, a loop variable, single-quoted text | `ok` |  |

## Deny

```powershell
Set-Content -Path report.md -Value $text
```

`break`: `Fix: assign $text in this same command before the write …`

## Allow

```powershell
$text = Get-Content a.md -Raw; Set-Content -Path report.md -Value $text
```

`ok`
