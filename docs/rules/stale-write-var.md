# stale-write-var

Shell state does not survive between tool calls. A variable written into a file but never assigned in the same command reads as `$null`, and the file is overwritten with nothing.

| Case | Level | Why |
|---|---|---|
| A variable used as the content of Set-Content, Out-File, `[IO.File]::WriteAll*` or piped into them, never assigned in the command | `break` | The file is emptied. |
| Assigned earlier in the command, an append, `$env:`, a loop variable, single-quoted text | `ok` |  |
| Bound earlier in the command by name: `-OutVariable`, `-PipelineVariable`, `-ErrorVariable`, `-WarningVariable`, `-InformationVariable`, `Tee-Object -Variable`, `Set-Variable`/`New-Variable` (`-Name` or its position), `Invoke-RestMethod`/`Invoke-WebRequest` `-StatusCodeVariable`, `-ResponseHeadersVariable`, `-SessionVariable` | `ok` | The cmdlet sets it. |
| Written after a dot-sourced script (`. .\vars.ps1; …`) | `ok` | The script may set any variable in this scope. `& .\vars.ps1` does not count. |
| A `.ps1` file checked with `shellwise lint` | not checked | A script keeps its variables from line to line. |

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
