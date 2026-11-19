# gate-truncated-pipeline

A test or build run whose output goes through `Tee-Object` and then into a command that stops after N lines (`Select-Object -First`, `head`). The truncator stops the producer early: the exit code reads as success and the log file is cut off. The truncators and tee commands are tagged in `data/programs.toml`; a configured gate command counts as a producer too.

| Case | Level | Why |
|---|---|---|
| A tee'd producer piped, at any later stage, into a truncator | `break` | The run is stopped early and reports success. |
| `Select-Object -Last N` | `ok` | It reads the whole stream. |

## Deny

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -First 30
```

`break`: `Fix: $out = npm test 2>&1 | Tee-Object run.log 2>&1; $out | Select-Object -Last 20`

## Allow

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -Last 20
```

`ok`
