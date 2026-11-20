# gate-truncated-pipeline

A test or build run whose output goes through `Tee-Object` and then into a command that stops after N lines (`Select-Object -First`, `head`). The truncator stops the producer early: the exit code reads as success and the log file is cut off. The truncators and tee commands are tagged in `data/programs.toml`; a configured gate command counts as a producer too.

| Case | Level | Why |
|---|---|---|
| A tee'd producer piped, at any later stage, into a truncator | `warn` | The run may be stopped early and report success. Warn: in the corpus it also fired on runs that worked (the truncator's count was never reached). |
| `Select-Object -Last N` | `ok` | It reads the whole stream. |

## Deny

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -First 30
```

`warn`: `Fix: $out = npm test 2>&1 | Tee-Object run.log 2>&1; $out | Select-Object -Last 20`

## Allow

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -Last 20
```

`ok`
