# gate-truncated-pipeline

A test or build run whose output goes through a tee (`Tee-Object`, in Bash `tee`) and then into a command that stops after N lines (`Select-Object -First`, `head`). The truncator stops the producer early: the exit code reads as success and the log file is cut off. The truncators and tee commands are tagged in `data/programs.toml`; a configured gate command (`gate_commands`) counts as a producer too. Both tools: PowerShell and Bash (Git Bash and POSIX bash).

| Case | Level | Why |
|---|---|---|
| A tee'd producer or a gate command piped, at any later stage, into a truncator (`Select-Object -First`, `head` with any count) | `warn` | The run may be stopped early and report success. Warn: in the corpus it also fired on runs that worked (the truncator's count was never reached). |
| `Select-Object -Last N`, `tail -n N`, `sed -n 'Np'` | `ok` | They read the whole stream. |
| A tee alone, or `head` after a producer that is no gate and has no tee (`cat file \| head -n 5`) | `ok` | Nothing a gate writes is cut. |

## Deny

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -First 30
```

`warn`: `Fix: $out = npm test 2>&1 | Tee-Object run.log 2>&1; $out | Select-Object -Last 20`

```bash
npm test 2>&1 | tee run.log | head -n 5
```

`warn`: `Fix: (set -o pipefail; npm test 2>&1 | tee run.log | tail -n 20)`: `pipefail` keeps the producer's exit code, and the subshell keeps the option from outliving the call.

## Allow

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -Last 20
```

```bash
npm test 2>&1 | tee run.log | tail -n 20
```

`ok`
