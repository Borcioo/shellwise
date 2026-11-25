# gate-truncated-pipeline

A test or build run whose output goes through a tee (`Tee-Object`, in Bash `tee`) and then into a command that stops after N lines (`Select-Object -First`, `head`). The truncator stops the producer early: the exit code reads as success and the log file is cut off. The truncators and tee commands are tagged in `data/programs.toml`; a configured gate command (`gate_commands`) counts as a producer too. Both tools: PowerShell and Bash (Git Bash and POSIX bash).

| Case | Level | Why |
|---|---|---|
| A tee'd producer or a gate command piped, at any later stage, into a truncator (`Select-Object -First`, `head` with a positive count: `head`, `head -5`, `head -n 5`) | `warn` | The run may be stopped early and report success. Warn: in the corpus it also fired on runs that worked (the truncator's count was never reached). |
| `Select-Object -Last N`, `tail -n N`, `sed -n 'Np'`, `head` with a negative count (`-n -5`, `-n-5`, `--lines=-5`, `-c -100`) | `ok` | They read the whole stream. |
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

The PowerShell Fix is the pipeline alone. The Bash Fix is the whole command with only the pipeline changed: every stage keeps its words and redirects, the cut's name and count become `tail -n 20` (its own redirects and any stage after it stay), and what stands around the pipeline stays where it was (`cd sub && …`, `; echo done`, `&& echo ok`, a trailing `&`, `time`). With the producer's exit code kept, a `&& …` after the pipeline now runs only when the producer succeeds. In `shellwise lint` the Fix is the line the pipeline stands on. A pipeline inside a compound command or a substitution, one with a heredoc, one whose cut has a redirect before its count (`head > out.txt -n 5`), or one the Fix would leave unparsable (a redirect before the first command's name) gets a sentence instead, which says to replace the cut with `tail -n 20` and run the pipeline as `(set -o pipefail; … | tail -n 20)`.

```bash
cd sub && ./scripts/run-gate.sh --all 2>&1 | tee gate.log | head -n 5; echo done
```

`warn`: `Fix: cd sub && (set -o pipefail; ./scripts/run-gate.sh --all 2>&1 | tee gate.log | tail -n 20); echo done`

## Allow

```powershell
npm test 2>&1 | Tee-Object run.log | Select-Object -Last 20
```

```bash
npm test 2>&1 | tee run.log | tail -n 20
```

`ok`
