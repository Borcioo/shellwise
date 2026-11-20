# follow-unbounded

A command that follows a file or a stream without end: `tail -f`, `tail -F`, `tail --follow`,
`Get-Content -Wait` (and its aliases), `watch`, `kubectl logs -f`, `docker logs -f`. Nothing in the
command stops it, so the call runs until the host's timeout. It is a warn, not a deny: it may be
meant to run in the background. The rule checks command lines and script files alike; the
`will-hang` rule does not cover these commands.

| Shape | Level | Why | Fix |
|---|---|---|---|
| A follow command with no `timeout` before it and no later pipeline stage that ends the pipeline | `warn` | It never ends by itself. | Bash `timeout 60 <command>`; PowerShell `<command> \| Select-Object -First 20` |
| Under `timeout <n>` (also through `bash -c '…'`), or piped into `head`, `grep -m <n>`, `grep -q`, `Select-Object -First`/`-Index` | `ok` | The wrapper or the stage that stops reading ends it. | |
| The same program without the follow option (`tail -n 20 log`, `kubectl logs pod`, `kubectl apply -f x`) | `ok` | It reads and ends. | |

## Warn

```bash
tail -f run.log
tail -f run.log | grep ERROR
kubectl logs -f deploy/api
```

`warn`: `Fix: timeout 60 tail -f run.log`

```powershell
Get-Content run.log -Wait -Tail 10
```

`warn`: `Fix: Get-Content run.log -Wait -Tail 10 | Select-Object -First 20`

## Allow

```bash
timeout 60 tail -f run.log
tail -f run.log | grep -m1 done
tail -f run.log | head -n 5
```

```powershell
Get-Content run.log -Wait | Select-Object -First 5
```

`ok`

## Limits

- A follow command whose arguments are not all literal is not judged: a dynamic word might hold
  the bound.
- `docker logs -f` and `kubectl logs -f` are read in Bash only.
- A follow in the background (`tail -f log &`) is a finding too: it keeps running after the call.
