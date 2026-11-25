# follow-unbounded

A command that follows a file or a stream without end: `tail -f`, `tail -F`, `tail --follow`,
`Get-Content -Wait` (and its aliases), `watch`, `kubectl logs -f`, `docker logs -f`. Nothing in the
command stops it, so the call runs until the host's timeout. It is a warn, not a deny: it may be
meant to run in the background. The rule checks command lines and script files alike; the
`will-hang` rule does not cover these commands.

Only a time bound ends a follow. A later stage that waits for a line or a count (`| grep -m1`,
`| grep -q`, `| head`, `| sed q`, `| Select-Object -First`) ends it only if that line comes: on a
quiet log, `tail -f quiet.log | grep -m1 done` runs on.

| Shape | Level | Why | Fix |
|---|---|---|---|
| A follow command with no time bound, whatever stages come after it | `warn` | It never ends by itself, and a stage that waits for a line ends it only if the line comes. | Bash: the pipeline with `timeout 60` before the follow command (`timeout 60 tail -f log \| grep -m1 ready`); PowerShell: the whole pipeline in a job that `Wait-Job -Timeout 60` waits for (`$j = Start-Job { <pipeline> }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force`) |
| Under `timeout <n>` (also through `bash -c '…'`), or in PowerShell inside `Start-Job { … }` when the command also runs `Wait-Job -Timeout` | `ok` | The wrapper or the job wait ends it. | |
| The same program without the follow option (`tail -n 20 log`, `kubectl logs pod`, `kubectl apply -f x`) | `ok` | It reads and ends. | |

The Fix keeps every later stage of the pipeline. The PowerShell one was shown to end after its
timeout on a quiet log in pwsh 7.7, with a relative path and no process left behind; it ends with
the job's output so far and exit status 0.

## Warn

```bash
tail -f run.log
tail -f run.log | grep ERROR
tail -f run.log | grep -m1 done
kubectl logs -f deploy/api
```

`warn`: `Fix: timeout 60 tail -f run.log`; for the third, `Fix: timeout 60 tail -f run.log | grep -m1 done`

```powershell
Get-Content run.log -Wait -Tail 10
Get-Content run.log -Wait | Select-Object -First 5
```

`warn`: `Fix: $j = Start-Job { Get-Content run.log -Wait -Tail 10 }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force`

## Allow

```bash
timeout 60 tail -f run.log
timeout 60 tail -f run.log | grep -m1 done
timeout 30 bash -c 'tail -f run.log'
```

```powershell
$j = Start-Job { Get-Content run.log -Wait }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force
```

`ok`

## Limits

- A follow command whose arguments are not all literal is not judged: a dynamic word might hold
  the bound.
- `docker logs -f` and `kubectl logs -f` are read in Bash only.
- A follow in the background (`tail -f log &`) is a finding too: it keeps running after the call.
- A job counts as bounded when any `Wait-Job -Timeout` appears in the same command, whichever job
  it waits for.
- In Windows PowerShell 5.1 a job starts in the Documents folder: a relative path in the Fix reads
  from there.
- A job does not see the caller's variables: in the Fix of `Get-Content log -Wait | Select-String
  $pat`, write `$using:pat`.
- `tail -f log --pid=<pid>` ends with that process but still warns.
