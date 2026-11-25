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
| A follow command with no time bound, whatever stages come after it | `warn` | It never ends by itself, and a stage that waits for a line ends it only if the line comes. | The whole command with each follow replaced in place. Bash: the pipeline with `timeout 60` before the follow command (`timeout 60 tail -f log \| grep -m1 ready`); PowerShell: the whole pipeline in a job that `Wait-Job -Timeout 60` waits for, started in the caller's folder, with the caller's variables read through `$using:` and its output as text (`$j = Start-Job { Set-Location -LiteralPath $using:PWD; <pipeline> \| Out-String -Stream -Width 4096 }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force`) |
| Under `timeout <n>` (also through `bash -c '…'`), or in PowerShell inside `Start-Job { … }` when the command also runs `Wait-Job -Timeout` | `ok` | The wrapper or the job wait ends it. | |
| The same program without the follow option (`tail -n 20 log`, `kubectl logs pod`, `kubectl apply -f x`) | `ok` | It reads and ends. | |

The Fix is the whole command: every later stage of the pipeline and every other statement stay,
in order, and each follow in it is bounded (60 s each). The PowerShell job takes a statement of its
own, and its variable is a name the command does not use. Where a follow cannot be replaced in
place (in a child shell, an `if`, a function, a loop, a block, an assignment, a substitution, or a
PowerShell pipeline joined to more by `&&` or `||`), the Fix is a sentence and no command, for
every follow of the command. The PowerShell one was shown to end after its
timeout on a quiet log in pwsh 7.7 and Windows PowerShell 5.1, with a relative path and no process
left behind; it ends with the job's output so far and exit status 0. A job sees none of the
caller's variables and in Windows PowerShell 5.1 starts in Documents, so the Fix starts it in the
caller's folder and writes each variable the pipeline reads as `$using:<name>` (`$pat` becomes
`$using:pat`, `$p.ToLower()` becomes `($using:p).ToLower()`; `$_`, `$true`, `$env:` and
single-quoted text stay). The job ends its pipeline with `| Out-String -Stream -Width 4096`:
Windows PowerShell 5.1 shows a `Select-String` result received from a job blank, and the width
keeps a long line whole. A pipeline that assigns a
variable (`ForEach-Object { $n++ }`) or names a scope (`$script:x`) gets a sentence instead:
`$using:` cannot pass it. So does one that reads a variable the command sets only after it.

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

`warn`: `Fix: $j = Start-Job { Set-Location -LiteralPath $using:PWD; Get-Content run.log -Wait -Tail 10 | Out-String -Stream -Width 4096 }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force`

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
- A variable a `-PipelineVariable` or `-OutVariable` sets is read as the caller's: its `$name`
  becomes `$using:name` in the Fix.
- `tail -f log --pid=<pid>` ends with that process but still warns.
