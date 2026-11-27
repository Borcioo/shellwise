# follow-unbounded

A command that follows a file or a stream without end: `tail -f`, `tail -F`, `tail --follow`,
`Get-Content -Wait` (and its aliases), `watch`, `kubectl logs -f`, `docker logs -f`. Nothing in the
command stops it, so the call runs until the host's timeout. It is a warn, not a deny: it may be
meant to run in the background. The rule checks command lines and script files alike; the
`will-hang` rule does not cover these commands.

Only a time bound ends a follow, and only a duration that sets a limit: GNU timeout reads `0` in
any spelling (`00`, `0s`, `0.0`), `inf` and `infinity` as no limit, so `timeout 0 tail -f log`
warns, and its Fix puts 60 in place of the duration (`timeout 60 tail -f log`). Options before the
duration are skipped (`timeout -k 5 0 tail -f log` warns, `timeout -k 0 60 tail -f log` is
bounded), and a duration the rule cannot read (`timeout "$T" …`) counts as a bound. A later stage that waits for a line or a count (`| grep -m1`,
`| grep -q`, `| head`, `| sed q`, `| Select-Object -First`) ends it only if that line comes: on a
quiet log, `tail -f quiet.log | grep -m1 done` runs on.

| Shape | Level | Why | Fix |
|---|---|---|---|
| A follow command with no time bound, whatever stages come after it | `warn` | It never ends by itself, and a stage that waits for a line ends it only if the line comes. | The whole command with each follow replaced in place. Bash: the pipeline with `timeout 60` before the follow command (`timeout 60 tail -f log \| grep -m1 ready`); PowerShell: the whole pipeline in a job that `Wait-Job -Timeout 60` waits for, started in the caller's folder, with the caller's variables read through `$using:` and its output as text (`$j = Start-Job { Set-Location -LiteralPath $using:PWD; <pipeline> \| Out-String -Stream -Width 4096 }; $null = Wait-Job $j -Timeout 60; Receive-Job $j; Remove-Job $j -Force`) |
| Under `timeout <n>`, also after other wrappers and assignments (`nohup timeout 60 tail -f log`, `sudo timeout 60 tail -f log`, `A=1 command timeout 60 tail -f log`) or through `bash -c '…'`, or in PowerShell inside `Start-Job { … }` when the command also runs `Wait-Job -Timeout` | `ok` | The wrapper or the job wait ends it. | |
| The same program without the follow option (`tail -n 20 log`, `kubectl logs pod`, `kubectl apply -f x`) | `ok` | It reads and ends. | |

The Fix is the whole command: every later stage of the pipeline and every other statement stay,
in order, and each follow in it is bounded (60 s each). In Bash, `timeout 60` goes right before
the follow command's name: its assignments and leading redirects stay in front
(`LC_ALL=C timeout 60 tail -f log`, `2>&1 timeout 60 tail -f log`), since `timeout` would run an
assignment as a program; a line continuation before the name stays, and the bound goes on the
name's line. Around the wrappers `env`, `nice` and `nohup` the bound goes first
(`timeout 60 nohup tail -f log`); under any other wrapper, anywhere in the chain (`command` and
`exec` are shell builtins `timeout` cannot run, `sudo` was not shown to work), the Fix is a
sentence that names the follow with the bound after its wrappers, right before the program
(`sudo timeout 60 tail -f log`, `nohup sudo timeout 60 tail -f log`), a form the rule reads as
bounded. `builtin tail -f log` fails in Bash (there is no `tail` builtin): its sentence says so and
names the program without `builtin` (`timeout 60 tail -f log`). An assignment to `PATH` in front
of the follow would also apply to `timeout` (`PATH=/x timeout 60 tail -f log`: "timeout: command
not found"), so it gets a sentence that sets the assignments after the bound
(`timeout 60 env PATH=/x tail -f log`). The PowerShell job takes a statement of its
own, and its variable is a name the command does not use. Where a follow cannot be replaced in
place (in a child shell, an `if`, a function, a loop, a block, an assignment, a substitution, or a
PowerShell pipeline joined to more by `&&` or `||`), the Fix is a sentence and no command, for
every follow of the command; in Bash it names where the bound goes, with an example
(`nohup timeout 60 tail -f log`). A follow that feeds a loop (`tail -f log | while read l; do …; done`)
is replaced in place: the loop ends with its input. The PowerShell one was shown to end after its
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
nohup timeout 60 tail -f run.log
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
- `builtin tail -f log` warns, though bash refuses it (`tail` is no builtin) and follows nothing.
- A follow a local `bash`, `sh` or `zsh` reads on stdin is read as its `bash -c '…'` twin: the
  shell's own heredoc or here-string (`bash <<< 'tail -f run.log'`) or a literal producer before it
  (`echo 'tail -f run.log' | bash`, `printf '%s\n' '…' | bash`, `cat <<'EOF' | bash`), also behind
  `sudo`, `env` and `nohup`, after options that take no value (`bash -e`, `bash -s a b`); under
  `timeout` it is ok. Not read: a body after an option that takes a value, alone or in a cluster
  (`bash -o pipefail <<'EOF'`, `bash -eo pipefail`), as its `-c` twin is not, or glued to its
  letter (`zsh -oerrexit <<'EOF'`), though its `-c` twin is read; a body that expands; a
  PowerShell program on stdin; a script operand or a `-c` body beside it; a shell on another
  machine or in a container.
