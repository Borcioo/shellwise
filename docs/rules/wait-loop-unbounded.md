# wait-loop-unbounded

A loop that waits for something outside it with nothing to bound the wait. If what it waits for
never comes (a log line that is never written, a server that never answers), the loop runs forever.
A worker's `until grep -q <line> <log>; do sleep 15; done` ran orphaned for nine hours. The rule
checks command lines and script files (`shellwise lint`) alike.

A loop is judged when its body waits (`sleep`, `Start-Sleep`, `Wait-Process`, `Wait-Job`,
`Wait-Event`, `[Threading.Thread]::Sleep`, `read -t`), its `while` condition waits (`while sleep
5`), or its condition is always true (`while true`, `while :`, `while ($true)`, `for (( ; ; ))`,
`for (;;)`). It is a finding when nothing visible ends it:

| Shape | Level | Why | Fix |
|---|---|---|---|
| Bash `while`/`until` and PowerShell `while`/`do … while`/`do … until`/`for (;;)` that waits or is always true, with no bound | `break` | Its end depends only on something outside the loop, which may never come. | `for i in $(seq 1 <N>); do <the stop test> && break; <the body>; done`, or in PowerShell `for ($i = 0; $i -lt <N>; $i++) { if (<the stop test>) { break }; <the body> }`. The rule fills in the loop's own condition and body, and an N that makes about ten minutes of the loop's own sleep. |
| A `for` over a list or a range (`for i in $(seq 1 60)`, `foreach ($k in 1..10)`, `1..60 \| ForEach-Object`), a counted `for ((i=0; i<60; i++))` or `for ($i = 0; $i -lt 60; $i++)` | `ok` | It ends with its items or its counter. | |
| The condition, or the test that guards a `break`, `exit`, `return` or `throw` in the body (also through `&& { echo timeout; exit 1; }` or `\|\| { …; break; }`), compares (`-lt`, `-le`, `-gt`, `-ge`, `-eq`, `-ne`, `<`, `>`, `==`, `!=` in `(( ))`) a clock (`$SECONDS`, `date +%s`, `Get-Date`, `[DateTime]::Now`, a `Stopwatch`'s `Elapsed`, `ElapsedMilliseconds`) or a counter: a variable whose new value reads its old one (`n=$((n+1))`, `((n++))`, `let n++`, `n+=1`, `$i++`, `$i += 1`, `$i = $i + 1`) | `ok` | A deadline or a counter ends it. | |
| A clock word that is no operand of a comparison (`grep -q "took 5 seconds"`, `"out-$(date +%F).txt"`, `echo "$(date) done"`, `Start-Sleep -Seconds 5`), or a comparison on a polled value (`c=$(ls out \| wc -l); [ $c -ge 10 ] && break`, `$c = (Get-ChildItem out).Count`) | `break` | A message or a file name reads no time, and a polled value may never reach its mark. | as above |
| The loop runs under `timeout <n>`, also through `bash -c '…'` or `sh -lc '…'` in the same text | `ok` | `timeout` ends it. | |
| No wait in the body and a condition that is not always true (`while grep -q x f; do sed -i 1d f; done`) | `ok` | It ends by its condition; it is no wait loop. | |
| A condition that is a `read` without `-t` (`while read -r h; do sleep 1; done < hosts.txt`, `cat f \| while IFS= read -r l; do …; done`), a sleep in the body or not | `ok` | It ends with its input; a sleep only paces it. A follow that feeds it (`tail -f log \| while read l`) is `follow-unbounded`. | |
| A body that runs a command the guard cannot read (`$step`, `eval`) | `ok` | That command may end the loop. | |

The Fix line is the whole command with the loop rewritten (a command of one line; else the loop alone), and it ends with one sentence as a trailing comment, so it still runs as pasted: when what you wait for is a process, wait on the process
(`wait <pid>`, `Wait-Process -Id <pid> -Timeout <seconds>`) rather than on a line in its log.

## Deny

```bash
until grep -q '^done' /tmp/x/run.log 2>/dev/null; do sleep 15; done; cat /tmp/x/summary.txt
```

`break`: `Fix: for i in $(seq 1 40); do grep -q '^done' /tmp/x/run.log 2>/dev/null && break; sleep 15; done; cat /tmp/x/summary.txt  # when you wait for a process, wait on the process (wait <pid>) rather than on a line in its log`

```bash
while ! curl -sf http://localhost:3000/health; do sleep 2; done
while true; do grep -q done run.log && break; sleep 5; done
until [ "$(grep -c exit run.log)" -ge 3 ]; do sleep 10; done
bash -c 'until grep -q done run.log; do sleep 15; done'
while true; do c=$(ls out | wc -l); [ $c -ge 10 ] && break; sleep 5; done
until grep -q "took 5 seconds" run.log; do sleep 15; done
```

`break`: the second one breaks on the log line only, the third and the fifth compare a polled
count, not a counter, and the last one names seconds only in its pattern.

```powershell
while (-not (Test-Path done.txt)) { Start-Sleep 5 }
```

`break`: `Fix: for ($i = 0; $i -lt 120; $i++) { if ((Test-Path done.txt)) { break }; Start-Sleep 5 }  # when you wait for a process, wait on the process (Wait-Process -Id <pid> -Timeout <seconds>) rather than on a line in its log`

## Allow

```bash
for i in $(seq 1 60); do grep -q '^done' run.log && break; sleep 15; done
timeout 600 bash -c 'until grep -q done run.log; do sleep 15; done'
n=0; until grep -q done run.log; do sleep 5; n=$((n+1)); [ $n -ge 60 ] && break; done
n=0; until grep -q done run.log; do n=$((n+1)); [ $n -gt 120 ] && { echo timeout; exit 1; }; sleep 5; done
while (( SECONDS < 600 )); do grep -q done run.log && break; sleep 5; done
while read -r host; do ssh "$host" uptime; sleep 1; done < hosts.txt
```

```powershell
$end = (Get-Date).AddMinutes(9); while ((Get-Date) -lt $end) { if (Test-Path done.txt) { break }; Start-Sleep 15 }
$n = 0; do { Start-Sleep 5; $n++ } while ($n -lt 30 -and -not (Test-Path done.txt))
```

`ok`: each one has a bound the rule can see.

## Limits

- A bound is read from the loop's own text: a counter or deadline that a function or a sourced
  script keeps is not seen, and the loop is a finding.
- A clock counts only where the comparison reads it: a time read into a variable first (`now=$(date
  +%s); [ $now -gt $end ] && break`) is a polled value, and the loop is a finding.
- PowerShell keeps no `break` in the parsed form: a guard is an `if` whose text holds an exit word.
  A `break` with no `if` around it is not seen.
- A `while read` over a FIFO that never closes runs on: the rule reads any `read` condition
  without `-t` as ending with its input.
- Bash `for ((;;))` written without blanks is a parse error for the Bash parser (warn
  `parse-error`); `for (( ; ; ))` is read.
- Only the outermost wrapper counts as a bound, as for `will-hang`.
