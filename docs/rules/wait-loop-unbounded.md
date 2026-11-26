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
| Bash `while`/`until` and PowerShell `while`/`do … while`/`do … until`/`for (;;)` that waits or is always true, with no bound | `break` | Its end depends only on something outside the loop, which may never come. | A counted loop that runs the condition as written first and fails when its rounds run out: `until C; do B; done` becomes `for i in $(seq 1 <N>); do C && break; B; [ "$i" -lt <N> ]; done` (`C \|\| break` for `while C`); in PowerShell `while (C) { B }` becomes `for ($i = 0; $i -lt <N>; $i++) { if (-not (C)) { break }; B }; if ($i -eq <N>) { throw 'the wait timed out' }` (`if (C)` for `until`). The rule fills in the loop's own condition and body, and an N that makes about ten minutes of the loop's own sleep (`sleep 1m` counts as 60 s). |
| A `for` over a list or a range (`for i in $(seq 1 60)`, `foreach ($k in 1..10)`, `1..60 \| ForEach-Object`), a counted `for ((i=0; i<60; i++))` or `for ($i = 0; $i -lt 60; $i++)` | `ok` | It ends with its items or its counter. | |
| The condition, or the test that guards a `break`, `exit`, `return` or `throw` in the body (also through `&& { echo timeout; exit 1; }` or `\|\| { …; break; }`), compares (`-lt`, `-le`, `-gt`, `-ge`, `-eq`, `-ne`, `<`, `>`, `==`, `!=` in `(( ))`) a clock (`$SECONDS`, `date +%s`, `Get-Date`, `[DateTime]::Now`, a `Stopwatch`'s `Elapsed`, `ElapsedMilliseconds`) or a counter: a variable whose new value reads its old one (`n=$((n+1))`, `((n++))`, `let n++`, `n+=1`, `$i++`, `++$k`, `$i += 1`, `$i = $i + 1`). In the loop's own condition the bound must end the loop by itself: `until A \|\| bound`, `while A && bound`. A Bash loop whose whole condition is a throttle on the shell's own jobs (below) | `ok` | A deadline or a counter ends it; the jobs count drops when one of the shell's own jobs ends. | |
| A clock word that is no operand of a comparison (`grep -q "took 5 seconds"`, `"out-$(date +%F).txt"`, `echo "$(date) done"`, `Start-Sleep -Seconds 5`) or that is text inside double quotes or a `$( )` (`[ "$(git pull)" == "Already up to date." ]`, `$(grep -c date log)`); a comparison on a polled value (`c=$(ls out \| wc -l); [ $c -ge 10 ] && break`, `state=$(cat state)`, `$c = (Get-ChildItem c).Count`); a bound joined so that the loop still waits for the rest (`until A && bound`, `while A \|\| bound`); a count of other processes (`pgrep -c x`, `ps \| grep -c x`, `docker ps -q \| wc -l`), a jobs count through another stage or option (`jobs -l`, `\| wc -c`), one read in the body or into a variable, or a jobs count in a condition that is not exactly a throttle as below | `break` | A message or a file name reads no time, a polled value may never reach its mark, and that bound alone does not end the loop. | as above |
| The loop runs under `timeout <n>`, also through `bash -c '…'` or `sh -lc '…'` in the same text | `ok` | `timeout` ends it. | |
| No wait in the body and a condition that is not always true (`while grep -q x f; do sed -i 1d f; done`) | `ok` | It ends by its condition; it is no wait loop. | |
| A condition that is a `read` without `-t` (`while read -r h; do sleep 1; done < hosts.txt`, `cat f \| while IFS= read -r l; do …; done`), a sleep in the body or not | `ok` | It ends with its input; a sleep only paces it. A follow that feeds it (`tail -f log \| while read l`) is `follow-unbounded`. | |
| A body that runs a command the guard cannot read (`$step`, `eval`) | `ok` | That command may end the loop. | |

A throttle on the shell's own jobs (`while (( $(jobs -rp | wc -l) >= 4 )); do sleep 0.1; done`)
is read only in one shape, and anything else polls (`break`):

- The loop's whole condition is one test: `[ … ]`, `test …`, `[[ … ]]` or `(( … ))`, with no `!`
  before it or inside it, and no `-o`, `-a`, `||` or `&&` inside it or between it and another
  test. A bound joined with another condition inside one test is not read as a bound.
- The test holds one comparison: the count of the shell's own background jobs on one side, the
  whole operand (`"$(jobs -rp | wc -l)"`; `jobs`, `jobs -r`, `-p`, `-rp` or `-pr` piped to
  `wc -l`), and on the other a mark that is one literal integer (`4`, `"4"`) or one variable
  (`$max`, `"${max}"`, `max` in `(( ))`): no expression (`4 - 4`, `$((max))`), no other
  substitution, no second count.
- The operator is one that test takes: `[ ]` and `test` only `-ge`, `-gt`, `-lt`, `-le`, `-ne`,
  `-eq` (there `<` and `>` are redirections and `>=`, `<=` are no operators); `(( ))` `>=`, `>`,
  `<`, `<=`, `!=`, `==`; `[[ ]]` the `-xx` set, and `<` or `>` only against a mark of digits
  (they compare text: an empty mark or a sign never lets the loop end).
- The comparison ends the loop as the count falls: `while` with the count `-ge` a mark of 1 or
  more, `-gt` 0 or more, or `-ne` 0; `until` with the count `-lt` a mark of 1 or more, `-le` 0 or
  more, or `-eq` 0 (a variable mark counts for all but `-ne`/`-eq`); the same with the count on the
  right (`while [ 4 -le "$(…)" ]`). Any other direction or mark (`while … -lt 4`, `-eq 4`,
  `>= 0`; `until … -ge 4`, `-ne 0`) is no throttle the guard reads.

The Fix line is the whole command with the loop rewritten (a command of one line; else the loop
alone, over as many lines as the loop had), and it ends with one sentence as a trailing comment, so
it still runs as pasted. The condition keeps its text, a leading `!` and every `&&`/`||` included;
a condition of several commands is grouped (`{ a; b; } && break`). When the rounds run out the
fixed loop fails (Bash: exit status 1; PowerShell: `throw`), so a command after it with `&&`
(Bash) or `;` (PowerShell) does not run. The loop counter is a name the command uses nowhere else
(`i`, else `attempt`, `attempt2`, …; in PowerShell compared in any case). A Bash loop whose body
holds a here-document, that is piped into a later stage (`… done | tee out.txt`: that stage's
status is the pipeline's) or that sits inside another loop (which would go on after a timeout)
gets a sentence instead of a command. The trailing sentence: when what you wait for is a process, wait on the
process (`timeout 600 tail --pid=<pid> -f /dev/null`, `Wait-Process -Id <pid> -Timeout <seconds>`)
rather than on a line in its log; a tool call's shell never has that process as its child, so
`wait <pid>` fails there.

## Deny

```bash
until grep -q '^done' /tmp/x/run.log 2>/dev/null; do sleep 15; done; cat /tmp/x/summary.txt
```

`break`: `Fix: for i in $(seq 1 40); do grep -q '^done' /tmp/x/run.log 2>/dev/null && break; sleep 15; [ "$i" -lt 40 ]; done; cat /tmp/x/summary.txt  # when you wait for a process, wait on the process (timeout 600 tail --pid=<pid> -f /dev/null) rather than on a line in its log`

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

`break`: `Fix: for ($i = 0; $i -lt 120; $i++) { if (-not (-not (Test-Path done.txt))) { break }; Start-Sleep 5 }; if ($i -eq 120) { throw 'the wait timed out' }  # when you wait for a process, wait on the process (Wait-Process -Id <pid> -Timeout <seconds>) rather than on a line in its log`

```bash
while ! grep -q a log && ! grep -q b log; do sleep 5; done
```

`break`: `Fix: for i in $(seq 1 120); do ! grep -q a log && ! grep -q b log || break; sleep 5; [ "$i" -lt 120 ]; done  # …`: the loop ends as the original does, as soon as either line is there.

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
- A counter counts when its new value refers to the variable (`$n`, `${n}`, a bare `n` in `$(( ))`,
  `(( ))`, `$[ ]` or `let`, or a bare `n` assigned after `declare -i n` or `typeset -i n`;
  PowerShell `$n` in any case, `$script:n`): `state=$(cat state)` names `state` only as a file and
  polls.
- A test command or a group in the condition is read as one test: in `until [[ -f ok && $n -ge 9
  ]]`, `until [ -f ok -a $n -ge 9 ]` or `while ! ( A || bound )` a compared counter bounds the loop,
  whichever way the inner operators join it.
- A loop piped on from inside a group or a function (`{ until …; done; } | tee log`) still gets a
  command: the later stage's status hides its failure.
- PowerShell keeps no `break` in the parsed form: a guard is an `if` whose text holds an exit word.
  A `break` with no `if` around it is not seen.
- A `while read` over a FIFO that never closes runs on: the rule reads any `while read` condition
  without `-t` as ending with its input (`until read` and `while ! read` wait as any poll does).
- `while read -t 5 line; do …; sleep 1; done` is a finding, though `read -t` ends it after 5 s
  without input.
- A subshell's `exit` or `break` (`[ $n -gt 9 ] && ( echo timeout; exit 1 )`) is no bound: it
  leaves the subshell only.
- A Bash body that runs `continue` gets a sentence, not a command: `continue` would skip the round
  test.
- Bash `for ((;;))` written without blanks is a parse error for the Bash parser (warn
  `parse-error`); `for (( ; ; ))` is read.
- Only the outermost wrapper counts as a bound, as for `will-hang`.
