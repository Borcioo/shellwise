# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `wait-loop-unbounded` now catches a loop whose only "deadline" is a clock word in a message, a
  file name, a pattern or a parameter (`grep -q "took 5 seconds"`, `Start-Sleep -Seconds 5`): a
  clock bounds a loop only when a comparison reads it.
- `wait-loop-unbounded` now catches a loop that compares a polled value (`c=$(ls out | wc -l);
  [ $c -ge 10 ] && break`): only a variable that counts from its own old value is a counter.
- `wait-loop-unbounded` no longer blocks a counted loop whose counter test exits through a block
  (`[ $n -gt 100 ] && { echo timeout; exit 1; }`) or compares with `-eq`, `-ne`, `==` or `!=`.
- `wait-loop-unbounded` no longer blocks a `while read` loop that sleeps between lines: it ends
  with its input.
- The `wait-loop-unbounded` Fix keeps the loop's condition as written: a compound condition
  (`while ! a && ! b`) no longer turns into a test that breaks on the wrong thing.
- The `wait-loop-unbounded` Fix now fails when its rounds run out (Bash exit status 1, PowerShell
  `throw`), so `… && deploy.sh` no longer runs after a timeout.
- The `wait-loop-unbounded` Fix of a loop over several lines is the loop with its own lines, not
  placeholders; a loop holding a here-document gets a sentence.
- The `wait-loop-unbounded` Fix keeps a body that starts or ends with a compound command (`if … fi`,
  `{ … }`, `( … )`, PowerShell `try { } catch { }`) whole, so the Fix parses.
- The `wait-loop-unbounded` Fix counts `sleep 1m` as a minute (it read 1 s, making a 10-hour loop).
- The `wait-loop-unbounded` hint names `timeout 600 tail --pid=<pid> -f /dev/null` instead of
  `wait <pid>`, which fails in a tool call's shell.
- `follow-unbounded` now warns on a follow piped into a stage that waits for a line (`tail -f log
  | grep -m1 done`, `| head`, `| Select-Object -First`): on a quiet log it never ends.
- The `follow-unbounded` Fix keeps the later pipeline stages, and the PowerShell Fix is
  time-bounded (a job with `Wait-Job -Timeout 60`) instead of `| Select-Object -First 20`, which
  did not end on a quiet log.
- `wait-loop-unbounded` now catches `until read …` and `while ! read …` polls, and no longer reads
  a subshell's `( …; exit 1 )` as the loop's end.
- `wait-loop-unbounded` reads a counter in backticks (``n=`expr $n + 1` ``) and `((--n))`.
- `wait-loop-unbounded` now catches a wait in a `while` condition (`while sleep 5; do …`) and
  `[Threading.Thread]::Sleep` in PowerShell.

## [0.1.0] - 2026-11-20

The first release. An early version: expect rough edges and tell us about wrong verdicts.

### Added

- `shellwise check`: judges one Bash or PowerShell command and answers `ok`, `warn`, `break`,
  `danger` or `critical`, with a `Fix:` line.
- `shellwise hook claude-code`: the same check as a Claude Code `PreToolUse` hook.
- `shellwise lint`: checks a `.ps1`, `.sh` or `.bash` script file.
- `shellwise explain`: prints the documentation of one rule.
- Rules for commands that will not run (quoting and syntax traps of each shell), will hang
  (unbounded wait loops, endless follows) or will destroy (deletes of unchecked, protected or
  system locations, git commands that discard work). One document per rule in `docs/rules/`.
- A user config file and a per-repository `.shellwise.toml` that can only raise levels.
- `SHELLWISE=off` turns the check off.
