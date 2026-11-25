# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `bash-ps-call-operator` (break): a Bash command that starts with the PowerShell call operator
  (`& "C:/path/tool.exe" args`, also after `;` as `;&`), which bash refuses as a syntax error. The
  Fix runs the program by its path (`"C:/path/tool.exe" args`) when the rest of the command means
  the same in bash, else a sentence; it replaces the `parse-error` warn for that error.
- `gate-truncated-pipeline` now also warns in the Bash tool: a tee'd run or a configured gate
  command piped into `head` with a positive count (`npm test 2>&1 | tee run.log | head -n 5`),
  with a Fix that keeps the whole command, reads the whole stream and keeps the exit code
  (`cd sub && (set -o pipefail; … | tail -n 20)`).

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
- `wait-loop-unbounded` no longer takes a polled value for a counter because the polled command
  names it (`state=$(cat state)`, `count=$(grep -c x count.log)`), and reads PowerShell `++$k` as
  a counter.
- `wait-loop-unbounded` no longer takes a clock word inside a quoted string or a `$( )` for a
  deadline (`[ "$(git pull)" == "Already up to date." ]`); `"$SECONDS"` and `$(date +%s)` still are.
- `wait-loop-unbounded` now catches a condition whose bound does not end the loop by itself
  (`until grep -q ok log && [ $n -ge 1 ]`, `while A || bound`).
- The `wait-loop-unbounded` Fix of a Bash loop piped into a later stage or nested in another loop
  is a sentence: the fixed loop's failure would not stop the command there. Its counter no longer
  reuses a variable of the command (`i`, PowerShell `$I`).
- The PowerShell `follow-unbounded` Fix starts its job in the caller's folder (Windows PowerShell
  5.1 started it in Documents) and passes the caller's variables with `$using:`.
- `lint` keeps a ShellCheck SC1xxx finding at break only where the shellwise parser fails at the
  same place (its line, or the end of the file for an unterminated construct); a file Bash parses
  no longer fails because of an unrelated parse gap elsewhere in it.
- `Remove-Item`/`Set-Location` with `-Path:`/`-LiteralPath:` and a variable value (`-Path: $HOME`,
  `-Path:$HOME`, `-Path: "$HOME"`, `-Path: $env:USERPROFILE`) now read the value as the uncoloned
  spelling does, so a home-folder delete is critical again.
- `Remove-Item` reads `-Confirm:$false`, `-Recurse:$true`, `-WhatIf:$false` as the switch on or off.
- The `follow-unbounded` Fix keeps the command's other statements; its PowerShell job prints text.
- A variable set by `-Path:variable:t` or `Set-Variable -Name:t` makes a later delete of it dynamic.
- `git worktree remove` of the main working tree is critical from any folder, a linked worktree
  beside the main tree included.

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
