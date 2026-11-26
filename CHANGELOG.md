# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `wait-loop-unbounded`: a Bash loop whose condition compares the count of the shell's own
  background jobs (`while (( $(jobs -rp | wc -l) >= 4 )); do sleep 0.1; done`, and the `[ ]`,
  `test`, `[[ ]]` and `until … -lt` forms) reads as bounded: the count drops when a job ends.

## [0.2.0] - 2026-11-26

### Added

- `install.sh` and `install.ps1`: one-line installers that verify the release archive against
  `SHA256SUMS` and install `shellwise`; running one again updates the binary.
- `shellwise update`: replaces the binary in its own folder with the latest release; `--check`
  compares the installed and the latest version, `--notify` prints one line at most once a day
  when a newer release exists.
- `shellwise agent-setup`: prints a text to paste to your AI agent, which then registers
  shellwise in its host's hook that runs before a shell command and proves the wiring.
- `shellwise hook generic`: a hook for hosts that block a command on exit code 2, with the
  findings and their `Fix:` lines on stderr.
- A Claude Code plugin and marketplace manifest in the repository:
  `claude plugin marketplace add Borcioo/shellwise`, then
  `claude plugin install shellwise@shellwise`.
- Static Linux builds among the release assets: `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`. The install scripts pick them on Linux.
- `install.sh` and `install.ps1` among the release assets and in `SHA256SUMS`, so a pinned version
  has its own installer.

### Changed

- `shellwise lint` is faster on long files (a 500-line PowerShell script about a third faster, a
  500-line Bash script about a sixth); its output is unchanged.
- Bash arithmetic reads like the text around it: a `$(…)` inside `$(( ))`, `(( ))`, `let`,
  `[[ -eq ]]`, a `${a[…]}` subscript, `${s:o:l}`, `for (( ))` or a value assigned to a
  `declare -i` name reads like the same `$(…)` outside arithmetic, and a name set by `read` like
  the same name read as text. Arithmetic no longer makes a later relative delete an unknown
  location (`echo $(( $(git rev-list --count HEAD) )); rm -rf build` and
  `read n; (( n > 0 )); rm -rf build` no longer warn `delete-unknown-location`), and a substitution
  inside arithmetic no longer warns `opaque-destructive`: its command is judged on its own, as
  outside arithmetic. A `$(…)` that only a variable's value holds in a subscript
  (`x='a[$(cmd)]'; (( x ))`) is no longer marked. In a script file, a `read` or an `eval`
  anywhere no longer makes the whole file unreadable for arithmetic: `lint` now judges the
  counter loops and deletes it skipped (more `wait-loop-unbounded`, `delete-empty-expansion` on
  `d=x rm -rf "$d/"`, fewer `opaque-destructive`), and a long Bash file lints about a third
  faster. No rule id changed.
- The hook and `check` now block, as `wait-loop-unbounded`, a Bash wait loop that polls a count
  in arithmetic, in `let` (`while let "$(pgrep -c worker) > 0"`) or in an arithmetic `[[ ]]` test
  (any of `-eq`, `-ne`, `-lt`, `-le`, `-gt`, `-ge`) and that nothing bounds, as they already
  blocked its `[ ]` form (`while (( $(pgrep -c worker) > 0 )); do sleep 1; done`, the job throttle
  `while (( $(jobs -rp | wc -l) >= 4 )); do sleep 0.1; done`): put a counter or a deadline in
  the condition or run the loop under `timeout`, and throttle jobs with `wait -n` instead of
  `sleep`.

### Fixed

- `follow-unbounded`: the Bash Fix puts `timeout 60` after the follow's assignments and leading
  redirects (`LC_ALL=C timeout 60 tail -f log`) and keeps a line continuation before the name;
  under any wrapper other than `env`, `nice` and `nohup` (`command`, `exec`, `builtin`, `sudo`),
  or after an assignment to `PATH`, it gives a sentence that names the bounded form instead of a
  command. A bound after a wrapper counts (`nohup timeout 60 tail -f log` is ok); a duration of
  `0`, `inf` or `infinity` is no bound (`timeout 0 tail -f log` now warns, Fix
  `timeout 60 tail -f log`).
- `wait-loop-unbounded`: `timeout` with a duration of `0` (also `0s`, `00`, `0.0`), `inf` or
  `infinity`, after its options too (`timeout -k 5 0`, `timeout --signal=KILL 0`), no longer
  counts as a bound on a wait loop it runs, as it already did not on a follow: GNU `timeout`
  then sets no limit (`timeout 0 bash -c 'while true; do sleep 1; done'` now blocks). A duration the guard cannot
  read (`timeout "$T"`, `timeout "${T:-0}"`) still counts as a limit.
- `wait-loop-unbounded`: a `timeout` with a limit behind another wrapper now bounds the wait loop
  it runs, as it already bounded a follow: `sudo timeout 60 bash -c '<loop>'`, `env A=1 timeout 60
  …`, `nice timeout 60 …`, `nohup timeout 600 …` and `timeout 0 timeout 600 …` no longer block,
  and a follow in that child shell (`sudo timeout 60 bash -c 'tail -f log'`) no longer warns
  `follow-unbounded`. A chain whose every `timeout` sets no limit (`sudo timeout 0 …`,
  `timeout 0 timeout 0 …`) still blocks. A `timeout` bounds only what it runs, not the words the
  calling shell expands before it starts, bare or behind a wrapper: a loop in a substitution in
  an argument, an option value, the duration, a redirect, a here-document or an assignment
  (`timeout 60 echo "$(while true; do sleep 1; done)"`, `sudo -u "$(…)" timeout 60 …`,
  `timeout 60 cat <(…)`, `X="$(…)" timeout 60 …`, `timeout 60 bash -c "$(…)"`) now blocks, and a
  follow there warns, as one in the words of a PowerShell `Start-Job` that is waited for with a
  timeout (`Start-Job -Name "$(Get-Content log -Wait)" { … }`). Known miss: a loop or a follow
  the child shell sends to the background still reads bounded, now behind a wrapper as well
  (`sudo timeout 60 bash -c '<loop> &'`), as its bare twin (`timeout 60 bash -c '<loop> &'`) did.
- A command that does not parse for a reason other than an unclosed quote (an unclosed quote
  already blocks, with the wrapper or without it), or whose analysis cannot finish, and pipes
  static delete text into a shell behind a wrapper (`sudo -u root printf 'rm -rf x' | bash`,
  `timeout 5 printf …`) now reads `danger` (`parse-error-destructive`, `analysis-incomplete`), as
  it already did without the wrapper, instead of a warn. Static text that is only an argument of
  another command there also reads `danger` (`sudo cat f printf 'rm -rf x' | bash`). A command
  that parses reads as before.
- A PowerShell delete through an alias the same command defines before it
  (`Set-Alias zz Remove-Item; zz C:\Windows -Recurse`, `Set-Alias -Name zz -Value Remove-Item;
  zz .git -Recurse`, also inside `& { }` or an `Invoke-Expression` string) is judged as the cmdlet
  the alias names; an alias the guard cannot read, or one read more ways than it follows, warns
  `dynamic-target` on a protected, unreadable or piped target.
- Bash and Git Bash: a PowerShell alias cmdlet in the command (`Import-Alias x`, `ipal x`) or an
  argument holding the text `alias:` (`grep -r alias: .`, a commit message) is a program or plain
  text there and no longer makes the delete guard read every variable as one the command may set: with
  32 or more values of one Bash alias, `d=/; rm -rf "$d"` is `critical` again instead of a
  `dynamic-target` warn, and a relative folder through a variable reads as written in place.

## [0.1.1] - 2026-11-25

### Added

- A combined `SHA256SUMS` file among the release assets, next to the per-archive `.sha256` files.
- `examples/integration-config.toml`: a config for a host that replaces a stricter guard: it
  raises the rules that only warn by default to break or danger and enables the `git_no_verify`
  policy.
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
