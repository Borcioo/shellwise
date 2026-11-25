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
