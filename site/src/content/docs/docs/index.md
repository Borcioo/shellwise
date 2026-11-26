---
title: Overview
description: What shellwise is, what it catches, its five levels, and what it is not.
---

shellwise is a guard and linter for the shell commands AI coding agents run. It reads a Bash or
PowerShell command before the shell runs it and stops the careless mistakes: the command that
will not run, the one that will hang, and the one that deletes the wrong thing.

Every finding carries a `Fix:` line the agent can copy, so it corrects the command and carries on.

## How it runs

- As a hook: your agent host starts `shellwise hook …` before each shell command, passes the
  command on stdin and reads the verdict back. See
  [Claude Code](/shellwise/docs/agents/claude-code/), [Codex CLI](/shellwise/docs/agents/codex/)
  and [other hosts](/shellwise/docs/agents/other/).
- By hand: `shellwise check` checks one command, `shellwise lint` checks a `.ps1`, `.sh` or
  `.bash` script.

Checking a command needs no service, no network and no interpreter. Only `shellwise update`
reaches the network.

## What it catches

| Kind | Example | What shellwise says |
|---|---|---|
| Will not run | `Write-Output "$name: done"` | `break ps-var-colon`: PowerShell reads `$name:` as a drive. Fix: `"${name}:"` |
| Will hang | `until grep -q done build.log; do sleep 15; done` | `break wait-loop-unbounded`: nothing bounds the loop. Fix: the same loop with a counter |
| Will hang | `tail -f app.log` | `warn follow-unbounded`. Fix: `timeout 60 tail -f app.log` |
| Will destroy | `rm -rf "$DIR/"` | `danger delete-empty-expansion`: an empty `DIR` makes this `rm -rf /`. Fix: write the variable as `${DIR:?}` |
| Will destroy | `Remove-Item -Recurse -Force C:\Windows\Temp\..` | `critical delete-critical`: a system folder |

One of them, checked by hand:

```text
$ shellwise check --shell bash -- 'until grep -q done build.log; do sleep 15; done'
break wait-loop-unbounded [0..47]: the loop polls and nothing bounds it: no counter, deadline or timeout ends it, so when what it waits for never comes it runs forever
  Fix: for i in $(seq 1 40); do grep -q done build.log && break; sleep 15; [ "$i" -lt 40 ]; done  # when you wait for a process, wait on the process (timeout 600 tail --pid=<pid> -f /dev/null) rather than on a line in its log
```

Each rule has its own page under [Rules](/shellwise/docs/rules/); `shellwise explain <id>` prints
the same text.

## Levels

| Level | Meaning | Effect in a hook |
|---|---|---|
| `ok` | nothing to say | runs, no output |
| `warn` | probably fine, worth a note | runs, the agent gets the note |
| `break` | will fail or hang as written | not run, the agent gets the fix |
| `danger` | may destroy work | not run, unless repeated with ` # shellwise: allow` at its end |
| `critical` | system files, the repository itself | never run; the marker has no effect |

Deleting is allowed and signalled; only the dangerous deletes are refused. A command shellwise
does not know is not blocked for being unknown:

```text
$ shellwise check --shell bash -- 'frobnicate --all --force'
ok
```

The `warn` note reaches the agent through `hook claude-code`. Through `hook generic` it goes to
stderr, and whether the agent sees it depends on the host. The allow marker also confirms most
`break` findings; it and its limits are described in [Quick start](/shellwise/docs/quick-start/).

## When the analysis cannot finish

The analysis can stop before it reaches a verdict: invalid UTF-8, input over 64 KiB, the
deadline, an internal failure, or a config file that did not load. The finding is then
[`analysis-incomplete`](/shellwise/docs/rules/analysis-incomplete/), and its level comes from a
scan of the raw text:

- `danger` when the scan finds a command that deletes or discards data (or a .NET `Delete()`
  call); the message names it.
- `warn` when it finds none. The command runs, and the agent gets the reason.

Input over 1 MiB, or stdin still open at the deadline, is `danger` without a scan: the text is
unknown. In `hook claude-code`, an event that could not be read whole is denied, unless the part
that was read names a tool that is not a shell.

The allow marker has no effect on `analysis-incomplete`: without a parse nothing shows that the
marker is a comment.

```text
$ printf 'git status \377' | shellwise check --shell bash
warn analysis-incomplete [0..14]: the command could not be analysed (invalid UTF-8); its raw text names no command that deletes or discards data
  Fix: split the command into simpler calls so each can be checked
```

## What it is not

shellwise guards against careless mistakes of an honest agent. It is not a security boundary.

- It does not stop someone who deliberately works around it.
- It is not a permission system: it does not decide which tools an agent may use.
- It does not replace backups, version control or reading the diff.

What it does not see yet is listed under [Limits](/shellwise/docs/limits/).

## Next steps

1. [Install](/shellwise/docs/install/) the binary.
2. Follow the [Quick start](/shellwise/docs/quick-start/): check a command by hand, read a
   finding, then wire shellwise into your agent.
