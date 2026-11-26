---
title: shellwise hook
description: Run shellwise as an agent host's pre-command hook, for Claude Code or any host that blocks on exit code 2.
---

`shellwise hook` reads the host's hook event (JSON) on stdin and answers before the shell runs
the command. There are two adapters.

| Command | For | Answer |
|---|---|---|
| `shellwise hook claude-code [--config FILE]` | Claude Code `PreToolUse` | JSON on stdout, exit 0 (64 on a usage error) |
| `shellwise hook generic [--shell SHELL] [--config FILE]` | hosts that block on exit code 2 | exit 0 or 2, findings on stderr |

`--config FILE` is an integration config file; see
[Configuration](/shellwise/docs/configuration/). Setup per host: [Claude Code](/shellwise/docs/agents/claude-code/),
[Codex CLI](/shellwise/docs/agents/codex/), [other hosts](/shellwise/docs/agents/other/).

## hook claude-code

### Event fields it reads

| Field | Use |
|---|---|
| `tool_name` | `Bash` or `PowerShell` is checked; any other tool gets no output. |
| `tool_input.command` | The command, a string. |
| `cwd` | The working directory; the repo file is looked for from here. An empty value is ignored. |

`Bash` is read as Git Bash on Windows and as bash elsewhere; `PowerShell` as PowerShell 7.
Other keys are ignored. Empty stdin gets no output.

### Reply per level

| Verdict | Reply |
|---|---|
| `ok` | no output |
| `warn` | `additionalContext` with the findings; no decision, the command runs |
| `break`, `danger`, `critical` | `permissionDecision` `deny`, the findings as the reason |
| only `danger` findings, each listed in `ask_instead_of_deny` | `permissionDecision` `ask` |

The adapter never answers `allow`, so the host's own permission rules still apply. A reply holds
the findings highest level first, each as `shellwise: <level> <rule>: <message>` and its `Fix:`
line. It stays under 9,000 bytes: findings that do not fit are counted in a last line,
`shellwise: <n> more findings not shown`. The exact JSON is on
[Exit codes and JSON](/shellwise/docs/reference/exit-codes-and-json/).

A `warn` reply:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"shellwise: warn follow-unbounded: `tail` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout\nFix: timeout 60 tail -f app.log"}}
```

A `deny` reply:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"shellwise: break ps-var-colon: in a double-quoted string PowerShell reads $name: as a variable on a drive called name, and refuses the whole command\nFix: write \"${name}:\" instead of \"$name:\""}}
```

### Events it cannot read

- Not valid JSON, no tool name, or no command string: the raw text is scanned. A `deny` at
  `danger` (`analysis-incomplete`) follows when it holds a destructive command or the scan gives
  no answer; otherwise there is no output.
- Stdin still open after 1.5 seconds, or over 1 MiB: a `deny` at `danger`, unless the bytes read
  so far already name a tool that is not a shell.

## The allow marker

A command that ends with the trailing comment `# shellwise: allow` has its `break` and `danger`
findings lowered to `ok`, so it runs. It does not lower `critical`, the length rules,
`parse-error`, `parse-error-destructive` or `analysis-incomplete`. The `Fix:` line of a `danger`
finding says when to use it. The agent adds it after reading the finding; it applies to the one
command it ends.

## Timeouts

| Step | Bound |
|---|---|
| Reading the event | 1.5 s from the start |
| Loading the config | 1 s after the event is read, at most 1.5 s from the start |
| The analysis | `min(walk_budget_ms, hook_timeout_ms - 1500)` from the start; 8 s by default |
| Raw scan after a failed analysis | at least 500 ms more |

Set the host's hook timeout and `hook_timeout_ms` to the same value, so shellwise answers before
the host gives up. `hook_timeout_ms` defaults to 10,000 and may not be below 3,000.

## hook generic

### Choosing the shell

| Case | Shell |
|---|---|
| `--shell` given | that shell: `pwsh`, `powershell5`, `bash` or `gitbash` |
| no `--shell`, `tool_name` or `toolName` is `powershell` (any case) | `pwsh` |
| otherwise, on Windows | `pwsh` |
| otherwise | `bash` |

Several hosts call their shell tool `Bash` whatever it runs. On Windows, always pass `--shell`.

### Where it finds the command

The first string at `tool_input.command`, `command`, `tool_info.command_line`, or `command`
inside `toolArgs` when `toolArgs` is a JSON string. `cwd` is read as for `claude-code`. An event
with no command in any of these places gets exit 0 and no output.

### Exit codes and stderr

| Case | Exit | stderr |
|---|---|---|
| `ok` | 0 | nothing |
| `warn` | 0 | the findings |
| `break` or worse | 2 | the findings, highest level first, with their `Fix:` lines |
| not JSON or not read whole, raw text destructive | 2 | an `analysis-incomplete` finding |
| not JSON or not read whole, nothing destructive | 0 | `shellwise: event not read (<reason>); the command was not checked` |
| usage error (unknown flag, bad `--shell`) | 0 | the usage error |
| internal error | 0 | `shellwise: internal error; the command was not checked` |

`ask_instead_of_deny` has no effect here. A blocked command:

```sh
printf '%s' '{"tool_input":{"command":"echo '"'"'abc"}}' | shellwise hook generic --shell bash
```

```text
shellwise: break parse-error: bash: unterminated single quote at 1,6: the ' opened at column 6 is never closed, so the shell refuses the whole command and runs none of it
Fix: close the ' opened at column 6, or write the text to a file and pass the file
```

Exit code 2.

## Switching it off

With `SHELLWISE=off` in the environment, both adapters exit 0 with no output before they read
the event. Any other value leaves shellwise on.
