---
title: Exit codes and JSON
description: "Every exit code per command, the check --json shape and the hook claude-code reply shapes."
---

## Exit codes

### check

| Code | Meaning |
|---|---|
| 0 | `ok` or `warn` |
| 1 | `break` |
| 2 | `danger` (also stdin still open at the deadline, or input over 1 MiB) |
| 3 | `critical` |
| 64 | usage error |
| 74 | stdin could not be read |

### lint

| Code | Meaning |
|---|---|
| 0 | no findings, or `warn` at most |
| 1 | `break`, `danger` or `critical` |
| 64 | file refused (name, size, encoding) or usage error |
| 74 | file cannot be opened or read, or the config did not load |

### explain

| Code | Meaning |
|---|---|
| 0 | the rule's text, or the note for a ShellCheck code, was printed |
| 64 | unknown id, or no id |

### hook claude-code

| Code | Meaning |
|---|---|
| 0 | every answer, `deny` and `ask` included: the decision is in the JSON |
| 64 | usage error |

### hook generic

| Code | Meaning |
|---|---|
| 0 | let the command run: `ok`, `warn`, no command in the event, nothing destructive in an unreadable event, `SHELLWISE=off`, an internal error |
| 2 | block the command: `break` or worse, or a destructive command in an unreadable event |
| 0 | usage error (with the error on stderr) |

### update

| Command | Code | Meaning |
|---|---|---|
| `update` | 0 | updated, or already current |
| `update` | 1 | refused or failed |
| `update --check` | 0 | the latest release is not newer |
| `update --check` | 1 | a newer release exists |
| `update --check` | 2 | the latest version could not be read |
| `update --notify` | 0 | always |

### agent-setup

| Code | Meaning |
|---|---|
| 0 | the text was printed |

### Usage errors

A usage error is an unknown command or flag, a missing argument, an invalid value, or `--check`
with `--notify`. The error goes to stderr.

| Case | Code |
|---|---|
| a usage error in any command except `hook generic` | 64 |
| a usage error in `hook generic` | 0 |
| `shellwise` with no command (prints the help) | 64 |
| `--help`, `help`, `--version` | 0 |

The binary also has a `bench` command for the maintainers; it is not part of the interface.

## check --json

`shellwise check --json` prints one line of JSON:

| Field | Type | Meaning |
|---|---|---|
| `version` | number | The shape's version, `1`. |
| `level` | string | The verdict: the highest finding level, `ok` when there are none. |
| `findings` | array | Every finding, config warnings included. |
| `findings[].rule` | string | The rule id. |
| `findings[].level` | string | `ok`, `warn`, `break`, `danger` or `critical`. |
| `findings[].message` | string | What is wrong. |
| `findings[].fix` | string or `null` | The correction, without the `Fix: ` prefix. |
| `findings[].span.start` | number | Byte offset where the finding starts in the command. |
| `findings[].span.end` | number | Byte offset where it ends. |

The exit code is the same as without `--json`.

```sh
shellwise check --shell bash --json -- 'ls'
```

```json
{"version":1,"level":"ok","findings":[]}
```

```sh
shellwise check --shell bash --json -- 'rm -rf "$DIR/"'
```

```json
{"version":1,"level":"danger","findings":[{"rule":"delete-empty-expansion","level":"danger","message":"if the variable or substitution in `\"$DIR/\"` is empty, this deletes `/`, the file-system root","fix":"write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf \"${X:?}/build\"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end","span":{"start":0,"end":14}}]}
```

A config warning has `fix` set to `null` and the span `0..0`:

```json
{"version":1,"level":"break","findings":[{"rule":"follow-unbounded","level":"break","message":"`tail` follows its input without end: nothing in the command stops it, so the call runs until the host's timeout","fix":"timeout 60 tail -f app.log","span":{"start":0,"end":15}},{"rule":"config-repo-ignored","level":"warn","message":"repo config key `scratch_dir` is ignored: a repo file may only raise levels and add protected paths","fix":null,"span":{"start":0,"end":0}}]}
```

## hook claude-code replies

One JSON object on one line, ending in a newline, or no output at all.

| Verdict | Shape |
|---|---|
| `ok` | no output |
| `warn` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"<text>"}}` |
| `break`, `danger`, `critical` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"<text>"}}` |
| only listed `danger` findings | the same with `"permissionDecision":"ask"` |

`<text>` holds the findings above `ok`, highest level first, joined by line breaks. Each finding
is `shellwise: <level> <rule>: <message>`, then `Fix: <fix>` on the next line when it has one.
Each of the two lines is cut to 600 characters, ending in `…`. The whole reply stays under 9,000
bytes; the findings left out are counted in a last line `shellwise: <n> more findings not shown`.

An `ask` reply, with `ask_instead_of_deny = ["delete-empty-expansion"]`:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"shellwise: danger delete-empty-expansion: if the variable or substitution in `\"$DIR/\"` is empty, this deletes `/`, the file-system root\nFix: write each variable as `${X:?}` so an empty value stops the command, for example `rm -rf \"${X:?}/build\"`; or, if this is intended, run the same command again with ` # shellwise: allow` at its end"}}
```

A `deny` for an event that is not valid JSON but holds a destructive command:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"shellwise: danger analysis-incomplete: the command could not be analysed (the hook event is not valid JSON); the raw scan flags `rm -rf x` as destructive\nFix: split the command into simpler calls so each can be checked"}}
```

`hook generic` writes the same `<text>` to stderr, without the 9,000-byte limit.
