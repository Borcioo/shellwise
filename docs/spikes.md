# Spikes

## PreToolUse contract

Claude Code 2.1.326, the build the desktop app (6.6395.0) runs; the CLI on PATH was 2.1.327 and was
not used. Windows 11, Git for Windows installed, PowerShell 7.7. Every probe ran `claude -p` in a fresh
config directory against a local stub of the Messages API that answers with scripted `tool_use`
blocks; no real model. Host-auth variables were stripped, `CLAUDE_CODE_CHILD_SESSION=1` stayed set and
`remoteControlAtStartup` was `false`. Each probe carried its own text; the proof is the stub's
request log (what the model would receive) and a canary file the command creates, never an exit
status.

### Output shapes

All replies are one JSON object on stdout, exit 0:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny", "permissionDecisionReason": "<text>"}}
```

| Reply | Tool ran | What the model receives |
|---|---|---|
| `deny` + reason | no, in `default` and `bypassPermissions` | `tool_result`, `is_error: true`, text `PreToolUse:Bash hook error: <reason>` |
| `ask` + reason, `-p` (any mode, with or without an allow rule) | no | `tool_result`, `is_error: true`, text `<reason>` (no prefix); listed in the result's `permission_denials` |
| `ask` + reason, SDK host (`--permission-prompt-tool stdio`), `default` or `bypassPermissions` | only if the host answers allow | the host gets a `can_use_tool` request (below); on a host deny the `tool_result` is the host's message |
| `allow` + `additionalContext` | yes, **even where the permission rules would have asked** (no allow rule, write outside the working directory) | a separate text block in the next request: `PreToolUse:Bash hook additional context: <text>` |
| `additionalContext` alone (no decision) | as the permission rules decide (ran with an allow rule; refused without one) | the same text block as above, in both cases |
| no output | yes | nothing |

`ask` never turns into an allow: `-p` refuses it in every mode, `bypassPermissions` included, and an
SDK host is always asked, in bypass mode too. `allow` skips the permission system, so it is never the
answer for a finding.

The SDK host's request for an `ask`:

```json
{"type": "control_request", "request_id": "<id>", "request": {
  "subtype": "can_use_tool", "tool_name": "Bash", "display_name": "Bash",
  "input": {"command": "<command>", "description": "<description>"}, "description": "<description>",
  "decision_reason": "<reason>", "decision_reason_type": "hook",
  "decision_reason_hook_event": "PreToolUse", "decision_reason_hook_source": "settings",
  "tool_use_id": "<id>"}}
```

Lengths: a 3,034-character one-line reason, a 40-line reason, a 9,081-character one-line context and a
250-line context all reached the model whole.

### Event on stdin

Keys: `session_id`, `transcript_path`, `cwd`, `permission_mode` (`default`, `bypassPermissions`),
`hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, `prompt_id`, `effort`. `cwd` uses
backslashes. `tool_input` for Bash: `command`, `description`, and `run_in_background` when set; for
PowerShell: `command`, `description`.

### Which tools reach `Bash|PowerShell`

The loaded tools whose input has a `command` field are Bash and PowerShell; among the deferred tools,
Monitor. With one hook on `Bash|PowerShell` and one on `*`:

| Call | `Bash\|PowerShell` hook sees | `*` hook sees |
|---|---|---|
| Bash | `tool_name: "Bash"` | `Bash` |
| Bash, `run_in_background: true` | `Bash`, with `run_in_background` | `Bash` |
| PowerShell | `PowerShell` | `PowerShell` |
| Monitor | `tool_name: "Bash"`, `tool_input` `{command, description}` | `Monitor`, with `timeout_ms` |

So a Monitor command reaches the adapter as a Bash event; a hook registered on `*` would see the
name `Monitor` instead.

### Failures: missing binary and timeout

Two spawn forms: `command` alone runs through a shell (Git Bash here, which says
`bash: line 1: <path>: No such file or directory`); `command` + `args` spawns the executable
directly (`ENOENT: no such file or directory, uv_spawn '<path>'`).

| Case | `onFailure` unset (`continue`) | `onFailure: "block"` |
|---|---|---|
| binary missing, shell form | tool runs; the model sees nothing; the stream gets `{"type":"system","subtype":"informational","tag":"hook_no_verdict","hook_no_verdict":{"hook_event":"PreToolUse","timed_out":false}}` | tool refused; `tool_result` `is_error: true`: `PreToolUse:Bash hook error: [<command>]: failed; blocking because onFailure is "block"` + the shell's error |
| binary missing, exec form | same as above | same, with the `ENOENT` line |
| hook sleeps past `timeout: 3` | tool runs after ~3 s; `hook_no_verdict` with `timed_out: true`; the hook process is killed (its late output never arrives) | tool refused: `…: timed out; blocking because onFailure is "block"` |

The adapter's fail-closed rule therefore covers only a hook that runs: a missing binary or a timeout
lets the command through unless the hook entry sets `"onFailure": "block"`.

### Environment: hook vs the tools

The host process had no `HOME` (the desktop app sets none).

| Variable | Hook, shell form (Git Bash) | Hook, exec form | Bash tool | PowerShell tool |
|---|---|---|---|---|
| `HOME` | Windows path of the profile | unset | MSYS path of the profile (`/c/…`) | `$env:HOME` empty; `$HOME` = profile |
| `USERPROFILE` | Windows path | Windows path | Windows path | Windows path |
| `TEMP` / `TMP` | Windows path | Windows path | Windows path | Windows path |
| `TMPDIR` | unset | unset | MSYS path of `TEMP` | unset |
| `MSYSTEM` | `MINGW64` | unset | `MINGW64` | — |
| `CLAUDE_PROJECT_DIR` | drive letter, forward slashes | backslashes | — | — |
| `PATH` | Git's `mingw64/bin`, `usr/bin`, `bin` prepended | the host's | — | — |
| working directory | the session cwd | the session cwd | MSYS form | Windows form |

Variables the CLI adds to every hook: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_SESSION_ID`,
`CLAUDE_PID`, `CLAUDE_PROJECT_DIR`, `CLAUDE_EFFORT`, `CLAUDE_CODE_SESSION_ATTENDED` and its messaging
socket and token. Resolving `~` or `$HOME` for a Bash command takes the profile from `USERPROFILE`
(in its MSYS form for Git Bash), never from the hook's own `HOME`, which is absent in exec form and in
Windows form in shell form.

### Not covered

An interactive terminal session was not driven (no TTY in the probe); the SDK host path is the one
the desktop app uses.
