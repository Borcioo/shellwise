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

## Parsers, build and latency

A throwaway crate outside the repo with `tree-sitter`, `tree-sitter-powershell` and `brush-parser`
dumped, per corpus row, the error status and the segmentation: every command (also nested ones) as
its list of elements, plus comments and static method calls for PowerShell. The same rows went
through each shell's own parser as the reference. The corpus was a snapshot of 50,787 rows (28,453
PowerShell, 22,334 Bash, 1,605 destructive) over 31 calendar days, 28 of them with calls; it grew by
137 rows after the baseline above was recorded. No corpus command was executed.

### Build

| | Windows 11 x64 | WSL Ubuntu 22.04 |
|---|---|---|
| Toolchain | Rust 1.97.1, MSVC (VS Build Tools 2022 17.14) through `cc` | Rust 1.100.0 (rustup installed for the spike), gcc 11.4 |
| `cargo build --release` | passes, no flags or env needed | passes |
| Release binary (unstripped, final build) | 1,888,768 bytes | 2,370,064 bytes |

Versions: `tree-sitter` 0.27.2, `tree-sitter-powershell` 0.26.6, `brush-parser` 0.4.0 (all MIT), plus
`serde_json` 1.0.154 for the event; 107 dependencies in the lockfile. `brush-parser` brings a
snapshot-test crate and its helpers into the normal dependency tree. `cargo deny check` (0.21.0)
passes advisories, bans, licences and sources with an allow list of MIT, Apache-2.0 (also with the
LLVM exception), Unlicense, Zlib, BSD-2-Clause and Unicode-3.0; bans warn about five duplicated
crates. Built from the same final source on both systems, the Linux binary's dump equals the
Windows binary's on every snapshot row: 28,453 PowerShell rows (tree-sitter, variant (a) below) and
22,334 Bash rows (brush-parser on the original text), 0 rows differing.

### PowerShell: tree-sitter-powershell against `Parser::ParseInput`

Reference: PowerShell 7.7.0 `ParseInput`; an element is a `CommandAst` element's extent text, a
row has an error when `ParseInput` reports any. tree-sitter counts an error on any ERROR or MISSING
node. Lowering applied before comparing, as Task 5 would: children of one argument that tree-sitter
splits (`a, b`, `-Name:value`) are joined back into one element; redirection nodes are dropped.
Variant (b) also reads a token shaped like a glued redirection (`2>$null`, a lone `1>` followed by
its target) as a redirection, which the grammar does not.

| Measure | (a) | (b) | Threshold |
|---|---:|---:|---|
| Equal error status | 96.80 % (27,542 of 28,453) | 96.80 % | ≥ 99 % |
| Equal segmentation | 94.36 % | 96.91 % | — |
| Silent mismatches (both parse, segmentation differs) | 3.94 % (1,120) | 1.44 % (409) | ≤ 0.5 % |
| Mismatches on destructive rows | 77 of 1,058 | 65 | 0 unlisted |
| Gap rows correct | 22 of 29 | 22 of 29 | all |

Errors only tree-sitter reports (886 rows; 25 rows the other way), bucketed by the text around the
first ERROR or MISSING node only, so each count is a floor: a variable glued to a path (`$name\dir`, `$env:NAME/x`) 332; a numeric multiplier suffix
(`1MB`) 156; a bare word starting with `@` (a package scope) 27; a parameter glued to a quoted
value 25; `??` and `?.` 15; the ternary operator 10; an error at the first character 19; a
`switch` clause 1; other shapes (escaped quotes inside double-quoted strings, recovery that swallows
the following statements) 301. A rescan of the whole command of those 301 rows finds one of the
named shapes in 165 of them (a variable glued to a path in 124, a multiplier suffix in 37, an `@`
word in 19, `??`/`?.` in 6, a glued quoted value in 4); the reviewer's broader patterns found 218.

Silent mismatches in (a): a glued redirection or a numbered stream redirect read as an extra
argument (711 rows, the difference between (a) and (b)); a range inside parentheses (`(1..5)`) read
as an extra command (357); other argument splits (44): a method call on a variable or a
here-string (`$x.Trim()`) split from its argument list, a `$(…)` glued to the end of a word split
off so the first part reads as a static literal, backslash-escaped double quotes inside a
double-quoted argument, `${name}:` losing its colon, `-split '\s+'` joined into one element,
`(Get-Date).AddDays(-5)` split from its argument list; comments (8). Even with every argument split
repaired in lowering, the phantom range commands alone are 1.25 % of the rows.

Destructive mismatches in (a), by mechanism: 52 rows where only tree-sitter reports an error (fail
closed: 31 of them are `ok` rows, so `danger` on a command that ran); 12 with a glued redirection
read as an extra target; 10 with a phantom range command; 2 where a `$(…)` glued to a path is split
so the target reads as a static path ending in `$` (the delete guard would judge the wrong, static
path); 1 member call after a here-string split.

Gap rows (the PowerShell rows of the baseline-guard "Known gaps" list, written as synthetic commands;
`ParseInput` gave the expected command names on all 24 rows that have one): wrong are a comment
glued to a number (`1# …` read as a command, its comment lost); U+00A0 and U+3000 as separators
(kept inside the next command name); U+00A0 before a comment (the comment read as arguments); a
here-string with CR-only line ends (parse error); typographic quotes around an assigned string (read
as a command); `--%` (the verbatim rest is one element instead of two: representation only).
Correct: the other glued-comment forms, block comments, `\f`, all six assignment forms, call by
path, `cd..`, `cd\`, a static `Delete` method.

### Bash: brush-parser against bash

Reference: Git Bash 5.2.37 parses without executing. Each row is the body of a function imported
through the environment (`BASH_FUNC___sw%%='() { <row>⏎}'`, then `declare -f __sw`); bash refuses an
import that holds anything after the closing brace, so a row cannot break out. Proof first, on 5
rows that create a canary file when run (plain, breaking out of the braces, `$(…)`, in a heredoc,
in backticks): the plain-script form created the canary, the import form did not on any row, and
the working directory of the corpus run was still empty after all 22,334 rows. brush-parser then
read both the row and bash's canonical text; words are compared as values (quotes removed, `$'…'`
decoded, each expansion one marker), because bash reprints quoting and spacing inside `$(…)`.
Commands inside `$(…)`, backticks, `${x:-…}`, process substitutions and expanding heredoc bodies
count as commands.

| Measure | Value | Threshold |
|---|---:|---|
| Equal error status | 99.996 % (22,333 of 22,334) | ≥ 99 % |
| Silent mismatches | 0.148 % (33) | ≤ 0.5 % |
| Mismatches on destructive rows | 0 of 547 | 0 unlisted |
| Gap rows correct | 17 of 19 | all |

0.148 % is a floor: brush-parser reads both the row and bash's canonical text, so a misreading it
makes the same way on both sides does not show.

The one error mismatch: `case` with unparenthesised patterns inside `$(…)`, which brush rejects.
Of the 33 silent rows, 32 are rows the reference cannot judge: bash prints a heredoc followed by
`||`/`&&` with the operator at the start of the next line, which no parser reads back (on the 6 of
them checked by hand, brush's command names for the original were right); 1 is the host setup's own CRLF
normalisation dropping a CR from a `$'…'` word. Heredoc rows: 3,834, 0 error mismatches, 32 silent,
all of them the printer case. `$'…'` rows: 246, 0 error mismatches, 2 silent (one of each cause).
The 10 rows bash rejects (unclosed backticks, a heredoc closed by the end of input, which the
wrapper turns into an error) brush rejects too. Gap rows wrong: a heredoc delimiter written `$'EOF'`
and one written `$(x)`; brush reports a parse error on both (fail closed, not silent). Correct:
`{ …; }` and `( … )` piped, `while`, an unquoted heredoc holding `$(…)`, `${x:-$(…)}`, backticks,
process substitution in all three forms, `cd` in a pipeline stage or background job, brace
expansion, `$'…'`, line continuations.

### Destructive `ok` rows with a dynamic target

From the reference segmentation, a target word holding a variable, an expansion, a wildcard or a
leading `~`, or a delete with no target word in PowerShell (pipeline input); `data/destructive.toml`
selects the commands. Known-answer check: 12 synthetic rows, the expected 6 counted.

| Shell | Destructive `ok` | Dynamic | Variable or expansion | `[IO.*]::Delete` with a variable | Wildcard only | Other |
|---|---:|---:|---:|---:|---:|---:|
| PowerShell | 834 | 333 | 159 | 149 | 18 | 7 (pipeline input) |
| Bash | 493 | 127 | 103 | — | 23 | 1 (`~`) |

460 of 1,327 rows (34.7 %): 14.8 per calendar day, 16.4 per day with calls; without the wildcard and
`~` rows, 13.5 per calendar day. FP meter 2 allows 2 per day, so with the default `danger` for a
dynamic target the meter cannot be met without the shim (v1.1) or another source of the values.
tree-sitter's own parse errors add 31 more destructive `ok` rows (1.0 per day) through the fail-closed
rule.

### Latency

The spike binary in hook mode reads a PreToolUse event from stdin, parses `tool_input.command` with
the parser for `tool_name` and exits 0 with no output. 2,000 sequential spawns per form from one
Python driver, wall time from spawn to exit, every exit code checked; Defender real-time protection
on; other Claude sessions were running on the machine. The baseline is the Python guard called as
`python -I -S baseline_guard.py --pwsh-all` (Python 3.12, the interpreter `py -3` finds), on the same
PowerShell event (three commands, one of them a delete). The shell form is Git's `bin\sh.exe -c`.

| Form | p50 ms | p99 ms |
|---|---:|---:|
| Python guard, exec | 103.5 | 136.9 |
| Python guard, `sh -c` | 197.1 | 315.3 |
| spike, exec, PowerShell event | 12.4 | 16.8 |
| spike, `sh -c`, PowerShell event | 96.4 | 160.5 |
| spike, exec, Bash event | 12.1 | 17.4 |
| spike, `sh -c`, Bash event | 99.3 | 167.3 |

Git's `sh` costs about 85 ms per spawn by itself, so the hook entry should use the exec form
(`command` + `args`), where the binary is 8 times faster than the Python guard at p50.

### Decision

Rule: keep a parser only if all gap rows are correct, no destructive row has an unlisted mismatch,
silent mismatches are at most 0.5 % and equal error status is at least 99 %.

| Parser | Gap rows | Destructive, unlisted | Silent | Equal error status | Result |
|---|---|---|---|---|---|
| tree-sitter-powershell | 22 of 29: fail | 0 (77 listed above, 2 of them a wrong static target) | 3.94 % (1.44 % with the redirection workaround): fail | 96.80 %: fail | not kept |
| brush-parser | 17 of 19: fail (both wrong rows fail closed) | 0 of 547 | 0.148 %: pass | 99.996 %: pass | fails on the gap rule only |

`stop: goal-unreachable`. PowerShell misses three of the four thresholds; the design's fallback is
a dedicated Rust lexer scoped to what the rules need, with `ParseInput` as the test oracle. brush-parser
meets the corpus thresholds and misses two heredoc-delimiter gap rows, which it rejects as parse
errors rather than misreading. Separately, destructive `ok` rows with a dynamic target run at 14.8
per day against the 2 per day of FP meter 2: the owner decides before Task 4.

Owner decisions:

- PowerShell: fork the tree-sitter-powershell grammar and re-measure it with the same thresholds.
- Dynamic targets: the shim moves into v1.
- Bash: brush-parser is kept; the two heredoc-delimiter gap rows fail closed.
