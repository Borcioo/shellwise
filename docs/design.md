# shellwise — design

Status: approved by the owner on 2026-11-18.

## Intent

AI coding agents waste turns on shell commands that break for mechanical reasons (quoting across
shells, `.bat` re-parsing, MSYS path mangling, CRLF, truncated one-liners) and occasionally run
commands that destroy work (recursive delete through a junction, `git checkout -- <path>`,
`reset --hard`). `shellwise` is a single fast binary the agent's host calls before every shell
command. It answers: **will this command break, or will it do damage?** — with a level, a one-line
reason and a concrete fix, so the agent rewrites the command instead of running it and reading a
cryptic error.

Why a new tool: no existing tool lints "will this break" (research 2026-11-18: shellfirm, dcg, Codex
command_safety, ShellCheck, PSScriptAnalyzer); none handles PowerShell plus Windows junctions; dcg's
licence excludes anyone acting for Anthropic (not forked, not read for code). The host setup's Python
baseline-guard proved the rules but hit the limit of a hand-written lexer: about 50 documented gaps, and
six review rounds could not make loop-variable values trustworthy. A real parser closes most lexer
gaps; values only the shell knows stay unknown, so destructive commands with them fail closed.

## Goals (v1)

1. **Replace the host setup's Python baseline-guard** for both tools (PowerShell, Bash): all 24 rule ids it
   holds today (14 installed, counting `git-unreadable`, + 10 in the uninstalled full guard), with the same or better catch rate
   within the false-positive budget below on the real corpus.
2. **Encode the mechanical traps** of `windows-dev-env` and the "Windows shell" rules, so those prose
   bullets can be deleted from the host setup (table below). A new rule enters v1 only with at least
   one real failure in the corpus or a measured trap already written in the skill.
3. **Delete guard with target resolution:** resolve the real target of a recursive delete (literal
   path, `~`, known env vars, globs, the `cd` earlier in the same command, the event's `cwd`), stat
   it, and refuse when it is a drive root, home, the root of the event's `cwd` repo or a parent of
   it, or when the tree
   holds a junction/symlink/mount whose target is outside the tree.
4. **Fast:** p50 ≤ 5 ms, p99 ≤ 15 ms per hook call on Windows for commands that need no folder walk
   (measured as a spawned process through the real hook, Defender on); a binary under 10 MB.
5. **Open contract:** a Claude Code PreToolUse adapter first; any other agent uses
   `shellwise check` with JSON on stdout and an exit code.

## Non-goals (v1)

- Sandboxing or replacing the host's permission system.
- A broad catalogue of destructive commands outside files and git (cloud CLIs, databases, k8s):
  later rule packs.
- Full cmd.exe as a top-level shell (cmd appears only nested: `cmd /c "…"`, `.bat` arguments).
- Rewriting the command for the agent (`updatedInput`): the fix is text the agent applies itself.
- The at-execution shim (v1.1, after a spike; see "Later").
- The host setup's shadow gates (commit-gate, Stop shadow, turn evidence, lessons guard): not command
  lint, they stay in the host setup.

## Anti-goals (a failure even if it works)

- Denies on corpus commands that succeeded, counted on two meters:
  - **non-destructive** (no command of the delete or git-discard family): ≤ 0.1 % of such calls,
    every one listed and justified;
  - **deliberate destructive** (a delete/discard that succeeded and that shellwise would deny, e.g. a
    dynamic target): ≤ 2 per corpus day on average, each with a fix that runs (a literal path).
- The host setup ends with more prose rules than before, or a second guard running beside it.
- Slower than the Python hook it replaces (today 64 ms spawn, 223–270 ms bench per hook call).
- A rule that cannot be tested red (every rule has a deny case and an allow twin).
- Fail-open on a destructive command because the parser failed.

## Constraints

- Rust, single static binary, Windows x64 first; Linux and macOS build and pass the same tests.
- Licence **MIT OR Apache-2.0**. Dependencies with compatible licences only (checked by
  `cargo deny`). Nothing from dcg.
- Public repo: no absolute paths, personal or client names in code, docs or fixtures; synthetic
  fixtures only, the real corpus stays outside the repo. Creating the GitHub repo, publishing to
  crates.io and every release need the owner's explicit OK each time.
- Branches `main`/`develop` per the owner's git workflow.
- Talk to the owner in Polish; code, docs and commits in English.

## Approaches considered

| | A. Real parsers → shared IR (chosen) | B. PowerShell's own parser via `pwsh` | C. Port the Python lexers |
|---|---|---|---|
| How | brush-parser (bash), tree-sitter-powershell, a small cmd tokenizer, lowered to one IR | `Parser::ParseInput` per call | rewrite baseline_guard.py's lexers in Rust |
| Cost per call | a few ms | 300 ms+ (pwsh start) | a few ms |
| Fidelity | most lexer gaps close; tree-sitter-powershell fidelity is the risk (spike) | exact for PowerShell | inherits every gap |
| Role | the product | test oracle: differential fuzz A↔B | dropped |

Owner picked A. B stays as the oracle in tests (as baseline-guard already fuzzes against `ParseInput`
and bash).

## Decided with the owner

| Topic | Decision |
|---|---|
| v1 success | replaces baseline-guard; host setup deletes it and the bullets shellwise encodes |
| Name | `shellwise` (crate, binary, repo): free on crates.io; the GitHub user `shellwise` is taken (unrelated game-design org), so the repo lives under the owner's org; the nearest namesake is a 4-star Python "AI terminal co-pilot" |
| Licence | MIT OR Apache-2.0 |
| Shells | PowerShell 7 (with a 5.1 dialect flag) and bash (profiles: Git Bash/MSYS, Linux, macOS); cmd only nested |
| Levels | `ok`, `warn`, `break`, `danger`, `critical` (below) |
| Dynamic words in a destructive command | configurable; default deny |
| Auto-fix | not in v1 |
| Shim | v1.1, after a spike |
| Host setup distribution | `shellwise` from PATH; missing binary → hook allows, SessionStart warns once with the install command (`cargo install --path <clone>` until a release exists) |
| Host setup switch | part of this plan, as its last stage: until shellwise reaches parity on the corpus only the Python guard runs (never both); then one host setup PR switches the hook and deletes the Python rules and the prose |
| Target machine | this Windows x64 machine; Linux build and tests in WSL in v1; macOS once CI exists (needs the GitHub repo, owner's OK) |
| `critical` repo root | the root of the repo holding the event's `cwd`, and its ancestors; other folders with `.git` (temp clones, worktrees) are judged by the normal delete guard |
| False positives | two meters (Anti-goals) |
| Old marker | `# baseline-guard: allow` is accepted as an alias during the transition (deny texts and skills name it) |

## Design

### Pipeline

```
event / argv ──► shell detect ──► parse (bash | pwsh) ──► IR ──► rules (lint, guard) ──► verdict ──► adapter output
                                     │                     ▲
                                     └─ nested scripts ────┘   (pwsh -c, bash -c, cmd /c, Invoke-Expression,
                                                                sh -c strings: parsed recursively, depth ≤ 4)
```

### IR

A command is a list of statements; each statement is pipelines of simple commands joined by
`;`/`&&`/`||`/newline, plus control flow (loops, conditionals, functions, script blocks) kept as
nodes so rules know a command runs inside a loop. A simple command has a name and words. A **word**
is a list of parts: `Literal(text)`, `Var(name)`, `Subst(script)`, `Glob(pattern)`, `Tilde`; it is
**static** when all parts resolve at check time, otherwise **dynamic**. Every node keeps its source
span, so a finding points at the exact text. Redirects, here-strings/heredocs (with their bodies)
and the shell's own comment/escape rules are resolved by the parser, never by regex on raw text.

### Levels and what the hook does with them

| Level | Meaning | Claude Code hook | `check` exit |
|---|---|---|---|
| `ok` | nothing found | no output | 0 |
| `warn` | likely to break or to surprise | allow, one line of context to the agent | 0 |
| `break` | certain to fail as written | deny, reason + fix | 1 |
| `danger` | destroys data the agent may not mean to (or target unknown) | deny, reason + fix (configurable: `ask`) | 2 |
| `critical` | drive root, home, repo root, `/` | deny; the allow marker does not apply | 3 |

The highest finding wins; all findings are listed. Exit 64+ is a usage or internal error.

### Contract

- `shellwise hook claude-code` — reads the PreToolUse event on stdin (`tool_name` Bash → bash with the
  OS profile, PowerShell → pwsh; `tool_input.command`, `cwd`), writes the host's JSON
  (`permissionDecision` deny/ask with the reason; warn as additional context), exits 0. Unknown tool
  → no output. Whether PreToolUse accepts additional context on an allow is a spike item; if it does
  not, `warn` is silent in this adapter.
- `shellwise check --shell pwsh|powershell5|bash|gitbash [--cwd DIR] [--json] [-- COMMAND | stdin]` —
  for other agents and for humans. JSON: `{"version":1,"level":…,"findings":[{"rule","level",
  "message","fix","span":{"start","end"}}]}`.
- `shellwise explain <rule>` — the rule's doc with a deny and an allow example.
- Allow marker `# shellwise: allow` (trailing comment, both shells) downgrades `break`/`danger` to
  `ok` for that call, never `critical`. `SHELLWISE=off` disables it.

### Fail-closed rules

- A destructive command (delete family, `git` discard family; list in code) whose target word is
  dynamic, whose location is unknown, or whose folder walk does not finish within the budget →
  `dynamic-target` / `walk-timeout`, level from config (default `danger`).
- A parse failure: `danger` when the raw text holds a destructive command name, `ok` otherwise (the
  shell will report its own syntax error). Never a silent allow of a destructive command.
- An internal error (panic, I/O error outside a walk): same as a parse failure.

### Delete guard

Commands: `rm`, `rmdir`, `Remove-Item` and its aliases, `[IO.Directory]::Delete`,
`[IO.File]::Delete`, `cmd /c rd /s`, `del /s`, `robocopy /MIR` (destination), `git clean -f…`,
`git worktree remove`, `git checkout -- / <path>`, `git restore`, `git reset --hard`, `git stash drop/clear`.
For each target: resolve as the shell would (static words only; `cd`/`Set-Location`/`Push-Location`
in the same command; the event's `cwd`), `lstat` it, then:
`critical` for a drive root, `/`, home, the root of the repo holding the event's `cwd`, or an
ancestor of any of them; `danger` for a recursive
delete whose tree holds a reparse point (junction, symlink, mount point) whose target is outside the
tree, found breadth-first without following links, within a shared time budget (default 8 s, under
the hook timeout); the git rules keep baseline-guard's semantics (`git checkout <word>` is a discard
only when the word exists on disk and is not a commit, etc.). Junctions are read with
`FSCTL_GET_REPARSE_POINT` on Windows; symlinks with `std::fs` everywhere.

### Configuration

TOML, in three layers: an integration file passed with `--config <file>` (how a plugin such as the
host setup ships its settings to every machine), then the user file, which overrides it, then the repo
file. The user file (`<config dir>/shellwise/config.toml`) may raise or lower any rule's level, set
`dynamic_target`, the walk budget, protected paths, and lists the generic rules need: "gate"
commands whose output must not be truncated (the host setup puts `my-tool.ps1` and its gate
commands here), `.bat` launcher names, optional tool paths named in fixes. A repo file
(`.shellwise.toml`) may **only raise** levels or add protected paths: a cloned repo cannot switch the
guard off.

### Rules v1

Ported from baseline-guard (24): `ps-git-commit-stdin`, `git-restore-discards`, `git-unreadable`,
`gate-truncated-pipeline` (gate list from config), `bash-backslash-collapse`, `cli-inline-prose`,
`stale-write-var`, `ps-bare-bash`, `ps-dotnet-relative-path`, `ps-native-nonewline`, `bat-metachar`,
`ps-bad-parameter`, `git-no-verify` (policy, off unless enabled in config), `git-worktree-junction`
(folded into the delete guard), `bash-msys-path-mangle`, `bash-cd-slash-d`, `bash-powershell-syntax`,
`bash-ps-call-operator`, `bash-unquoted-backslash-path`, `bash-vendor-bin-shebang`,
`bash-versioned-php` (generalised: a Windows `.bat` launcher by name from Git Bash),
`ps-unix-command`, `bash-too-long`, `bash-unterminated-quote`.

New candidates, each entering v1 only with corpus evidence: `ps-remove-trailing-star`,
`ps-assign-automatic`, `ps-stdin-script-nonascii`, `ps-empty-native-arg` (`'""'`), `bash-crlf`,
`ps51-syntax` (pwsh-only syntax under the 5.1 dialect), `dash-leading-arg` (a literal file argument
starting with `-` before any `--`), `inline-script-too-long` (warn; the fix carries a ready script
template and the command to run it by path).

### What the host setup deletes when shellwise ships

| Host setup piece | Replaced by |
|---|---|
| `tools/baseline-guard/baseline_guard.py` rules, lexers, tests (the commit shadow rule moves to a small handler of its own) | shellwise rules |
| 8 `PreToolUse` handlers in `the-host-plugin/hooks/hooks.json` | 1 handler, matcher `Bash\|PowerShell`, no `if` |
| `INSTALL.md` rule tables and ~50 "known gaps" | shellwise docs |
| windows-dev-env: bash flags on cmdlets, `.bat` metacharacters, `Remove-Item <dir>\*`, automatic variables, stdin scripts, `'""'`, Bash 7.8 KB, `\\` collapse, MSYS mangling, CRLF, junction delete, commit `-F -`, `gh --body` quotes | rule ids above (bullet becomes "shellwise denies it", or goes) |
| "Windows shell" rule: scripts over ~10 lines through the Write tool | `inline-script-too-long` |

The commit shadow rule (`log_commit` and its helpers in `baseline_guard.py`) moves to its own small
handler with an `if` on `*commit*`; `tests/test_repo.py` `DuplicateHookTests` counts change with
the handlers. The exact deletions are the plan's last stage, one host setup PR after parity; prose stays where the agent needs
it before writing the command (e.g. which shell to choose).

### Measurement

`tools/corpus/` (in the repo, generic): extracts Bash/PowerShell `tool_use` with their results from
Claude Code transcripts (main and subagent) into JSONL with a label: `failed` (error output),
`denied-hook`, `denied-permission`, `ok`, plus a `destructive` flag set by an independent matcher
(command names of the delete/discard family, not shellwise's own resolution). The corpus is the
owner's Claude Code transcripts (at least the last 30 days); the file stays outside the repo, in
the folder `$SHELLWISE_CORPUS` names. **Baseline:** the current `baseline_guard.py` (`check()` and the installed
`check_installed()`) replayed over the same rows, recorded before the first rule is ported. `shellwise bench
--corpus` reports per rule: catches on `failed`/`denied-*`, denies on `ok` (false positives, each
listed), parse failures per shell, latency p50/p99, and a differential against baseline-guard on the
same rows (every baseline-guard deny is a shellwise deny or a listed, justified difference). Positive
control: a known-answer slice that must produce known findings; 0 rows read fails.

## Spikes before the plan is fixed

1. tree-sitter-powershell on the corpus vs `ParseInput`: share of commands parsed without error and
   with the same command/word structure; Rust binding availability and build on Windows (MSVC).
2. brush-parser on Git Bash corpus commands: same, plus heredoc and `$'…'` handling.
3. Spawn latency and binary size of a release build on this machine (Dev Drive, Defender on).
4. Claude Code PreToolUse output: deny/ask reason and context on allow, on the CLI version the
   owner's sessions run (stub API, isolated config).

A spike that fails changes the approach before code: (1) failing → PowerShell falls back to a
dedicated Rust lexer scoped to what the rules need, with B as oracle.

## Later

- v1.1 shim: `rm`/`Remove-Item`/`git` wrappers that call `shellwise` with real values at execution
  (PowerShell proxy functions via a module the tool loads; bash functions via `BASH_ENV`) — spike
  first whether the hosts load them.
- Rule packs (cloud CLIs, databases), cmd.exe as a top-level shell, more agent adapters (Codex,
  Gemini CLI, Cursor), winget/Homebrew packaging.

## Left to the builder

Module layout, crate choices beyond the parsers, the IR's exact types, error type, test framework,
fixture format, CLI parsing library, how rule docs are generated.

## Estimate

v1: ~55 agent working hours; ~7,000 lines of Rust, ~6,500 lines of tests and fixtures (porting
`test_rules.py` alone is ~2,150 lines of cases); spikes ~6 h; the host setup stage ~6 h: the commit shadow
keeps the Python lexer parts it needs (~900 lines stay), ~2,000 rule lines and ~40 prose lines go.
Simpler version (~15 h, ~3,000 + ~2,000 lines): PowerShell only, the 13 installed rules and the
delete guard, no new lint rules. It drops Bash coverage (the Bash handlers would stay in Python, so
baseline-guard could not be deleted) and the "will it break" additions.
