# shellwise — design

Status: approved by the owner on 2026-11-18; amended the same day for two owner decisions taken on the
spike results (PowerShell grammar fork, at-execution shim in v1).

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
gaps; values only the shell knows stay unknown at check time, so a destructive command with them either
runs under an execution-time check (the shim, below) or fails closed.

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
6. **Deliberate deletes with a variable target pass when safe:** in the Claude Code adapter, a
   delete or git discard whose only problem is a target known only at run time runs under the
   shim, which checks the real target when the command runs (section "At-execution shim").

## Non-goals (v1)

- Sandboxing or replacing the host's permission system.
- A broad catalogue of destructive commands outside files and git (cloud CLIs, databases, k8s):
  later rule packs.
- Full cmd.exe as a top-level shell (cmd appears only nested: `cmd /c "…"`, `.bat` arguments).
- Rewriting the command for the agent (`updatedInput`): the fix is text the agent applies itself.
  The shim is the single exception: its rewrite only prepends generated definitions and
  substitutes the delete receiver, and never changes what the command does.
- Shim coverage outside Claude Code: `shellwise check` reports a dynamic target as `danger`, as
  before; other adapters can add the shim later.
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
| How | brush-parser (bash), a fork of tree-sitter-powershell (section "PowerShell grammar fork"), a small cmd tokenizer, lowered to one IR | `Parser::ParseInput` per call | rewrite baseline_guard.py's lexers in Rust |
| Cost per call | a few ms | 300 ms+ (pwsh start) | a few ms |
| Fidelity | most lexer gaps close; upstream tree-sitter-powershell missed 3 of 4 thresholds (spike), the fork must reach them | exact for PowerShell | inherits every gap |
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
| Dynamic words in a destructive command | configurable; default deny; in the Claude Code adapter a shim-eligible one runs under the shim |
| Auto-fix | not in v1 |
| Shim | in v1 (owner, after the spike measured 14.8 dynamic-target deletes per day against meter 2's 2): loaded by an `updatedInput` rewrite in both shells (section "At-execution shim") |
| PowerShell parser | fork tree-sitter-powershell, fix the measured mechanisms, re-measure with the same thresholds; not reached in about 6 agent hours → a dedicated Rust lexer with `ParseInput` as oracle; upstream contributions only with the owner's OK |
| Bash parser | brush-parser kept; its two failing gap rows (heredoc delimiter `$'EOF'`, `$(x)`) are parse errors, so they fail closed |
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

verdict whose only deny is shim-eligible dynamic-target ──► adapter: updatedInput = shim text + command
                                                            └─ at run time: wrapper ──► shellwise shim-check (real argv) ──► run | refuse
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
- `shellwise shim-check --shell pwsh|bash|gitbash [--config FILE] --session-cwd DIR --cwd DIR -- NAME ARG…` — called by the shim's
  wrappers at execution time with the real argument values (section "At-execution shim"); exit 0
  = run it, anything else = refuse.
- Allow marker `# shellwise: allow` (trailing comment, both shells) downgrades `break`/`danger` to
  `ok` for that call, never `critical`. `SHELLWISE=off` disables it.

### Fail-closed rules

- A destructive command (delete family, `git` discard family; list in code) whose target word is
  dynamic, whose location is unknown, or whose folder walk does not finish within the budget →
  `dynamic-target` / `walk-timeout`, level from config (default `danger`). In the Claude Code
  adapter a verdict whose only deny is shim-eligible `dynamic-target` runs under the shim instead
  (next sections); everything else about it stays as here.
- A failed analysis (parse error, panic, internal error, input over the cap, invalid UTF-8,
  deadline) → `danger` (`analysis-failed`), unless the whole raw text matches the harmless grammar:
  no shell metacharacter (``; & | < > ( ) $ ` \ " ' { } [ ] * ? ~ #``, newline) and a first word
  from a short read-only list (`ls`, `cat`, `echo`, `pwd`, `git status|log|diff|show`, `grep`,
  `rg`, `head`, `tail`, `wc`, `which`, `type`, `<tool> --version`). The raw-text scan only names
  the destructive command in the reason; it never clears a command. The allow marker is matched in
  the raw text on this path (the parse that fills `Script.comments` failed). Measured on the
  corpus: 2 of 22,346 bash rows (0.009 %) fall on this path without being shell syntax errors.

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

### At-execution shim

**Why.** 460 of the 1,327 successful destructive corpus commands (14.8 per calendar day) delete a
target held in a variable, a wildcard or pipeline input; the static guard cannot see the value and
denies them, against meter 2's 2 per day. The shim lets such a command run and checks the real
target, with the same delete and git rules, at the moment the delete runs.

**How the hosts load it** (spike "Shim loading"). The PowerShell tool starts a fresh `pwsh
-NoProfile` per call and keeps no state; neither a profile, `PSModulePath` nor the session
environment file can replace `Remove-Item`. The Bash tool would accept functions from
`CLAUDE_ENV_FILE` or `BASH_ENV`, but the PreToolUse hook cannot prove a given call sourced them. So
both shells use one route: the PreToolUse adapter answers with `updatedInput` (and no
`permissionDecision`), whose command is the shim text followed by the agent's command. Loading is
proven by construction: the definitions are part of the very command that runs.

**When the adapter rewrites** — all of (an allow-list: anything not named here keeps its deny):

1. `cfg.shim` is on (default; user or integration layer only — a repo file cannot set it);
2. every finding at `break` or above is `dynamic-target`, at a level no higher than `danger`
   (a `dynamic_target` or `levels` setting that raises it to `critical` keeps the deny), and
   `dynamic-target` is not in `ask_instead_of_deny` (see "Order of decisions");
3. every command behind those findings is one of:
   - a simple command whose first word **as written** is a wrapped name — bash `rm`, `rmdir`,
     `git`, matched byte for byte (Git Bash finds `RM`, `Rm`, `GIT`, `rm.exe` case-insensitively
     on NTFS and runs the binary, past a case-sensitive function, so any other case, quotes or
     `.exe` keeps the deny); PowerShell `Remove-Item`, `ri`, `rm`, `del`, `erase`, `rd`, `rmdir`,
     matched without regard to case (PowerShell resolves names that way, so every case reaches
     the function), with no quotes. So nothing stands before it: `nohup rm`, `time rm`, `env rm`,
     `sudo rm`, `command rm`, `timeout 5 rm` keep their deny, as do path- or module-qualified
     names (`/usr/bin/rm`, `\rm`, `Microsoft.PowerShell.Management\Remove-Item`);
   - a static method call `[IO.Directory]::Delete` / `[IO.File]::Delete` (also `[System.IO.…]`,
     any case);

   and it does not sit inside a nested script string (`bash -c`, `pwsh -c '…'`, `cmd /c`, `iex`,
   `eval`) nor inside a script block that runs elsewhere. A script block is allowed only when every
   enclosing block is run in the same runspace by one of: `ForEach-Object`/`%`/`foreach`/
   `Where-Object`/`?`/`where` whose parameters are all static and none of which is a
   case-insensitive prefix of two or more letters of `Parallel`, `AsJob` or `ThrottleLimit`, in the
   `-Name` or the `-Name:value` form (PowerShell accepts any unambiguous prefix, so `-Par` and
   `-parallel:{ }` run in another runspace); a splat (`@p`) or a dynamic parameter name keeps the
   deny; `&` or `.` of a literal block; `if`/`switch`/loops/`try`. Any other receiver of the block
   (`Start-Job`, `Start-ThreadJob`, `Invoke-Command`, `Measure-Command`, `pwsh -Command { }`, a
   function definition or call) keeps the deny: there `Remove-Item` may resolve to the cmdlet;
4. the command does not touch a wrapped name or a `__sw*` name. Bash: `unset`, `unalias`, `alias`,
   `builtin`, `enable`, `declare -f`/`typeset -f`, or a function definition, with a wrapped name,
   `command` or `__sw*` as argument or name. PowerShell: `function`/`filter` definitions,
   `Set-Alias`, `New-Alias`, `Set-Variable`, `New-Variable`, `Remove-Variable`, `Clear-Variable`,
   `Rename-Item`/`Remove-Item`/`Set-Item` on `function:`, `alias:` or `variable:` paths, any
   assignment to a `__sw*` variable in any form (`$__sw_File =`, `${__sw_File} =`, `$global:` /
   `$script:` scopes), `Get-Command … -CommandType Cmdlet`, with a wrapped name or a `__sw*` name;
5. PowerShell only: the command does not start with `using` or `param(` (they must come first in a
   script, so a prepended shim would break it);
6. the reply stays under the host's hook-output limit measured in the Task 21 spike step; a longer
   rewrite keeps the deny.

The PowerShell `git` is not wrapped: a function's `$args` drops a literal `--` (`git checkout -- f`
would reach git as `git checkout f`), so a PowerShell git discard with a dynamic target keeps its
deny. Bash wrappers keep `--` (`"$@"`).

**Order of decisions.** First the static verdict; then the shim decision (conditions above); a
rewrite wins over `ask_instead_of_deny` only when `dynamic-target` is not listed there — when it is
listed, the person chose to be asked, so the adapter asks and does not rewrite. Every verdict that
is not rewritten goes through Task 14's mapping (deny, or ask per `ask_instead_of_deny`).

**The rewrite.** The original text follows the shim unchanged, except that each eligible receiver
with its `::` — `[IO.Directory]::`, `[System.IO.File]::` … (span from the parser) — becomes
`$__sw_Directory.` / `$__sw_File.` (a `ScriptMethod` is called with `.`, never `::`). The binary
writes the shim text itself (embedded, versioned with it) and bakes in, single-quoted and made
absolute at rewrite time: its own path (`current_exe()`), the integration config the hook was
started with (`--config`, when given) and the event's `cwd` as `--session-cwd`. An event without a
`cwd` gets no rewrite (the deny is kept). Bash (Git Bash; Posix the same with
`--shell bash`):

```bash
\unalias rm rmdir git 2>/dev/null; \unset -f __sw 2>/dev/null
function __sw { '<shellwise>' shim-check --shell gitbash --config '<integration file>' --session-cwd '<event cwd>' --cwd "$PWD" -- "$@"; }
function rm { __sw rm "$@" && command rm "$@"; }
function rmdir { __sw rmdir "$@" && command rmdir "$@"; }
function git { __sw git "$@" && command git "$@"; }
# shellwise shim: the command below runs with an execution-time check on rm, rmdir and git
<original command>
```

The `unalias` line comes first because the host's shell snapshot may carry an alias for `rm`, which
would turn `rm() {` into a syntax error; the `function name { }` form is not alias-expanded.

PowerShell (pwsh 7 only — the PowerShell tool always runs pwsh 7):

```powershell
function __sw_check { # one place that calls the binary and fails closed on its own state
  $global:LASTEXITCODE = $null; $ok = $false
  try { $out = & '<shellwise>' shim-check --shell pwsh --config '<integration file>' --session-cwd '<event cwd>' --cwd $PWD.ProviderPath -- @args 2>&1
        $ok = $? -and ($LASTEXITCODE -eq 0) } catch { $ok = $false }
  if (-not $ok) { throw "shellwise: refused: $out" } }
function Remove-Item { <proxy with Remove-Item's own parameters and pipeline binding. It collects
  the items exactly as the cmdlet will delete them — Get-Item / Get-ChildItem with the same -Path or
  -LiteralPath, -Filter, -Include, -Exclude and -Force, hidden items included, pipeline PSPath as
  -LiteralPath — and calls __sw_check once per item with its file-system ProviderPath
  (Remove-Item -LiteralPath <ProviderPath> [-Recurse]) for every item of every pipeline input. The
  process block buffers each input object; only after all of them passed does the end block run
  the generated steppable pipeline of Microsoft.PowerShell.Management\Remove-Item over the buffer
  ($sp.Begin($true); $sp.Process($i) per buffered object; $sp.End()), or, with no pipeline input,
  the cmdlet once with the bound parameters (in end, $PSBoundParameters holds only the last
  pipeline item)> }
$__sw_Directory = <object with ScriptMethod Delete: refuses unless [IO.Path]::IsPathFullyQualified($args[0])
  ("use an absolute path": .NET resolves a relative path against the process directory, which
  Set-Location does not move), then __sw_check Remove-Item -LiteralPath $args[0] [-Recurse when $args[1]],
  then [IO.Directory]::Delete.Invoke($args)>
$__sw_File = <same for [IO.File]::Delete>
# shellwise shim: the command below runs with an execution-time check on Remove-Item and [IO.*]::Delete
<original command, delete receivers substituted>
```

The proxy body is generated once from `[System.Management.Automation.ProxyCommand]::Create` (pwsh
7) and embedded. Aliases reach the function because PowerShell resolves an alias to the name
`Remove-Item` and a function wins over a cmdlet in the same runspace (checked in pwsh 7.7). Paths of
another provider (`env:`, `HKCU:`) pass the check (outside v1's file and git scope).

**What `shim-check` checks.** It builds a simple command from the argv it receives — every word a
literal, the shell's quoting already removed — and runs only the guard rules (delete guard, git
discard rules) on it: `--cwd` is the location, `--session-cwd` supplies the repo root for
`critical` (so `cd ..` before deleting the project through a variable is still `critical`), and the
config is `Config::discover(--config, --session-cwd)`, the same layers the hook used. Git Bash
arguments arrive as MSYS converted them (`/tmp/x` → `C:/…/Temp/x`), or in POSIX form under
`MSYS_NO_PATHCONV=1`, which the resolver handles for `/<drive>/` and `/tmp` and refuses otherwise.
Exit 0 for `ok`, `warn` and `break` (lint is not its job); 2 for `danger`, 3 for `critical`; 64+ for
a usage or internal error.

**How it reports.** The adapter's reply always carries `additionalContext`:
`shellwise: this command deletes a target known only when it runs, so it runs with an
execution-time check (shim definitions were prepended to it). If the check refuses, nothing is
deleted and the error output says why.` Warn findings' context lines follow it in the same field. A
refusal writes `shellwise: <rule>: <message> Fix: <fix>` to stderr; bash returns the check's exit
code, PowerShell throws a terminating error.

**How it fails closed.** The delete runs only after `shim-check` exits 0, judged from the call
itself, never from a value an earlier command left: PowerShell resets `$LASTEXITCODE`, wraps the
call in `try`/`catch` and requires `$?` too, because a missing binary inside a function only ends
that statement and leaves a stale 0. A missing or unstartable binary (bash 127, PowerShell
`CommandNotFoundException`), a crash, a timeout (the check's own deadline) or any exit other than 0
refuses that delete. A shim definition that does not parse makes the whole PowerShell script fail
before anything runs; the bash shim text is fixed and tested in both profiles. A `try`/`catch` in
the agent's command can swallow the refusal, but the delete still did not happen. Between the check
and the delete a few milliseconds pass; a junction created in that window is not seen (the same
race the static guard has).

**Division of work.** The static guard still decides everything it can see: `critical`, links
inside a literal target, every lint rule, and every dynamic target outside the allow-list
(PowerShell `git`, wrappers, other runspaces, `xargs rm`, `find -delete`, a nested `bash -c`). The
shim decides only the eligible dynamic targets, per real value, per loop iteration and per pipeline
item. `bench` reports an eligible row as `shimmed` (not a deny on meter 2) and lists the count;
whether the shim would have refused a corpus row cannot be replayed, because the values are gone.
`shellwise check` still reports such a row as `danger`.

**Other hooks and Monitor.** Another PreToolUse hook that returns its own `updatedInput`, or the
Monitor tool (which arrives as a Bash event), could replace or drop the shim text. Pass rule (Task 21
spike step): in each case either the shim text runs or nothing runs. If a case fails the rule, the
adapter does not rewrite where it can tell the case apart; otherwise the limit is stated here and
the host setup stage checks that no other installed hook returns `updatedInput`.

**Cost.** The host judges the rewritten text. With an allow rule for the whole tool or in
`bypassPermissions` the rewritten command runs; under fine-grained allow rules (`Bash(rm:*)`)
the host's own checks ask about any prefix ("evaluates arguments as shell code", "uses
splatting"), and in `-p` that ask is a refusal. Such a command was a deny before, so this is
never worse, but the ask shows the shim text to the person. Each wrapped call costs one spawn of
the binary (about 12 ms) at execution time.

**Coverage** (spike "Shim loading", recount with wrappers stripped first and a known-answer
control). Of the 462 dynamic-target destructive `ok` corpus rows, 413 meet conditions 3–5 (13.3 per
calendar day); 49 keep their deny (43 PowerShell `git`, 2 other runspaces, `xargs`, `robocopy`,
`shred`, `find`). 25 more destructive rows are not matched by the segmentation (inside `cmd /c`,
`bash -c`, `powershell -c` strings, `find -exec`); 5 of them look dynamic, and a dynamic target
inside a nested script string keeps its deny. Measured deny rate: 54 rows, **1.74 per day**; 2.39 per
day is the upper bound if all 25 were denied. Of the `[IO.*]::Delete` rows whose variable has
one literal assignment, 2 of 76 are relative paths the shim would refuse.

### PowerShell grammar fork

Where: `vendor/tree-sitter-powershell/`, a path crate in this repository (not published, not a
separate repo), started from the crates.io package 0.26.6 (MIT, upstream repository
`airbus-cert/tree-sitter-powershell`). It keeps the upstream `LICENSE` file; `NOTICE.md` names the
upstream version and lists every change. `src/parser.c` is generated and committed; only
`scripts/regen-grammar.ps1` writes it, with the pinned `tree-sitter-cli` version recorded in
`NOTICE.md`, and it records the SHA-256 of `grammar.js` and `src/grammar.json` in
`vendor/tree-sitter-powershell/GENERATED`, which a test compares. Before any crates.io publish of
`shellwise` the fork must become a published crate or move under `shellwise`'s own build script
(owner's decision then). Upstream pull requests only with the owner's OK.

Known-answer control first: the unchanged fork, through shellwise's own dump of the lowered IR,
must reproduce the spike's upstream counts (equal error status, silent and destructive mismatches,
gap rows), every difference listed and explained, before the first grammar change; those numbers
are the baseline beside the new ones.

What changes: each mechanism the parser spike measured is one test row (synthetic command,
`ParseInput`'s command names and elements as the expected answer) and is fixed in the grammar, the
external scanner or the lowering, whichever is smaller. Then the same measurement as the spike
runs on the same corpus snapshot with the same thresholds: all gap rows correct, 0 unlisted
mismatches on destructive rows, silent mismatches ≤ 0.5 %, equal error status ≥ 99 %. If they are
not all met within about 6 agent hours of fork work, PowerShell switches to the fallback: a
dedicated Rust lexer scoped to what the rules need, with `ParseInput` as the test oracle, measured
against the same thresholds on the same rows (compared with the same `ParseInput` reference, beside
the upstream and fork numbers); the fallback deletes `vendor/`, `scripts/regen-grammar.ps1` and
the fork's tests.

### Configuration

TOML, in three layers: an integration file passed with `--config <file>` (how a plugin such as the
host setup ships its settings to every machine), then the user file, which overrides it, then the repo
file. The user file (`<config dir>/shellwise/config.toml`) may raise or lower any rule's level, set
`dynamic_target`, `shim` (on by default), the walk budget, protected paths, and lists the generic rules need: "gate"
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

5. Shim loading: what the Claude Code tools load (profile, modules, `PSModulePath`, `BASH_ENV`,
   `CLAUDE_ENV_FILE`) and what `updatedInput` does (done; `docs/spikes.md` "Shim loading").

Spike results: (1) failed three of four thresholds → the grammar fork, with the lexer as fallback;
(2) passed the corpus thresholds; (3) and (4) recorded in `docs/spikes.md`; (5) chose the rewrite
route above.

## Later

- The shim for other agents' adapters, and a bash route through `CLAUDE_ENV_FILE` that would keep
  fine-grained allow rules matching (needs a way for the hook to prove the file was sourced).
- Rule packs (cloud CLIs, databases), cmd.exe as a top-level shell, more agent adapters (Codex,
  Gemini CLI, Cursor), winget/Homebrew packaging.

## Left to the builder

Module layout, crate choices beyond the parsers, the IR's exact types, error type, test framework,
fixture format, CLI parsing library, how rule docs are generated.

## Estimate

v1: ~77 agent working hours; ~8,600 lines of Rust (7,000 + Task 20's 900 + Task 21's 500 + ~200
for Task 5's dump example and grammar scripts), ~9,100 lines of tests and fixtures (porting
`test_rules.py` alone is ~2,150 lines of cases), plus the generated grammar (not counted); of that,
the grammar fork ~7 h (known-answer control ~1 h, fixes capped at ~6 h), ~400 lines of
grammar/scanner changes and ~600 lines of tests; the shim ~14 h: `shim-check` and the shim text ~9 h,
~900 lines of Rust and embedded shim text, ~1,300 lines of tests; eligibility, the adapter rewrite
and its host spike ~5 h, ~500 + ~700 lines. If the fork misses its thresholds, the lexer fallback
adds ~10 h, ~2,000 + ~1,000 lines. Spikes ~7 h (done); the host setup stage ~6 h: the commit shadow
keeps the Python lexer parts it needs (~900 lines stay), ~2,000 rule lines and ~40 prose lines go.
Simpler version (~20 h, ~3,000 + ~2,000 lines): PowerShell only, the 13 installed rules and the
delete guard, no new lint rules. It drops Bash coverage (the Bash handlers would stay in Python, so
baseline-guard could not be deleted) and the "will it break" additions. A simpler shim (~8 h) wraps
only the bare names: it drops the `[IO.*]::Delete` receiver substitution and leaves 204 corpus rows
(6.6 per day) denied, so meter 2 is not met.
