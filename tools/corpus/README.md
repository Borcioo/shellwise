# Corpus tools

The measurement corpus every shellwise rule is judged against: real Bash and PowerShell tool calls
from Claude Code transcripts, labelled by what happened, and the current baseline-guard hook replayed
over them as the baseline. Python 3.11+, stdlib only.

The corpus holds command text, session ids and machine paths. It lives outside the repo, in the
folder `$SHELLWISE_CORPUS` names; only counts reach the repo (`docs/baseline.md`).

## extract.py

```
python -I tools/corpus/extract.py --projects <Claude Code projects folder> --days 30 --out "$SHELLWISE_CORPUS/corpus.jsonl"
```

Reads `<projects>/<project>/<session>.jsonl` and every `subagents/*.jsonl` below a session, keeps
the calls whose `timestamp` falls within `--days`, and writes one row per call:

| Field | Meaning |
|---|---|
| `id` | 12 hex characters derived from the `tool_use` id |
| `session`, `ts`, `cwd`, `cli_version` | from the transcript line holding the call |
| `tool` | `Bash` or `PowerShell` |
| `command` | the command as sent, byte for byte (CRLF kept) |
| `label` | `ok`, `failed`, `denied-hook`, `denied-permission` |
| `denied_by` | the hook name for `denied-hook`, the denial kind for `denied-permission`, else `null` |
| `destructive` | the call names a command from `data/destructive.toml` |
| `error_excerpt` | the first 300 characters of the result (CRLF as LF), `""` for `ok` |

Labels, in this order:

- `denied-hook`: an error result starting with `PreToolUse:<Tool> hook error: <hook>: …`;
  `denied_by` is `<hook>`. Claude Code also flags these with `toolDenialKind`, so this test comes first.
- `denied-permission`: the result line carries `toolDenialKind` (`denied_by` is its value), or an
  error result starts with a denial text Claude Code sends unflagged (user rejection, permission
  rule, auto mode, `<tool_use_error>` validation, worktree isolation).
- `failed`: any other error result.
- `ok`: everything else, including `(Bash completed with no output)` and calls moved to the background.

The label says what the tool result showed, not what the shell parsed: 16 `ok` PowerShell rows are
texts pwsh's parser refuses (14 of them a `\"` inside a double-quoted string), labelled from
their tool result. Read such a row by its real-parse answer, not by its label.

A fork or a resume copies earlier lines with the same uuid and `tool_use` id: each call is kept once.
User lines marked `isMeta` or `isCompactSummary` quote earlier text and are never read as a result.
A call with no result is dropped and counted. It also writes `<out stem>.stats.json` (files read, lines,
duplicates, calls outside the window, no result) and exits 1 when it reads no transcript or writes no row.

## baseline.py

```
git -C <host setup repo> log --diff-filter=A --format=%H -- <baseline_guard.py path>
git -C <host setup repo> log -1 --format=%cI <that commit>
git -C <host setup repo> show <that commit>:<baseline_guard.py path> > <scratch>/first_guard.py
python -I tools/corpus/baseline.py --baseline-guard <baseline_guard.py path> --first-guard <scratch>/first_guard.py \
    --first-guard-date <that commit's date> --corpus "$SHELLWISE_CORPUS/corpus.jsonl" --out "$SHELLWISE_CORPUS/baseline.jsonl" \
    --report docs/baseline.md --known "$SHELLWISE_CORPUS/known.jsonl"
```

Write `first_guard.py` as UTF-8 (in PowerShell, `[IO.File]::WriteAllText` with a UTF-8 encoding).

Loads `baseline_guard.py` by path with `BASELINE_GUARD` unset and no bytecode written, and calls its
`check()` (`full`) and `check_installed()` (`installed`, what the host setup hooks run) on each row's
command and cwd. It never runs a command; some git rules run read-only `git rev-parse` and read the
disk under the row's cwd. Each row of `baseline.jsonl` is `{"id", "full": [rule…], "installed": [rule…]}`
(deny findings only).

`--report` writes counts only. `--known` writes a known-answer slice, `{"id", "os", "expected_rules"}`:
10 rows that baseline-guard denies, spread over different rules, and 10 `ok`, non-destructive rows with no
finding, plus Linux rows up to 2 of each kind when the corpus has them. `os` is read from the cwd the
way `shellwise bench` reads it (`row_os`, a copy of the bench's rule; `tests/bench_fixture/cwd_shapes.tsv`
tests both), and the bench fails on a row it replays on another OS. A deny row expects only rules that
can fire on its tool and OS (`[runs_on]` in `rule_map.toml`, read into `RUNS_ON`, one line of evidence
per rule; an id not listed counts as Windows-only).

Replaying the `denied-hook` rows with `denied_by = baseline-guard` is a positive control that replay
works, not a coverage target. Each such row that does not replay to a deny today gets a computed cause:
`target gone` (a git command, the rules that read the disk, whose cwd or a drive path the deny message
names does not exist now), else `rule narrowed` (a row dated before `--first-guard-date`, which
baseline-guard at its first commit, `--first-guard`, does not deny either), else `unexplained`. The rows of
git commands that do not replay are replayed a second time with the disk check neutralised (every
folder exists); the report gives both counts.

The run fails (exit 1, one `FAIL:` line each) on 0 rows for a shell, 0 destructive rows, 0 baseline
denies, 0 baseline-guard hook denies, a replay call that raised, a known slice short of 10 + 10, or more
than 5 % of the rows that do not replay being `unexplained`.

## data/destructive.toml

The single table of the delete and git-discard families; its schema is documented at the top of the
file. The extractor's matcher is deliberately simple and independent of shellwise: it splits raw text
into simple commands (heredoc bodies and PowerShell here-strings are text), skips prefixes such as
`sudo` or `$x =`, scans `bash -c` / `pwsh -Command` / `cmd /c` bodies and the command a `find -exec`
clause runs, and matches names case-insensitively.

## rule_map.toml and real_parse.ps1

`rule_map.toml` maps each baseline-guard rule id to its shellwise id (header in the file). `shellwise bench`
compiles it in; every id `baseline.jsonl` or `known.jsonl` names must be in it. A shellwise id that has
not landed yet is not an error: its `known.jsonl` rows count as not landed until the rule exists.
`[runs_on]` says on which tools and OSes each mapped rule can fire, read from the rule's gate. The bench
fails on a `[map]` key without an entry, and on a mapped rule that fires outside its entry on a row
baseline-guard denies with that id (`full` or `installed`), so a too-narrow entry cannot shrink the known
slice silently.

```
pwsh -NoProfile -File tools/corpus/real_parse.ps1 -Corpus "$SHELLWISE_CORPUS/corpus.jsonl" -Ids <dump.tsv> -Out <real_parse.tsv>
```

Runs five known-answer controls, then asks pwsh's parser (`ParseInput`, in process) about each PowerShell
row and Git Bash's `bash -n` (one process per row, about 0.2 s) about each Bash row. Writes `id`, `refused`
(`yes`/`no`) and the first error id. `-Ids` with a bench dump keeps only the rows at break or above.

## shellwise bench

```
shellwise bench --corpus "$SHELLWISE_CORPUS/corpus.jsonl" --baseline "$SHELLWISE_CORPUS/baseline.jsonl" \
    --out <report.json> [--known <known.jsonl>] [--rule-map <map.toml>] [--real-parse <real_parse.tsv>] \
    [--dump <dump.tsv>] [--diff <old dump>] [--config <shellwise.toml>] \
    [--parity-exceptions <parity_exceptions.toml>] [--passes <n>]
```

Each row replays as the hook would have seen it. The corpus records no platform, so the cwd shape
names the OS: a drive-letter cwd, a UNC cwd (`\\host\share`, `//host/share`), no cwd or any other
non-`/` cwd is Windows (Git Bash for `Bash`); `/mnt/<letter>` (WSL) and any other `/…` cwd is Linux
(POSIX bash). The environment is a fixed synthetic one per OS (`WINDOWS_ENV`, `POSIX_ENV` in
`src/bench.rs`: home, `TEMP`/`TMP`, so Git Bash's `/tmp` maps into that temp), never the machine's
own. The report prints the rows replayed per OS and per cwd shape (`rows_per_os`, `cwd_shapes`), and
`--diff` the moved rows per OS (`moved_by_os`).

The result still depends on the machine that runs it. The rules read this machine's disk: a row whose
recorded cwd is not a folder here cannot fire a rule that reads the disk (a repo-root or `.git`
critical, a junction, a `.bat` launcher found on disk). The report counts those rows per OS
(`rows_cwd_missing`, printed as `cwd gone here, replayed on <OS>`) and lists the rules that read the
disk on this run, with the finding ids they gave (`disk_reading_rules`): their counts are lower bounds
by up to that many rows. The resolver also reads system paths by the host's OS (`Os::host()`), so a
Linux row's system path reads differently on a Windows host, and the default config's allowed root is
this machine's temp folder.

`--config` replays with that integration file alone (the file the host setup installs; no user or repo
file); a file that does not load, or any finding of its load, stops the run. Without it the default
config runs.

Parity is counted per installed baseline-guard rule and, for the rows shellwise allows, per key: the
rule, the shape class the bench computes (`mapped-warn`: shellwise's mapped rule names the row below
break; `mapped-silent`: it says nothing) and the row's label. `--parity-exceptions` reads the file
Task 35 keeps at `tests/cases/parity_exceptions.toml`:

```
[[exception]]
baseline_guard = "<baseline-guard id>"   # a [map] key
shape = "mapped-silent"            # or mapped-warn
label = "ok"                       # ok, failed, denied-hook, denied-permission
expected = <count above 0>
why = "<reason>"
```

Each key is listed once; no corpus ids. The report gives per key the allowed rows, the expected count,
`unexplained` (allowed above expected) and `excepted_over_allows`, and their sums per rule.

Meter 2 is split by the line each row would count on (refused, parity, own line, meter 1, as for the
non-destructive rows) and by family: rows a delete or git rule denies (`delete_git`) and the rest.

The latency (per shell, in process) and each rule's own cost (`rule_cost_ms`: its check alone, per
shell, with the rows it ran on) are the median of `--passes` passes (default 3) of their p50 and p99;
the verdicts come from the first pass. The rule costs come from a second run of the rules after
`analyse` on each row it finished, timing and attribution only; it mirrors the order in
`src/lib.rs` `check`. No process spawn is measured.

Build it with `--release`: the latency lines are meaningless in a debug build. The order: a first run
with `--dump`, `real_parse.ps1 -Ids` on that dump, then the run with `--real-parse`. Without
`--real-parse` the refused-by-the-real-parser line reads "not measured" and meter 1 is an upper bound.
For a base-vs-head diff, dump the base build's run, then run the head build with `--diff <base dump>`:
it replays twice and fails when its own two passes differ (the head-vs-head control). The report keeps
meter 1, the refused-by-the-real-parser line, the parity line and the own line apart; the meters gate
nothing before Task 35. Exit 1 on 0 rows (or 0 for one shell, or 0 joined to the baseline), an unmapped
baseline-guard id, a map key without a `runs_on` entry or a rule firing outside it, a config or parity
exception file that does not load, `--passes 0`, a missing `known.jsonl` (default: next to the corpus),
0 known rows checked, a checked known row missing its rule or absent from the corpus, or a moved
control. The dump's columns are `id`, `level`, `rules`, `raw_hit` and `rule_levels` (`rule:level`
pairs); `--diff` also reads a dump without the last column, comparing rules by name. The run prints
`baseline missing` (corpus rows without a baseline row) and, with `--diff`, `missing in old` and
`missing in new`. The dump and the report name row ids: keep them outside the repo.

## Tests

```
python -I tools/corpus/test_extract.py
```

Synthetic transcripts and a fake baseline-guard module in a temp folder; nothing reads real transcripts.
