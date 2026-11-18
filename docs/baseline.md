# baseline-guard baseline

Counts only, produced by `tools/corpus/baseline.py` over the corpus `tools/corpus/extract.py` writes (see `tools/corpus/README.md`). `full` is baseline-guard's `check()`, `installed` its `check_installed()` (the rules the host setup hooks run); only deny findings count.

## Corpus read

| Count | Value |
|---|---:|
| files_main | 941 |
| files_subagent | 2741 |
| lines | 1592651 |
| rows | 50650 |
| duplicate_calls | 14518 |
| outside_window | 53672 |

## Rows per label and shell

| Label | Bash | PowerShell | Total |
|---|---:|---:|---:|
| ok | 21592 | 24850 | 46442 |
| failed | 446 | 3213 | 3659 |
| denied-hook | 179 | 123 | 302 |
| denied-permission | 87 | 160 | 247 |
| **all** | 22304 | 28346 | 50650 |

## Destructive rows

`destructive` comes from `data/destructive.toml`; a dynamic target is a non-flag word after the command name holding `$`, a backtick, `*`, `?`, `%VAR%` or a leading `~` (draft regex).

| Shell | Destructive | Dynamic target |
|---|---:|---:|
| Bash | 542 | 160 |
| PowerShell | 1057 | 260 |

## Deny count per rule

| Rule | Full | Installed |
|---|---:|---:|
| bash-backslash-collapse | 835 | 853 |
| bash-msys-path-mangle | 188 | 0 |
| bash-too-long | 108 | 108 |
| ps-unix-command | 77 | 0 |
| git-restore-discards | 72 | 74 |
| gate-truncated-pipeline | 46 | 48 |
| bat-metachar | 36 | 35 |
| bash-versioned-php | 35 | 0 |
| bash-vendor-bin-shebang | 21 | 0 |
| git-worktree-junction | 20 | 20 |
| ps-bad-parameter | 18 | 19 |
| ps-bare-bash | 10 | 11 |
| ps-git-commit-stdin | 9 | 9 |
| ps-dotnet-relative-path | 6 | 6 |
| git-no-verify | 5 | 5 |
| git-unreadable | 5 | 5 |
| stale-write-var | 5 | 5 |
| ps-native-nonewline | 4 | 4 |
| bash-powershell-syntax | 4 | 0 |
| bash-unterminated-quote | 3 | 0 |
| cli-inline-prose | 1 | 1 |

## Rows with a deny, by label

A deny on an `ok` row is a call that ran without the error the rule predicts: a false-positive candidate.

| Label | Full | Installed |
|---|---:|---:|
| ok | 1072 | 804 |
| failed | 174 | 138 |
| denied-hook | 259 | 259 |
| denied-permission | 3 | 2 |

## `denied-hook` rows by hook

| Hook | Rows |
|---|---:|
| baseline-guard | 302 |

## Replay of baseline-guard hook denies

259 of 302 rows that baseline-guard denied in the session replay to a deny today (85.8 %). The check is a positive control: each row that does not replay gets a computed cause, and the run fails when more than 5 % of them are unexplained.

Rows that no longer replay, by cause: `target gone` = the row's cwd or a drive path the deny message names does not exist now; `rule narrowed` = baseline-guard at its first commit in the host setup repo does not deny the row either; anything else is `unexplained`.

| Cause | Rows |
|---|---:|
| target gone | 10 |
| rule narrowed | 33 |
| unexplained | 0 |
