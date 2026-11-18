# baseline-guard baseline

Counts only, produced by `tools/corpus/baseline.py` over the corpus `tools/corpus/extract.py` writes (see `tools/corpus/README.md`). `full` is baseline-guard's `check()`, `installed` its `check_installed()` (the rules the host setup hooks run); only deny findings count.

## Corpus read

| Count | Value |
|---|---:|
| files_main | 942 |
| files_subagent | 2745 |
| lines | 1594389 |
| rows | 50787 |
| duplicate_calls | 14518 |
| no_result | 1 |
| outside_window | 53672 |

## Rows per label and shell

| Label | Bash | PowerShell | Total |
|---|---:|---:|---:|
| ok | 21618 | 24949 | 46567 |
| failed | 447 | 3220 | 3667 |
| denied-hook | 197 | 150 | 347 |
| denied-permission | 72 | 134 | 206 |
| **all** | 22334 | 28453 | 50787 |

## Destructive rows

`destructive` comes from `data/destructive.toml`; a dynamic target is a non-flag word after the command name holding `$`, a backtick, `*`, `?`, `%VAR%` or a leading `~` (draft regex).

| Shell | Destructive | Dynamic target |
|---|---:|---:|
| Bash | 547 | 148 |
| PowerShell | 1058 | 255 |

## Deny count per rule

| Rule | Full | Installed |
|---|---:|---:|
| bash-backslash-collapse | 837 | 855 |
| bash-msys-path-mangle | 188 | 0 |
| bash-too-long | 109 | 109 |
| ps-unix-command | 77 | 0 |
| git-restore-discards | 72 | 74 |
| gate-truncated-pipeline | 46 | 48 |
| bat-metachar | 36 | 35 |
| bash-versioned-php | 35 | 0 |
| bash-vendor-bin-shebang | 21 | 0 |
| git-worktree-junction | 20 | 20 |
| ps-bad-parameter | 18 | 19 |
| ps-bare-bash | 11 | 12 |
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
| denied-hook | 264 | 264 |
| denied-permission | 2 | 1 |

## `denied-hook` rows by hook

| Hook | Rows |
|---|---:|
| baseline-guard | 306 |
| workbench | 41 |

## Replay of baseline-guard hook denies

Rows that baseline-guard denied in the session, replayed today on the real disk: 263 of 306 (85.9 %); with the disk check neutralised: 273 of 306 (89.2 %), where every folder exists and the rows of git commands, which read the disk, are replayed a second time. The check is a positive control: each row that does not replay on the real disk gets a computed cause, and the run fails when more than 5 % of them are unexplained.

Rows that no longer replay, by cause: `target gone` = a git command whose cwd, or a drive path the deny message names, does not exist now; `rule narrowed` = a row dated before baseline-guard's first commit in the host setup repo, which that version does not deny either; anything else is `unexplained`.

| Cause | Rows |
|---|---:|
| target gone | 10 |
| rule narrowed | 33 |
| unexplained | 0 |
