# bash-unquoted-backslash-path

Outside quotes, bash reads a backslash as an escape and drops it: `cd X:\src\x` changes to the
folder `X:srcx`. A Windows path in a Bash command needs forward slashes or quotes.

| Case | Level |
|---|---|
| a command word or argument holding `X:\` outside quotes | `warn` by default |
| the path in `"…"` or `'…'`, or written with `/` | no finding |
| `X:\\` (two backslashes) | no finding here: see `bash-backslash-collapse` |

The level follows the landing rule: a draft matcher that did not tell quoted words from unquoted
ones counted 87 `ok` rows, so it starts as `warn` (`UNQUOTED_PATH_LEVEL`) until the replay counts
the rule itself. Git Bash only.

## Deny

```bash
cd X:\src\x && git status
```

`warn`: `Fix: write X:/src/x with forward slashes`

## Allow

```bash
cd "X:/src/x" && git status
```

`ok`.
