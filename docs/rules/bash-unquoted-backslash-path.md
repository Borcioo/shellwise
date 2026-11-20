# bash-unquoted-backslash-path

Outside quotes, bash reads a backslash as an escape and drops it: `cd X:\src\x` changes to the
folder `X:srcx`. A Windows path in a Bash command needs forward slashes or quotes.

| Case | Level |
|---|---|
| a command word or argument holding `X:\` outside quotes | `break` |
| the path in `"…"` or `'…'`, or written with `/` | no finding |
| `X:\\` (two backslashes) | no finding here: see `bash-backslash-collapse` |

The level follows the landing rule: the corpus replay denies 0 `ok` rows, so it is `break`
(`UNQUOTED_PATH_LEVEL`). Git Bash only.

## Deny

```bash
cd X:\src\x && git status
```

`break`: `Fix: write X:/src/x with forward slashes`

## Allow

```bash
cd "X:/src/x" && git status
```

`ok`.
