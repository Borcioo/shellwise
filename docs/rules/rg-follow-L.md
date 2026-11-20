# rg-follow-L

`rg -L` is `--follow` (follow symbolic links), not grep's "files without a match".

| Case | Level | Why |
|---|---|---|
| `rg` with `-L` | `warn` | It lists matches, not files without one. |
| `rg -l` | `ok` |  |

## Deny

```powershell
rg -L TODO src
```

`warn`: `Fix: for files without a match use --files-without-match: rg --files-without-match TODO src`

## Allow

```powershell
rg -l TODO src
```

`ok`
