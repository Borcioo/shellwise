# ps-git-commit-stdin

`git commit -F -` reads the message from stdin. When nothing is piped in, PowerShell passes the here-string written after it as a pathspec, and no commit is made.

| Case | Level | Why |
|---|---|---|
| `-F -`, `--file=-` or a cluster ending in F with `-` and nothing piped in | `break` | No commit. |
| The here-string piped in, `-m`, or a message file | `ok` |  |

## Deny

```powershell
git commit -qF - @'
msg
'@
```

`break`: the fix replaces `-F -` with `-m` and keeps the here-string after it.

## Allow

```powershell
@'
msg
'@ | git commit -F -
```

`ok`
