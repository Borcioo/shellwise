# ps-stdin-script

Script text piped into an interpreter through PowerShell's stdin loses its non-ASCII characters: they arrive as U+FFFD.

| Case | Level | Why |
|---|---|---|
| Piped into an interpreter with no script argument, or with `-` | `warn` | Non-ASCII text is lost. |
| A script file, or data piped into a script | `ok` |  |

## Deny

```powershell
Get-Content x.py | python
```

`warn`: `Fix: write the script to a UTF-8 file with the Write tool and run python <file>`

## Allow

```powershell
git diff | python tools/count.py
```

`ok`
