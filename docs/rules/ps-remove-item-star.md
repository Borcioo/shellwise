# ps-remove-item-star

`Remove-Item <dir>\*` is refused by the tool guard, which does not delete a path ending in `\*`, so the folder is not emptied.

| Case | Level | Why |
|---|---|---|
| A delete cmdlet with a path argument ending in `\*` or `/*` | `warn` | The guard refuses it. |
| The same text inside a string | `ok` |  |

## Deny

```powershell
Remove-Item build\* -Recurse -Force
```

`warn`: `Fix: Get-ChildItem -LiteralPath build -Force | Remove-Item -Recurse -Force`

## Allow

```powershell
Write-Output 'Remove-Item build\*'
```

`ok`
