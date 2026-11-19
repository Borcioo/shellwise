# ps-native-nonewline

A native program's output reaches a cmdlet as separate lines; `Set-Content -NoNewline` (or `Out-File -NoNewline`, `Add-Content -NoNewline`) joins them with nothing between, so every line break in the file is lost. A producer counts as native when its name is not an approved PowerShell verb-noun.

| Case | Level | Why |
|---|---|---|
| A native producer piped into a write cmdlet with -NoNewline | `break` | The file becomes one line. |
| A cmdlet producer, or `-NoNewline:$false` | `ok` |  |

## Deny

```powershell
git show HEAD:src/a.js | Set-Content -NoNewline src/a.js
```

`break`: `Fix: drop -NoNewline: Set-Content src/a.js`

## Allow

```powershell
Get-Content a.txt | Set-Content -NoNewline b.txt
```

`ok`
