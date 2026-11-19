# pwsh-file-list-arg

Through `pwsh -File`, a comma list reaches the script as one string, not as an array, so a parameter that takes several values gets one.

| Case | Level | Why |
|---|---|---|
| An unquoted comma list after the script path of `-File` | `warn` | One value instead of several. |
| One quoted value, or `-Command` | `ok` |  |

## Deny

```powershell
pwsh -NoProfile -File tools\sync.ps1 -Exclude a,b
```

`warn`: `Fix: pass the list as one quoted value, or use -Command`

## Allow

```powershell
pwsh -NoProfile -File tools\sync.ps1 -Exclude 'a,b'
```

`ok`
