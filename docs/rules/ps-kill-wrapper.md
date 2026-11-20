# ps-kill-wrapper

Stopping processes by name stops other sessions' runs too, and stopping an npm or pnpm wrapper leaves its node child holding the port.

| Case | Level | Why |
|---|---|---|
| `Stop-Process -Name`, `taskkill /IM`, `pkill`, `killall` | `warn` | Too wide. |
| By process id | `ok` |  |

## Deny

```powershell
Stop-Process -Name node -Force
```

`warn`: `Fix: stop the process that owns the port: Get-NetTCPConnection -LocalPort <p> | % OwningProcess | Stop-Process`

## Allow

```powershell
Stop-Process -Id $serverPid -Force
```

`ok`
