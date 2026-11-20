# ps-bare-bash

`bash` typed in PowerShell on Windows runs `System32\bash.exe`, which is WSL, not Git Bash: Windows paths and CRLF scripts break there. Windows only.

| Case | Level | Why |
|---|---|---|
| `bash` or `bash.exe` with no folder, in any statement or script block | `break` | It starts WSL. |
| Git Bash by its full path | `ok` |  |

## Deny

```powershell
bash tools/x.sh
```

`break`: `Fix: & "$env:ProgramFiles\Git\bin\bash.exe" tools/x.sh`

## Allow

```powershell
& 'C:\Program Files\Git\bin\bash.exe' tools/x.sh
```

`ok`
