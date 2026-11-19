# ps-missing-mandatory

A cmdlet call that leaves a mandatory parameter of every usable parameter set unbound and pipes nothing in. PowerShell then prompts for the value, which a non-interactive tool cannot answer.

| Case | Level | Why |
|---|---|---|
| No parameter set has all its mandatory parameters bound, and no input is piped in | `warn` | The call waits for a prompt. |
| A positional value, or input from the pipeline | `ok` |  |

Derived from Specter's `UseCmdletCorrectly` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint.rs`).

## Deny

```powershell
Get-Item -Force
```

`warn`: `Fix: pass it: Get-Item -Force -path <value>`

## Allow

```powershell
Get-ChildItem a.txt | Get-Item -Force
```

`ok`
