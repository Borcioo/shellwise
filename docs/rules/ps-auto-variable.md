# ps-auto-variable

An assignment to a variable PowerShell owns: a read-only or constant one (`$home`, `$true`) fails, an automatic one (`$input`, `$matches`, `$args`) is overwritten by PowerShell. The variable kinds come from the generated table (`variable` rows, from a fresh pwsh 7 session, plus Specter's list of writable automatic variables).

| Case | Level | Why |
|---|---|---|
| Assignment to a constant, read-only or automatic variable | `warn` | Fails, or the value is lost. |
| Any other name, `$null = …` | `ok` |  |

Derived from Specter's `AvoidAssignmentToAutomaticVariable` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint/mod.rs`).

## Deny

```powershell
$home = 'x'; Write-Output $home
```

`warn`: `Fix: rename the variable, for example $homeValue`

## Allow

```powershell
$null = Get-Item a.txt
```

`ok`
