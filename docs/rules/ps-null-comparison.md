# ps-null-comparison

`$null` on the right of an equality test: when the left side is an array, PowerShell filters it, and the condition reads the filtered result, not whether the value is null.

| Case | Level | Why |
|---|---|---|
| `-eq`, `-ne` and their case variants with `$null` on the right | `warn` | Wrong answer for arrays. |
| `$null` on the left | `ok` |  |

Derived from Specter's `PossibleIncorrectComparisonWithNull` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint.rs`).

## Deny

```powershell
if ($items -eq $null) { 'none' }
```

`warn`: `Fix: put $null on the left: $null -eq $items`

## Allow

```powershell
if ($null -eq $items) { 'none' }
```

`ok`
