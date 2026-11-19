# ps-assign-in-condition

`=` in an `if`, `elseif`, `while` or `do` condition assigns; it does not compare, so the condition tests the assigned value.

| Case | Level | Why |
|---|---|---|
| An assignment of a plain value in a condition | `warn` | Always the assigned value. |
| A command or method result assigned, double parentheses, or `-eq` | `ok` | The usual intended assignments. |

Derived from Specter's `PossibleIncorrectUsageOfAssignmentOperator` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint.rs`).

## Deny

```powershell
if ($a = 5) { 'x' }
```

`warn`: `Fix: compare with -eq: $a -eq 5`

## Allow

```powershell
if (($a = 5)) { 'x' }
```

`ok`
