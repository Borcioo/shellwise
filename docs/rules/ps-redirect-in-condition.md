# ps-redirect-in-condition

`>` or `<` in a condition redirects output to a file named after the right side; it does not compare.

| Case | Level | Why |
|---|---|---|
| A file redirection inside an `if`, `elseif`, `while` or `do` condition | `warn` | It writes a file. |
| `-gt` / `-lt`, or a redirection in the body | `ok` |  |

Derived from Specter's `PossibleIncorrectUsageOfRedirectionOperator` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint.rs`).

## Deny

```powershell
if ($a > 5) { 'x' }
```

`warn`: `Fix: compare with -gt instead of >`

## Allow

```powershell
if ($a -gt 5) { 'x' }
```

`ok`
