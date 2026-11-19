# ps-misleading-backtick

A line that ends in a backtick followed by whitespace: the backtick escapes the space, not the line break, so the next line runs as a separate command.

| Case | Level | Why |
|---|---|---|
| Backtick then spaces or tabs at the end of a line, outside strings and comments | `warn` | The continuation is lost. |
| A backtick right before the line break, or inside a string | `ok` |  |

Derived from Specter's `MisleadingBacktick` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint.rs`).

## Deny

```powershell
Copy-Item a.txt `  
b.txt
```

`warn`: `Fix: delete the spaces after the backtick at the end of the line`

## Allow

```powershell
Copy-Item a.txt `
b.txt
```

`ok`
