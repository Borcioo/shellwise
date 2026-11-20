# cli-inline-prose

PowerShell ends a string at a typographic quote of the same family as the one that opened it (`„`, `”` and `“` close a `"` string; `‘` and `’` close a `'` string). Text passed to a CLI's prose flag (`gh pr create --body`, `--title`, `-n`) is then torn into pieces. The CLIs, subcommands and flags come from `data/programs.toml`.

| Case | Level | Why |
|---|---|---|
| A typographic quote of the opening quote's family inside the value of a prose flag | `break` | The text arrives torn. |
| A typographic quote of the other family, or a body file | `ok` |  |

Derived from Specter's `AvoidSmartQuotes` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint/mod.rs`).

## Deny

```powershell
gh pr create --title 'fix: x' --body="Fix „the” thing"
```

`break`: `Fix: quote the --body text with '...' instead, or write the text with the Write tool and pass --body-file <file>`

## Allow

```powershell
gh pr create --title x --body 'Zmiana „x” gotowa'
```

`ok`
