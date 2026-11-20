# claude-cmd-live-config

A `claude` subcommand that writes into the live config dir (`.claude.json`, `backups/`) unless `CLAUDE_CONFIG_DIR` points elsewhere. The harmless subcommands are listed on the `claude` row of `data/programs.toml`.

| Case | Level | Why |
|---|---|---|
| A writing subcommand with no config dir set in the command or the environment | `warn` | It changes the live config. |
| The variable set first, or a harmless call | `ok` |  |

## Deny

```powershell
claude plugin validate .
```

`warn`: `Fix: $env:CLAUDE_CONFIG_DIR = Join-Path $env:TEMP 'claude-scratch'; claude plugin validate .`

## Allow

```powershell
$env:CLAUDE_CONFIG_DIR = 'X:\tmp\cfg'; claude plugin validate .
```

`ok`
