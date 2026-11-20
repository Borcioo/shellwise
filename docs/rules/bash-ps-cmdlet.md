# bash-ps-cmdlet

A PowerShell cmdlet as a command in the Bash tool: Git Bash has no such command
(`Get-ChildItem: command not found`). It replaces the baseline guard's `bash-powershell-syntax`.

| Case | Level |
|---|---|
| a command named by a cmdlet's own name (`Get-Content`, `select-string`), behind wrappers too | `break` |
| a PowerShell alias such as `ls` or `cat` | no finding: those are real programs in Git Bash |
| a dashed name the program table knows (`docker-compose`) or no cmdlet has (`git-lfs`) | no finding |
| a cmdlet name as an argument (`echo Get-Content`) | no finding |

The cmdlet names come from the generated PowerShell name table (`src/parse/pwsh_names.txt`).
The level follows the landing rule: the corpus replay denies 2 `ok` rows, both a cmdlet that
failed behind `2>/dev/null`, so it is `break` (`PS_CMDLET_LEVEL`). Git Bash only.

## Deny

```bash
Get-ChildItem -Path C:/x -Recurse | Select-Object -First 5
```

`break`: `Fix: run this in the PowerShell tool`

## Allow

```bash
docker-compose up -d
```

`ok`.
