# ps-bad-parameter

A cmdlet call that PowerShell refuses at binding time: a parameter name it cannot find, a prefix that matches several parameters, a parameter left without its value, or one positional argument too many. Parameters are bound as PowerShell binds them, from the generated table `data/pwsh_commands.tsv`: exact name, exact alias, then a unique prefix of a name or alias; a provider's dynamic parameters only when no other parameter matches. A parameter that takes a value takes the next word, even one starting with a dash, unless that word names a static parameter (`-l -File` lists a path named `-File`). The table holds pwsh 7 facts only, so Windows PowerShell 5.1 is not judged; a simple function (no CmdletBinding) and a path on another provider's drive (`Cert:`, `HKLM:`) get no unknown-parameter finding. Known bash habits (`ls -la`, `Select-String -A 1`, `cd /d`, `Get-Content a.txt -n 5`, `Select-Object -n 5`) get the PowerShell spelling from the cmdlet's row in `data/programs.toml` (`lint.flag_hints`).

| Case | Level | Why |
|---|---|---|
| NamedParameterNotFound: no parameter or alias has this name or prefix | `break` | The call fails. |
| AmbiguousParameter: the prefix matches several parameters | `break` | The call fails. |
| MissingArgument: a non-switch parameter at the end or before another parameter | `break` | The call fails. |
| PositionalParameterNotFound: more positional arguments than the cmdlet takes | `break` | The call fails. |
| Words after `--`, after `--%`, or a command the table does not hold | `ok` | Not bound here. |

Derived from Specter's `UseCmdletCorrectly` and `UseCompatibleCommands` (https://github.com/rjmholt/Specter, MIT License, Copyright (c) Specter Contributors; the full notice is in the header of `src/rules/pwsh_lint/mod.rs`).

## Deny

```powershell
Get-ChildItem -la D:\x
```

`break`: `Fix: use -Force: Get-ChildItem -Force D:\x`

```powershell
Get-ChildItem -a D:\x
```

`break`: `-a` matches the FileSystem provider's -Attributes and the -ad, -af, -ah, -ar and -as aliases.

```powershell
Set-Location D:\a D:\b
```

`break`: the fix names the extra argument: `Set-Location D:\a`

## Allow

```powershell
Get-ChildItem -fo D:\x
```

`ok`: `-fo` binds -Force before the dynamic -FollowSymlink.

```powershell
Get-ChildItem D:\x -ea SilentlyContinue
```

`ok`: a common parameter alias.
