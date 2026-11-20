# bash-cd-slash-d

`cd /d <path>` is cmd.exe syntax. Bash reads `/d` as the folder and fails with
`cd: too many arguments`, so nothing after `&&` runs. The spelling comes from the `cmd_options`
of the `cd` row in `data/programs.toml`.

| Case | Level |
|---|---|
| `cd /d <path>` (any case of `/d`), behind wrappers too | `break` |
| `cd /d` with no path after it (`cd /d && ls`, `cd /d 2>/dev/null`) | no finding: that is the D: drive |

`break`: 0 `ok` corpus rows give `cd /d` a path. Git Bash only.

## Deny

```bash
cd /d X:\src\x && dotnet test
```

`break`: `Fix: cd "X:/src/x"`. The unquoted backslash path is also reported
(`bash-unquoted-backslash-path`).

## Allow

```bash
cd /d && ls
```

`ok`.
