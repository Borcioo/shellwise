# shellwise

A command guard and lint for shell commands written by AI coding agents. It reads one command
(PowerShell or bash), judges it and answers with a level: `ok`, `warn`, `break`, `danger` or
`critical`. When it cannot finish the analysis it fails closed: `danger` if the raw text holds a
destructive command (from `data/destructive.toml`), `ok` otherwise.

Status: early development, not released.

## Use

```
shellwise check --shell pwsh|powershell5|bash|gitbash [--cwd DIR] [--json] [-- COMMAND]
```

Without `-- COMMAND` the command is read from stdin. Exit codes: 0 ok/warn, 1 break, 2 danger,
3 critical, 64 usage error. `--json` prints
`{"version":1,"level":…,"findings":[{"rule","level","message","fix","span":{"start","end"}}]}`.

## Limits

- Bash: a name without the integer attribute assigned exactly one run-time expansion and nothing
  else (`n=$(cmd)`, `n=$1`) counts as clean when arithmetic evaluates it, so a `$(…)` that such a
  value carries in an array subscript is not seen: the value is command output or an argument at
  run time.
- Bash: command output that arithmetic reads directly (`(( $(cmd) ))`, `$(( $(cmd) ))`,
  `[[ $(cmd) -eq 1 ]]`, `${s:$(cmd)}`, `${a[$(cmd)]}`, `a[$(cmd)]=1`, `a=([$(cmd)]=1)`,
  `unset "a[$(cmd)]"`, `[[ -v a[$(cmd)] ]]`, `declare -i n; n=$(cmd)`) makes the command opaque,
  unless the command is `date +%s`, `date +%s%N`, `id -u` or `wc -l < FILE` with a literal path,
  written with spaces (a tab between the words of a `$(…)` counts as one; other tabs make the
  command opaque), and the script defines no function of that name or `command_not_found_handle`,
  writes (also by `{NAME}>f` or `coproc NAME`), declares or unsets none of `PATH`,
  `BASH_ALIASES`, `BASH_CMDS` and `EXECIGNORE`, and runs no `hash`, `alias`, `enable`, `source`,
  `.` or command whose name is not static. A `PATH`, `EXECIGNORE` or function inherited from the
  environment that finds another such command is not seen.

## Develop

```
pwsh -NoProfile -File scripts/gate.ps1
```

The gate runs `cargo fmt --check`, clippy, the tests on Windows and in WSL, `cargo deny check` and
a leak check. The leak check needs two private inputs outside the repo: `SHELLWISE_CORPUS` (the
folder with the mined command corpus) and `SHELLWISE_DENYLIST` (a file of terms that must never
appear in the repo, one regex per line, `#` comments).

## Licence

MIT OR Apache-2.0, at your option.
