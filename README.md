# shellwise

A command guard and lint for shell commands written by AI coding agents. It reads one command
(PowerShell or bash), judges it and answers with a level: `ok`, `warn`, `break`, `danger` or
`critical`. When it cannot finish the analysis it fails closed: `danger`, unless the raw text is a
simple read-only command without options (`git status`, `ls src`, `cargo --version`, …); the allow
marker has no effect there. A destructive command (from `data/destructive.toml`) found in the raw
text is named in the reason.

Status: early development, not released.

## Use

```
shellwise check --shell pwsh|powershell5|bash|gitbash [--cwd DIR] [--json] [-- COMMAND]
```

Without `-- COMMAND` the command is read from stdin. Exit codes: 0 ok/warn, 1 break, 2 danger,
3 critical, 64 usage error. `--json` prints
`{"version":1,"level":…,"findings":[{"rule","level","message","fix","span":{"start","end"}}]}`.

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
