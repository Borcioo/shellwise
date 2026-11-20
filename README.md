# shellwise

A guard and linter for the shell commands AI coding agents run.

An agent writes a Bash or PowerShell command and runs it within the same second, hundreds of times
a day. Most are fine. shellwise reads each one before the shell does and stops the careless
mistakes: the command that will not run, the one that will hang, and the one that deletes the wrong
thing. Every finding carries a `Fix:` line the agent can copy, so it corrects itself and carries on.

It is a seatbelt, not armour: it guards against an honest agent's mistakes, not against someone
trying to get around it.

Status: version 1 is in final review. Not released; build it from source.

## What it catches

| Kind | Example | What shellwise says |
|---|---|---|
| Will not run | `Write-Output "$name: done"` | `break ps-var-colon`: PowerShell reads `$name:` as a drive. Fix: `"${name}:"` |
| Will hang | `until grep -q done build.log; do sleep 15; done` | `break wait-loop-unbounded`: nothing bounds the loop. Fix: the same loop with a counter |
| Will hang | `tail -f app.log` | `warn follow-unbounded`. Fix: `timeout 60 tail -f app.log` |
| Will destroy | `rm -rf "$DIR/"` | `danger delete-empty-expansion`: an empty `DIR` makes this `rm -rf /`. Fix: `"${DIR:?}/"` |
| Will destroy | `Remove-Item -Recurse -Force C:\Windows\Temp\..` | `critical delete-critical`: a system folder |

```
$ shellwise check --shell bash -- 'until grep -q done build.log; do sleep 15; done'
break wait-loop-unbounded [0..47]: the loop polls and nothing bounds it: no counter, deadline or
timeout ends it, so when what it waits for never comes it runs forever
  Fix: for i in $(seq 1 40); do grep -q done build.log && break; sleep 15; done
```

The rules are documented one file each in [`docs/rules/`](docs/rules); `shellwise explain <id>`
prints the same text.

## Levels

| Level | Meaning | Effect in a hook |
|---|---|---|
| `ok` | nothing to say | runs, no output |
| `warn` | probably fine, worth a note | runs, the agent gets the note |
| `break` | will fail or hang as written | not run, the agent gets the fix |
| `danger` | may destroy work | not run, unless repeated with ` # shellwise: allow` at its end |
| `critical` | system files, the repository itself | never run; the marker has no effect |

Deleting is allowed and signalled; only the truly dangerous deletes are refused. A command
shellwise does not know is never blocked for being unknown.

When shellwise cannot finish its analysis it fails closed: `danger`, unless the raw text is a
simple read-only command without options (`git status`, `ls src`, `cargo --version`, …); the allow
marker has no effect there. A destructive command (from `data/destructive.toml`) found in the raw
text is named in the reason.

## Install

Build from source with the toolchain `rust-toolchain.toml` pins:

```
cargo build --release
```

The binary is `target/release/shellwise` (`shellwise.exe` on Windows). It needs no service, no
network and no interpreter.

### Claude Code hook

Add a `PreToolUse` hook to your user `settings.json`, with the full path of the binary:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          { "type": "command", "command": "/full/path/to/shellwise", "args": ["hook", "claude-code"], "timeout": 5 }
        ]
      }
    ]
  }
}
```

Give shellwise the same time limit, so it answers before the host gives up, in
`<config dir>/shellwise/config.toml` (`%APPDATA%` on Windows, `~/Library/Application Support` on
macOS, `$XDG_CONFIG_HOME` or `~/.config` elsewhere):

```toml
hook_timeout_ms = 5000
```

To switch it off, set the environment variable `SHELLWISE=off`, or remove the hook entry.

## Use

```
shellwise check --shell pwsh|powershell5|bash|gitbash [--cwd DIR] [--json] [-- COMMAND]
shellwise lint FILE            # a .ps1, .sh or .bash script
shellwise explain RULE-ID
shellwise hook claude-code     # the event on stdin, the host's reply on stdout
```

`check` without `-- COMMAND` reads the command from stdin. Exit codes: 0 ok/warn, 1 break,
2 danger, 3 critical, 64 usage error. `--json` prints
`{"version":1,"level":…,"findings":[{"rule","level","message","fix","span":{"start","end"}}]}`.

`lint` exits 0 for clean or warn, 1 for break or worse, 64 when it refuses the file, 74 when it
cannot read it.

A repository may carry a `.shellwise.toml` at its root; it can only raise levels, never lower them.

## Speed

Measured on 2026-11-20 on one Windows 11 developer machine:

| What | Result |
|---|---|
| Whole hook call, process start included (2,000 calls, no shell, event on stdin) | median 15 ms, 99th percentile 22 ms |
| The same call through a Python guard doing a similar job | median 105 ms |
| Analysis alone, inside the process | median 0.3 ms (Bash), 0.6 ms (PowerShell); 99th percentile under 6 ms |

Known gap: `lint` on a whole script is slower than its target of 50 ms per 500 lines.

## How it is tested

- The real shell is the judge: where a rule says a shell refuses or misreads a command, a test
  asks that shell (`--features oracle`; needs `pwsh` and Git Bash). Fix lines are run in the real
  shell.
- Each safety check is broken on purpose once to show a test goes red.
- The suite runs on Windows and on Linux before every merge.
- Every build replays a private set of about 50,000 commands recorded from real agent sessions.
  On 2026-11-20, of 45,303 commands that had run fine, 26 were stopped by mistake; a further 206
  unbounded wait loops were stopped on purpose.

## What it is not

- Not an antivirus or a sandbox: it does not stop an attacker.
- Not a permission system: it does not decide which tools an agent may use.
- Not a replacement for backups, version control or reading the diff.

## Limits

- Interactive programs (an editor, `git rebase -i`) are not flagged yet.
- Bash: a name without the integer attribute assigned exactly one run-time expansion and nothing
  else (`n=$(cmd)`, `n=$1`) counts as clean when arithmetic evaluates it, so a `$(…)` that such a
  value carries in an array subscript is not seen: the value is command output or an argument at
  run time.
- Bash: command output that arithmetic reads directly (`(( $(cmd) ))`, `$(( $(cmd) ))`,
  `[[ $(cmd) -eq 1 ]]`, `${s:$(cmd)}`, `${a[$(cmd)]}`, `a[$(cmd)]=1`, `a=([$(cmd)]=1)`,
  `unset "a[$(cmd)]"`, `[[ -v a[$(cmd)] ]]`, `exec {a[$(cmd)]}>f`, `declare -i n; n=$(cmd)`) makes
  the command opaque,
  unless the command is `date +%s`, `date +%s%N`, `id -u` or `wc -l < FILE` with a literal path,
  written with spaces (a tab between the words of a `$(…)` counts as one; other tabs make the
  command opaque), and the script defines no function of that name or `command_not_found_handle`,
  writes (also by `{NAME}>f` or `coproc NAME`), declares or unsets none of `PATH`,
  `BASH_ALIASES`, `BASH_CMDS` and `EXECIGNORE`, and runs no `hash`, `alias`, `enable`, `source`,
  `.` or command whose name is not static. A `PATH`, `EXECIGNORE` or function inherited from the
  environment that finds another such command is not seen.
- `CDPATH` set by a shell profile the hook cannot see is not modelled.

## Develop

```
pwsh -NoProfile -File scripts/gate.ps1
```

The gate runs `cargo fmt --check`, clippy, the tests on Windows and in WSL, `cargo deny check` and
a leak check. The leak check needs two private inputs outside the repo: `SHELLWISE_CORPUS` (the
folder with the mined command corpus) and `SHELLWISE_DENYLIST` (a file of terms that must never
appear in the repo, one regex per line, `#` comments).

## Licence

GPL-3.0-or-later. The full text is in `LICENSE`.
