# shellwise

A guard and linter for the shell commands AI coding agents run.

An agent writes a Bash or PowerShell command and runs it within the same second, hundreds of times
a day. Most are fine. shellwise reads each one before the shell does and stops the careless
mistakes: the command that will not run, the one that will hang, and the one that deletes the wrong
thing. Every finding carries a `Fix:` line the agent can copy, so it corrects itself and carries on.

It is a seatbelt, not armour: it guards against an honest agent's mistakes, not against someone
trying to get around it.

[![ci](https://github.com/Borcioo/shellwise/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/Borcioo/shellwise/actions/workflows/ci.yml)

Status: early. Version 0.1.0 is the first release; expect rough edges and please report wrong
verdicts. `main` holds released versions, `develop` the current code.

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

```
# macOS and Linux
curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | sh
# Windows (PowerShell)
irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
```

Each downloads the release for your system, checks it against the release's `SHA256SUMS` and puts
`shellwise` in `~/.local/bin`, or `%LOCALAPPDATA%\Programs\shellwise` on Windows, where it also
adds the folder to your user `PATH`. Elsewhere it prints the line to add when the folder is not on
`PATH`.

Claude Code: install the plugin, which checks every Bash and PowerShell command before it runs:

```sh
claude plugin marketplace add Borcioo/shellwise
claude plugin install shellwise@shellwise
```

Any other agent: run `shellwise agent-setup` and paste the output to your agent. It finds its
host's hook that runs before a shell command, registers shellwise there and proves the wiring.

Update with `shellwise update`. The binary never updates itself; when a newer release exists,
the plugin adds one line to the session at its start, so the agent sees it and can tell you. To uninstall, delete the binary and remove the hook
entry or the plugin. To switch shellwise off, set `SHELLWISE=off`.

Status: these lines work from the first release that contains them (v0.1.1 has no musl builds,
no `update`, `agent-setup` or `hook generic`, and no plugin on the default branch). Tested live:
Claude Code and Codex CLI; the other hosts in the setup text come from their documentation.

### Other ways

Download the archive for your system from the
[latest release](https://github.com/Borcioo/shellwise/releases/latest), unpack it and put
`shellwise` (`shellwise.exe` on Windows) somewhere stable. Each archive comes with a `.sha256`
file and a line in `SHA256SUMS`. On Linux the install scripts pick the static musl build, which
also runs on older distributions. `SHELLWISE_INSTALL_DIR` and `SHELLWISE_VERSION` make them use
another folder or version.

| System | Archive |
|---|---|
| Windows (x64) | `shellwise-v<version>-x86_64-pc-windows-msvc.zip` |
| Linux (x64) | `shellwise-v<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (x64, static) | `shellwise-v<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux (arm64, static) | `shellwise-v<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS (Apple silicon) | `shellwise-v<version>-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `shellwise-v<version>-x86_64-apple-darwin.tar.gz` |

On macOS, CI tests the install scripts and `shellwise update` only; the rest of the suite runs on
Windows and Linux.

With a Rust toolchain:

```
cargo install --git https://github.com/Borcioo/shellwise
```

Or build from source; `rustup` installs the toolchain `rust-toolchain.toml` pins:

```
git clone https://github.com/Borcioo/shellwise
cd shellwise
cargo build --release
```

The built binary is `target/release/shellwise` (`shellwise.exe` on Windows). Checking a command
needs no service, no network and no interpreter; only `shellwise update` reaches the network, and
it runs the install script through `sh` or PowerShell.

### Claude Code hook

Without the plugin, add a `PreToolUse` hook to your user `settings.json`, with the full path of
the binary:

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

The plugin uses a 10 second timeout instead, because it cannot write your config file.

To switch it off, set the environment variable `SHELLWISE=off`, or remove the hook entry.

## Use

```
shellwise check --shell pwsh|powershell5|bash|gitbash [--cwd DIR] [--json] [-- COMMAND]
shellwise lint FILE            # a .ps1, .sh or .bash script
shellwise explain RULE-ID
shellwise hook claude-code     # the event on stdin, the host's reply on stdout
shellwise hook generic [--shell pwsh|powershell5|bash|gitbash]
shellwise update [--check|--notify]
shellwise agent-setup          # the setup text for your agent
```

`check` without `-- COMMAND` reads the command from stdin. Exit codes: 0 ok/warn, 1 break,
2 danger, 3 critical, 64 usage error. `--json` prints
`{"version":1,"level":…,"findings":[{"rule","level","message","fix","span":{"start","end"}}]}`.

`lint` exits 0 for clean or warn, 1 for break or worse, 64 when it refuses the file, 74 when it
cannot read it.

`hook generic` serves hosts that block a command on exit code 2. It reads the event on stdin and
exits 0 to let the command run (a `warn` note goes to stderr) or 2 to refuse it, with the findings
and their `Fix:` lines on stderr. Without `--shell`, a tool name of `PowerShell` in the event
means `pwsh`; otherwise it is `pwsh` on Windows and `bash` elsewhere. A usage error exits 0 with a
line on stderr, so a mistyped hook entry never blocks the shell tool.

`update` replaces the binary in its own folder with the latest release (or `SHELLWISE_VERSION`),
through the install script built into it; exit 0 updated or already current, 1 refused (a folder
it cannot write, a failed download or checksum). `--check` prints `installed <a>, latest <b>` and
exits 0 when they match, 1 when a newer release exists, 2 when the latest version cannot be read.
`--notify` prints one line when a newer release exists, checks at most once a day, returns within
3 seconds and always exits 0. `update` is the only command that uses the network.

`agent-setup` prints the setup text built into the binary.

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

- Not a security boundary: it catches mistakes, not someone deliberately working around it.
- Not a permission system: it does not decide which tools an agent may use.
- Not a replacement for backups, version control or reading the diff.

## Limits

- Interactive programs (an editor, `git rebase -i`) are not flagged yet.
- Bash: arithmetic reads a `$(…)` written inside it like the same `$(…)` outside it, except two
  that bash still runs: one in single quotes inside `(( ))`, `$(( ))` or `$[ ]`
  (`(( '$(cmd)' > 0 ))`, `$[ '$(cmd)' ]`) and one that only a variable's value carries in an array subscript (`x='a[$(cmd)]'; (( x ))`)
  are not read. One written in a static subscript that bash evaluates (`let 'a[$(cmd)]'`,
  `declare -i n; n='a[$(cmd)]'`) is, when the integer name is declared earlier in the text than
  the assignment (an assignment in a function written before the `declare -i` that precedes its
  call is not seen).
- `CDPATH` set by a shell profile the hook cannot see is not modelled.

## Develop

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and report a wrong verdict;
[SECURITY.md](SECURITY.md) says what counts as a security problem; changes are listed in
[CHANGELOG.md](CHANGELOG.md).

The maintainers' full gate:

```
pwsh -NoProfile -File scripts/gate.ps1
```

It runs `cargo fmt --check`, clippy, the tests on Windows and in WSL, `cargo deny check` and
a leak check. The leak check needs two private inputs outside the repo: `SHELLWISE_CORPUS` (the
folder with the mined command corpus) and `SHELLWISE_DENYLIST` (a file of terms that must never
appear in the repo, one regex per line, `#` comments).

## Licence

GPL-3.0-or-later. The full text is in `LICENSE`.
