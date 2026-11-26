---
title: shellwise update
description: Replace the binary with the latest release, check for a newer one, or print a once-a-day notice.
---

`shellwise update` installs a release over the running binary, in the binary's own folder.
`update` is the only command that uses the network. `check`, `lint`, `explain`, `agent-setup`
and the hooks never reach it.

The binary has no HTTP client of its own. It runs the install script built into it: through `sh`
on macOS and Linux, through PowerShell 7 (`pwsh`) or, when that is missing, Windows PowerShell on
Windows. The script downloads the archive and checks it against the release's checksums.

## Usage

```text
shellwise update
shellwise update --check
shellwise update --notify
```

`--check` and `--notify` cannot be used together (usage error, exit 64).

## shellwise update

1. Finds the running binary's folder and checks that it can create a file there.
2. Reads the latest release version (it waits at most 10 seconds), unless `SHELLWISE_VERSION`
   names a version.
3. Stops when the target is the installed version: `shellwise <version> is current`.
4. Stops when the latest release is older than this build:
   `shellwise <version> is current (the latest release is <latest>)`.
5. Runs the install script with the binary's folder as the install folder. It does not change
   your `PATH`.

| Exit | Meaning |
|---|---|
| 0 | updated, or already current |
| 1 | refused: the folder cannot be written, the latest version cannot be read, the script failed or could not start |
| 64 | usage error |

On a refusal, stderr holds one line saying why. When the folder cannot be written, the line ends
with `update this copy the way it was installed`: a copy installed by a package manager or into a
system folder is updated that way.

### SHELLWISE_VERSION

`SHELLWISE_VERSION=1.2.3` (or `v1.2.3`) installs that version instead of the latest. It skips the
latest-version check, so it can also install an older version. An empty value counts as unset.

```sh
SHELLWISE_VERSION=0.2.0 shellwise update
```

```powershell
$env:SHELLWISE_VERSION = '0.2.0'; shellwise update
```

## shellwise update --check

Prints the installed and the latest version and installs nothing. It waits at most 10 seconds.

```sh
shellwise update --check
```

```text
installed 0.2.0, latest 0.2.0
```

| Exit | Meaning |
|---|---|
| 0 | the latest release is not newer |
| 1 | a newer release exists |
| 2 | the latest version could not be read |

On exit 2, stderr says `shellwise update: the latest version could not be read: <reason>`.

## shellwise update --notify

Made for a session-start hook. It prints one line when a newer release exists and nothing
otherwise:

```text
shellwise <latest> is available (installed <installed>): run shellwise update
```

- It checks at most once in 24 hours. The time of the last check is written, before the check
  runs, to a file `update-check` next to the user config file:

  | System | File |
  |---|---|
  | Windows | `%APPDATA%\shellwise\update-check` |
  | macOS | `~/Library/Application Support/shellwise/update-check` |
  | Linux and others | `$XDG_CONFIG_HOME/shellwise/update-check`, else `~/.config/shellwise/update-check` |

  The file holds the time as seconds since 1970. When it cannot be written, no check runs.
- The version check gets 2.3 seconds; the whole call returns within about 3 seconds.
- It writes nothing to stderr and always exits 0, also when the network is down.

The Claude Code plugin runs `--notify` at session start, so the agent sees the line and can tell
you; see [Claude Code](/shellwise/docs/agents/claude-code/).

## Environment

| Variable | Effect |
|---|---|
| `SHELLWISE_VERSION` | the version `update` installs |
| `SHELLWISE_BASE_URL` | passed on to the install script: the release URL, or a local folder with the same layout |

Other installation options are on [Install](/shellwise/docs/install/).
