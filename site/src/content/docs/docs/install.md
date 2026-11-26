---
title: Install
description: The one-line installers, other ways to install, update, uninstall and platform status.
---

## One-line install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | sh
```

Windows (Windows PowerShell 5.1 or PowerShell 7):

```powershell
irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
```

Open a new terminal and check that the binary runs:

```text
$ shellwise --version
shellwise 0.2.0
```

## What the installers do

Both scripts do the same steps. Running one again is the update.

1. Pick the release for your system. `install.sh` installs `x86_64-unknown-linux-musl` on Linux
   x64 (the static build, which also runs on older distributions), `aarch64-unknown-linux-musl`
   on Linux arm64, and `x86_64-apple-darwin` or `aarch64-apple-darwin` on macOS. `install.ps1`
   installs `x86_64-pc-windows-msvc` and refuses on any processor other than x64.
2. Read the latest version from the latest release's `SHA256SUMS`, unless `SHELLWISE_VERSION`
   names one.
3. Download that release's `SHA256SUMS` and the archive (`install.sh` uses `curl`, or `wget`
   when there is no `curl`).
4. Compute the archive's SHA-256 and refuse unless it matches the one line for that archive in
   `SHA256SUMS`. No line, more than one line or a different digest ends the run with
   `nothing was installed`.
5. Unpack the archive in a temp folder and copy the binary into the install folder under a
   temporary name, then rename it over the old binary. On Windows the old `shellwise.exe` is
   first renamed to `shellwise.exe.old`, because a running binary cannot be overwritten, and then
   deleted; while a program still runs it, the next run deletes it.
6. Print `Installed shellwise <version> at <path>`, handle `PATH` (below) and print
   `Next: shellwise agent-setup`.

The install folder is `~/.local/bin` on macOS and Linux and `%LOCALAPPDATA%\Programs\shellwise` on
Windows.

`PATH` handling differs:

- `install.sh` never edits a shell profile. When the folder is not on `PATH`, it prints the line
  to add, `export PATH="<folder>:$PATH"`.
- `install.ps1` adds the folder to your user `PATH` when it is not there yet, and to the `PATH` of
  the current session. It prints `Added <folder> to your user PATH; open a new terminal to use it
  there.`

A refusal is one message starting with `shellwise install:`. `install.sh` then exits 1;
`install.ps1` throws it as an error under `iex`, and exits 1 when run as a file.

## Settings

The scripts read their settings only from the environment.

| Variable | Effect |
|---|---|
| `SHELLWISE_VERSION` | Install this version (`1.2.3` or `v1.2.3`) instead of the latest |
| `SHELLWISE_INSTALL_DIR` | Install into this folder; a relative path is taken from the current folder |
| `SHELLWISE_NO_PATH` | `1` skips the `PATH` step |

```sh
curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | SHELLWISE_VERSION=0.2.0 SHELLWISE_INSTALL_DIR="$HOME/bin" sh
```

```powershell
$env:SHELLWISE_VERSION = '0.2.0'; irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
```

## Other ways

### Release archives

Download the archive for your system from the
[latest release](https://github.com/Borcioo/shellwise/releases/latest), unpack it and put
`shellwise` (`shellwise.exe` on Windows) somewhere stable on your `PATH`. Each archive has a
`.sha256` file next to it and a line in the release's `SHA256SUMS`. It unpacks to a folder
`shellwise-v<version>-<target>` that holds the binary, `README.md`, `LICENSE` and `CHANGELOG.md`.

| System | Archive |
|---|---|
| Windows (x64) | `shellwise-v<version>-x86_64-pc-windows-msvc.zip` |
| Linux (x64) | `shellwise-v<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (x64, static) | `shellwise-v<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux (arm64, static) | `shellwise-v<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS (Apple silicon) | `shellwise-v<version>-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `shellwise-v<version>-x86_64-apple-darwin.tar.gz` |

### Cargo

With a Rust toolchain:

```sh
cargo install --git https://github.com/Borcioo/shellwise
```

### From source

`rustup` installs the toolchain that `rust-toolchain.toml` pins:

```sh
git clone https://github.com/Borcioo/shellwise
cd shellwise
cargo build --release
```

The binary is `target/release/shellwise` (`shellwise.exe` on Windows).

## Update

```sh
shellwise update
```

`update` runs the install script built into the binary (`sh` on macOS and Linux; PowerShell 7,
else Windows PowerShell, on Windows). It installs into the folder of the running binary, whatever
`SHELLWISE_INSTALL_DIR` says, and leaves `PATH` alone. `SHELLWISE_VERSION` pins the version.

- Exit 0: updated, or already current. A build newer than the latest release is kept.
- Exit 1: refused. A folder it cannot write, a failed download or a checksum mismatch. For a
  folder it cannot write, update that copy the way it was installed.

`shellwise update --check` only compares versions: exit 0 when they match, 1 when a newer release
exists, 2 when the latest version cannot be read.

```text
$ shellwise update --check
installed 0.2.0, latest 0.2.0
```

The binary never updates itself. See [`update`](/shellwise/docs/commands/update/) for `--notify`.

## Uninstall

1. Delete the binary.
2. Remove the hook entry from your agent's config, or uninstall the plugin.
3. On Windows, remove the install folder from your user `PATH` if the installer added it.
4. Optional: delete the `shellwise` folder in your config folder (`%APPDATA%` on Windows,
   `~/Library/Application Support` on macOS, `$XDG_CONFIG_HOME` or `~/.config` elsewhere). It
   holds your `config.toml` and the `update-check` stamp.

## Switch off

Set `SHELLWISE=off` in the environment. The hooks then let every command through and `check`
prints `ok`. Remove the variable to switch shellwise on again.

## Platform status

- Windows x64 and Linux x64 (`x86_64-unknown-linux-gnu`): CI runs the full test suite on
  `windows-latest` and `ubuntu-latest`, on pushes to `main` and `develop`, on pull requests, and
  again before each release.
- Linux x64 static (`x86_64-unknown-linux-musl`) and Linux arm64 (`aarch64-unknown-linux-musl`):
  CI builds each on a native runner and runs only `shellwise --version` and one `check` on it.
  Nobody has run the arm64 binary beyond that.
- macOS (both): on macOS, CI runs only the install-script and `update` tests. The two macOS
  binaries are built but never run, in CI or anywhere else.
