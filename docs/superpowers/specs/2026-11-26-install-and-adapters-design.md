# Install, update and agent setup — design

Status: approved by the owner on 2026-11-26.

## Intent

Two conditions were put to the project before adoption:

1. easy to install and set up;
2. easy to let agents use it by default, across harnesses.

Today a user downloads an archive by hand, puts the binary on `PATH` and pastes a hook block into
Claude Code's settings. Nothing helps with any other agent host.

shellwise stays what it is: one binary. Everyone who would install it already works with an AI
agent, so the agent does the host-specific wiring from a text we ship. The project owns three small
things: getting the binary onto `PATH`, keeping it current, and a contract simple enough that any
agent can wire it into any host that has a pre-command hook.

## Goals

1. One line installs the binary on Windows, macOS and Linux, verified against the release
   checksums, and puts it on `PATH`.
2. One command updates it.
3. One text, pasted to an agent, is enough for that agent to wire shellwise into its own host and
   prove the wiring works.
4. One hook entry point that blocks a bad command on every host whose pre-command hook follows
   the common convention (exit code 2 blocks). Whether the reason reaches the model is the host's
   doing: documented for Codex CLI and Gemini CLI, not documented for Cursor, Copilot CLI and
   Devin. A `warn` note reaches the model only through `hook claude-code`.
5. Claude Code users can install it as a plugin from a marketplace instead of editing settings.
6. The Linux binary runs on distributions older than the build runner.

## Non-goals

- A native adapter per host (Codex, Cursor, Gemini CLI, Copilot CLI, …). A host gets its own
  adapter only when the generic entry point cannot serve it, and only after a live run on that host.
- A subcommand that edits a host's config files. The agent does that from the setup text.
- `shellwise doctor`. The setup text carries the known-answer check.
- Package managers (winget, Homebrew, Scoop, npm). The README lists the routes that already work
  with no maintenance (`cargo install --git`). Each registry is a separate decision by the owner.
- crates.io. Publishing today would build against the upstream PowerShell grammar instead of the
  vendored fork (`path` plus `version` on a crate name that exists upstream); that needs its own
  design first.
- Plugins for other hosts' marketplaces. They follow once the generic entry point has been run live
  on that host.

## Anti-goals

- A broken or missing binary that blocks the user's shell tool. Claude Code, Codex CLI, Cursor and
  Devin let the command through when the hook program is missing or fails. Gemini CLI on macOS and
  Linux and Copilot CLI read a missing program or any unexpected exit code as a block, so on those
  the setup text registers the guard line (section "`shellwise agent-setup`") instead of the bare
  command.
- Network access from the hook path. Only `update` reaches the network, and only when a person or
  agent runs it.
- A change to the frozen interface: `hook claude-code` input and output, `check` flags and exit
  codes, `SHELLWISE=off`, config keys and locations, the allow marker, rule ids, the four existing
  release asset names, `--version` output. Everything here is an addition.
- Promising a host we have not run. The setup text labels each host hint as tested or as taken from
  that host's documentation.

## Constraints

- GPL-3.0-or-later; no company, client or private-harness names in the repo; nothing from dcg.
- A release, a registry publication or a new repository needs the owner's explicit OK each time.
- The sibling plugin project that enables the hook by default for Claude Code depends on the frozen
  interface and is told before any change to it and before each release. It is told about the new
  release assets and the in-repo plugin (two plugins enabled together would run the check twice).
- The binary is executed on every command and is locked while running on Windows: an update
  replaces it by rename, never by writing over it.

## Approaches

| | A. Native adapters and a config-writing installer | B. Binary, setup text, generic hook (chosen) | C. Binary and setup text only |
|---|---|---|---|
| What ships | `install`/`uninstall`/`doctor` subcommands that merge into each host's config; one adapter per host | install scripts, `update`, `agent-setup`, `hook generic`, a Claude Code plugin | install scripts and the setup text |
| Wiring a host | one command, for the hosts we cover | the user's agent, from the text; one hook command for all hosts | the user's agent writes a wrapper script per host |
| Cost | about 1500 lines of code, 1900 of tests, 22 agent hours | about 520 and 430, 8 agent hours | about 300 and 150, 4 agent hours |
| Weakness | most of the code edits other tools' config files; each host's format moves under us | the generic hook cannot give a non-blocking note on hosts that need their own JSON for it | every agent invents its own wrapper; a deny message that reaches the model is not guaranteed |

The owner rejected A as too much machinery for a binary and asked for the paste-to-agent text,
plugin installation and a built-in update. B adds one small entry point to C so the agent's wiring
is one line instead of a script it has to invent.

## Design

### Install scripts

`install.sh` (POSIX sh) and `install.ps1` (Windows PowerShell 5.1 and PowerShell 7) at the repo
root, served from the default branch:

```
curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | sh
irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
```

Both do the same steps:

1. Pick the target from the OS and CPU. Linux takes the static musl build, or the glibc build on
   x64 when the chosen release has no musl asset in `SHA256SUMS` (v0.1.1 and older). An unsupported
   pair stops with the list of supported ones.
2. Resolve the version: `SHELLWISE_VERSION` when set, else the latest release.
3. Download the archive and `SHA256SUMS` from the release into a new temp folder.
4. Verify the archive's SHA-256 against its line in `SHA256SUMS`. A missing line, a missing hash
   tool or a mismatch stops the install and leaves the existing binary untouched.
5. Unpack, then move the binary into the install folder: `SHELLWISE_INSTALL_DIR` when set, else
   `~/.local/bin` on macOS and Linux and `%LOCALAPPDATA%\Programs\shellwise` on Windows. The new
   binary is first copied into the install folder under a temporary name, so the swap never crosses
   a file system. On macOS and Linux one `rename` then replaces the old binary, with no moment
   without one. On Windows a running binary cannot be replaced but can be renamed: the old one
   becomes `shellwise.old`, the new one takes its name, and when that second step fails the old name
   is restored. A leftover `.old` from an earlier run is deleted when it is no longer locked.
6. When the folder is not on `PATH`: on Windows add it to the user `PATH`; on macOS and Linux print
   the line to add, without editing shell profiles.
7. Print the installed version and the next step: `shellwise agent-setup`.

Running the script again is the update. Uninstalling is deleting the binary; the README says so.
`SHELLWISE_BASE_URL` replaces the release URL so the tests can run against a local folder.

### `shellwise update`

Runs the install script that was embedded in the binary at build time (`sh` on macOS and Linux,
`powershell` on Windows), with the install folder set to the running binary's own folder.
`shellwise update --check` prints the installed and the latest version and exits 0 when they match,
1 when a newer one exists, 2 when the latest version could not be read. The binary gains no HTTP client: the script's `curl` or
`Invoke-WebRequest` does the download, so the binary size and the dependency set stay as they are.
Nothing else in the binary calls `update`; the hook never checks for updates.

The binary never replaces itself unasked, as other command-line tools do not: an update happens
when someone runs `shellwise update`. `shellwise update --notify` is the check a session-start hook
may run: it looks for a newer release at most once a day (a timestamp file in the user config
folder), waits at most 3 seconds, prints one line naming the new version and the command to run
when there is one, prints nothing otherwise, and exits 0 whatever happens.

### `shellwise agent-setup`

Prints `docs/agent-setup.md`, embedded at build time, so the text always matches the installed
version and works offline. The README's Install section says: paste the output to your agent.

The text is written to an agent, in the imperative, and holds:

- What shellwise is, in three lines, and that it is a guard against mistakes, not a security
  boundary.
- The contract: `shellwise hook generic` (below), `shellwise check … --json` and its exit codes,
  `SHELLWISE=off`, the allow marker.
- The steps: find your host's hook that runs before a shell command, at user level; back up the
  config file before editing it; register `shellwise hook generic --shell <shell>` with the full
  path of the binary, in the form that spawns the program directly where the host offers one; set
  the host's hook timeout to 10 seconds or more, in the host's own unit (the analysis ends by
  itself after 8.5 seconds with the default `hook_timeout_ms`, so the host never has to cut it off).
- The guard line, for a host that blocks on a missing program or on any exit code other than 0:
  a one-line shell command (one for `sh`, one for PowerShell) that runs the hook, passes exit code 2
  and its stderr through, and turns a missing binary and every other exit code into 0.
- A table of hosts with a known pre-command hook (config file, event name, matcher, timeout unit,
  bare command or guard line, whether the host shows the block reason to the model), each row marked
  `tested` or `from the host's documentation`. Claude Code's row names `hook claude-code` and the
  plugin instead. Cursor's row says it already runs a Claude Code hook found in the user's Claude
  settings, so a second entry is added only when there is none.
- The proof, in this order, so nothing runs unguarded: first `shellwise check` on the proof command
  must report `break`; then the agent runs through its own shell tool that same command, one
  shellwise refuses and that only prints a shell error if it runs anyway (an unterminated quote for
  bash, a `$name:` drive reference for PowerShell); then one harmless command that must pass. The
  agent reports what the host showed for each. A host that needs a hook approved by the user
  (Codex CLI) is named, with the step to take.
- What to tell the user when the host has no such hook: shellwise cannot guard it; `shellwise check`
  can still be called by hand.
- How to undo it: remove the entry, restore the backup.

### `shellwise hook generic`

One entry point for hosts whose hook reads a JSON event on stdin and treats exit code 2 as a block
with stderr shown to the model.

- Input: the command is the first string found at `tool_input.command`, `command`,
  `tool_info.command_line`, or `command` inside `toolArgs` when that is a JSON string. The working
  directory is `cwd` when present. Any other event shape is not ours: exit 0, no output.
- Shell: `--shell pwsh|powershell5|bash|gitbash` decides. Without it, a tool name (`tool_name` or
  `toolName`) of `powershell` (any case) means `pwsh`; otherwise `pwsh` on Windows and `bash`
  elsewhere. The setup text tells
  the agent to pass `--shell` whenever it knows what its host runs.
- Output: `ok` exits 0 silently. `warn` exits 0 with the findings on stderr. `break`, `danger` and
  `critical` exit 2 with the findings and their `Fix:` lines on stderr, in the same text form
  `hook claude-code` puts in its reason.
- Failure. `SHELLWISE=off` exits 0 before reading. Once a command was read, a panic or a deadline
  inside the analysis is the fail-closed verdict the analysis already gives (exit 2). Where no
  command could be read (stdin still open at the read bound, input over the size cap, JSON that
  does not parse), the bytes read so far go through the raw scan `hook claude-code` uses: a
  destructive command in them, or a scan that gives no answer, exits 2; anything else exits 0 with
  one line on stderr. This is narrower than `hook claude-code`, which refuses every unread event of
  a shell tool: here the host is unknown, and one that leaves stdin open must not lose its shell
  tool. A usage error and a panic outside the analysis exit 0 with a line on stderr, so a mistyped
  hook entry never blocks the tool.
- `ask_instead_of_deny` has no effect here: the convention has no "ask".

### Claude Code plugin

`.claude-plugin/marketplace.json` at the repo root and `plugins/shellwise/` with a plugin manifest
and a `hooks/hooks.json` that registers `shellwise hook claude-code` for `Bash|PowerShell` with a
10 second timeout (above the 8.5 seconds after which the analysis ends by itself with the default
`hook_timeout_ms`), calling `shellwise` from `PATH`, and a session-start hook that runs
`shellwise update --notify`. The plugin's own files are kept current by the host's marketplace
update; the binary is updated by the user. The plugin ships no binary: when `shellwise` is
not on `PATH` the hook fails open (measured in `docs/spikes.md`), and the plugin's README names the
install line. The README's Install section gives the two commands that add the marketplace and
install the plugin. Using this plugin together with another plugin that registers the same hook
runs the check twice; the README says to enable one.

### Release

- New assets: `shellwise-v<version>-x86_64-unknown-linux-musl.tar.gz` and
  `shellwise-v<version>-aarch64-unknown-linux-musl.tar.gz`, each with its `.sha256`, both in
  `SHA256SUMS`. The four existing assets keep their names and contents.
- `install.sh` and `install.ps1` are also attached to each release and listed in `SHA256SUMS`, so
  a pinned version has its own installer.
- The README's Install section becomes: the two one-liners, the plugin commands, `shellwise
  agent-setup`, `shellwise update`, then the manual download and `cargo install --git` as
  alternatives.

## Tests

- Install scripts: run in CI on Windows, Linux and macOS against a local release folder
  (`SHELLWISE_BASE_URL`): a fresh install, a second run over an existing binary, a wrong checksum
  (the old binary must still be there and still run), a missing `SHA256SUMS` line, an unsupported
  target. The checksum check is a guard: each of its refusals is shown red once by breaking it.
- `hook generic`: one row per input shape and per level, the shell rule, the fail-open rows (usage
  error, `SHELLWISE=off`, an event that is not ours), the fail-closed rows shared with
  `hook claude-code`.
- `update --check` and `agent-setup`: output and exit codes.
- Live runs before the text calls a host `tested`: Claude Code through the plugin, in an isolated
  config against the local API stub the earlier spikes used; Codex CLI with `hook generic`, on the
  one machine that has it.

## Left to the builder

- How the musl and aarch64 builds are produced in CI (cross toolchain or a native ARM runner), and
  the measured size of the static binaries.
- The exact plugin manifest fields, read from Claude Code's plugin documentation at build time.
- Whether `update` on Windows needs to start the script detached so the rename succeeds.
- Whether a plugin hook that names a bare `shellwise` is found through `PATH` in the form that
  spawns the program directly (the earlier spike proved only a missing full path), and what Cursor
  does with a hook that exits 0 with empty output; both are live runs.

## Calls made without the owner

- Cursor, Copilot CLI and Devin do not document that a block reason on stderr reaches the model.
  `hook generic` still serves them and the setup text says so per host; it does not print each
  host's own JSON, which would be the native adapters this design leaves out.
- A broken hook lets commands through wherever the host allows it; the guard line covers the two
  hosts that would block.
- The proof command in the setup text is one that does nothing when it runs unguarded.

## Estimate

About 8 agent hours; about 520 lines of code (260 of them the two scripts) and 430 lines of tests;
docs on top.

The simpler version (approach C) drops `hook generic`, `update` and the plugin: about 4 agent hours,
300 lines of code and 150 of tests. It drops the one-line wiring on hosts other than Claude Code
(each agent writes its own wrapper around `shellwise check`), the one-command update and plugin
installation.
