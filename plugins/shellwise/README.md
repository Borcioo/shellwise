# shellwise plugin for Claude Code

Checks every Bash and PowerShell command Claude Code is about to run with `shellwise hook
claude-code`, and refuses the ones shellwise finds broken or destructive. Once a day, at session
start, it prints one line when a newer shellwise is released (`shellwise update --notify`).

The plugin ships no binary: it runs the `shellwise` found on `PATH`. Without it the hook fails and
every command runs unchecked, so install the binary first.

If your PATH contains `.` or another relative entry, a file named `shellwise` in a project folder
can run instead of the installed one; remove such entries.

## Install

1. Install the binary.

   macOS and Linux:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | sh
   ```

   Windows (PowerShell):

   ```powershell
   irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
   ```

   Open a new terminal and check that `shellwise --version` runs.

2. Add the marketplace and install the plugin, from your shell:

   ```sh
   claude plugin marketplace add Borcioo/shellwise
   claude plugin install shellwise@shellwise
   ```

   or inside a Claude Code session: `/plugin marketplace add Borcioo/shellwise`, then
   `/plugin install shellwise@shellwise`.

Enable only one plugin that registers this hook, or every command is checked twice.

## Update

The marketplace keeps the plugin's files current. Update the binary with `shellwise update`.

## Switch off

- For one session: start Claude Code with `SHELLWISE=off` in its environment. The hook then lets
  every command through.
- For good: `claude plugin disable shellwise@shellwise`, or `/plugin disable shellwise@shellwise`
  in a session.
