---
title: shellwise agent-setup
description: Print the setup text you paste to your AI agent so it wires shellwise into its host.
---

`shellwise agent-setup` prints a text addressed to your AI coding agent. The agent follows it to
register shellwise in its host's pre-command hook and to prove the wiring works.

## Usage

```text
shellwise agent-setup
```

It takes no flags, reads nothing and uses no network. The text is built into the binary, so it
matches the installed version. It always exits 0 (64 on a usage error, such as an extra
argument).

## How to use it

1. Install shellwise; see [Install](/shellwise/docs/install/).
2. Run `shellwise agent-setup` and copy the whole output.
3. Paste it into a session with your agent and let it work.
4. Read the agent's report: what it changed, where the backup is, and what the three proof steps
   showed.

You can also pipe the text to a file and point the agent at it:

```sh
shellwise agent-setup > shellwise-setup.md
```

```powershell
shellwise agent-setup | Set-Content shellwise-setup.md
```

On Claude Code, the plugin is the shorter way; see [Claude Code](/shellwise/docs/agents/claude-code/).

## What the text asks the agent to do

- Find its host's hook that runs before a shell command, at user level.
- Find the full path of the `shellwise` binary and use it in the entry.
- Pick `--shell` for the shell its shell tool really runs (always on Windows).
- Back up the host's config file next to itself before editing it.
- Add one entry for the shell tool only, using a guard line where the host needs one.
- Set the hook timeout to 10 seconds or more.
- Run the proof: `shellwise check` on a command that must give `break`, the same command through
  the shell tool (it must be blocked), and one harmless command (it must run).
- Undo the change if the harmless command is blocked, and report.

It also holds a table of hosts with their config file, event name, matcher and timeout unit, and
the guard lines for hosts that run the entry through `sh` or PowerShell. The text is also
on [Setup text](/shellwise/docs/agents/setup-text/). Hosts other than
Claude Code and Codex CLI are on [Other hosts](/shellwise/docs/agents/other/).

## Output

The start of the output:

```sh
shellwise agent-setup
```

```text
# Wire shellwise into your agent host

You are the AI coding agent reading this. Follow these steps to make your host run shellwise
before every shell command you run. Report to the user what you changed and what the proof showed.

## What shellwise is
```

The text goes on with `## The contract`, `## The steps`, `## The guard line`, `## Hosts`,
`## The proof`, `## No hook on this host` and `## Undo`.

:::note
Only Claude Code and Codex CLI were tested live. The other hosts in the text are described from
their documentation; see [Limits](/shellwise/docs/limits/).
:::
