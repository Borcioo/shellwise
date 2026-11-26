---
title: shellwise explain
description: Print the documentation of one rule, by the id a finding names.
---

`shellwise explain` prints the documentation of one rule. The text is built into the binary, so it
matches the installed version and works offline. It is the same text as the rule's page in
[the rule reference](/shellwise/docs/rules/).

## Usage

```text
shellwise explain RULE-ID
```

`RULE-ID` is the id as a finding prints it, for example `ps-var-colon` in
`break ps-var-colon [14..20]: …`. The id is matched exactly, case included.

## What it prints

| Id | Output | Exit code |
|---|---|---|
| a shellwise rule id | the rule's documentation, as Markdown, on stdout | 0 |
| a ShellCheck code (`SC` and a number) | a short note and the ShellCheck wiki link, on stdout | 0 |
| anything else | `shellwise: no rule "<id>"` on stderr | 64 |
| no id | a usage error on stderr | 64 |

The two config finding ids, `config-invalid` and `config-repo-ignored`, have no rule
documentation: `explain` answers them as unknown ids. They are described on
[Configuration](/shellwise/docs/configuration/).

## Examples

A shellwise rule (the start of the output):

```sh
shellwise explain ps-var-colon
```

```text
# ps-var-colon

In a PowerShell double-quoted string, `$name:` is read as a variable on a drive or scope named
`name` (`$env:TEMP`, `$script:x`). When the colon is not followed by a name, PowerShell refuses the
whole string (`InvalidVariableReferenceWithDrive`) and runs nothing.
```

The full text goes on with what the rule flags, its `Fix:` line, what it does not catch yet, and
examples under `## Deny` and `## Allow`.

A ShellCheck code, as `shellwise lint` reports it on a Bash file:

```sh
shellwise explain SC2086
```

```text
# SC2086

A ShellCheck check that `shellwise lint` runs on a Bash file (`warn`; a parse error is `break` when the shellwise parser also fails on the file). Its page: https://www.shellcheck.net/wiki/SC2086
```

Any `SC` code with a number gets this note; `explain` does not check that ShellCheck has such a
code.

An unknown id:

```sh
shellwise explain no-such-rule
```

```text
shellwise: no rule "no-such-rule"
```

Exit code 64.

## See also

- [The rule reference](/shellwise/docs/rules/): every rule, one page each.
- [shellwise check](/shellwise/docs/commands/check/): where the rule ids come from.
- [shellwise lint](/shellwise/docs/commands/lint/): the command that reports ShellCheck codes.
