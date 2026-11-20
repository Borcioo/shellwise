# will-hang

The command can wait without end in the hook's tool. The Bash tool gives a command no terminal and
a stdin that is an open pipe that never ends, so a read of stdin never returns. The host stops the
call only at its own timeout.

The rule reads command lines only. A script file may run in a terminal, where a prompt is answered.
It never blocks an unknown program, and a dynamic argument that might hold the bound ends the check
without a finding.

| Shape | Level | Why | Fix |
|---|---|---|---|
| Bash `read` with no input: no `-t` or `-u` (alone or in a cluster such as `-rt 5`), no input redirect on stdin (`<`, `0<`, `<&`, here-string, here-document), not after a pipe, not in the background, not inside a compound command or a function | `break` | `read` waits on stdin, which stays open and empty. Probed in Git Bash: it waits until the outer timer. | `feed read its input on the same line: append <<< "<value>" to the read command` |
| Bash `claude -p` or `claude --print` with no `timeout` before it | `warn` | Against an unreachable API it retries about 10 times at 2 minutes or more each. | `timeout 120 claude -p <prompt>` |

PowerShell's `Read-Host` and ssh without `BatchMode` are not findings: in the PowerShell tool a
prompt fails at once, and no ssh wait was shown.

## Deny

```bash
read x
```

`break`: `Fix: feed read its input on the same line: append <<< "<value>" to the read command`

```bash
v=$(read y)
```

`break`: a substitution reads the stdin of the command it is in.

```bash
read x 2>/dev/null
read x 3< answers.txt
```

`break`: neither redirect feeds stdin.

## Warn

```bash
claude -p "summarise the diff"
```

`warn`: `Fix: timeout 120 claude -p <prompt>`

A PowerShell function named like a built-in alias is `ps-alias-shadow`. A loop that waits with
nothing to bound it is `wait-loop-unbounded`, and a follow command (`tail -f`) is `follow-unbounded`.

## Allow

```bash
read -t 5 x
read -rt 5 x
read x < answers.txt
read x <<< "yes"
echo yes | read x
read x & wait
while read -r line; do echo "$line"; done < list
if read x; then echo "$x"; fi < answers.txt
timeout 120 claude -p "summarise the diff"
```

`ok`: each one bounds or feeds the wait.

## Limits

- A `read` inside a loop, an `if`, a `case`, a group or a function is never flagged: the input
  may come from a redirect or a pipe on the compound command, which the IR does not carry. So
  `if true; then read x; fi` is a missed wait.
- An earlier `exec < file` that feeds the rest of the script is not seen: a later `read x` is
  flagged.
- A `read` with a dynamic word (`read -p "$prompt" x`) is not judged.
- Only the outermost wrapper counts as a bound: `nohup timeout 120 claude -p x` reads as unbounded.
- `claude -p` is checked in Bash only.
