# will-hang

The command can wait without end in the hook's tool. The tool gives a command no terminal and an
open stdin that never ends, so a prompt is never answered and a read of stdin never returns. The
host stops the call only at its own timeout.

The rule reads command lines only. A script file may run in a terminal, where a prompt is answered.
It never blocks an unknown program: a dynamic argument might hold the bound, so it ends the check
without a finding.

| Shape | Level | Why | Fix |
|---|---|---|---|
| Bash `read` with no input: no `-t`, no `-u`, no `<`, here-string or here-document, not after a pipe, not in a loop, group or function | `break` | `read` waits on stdin, which stays open and empty. Confirmed in the tool: it blocks until the outer timer. | `set the variable directly (x=<value>) or feed read its input: read x <<< "<value>"` |
| PowerShell `Read-Host` | `warn` | Waits for a console answer. Not yet confirmed for the PowerShell tool. | `pass the value as a parameter or a variable instead of asking for it` |
| `ssh` with no `BatchMode=yes` option | `warn` | A password or host-key prompt would never be answered. Not yet confirmed: a probe against an unroutable address failed fast. | `ssh -o BatchMode=yes <host> '<command>'` |
| Bash `claude -p` or `claude --print` with no `timeout` before it | `warn` | Against an unreachable API it retries for about 10 × 2 minutes. | `timeout 120 claude -p <prompt>` |
| A PowerShell function named like a built-in alias (`md`, `rd`) | `warn` | The alias outranks the function, so the call runs the aliased command with the function's arguments and the function body never runs. | `rename the function <name> to a Verb-Noun name and call it by that name` |

The levels follow the landing rule: a rule is `break` only when its corpus replay denies at most 5
`ok` rows. `read` is the only break; the others match more `ok` rows than that.

## Deny

```bash
read x
```

`break`: `Fix: set the variable directly (x=<value>) or feed read its input: read x <<< "<value>"`

```bash
read x | cat
```

`break`: `read` is the first command of the pipeline, so nothing feeds it.

## Warn

```bash
claude -p "summarise the diff"
```

`warn`: `Fix: timeout 120 claude -p <prompt>`

```powershell
function md { New-Item -ItemType Directory -Path $args[0] }
```

`warn`: `Fix: rename the function md to a Verb-Noun name and call it by that name`

## Allow

```bash
read -t 5 x
read x < answers.txt
read x <<< "yes"
echo yes | read x
while read -r line; do echo "$line"; done < list
timeout 120 claude -p "summarise the diff"
```

`ok`: each one bounds or feeds the wait.

```powershell
ssh -o BatchMode=yes my-server 'ls'
function New-Dir { New-Item -ItemType Directory -Path $args[0] }
```

`ok`.

## Limits

- Only the outermost wrapper counts as a bound: `nohup timeout 120 claude -p x` reads as unbounded.
- `claude -p` is checked in Bash only. PowerShell has no one-line bound to name.
- `ssh -o "BatchMode yes"` (a space, not `=`) and a `BatchMode` set in the user's ssh config are not seen.
- A `read` inside a loop, a group or a function is never flagged: its input may come from the
  enclosing redirect or pipe, which the IR does not carry.
