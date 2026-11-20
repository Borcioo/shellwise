# analysis-incomplete

The analysis did not finish for a reason other than a parse error:

- a panic inside the analysis;
- a parser that failed itself (a panic, a thread that did not start, a grammar that did not load);
- the deadline;
- a worker that ended without a result or did not start;
- invalid UTF-8;
- input over 64 KiB (`MAX_INPUT_BYTES`);
- a config that did not load (the length rules still run).

| Case | Level |
|---|---|
| The raw-text scan names a command of the destructive table, or a .NET `Delete()` call (`(Get-Item x).Delete()`) | `danger` |
| The raw-text scan finds only text it cannot read (a pipe into a shell, nesting past its depth limit, an encoded body) | `warn` |
| The raw-text scan itself did not finish | `warn` |
| A hook event that is not valid JSON, and its raw-text scan did not finish | `danger` |
| Otherwise | `warn` |

The raw-text scan runs only on this path. Started when the deadline has run out, it still gets
500 ms (the deadline ends 1500 ms before the hook timeout).

A hook event that is not valid JSON shows no command, so the hook replies only when its raw text
is scanned: a deny when the scan flags a destructive command or gives no answer (a timeout, a
panic, a worker that did not start), otherwise no output. Its scan runs until 1000 ms after the
event read ends, but not past 2500 ms from the hook's start.

Input over 1 MiB (`MAX_READ_BYTES`), or stdin still open at the deadline, is `danger` unread: the
text is unknown and cannot be scanned.

The allow marker has no effect here: without a parse nothing shows that the marker is a comment.

`Fix: split the command into simpler calls so each can be checked`

## Deny

A 70 KB command that holds `rm -rf x` is `danger`, with the span on `rm -rf x`.

## Allow

A 70 KB command with no delete is `warn`: the hook passes the reason on as context.
