# analysis-incomplete

The analysis did not finish for a reason other than a parse error:

- a panic inside the analysis;
- the deadline;
- a worker that ended without a result or did not start;
- invalid UTF-8;
- input over 64 KiB (`MAX_INPUT_BYTES`);
- a config that did not load.

| Case | Level |
|---|---|
| The raw-text scan names a command that deletes or discards data, or text it cannot read | `danger` |
| The raw-text scan itself did not finish | `danger` |
| Otherwise | `warn` |

Input over 1 MiB (`MAX_READ_BYTES`), or stdin still open at the deadline, is `danger` unread.

The allow marker has no effect here: without a parse nothing shows that the marker is a comment.

`Fix: split the command into simpler calls so each can be checked`

## Deny

A 70 KB command that holds `rm -rf x` is `danger`, with the span on `rm -rf x`.

## Allow

A 70 KB command with no delete is `warn`: the hook passes the reason on as context.
