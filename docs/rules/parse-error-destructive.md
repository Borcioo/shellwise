# parse-error-destructive

The command does not parse, the error is not a kind the shell is proven to refuse (see
`parse-error`), and its raw text names a command of the destructive table (`data/destructive.toml`)
or a .NET `Delete()` call (`(Get-Item x).Delete()`): `danger`. Nothing proves the shell refuses
the text, and part of it may delete.

It also fires next to a Bash unclosed quote (`parse-error` at `break`), which Bash runs the
complete commands before: when the parser cannot tell where those commands end (a construct open
over more than 32 lines before the quote, or over more text than the search parses: 256 KiB in
all its tries), a destructive match in the lines before the quote's
line is `danger`, with `Fix: correct the syntax at line <l>, column <n>, then run the command again
so each line can be checked`.

A part of the text the raw scan cannot read (a pipe into a shell, nesting past its depth limit, an
encoded body) is no destructive match: such a parse error is `parse-error` at `warn`.

This rule has its own id so that a level configured for `parse-error` does not lower it:
`[levels] parse-error = "warn"` leaves this one at `danger`.

The message names the parser's reason and the position (`column <n>`, or `line <l>, column <n>`
after the first line).

## Deny

```powershell
Get-Date ( ; rm -rf x
```

`danger`: `Fix: correct the syntax at column 10 (…)`

```bash
if true; then rm -rf x
```

`danger`: the `if` is never closed, and the text holds `rm -rf x`.

## Allow

```powershell
Get-Date (
```

`parse-error` at `warn`: no command of the destructive table.

```bash
if true; then cat setup.sh | bash
```

`parse-error` at `warn`: the scan cannot read what the shell runs, but no table row matches.
