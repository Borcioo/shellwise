# parse-error

The command does not parse. The level depends on the kind of error the parser found.

| Kind | Level | Why |
|---|---|---|
| An unclosed quote (`'`, `"`, a PowerShell here-string, or a Bash backtick) | `break` | The shell refuses the whole text and runs none of it. This is the only finding. |
| PowerShell: an empty pipe element (`a \| \| b`, a `\|` at the end, a piped `foreach`/`for`/`while`/`if`/`switch` statement) | `break` | pwsh refuses the text (`EmptyPipeElement`). |
| PowerShell: a parameter glued to a comma (`git log -L1,2:f.txt`) | `break` | pwsh reads `-L1` as a parameter and finds no argument before the comma (`MissingArgument`). |
| An unclosed quote inside a Bash backtick substitution | `warn` | `bash -n` does not parse inside backticks, so the refusal is not proven. |
| Any other kind | `warn` | Context only: the shell may still accept and run it. |

Any other kind whose raw text names a command of the destructive table or a .NET `Delete()` call
is `danger` under its own rule, `parse-error-destructive`, so a level configured here does not
lower it.

How PowerShell text is read for these kinds:

- Inside a double-quoted string, `$(…)` is code with its own quotes: the `'` in `"$("it's")"` is
  closed. A comment inside that `$(…)` hides no quote from the string: PowerShell finds where the
  string ends without reading the comment, so `"$(Get-Date # c)"` closes its string.
- A here-string runs from `@'` or `@"` at the end of a line to a line that starts with `'@` or
  `"@`; quotes inside it are text. Text after a here-string header is `warn`. Glued to the text
  before it, `@'` opens a here-string after a parameter's colon (`-Value:@'`) and in a statement
  that starts as an expression (`$msg=@'`, `$a=[string]@'`), unless the word starts with a letter;
  glued to a command's argument (`Write-Output a=@'`, `$a=@'`) it is a quote, as in PowerShell.
- A `#` glued to a bare word that starts with a letter (`a#b`) is part of the word. After a
  variable, a number, a quote or a bracket it starts a comment, as in an expression.
- A `|` at the end of a line continues the pipeline on the next line.
- A backslash does not escape a double quote: `"a\"b"` ends the string at the backslash.
- Empty or blank text is no error.

A parser that fails itself (a panic, a thread that did not start, a grammar that did not load) is
no parse error: the analysis is incomplete (`analysis-incomplete`).

The message names the parser's reason and the position (`column <n>`, or `line <l>, column <n>`
after the first line).

## Fix lines

| Shape | Fix line |
|---|---|
| An unclosed quote | `Fix: close the " opened at column <n>, or write the text to a file and pass the file` |
| An unclosed quote in PowerShell text holding `\"` | `Fix: in PowerShell write a quote inside "…" as "" or use '…'` |
| An unclosed quote in PowerShell text holding a typographic quote (U+2018–U+201E) | `Fix: replace the typographic quote at column <n> with ' or "` |
| A here-string that never ends | `Fix: end the here-string opened at column <n> with a line that starts with '@` |
| An empty pipe element | `Fix: remove the empty \| at column <n>, or put the command after it on the same line` |
| A piped statement | `Fix: write $( before the foreach at column <m> and ) before the \| at column <n>` |
| A parameter glued to a comma | `Fix: quote the argument: '-L1,2:f.txt'` |
| Any other kind | `Fix: correct the syntax at column <n> (<the parser's reason>)` |

## Deny

```powershell
Write-Output "abc
```

`break`: `Fix: close the " opened at column 14, or write the text to a file and pass the file`

```powershell
git log -L1,2:f.txt
```

`break`: `Fix: quote the argument: '-L1,2:f.txt'`

```powershell
foreach ($x in 1,2) { $x } | Out-Host
```

`break`: `Fix: write $( before the foreach at column 1 and ) before the | at column 28`

```bash
rm -rf "x
```

`break`, and no other finding: the shell refuses the text, so the delete never runs.

## Allow

```powershell
Get-Date
```

`ok`. `Get-Date (` alone is `warn`, which the hook passes on as context.

```powershell
git log '-L1,2:f.txt'
```

`ok`.
