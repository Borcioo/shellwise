# bash-ps-call-operator

A command in the Bash tool that starts with the PowerShell call operator: `& "C:/path/tool.exe"
args`. Bash reads a `&` at the start of a command as a syntax error and runs none of that line
(`bash -c '& "x"'` exits 2). The program runs in bash by its path alone.

| Case | Level |
|---|---|
| a command, or a pipeline or list segment, starting with `&` and an operand (`& "x.exe"`, `& 'x.exe'`, `& $tool`, `& path\tool.exe`) | `break` |
| `;&` then an operand outside a `case` arm (`cd x;& "x.exe"`): bash reads `;&` as a case terminator | `break` |
| a background job (`cmd &`, `cmd & other`, `a & b & wait`), `a && b` | no finding |
| a redirect (`&>file`, `&>>file`, `2>&1`, `\|&`, `<&3`), a `&` in quotes or a heredoc body | no finding |
| `;&` or `;;&` ending a `case` arm | no finding |
| a leading `&&`, a lone `&`, `;;&` outside a `case` | no finding here: see `parse-error` |

The finding takes the place of the parser's `parse-error` warn for that error; a
`parse-error-destructive` on the same text stays.

The Fix is the text with each call operator taken out (a `&` where a command starts: at the
start, after a line break, `;`, `&&`, `||`, `|`, `(`, a background `&`, or `if`, `then`, `else`,
`elif`, `do`, `while`, `until`) and its operand as bash runs it: a quoted path as written,
`$name` in double quotes, a bare path with forward slashes. It is given only when every other
word means the same in bash as in PowerShell:

- a plain word of letters, digits and `/._+=:%-`;
- a single-quoted string, or a double-quoted string whose only `$` starts a `$name` or
  `${name}`, with no backtick and no backslash before `"`, `$`, `` ` ``, `\` or a line break;
  both of printable ASCII;
- a whole-word `$name` or `${name}`, written in double quotes as PowerShell passes it whole;
- bash operators and comments.

Anything else gets the sentence (`remove the leading & and start the program by its path, or run
this command in the PowerShell tool`): a backtick, `$null`, `$true`, `$false`, `$(`, `@name`,
`-Name:value`, a cmdlet name (`Out-Null`), an unquoted backslash (`C:\data\x`), `$env:X` (any
case, anywhere), a property (`$x.Name`), a doubled quote (`'it''s'`), a heredoc, a PowerShell
assignment (`$t = 'x'`), a script block or an expression as the operand, more than 8 call
operators, a text over 16 KiB, the analysis deadline, or a result bash does not parse. A `.ps1`
operand is sent to the PowerShell tool. The text is read once and the result parsed once. In
`shellwise lint` the Fix holds only the corrected lines. Both Bash profiles (Git Bash and POSIX
bash).

## Deny

```bash
& "C:/path/tool.exe" args
```

`break`: `Fix: "C:/path/tool.exe" args`

```bash
& "C:/path/tool.exe" x 2>$null
```

`break`, with the sentence: `$null` is empty in bash, so the Fix would redirect to no file.

## Allow

```bash
"C:/path/tool.exe" args
```

`ok`.
