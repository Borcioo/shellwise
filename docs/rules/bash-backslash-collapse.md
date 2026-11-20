# bash-backslash-collapse

Git Bash turns every `\\` in a Bash tool command into `\` before bash reads it. This happens
inside quotes and heredoc bodies too, so code that needs two backslashes reaches bash with one.
The rule checks Git Bash command lines only: a script file run by path keeps its backslashes.

| Shape | Level | Why |
|---|---|---|
| `\\` in an argument of `printf`, or of `echo` with `-e` | `break` | the program then reads the single backslash as an escape: `printf 'a\\b'` writes `a` and a backspace |
| `\\` in the body of a heredoc with a quoted delimiter (`<<'EOF'`) | `break` | the file or program gets one backslash where the text has two |
| `\\` before `$`, `` ` ``, `\` or a line end in an expanding heredoc (`<<EOF`) | `break` | `a\\$X` is written as `a$X` instead of `a\` and the value |
| any other `\\` in an expanding heredoc | `warn` | bash reads `\\` there as `\` anyway, so `a\\b` is written as `a\b` either way |
| `\\` anywhere else, a `sed` script included | `warn` | the text changes, but whether that breaks the command depends on how it is read |

A shape is `break` only when the real Bash tool was shown to write other bytes than the same text
run from a file (spike S4, and the `<<EOF` probe of Task 29); `PROVEN` in `src/rules/bash_lint.rs`
lists those shapes, and every shape left out is `warn`. A single-backslash class such as
`sed -E 's/\d/x/'` holds no `\\` and gets no finding here: GNU sed lacking `\d` is another defect.
The message quotes the line as bash receives it.

## Deny

```bash
printf '%s' 'a\\b'
```

`break`: `Fix: write the text with the Write tool to <file> and run bash <file>`

```bash
python - <<'EOF'
print('a\\nb')
EOF
```

`break`, with the same Fix line.

```bash
echo "a\\b"
```

`warn`: context only.

## Allow

```bash
printf 'a\nb'
```

`ok`: one backslash passes unchanged. The same text in the POSIX profile is `ok` too.
