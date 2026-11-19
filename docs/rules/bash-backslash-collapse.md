# bash-backslash-collapse

Git Bash turns every `\\` in a Bash tool command into `\` before bash reads it. This happens
inside quotes and heredoc bodies too, so code that needs two backslashes reaches bash with one.
The rule checks Git Bash command lines only: a script file run by path keeps its backslashes.

| Shape | Level | Why |
|---|---|---|
| `\\` in an argument of `printf`, or of `echo` with `-e` | `break` | the program then reads the single backslash as an escape: `printf 'a\\b'` writes `a` and a backspace |
| `\\` in the body of a heredoc with a quoted delimiter (`<<'EOF'`) | `break` | the file or program gets one backslash where the text has two |
| `\\d` or `\\w` in a `sed` script | `warn` | S4 showed no collapse effect here: GNU sed has no `\d` either way, and `\w` works |
| `\\` anywhere else, an expanding heredoc (`<<EOF`) included | `warn` | the text changes, but whether that breaks the command depends on how it is read |

A shape is `break` only when spike S4 shows it collapsing in the real Bash tool (`docs/spikes.md`
"Hook tool runtime"); `PROVEN` in `src/rules/bash_lint.rs` lists those shapes, and every shape left
out is `warn`. The message quotes the line as bash receives it.

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
