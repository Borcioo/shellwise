# too-long

A command line for Git Bash is too long to run whole. The host hands Git Bash the command inside
single quotes, each `'` written as `'\''`, and cuts that text at 7790 characters. The part before
the cut runs, sometimes with exit 0; the rest, often the end of a heredoc, is silently lost.

The rule measures the escaped length, `command.replace("'", "'\\''").len()`, so every `'` counts as
four characters. It is `break` at 7790 and above, and `ok` below. It checks command lines only,
never a script file, and only for Git Bash (a POSIX Bash and PowerShell have no such cut). It runs
before the size cap and the parse, so a command over 64 KB gets this finding and also
`analysis-incomplete`. The allow marker does not change it.

The path in the Fix line is `scratch_dir` from the config, else the OS temp directory plus
`shellwise`.

## Deny

A Git Bash command whose escaped length is 7790 or more, for example a long heredoc:

```bash
cat > notes.txt <<'EOF'
…7,800 characters of text…
EOF
```

`break`: `Fix: write the command to /tmp/shellwise/command.sh with the Write tool, run shellwise lint /tmp/shellwise/command.sh, then run bash /tmp/shellwise/command.sh`

## Allow

```bash
echo hi
```

`ok`. The same text at 7789 escaped characters is `ok` too; the line is exact.
