# too-long

A command line for Git Bash is too long to run whole. The Bash tool runs `bash.exe -c` with the
command inside `eval '…'`, each `'` written as `'"'"'`, in a wrapper of about 515 characters, and
Git Bash keeps only the first 8186 characters of that text. A command cut inside the quote fails
with `unexpected EOF` and runs none of it; one cut in the wrapper's tail runs, but the tool reports
an error and may write a file at a cut path.

The rule measures the escaped length: characters as the Windows command line counts them (UTF-16
units, so a Polish letter is one, not two bytes), plus four for each `'`. It is `break` from 7672
and `ok` below. It checks command lines only, never a script file, and only for Git Bash (a POSIX
Bash and PowerShell have no such cut). It runs before the size cap and the parse, so a command over
64 KB gets this finding and also `analysis-incomplete`. The allow marker does not change it.

The wrapper's length depends on the machine (the home folder's path appears in it several times)
and on the CLI version: 7672 is the limit measured with CLI 2.1.327 on a short home path.

The Fix line names a new script file on each call, so parallel agents never write the same file:
`command-<pid>-<time>-<n>.sh` in `scratch_dir` from the config, else in `shellwise-<user>` under
the OS temp directory.

## Deny

A Git Bash command whose escaped length is 7672 or more, for example a long heredoc:

```bash
cat > notes.txt <<'EOF'
…7,700 characters of text…
EOF
```

`break`: `Fix: write the command to /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh with the Write tool, run shellwise lint /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh, then run bash /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh`

## Allow

```bash
echo hi
```

`ok`. The same text at 7671 escaped characters is `ok` too; the line is exact.
