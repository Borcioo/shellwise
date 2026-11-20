# too-long

A command line for Git Bash is too long to run whole. The Bash tool runs `bash.exe -c` with the
command inside `eval '…'`, each `'` written as `'"'"'`, in a wrapper of about 515 characters, and
Git Bash keeps only the first 8186 characters of that text. A command cut inside the quote fails
with `unexpected EOF` and runs none of it; one cut in the wrapper's tail runs, but the tool reports
an error and may write a file at a cut path.

The rule measures the escaped length: characters as the Windows command line counts them (UTF-16
units, so a Polish letter is one, not two bytes), plus four for each `'`. It is `break` from the
limit `limits.git_bash_command` (default 7500) and `ok` below. It checks command lines only, never
a script file, and only for Git Bash (a POSIX Bash and PowerShell have no such cut). It runs before
the size cap and the parse, so a command over 64 KB gets this finding and also
`analysis-incomplete`. The allow marker does not change it.

The real boundary depends on the machine and the CLI version. Measured with CLI 2.1.326 on a home
path of 14 characters, the wrapper was 515 characters and a command was cut from 7672. The wrapper
holds the home path about four times, so the default 7500 leaves room for a home path about 40
characters longer. Set the limit in the user or integration config file (a repo file cannot):

```toml
[limits]
git_bash_command = 7672
```

The Fix line names a new script file on each call, so parallel agents never write the same file:
`command-<pid>-<time>-<n>.sh` in `scratch_dir` from the config, else in `shellwise-<user>` under
the OS temp directory. A path with a space is quoted where a shell reads it.

## Deny

A Git Bash command whose escaped length is 7500 or more, for example a long heredoc:

```bash
cat > notes.txt <<'EOF'
…7,500 characters of text…
EOF
```

`break`: `Fix: write the command to /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh with the Write tool, run shellwise lint /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh, then run bash /tmp/shellwise-ann/command-1f2c-6243b1d0e8a10-0.sh`

## Allow

```bash
echo hi
```

`ok`. The same text at 7499 escaped characters is `ok` too; the line is exact.

## cmd.exe from PowerShell

On Windows, a PowerShell command that starts `cmd` (`cmd /c …`, `cmd.exe /c …`, `& cmd /c …`) is
`too-long` when the line cmd gets is over 8,191 characters, the limit `line_limit` of the `cmd`
row in `data/programs.toml`. pwsh starts cmd by its full path, `"C:\WINDOWS\system32\cmd.exe"`
(29 characters, the row's `launch_path_units`), in place of everything up to the end of the typed
word, so the rule counts the rest of the text in UTF-16 units plus 29. cmd then prints "The command
line is too long." and runs nothing, and the PowerShell tool still exits 0. Measured with pwsh 7.7:
a typed `cmd /c echo a…` runs at 8,165 characters and is refused at 8,166.

A script file does not help here, because the script starts the same cmd line, so this finding has
its own Fix line:

`Fix: delete the leading cmd /c and run the program directly from PowerShell, which starts command lines up to 32766 characters`

The PowerShell tool's own text has no limit: the tool passes it to pwsh in an environment variable,
not on the command line, and a script of 100,000 characters runs. A long PowerShell command is
`inline-script-too-long`, not `too-long`. A Git Bash `cmd //c …` command reaches the Git Bash limit
first.
