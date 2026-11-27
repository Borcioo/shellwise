# opaque-destructive

A command whose code the guard does not read: an opaque command name, a shell or eval body
(`bash -c '…'`, `pwsh -Command "…"`, `eval`), a wrapper past the nesting limit, or a wrapper with
an option the program table does not model. It is a finding only when its raw text (in Bash its name
and arguments, whatever redirect stands before, between or after them, a redirect target not read)
names a command that deletes or discards data (Ruling 91a): an unknown tool, or such a command
with no delete in it, is ok.

Level `danger` when a word the delete acts on (after the delete command's name, matched as the
scan matches it: with a folder, a module or `.exe` (`/usr/bin/rm`, `rm.exe`,
`Microsoft.PowerShell.Management\Remove-Item`); every word of the command when no word spells the
name, as in `r""m`; in the same
statement: not a wrapper's switch such as Git Bash's `//c`, not a `cd` before or after it) spells
a protected location literally: an absolute path that is
a drive root, `/`, a system folder, the home folder, the repo root or a protected path (or an
ancestor of one), `~` or `$HOME`, or `.git` from the repo root (Ruling 122 (b)); in Git Bash also
a rooted path with no drive under an MSYS system folder (`/usr`) and a `/<letter>/` drive path
(`/c/` is the drive root). A `.git` spelling is danger too when the repo lookup that would place
it ran out of time. Level `warn` otherwise.

A program a local shell reads on stdin is read as the same shell's `-c` body (`-Command` in
PowerShell): its own heredoc or here-string (`bash <<'EOF'`, `sh -s <<< '…'`,
`pwsh -Command - <<'EOF'`), or what a literal producer before it in the pipeline writes
(`echo '…' | bash`, `echo -n '…' 2>/dev/null | bash`, `printf '…\n' | sh`,
`printf '%s\n' '…' '…' | bash`, `cat <<'EOF' | bash`, in PowerShell `'…' | pwsh -Command -` and
`Write-Output '…' | pwsh`), also behind `sudo`, `env`, `nohup` and `timeout`, and a heredoc or
here-string behind `time`. Its targets are read as in that `-c` body: `${HOME}` and `$(pwd)/..`
are protected there too. The shell reads its options as the shell does: `bash -eo pipefail`,
`bash -ox pipefail` and `zsh -oerrexit` read stdin, `bash -s a b` too, and PowerShell with
`-NoExit` reads it after its file or command; a script operand (`bash run.sh`,
`bash ~/x.sh`, `bash "$S"`, `zsh -O extglob`, `pwsh ./x.ps1`), a `-c` body or a heredoc on
another descriptor (`bash 3<<EOF`) leaves stdin as data. A word that may expand to no argument or
to several (`bash $OPTS`, `bash "$@"`, `pwsh $script`, `pwsh @args`, `pwsh (Join-Path $d x.ps1)`)
leaves stdin the program.

`Fix: run the delete as a plain command of its own so the guard can check it` (danger: `Fix: run
the delete as a plain command of its own, or, if this is intended, run the same command again
with ` # shellwise: allow` at its end`)

## Deny

```bash
bash -c 'rm -rf "$HOME" && make'
bash -c 'builtin rm -rf ~'
bash -c 'rm -rf /c/'      # Git Bash
printf '%s\n' 'rm -rf ~' | bash
```

## Warns

```bash
bash -c 'rm -rf build && make'
echo 'rm -rf build' | sh
timeout --weird 60 rm -rf build
cmd //c "rmdir node_modules"
```

## Allow

```bash
bash -c "$script_text"
timeout 60 newtool -x
bash run.sh <<< 'rm -rf build'
ssh host bash <<< 'rm -rf build'
```

## Limits

- A redirect before `time` makes `time` a program rather than Bash's keyword, and the guard does
  not read what that program runs: `2>/dev/null time bash -c 'rm -rf ~'` is ok, while
  `time bash -c 'rm -rf ~' 2>/dev/null` is danger.
- A program on stdin is not read when the guard does not have its text or the shell is not
  local: a producer whose words may still expand (`echo "rm -rf $DIR" | bash`), that reads a
  file or the network (`cat setup.sh | bash`, `curl … | sh`), redirects its stdout or copies a
  descriptor (`echo … >out`, `echo … 2>&1`), holds `$`, a backtick or `%` in a word, single-quoted
  too (`echo '$X; …'`), or prints an escape other than `\n`, `\t` and `\\` (`echo -e '…\c'`,
  `printf '…\x41'`); `printf` with a format other than `%s` (one argument) or `%s\n`; a filter
  between the producer and the shell (`echo … | cat | bash`); a pipe into `time bash` (`time`
  there is a program); a heredoc on a compound command (`{ bash; } <<'EOF'`); a shell on another
  machine or in a container (`ssh host bash`, `docker exec -i c bash`, `kubectl exec`, `wsl`);
  `cmd`; `dash` and `ksh` called by those names.
