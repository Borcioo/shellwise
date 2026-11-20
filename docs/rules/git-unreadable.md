# git-unreadable

Ported from baseline-guard. The guard cannot tell what git runs: a variable or a substitution stands
before or in the subcommand (`git $x worktree remove wt`, `git -C D:\x $s`), a global option's
value holds one (`--git-dir=$gd`), or a value that Bash splits (or a PowerShell array) is not
followed by a literal subcommand. Global options with literal values may stand between the two:
`git -C $d -c core.autocrlf=false status` is read.

Level `warn` (Ruling 122).

`Fix: write git's options and the subcommand literally, for example `git -C <path> <subcommand> ...``

## Warns

```powershell
git $x worktree remove wt
```

## Allow

```powershell
git -C $d status
git -C "$d" -c core.quotepath=off log -1
```
