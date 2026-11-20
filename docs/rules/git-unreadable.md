# git-unreadable

Ported from baseline-guard. The guard cannot tell what git runs: a variable or a substitution stands
before or in the subcommand (`git $x worktree remove wt`, `git -C D:\x $s`), a global option's
value holds one (`--git-dir=$gd`), or a value that Bash splits (or a PowerShell array) is not
followed by a literal subcommand. Global options with literal values may stand between the two:
`git -C $d -c core.autocrlf=false status` is read.

Also a word the guard cannot read where an option of a subcommand that discards by an option
stands (`git reset $MODE`, `git clean $OPTS`): it may be `--hard` or `-fd`. The value of an
option that takes one is no option: `git switch -c "$BRANCH"`, `git checkout -b "$BRANCH"`.

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
