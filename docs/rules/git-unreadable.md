# git-unreadable

Ported from baseline-guard. The guard cannot tell what git runs: a variable or a substitution stands
before or in the subcommand (`git $x worktree remove wt`, `git -C D:\x $s`), a global option's
value holds one (`--git-dir=$gd`), or a value that Bash splits (or a PowerShell array) is not
followed by a literal subcommand. A `worktree remove` or a `checkout` behind it would go
unchecked. Level from the config's `dynamic_target` (default `danger`).

`Fix: write git's options and the subcommand literally, for example `git -C <path> <subcommand> ...``

## Deny

```powershell
git $x worktree remove wt
```

## Allow

```powershell
git -C $d status
```
