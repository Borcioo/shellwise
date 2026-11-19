# git-worktree-junction

Ported from baseline-guard. `git worktree remove [--force] <path>` deletes through junctions inside
the worktree and empties their targets, with or without `--force`. The worktree is walked for
links whose target is outside it. A worktree the guard cannot place (a variable, an unknown
folder, or a bare name that is no folder here, which git may match to a registered worktree by
its name) is a finding too. A worktree outside the project is no finding by itself: git removes
only a registered worktree.

Level `danger`.

`Fix: remove each link inside it first with `[IO.Directory]::Delete('<link>')` (PowerShell) or
`rm '<link>'` (Bash) in a command of its own, then remove the worktree` (or, when the guard
cannot place it, `Fix: pass the worktree's full path`)

## Deny

```powershell
git worktree remove --force wt   # wt\node_modules is a junction
```

## Allow

```powershell
git worktree remove wt-clean
```
