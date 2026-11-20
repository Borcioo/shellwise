# git-worktree-junction

Ported from baseline-guard. `git worktree remove --force <path>` deletes through junctions inside
the worktree and empties their targets. The worktree is walked for links whose target is outside
it. Without `--force` git refuses a worktree that holds one (the junction is an untracked file).

Level `danger` with `--force` (or `-f`, before or after the path) and a junction found (Ruling 122
(c)). Level `warn` without `--force`, and for a worktree the guard cannot place (a variable, an
unknown folder, or a bare name that is no folder here, which git may match to a registered
worktree by its name). A worktree outside the project is no finding by itself: git removes only a
registered worktree.

`Fix: remove each link inside it first with `[IO.Directory]::Delete('<link>')` (PowerShell) or
`rm '<link>'` (Bash) in a command of its own, then remove the worktree` (or, when the guard
cannot place it, `Fix: pass the worktree's full path`)

## Deny

```powershell
git worktree remove --force wt   # wt\node_modules is a junction
```

## Warns

```powershell
git worktree remove wt   # git refuses it; with --force it would empty the junction's target
```

## Allow

```powershell
git worktree remove wt-clean
```
