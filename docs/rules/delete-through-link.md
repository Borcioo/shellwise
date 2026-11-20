# delete-through-link

A recursive delete of a tree that holds a link (junction, symbolic link, mount point) whose target
is outside the tree, or that is a link itself; or any delete of a path below a link. The tree is
walked breadth first without following links, within the walk budget (`walk-timeout` when it runs
out).

Level `warn` (Ruling 122): `rm -rf`, `Remove-Item -Recurse`, `[IO.Directory]::Delete(p, $true)`
and `rd /s` remove a junction without emptying its target (probed on pwsh 7.7, Git Bash 5.2), so
the warning is for a tool that follows links. `git worktree remove --force` does empty it: that is
`git-worktree-junction`. A non-recursive delete of the link itself is ok.

`Fix: remove the link itself first with `[IO.Directory]::Delete('<link>')` (PowerShell) or
`rm '<link>'` (Bash) in a command of its own`

## Warns

```powershell
Remove-Item -Recurse -Force linked   # linked\out is a junction to a folder outside it
```

## Allow

```powershell
[IO.Directory]::Delete('jn')   # jn is the junction: only the link goes
```
