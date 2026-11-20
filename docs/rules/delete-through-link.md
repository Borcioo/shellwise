# delete-through-link

A recursive delete of a tree that holds a link (junction, symbolic link, mount point) whose target
is outside the tree, or that is a link itself; or any delete of a path below a link. The tree is
walked breadth first without following links, within the walk budget (`walk-timeout` when it runs
out).

Level `warn` for the tools that remove a junction without emptying its target: `rm -rf`,
`Remove-Item -Recurse` and `[IO.Directory]::Delete(p, $true)` (probed on pwsh 7.7, Windows
PowerShell 5.1 and Git Bash 5.2), and `rd /s`. Level `danger` for a tool that follows links:
`robocopy /MIR` empties the target (`follows_links` in `data/programs.toml`). `git worktree
remove --force` empties it too: that is `git-worktree-junction`. A non-recursive delete of the
link itself is ok.

`Fix: remove the link itself first with `[IO.Directory]::Delete('<link>')` (PowerShell) or
`rm '<link>'` (Bash) in a command of its own`

## Deny

```powershell
robocopy empty linked /MIR   # linked\out is a junction: its target is emptied
```

## Warns

```powershell
Remove-Item -Recurse -Force linked   # linked\out is a junction to a folder outside it
```

## Allow

```powershell
[IO.Directory]::Delete('jn')   # jn is the junction: only the link goes
```
