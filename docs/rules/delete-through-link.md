# delete-through-link

A recursive delete of a tree that holds a link (junction, symbolic link, mount point) whose target
is outside the tree, or that is a link itself; or any delete of a path below a link. The delete
would empty the link's target too. The tree is walked breadth first without following links,
within the walk budget (`walk-timeout` when it runs out).

Level `danger`. A non-recursive delete of the link itself is ok: it removes the link only.

`Fix: remove the link itself first with `[IO.Directory]::Delete('<link>')` (PowerShell) or
`rm '<link>'` (Bash) in a command of its own, then run the delete again`

## Deny

```powershell
Remove-Item -Recurse -Force linked   # linked\out is a junction to a folder outside it
```

## Allow

```powershell
[IO.Directory]::Delete('jn')   # jn is the junction: only the link goes
```
