# delete-unknown-location

The guard cannot tell which folder a delete's target names: there is no cwd, or before the
delete the command moves to a folder it cannot follow, maps a drive, runs a script or makes a
link, or the target is on a share, a device or a drive nothing shows is the file system the guard
sees. A `Remove-Item` on `Env:`, the registry or another built-in drive that is no file system
deletes no file and is no finding, unless the command visibly remaps a drive or runs a script.

Level `warn` (Ruling 122).

`Fix: use the full path of the folder so the guard can check it`

## Warns

```powershell
cd $dir; Remove-Item -Recurse -Force build
```

## Allow

```powershell
Remove-Item -Recurse -Force build
Remove-Item Env:MY_VAR
```
