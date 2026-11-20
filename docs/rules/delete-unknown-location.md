# delete-unknown-location

The guard cannot tell which folder a delete's target names: there is no cwd, or before the
delete the command moves to a folder it cannot follow, maps a drive, runs a script or makes a
link, or the target is on a drive nothing shows is the file system the guard sees. Level
`danger`.

`Fix: use the full path of the folder, or, if this is intended, run the same command again with
` # shellwise: allow` at its end`

## Deny

```powershell
New-Item -ItemType Junction -Path box -Target ..\outside; Remove-Item -Recurse -Force box
```

## Allow

```powershell
Remove-Item -Recurse -Force build
```
