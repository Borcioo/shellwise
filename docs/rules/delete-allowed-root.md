# delete-allowed-root

A delete of an allowed root itself (`allowed_roots`, by default the OS temp folder): every
other session's files live there too. Deleting inside it is ok.

Level `warn` (Ruling 122).

`Fix: delete only what you made inside it, for example `<root>\<name>``

## Warns

```powershell
Remove-Item -Recurse -Force $env:TEMP
```

## Allow

```powershell
Remove-Item -Recurse -Force $env:TEMP\my-build
```
