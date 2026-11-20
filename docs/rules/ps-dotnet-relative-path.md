# ps-dotnet-relative-path

`[IO.File]` and `[IO.Directory]` resolve a relative path against the process directory, not the location `cd` / `Set-Location` set, so the call reads or writes a file in another folder. The methods and their path arguments come from the generated table (`dotnet` rows).

| Case | Level | Why |
|---|---|---|
| A literal relative path (including `~`) in a path argument | `break` | It names another file. |
| A rooted path, or a path built with Join-Path | `ok` |  |

## Deny

```powershell
[IO.File]::ReadAllText('tools\x.php')
```

`break`: `Fix: pass an absolute path: [IO.File]::ReadAllText((Join-Path $PWD 'tools\x.php'))`

## Allow

```powershell
[IO.File]::ReadAllText((Join-Path $PWD 'tools\x.php'))
```

`ok`
