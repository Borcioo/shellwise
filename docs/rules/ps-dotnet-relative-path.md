# ps-dotnet-relative-path

`[IO.File]` and `[IO.Directory]` resolve a relative path against the process directory, not the location `cd` / `Set-Location` set, so the call reads or writes a file in another folder. The methods and their path arguments come from the generated table (`dotnet` rows).

| Case | Level | Why |
|---|---|---|
| A literal relative path (including `~`) in a path argument | `warn` | It names another file whenever the process directory differs from the location. Warn: in the corpus it also fired on runs that worked (the two were the same folder). |
| A rooted path, or a path built with Join-Path | `ok` |  |

## Deny

```powershell
[IO.File]::ReadAllText('tools\x.php')
```

`warn`: `Fix: pass an absolute path: [IO.File]::ReadAllText((Join-Path $PWD 'tools\x.php'))`

## Allow

```powershell
[IO.File]::ReadAllText((Join-Path $PWD 'tools\x.php'))
```

`ok`
