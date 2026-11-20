# wsl-argv-rejoin

`wsl <command>` joins its arguments into one line that the Linux shell parses again, so an argument with a space or a shell character may not arrive as written. Windows only.

| Case | Level | Why |
|---|---|---|
| An argument with whitespace or a shell metacharacter, without `--exec` | `warn` | It is parsed again. |
| `wsl --exec`, or plain words | `ok` |  |

## Deny

```powershell
wsl ls -la '/mnt/c/my dir'
```

`warn`: `Fix: run it as wsl.exe --exec <shell> -c '<command>'`

## Allow

```powershell
wsl --exec ls -la '/mnt/c/my dir'
```

`ok`
