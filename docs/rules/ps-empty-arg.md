# ps-empty-arg

`'""'` reaches a native program as two quote characters, not as an empty value.

| Case | Level | Why |
|---|---|---|
| An argument that is exactly `'""'` | `warn` | The program gets two quote characters. |
| `''` | `ok` |  |

## Deny

```powershell
ssh-keygen -t ed25519 -N '""' -f key
```

`warn`: `Fix: write an empty native argument as ''`

## Allow

```powershell
ssh-keygen -t ed25519 -N '' -f key
```

`ok`
