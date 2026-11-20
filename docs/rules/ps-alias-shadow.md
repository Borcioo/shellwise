# ps-alias-shadow

A PowerShell 7 function named like a built-in alias (`md`, `rd`, and on Windows `ls`) is never
called by that name: the alias outranks the function, so the call runs the aliased command with the
function's arguments and the function body never runs. A scope prefix (`global:md`) names the same
function. The rule checks command lines and script files (`shellwise lint`) alike; Windows
PowerShell 5.1 is not checked.

| Case | Level | Why |
|---|---|---|
| `function md { … }` and every other name a built-in alias holds | `warn` | The function is dead code, and its callers run the alias. |
| A function with a Verb-Noun name, or any name no alias holds | `ok` |  |

## Deny

```powershell
function md { New-Item -ItemType Directory -Path $args[0] }
```

`warn`: `Fix: rename the function md to a Verb-Noun name and call it by that name`

## Allow

```powershell
function New-Folder { New-Item -ItemType Directory -Path $args[0] }
```

`ok`
