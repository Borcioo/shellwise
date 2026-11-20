# bat-metachar

A `.bat` or `.cmd` launcher (a Composer `vendor\bin` shim, a `tools\*.bat` wrapper) hands its arguments to cmd.exe, which parses them again. PowerShell has already removed its own quotes, so `|`, `&`, `<`, `>` and `^` outside cmd.exe's double quotes become cmd.exe operators, and a `%NAME%` of a defined variable is replaced. Windows only.

| Case | Level | Why |
|---|---|---|
| An operator character outside double quotes in an argument the launcher receives | `break` | cmd.exe splits the command at it or strips it; the program gets another argument or never runs. |
| `%NAME%` where NAME is defined in the environment | `break` | cmd.exe replaces it with the value. |
| The program is called by the path of its `.exe`, or is not a batch launcher | `ok` | No second parse. |

## Deny

```powershell
vendor\bin\phpunit --filter 'A|B'
```

`break`: `Fix: vendor\bin\phpunit --% --filter "A|B"`

After `--%` every argument that holds an operator or a space is put in double quotes, not only the first one:

```powershell
tools\composer.bat require 'a/b:^1.2' 'c/d:^2.0'
```

`break`: `Fix: tools\composer.bat --% require "a/b:^1.2" "c/d:^2.0"`

```powershell
tools\wp.bat option get %PATH%
```

`break`: the fix says to call the program the launcher starts by its own path (its `.exe`).

## Allow

```powershell
vendor\bin\phpunit --filter 'A B|C'
```

`ok`: the space makes PowerShell pass the value in double quotes, which cmd.exe keeps.

```powershell
rg -n 'tail|head' .
```

`ok`: `rg` is an `.exe`.
