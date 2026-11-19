# ps-var-colon

In a PowerShell double-quoted string, `$name:` is read as a variable on a drive or scope named
`name` (`$env:TEMP`, `$script:x`). When the colon is not followed by a name, PowerShell refuses the
whole string (`InvalidVariableReferenceWithDrive`) and runs nothing.

The rule is `break` on a variable name directly followed by `:` and then by anything but a name
character (a space, `$`, a quote, the end of the string). `$env:TEMP`, `$script:x` and `$global:x`
have a name after the colon, so they are not findings. Single-quoted text and `$(…)` are not read.

The Fix line names the variable as written: write `"${n}:"` instead of `"$n:"`.

## Deny

```powershell
Write-Output "$n: done"
```

`break`: `Fix: write "${n}:" instead of "$n:"`

```powershell
Write-Output "$f:$l"
```

`break`: `Fix: write "${f}:" instead of "$f:"`

## Allow

```powershell
Write-Output "${n}: done"
Write-Output "$($n): done"
Write-Output "$env:TEMP done"
Write-Output '$n: done'
```

`ok`.
