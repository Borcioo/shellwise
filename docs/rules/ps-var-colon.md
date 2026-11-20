# ps-var-colon

In a PowerShell double-quoted string, `$name:` is read as a variable on a drive or scope named
`name` (`$env:TEMP`, `$script:x`). When the colon is not followed by a name, PowerShell refuses the
whole string (`InvalidVariableReferenceWithDrive`) and runs nothing.

The rule is `break` on a variable name directly followed by `:` and then by anything but a name
character or a second `:` (a space, `$`, a quote, the end of the string). Name characters are
letters and digits of any script, `_` and `?`. `$env:TEMP`, `$script:x` and `$global:x` have a name
after the colon, and `$t::Now` is a static member, so they are not findings. Single-quoted text,
`${…}` and `$(…)` are not read as part of the outer string; a string inside `$(…)` is read on its
own.

The Fix line names the variable as written: write `"${n}:"` instead of `"$n:"`.

Not caught yet: a string that is an operand of an operator in statement position
(`{ "$n: " + $c }`), because the parser keeps no word for it.

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
Write-Output "$t::Now"
Write-Output '$n: done'
```

`ok`.
