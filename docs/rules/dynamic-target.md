# dynamic-target

A delete whose target is not known before the command runs: a variable the hook does not know,
a substitution, the folder after `cd $x`, or targets fed by a pipeline or `xargs`. A variable
the command assigns a literal earlier, and a loop over a literal list, are read with their
values where the name still holds them: a reassignment before the delete, an assignment in a
branch, loop or subshell, and a value built from such a name leave it unknown. A top-level
assignment that runs whatever came before it replaces an earlier top-level one of any value
(`X=$(pwd); X=/`); one in a function body still leaves the name unknown. `rm -rf "${X:?}"/*`,
whose empty value stops the command, is this warn too.

Level `warn` (Ruling 122): it names what could not be read and blocks nothing. When the target
taken with its unknown parts as empty is a protected location, the finding is
`delete-empty-expansion` instead.

`Fix: write the path literally so the guard can check it`

## Warns

```bash
rm -rf "$OUT_DIR/build"
```

```powershell
Get-ChildItem build -Filter *.o | Remove-Item -Force
```

## Allow

```bash
rm -rf build/out
```
