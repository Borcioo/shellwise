# delete-empty-expansion

A recursive or forced delete whose target, with every variable or substitution the guard cannot
read taken as empty, is a protected location (a drive root, `/`, a system folder, the home
folder, the repo root, its `.git`, a protected path) or the direct contents of one. `~` (and a
leading `~` in a PowerShell provider path) is the home folder, as `$HOME` is: `rm -rf ~/"$X"`.
In Git Bash a rooted path with no drive under an MSYS system folder counts too (`rm -rf $D/usr`).
`${X:?}` (the operator right after the name) is never read as empty: an empty or unset `X` stops
the command, so the target is `dynamic-target` (warn); `${X?}` lets an empty value through.
When the variable is empty at run time, the delete takes that location. A variable the command assigns a
literal earlier, or a loop over a literal list, is read with its value where the name still holds
it (see `dynamic-target`), not as empty. Recursive or forced is read as the tool parses its
options: `rm` takes a unique prefix of a long option (`--recurs`, `--forc`), and a `--` option the
guard does not know counts as forced.

Level `danger`: the trailing allow marker confirms it.

`Fix: write each variable as `${X:?}` so an empty value stops the command, for example
`rm -rf "${X:?}/build"`` (Bash), or test the variable first,
`if ($x) { Remove-Item -Recurse -Force "$x\build" }` (PowerShell)

## Deny

```bash
rm -rf "$OUT_DIR/"
rm -rf $BUILD/*
```

```powershell
Remove-Item -Recurse -Force "$dir\*"
```

## Allow

```bash
rm -rf "$OUT_DIR/build"      # empty, it names /build: warn dynamic-target
rm -rf "${OUT_DIR:?}/"       # an empty value stops the command: warn dynamic-target
rm -rf "${OUT_DIR:?}"/*      # the same
OUT_DIR=build; rm -rf "$OUT_DIR/"
```
