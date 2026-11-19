# dynamic-target

A delete whose target is not known before the command runs: a variable the hook does not know,
one the command itself assigns, a substitution, the folder after `cd $x`, or targets fed by a
pipeline or `xargs`. Level from the config's `dynamic_target` (default `danger`).

`Fix: write the path literally, or, if this is intended, run the same command again with
` # shellwise: allow` at its end`

## Deny

```bash
rm -rf "$OUT_DIR"
```

```powershell
Get-ChildItem build -Filter *.o | Remove-Item -Force
```

## Allow

```bash
rm -rf build/out
```
