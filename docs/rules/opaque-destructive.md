# opaque-destructive

A command whose code the guard does not read: an opaque command name, a shell or eval body
(`bash -c '…'`, `pwsh -Command "…"`, `eval`), or a wrapper with an option the program table does
not model. It is a finding only when its raw text names a command that deletes or discards data
(Ruling 91a): an unknown tool, or such a command with no delete in it, is ok.

Level `danger`.

`Fix: run the delete as a plain command of its own, or, if this is intended, run the same command
again with ` # shellwise: allow` at its end`

## Deny

```bash
bash -c 'rm -rf build && make'
timeout --weird 60 rm -rf build
```

## Allow

```bash
bash -c "$script_text"
timeout 60 newtool -x
```
