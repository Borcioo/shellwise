# opaque-destructive

A command whose code the guard does not read: an opaque command name, a shell or eval body
(`bash -c '…'`, `pwsh -Command "…"`, `eval`), a wrapper past the nesting limit, or a wrapper with
an option the program table does not model. It is a finding only when its raw text names a
command that deletes or discards data (Ruling 91a): an unknown tool, or such a command with no
delete in it, is ok.

Level `danger` when its words also spell a protected location literally: an absolute path that is
a drive root, `/`, a system folder, the home folder, the repo root or a protected path (or an
ancestor of one), `~` or `$HOME`, or `.git` from the repo root (Ruling 122 (b)). Level `warn`
otherwise.

`Fix: run the delete as a plain command of its own so the guard can check it` (danger: `or, if
this is intended, run the same command again with ` # shellwise: allow` at its end`)

## Deny

```bash
bash -c 'rm -rf "$HOME" && make'
```

## Warns

```bash
bash -c 'rm -rf build && make'
timeout --weird 60 rm -rf build
```

## Allow

```bash
bash -c "$script_text"
timeout 60 newtool -x
```
