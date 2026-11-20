# delete-repo-contents

A glob over the direct contents of the repo root (`*`, `./*`, `-- *` from the root, `../*` from a
folder just below it): the delete takes the whole working tree, uncommitted and untracked files
included, but leaves `.git`, which a Bash glob that does not start with `.` never matches. A glob
that takes `.git` too (`.*`, or any PowerShell wildcard, which matches names starting with `.`) is
`delete-critical`, and so is the repo root itself.

Level `danger`: the trailing allow marker confirms it.

`Fix: name each folder you mean in place of the glob, for example `<repo>/build`; or, if this is
intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

```bash
rm -rf *        # from the repo root
rm -rf ./*
```

## Allow

```bash
rm -rf build/*
rm -rf *        # from a folder inside the repo, or outside any repo
```
