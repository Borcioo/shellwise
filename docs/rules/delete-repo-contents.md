# delete-repo-contents

A glob over the direct contents of the repo root (`*`, `./*`, `-- *` from the root, `../*` from a
folder just below it): the delete takes the whole working tree, uncommitted and untracked files
included, but leaves `.git`, which a Bash glob that does not start with `.` never matches, nor a
PowerShell wildcard without `-Force` (`.git` is hidden). A glob that takes `.git` too (`.*`, or a
PowerShell wildcard with `-Force`) is `delete-critical`, and so is the repo root itself.

After a `cd`, the glob is read in the folder the shell is surely in (Ruling 127): a literal folder
that exists on disk, when every statement before the `cd` is known to leave the disk alone (a bare
assignment, a plain location move, or a read-only program such as `echo`, `ls`, `git status`,
`Get-ChildItem`, with no redirect or substitution: any other command may have removed the
folder); a Bash `cd X || exit` (no `!` in the command); in PowerShell
`$ErrorActionPreference = 'Stop'` or `-ErrorAction Stop` on the location command (no `trap` in
the command). After any other form (`cd X; …` to a missing folder, `set -e`, `cd X || return`,
`mv build old; cd build; …`) a `cd` that fails leaves the shell in the old folder, so a glob
there may still be the repo root's.

Level `danger`: the trailing allow marker confirms it.

`Fix: name each folder you mean in place of the glob, for example `<repo>/build`; or, if this is
intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

```bash
rm -rf *        # from the repo root
rm -rf ./*
cd nosuch; rm -rf *
mv build old; cd build; rm -rf *
```

```powershell
Remove-Item -Recurse *
```

## Allow

```bash
rm -rf build/*
rm -rf *        # from a folder inside the repo, or outside any repo
cd build; rm -rf *
echo start; cd build; rm -rf *
cd nosuch || exit 1; rm -rf *
```

```powershell
$ErrorActionPreference = 'Stop'; cd nosuch; Remove-Item -Recurse -Force *
```
