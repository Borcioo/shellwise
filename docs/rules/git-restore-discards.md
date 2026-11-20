# git-restore-discards

Ported from baseline-guard. `git checkout -- <paths>`, `git checkout .`, `git checkout <word>` where
the word is a file on disk, and `git restore <paths>` (unless limited to the index with
`--staged`/`-S` and no `--worktree`/`-W`) overwrite every uncommitted edit in those files, not
only the agent's own. `--ours`, `--theirs`, `-p` and `-m` choose hunk by hunk and are no
finding; a branch operation (`-b`, `-B`, `--orphan`, `--detach`) is none either. A word that is
no file in a folder the guard can read is the branch, tag or commit git takes it for (probed on
git 2.53: such a word only switches), so it is ok.

Level `danger` when a path may be the repo root (`git checkout -- .`, `git restore .` run there,
or `.` in a folder the guard cannot place): the whole working tree. Level `warn` for named files,
and for a word or folder the guard cannot read (a variable, an unknown folder), which may be a
file (Ruling 122).

`Fix: look at `git diff --stat` first and restore only the files you mean; or, if this is
intended, run the same command again with ` # shellwise: allow` at its end` (for named files:
`Fix: look at `git diff --stat -- <paths>` first`)

## Deny

```powershell
git checkout -- .   # at the repo root
```

## Warns

```powershell
git checkout -- src/a.js
git restore src/a.js
git checkout $b   # a file named so would be overwritten
```

## Allow

```powershell
git restore --staged a.txt
git checkout -b feature/x
git checkout main
```
