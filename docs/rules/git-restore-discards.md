# git-restore-discards

Ported from baseline-guard. `git checkout -- <paths>`, `git checkout .`, `git checkout <word>` where
the word is a file on disk, and `git restore <paths>` (unless limited to the index with
`--staged`/`-S` and no `--worktree`/`-W`) overwrite every uncommitted edit in those files, not
only the agent's own. `--ours`, `--theirs`, `-p` and `-m` choose hunk by hunk and are no
finding; a branch operation (`-b`, `-B`, `--orphan`, `--detach`) is none either. A word the guard
cannot place as a file (a variable, a word in an unknown folder) is read as the branch, tag or
commit it usually is: a switch deletes nothing.

Level `danger` when a path is the repo root (`git checkout -- .`, `git restore .` run there): the
whole working tree. Level `warn` for named files (Ruling 122).

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
```

## Allow

```powershell
git restore --staged a.txt
git checkout -b feature/x
git checkout main
```
