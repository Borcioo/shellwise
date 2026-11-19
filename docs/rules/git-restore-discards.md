# git-restore-discards

Ported from baseline-guard. `git checkout -- <paths>`, `git checkout .`, `git checkout <word>` where
the word is a file on disk, and `git restore <paths>` (unless limited to the index with
`--staged`/`-S` and no `--worktree`/`-W`) overwrite every uncommitted edit in those files, not
only the agent's own. `--ours`, `--theirs`, `-p` and `-m` choose hunk by hunk and are no
finding; a branch operation (`-b`, `-B`, `--orphan`, `--detach`) is none either. A word the guard
cannot place (a variable, an unknown folder) counts as a file.

Level `danger`.

`Fix: look at `git diff --stat -- <paths>` first; if this is intended, run the same command again
with ` # shellwise: allow` at its end`

## Deny

```powershell
git checkout -- src/a.js
git restore src/a.js
```

## Allow

```powershell
git restore --staged a.txt
git checkout -b feature/x
```
