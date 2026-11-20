# git-discard

A git command that throws away uncommitted work, which no commit or stash holds. The flags come
from `data/destructive.toml` and the `discard` facts in `data/programs.toml`.

Level `danger` (Ruling 122 (c)) for a whole-tree discard: `git reset --hard` or `--merge`,
`git stash clear`, `git switch -f` or `--discard-changes`, `git checkout -f`, and `git clean`
with `-d` (also inside a cluster, `-fd`, `-fdx`) and no pathspec, or with a pathspec of the
whole tree, `:/` or `.` from the repo root (with a pathspec git removes untracked folders, `-d`
or not). A long option counts by any unique prefix, as git reads it (`--har`, `--forc`; each
subcommand's options are listed in `data/programs.toml`). Level `warn` for the shapes that keep
the work or drop one entry: `git reset --keep` (git refuses when a file it would touch has
edits) and `git stash drop` (one stash entry, still reachable by its hash for a while). `git clean -f`
without `-d`, or with a pathspec of part of the tree, is no finding of this rule: the delete rules judge its paths.
Level `warn` for `git worktree remove --force` on a worktree with no link inside it: any uncommitted
or untracked work in it is lost (with a link it is `git-worktree-junction`; without `--force` git
refuses a worktree that holds changes, so it is no finding).

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`
(for `git clean`: look at `git clean -nd` first)

## Deny

```bash
git reset --hard origin/develop
git clean -fdx
```

## Warns

```bash
git reset --keep HEAD~1
git stash drop
git worktree remove --force .claude/worktrees/x
```

## Allow

```bash
git reset --soft HEAD~1
git stash list
git clean -n
```
