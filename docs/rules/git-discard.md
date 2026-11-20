# git-discard

A git command that throws away uncommitted work over the whole tree, which no commit or stash
holds: `git reset --hard` (also `--merge`, `--keep`), `git stash drop`, `git stash clear`,
`git switch -f` or `--discard-changes`, `git checkout -f`, and `git clean -fd` (any cluster with
`-f` and `-d`) with no pathspec. The flags come from `data/destructive.toml` and the `discard`
facts in `data/programs.toml`.

Level `danger` (Ruling 122 (c)).

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`
(for `git clean`: look at `git clean -nd` first)

## Deny

```bash
git reset --hard origin/develop
git clean -fdx
```

## Allow

```bash
git reset --soft HEAD~1
git stash list
git clean -n
```
