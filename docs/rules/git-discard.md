# git-discard

A git command that throws away uncommitted work no commit or stash holds: `git reset --hard`
(also `--merge`, `--keep`), `git stash drop`, `git stash clear`, `git switch -f` or
`--discard-changes`, `git checkout -f`. The flags come from `data/destructive.toml`.

Level `danger`.

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

```bash
git reset --hard origin/develop
```

## Allow

```bash
git reset --soft HEAD~1
git stash list
```
