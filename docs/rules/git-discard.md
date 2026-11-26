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

`git rm` on the whole folder git runs in or the whole repository removes every tracked file there
from the working tree. The pathspecs that take it whole: `.`, `./` and a `*` or `./*` the shell
expands, by their text wherever git runs (with `-C <dir>`, that folder); `:/`, `:/.` and `:(top)`;
a path that resolves to the folder git runs in or to the repo root (`git -C build rm -rf ..`).
These need `-r`. A `*` or `./*` git expands itself (`'*'`, `'./*'` in Bash; any `*`, `./*` or `.\*`
in PowerShell, probed on Windows; where pwsh expands an unquoted one first, the rule still reads
it the stricter way) and `:/*` reach nested files without `-r`. Level `danger` with `-f`/`--force` (also in a cluster, `-rf`, or by a prefix, `--forc`):
their uncommitted changes are lost too. Level `warn` without it: git refuses a file with
uncommitted changes, and the rest can be restored from HEAD. `--cached` (only the index) and
`-n`/`--dry-run` before `--` or `--end-of-options` are no finding; the last of an option and its
`--no-` form counts.
A narrow pathspec (`git rm -rf build/`) is no finding of this rule, nor a pathspec the guard
cannot read (`git rm -rf "$d"`). git takes no `-R`. An option word the guard cannot read with a
whole-folder pathspec (`git rm $OPTS .`) warns `git-unreadable`.

Level `warn` for the recipe that starts an empty branch: a whole-folder `git rm -rf` after a
`git checkout --orphan <branch>` or `git switch --orphan <branch>` earlier in the same command
(`&&`, `;` or a new line), in the same folder, with no `cd` and no other branch switch between
them. The branch left still holds every tracked file; only uncommitted changes carried onto the
new branch are lost. With no known folder, or with the orphan checkout after the `git rm`, it
stays danger.

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`
(for `git clean`: look at `git clean -nd` first; for `git rm`: to untrack the files only, run
`git rm -r --cached <pathspec>` with git's own options kept, `git -C sub rm -r --cached .`; after
a `cd`, run the same `git rm` with `--cached` in the folder it runs in; otherwise look at
`git status` first and commit or stash what you keep)

## Deny

```bash
git reset --hard origin/develop
git clean -fdx
git rm -rf .
```

## Warns

```bash
git reset --keep HEAD~1
git stash drop
git worktree remove --force .claude/worktrees/x
git rm -r .
```

## Allow

```bash
git reset --soft HEAD~1
git stash list
git clean -n
git rm -r --cached .
git rm -rf build/
```

## Limits

- `git rm` pathspec magic is read only in the literal forms above: an exclude-only pathspec
  (`git rm -rf ':!keep'`, which takes everything but `keep`), long magic other than `:(top)`
  (`':(glob)**'`, `':(icase)…'`) and a wildcard other than `*`, `./*`, `.\*` and `:/*` (`'*.log'`,
  which also reaches nested files, `'**'`, `'./**'`, `'*.*'`, `'[a-z]*'`, `':/**'`) are no finding
  of this rule.
- `git rm -rf .` in a command the guard does not read is no finding of this rule: inside a child
  shell's body (`bash -c '…'`, `pwsh -Command '…'`), `eval`, `Invoke-Expression` or `cmd /c`, or
  on a line with a parse error (where `git clean -fdx` reads `opaque-destructive` or
  `parse-error-destructive`).
