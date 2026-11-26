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

Level `warn` for the recipe that starts an empty branch, `git checkout --orphan <branch> && git
rm -rf .` (or `git switch --orphan <branch>`): the whole-folder `git rm -rf` is the very next
statement after the orphan call and joined to it by `&&`, so it runs only when the orphan call
succeeded; both are top-level statements of the same command, each a single command, in the same
folder. The branch left still holds every tracked file; only uncommitted changes carried onto the
new branch are lost. It stays danger when they are joined by `;` or a new line (the orphan call
fails when the branch already exists, and the `git rm` then empties the branch you are on), with
any statement between them, with a `!` before the orphan call, with no branch name after
`--orphan`, with no known folder, with the orphan call after the `git rm` or on the right of an
`||`, inside an `if`, a loop, a function, a subshell or a pipeline (or the `git rm` inside one),
and when the command assigns `GIT_DIR`, `GIT_WORK_TREE` or `GIT_INDEX_FILE` anywhere (a prefix,
`export`, `$env:GIT_DIR = …`): the two calls may then name different repositories. Windows
PowerShell 5.1 has no `&&`, so there the recipe is always danger.

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`
(for `git clean`: look at `git clean -nd` first; for `git rm`: to untrack the files only, run
`git rm -r --cached <pathspec>` with git's own options kept, `git -C sub rm -r --cached .`; after
a `cd`, run the same `git rm` with `--cached` in the folder it runs in; when the command assigns
`GIT_DIR`, `GIT_WORK_TREE` or `GIT_INDEX_FILE`, run the same command with `--cached`; otherwise
look at `git status` first and commit or stash what you keep)

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
