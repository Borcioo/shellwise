# walk-timeout

The guard ran out of its time budget (`walk_budget_ms`, under the hook timeout) while checking a
delete: the folder walk, the repo lookup or a target's resolution did not finish. Level `warn`
(Ruling 122): the message says the target could not be read. Level `danger` when the repo lookup
or the match by file identity ran out of time on a recursive or forced delete, a glob over a
folder's contents included (`rm -rf ./*`, `rm -rf ../*`): the target may be the repo root, its
`.git` or a protected folder (a lexical match, such as the home folder, is still
`delete-critical`); the allow marker confirms it.

## Warns

A recursive delete of a tree too large to walk within the budget.

## Allow

A recursive delete of a small tree with no link leading out of it.
