# walk-timeout

The guard ran out of its time budget (`walk_budget_ms`, under the hook timeout) while checking a
delete: the folder walk, the repo lookup or a target's resolution did not finish. Level from the
config's `dynamic_target` (default `danger`).

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

A recursive delete of a tree too large to walk within the budget.

## Allow

A recursive delete of a small tree with no link leading out of it.
