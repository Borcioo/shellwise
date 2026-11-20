# walk-unreadable

The folder walk behind a recursive delete met a folder or entry it cannot read, so it cannot tell
whether a link there leads outside the tree. Level `danger` (Ruling 122): an unread walk may hide
a link that a delete follows.

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

`rm -rf build` where `build/private` denies listing.

## Allow

`rm -rf build` where every folder in it can be listed and no link leads out.
