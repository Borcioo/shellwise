# walk-unreadable

The folder walk behind a recursive delete met a folder or entry it cannot read, so it cannot tell
whether a link there leads outside the tree. Level `warn` (Ruling 122).

## Warns

`rm -rf build` where `build/private` denies listing.

## Allow

`rm -rf build` where every folder in it can be listed and no link leads out.
