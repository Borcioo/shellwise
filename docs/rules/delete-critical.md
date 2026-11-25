# delete-critical

A delete whose target is one of these, or an ancestor of one:

- a system path: `C:\Windows`, `C:\Program Files*`, `C:\ProgramData` (any drive), `/usr`, `/etc`,
  `/bin`, `/sbin`, `/lib*`, `/System` (in Git Bash, the same rooted paths with no drive: the MSYS
  tree's own folders);
- a drive root, or `/`;
- the home folder (from the hook's own environment, whatever the command assigns to `HOME`);
- the root of the repo holding the cwd (only when the cwd is in a repo);
- a path in the config's `protected` list.

Level `critical`: a hard block. The allow marker does not lower it. Deleting *inside* the repo
root (`find . -name '*.o' -delete` from the root, `git clean -fd`) is not critical; inside a drive
root, `/`, a system path, the home folder or a protected path still is, and so is a glob over
their direct contents (`rm -rf ~/*`, `rm -rf /*`, `cd ~ && rm -rf *`, Git Bash
`cd /usr && rm -rf *`, Ruling 125). A glob over the
repo root's contents is `delete-repo-contents` (danger) unless it takes `.git` too (`rm -rf .*`).
The lexical match of these folders never waits on the repo lookup.

A pwsh list is split and each element judged (`Remove-Item build,C:\` is critical because of
`C:\`, `Remove-Item build, clean` is ok).

`Fix: delete only the folders inside it you mean, each by its full path, for example `<path>\<name>``

In a system folder every path below it is critical too, so the Fix names no path: `Fix: do not
delete in a system folder; if it must go, ask the user to run the command themselves`

## Deny

```bash
rm -rf ~
```

```powershell
Remove-Item -Recurse -Force .   # from the repo root
```

## Allow

```bash
rm -rf build
```

## Limits

- A PowerShell alias the same command defines (`Set-Alias`, `New-Alias`, `sal`, `nal`,
  `$alias:zz = …`) before its call reads as each cmdlet its definitions name, so
  `Set-Alias zz Remove-Item; zz C:\Windows -Recurse` is critical. Every earlier definition
  counts, also one in a `& { }` block or one a later definition replaced: the stricter reading.
  A definition after the call is not read. A call of an alias whose value the guard cannot read
  (`Set-Alias zz $x`) is `dynamic-target` when a word of it spells a protected folder as an
  absolute path, `~` or `$HOME`; a relative one (`zz .` from the repo root) is not judged.
- A call of an alias the command defines counts as a possible move of the location, so a
  relative delete after it (`zz build; zz src`) is `delete-unknown-location`.
- A Bash alias is not read: bash expands none on the line that defines it, and a non-interactive
  bash none without `shopt -s expand_aliases`. A function that passes its arguments on
  (`zz() { rm -rf "$@"; }`, `function zz { Remove-Item @args }`) is `dynamic-target`, not
  judged by the folder it is called with.
- An alias to a location cmdlet (`Set-Alias zz Set-Location`) is not followed: a relative delete
  after its call is `delete-unknown-location`.
