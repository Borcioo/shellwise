# git-no-verify

Ported from baseline-guard; a policy rule, off unless the config sets `policies.git_no_verify`.
`git commit`, `push`, `merge`, `rebase` or `am` with `--no-verify` (or `-n` where it means that:
`commit` and `am`) skips the repository's hooks; so does `-c core.hooksPath=…` before the
subcommand. The last of `--no-verify` and `--verify` wins; a value of `-m`, `--message` and the
other value options, and anything after `--`, is text.

Level `danger`.

`Fix: run the same `git commit` without `--no-verify` and fix what the hook reports`

## Deny

```powershell
git commit --no-verify -m 'fix: x'
git commit -nm x
```

## Allow

```powershell
git commit -m '--no-verify'
git push -n origin feature/x
```
