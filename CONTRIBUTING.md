# Contributing

## The most useful report: a command shellwise got wrong

Open an issue with:

- the command, exactly as the agent wrote it (remove anything private first);
- the shell (`bash`, `gitbash`, `pwsh`, `powershell5`) and the operating system;
- what shellwise answered (`shellwise check --shell <shell> -- '<command>'`);
- what really happens when the command runs.

A good command that was stopped and a bad command that passed are both bugs. Each one becomes a
test row.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on the first `cargo` call.

```
cargo build
cargo test --features testhooks
cargo fmt --check
cargo clippy --all-targets --features testhooks -- -D warnings
```

`--features oracle` adds the tests that ask the real shells; they need `pwsh` and Git Bash on
Windows. The maintainers' full gate is `scripts/gate.ps1`; it also needs two private inputs (see
the README) and is not required for a pull request. CI runs the commands above on Windows and
Linux.

## Changing or adding a rule

- A rule states what the shell does, so its tests ask the shell or run the command in a scratch
  folder. A rule nobody checked against the real shell is not accepted.
- Every finding has a `Fix:` line that works when pasted.
- A command the tool does not know is never blocked for being unknown, and a new rule that stops
  good commands needs the evidence that it is worth it.
- Add the rule's document to `docs/rules/` and a line under `## [Unreleased]` in `CHANGELOG.md`.

## Pull requests

Branch from `develop` (`feature/…`, `fix/…`, `chore/…`) and open the pull request against
`develop`. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
`main` holds released versions only.

By contributing you agree that your contribution is licensed under GPL-3.0-or-later.
