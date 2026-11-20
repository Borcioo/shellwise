**What changes and why**

**How it was checked** (commands run and their result; for a rule: what the real shell did)

- [ ] `cargo fmt --check`, `cargo clippy --all-targets --features testhooks -- -D warnings` and
      `cargo test --features testhooks` pass
- [ ] A rule change has a test that fails without it, and its document in `docs/rules/`
- [ ] A user-visible change has a line under `## [Unreleased]` in `CHANGELOG.md`
