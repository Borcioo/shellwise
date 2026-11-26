# Documentation site: design

## Intent

shellwise has a one-page landing site and a README. A user who wants to install it, wire it into
an agent host, read what a rule means or look up an exit code has to read the README top to
bottom or browse `docs/rules/` on GitHub. This adds a documentation site in the look of the
landing page, published through the same GitHub Pages route.

## Goals

- One place for install, quick start, per-host setup, commands, configuration, the rule
  reference, exit codes and JSON output, limits and the changelog.
- The rule reference, the changelog and the agent setup text are rendered from the repository's
  own files at build time, so the site cannot drift from them.
- The landing page keeps its URL, its content and its look. Its header carries the same name,
  colours and type as the docs header (Starlight's own, which adds search); each links to the other.
- A pull request that breaks the site build fails CI.

## Non-goals

- No change to Rust code, rule behaviour, the public interface or `docs/rules/*.md`.
- No versioned docs: the site is built from `main`, so it describes the latest release.
- No translation; English only.
- Maintainer documents (`docs/design.md`, `docs/spikes.md`, `docs/superpowers/`) are neither published nor linked: the site is for users.

## Anti-goals

- A claim the tool does not keep. Every statement about behaviour is checked against the code or
  the v0.2.0 binary; untested platforms and hosts are named as untested.
- Presenting shellwise as a security boundary.

## Approaches

| | Approach | Trade-off |
|---|---|---|
| A (chosen) | Astro with Starlight, themed with the landing page's tokens | Search (Pagefind), sidebar, table of contents, code blocks with copy buttons and accessible navigation come ready; the look is set through CSS variables and fonts, so it follows the landing page closely but is still recognisably a docs layout |
| B | Plain Astro with hand-written layouts | Pixel-level match with the landing page; search, sidebar, mobile navigation and heading anchors are all ours to write and maintain (roughly three times the code) |
| C | Keep Markdown on GitHub, link it from the landing page | No build; no search, no navigation, no styling, and the rule files stay a folder listing |

A is chosen: the site is reference material with 54 rule pages, where search and navigation
matter more than a bespoke layout.

## Decisions

| Topic | Decision |
|---|---|
| Versions | `astro` 7.4.x and `@astrojs/starlight` 0.43.x (latest on 2026-11-26; Astro 7 needs Node >= 22.23.4) |
| Node and package manager | Node 24 (`site/.nvmrc`), npm, `package-lock.json` committed |
| Where it lives | `site/` becomes the Astro project. The landing page is rewritten as `site/src/pages/index.astro` (the owner's choice): the same sections, text and styles, split into a layout, a shared header and one stylesheet with the colour and type tokens the docs theme also reads |
| URLs | Landing: `https://borcioo.github.io/shellwise/` (unchanged). Docs: `/shellwise/docs/…` (`site: https://borcioo.github.io`, `base: /shellwise`) |
| Landing page changes | A header with the name and links to Docs and GitHub; the hero's buttons are Install, Read the docs and View on GitHub (no release version is written on the page, so a release edits nothing here); the install section shows the one-line installers, the Claude Code plugin commands and `agent-setup`, and links to the install page (the manual hook entry moves to the docs, with its timeout setting); the footer's Rules and Changelog links point at the docs; fonts come from the self-hosted packages instead of Google Fonts. Everything else is carried over as is |
| Rule pages | A `rules` content collection with Astro's `glob()` loader on `../docs/rules/*.md`; one route `docs/rules/[id]` renders each in the Starlight layout, the title from the file name (ids keep their case: `rg-follow-L`). The sidebar group and the rule index page are built from the same directory listing |
| Changelog, agent setup text | Rendered the same way from `CHANGELOG.md` and `docs/agent-setup.md` |
| Hand-written pages | Markdown under `site/src/content/docs/docs/`, text reused from the README and the plugin README |
| Theme | Dark only (the owner's choice; no theme switch), with the landing page's colours (`#0E1116` background, `#F2B544` accent), Space Grotesk headings, Inter body, JetBrains Mono code. Fonts are self-hosted npm packages, so the docs make no third-party request |
| Code fences | The four fence names of `agent-setup.md` (`guard-sh`, `guard-pwsh`, `proof-bash`, `proof-pwsh`) are aliased to `sh`/`powershell` in the highlighter config |
| Deploy | `pages.yml`: a `build` job on pull requests and on pushes to `main` (paths: `site/**`, `docs/rules/**`, `docs/agent-setup.md`, `CHANGELOG.md`, the workflow); the `deploy` job runs on `main` only |
| Build check | `npm run check` after the build fails when: no rule file was read, the number of rule pages differs from the number of files in `docs/rules/`, the landing page is missing from the output or lacks its headline, or an internal link in the output points at nothing |

Spiked on 2026-11-26 outside the repo: the loader reads a folder outside the Astro project, the
54 rule pages build, `rg-follow-L` keeps its capital, a page at the root coexists with docs under `/docs/`, search indexes the rule pages; the whole build takes about 4 seconds locally.

## Site map

| Path under `/shellwise/docs/` | Content | Source |
|---|---|---|
| `/` | What shellwise is and is not; the five levels; what it catches | README, landing page |
| `install/` | One-line installers, what they do, other ways (archives, cargo, source), update, uninstall, switch off; platform status | README |
| `quick-start/` | First `check`, reading a finding, the allow marker, `explain` | README, binary output |
| `agents/claude-code/` | The plugin; the manual hook entry; timeout; switching off | plugin README, README |
| `agents/codex/` | Codex CLI entry, approval step, Windows guard line | `agent-setup.md` |
| `agents/other/` | `agent-setup` flow, the hosts table with tested / documentation-only marks, the guard line, hosts with no hook | `agent-setup.md` |
| `agents/setup-text/` | The text `shellwise agent-setup` prints | rendered from `docs/agent-setup.md` |
| `commands/check/` … `lint/`, `explain/`, `hook/`, `update/`, `agent-setup/` | Usage, flags, exit codes, examples | README, `src/main.rs`, binary |
| `configuration/` | `config.toml` location and keys, `.shellwise.toml` (raise only), environment variables | `src/config.rs`, README |
| `reference/exit-codes-and-json/` | Exit codes per command, the `--json` shape, hook replies | README, `src/adapter/` |
| `rules/` | Index of all rules | generated from `docs/rules/` |
| `rules/<id>/` | One page per rule | rendered from `docs/rules/<id>.md` |
| `limits/` | Not a security boundary; known limits; untested platforms and hosts; fail-closed behaviour | README, SECURITY.md |
| `changelog/` | Changelog | rendered from `CHANGELOG.md` |

Stated plainly on `install/` and `limits/`: the macOS binaries and the Linux arm64 binary have not
been run by anyone beyond what CI does (on macOS, CI runs the install-script and update tests
only); hosts other than Claude Code and Codex CLI are described from their documentation only.

## Left to the builder

- Sidebar order and labels; wording of the hand-written pages.
- Whether a mismatch between a document and the code is found: report it in the PR body, do not
  change Rust code, `docs/rules/` or `docs/agent-setup.md`.

## Estimate

About 4 agent working hours; about 250 lines of config, components, CSS and check script, about
900 lines of Markdown content, about 60 lines of workflow. Simpler version: drop the hand-written
pages and publish only the rule reference, changelog and setup text behind the landing page
(about 1 hour); it drops install, commands, configuration and per-host instructions.
