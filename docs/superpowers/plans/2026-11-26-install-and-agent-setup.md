# Install, Update and Agent Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One line installs shellwise, one command updates it, one pasted text lets any agent wire it into its host, and Claude Code users can install it as a plugin.

**Architecture:** Two install scripts at the repo root do all downloading and verifying; the binary embeds them and runs them for `update`. A new `hook generic` entry point speaks the exit-code-2 convention so no per-host adapter is needed. A setup text embedded in the binary tells the user's agent how to wire it. A Claude Code plugin in the repo registers the existing `hook claude-code`.

**Tech Stack:** Rust 2024 (clap, serde_json; no new dependencies), POSIX sh, PowerShell 5.1/7, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-26-install-and-adapters-design.md`

**Estimate:** about 9 agent hours; about 520 lines of code (260 in the two scripts) and 430 of tests. Simpler version: tasks 1, 2, 5 and 8 only (scripts, setup text without `hook generic`, README), about 4 hours; it drops the one-line wiring on other hosts, `update` and the plugin.

## Global Constraints

- The frozen interface does not change: `hook claude-code` input, output and exit 0; `check` flags and exit codes (0, 1, 2, 3, 64); `SHELLWISE=off`; config keys and file locations; the allow marker; rule ids; the four existing release asset names; `shellwise --version` output.
- No new Cargo dependency. No network access outside `update`.
- No company, client or private-harness name anywhere; the sibling plugin project is "another plugin that registers the same hook".
- Do not touch `src/rules/wait_loop.rs`, `src/scan.rs`, `tests/cases/*.toml` or `CHANGELOG.md` before task 8 (another branch holds them).
- Nothing is published: no tag, no release, no registry. The branch merges into `develop` only.
- Scripts and hooks write LF. Text encodings are explicit (UTF-8 without BOM).
- Every commit command ends with ` # workbench:confirmed`.
- Tests: `cargo test --features testhooks <filter>` while working; the full gate (`pwsh -NoProfile -File scripts/gate.ps1`, with `SHELLWISE_CORPUS` and `SHELLWISE_DENYLIST` set) once before the PR.
- Risk marks: the checksum check (task 2) and the `hook generic` failure rules (task 1) are guards: each refusal branch is shown red once by breaking the code, with the mutation named in the report. Everything else: one test per behaviour, one red run per test.

## Review Focus

- A host leaves stdin open for `hook generic`: the user's shell tool must keep working (exit 0 at the read bound unless the bytes read show a destructive command). Test in task 1.
- The install folder path holds a space or a non-ASCII character (`C:\Users\Zoë Q\…`): both scripts must install and report the right path. Test in task 2.
- The download is cut short or `SHA256SUMS` is an HTML error page: the old binary must still be in place and runnable. Test in task 2.
- `shellwise update` run from a binary the install scripts did not place (a `cargo install` copy, a read-only folder): it must fail with one clear line and leave the binary alone. Test in task 3.
- `update --notify` with no network, or a release host that never answers: no output, exit 0, back within 3 seconds. Test in task 3.

## Amendments from the plan review

These bind every task and replace the task text where they differ.

**Task 1**
- `src/main.rs` is its own crate: it cannot reach a `pub(crate)` item. `generic.rs` exports `pub fn unread_verdict(bytes: &[u8], reason: &str, deadline: &Deadline) -> Option<String>` (the rendered stderr text when the raw scan of the bytes gives `danger` or above, as `claude_code::malformed` decides it), built on a `pub(crate)` `scan_text`; `finding_text` becomes `pub(crate)` with unchanged output.
- The usage-error rule lives only in the `Cli::try_parse` error branch and reads `std::env::args_os()` (never `args()`, which panics on non-Unicode arguments that `check` must keep accepting).
- Every process test passes `--shell bash` or `--shell pwsh` explicitly and removes `DIR` from the child's environment.
- Extra rows: `a_break_exits_2` (`--shell bash`, `echo 'abc` → exit 2, stderr `shellwise: break parse-error`); `an_analysis_panic_blocks` uses `rm -rf x` under `SHELLWISE_TESTHOOK=panic`, as `tests/failclosed.rs` does; `switched_off_exits_0_unread` feeds a cut destructive event (`{"command":"rm -rf x`), which exits 2 without the switch; `a_scan_with_no_answer_blocks` (a malformed event under the scan-sleep test hook `tests/failclosed.rs` uses → exit 2).
- The open-stdin tests allow 5 s of wall time, as `tests/failclosed.rs` does.

**Task 2**
- The fake release is built without a new crate: `tar -czf` for `.tar.gz`, `Compress-Archive` for `.zip`, in `tests/common/release.rs`. Each archive holds the top-level folder `shellwise-v<version>-<target>/` with the binary inside, as `release.yml` packages it. The fake binary of each version is the test binary plus a trailing marker file next to it named `VERSION` holding the version; tests tell versions apart by reading the marker the script must not install and by the binary's byte length after appending one marker byte per version.
- `SHELLWISE_TARGET` overrides target detection (documented as a test and troubleshooting variable); test row `an_unsupported_target_refuses` sets it to `riscv64-unknown-none` and expects exit 1 with the supported list on stderr.
- Windows swap: after the new binary is in place, delete `shellwise.old` when it is not locked. The test asserts no `.old` and no `.new` remains (the test's old binary is not running).
- Names: the temporary and old files are `shellwise.new` / `shellwise.old` on POSIX and `shellwise.exe.new` / `shellwise.exe.old` on Windows.
- `install.ps1` must behave under `irm … | iex`: the whole body runs inside `& { … }` so `Set-StrictMode` and `$ErrorActionPreference` do not leak into the user's session, and a refusal is a `throw` (never `exit`, which would close the user's window); when run with `-File` the script ends with exit code 1 on a refusal. Test row `the_script_works_through_iex` pipes the file text into `pwsh -NoProfile -Command -` as `Get-Content -Raw <path> | Invoke-Expression`.
- PATH on Windows: read the user value with `Registry::CurrentUser` `Environment` `GetValue('Path', '', 'DoNotExpandEnvironmentNames')` and write it back as `ExpandString`, so existing `%VAR%` entries stay unexpanded.
- Both scripts bound every download (`curl --connect-timeout 10 --max-time 120`; `Invoke-WebRequest -TimeoutSec 120`); in `check` mode the bounds are 2 and 3 seconds.
- The Windows PowerShell 5.1 test run passes `-ExecutionPolicy Bypass`; every test that starts PowerShell sets `POWERSHELL_TELEMETRY_OPTOUT=1` and reads output as UTF-8.

**Task 3**
- `notify_checks_at_most_once_a_day`: the newer fake release stays in place for the second run, which must print nothing.
- On POSIX the script child is started in its own process group and the whole group is killed at the bound.
- `update` refuses with one line when the running binary's folder is not writable; the Review Focus line about a `cargo install` copy means exactly that. The mode-555 test is skipped (printed SKIP) when the effective user is root.
- `current_exe()` is used without the `\\?\` prefix on Windows.

**Task 4**
- The proof command is one shellwise refuses at `break` and that only prints a shell error if it runs unguarded: `echo 'abc` for bash (rule `parse-error`) and `Write-Output "$name: done"` for PowerShell (rule `ps-var-colon`). The test expects `shellwise check` exit code 1 for each and, through `hook generic`, exit code 2. The text tells the agent how to tell the two outcomes apart: a block shows a line starting `shellwise: break`, an unguarded run shows the shell's own syntax error. The text says to pass the command to `check` after `--` or on stdin without a trailing newline.
- The host table's values come from the three files `install-research-codex-gemini-copilot.md`, `install-research-cursor-windsurf-cline.md`, `install-research-opencode-aider-zed-t3.md`, whose folder the task brief names (outside the repo); a value not in them is left out.
- The contract-items test also checks `--json`.

**Task 5**
- The plugin's `PreToolUse` timeout is 10 seconds (the default `hook_timeout_ms` is 10000, so the analysis ends by itself at 8.5 s; the plugin cannot write the user's config). The `SessionStart` timeout stays 5.
- The live proof builds its own stub from the method `docs/spikes.md` describes; no stub file is tracked in the repo. When the stub cannot be rebuilt within an hour of work, stop and report BLOCKED with what was tried.

**Task 6**
- No separate `install-scripts` job for Windows and Ubuntu (the `test` job already runs every test file there): add one `macos-latest` job that runs `cargo test --features testhooks --test install_scripts --test update`, and a `shellcheck install.sh` step in the Ubuntu `test` job.

**Task 7** depends on task 5 (both edit `docs/spikes.md`). No live run on Cursor is planned: its row stays `from the host's documentation`.

**Task 8** README order: the two one-liners, the plugin commands, `shellwise agent-setup`, `shellwise update`, then the alternatives.

**Global:** the frozen `check` exit codes are 0, 1, 2, 3, 64 and 74. Test lines are expected to reach about 600.

---

### Task 1: `shellwise hook generic`

**Files:**
- Create: `src/adapter/generic.rs`
- Modify: `src/adapter/mod.rs` (add `pub mod generic;`), `src/main.rs` (`HookCmd::Generic`, `run_hook_generic`, the `Hook` doc comment: "exits 0, or 2 from `generic` for a refused command")
- Test: unit tests in `src/adapter/generic.rs`; `tests/hook_generic.rs` (process level, modelled on `tests/hook.rs`)

**Interfaces:**
- Consumes: `claude_code::malformed`-style raw scan (`shellwise::malformed_within`), `analyse`, `Deadline`, `Config`, `Shell`, `Os` as `run_hook` uses them.
- Produces:
  - `pub enum Event { Command { shell: Shell, command: String, cwd: Option<PathBuf> }, NotOurs, Malformed(&'static str) }`
  - `pub fn parse_event(bytes: &[u8], shell: Option<Shell>, os: Os) -> Event`
  - `pub fn render(verdict: &Verdict) -> Option<String>` — the stderr text: the same `shellwise: <level> <rule>: <message>` and `Fix:` lines `hook claude-code` writes into its reason, highest level first, `None` for `ok`
  - `pub const EXIT_BLOCK: i32 = 2;`
  - CLI: `shellwise hook generic [--shell pwsh|powershell5|bash|gitbash] [--config FILE]`

- [ ] **Step 1: Write the failing unit tests** in `src/adapter/generic.rs`:

```rust
#[test]
fn the_command_is_found_in_each_host_shape() {
    let rows: [(&str, &str); 5] = [
        (r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/w"}"#, "ls -la"),
        (r#"{"command":"ls -la","cwd":"/w"}"#, "ls -la"),
        (r#"{"tool_info":{"command_line":"ls -la"}}"#, "ls -la"),
        (r#"{"toolName":"bash","toolArgs":"{\"command\":\"ls -la\"}"}"#, "ls -la"),
        (r#"{"tool_name":"run_shell_command","tool_input":{"command":"ls -la","dir_path":"x"}}"#, "ls -la"),
    ];
    for (raw, want) in rows {
        match parse_event(raw.as_bytes(), None, Os::Posix) {
            Event::Command { command, .. } => assert_eq!(command, want, "{raw}"),
            other => panic!("{raw}: {other:?}"),
        }
    }
}

#[test]
fn the_shell_comes_from_the_flag_then_the_tool_name_then_the_os() {
    let ps = r#"{"toolName":"PowerShell","toolArgs":"{\"command\":\"Get-Date\"}"}"#;
    let plain = r#"{"command":"ls"}"#;
    let shell = |raw: &str, flag, os| match parse_event(raw.as_bytes(), flag, os) {
        Event::Command { shell, .. } => shell,
        other => panic!("{other:?}"),
    };
    assert_eq!(shell(ps, None, Os::Posix), Shell::Pwsh);
    assert_eq!(shell(ps, Some(Shell::Bash(BashProfile::Posix)), Os::Posix), Shell::Bash(BashProfile::Posix));
    assert_eq!(shell(plain, None, Os::Windows), Shell::Pwsh);
    assert_eq!(shell(plain, None, Os::Posix), Shell::Bash(BashProfile::Posix));
}

#[test]
fn an_event_without_a_command_is_not_ours() {
    for raw in ["", " \n", r#"{"tool_name":"Read","tool_input":{"file_path":"x"}}"#, r#"{"command":7}"#, "[]"] {
        assert_eq!(parse_event(raw.as_bytes(), None, Os::Posix), Event::NotOurs, "{raw}");
    }
    assert!(matches!(parse_event(b"{\"command\":\"rm", None, Os::Posix), Event::Malformed(_)));
}
```

- [ ] **Step 2: Run** `cargo test --features testhooks --lib adapter::generic` — expected: compile error (module missing), then FAIL on the assertions once the stubs exist.

- [ ] **Step 3: Implement `parse_event` and `render`.** Lookup order: `tool_input.command`, top-level `command`, `tool_info.command_line`, `command` inside `toolArgs` parsed as JSON. Tool name from `tool_name` or `toolName`, compared case-insensitively to `powershell`. `cwd` only when a non-empty string. `render` reuses the finding text of `claude_code` (make `finding_text` `pub(crate)`; do not change its output).

- [ ] **Step 4: Write the failing process tests** in `tests/hook_generic.rs` (helper: spawn the built binary with stdin bytes and env, return `(exit code, stdout, stderr)`; no quote or glob characters in argv):

| Test | stdin | Expect |
|---|---|---|
| `ok_is_silent` | `{"command":"ls"}` | exit 0, stdout and stderr empty |
| `a_refused_command_exits_2_with_the_fix_on_stderr` | bash event `rm -rf "$DIR/"` | exit 2; stderr holds `shellwise: danger delete-empty-expansion` and a line starting `Fix: `; stdout empty |
| `a_warn_exits_0_with_the_note_on_stderr` | bash event `tail -f app.log` | exit 0; stderr holds `shellwise: warn follow-unbounded` |
| `switched_off_exits_0_unread` | any, env `SHELLWISE=off` | exit 0, no output |
| `a_usage_error_exits_0` | args `hook generic --shell fish` | exit 0; stderr non-empty |
| `stdin_left_open_does_not_block` | stdin held open, harmless prefix `{"command":"ls` | exit 0 within 3 s; one line on stderr |
| `stdin_left_open_with_a_destructive_prefix_blocks` | held open, prefix `{"command":"rm -rf x` | exit 2 |
| `malformed_json_with_a_destructive_command_blocks` | `{"command":"rm -rf x"` (cut) | exit 2 |
| `malformed_json_without_one_passes` | `{"command":"ls"` (cut) | exit 0 |
| `an_analysis_panic_blocks` | env `SHELLWISE_TESTHOOK` as `tests/failclosed.rs` sets it, a parsed command | exit 2; stderr holds `analysis-incomplete` |
| `claude_code_still_exits_0_on_a_deny` | `hook claude-code` with a refused command | exit 0; stdout JSON has `permissionDecision` `deny` |

- [ ] **Step 5: Run** `cargo test --features testhooks --test hook_generic` — expected: FAIL (subcommand unknown).

- [ ] **Step 6: Implement `run_hook_generic` in `src/main.rs`.** A usage error under `hook generic` exits 0: detect it in `run` before `Cli::try_parse` reports (`std::env::args` second and third words are `hook`, `generic`), print clap's message to stderr. Wrap the body in `panic::catch_unwind`: a panic outside the analysis prints one line and exits 0. Read stdin under the same bound as `run_hook` (`HOOK_READ_MS`); for `Input::Unread`, over-size and `Event::Malformed`, run the raw scan (`malformed_within` over `scan_text` of the bytes read, made `pub(crate)`) under `hook_scan_deadline`: level `danger` or above exits 2 with the rendered verdict, else exit 0 with `shellwise: event not read (<reason>); the command was not checked`. For `Event::Command` follow `run_hook` (config from `cwd`, `analyse`), then `render` to stderr and exit `EXIT_BLOCK` when `verdict.level >= Level::Break`, else 0.

- [ ] **Step 7: Run** `cargo test --features testhooks --test hook_generic --test hook` and the unit tests — expected: PASS. Then the red runs for the guard rows: (a) make the unread branch return 0 unconditionally → `stdin_left_open_with_a_destructive_prefix_blocks` fails; (b) make it return 2 unconditionally → `stdin_left_open_does_not_block` fails; (c) drop the `>= Level::Break` test → `a_refused_command_exits_2…` fails. Restore each.

- [ ] **Step 8: Commit** `feat(hook): add the generic exit-code adapter`.

### Task 2: Install scripts

**Files:**
- Create: `install.sh`, `install.ps1`, `tests/install_scripts.rs`, `tests/install_fixture/` (built at test time in a temp folder, nothing committed there but a README line is not needed: do not create the folder)
- Modify: `.gitattributes` only if `install.sh` would not check out with LF (the repo already sets `* text=auto eol=lf`; verify with `git ls-files --eol install.sh`)

**Interfaces:**
- Produces, as environment variables both scripts read (no arguments, so the binary can run them from stdin):
  - `SHELLWISE_VERSION` — `1.2.3` or `v1.2.3`; unset means latest
  - `SHELLWISE_INSTALL_DIR` — target folder
  - `SHELLWISE_BASE_URL` — default `https://github.com/Borcioo/shellwise/releases`; an `http(s)` URL or a local folder with the same layout: `<base>/latest/download/SHA256SUMS`, `<base>/download/v<version>/<file>`
  - `SHELLWISE_MODE` — unset or `install`; `check` prints only the latest version (`1.2.3`) on stdout and installs nothing
  - `SHELLWISE_NO_PATH=1` — skip the PATH step
- Exit codes: 0 done; 1 any refusal, with one line on stderr starting `shellwise install: `.
- Latest version: read from `<base>/latest/download/SHA256SUMS`, the `<version>` in the first `shellwise-v<version>-` file name. A pinned version reads `<base>/download/v<version>/SHA256SUMS`.
- Targets: Windows x64 → `x86_64-pc-windows-msvc.zip`; macOS arm64/x64 → `aarch64-apple-darwin` / `x86_64-apple-darwin` `.tar.gz`; Linux x64 → `x86_64-unknown-linux-musl`, else `x86_64-unknown-linux-gnu` when `SHA256SUMS` has no musl line; Linux arm64 → `aarch64-unknown-linux-musl`.

- [ ] **Step 1: Write the failing tests** in `tests/install_scripts.rs`. Each test builds a fake release in a temp folder: an archive for the host target holding a fake `shellwise` (a copy of the test binary `env!("CARGO_BIN_EXE_shellwise")`), `SHA256SUMS` made with the `sha2` dev-dependency, laid out as above for version `9.9.9`. The script under test is `install.ps1` on Windows (run with `pwsh -NoProfile -File`, and once more with `powershell` when present) and `install.sh` elsewhere (`sh`). Every run sets `SHELLWISE_NO_PATH=1` and a temp `SHELLWISE_INSTALL_DIR`. Skip with a printed reason and a SKIP count when the interpreter is missing; never pass silently.

| Test | Setup | Expect |
|---|---|---|
| `a_fresh_install_places_a_runnable_binary` | empty install dir | exit 0; `<dir>/shellwise[.exe] --version` runs |
| `a_second_run_replaces_the_binary` | install dir holds an older fake (a different file) | exit 0; the new bytes are in place; no `.old` or temp file left (on Windows `.old` may remain only while locked) |
| `a_wrong_checksum_leaves_the_old_binary` | `SHA256SUMS` line altered by one hex digit | exit 1; stderr names the checksum; the old file is byte-identical and runs |
| `a_missing_checksum_line_refuses` | `SHA256SUMS` without the host target's line (and without the gnu fallback) | exit 1; old binary untouched |
| `an_html_error_page_as_sums_refuses` | `SHA256SUMS` = `<html>Not Found</html>` | exit 1 |
| `a_cut_archive_refuses` | archive truncated to half, sums for the whole | exit 1; old binary untouched |
| `a_pinned_version_is_used` | two versions laid out, `SHELLWISE_VERSION=9.9.8` | the 9.9.8 fake is installed |
| `check_mode_prints_the_latest_version_only` | `SHELLWISE_MODE=check` | stdout `9.9.9`, install dir unchanged |
| `an_install_dir_with_a_space_and_a_non_ascii_letter_works` | dir name built at run time with a space and U+00EB | exit 0; binary runs |
| `linux_falls_back_to_gnu_when_no_musl_line` (Linux only) | sums with only the gnu line | the gnu archive is installed |

- [ ] **Step 2: Run** `cargo test --features testhooks --test install_scripts` — expected: FAIL (scripts missing).

- [ ] **Step 3: Write `install.sh`** (POSIX `sh`, `set -eu`, no bashisms; `shellcheck install.sh` clean). Download with `curl -fsSL` or `wget -qO`; a local-folder base is copied with `cp`. Hash with `sha256sum`, else `shasum -a 256`; neither present is a refusal. Compare the lowercase 64-hex digest for the exact file name. Unpack in a `mktemp -d` folder removed on exit (`trap`). Copy the binary to `<dir>/.shellwise.new.$$`, `chmod 755`, then `mv -f` onto `<dir>/shellwise`. PATH step: when `<dir>` is not in `$PATH`, print the `export PATH=…` line to add; never edit a profile. Last lines: the installed version and `Next: shellwise agent-setup`.

- [ ] **Step 4: Write `install.ps1`** (runs on Windows PowerShell 5.1 and PowerShell 7; `$ErrorActionPreference = 'Stop'`; `Set-StrictMode -Version Latest`; no `&&`, no ternary). Download with `Invoke-WebRequest -UseBasicParsing`; hash with `Get-FileHash -Algorithm SHA256`; unpack with `Expand-Archive`. Swap: copy to `<dir>\shellwise.exe.new`; if `shellwise.exe` exists, delete a stale `shellwise.exe.old` (ignore a locked one), rename the current one to `.old`, rename `.new` into place, and on failure rename `.old` back and refuse. PATH step: when the user `PATH` (registry value read with `[Environment]::GetEnvironmentVariable('Path','User')`) lacks the folder, append it with `SetEnvironmentVariable` and say a new terminal is needed. Default dir `%LOCALAPPDATA%\Programs\shellwise`. All files written by the script are the binary only.

- [ ] **Step 5: Run** the tests — expected: PASS on this OS; then in WSL through the gate's Linux leg at the PR. Red runs for the checksum guard: (a) skip the comparison → `a_wrong_checksum…` and `a_cut_archive…` fail; (b) treat a missing line as a pass → `a_missing_checksum_line…` and `an_html_error_page…` fail. Restore.

- [ ] **Step 6: Commit** `feat(install): add checksum-verifying install scripts`.

### Task 3: `shellwise update`

**Files:**
- Create: `src/update.rs` (binary-side module, declared in `src/main.rs` like `bench`), `tests/update.rs`
- Modify: `src/main.rs` (`Cmd::Update(UpdateArgs)`)

**Interfaces:**
- Consumes: `install.sh`, `install.ps1` from task 2 via `include_str!("../install.sh")` / `include_str!("../install.ps1")`; `shellwise::config::user_file()` for the config folder.
- Produces:
  - CLI: `shellwise update` (exit 0 updated or already current, 1 refused), `shellwise update --check` (stdout `installed <a>, latest <b>`; exit 0 same, 1 newer exists, 2 latest not readable), `shellwise update --notify` (always exit 0)
  - `fn run_script(mode: &str, install_dir: Option<&Path>, wait: Option<Duration>) -> io::Result<(i32, String)>` — spawns `sh -s` on POSIX, `pwsh -NoProfile -ExecutionPolicy Bypass -Command -` (else `powershell` with the same arguments) on Windows, the script on stdin, the task 2 variables in the environment (the caller's `SHELLWISE_BASE_URL` and `SHELLWISE_VERSION` pass through); kills the child at `wait`.
  - Timestamp file: `<user config folder>/shellwise/update-check`, holding the Unix time of the last notify check.

- [ ] **Step 1: Write the failing tests** in `tests/update.rs`, reusing the fake-release builder from `tests/install_scripts.rs` (move it to `tests/common/`). The binary under test is a copy of the test binary in a temp folder, run with `SHELLWISE_BASE_URL` pointing at the fake release and a fake config home (`APPDATA` / `XDG_CONFIG_HOME` / `HOME` set to a temp folder; on Windows fake `HOME` alone is not used by the code under test).

| Test | Setup | Expect |
|---|---|---|
| `check_reports_a_newer_release` | fake latest `9.9.9` | exit 1; stdout `installed <CARGO_PKG_VERSION>, latest 9.9.9` |
| `check_reports_current` | fake latest = `CARGO_PKG_VERSION` | exit 0 |
| `check_exits_2_when_the_release_is_unreadable` | base URL = an empty folder | exit 2; one line on stderr |
| `update_replaces_the_running_binary_in_its_own_folder` | fake latest `9.9.9` | exit 0; the file next to the copy is the fake 9.9.9 |
| `update_in_a_read_only_folder_refuses_and_keeps_the_binary` | POSIX: folder mode 555 (skip on Windows with a printed SKIP) | exit 1; one line on stderr; binary unchanged |
| `notify_prints_one_line_when_newer` | newer fake | exit 0; stdout one line holding `9.9.9` and `shellwise update` |
| `notify_is_silent_when_current_or_unreachable` | current; then an empty folder | exit 0; no stdout |
| `notify_checks_at_most_once_a_day` | run twice with a newer fake | the second run prints nothing and does not read the release (remove the fake between runs; still exit 0) |
| `notify_returns_within_the_bound` | base URL `http://127.0.0.1:<port>` of a listener that accepts and never answers | exit 0, no stdout, under 4 s wall time |

- [ ] **Step 2: Run** `cargo test --features testhooks --test update` — expected: FAIL (subcommand unknown).

- [ ] **Step 3: Implement `src/update.rs`.** `update`: install dir = the parent of `std::env::current_exe()` (canonicalised); run the script in install mode with `SHELLWISE_NO_PATH=1`, stream its output through. `--check`: run in `check` mode with a 10 s bound; compare with `env!("CARGO_PKG_VERSION")` as dotted integers. `--notify`: return at once when the timestamp is younger than 24 h; write the timestamp first (atomically: temp file, rename), then run `check` with a 3 s bound; print `shellwise <latest> is available (installed <current>): run shellwise update` only when newer; swallow every error.

- [ ] **Step 4: Run** the tests — expected: PASS. Red runs: one per test by breaking the branch it covers (list them in the report).

- [ ] **Step 5: Commit** `feat(update): update from the embedded install script`.

### Task 4: `shellwise agent-setup` and the setup text

**Files:**
- Create: `docs/agent-setup.md`
- Modify: `src/main.rs` (`Cmd::AgentSetup`, prints `include_str!("../docs/agent-setup.md")`), `tests/cli.rs`

**Interfaces:**
- Consumes: `hook generic` (task 1), `update` (task 3).
- Produces: `shellwise agent-setup` prints the file byte for byte, exit 0.

- [ ] **Step 1: Write the failing tests** in `tests/cli.rs`: `agent_setup_prints_the_embedded_text` (stdout equals the file read from disk, LF only); `the_setup_text_names_every_contract_item` (the text contains each of: `shellwise hook generic`, `--shell`, `exit code 2`, `SHELLWISE=off`, `# shellwise: allow`, `shellwise check`, `shellwise update`, `back up`, `10 seconds`); `the_proof_command_in_the_text_is_refused_and_harmless` (extract the fenced block tagged `proof-bash` and the one tagged `proof-pwsh`, run each through `shellwise check --shell bash|pwsh`: exit 2 or 3; and assert the text of each names no existing path: the delete target contains `shellwise-proof-`).

- [ ] **Step 2: Run** `cargo test --features testhooks --test cli` — expected: FAIL.

- [ ] **Step 3: Write `docs/agent-setup.md`** with the sections the spec lists under "`shellwise agent-setup`", in this order: what shellwise is; the contract; the steps; the guard line (one `sh` form, one PowerShell form: run the hook, pass exit 2 and its stderr through, turn a missing binary and any other exit code into 0); the host table; the proof; no hook on this host; undo. Host table rows and their marks: Claude Code (`tested`; `hook claude-code` or the plugin), Codex CLI (`from the host's documentation` until task 7 flips it; user approval of the hook in `/hooks` is required), Cursor (already runs a Claude Code hook from the user's Claude settings; add an entry only when there is none), Gemini CLI (timeout in milliseconds; guard line on macOS and Linux), Copilot CLI (guard line; own file under the hooks folder), Devin (matcher `exec`). Config paths, event names and matchers come from the research notes named in the spec's status line of the PR, copied exactly; a value not in the notes is left out, not guessed. Proof blocks: `rm -rf "$SHELLWISE_PROOF_UNSET/shellwise-proof-0000"` (tag `proof-bash`) and the PowerShell equivalent with `Remove-Item -Recurse -Force` (tag `proof-pwsh`); if `check` does not refuse a block, change the block, not the rule.

- [ ] **Step 4: Run** the tests — expected: PASS. Red run: change the bash proof block to `ls` → the third test fails.

- [ ] **Step 5: Commit** `feat(cli): add agent-setup and the setup text`.

### Task 5: Claude Code plugin

**Files:**
- Create: `.claude-plugin/marketplace.json`, `plugins/shellwise/.claude-plugin/plugin.json`, `plugins/shellwise/hooks/hooks.json`, `plugins/shellwise/README.md`
- Test: `tests/plugin_files.rs`

**Interfaces:**
- Consumes: `hook claude-code` (unchanged), `update --notify` (task 3).
- Produces: marketplace name `shellwise`, plugin name `shellwise`; hooks: `PreToolUse` matcher `Bash|PowerShell`, command `shellwise`, args `["hook","claude-code"]`, timeout 5; `SessionStart`, command `shellwise`, args `["update","--notify"]`, timeout 5.

- [ ] **Step 1: Read the current plugin and marketplace manifest reference** (Claude Code docs: plugins reference, plugin marketplaces, hooks) and note the required fields and whether a plugin hook entry supports `args`. If `args` is not supported there, the command is the single string `shellwise hook claude-code`.

- [ ] **Step 2: Write the failing test** `tests/plugin_files.rs`: the three JSON files parse; the plugin version equals `CARGO_PKG_VERSION`; the `PreToolUse` entry has matcher `Bash|PowerShell` and timeout 5; no file under `plugins/` holds an absolute path. Run — expected: FAIL (files missing).

- [ ] **Step 3: Write the files.** README: install the binary first (the one-liner), then the two commands that add the marketplace and install the plugin; enable only one plugin that registers this hook.

- [ ] **Step 4: Live proof**, in an isolated config dir against the local Messages API stub the earlier spikes used (`docs/spikes.md` "PreToolUse contract" names the method): strip host auth variables, load the plugin with `--plugin-dir`, script one refused Bash command and one harmless one. Proof: the stub's request log shows the deny reason for the first and a canary file for the second; then remove `shellwise` from that run's `PATH` and show the harmless command still runs (fail open). Record the three results in `docs/spikes.md` under a new heading "Plugin hook with a bare command name". Never run `claude plugin validate` or any `claude` command against the real config dir.

- [ ] **Step 5: Commit** `feat(plugin): add a Claude Code plugin and marketplace manifest`.

### Task 6: Release and CI workflows

**Files:**
- Modify: `.github/workflows/release.yml`, `.github/workflows/ci.yml`

- [ ] **Step 1: `release.yml`** — add matrix rows `x86_64-unknown-linux-musl` (ubuntu-latest, `musl-tools` installed) and `aarch64-unknown-linux-musl` (the hosted ARM Linux runner label current at build time, read from the runner-images README; `musl-tools` installed). The Package step is unchanged, so the names follow the existing pattern. In `publish`, copy `install.sh` and `install.ps1` into `dist` before `sha256sum`, and extend the sum line to cover them. The four existing rows are not edited.
- [ ] **Step 2: `ci.yml`** — add `macos-latest` to a new job `install-scripts` (matrix windows, ubuntu, macos) that runs `cargo test --features testhooks --test install_scripts --test update`; add a `shellcheck install.sh` step on ubuntu. Add the two musl targets to the `build` job matrix so a `workflow_dispatch` run proves they compile.
- [ ] **Step 3: Verify** with a `workflow_dispatch` CI run on the branch after pushing (one bounded `gh run watch`); the musl build artifacts exist; download the x64 musl binary's size and `file` output from the run log into the PR body. Do not create a tag.
- [ ] **Step 4: Commit** `ci: build musl targets and test the install scripts`.

### Task 7: Live run on Codex CLI

**Files:**
- Modify: `docs/spikes.md` (new section "Generic hook on Codex CLI"), `docs/agent-setup.md` (flip the Codex row to `tested` only when every check below passed)

- [ ] **Step 1:** In a scratch `CODEX_HOME` (never the user's `~/.codex`), write a `hooks.json` with a `PreToolUse` entry for `shellwise hook generic --shell pwsh` (full path of the built binary). Find from `codex --help` and the hooks documentation how a non-interactive run trusts a hook for one invocation; if the run needs a model call the owner's login in that scratch home does not have, stop and report BLOCKED with the exact message: the row then stays `from the host's documentation`.
- [ ] **Step 2:** Run one refused command and one harmless one through Codex. Record: did the refused one not run (canary file absent), what text the model received, did the harmless one run, and what happens with the binary path pointed at a missing file.
- [ ] **Step 3: Commit** `docs(spikes): record the generic hook on Codex CLI`.

### Task 8: README and changelog

**Files:**
- Modify: `README.md` (sections "Install", "Claude Code hook", "Use"), `CHANGELOG.md` (only after `fix/loop-bound-behind-wrappers` is merged into `develop` and merged into this branch)

- [ ] **Step 1: Rewrite "Install"** in this order, short enough to paste into a reply: the two one-liners; `shellwise agent-setup` ("paste the output to your agent"); the plugin commands for Claude Code; `shellwise update`; then "Other ways": the release archives table (kept, with the two musl rows), `cargo install --git https://github.com/Borcioo/shellwise`, build from source. State that the scripts verify the archive against `SHA256SUMS`, and how to uninstall (delete the binary; remove the hook entry). Keep the manual Claude Code hook block under "Claude Code hook" as the alternative to the plugin. Add `hook generic`, `update` and `agent-setup` to "Use" with their exit codes.
- [ ] **Step 2: `CHANGELOG.md`** — under `## [Unreleased]`, `### Added`: the install scripts, `update`, `agent-setup`, `hook generic`, the plugin, the two musl assets.
- [ ] **Step 3: Run the full gate** in the background and read its status file; then `python -I scripts/leak_check.py` is part of it: the new files must pass the denylist.
- [ ] **Step 4: Commit** `docs: describe the one-line install, update and agent setup`, push, open the PR to `develop`.

## Order

Tasks 1 and 2 have no inputs and disjoint files. Task 3 needs task 2's scripts. Task 4 needs task 1's CLI name and task 3's. Task 5 needs task 3 (`--notify`). Task 6 needs tasks 2 and 3 (their test files). Task 7 needs task 1 and 4. Task 8 is last. `src/main.rs` is edited by tasks 1, 3 and 4: they run one after another.
