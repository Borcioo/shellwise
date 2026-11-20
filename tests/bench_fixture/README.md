# bench fixture

Synthetic rows with known answers for `tests/bench.rs`, written by `make_fixture.py`
(`python -I tests/bench_fixture/make_fixture.py tests/bench_fixture`; no corpus text, ids or paths); every command holds a `fixture` word so it matches no corpus row. The answers assume the
rules of Task 22 (`parse-error` and `analysis-incomplete`); a later rule that fires on one of these
commands changes them.

## corpus.jsonl

| Row | Tool | Label | Destructive | Command shape | Verdict | Installed (baseline) | Counts on |
|---|---|---|---|---|---|---|---|
| …01 | Bash | ok | no | plain echo | ok | — | — |
| …02 | PowerShell | ok | no | plain `Get-Date` | ok | — | — |
| …03 | PowerShell | ok | no | unclosed `"` | break `parse-error` | — | refused by the real parser |
| …04 | Bash | ok | no | unclosed `'` | break `parse-error` | bash-unterminated-quote | parity |
| …05 | Bash | ok | no | unclosed `"` | break `parse-error` | — | meter 1 (own line with `rule_map_own_line.toml`) |
| …06 | Bash | ok | yes | delete with an unclosed `"` | break `parse-error` | — | meter 2 |
| …07 | PowerShell | failed | yes | open `(` then a delete | danger (destructive arm), raw hit | — | per rule, failed |
| …08 | PowerShell | ok | no | open `(` | warn `parse-error` | — | per rule, ok warn |
| …09 | Bash | denied-hook | no | plain echo | ok | bash-too-long | parity per rule: allowed, unexplained |
| …0a | Bash | ok | no | plain echo | ok | bash-backslash-collapse | parity per rule: allowed, excepted by `fixture-shape` |

Days: 2. Rows 3–6 are deny kinds.

## real_parse.tsv

Real answers (checked with `tools/corpus/real_parse.ps1`) except row 5: Git Bash refuses its text,
and the file says `no` so that meter 1 and `parse_kind_false_deny` each get one row. Row 4 has no
answer on purpose (`real_parse_missing`, `parse_kind_unmeasured`).

## corpus_os.jsonl, baseline_os.jsonl

The OS each row replays on, from its cwd shape (`each_row_replays_on_the_os_its_cwd_names`), with
row 4 of `corpus.jsonl` (no cwd) so `known.jsonl` checks a row:

| Row | Tool | cwd shape | Command shape | Verdict |
|---|---|---|---|---|
| …b1 | Bash | drive (Windows) | `docker` with a `/usr:` volume | warn `bash-msys-path-mangle` (Git Bash) |
| …b2 | Bash | posix (Linux) | the same | ok (POSIX bash rewrites nothing) |
| …b5 | PowerShell | UNC (Windows) | plain `Get-Date` | ok |
| …b6 | Bash | `/mnt/c` (Linux) | plain echo | ok |

Per OS: Windows 3 (Bash 2, PowerShell 1), Linux 2 (Bash 2). `old_dump_os.tsv` holds the old
replay's verdicts (every row as Windows): with `--diff` only …b2 moves (down, Linux).

## Other files

| File | Known answer |
|---|---|
| `rule_map.toml` | the fixture's map: three baseline-guard ids, `fixture-unlanded` (maps to a rule that never lands), and a `runs_on` entry for each |
| `rule_map_own_line.toml` | the same with `parse-error` as the own-line rule |
| `parity_exceptions.toml` | one exception: `bash-backslash-collapse`, `mapped-silent`, `ok`, expected 1 (row 0a) |

Tests in `tests/bench.rs` that need a cwd that exists on the machine, or rows these files do not hold,
write their corpus, baseline and known slice into their own folder at run time.
| `known.jsonl` | 1 checked (row 4), 1 not landed (row 9), 2 that expect none, of which row 5 is denied |
| `known_miss.jsonl` | row 1 expects `parse-error`: exit 1 |
| `known_not_landed.jsonl` | 0 checked: exit 1 |
| `known_unmapped.jsonl`, `baseline_unmapped.jsonl` | an id the map lacks: exit 1 |
| `known_absent.jsonl` | a checked row missing from the corpus: exit 1 |
| `known_os_mismatch.jsonl` | row 4 (no cwd, so Windows) marked `"os": "Linux"`: exit 1 |
| `cwd_shapes.tsv` | cwd → shape → OS cases, read by `bench::tests` and by `tools/corpus/test_extract.py` (`row_os`) |
| `known_default_map.jsonl` | row 4 under the compiled-in map: checked, passes |
| `corpus_empty.jsonl`, `corpus_bash_only.jsonl` | 0 rows, 0 PowerShell rows: exit 1 |
| `baseline_unjoined.jsonl` | 0 rows joined: exit 1 |
| `real_parse_unjoined.tsv`, `old_dump_unjoined.tsv` | well-formed, but no id is in the corpus: exit 1 (`corpus_empty.jsonl` serves as the empty file for both flags) |
| `old_dump.tsv` | `--diff`: row 1 down (break → ok), row 3 up (ok → break), row 2 unchanged, 7 rows missing in it |
| `corpus_host_os.jsonl`, `baseline_host_os.jsonl` | a Linux `rm -rf /usr` (…c1), a Windows PowerShell row (…c2) and row 4: …c1 is critical on any host |
