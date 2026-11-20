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

## Other files

| File | Known answer |
|---|---|
| `rule_map.toml` | the fixture's map: three baseline-guard ids, `fixture-unlanded` (maps to a rule that never lands), one parity exception |
| `rule_map_own_line.toml` | the same with `parse-error` as the own-line rule |
| `known.jsonl` | 1 checked (row 4), 1 not landed (row 9), 2 that expect none, of which row 5 is denied |
| `known_miss.jsonl` | row 1 expects `parse-error`: exit 1 |
| `known_not_landed.jsonl` | 0 checked: exit 1 |
| `known_unmapped.jsonl`, `baseline_unmapped.jsonl` | an id the map lacks: exit 1 |
| `known_absent.jsonl` | a checked row missing from the corpus: exit 1 |
| `known_default_map.jsonl` | row 4 under the compiled-in map: checked, passes |
| `corpus_empty.jsonl`, `corpus_bash_only.jsonl` | 0 rows, 0 PowerShell rows: exit 1 |
| `baseline_unjoined.jsonl` | 0 rows joined: exit 1 |
| `old_dump.tsv` | `--diff`: row 1 down (break → ok), row 3 up (ok → break), row 2 unchanged, 7 rows missing in it |
