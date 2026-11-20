"""Writes tests/bench_fixture/*.jsonl and *.tsv (synthetic rows with known answers)."""
import json, os, sys
out = sys.argv[1]
DQ, SQ = chr(0x22), chr(0x27)
D1, D2 = "2026-11-01T10:00:00.000Z", "2026-11-02T10:00:00.000Z"
# id, ts, tool, command, label, destructive, installed
ROWS = [
    ("f00000000001", D1, "Bash", "echo fixture-plain", "ok", False, []),
    ("f00000000002", D2, "PowerShell", "Get-Date -Format fixture", "ok", False, []),
    ("f00000000003", D1, "PowerShell", "Write-Output " + DQ + "fixture-refused", "ok", False, []),
    ("f00000000004", D1, "Bash", "echo " + SQ + "fixture-parity", "ok", False, ["bash-unterminated-quote"]),
    ("f00000000005", D2, "Bash", "echo " + DQ + "fixture-meter", "ok", False, []),
    ("f00000000006", D2, "Bash", "rm -rf " + DQ + "fixture-dir", "ok", True, []),
    ("f00000000007", D1, "PowerShell", "Get-Date ( ; rm -rf fixture-dir", "failed", True, []),
    ("f00000000008", D1, "PowerShell", "Get-Date (", "ok", False, []),
    ("f00000000009", D2, "Bash", "echo fixture-hook", "denied-hook", False, ["bash-too-long"]),
    ("f0000000000a", D2, "Bash", "echo fixture-collapse", "ok", False, ["bash-backslash-collapse"]),
]


def row(r):
    i, ts, tool, cmd, label, destr, _ = r
    return {"id": i, "session": "fixture", "ts": ts, "tool": tool, "command": cmd, "cwd": None,
            "cli_version": "0.0.0", "label": label, "denied_by": None, "destructive": destr,
            "error_excerpt": ""}


def write(name, lines):
    with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
        for l in lines:
            f.write(l + "\n")


def jl(objs):
    return [json.dumps(o, ensure_ascii=True) for o in objs]


write("corpus.jsonl", jl(row(r) for r in ROWS))
write("corpus_bash_only.jsonl", jl(row(r) for r in ROWS if r[2] == "Bash"))
write("corpus_empty.jsonl", [])
write("baseline.jsonl", jl({"id": r[0], "full": r[6], "installed": r[6]} for r in ROWS))
write("baseline_unjoined.jsonl", jl([{"id": "f000000000ff", "full": [], "installed": []}]))
write("baseline_unmapped.jsonl", jl([{"id": "f00000000001", "full": ["fixture-unknown-id"], "installed": ["fixture-unknown-id"]}]))
write("known.jsonl", jl([
    {"id": "f00000000004", "expected_rules": ["bash-unterminated-quote"]},
    {"id": "f00000000009", "expected_rules": ["fixture-unlanded"]},
    {"id": "f00000000001", "expected_rules": []},
    {"id": "f00000000005", "expected_rules": []},
]))
write("known_miss.jsonl", jl([{"id": "f00000000001", "expected_rules": ["bash-unterminated-quote"]}]))
write("known_not_landed.jsonl", jl([
    {"id": "f00000000009", "expected_rules": ["fixture-unlanded"]},
    {"id": "f00000000001", "expected_rules": []},
]))
write("known_unmapped.jsonl", jl([{"id": "f00000000001", "expected_rules": ["fixture-unknown-id"]}]))
write("known_absent.jsonl", jl([{"id": "f000000000ff", "expected_rules": ["bash-unterminated-quote"]}]))
# Row 4 has no cwd, so it replays on Windows: a slice that says Linux is wrong.
write("known_os_mismatch.jsonl", jl([{"id": "f00000000004", "os": "Linux",
                                       "expected_rules": ["bash-unterminated-quote"]}]))
write("known_default_map.jsonl", jl([{"id": "f00000000004", "expected_rules": ["bash-unterminated-quote"]}]))
# Row 5 says "no" although bash refuses its text: the one fabricated answer, so meter 1 and
# parse_kind_false_deny each have a row. Row 4 has no answer on purpose.
write("real_parse.tsv", ["id\trefused\terror_id",
                         "f00000000001\tno\t", "f00000000002\tno\t",
                         "f00000000003\tyes\tTerminatorExpectedAtEndOfString",
                         "f00000000005\tno\t",
                         "f00000000006\tyes\tunexpected EOF"])
write("old_dump.tsv", ["id\tlevel\trules\traw_hit",
                       "f00000000001\tbreak\tparse-error\tno",
                       "f00000000002\tok\t-\tno",
                       "f00000000003\tok\t-\tno"])
# The OS each row replays on comes from its cwd shape; the env is the bench's synthetic one.
BS = chr(0x5C)
WIN_CWD = "C:" + BS + "fixture" + BS + "proj"
UNC_CWD = BS + BS + "fixture-host" + BS + "share" + BS + "proj"
# id, tool, cwd, command
OS_ROWS = [
    ("f000000000b1", "Bash", WIN_CWD, "docker run -v /usr:/x fixture"),
    ("f000000000b2", "Bash", "/fixture/proj", "docker run -v /usr:/x fixture"),
    ("f000000000b5", "PowerShell", UNC_CWD, "Get-Date -Format fixture"),
    ("f000000000b6", "Bash", "/mnt/c/fixture", "echo fixture-wsl"),
]


def os_row(r):
    i, tool, cwd, cmd = r
    return {"id": i, "session": "fixture", "ts": D1, "tool": tool, "command": cmd, "cwd": cwd,
            "cli_version": "0.0.0", "label": "ok", "denied_by": None, "destructive": False,
            "error_excerpt": ""}


ROW4 = row(ROWS[3])
write("corpus_os.jsonl", jl([os_row(r) for r in OS_ROWS] + [ROW4]))
write("baseline_os.jsonl", jl({"id": r[0], "full": [], "installed": []} for r in OS_ROWS))
# The verdicts of the old replay (every row as Windows): only the Linux row …b2 moves.
write("old_dump_os.tsv", ["id\tlevel\trules\traw_hit",
                          "f000000000b1\twarn\tbash-msys-path-mangle\tno",
                          "f000000000b2\twarn\tbash-msys-path-mangle\tno",
                          "f000000000b5\tok\t-\tno",
                          "f000000000b6\tok\t-\tno"])
# Well-formed files that join to no corpus row: each must fail, not report a measured 0.
write("real_parse_unjoined.tsv", ["id\trefused\terror_id", "f000000000ff\tyes\tfixture"])
write("old_dump_unjoined.tsv", ["id\tlevel\trules\traw_hit", "f000000000ff\tok\t-\tno"])
