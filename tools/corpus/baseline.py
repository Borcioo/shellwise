"""Replay the baseline guard over the corpus: the baseline every shellwise rule is measured against.

Usage: python -I tools/corpus/baseline.py --baseline-guard <guard.py> --first-guard <first guard.py>
           --first-guard-date <date> --hook-name <hook name> --off-env <ENV NAME>
           --corpus <corpus.jsonl> --out <baseline.jsonl> [--report <baseline.md>] [--known <known.jsonl>]

The baseline guard is the earlier, rule-per-regex Python guard whose verdicts the bench compares against.
--first-guard is its module as of its first commit (`git log --diff-filter=A`, then
`git show <commit>:<path>`): a hook deny that neither it nor today's version replays is "rule narrowed".
--hook-name is the hook name the guard's deny messages carry (the corpus `denied_by` value extract.py reads
from them); --off-env is the environment variable that switches the guard off.

Loads the guard module by path (no copy, no bytecode written next to it) with --off-env unset, and calls its check() and check_installed() on each row's command and cwd. Commands are never run.
Each output row:
  {"id", "full": [rule, ...], "installed": [rule, ...]}  (rules of the deny findings only)
--report writes counts only (no command text, ids or paths). --known writes a known-answer slice:
10 rows the baseline guard denies (different rules) and 10 ok, non-destructive rows, plus Linux rows up to 2
deny and 2 ok, {"id", "os", "expected_rules"}: `os` comes from the cwd as `shellwise bench` reads it (`row_os`),
and a deny row expects only rules that can fire on its tool and OS (`RUNS_ON`).
Exits 1 when a check fails: 0 rows for a shell, 0 destructive rows, 0 baseline denies, or more than 5 % of
the baseline guard's hook denies that do not replay having no computed cause (target gone, rule narrowed).
--first-guard-date is that first commit's date (`git log --format=%cI`): only rows dated before it can be
"rule narrowed"; "target gone" is for git commands, the rules that read the disk. The rows of git commands
that do not replay are replayed a second time with the disk check neutralised, and both counts are reported.
"""
import argparse
import collections
import contextlib
import importlib.util
import json
import os
import re
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ("Bash", "PowerShell")
LABELS = ("ok", "failed", "denied-hook", "denied-permission")
UNEXPLAINED_MAX = 0.05   # of the baseline guard's hook denies that do not replay
CAUSE_TARGET, CAUSE_NARROWED, CAUSE_UNEXPLAINED = "target gone", "rule narrowed", "unexplained"
EXCERPT = 300            # extract.py's error_excerpt cap
DRIVE_PATH = re.compile(r"(?<![\w])[A-Za-z]:\\[^\s`'\",;|<>()]*")
KNOWN_EACH = 10
KNOWN_LINUX = 2          # Linux deny rows and Linux ok rows the slice holds at least, when the corpus has them
WINDOWS, LINUX = "Windows", "Linux"
DRIVE_CWD = re.compile(r"^[A-Za-z]:[\\/]")
# Where the shellwise rule a baseline guard id maps to can fire: (tools, OSes), from `[runs_on]` in
# rule_map.toml (one line of evidence per rule there; the bench fails on a map key without an entry and on a
# rule that fires outside it). A slice row expects only rules that can fire on its tool and OS. An id not
# listed is taken as Windows-only (the baseline guard is a Windows hook), for both tools.
RULE_MAP = os.path.join(HERE, "rule_map.toml")


def load_runs_on(path):
    with open(path, "rb") as f:
        table = tomllib.load(f)["runs_on"]
    return {rule: (tuple(e["tools"]), tuple(e["os"])) for rule, e in table.items()}


RUNS_ON = load_runs_on(RULE_MAP)
# Draft: a target word the shell resolves at run time (variable, substitution, glob, %VAR%, ~).
DYNAMIC = re.compile(r"[$`*?]|%[^%\s]+%|^~")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit("FAIL: cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_guard(path, name, off_env):
    os.environ.pop(off_env, None)
    return load_module(name, path)


def deny_rules(findings):
    rules = []
    for f in findings or []:
        if getattr(f, "deny", False) is True and f.rule not in rules:
            rules.append(f.rule)
    return rules


def replay(guard, rows, stats):
    out = []
    for k, row in enumerate(rows):
        result = {"id": row["id"]}
        for key, fn in (("full", guard.check), ("installed", guard.check_installed)):
            try:
                result[key] = deny_rules(fn(row["tool"], row["command"], row.get("cwd")))
            except Exception as exc:   # counted and reported: a crash is no "allow"
                stats["errors " + key + " " + type(exc).__name__] += 1
                result[key] = []
        out.append(result)
        if (k + 1) % 20000 == 0:
            print("replayed %d of %d" % (k + 1, len(rows)), file=sys.stderr, flush=True)
    return out


def target_gone(row, hook):
    """True when the folder the rule resolved is gone now: the row's cwd, or a drive path the deny message
    names. A path cut off by the excerpt's end is not read."""
    cwd = row.get("cwd")
    if isinstance(cwd, str) and cwd and not os.path.isdir(cwd):
        return True
    text = row.get("error_excerpt") or ""
    reason = text.split(hook + ":", 1)[-1]
    cut = len(text) >= EXCERPT
    for m in DRIVE_PATH.finditer(reason):
        if cut and m.end() == len(reason):
            continue
        if not os.path.exists(m.group(0).rstrip(".:")):
            return True
    return False


def is_git_row(extract, row):
    """True when a simple command of the row is git: the git rules, and the junction rule behind `git worktree
    remove`, are the baseline guard rules that read the disk."""
    shell = extract.TOOL_SHELL.get(row["tool"], row["tool"])
    return any(extract.base_name(words[0][0]) == "git" for _, words in extract.simple_commands(shell, row["command"]))


@contextlib.contextmanager
def disk_neutralised():
    """Every folder and path exists: the replay with the disk check switched off."""
    real = os.path.isdir, os.path.exists
    os.path.isdir = os.path.exists = lambda path: True
    try:
        yield
    finally:
        os.path.isdir, os.path.exists = real


def replay_neutralised(guard, rows):
    """{id: True} for each row that replays to a deny with the disk neutralised; a call that raises is no deny."""
    found = {}
    with disk_neutralised():
        for row in rows:
            for fn in (guard.check, guard.check_installed):
                try:
                    if deny_rules(fn(row["tool"], row["command"], row.get("cwd"))):
                        found[row["id"]] = True
                except Exception:
                    pass
    return found


def shortfall_cause(extract, row, first_guard, first_date, hook):
    """Why a baseline guard hook deny does not replay today, computed: for a rule that reads the disk (git), the
    target it resolved is gone; for a row dated before the first committed baseline guard, that version does not
    deny it either (the rule was narrowed before that); anything else is unexplained."""
    if is_git_row(extract, row) and target_gone(row, hook):
        return CAUSE_TARGET
    ts = extract.parse_ts(row.get("ts"))
    if ts is None or ts >= first_date:
        return CAUSE_UNEXPLAINED
    try:
        first = deny_rules(first_guard.check(row["tool"], row["command"], row.get("cwd"))) + \
            deny_rules(first_guard.check_installed(row["tool"], row["command"], row.get("cwd")))
    except Exception:
        return CAUSE_UNEXPLAINED
    return CAUSE_UNEXPLAINED if first else CAUSE_NARROWED


def dynamic_target(table, extract, row):
    for _, args in extract.destructive_hits(table, row["tool"], row["command"]):
        if any(DYNAMIC.search(a) for a in args if not a.startswith("-")):
            return True
    return False


def row_os(cwd):
    """The OS a row ran on, from its cwd shape: a copy of `CwdShape` in src/bench.rs (the corpus records no
    platform). Drive and UNC cwds, no cwd and a relative cwd are Windows; any other `/...` cwd, `/mnt/<letter>`
    (WSL) included, is Linux. tests/bench_fixture/cwd_shapes.tsv holds the cases both are tested on."""
    if not isinstance(cwd, str) or not cwd:
        return WINDOWS
    if DRIVE_CWD.match(cwd) or cwd.startswith(("\\\\", "//")):
        return WINDOWS
    return LINUX if cwd.startswith("/") else WINDOWS


def can_fire(rule, tool, os_name):
    tools, oses = RUNS_ON.get(rule, (TOOLS, (WINDOWS,)))
    return tool in tools and os_name in oses


def spread(ids, n):
    """n of ids, spread evenly over them."""
    n = min(n, len(ids))
    return [ids[k * len(ids) // n] for k in range(n)]


def known_slice(rows, base):
    """KNOWN_EACH deny rows over different rules and KNOWN_EACH ok rows, plus Linux rows up to KNOWN_LINUX of each.
    A deny row is a candidate only when every rule it expects can fire on its tool and OS."""
    by_id = {r["id"]: r for r in rows}
    os_of = {r["id"]: row_os(r.get("cwd")) for r in rows}
    ordered = sorted(base, key=lambda b: b["id"])

    def fits(b):
        r = by_id[b["id"]]
        return all(can_fire(rule, r["tool"], os_of[b["id"]]) for rule in b["full"])

    by_rule = collections.defaultdict(list)
    for b in ordered:
        if b["full"] and fits(b):
            by_rule[b["full"][0]].append(b)
    picked, depth = [], 0
    while len(picked) < KNOWN_EACH and any(len(v) > depth for v in by_rule.values()):
        for rule in sorted(by_rule):
            if len(picked) < KNOWN_EACH and len(by_rule[rule]) > depth:
                picked.append(by_rule[rule][depth])
        depth += 1
    # Linux rows, spread over rules, when the round above picked too few.
    taken = {b["id"] for b in picked}
    linux = collections.defaultdict(list)
    for rule in sorted(by_rule):
        linux[rule] = [b for b in by_rule[rule] if os_of[b["id"]] == LINUX and b["id"] not in taken]
    depth = 0
    while sum(os_of[b["id"]] == LINUX for b in picked) < KNOWN_LINUX and any(len(v) > depth for v in linux.values()):
        for rule in sorted(linux):
            if sum(os_of[b["id"]] == LINUX for b in picked) < KNOWN_LINUX and len(linux[rule]) > depth:
                picked.append(linux[rule][depth])
        depth += 1
    oks = {t: [] for t in TOOLS}
    for b in ordered:
        r = by_id[b["id"]]
        if r["label"] == "ok" and not r["destructive"] and not b["full"] and not b["installed"] and r["tool"] in oks:
            oks[r["tool"]].append(b["id"])
    # half per shell where both have enough, spread evenly over each shell's rows
    want = {t: min(len(oks[t]), KNOWN_EACH // len(TOOLS)) for t in TOOLS}
    for t in TOOLS:
        want[t] = min(len(oks[t]), KNOWN_EACH - sum(want[o] for o in TOOLS if o != t))
    ok_ids = [i for t in TOOLS for i in spread(oks[t], want[t])]
    linux_oks = [i for t in TOOLS for i in oks[t] if os_of[i] == LINUX and i not in ok_ids]
    short = KNOWN_LINUX - sum(os_of[i] == LINUX for i in ok_ids)
    if short > 0:
        ok_ids += spread(linux_oks, short)
    return ([{"id": b["id"], "os": os_of[b["id"]], "expected_rules": b["full"]} for b in picked]
            + [{"id": i, "os": os_of[i], "expected_rules": []} for i in ok_ids])


def table_lines(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" if k == 0 else "---:" for k in range(len(header))) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines


def report(rows, base, stats_file, table, extract, first_guard, first_date, neutral, hook):
    by_id = {b["id"]: b for b in base}
    per = collections.Counter((r["label"], r["tool"]) for r in rows)
    destr = collections.Counter(r["tool"] for r in rows if r["destructive"])
    dyn = collections.Counter(r["tool"] for r in rows if r["destructive"] and dynamic_target(table, extract, r))
    full = collections.Counter(rule for b in base for rule in b["full"])
    inst = collections.Counter(rule for b in base for rule in b["installed"])
    deny_by_label = collections.Counter()
    for r in rows:
        b = by_id[r["id"]]
        deny_by_label[(r["label"], "full")] += bool(b["full"])
        deny_by_label[(r["label"], "installed")] += bool(b["installed"])
    hooks = collections.Counter("baseline guard" if r["denied_by"] == hook else "other hook"
                                for r in rows if r["label"] == "denied-hook")
    sg = [r for r in rows if r["label"] == "denied-hook" and r["denied_by"] == hook]
    replayed = [r for r in sg if by_id[r["id"]]["full"] or by_id[r["id"]]["installed"]]
    causes = collections.Counter(shortfall_cause(extract, r, first_guard, first_date, hook) for r in sg
                                 if not (by_id[r["id"]]["full"] or by_id[r["id"]]["installed"]))
    replayed_neutral = len(replayed) + sum(1 for r in sg if r["id"] in neutral)
    missed = len(sg) - len(replayed)

    failures = []
    for t in TOOLS:
        if not any(r["tool"] == t for r in rows):
            failures.append("FAIL: 0 rows for %s" % t)
    if not sum(destr.values()):
        failures.append("FAIL: 0 destructive rows")
    if not sum(full.values()):
        failures.append("FAIL: 0 baseline denies")
    if not sg:
        failures.append("FAIL: 0 baseline guard hook denies to replay")
    elif causes[CAUSE_UNEXPLAINED] > UNEXPLAINED_MAX * missed:
        failures.append("FAIL: %d of %d baseline guard hook denies that do not replay are unexplained (%.1f %%, at most "
                        "%d %%); causes: %s"
                        % (causes[CAUSE_UNEXPLAINED], missed, 100.0 * causes[CAUSE_UNEXPLAINED] / missed,
                           UNEXPLAINED_MAX * 100,
                           ", ".join("%s: %d" % kv for kv in sorted(causes.items(), key=lambda kv: (-kv[1], kv[0])))))

    stats = {}
    if stats_file and os.path.isfile(stats_file):
        with open(stats_file, encoding="utf-8") as f:
            stats = json.load(f)
    L = ["# Baseline guard replay", "",
         "Counts only, produced by `tools/corpus/baseline.py` over the corpus `tools/corpus/extract.py` writes "
         "(see `tools/corpus/README.md`). `full` is the baseline guard's `check()`, `installed` its "
         "`check_installed()` (the rules its hook runs); only deny findings count.", ""]
    if stats:
        L += ["## Corpus read", ""]
        L += table_lines(["Count", "Value"], [(k, stats[k]) for k in (
            "files_main", "files_subagent", "lines", "rows", "duplicate_calls", "no_result", "outside_window",
            "bad_json", "bad_input") if k in stats])
        L.append("")
    L += ["## Rows per label and shell", ""]
    L += table_lines(["Label"] + list(TOOLS) + ["Total"],
                     [(lab,) + tuple(per[(lab, t)] for t in TOOLS) + (sum(per[(lab, t)] for t in TOOLS),) for lab in LABELS]
                     + [("**all**",) + tuple(sum(per[(lab, t)] for lab in LABELS) for t in TOOLS) + (len(rows),)])
    L += ["", "## Destructive rows", "",
          "`destructive` comes from `data/destructive.toml`; a dynamic target is a non-flag word after the "
          "command name holding `$`, a backtick, `*`, `?`, `%VAR%` or a leading `~` (draft regex).", ""]
    L += table_lines(["Shell", "Destructive", "Dynamic target"], [(t, destr[t], dyn[t]) for t in TOOLS])
    L += ["", "## Deny count per rule", ""]
    L += table_lines(["Rule", "Full", "Installed"],
                     [(rule, full[rule], inst[rule]) for rule in sorted(set(full) | set(inst), key=lambda x: (-full[x], -inst[x], x))])
    L += ["", "## Rows with a deny, by label", "",
          "A deny on an `ok` row is a call that ran without the error the rule predicts: a false-positive candidate.", ""]
    L += table_lines(["Label", "Full", "Installed"], [(lab, deny_by_label[(lab, "full")], deny_by_label[(lab, "installed")]) for lab in LABELS])
    L += ["", "## `denied-hook` rows by hook", ""]
    L += table_lines(["Hook", "Rows"], sorted(hooks.items(), key=lambda kv: (-kv[1], kv[0])))
    L += ["", "## Replay of baseline guard hook denies", ""]
    if sg:
        L.append("Rows that the baseline guard denied in the session, replayed today on the real disk: %d of %d (%.1f %%); "
                 "with the disk check neutralised: %d of %d (%.1f %%), where every folder exists and the rows of git "
                 "commands, which read the disk, are replayed a second time. The check is a positive control: each "
                 "row that does not replay on the real disk gets a computed cause, and the run fails when more than "
                 "%d %% of them are unexplained."
                 % (len(replayed), len(sg), 100.0 * len(replayed) / len(sg), replayed_neutral, len(sg),
                    100.0 * replayed_neutral / len(sg), UNEXPLAINED_MAX * 100))
    if missed:
        L += ["", "Rows that no longer replay, by cause: `target gone` = a git command whose cwd, or a drive path "
              "the deny message names, does not exist now; `rule narrowed` = a row dated before the baseline "
              "guard's first commit, which that version does not deny either; anything else is "
              "`unexplained`.", ""]
        L += table_lines(["Cause", "Rows"], [(c, causes[c]) for c in (CAUSE_TARGET, CAUSE_NARROWED, CAUSE_UNEXPLAINED)])
    L.append("")
    return L, failures


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--baseline-guard", required=True, help="the baseline guard's module")
    ap.add_argument("--first-guard", required=True, help="the baseline guard's module as of its first commit")
    ap.add_argument("--first-guard-date", required=True,
                    help="commit date of that first commit (ISO 8601, `git log --format=%%cI`)")
    ap.add_argument("--hook-name", required=True,
                    help="the hook name the guard's deny messages carry (the corpus `denied_by` value)")
    ap.add_argument("--off-env", required=True, help="the environment variable that switches the guard off")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report")
    ap.add_argument("--known")
    args = ap.parse_args(argv)
    sys.dont_write_bytecode = True   # neither the corpus tools nor the guard's folder get a __pycache__
    extract = load_module("corpus_extract", os.path.join(HERE, "extract.py"))
    table = extract.load_table()
    first_date = extract.parse_ts(args.first_guard_date)
    if first_date is None:
        print("FAIL: --first-guard-date is not an ISO 8601 date")
        return 1
    with open(args.corpus, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    if not rows:
        print("FAIL: read 0 rows from the corpus")
        return 1
    guard = load_guard(args.baseline_guard, "baseline_guard", args.off_env)
    first_guard = load_guard(args.first_guard, "baseline_guard_first", args.off_env)
    stats = collections.Counter()
    base = replay(guard, rows, stats)
    by_id = {b["id"]: b for b in base}
    neutral = replay_neutralised(guard, [r for r in rows if r["label"] == "denied-hook" and r["denied_by"] == args.hook_name
                                         and not (by_id[r["id"]]["full"] or by_id[r["id"]]["installed"])
                                         and is_git_row(extract, r)])
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for b in base:
            f.write(json.dumps(b) + "\n")
    lines, failures = report(rows, base, os.path.splitext(args.corpus)[0] + ".stats.json", table, extract,
                             first_guard, first_date, neutral, args.hook_name)
    if stats:
        lines += ["## Replay errors", ""] + table_lines(["Error", "Rows"], sorted(stats.items())) + [""]
        failures.append("FAIL: %d replay calls raised" % sum(stats.values()))
    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
    if args.known:
        known = known_slice(rows, base)
        n_deny = sum(1 for k in known if k["expected_rules"])
        if n_deny < KNOWN_EACH or len(known) - n_deny < KNOWN_EACH:
            failures.append("FAIL: known slice has %d deny and %d ok rows, needs %d each"
                            % (n_deny, len(known) - n_deny, KNOWN_EACH))
        with open(args.known, "w", encoding="utf-8", newline="\n") as f:
            for k in known:
                f.write(json.dumps(k) + "\n")
    print("rows %d, full deny rows %d, installed deny rows %d"
          % (len(rows), sum(1 for b in base if b["full"]), sum(1 for b in base if b["installed"])))
    for line in failures:
        print(line)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
