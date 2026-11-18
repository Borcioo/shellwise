"""Replay baseline-guard over the corpus: the baseline every shellwise rule is measured against.

Usage: python -I tools/corpus/baseline.py --baseline-guard <baseline_guard.py> --corpus <corpus.jsonl>
           --out <baseline.jsonl> [--report <baseline.md>] [--known <known.jsonl>]

Loads baseline_guard.py by path (no copy, no bytecode written next to it) with BASELINE_GUARD unset, and calls
its check() and check_installed() on each row's command and cwd. Commands are never run. Each output row:
  {"id", "full": [rule, ...], "installed": [rule, ...]}  (rules of the deny findings only)
--report writes counts only (no command text, ids or paths). --known writes a known-answer slice:
10 rows baseline-guard denies (different rules) and 10 ok, non-destructive rows, {"id", "expected_rules"}.
Exits 1 when a check fails: 0 rows for a shell, 0 destructive rows, 0 baseline denies, or fewer than
90 % of the baseline-guard hook denies in the corpus replaying to a deny.
"""
import argparse
import collections
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ("Bash", "PowerShell")
LABELS = ("ok", "failed", "denied-hook", "denied-permission")
REPLAY_MIN = 0.90
KNOWN_EACH = 10
# Draft: a target word the shell resolves at run time (variable, substitution, glob, %VAR%, ~).
DYNAMIC = re.compile(r"[$`*?]|%[^%\s]+%|^~")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit("FAIL: cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_guard(path):
    os.environ.pop("BASELINE_GUARD", None)
    return load_module("baseline_guard_baseline", path)


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


def shortfall_cause(row):
    text = row.get("error_excerpt") or ""
    reason = text.split("baseline-guard:", 1)[-1]
    if re.search(r"\bgit\b", reason):
        return "git rule (repository state)"
    if ".bat" in reason or "launcher" in reason:
        return "launcher or environment rule"
    cwd = row.get("cwd")
    if not cwd or not os.path.isdir(cwd):
        return "cwd gone"
    return "rule changed since"


def dynamic_target(table, extract, row):
    for _, args in extract.destructive_hits(table, row["tool"], row["command"]):
        if any(DYNAMIC.search(a) for a in args if not a.startswith("-")):
            return True
    return False


def known_slice(rows, base):
    by_id = {r["id"]: r for r in rows}
    by_rule = collections.defaultdict(list)
    for b in sorted(base, key=lambda b: b["id"]):
        if b["full"]:
            by_rule[b["full"][0]].append(b)
    picked, depth = [], 0
    while len(picked) < KNOWN_EACH and any(len(v) > depth for v in by_rule.values()):
        for rule in sorted(by_rule):
            if len(picked) < KNOWN_EACH and len(by_rule[rule]) > depth:
                picked.append({"id": by_rule[rule][depth]["id"], "expected_rules": by_rule[rule][depth]["full"]})
        depth += 1
    oks = {t: [] for t in TOOLS}
    for b in sorted(base, key=lambda b: b["id"]):
        r = by_id[b["id"]]
        if r["label"] == "ok" and not r["destructive"] and not b["full"] and not b["installed"] and r["tool"] in oks:
            oks[r["tool"]].append(b["id"])
    # half per shell where both have enough, spread evenly over each shell's rows
    want = {t: min(len(oks[t]), KNOWN_EACH // len(TOOLS)) for t in TOOLS}
    for t in TOOLS:
        want[t] = min(len(oks[t]), KNOWN_EACH - sum(want[o] for o in TOOLS if o != t))
    ok_ids = [oks[t][k * len(oks[t]) // want[t]] for t in TOOLS for k in range(want[t])]
    return picked + [{"id": i, "expected_rules": []} for i in ok_ids]


def table_lines(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" if k == 0 else "---:" for k in range(len(header))) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines


def report(rows, base, stats_file, table, extract):
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
    hooks = collections.Counter(r["denied_by"] for r in rows if r["label"] == "denied-hook")
    sg = [r for r in rows if r["label"] == "denied-hook" and r["denied_by"] == "baseline-guard"]
    replayed = [r for r in sg if by_id[r["id"]]["full"] or by_id[r["id"]]["installed"]]
    causes = collections.Counter(shortfall_cause(r) for r in sg if not (by_id[r["id"]]["full"] or by_id[r["id"]]["installed"]))

    failures = []
    for t in TOOLS:
        if not any(r["tool"] == t for r in rows):
            failures.append("FAIL: 0 rows for %s" % t)
    if not sum(destr.values()):
        failures.append("FAIL: 0 destructive rows")
    if not sum(full.values()):
        failures.append("FAIL: 0 baseline denies")
    if not sg:
        failures.append("FAIL: 0 baseline-guard hook denies to replay")
    elif len(replayed) < REPLAY_MIN * len(sg):
        failures.append("FAIL: %d of %d baseline-guard hook denies replay to a deny (%.1f %%, need %d %%); causes: %s"
                        % (len(replayed), len(sg), 100.0 * len(replayed) / len(sg), REPLAY_MIN * 100,
                           ", ".join("%s: %d" % kv for kv in sorted(causes.items(), key=lambda kv: (-kv[1], kv[0])))))

    stats = {}
    if stats_file and os.path.isfile(stats_file):
        with open(stats_file, encoding="utf-8") as f:
            stats = json.load(f)
    L = ["# baseline-guard baseline", "",
         "Counts only, produced by `tools/corpus/baseline.py` over the corpus `tools/corpus/extract.py` writes "
         "(see `tools/corpus/README.md`). `full` is baseline-guard's `check()`, `installed` its `check_installed()` "
         "(the rules the host setup hooks run); only deny findings count.", ""]
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
    L += ["", "## Replay of baseline-guard hook denies", ""]
    if sg:
        L.append("%d of %d rows that baseline-guard denied in the session replay to a deny today (%.1f %%; the run "
                 "needs %d %%)." % (len(replayed), len(sg), 100.0 * len(replayed) / len(sg), REPLAY_MIN * 100))
    if causes:
        L += ["", "Rows that no longer replay, by cause:", ""]
        L += table_lines(["Cause", "Rows"], sorted(causes.items(), key=lambda kv: (-kv[1], kv[0])))
    L.append("")
    return L, failures


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--baseline-guard", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report")
    ap.add_argument("--known")
    args = ap.parse_args(argv)
    sys.dont_write_bytecode = True   # neither the corpus tools nor baseline-guard's folder get a __pycache__
    extract = load_module("corpus_extract", os.path.join(HERE, "extract.py"))
    table = extract.load_table()
    with open(args.corpus, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    if not rows:
        print("FAIL: read 0 rows from the corpus")
        return 1
    guard = load_guard(args.baseline_guard)
    stats = collections.Counter()
    base = replay(guard, rows, stats)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for b in base:
            f.write(json.dumps(b) + "\n")
    lines, failures = report(rows, base, os.path.splitext(args.corpus)[0] + ".stats.json", table, extract)
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
