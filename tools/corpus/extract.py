"""Extract Bash/PowerShell tool calls and their results from Claude Code transcripts into JSONL.

Usage: python -I tools/corpus/extract.py --projects <dir> [--days 30] --out <file>

<dir> is a Claude Code projects folder: <dir>/<project>/<session>.jsonl and, below each session,
subagents/*.jsonl. Each output row is one call:
  {"id", "session", "ts", "tool", "command", "cwd", "cli_version", "label", "denied_by",
   "destructive", "error_excerpt"}
label: ok | failed | denied-hook | denied-permission. A stats file (<out stem>.stats.json) holds
the read counts. Exits 1 when it reads no transcript or writes no row. Stdlib only.
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import re
import sys
import time
import tomllib
from datetime import datetime, timezone

TABLE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                     "data", "destructive.toml")
SHELLS = {"bash", "pwsh", "cmd"}
TOOL_SHELL = {"Bash": "bash", "PowerShell": "pwsh"}
EXCERPT = 300

# A PreToolUse hook that denied the call: "PreToolUse:<Tool> hook error: <hook>: <reason>".
HOOK_RE = re.compile(r"\s*(?:Error:\s*)?PreToolUse:\w+ hook error:?\s*(?:([A-Za-z][\w.-]{0,40}):)?")
# Denials Claude Code reports without a toolDenialKind flag (seen in transcripts), by the kind they belong to.
UNFLAGGED_DENIALS = (
    (re.compile(r"\s*(?:Error:\s*)?The user doesn't want to"), "user-rejected"),
    (re.compile(r"\s*(?:Error:\s*)?Permission for this action was denied by the Claude Code auto mode"),
     "automode-blocked"),
    (re.compile(r"\s*(?:Error:\s*)?(Permission to use \w+ denied|Permission for this command was denied|"
                r"Remove-Item on system path .* is blocked)"), "permission-rule"),
    (re.compile(r"\s*(?:Error:\s*)?<tool_use_error>"), "tool-validation"),
    (re.compile(r"\s*(?:Error:\s*)?This agent is isolated in the worktree"), "worktree-isolation"),
)


# ------------------------------------------------------------------------------------------------
# Destructive matcher (independent of shellwise: names from data/destructive.toml on raw text)
# ------------------------------------------------------------------------------------------------

def load_table(path=TABLE):
    """The [[command]] rows of the table, validated: names, shells and requires_any are lists of strings."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    rows = data.get("command")
    if set(data) != {"command"} or not isinstance(rows, list) or not rows:
        raise ValueError("%s: expected only [[command]] rows" % path)
    table = []
    for k, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"names", "shells", "requires_any"}:
            raise ValueError("%s: row %d needs exactly names, shells, requires_any" % (path, k + 1))
        for key in ("names", "shells", "requires_any"):
            value = row[key]
            if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                raise ValueError("%s: row %d: %s must be a list of strings" % (path, k + 1, key))
        if not row["names"] or not row["shells"] or not set(row["shells"]) <= SHELLS:
            raise ValueError("%s: row %d: names and shells (%s) must be non-empty" % (path, k + 1, "/".join(sorted(SHELLS))))
        table.append({"names": [n.lower().split() for n in row["names"]], "shells": set(row["shells"]),
                      "requires_any": list(row["requires_any"])})
    return table


SEPARATORS = set("\n;|&(){}")


def segments(text, shell):
    """Simple commands of text as lists of (value, quoted) words: split at ; | & ( ) { } and newlines,
    quotes joined into their word, comments dropped. Lenient: an unclosed quote runs to the end."""
    out, words, cur, quoted = [], [], None, False
    i, n = 0, len(text)

    def end_word():
        nonlocal cur, quoted
        if cur is not None:
            words.append((cur, quoted))
        cur, quoted = None, False

    def end_segment():
        nonlocal words
        end_word()
        if words:
            out.append(words)
        words = []

    while i < n:
        c = text[i]
        if c in " \t\r":
            end_word()
            i += 1
        elif c in SEPARATORS or (c == "`" and shell == "bash"):
            end_segment()
            i += 1
        elif c == "#" and cur is None:
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            cur = (cur or "") + text[i + 1:j]
            quoted = True
            i = j + 1
        elif c == '"':
            j = i + 1
            esc = "`" if shell == "pwsh" else "\\"
            while j < n and text[j] != '"':
                j += 2 if text[j] == esc else 1
            cur = (cur or "") + text[i + 1:min(j, n)]
            quoted = True
            i = j + 1
        elif (c == "\\" and shell == "bash") or (c == "`" and shell == "pwsh"):
            if text.startswith("\n", i + 1) or text.startswith("\r\n", i + 1):
                i += 2 if text[i + 1] == "\n" else 3
                continue
            cur = (cur or "") + text[i + 1:i + 2]
            i += 2
        else:
            cur = (cur or "") + c
            i += 1
    end_segment()
    return out


PREFIX_WORDS = {"sudo", "command", "exec", "nohup", "time", "xargs", "env", "&", "!", "then", "do", "else",
                "elif", "if", "while", "until", "call"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PS_VAR = re.compile(r"^(\[[\w.\[\]]+\])*\$[\w:]+$")
NESTED = {"bash": "bash", "sh": "bash", "pwsh": "pwsh", "powershell": "pwsh", "cmd": "cmd"}
NESTED_FLAG = re.compile(r"^(-[a-z]*c|-command|-c|/c|/k)$", re.I)
GIT_VALUE_OPTS = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}


def base_name(word):
    name = re.split(r"[\\/]", word.lower())[-1]
    return name[:-4] if name.endswith(".exe") else name


def strip_prefix(words):
    k = 0
    while k < len(words):
        v, q = words[k]
        if q:
            break
        if v.lower() in PREFIX_WORDS or ASSIGN.match(v) or (v.startswith("-") and k and words[k - 1][0] == "xargs"):
            k += 1
        elif PS_VAR.match(v) and k + 1 < len(words) and words[k + 1][0] in ("=", "+="):
            k += 2
        elif v.startswith("[") and v.endswith("]") and "::" not in v:   # a cast such as [void]
            k += 1
        else:
            break
    return words[k:]


def flag_matches(entry, word):
    if entry.startswith("--") and len(entry) > 2:
        return word == entry or word.startswith(entry + "=")
    if re.match(r"^-[A-Za-z]$", entry):
        return bool(re.match(r"^-[A-Za-z]*%s[A-Za-z]*$" % entry[1], word))
    if entry.startswith("/"):
        return word.lower() == entry.lower()
    return word == entry


def match_name(name_words, words):
    """The index after the matched name in words, or None. git global options are skipped."""
    if base_name(words[0][0]) != name_words[0]:
        return None
    k = 1
    if name_words[0] == "git":
        while k < len(words) and words[k][0].startswith("-"):
            k += 2 if words[k][0] in GIT_VALUE_OPTS else 1
    for part in name_words[1:]:
        if k >= len(words) or words[k][0].lower() != part:
            return None
        k += 1
    return k


def destructive_hits(table, tool, command, depth=0):
    """[(name, args)] for each simple command of command that the table names; args are the words after the
    name. A nested `bash -c`, `pwsh -Command` or `cmd /c` body is scanned with that shell's rows."""
    shell = TOOL_SHELL.get(tool, tool)
    hits = []
    if not isinstance(command, str) or depth > 4:
        return hits
    for words in segments(command, shell):
        words = strip_prefix(words)
        if not words:
            continue
        nested = NESTED.get(base_name(words[0][0]))
        if nested:
            for k in range(1, len(words)):
                if NESTED_FLAG.match(words[k][0]) and not words[k][1]:
                    body = " ".join(v for v, _ in words[k + 1:])
                    hits += destructive_hits(table, nested, body, depth + 1)
                    break
            continue
        for row in table:
            if shell not in row["shells"]:
                continue
            for name_words in row["names"]:
                end = match_name(name_words, words)
                if end is None:
                    continue
                args = [v for v, _ in words[end:]]
                if not row["requires_any"] or any(flag_matches(e, a) for e in row["requires_any"] for a in args):
                    hits.append((" ".join(name_words), args))
    return hits


def is_destructive(table, tool, command):
    return bool(destructive_hits(table, tool, command))


# ------------------------------------------------------------------------------------------------
# Transcript walk
# ------------------------------------------------------------------------------------------------

def result_text(content):
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str))
    else:
        text = ""
    return text.replace("\r\n", "\n")


def line_origin(o):
    """Where a user line comes from: meta and compact-summary lines quote text and are never a call's result."""
    if o.get("isMeta"):
        return "meta"
    if o.get("isCompactSummary"):
        return "compact-summary"
    turn = o.get("turnOrigin")
    if isinstance(turn, str) and turn not in ("human",):
        return "turn-" + turn
    return "user"


def label_of(text, is_error, denial_kind):
    """(label, denied_by) for a tool result."""
    m = HOOK_RE.match(text)
    if m and is_error:
        return "denied-hook", m.group(1) or "(unnamed)"
    if isinstance(denial_kind, str) and denial_kind:
        return "denied-permission", denial_kind
    if is_error:
        for rx, kind in UNFLAGGED_DENIALS:
            if rx.match(text):
                return "denied-permission", kind
        return "failed", None
    return "ok", None


def parse_ts(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def transcripts(projects, cutoff):
    main = sorted(p for p in glob.glob(os.path.join(projects, "*", "*.jsonl")) if os.path.getmtime(p) >= cutoff)
    sub = sorted(p for p in glob.glob(os.path.join(projects, "*", "**", "subagents", "*.jsonl"), recursive=True)
                 if os.path.getmtime(p) >= cutoff)
    return main, sub


def walk(paths, stats):
    """(calls, results), each keyed by tool_use id: a fork or resume copies earlier lines with their uuid,
    tool_use id and sessionId, so the first copy read is the call."""
    calls, results = {}, {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                stats["lines"] += 1
                try:
                    o = json.loads(line)
                except ValueError:
                    stats["bad_json"] += 1
                    continue
                if not isinstance(o, dict):
                    stats["bad_json"] += 1
                    continue
                msg = o.get("message")
                content = msg.get("content") if isinstance(msg, dict) else None
                if not isinstance(content, list):
                    continue
                if o.get("type") == "assistant":
                    for b in content:
                        if not (isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") in TOOL_SHELL):
                            continue
                        inp = b.get("input")
                        tid = b.get("id")
                        if not isinstance(tid, str) or not isinstance(inp, dict) or not isinstance(inp.get("command"), str):
                            stats["bad_input"] += 1
                            continue
                        if tid in calls:
                            stats["duplicate_calls"] += 1
                            continue
                        calls[tid] = {"tid": tid, "session": o.get("sessionId"), "ts": o.get("timestamp"),
                                      "tool": b["name"], "command": inp["command"], "cwd": o.get("cwd"),
                                      "cli_version": o.get("version")}
                elif o.get("type") == "user":
                    origin = line_origin(o)
                    for b in content:
                        if not (isinstance(b, dict) and b.get("type") == "tool_result"):
                            continue
                        stats["origin " + origin] += 1
                        if origin in ("meta", "compact-summary"):
                            continue
                        tid = b.get("tool_use_id")
                        if isinstance(tid, str) and tid not in results:
                            results[tid] = (result_text(b.get("content")), bool(b.get("is_error")),
                                            o.get("toolDenialKind"))
    return calls, results


def build_rows(calls, results, table, cutoff, stats):
    rows = []
    for call in calls.values():
        tid = call["tid"]
        ts = parse_ts(call["ts"])
        if ts is None or ts < cutoff:
            stats["outside_window"] += 1
            continue
        if tid not in results:
            stats["no_result"] += 1
            continue
        text, is_error, kind = results[tid]
        label, denied_by = label_of(text, is_error, kind)
        rows.append({
            "id": hashlib.sha1(tid.encode("utf-8")).hexdigest()[:12],
            "session": call["session"], "ts": call["ts"], "tool": call["tool"], "command": call["command"],
            "cwd": call["cwd"], "cli_version": call["cli_version"], "label": label, "denied_by": denied_by,
            "destructive": is_destructive(table, call["tool"], call["command"]),
            "error_excerpt": "" if label == "ok" else text[:EXCERPT],
        })
    rows.sort(key=lambda r: (r["ts"], r["id"]))
    return rows


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--projects", required=True)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    cutoff = time.time() - args.days * 86400
    table = load_table()
    main_files, sub_files = transcripts(args.projects, cutoff)
    if not main_files and not sub_files:
        print("FAIL: read 0 transcripts under the projects folder (newer than %d days)" % args.days)
        return 1
    stats = collections.Counter(files_main=len(main_files), files_subagent=len(sub_files))
    calls, results = walk(main_files + sub_files, stats)
    rows = build_rows(calls, results, table, cutoff, stats)
    stats["rows"] = len(rows)
    if not rows:
        print("FAIL: 0 rows from %d transcripts" % (len(main_files) + len(sub_files)))
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    with open(os.path.splitext(args.out)[0] + ".stats.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(dict(sorted(stats.items())), f, indent=1)
        f.write("\n")
    print("rows %d from %d main + %d subagent transcripts; duplicates skipped %d, no result %d, outside window %d"
          % (len(rows), len(main_files), len(sub_files), stats["duplicate_calls"], stats["no_result"],
             stats["outside_window"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
