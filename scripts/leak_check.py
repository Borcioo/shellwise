"""Leak check for the public repo: this machine's real paths, private terms and mined commands.

Usage: python -I scripts/leak_check.py

Reads every file git tracks or would add (`git ls-files --cached --others --exclude-standard`) and
every commit message on HEAD, and fails on:
  - this machine's real paths in any spelling (`X:\\a\\b`, `X:/a/b`, `/x/a/b`, `/mnt/x/a/b`, escaped
    backslashes): the user profile, the repo's own path, the corpus folder;
  - the user name as a word;
  - any profile path (`<drive>:\\Users\\<name>`, `/home/<name>`, `/mnt/<d>/Users/<name>`); synthetic
    paths such as `C:\\x` pass;
  - a term (one regex per line, `#` comments) from the file `$SHELLWISE_DENYLIST`;
  - a `command` in `tests/cases/*.toml` that equals a command in `$SHELLWISE_CORPUS/corpus.jsonl`.

It fails on an unset variable, a missing input, 0 files read, and when its positive controls are not
caught (`tests/leak_fixture/`, planted real-path spellings, a literal denylist term). Findings name
the file, line and kind, never the private text. Last line: `leak_check: PASS|FAIL <counts>`.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = "tests/leak_fixture/"
# A fixture corpus and cases for the case-check control (not path fixtures).
FIXTURE_CASES = "tests/leak_fixture/cases/"
MIN_CHECKED_LENGTH = 40
SEP = r"[\\/]+"
# A real profile name; placeholders (`<name>`, `…`, `...`, `%USERNAME%`, `$env:USERNAME`) do not count.
NAME_CHARS = r"(?![.])[^\\/\s'\"`<>|:*?()\[\]{},;…%$]+"
PROFILE_PATHS = [
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:" + SEP + "users" + SEP + NAME_CHARS, re.I),
    re.compile(r"(?<![A-Za-z0-9:])/(?:mnt/)?[a-z]/users/" + NAME_CHARS, re.I),
    re.compile(r"(?<![A-Za-z0-9.~])/home/" + NAME_CHARS),
]


class InputError(Exception):
    pass


def fold(text):
    """Text without diacritics, so a term matches every spelling of a name (matching ignores case)."""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def path_pattern(path):
    """A regex for every spelling of an absolute Windows path, or None for a path we cannot split."""
    m = re.match(r"^([A-Za-z]):[\\/]+(.+?)[\\/]*$", path)
    if not m:
        return None
    drive = m.group(1).lower()
    parts = [re.escape(p) for p in re.split(r"[\\/]+", m.group(2)) if p]
    prefix = r"(?:%s:|/%s|/mnt/%s)" % (drive, drive, drive)
    return re.compile(prefix + SEP + SEP.join(parts) + r"(?![A-Za-z0-9])", re.I)


def spellings(path):
    """Concrete spellings of a Windows path, for the planted control."""
    drive, rest = path[0], path[3:].replace("/", "\\").strip("\\")
    fwd = rest.replace("\\", "/")
    return [
        "%s:\\%s" % (drive, rest),
        "%s:/%s" % (drive.lower(), fwd),
        "%s:\\\\%s" % (drive, rest.replace("\\", "\\\\")),
        "/%s/%s" % (drive.lower(), fwd),
        "/mnt/%s/%s" % (drive.lower(), fwd),
    ]


def git(*args):
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True)
    return out.stdout.decode("utf-8", "replace")


def require_env(name):
    value = os.environ.get(name, "")
    if not value:
        raise InputError("%s is not set" % name)
    return value


def load_terms(path):
    if not os.path.isfile(path):
        raise InputError("SHELLWISE_DENYLIST file not found")
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    terms = []
    for k, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            terms.append((line, re.compile(fold(line), re.I)))
        except re.error:
            raise InputError("SHELLWISE_DENYLIST line %d is not a valid regex" % k)
    if not terms:
        raise InputError("SHELLWISE_DENYLIST holds no terms")
    return terms


def load_corpus(folder):
    path = os.path.join(folder, "corpus.jsonl")
    if not os.path.isfile(path):
        raise InputError("corpus.jsonl not found in %s" % ("SHELLWISE_CORPUS" if folder != FIXTURE_CASES else FIXTURE_CASES))
    commands = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                command = json.loads(line).get("command")
                if isinstance(command, str):
                    commands.add(command)
    if not commands:
        raise InputError("corpus.jsonl holds no commands")
    return commands


def is_checked(command):
    """Only a command that could identify a corpus row is checked: 40+ characters or a path."""
    return len(command) >= MIN_CHECKED_LENGTH or "/" in command or "\\" in command


def case_leaks(cases, corpus):
    """(file, row number) of each checked case command that equals a corpus command."""
    return [(rel, k) for rel, k, cmd in cases if is_checked(cmd) and cmd in corpus]


def case_commands(files, folder="tests/cases/"):
    """(file, row number, command) for every `command` string in <folder>*.toml."""
    out = []
    for rel in files:
        if not (rel.startswith(folder) and rel.endswith(".toml")):
            continue
        with open(os.path.join(ROOT, rel), "rb") as f:
            data = tomllib.load(f)
        stack, k = [data], 0
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "command" and isinstance(value, str):
                        k += 1
                        out.append((rel, k, value))
                    else:
                        stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
    return out


class Matchers:
    def __init__(self, roots, user_names, terms):
        self.paths = [p for p in (path_pattern(r) for r in roots) if p]
        self.users = [re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(n), re.I) for n in user_names]
        self.terms = terms

    def findings(self, text):
        """(line number, kind) for each finding in text."""
        out = []
        folded = fold(text)
        for number, (line, fline) in enumerate(zip(text.split("\n"), folded.split("\n")), 1):
            kinds = []
            if any(p.search(line) for p in self.paths):
                kinds.append("machine path")
            if any(u.search(line) for u in self.users):
                kinds.append("user name")
            if any(p.search(line) for p in PROFILE_PATHS):
                kinds.append("profile path")
            for k, (_, term) in enumerate(self.terms, 1):
                if term.search(fline):
                    kinds.append("denylist term #%d" % k)
            out.extend((number, kind) for kind in kinds)
        return out


def read_text(rel):
    with open(os.path.join(ROOT, rel), "rb") as f:
        return f.read().decode("utf-8", "replace")


def case_control(files):
    """Problems with the case-check control: in the fixture, the long command and the short one
    with a path must be flagged, the short one without a path must pass."""
    try:
        corpus = load_corpus(os.path.join(ROOT, FIXTURE_CASES))
    except InputError as e:
        return ["case fixture: %s" % e]
    cases = case_commands(files, FIXTURE_CASES)
    flagged = {cmd for rel, k, cmd in cases if (rel, k) in set(case_leaks(cases, corpus))}
    # The expected answer comes from the fixture rows, never from is_checked.
    with open(os.path.join(ROOT, FIXTURE_CASES, "cases.toml"), "rb") as f:
        rows = tomllib.load(f).get("case", [])
    want = {r["command"] for r in rows if r.get("expect_flagged") is True}
    keep = {r["command"] for r in rows if r.get("expect_flagged") is False}
    if not want or not keep:
        return ["case fixture needs rows with expect_flagged = true and false"]
    problems = []
    if want - flagged:
        problems.append("case fixture: %d expected row(s) not flagged" % len(want - flagged))
    if keep & flagged:
        problems.append("case fixture: %d short row(s) flagged" % len(keep & flagged))
    return problems


def controls(matchers, roots, terms, fixture_files):
    """Problems with the positive controls; each must be caught."""
    problems = []
    if not fixture_files:
        problems.append("no fixture in %s" % FIXTURE_DIR)
    for rel in fixture_files:
        if not matchers.findings(read_text(rel)):
            problems.append("fixture %s not caught" % rel)
    for root in roots:
        for k, s in enumerate(spellings(root), 1):
            if not any(kind == "machine path" for _, kind in matchers.findings("x %s\\sub y" % s)):
                problems.append("planted spelling %d of a real path not caught" % k)
    literal = [t for t, _ in terms if re.fullmatch(r"[A-Za-z0-9_-]+", t)]
    if not literal:
        problems.append("no literal denylist term to plant")
    elif not any(kind.startswith("denylist") for _, kind in matchers.findings("x %s y" % literal[0].upper())):
        problems.append("planted denylist term not caught")
    return problems


def main():
    try:
        corpus_dir = require_env("SHELLWISE_CORPUS")
        terms = load_terms(require_env("SHELLWISE_DENYLIST"))
        profile = require_env("USERPROFILE") if os.name == "nt" else require_env("HOME")
        corpus = load_corpus(corpus_dir)
    except InputError as e:
        print("leak_check: FAIL input: %s" % e)
        return 2

    common = os.path.abspath(os.path.join(ROOT, git("rev-parse", "--git-common-dir").strip()))
    roots = sorted({os.path.abspath(p) for p in (profile, os.path.dirname(common), ROOT, corpus_dir)})
    roots = [r for r in roots if re.match(r"^[A-Za-z]:", r)]
    user_names = sorted({n for n in (os.environ.get("USERNAME", ""), os.path.basename(profile)) if n})
    matchers = Matchers(roots, user_names, terms)

    listed = [f for f in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0") if f]
    files = [f for f in listed if os.path.isfile(os.path.join(ROOT, f))]
    fixture_files = [f for f in files if f.startswith(FIXTURE_DIR) and not f.startswith(FIXTURE_CASES)]
    scanned = [f for f in files if not f.startswith(FIXTURE_DIR)]

    leaks = []
    for rel in scanned:
        leaks += ["%s:%d: %s" % (rel, n, kind) for n, kind in matchers.findings(read_text(rel))]
    commits = [c for c in git("log", "--format=%H%n%B%x00").split("\0") if c.strip()]
    for c in commits:
        sha, _, body = c.strip().partition("\n")
        leaks += ["commit %s line %d: %s" % (sha[:9], n, kind) for n, kind in matchers.findings(body)]
    cases = case_commands(scanned)
    leaks += ["%s: command #%d is a corpus command" % (rel, k) for rel, k in case_leaks(cases, corpus)]

    problems = controls(matchers, roots, terms, fixture_files) + case_control(files)
    if not scanned:
        problems.append("0 files read")
    counts = "files=%d commits=%d terms=%d cases=%d corpus=%d" % (
        len(scanned), len(commits), len(terms), len(cases), len(corpus))
    for line in leaks:
        print("LEAK " + line)
    for line in problems:
        print("CONTROL " + line)
    if leaks or problems:
        print("leak_check: FAIL %s leaks=%d control_problems=%d" % (counts, len(leaks), len(problems)))
        return 1
    print("leak_check: PASS %s" % counts)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
