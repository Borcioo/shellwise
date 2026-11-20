"""Tests for the corpus extractor and the baseline guard replay.

Run: python -I tools/corpus/test_extract.py
Every fixture is synthetic and built in a temp folder; nothing here reads real transcripts.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(HERE, "extract.py")
BASELINE = os.path.join(HERE, "baseline.py")


def load_extract():
    sys.dont_write_bytecode = True   # a mutant must never load a stale .pyc
    spec = importlib.util.spec_from_file_location("corpus_extract", EXTRACT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def iso(days_ago):
    t = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def run(script, *args, env=None):
    proc = subprocess.run([sys.executable, "-I", script, *args], capture_output=True, text=True,
                          encoding="utf-8", env=env)
    return proc.returncode, proc.stdout.replace("\r\n", "\n"), proc.stderr.replace("\r\n", "\n")


class Transcript:
    """Builds the lines of one transcript file in Claude Code's shape."""

    def __init__(self, session):
        self.session = session
        self.lines = []
        self.n = 0

    def _uuid(self):
        self.n += 1
        return "%s-%04d" % (self.session, self.n)

    def call(self, tid, tool, command, days_ago=1, uuid=None):
        uuid = uuid or self._uuid()
        self.lines.append({
            "type": "assistant", "uuid": uuid, "sessionId": self.session, "timestamp": iso(days_ago),
            "cwd": "/work/repo", "version": "2.1.300", "isSidechain": False,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": tid, "name": tool, "input": {"command": command, "description": "d"}}]},
        })
        return uuid

    def result(self, tid, content, is_error=False, uuid=None, **extra):
        line = {
            "type": "user", "uuid": uuid or self._uuid(), "sessionId": self.session, "timestamp": iso(1),
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid, "content": content, "is_error": is_error}]},
        }
        line.update(extra)
        self.lines.append(line)
        return line["uuid"]

    def raw(self, text):
        self.lines.append(text)

    def write(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            for line in self.lines:
                f.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


HOOK_TEXT = "PreToolUse:PowerShell hook error: fixture-guard: `Remove-Item` here deletes a tree."


def build_projects(root):
    """One known-answer row per label, plus the traps the extractor must get right."""
    main = Transcript("sess-main")
    main.call("t-ok", "Bash", "echo hi")
    main.result("t-ok", "(Bash completed with no output)")
    main.call("t-hook", "PowerShell", "Remove-Item -Recurse x")
    main.result("t-hook", HOOK_TEXT, is_error=True, toolDenialKind="permission-rule")
    main.call("t-perm", "Bash", "rm -rf x")
    main.result("t-perm", "The user doesn't want to proceed with this tool use. The tool use was rejected.",
                is_error=True, toolDenialKind="user-rejected")
    main.call("t-cancel", "Bash", "rmdir y")
    main.result("t-cancel", "The user doesn't want to take this action right now. STOP.", is_error=True,
                toolDenialKind="cancelled")
    main.call("t-perm2", "Bash", "ls")
    main.result("t-perm2", "Permission for this command was denied.", is_error=True)
    # a PreToolUse plugin hook deny reads "Permission to use <Tool> denied by plugin(s) <name>: ..."
    main.call("t-plug", "Bash", "ls -la")
    main.result("t-plug", "Permission to use Bash denied by plugin(s) alpha-guard, beta.hook: no.", is_error=True,
                toolDenialKind="permission-rule")
    main.call("t-plug1", "Bash", "pwd")
    main.result("t-plug1", "Permission to use Bash denied by plugin example-hook: no.", is_error=True)
    # hook text in a result that is not an error is quoted text, not a deny
    main.call("t-quoted", "Bash", "echo quoted")
    main.result("t-quoted", HOOK_TEXT)
    main.call("t-quoted2", "Bash", "echo quoted-plugin")
    main.result("t-quoted2", "Permission to use Bash denied by plugin example-hook: quoted in output")
    main.call("t-fail", "Bash", "false")
    main.result("t-fail", [{"type": "text", "text": "Exit code 1\r\nboom " + "x" * 400}], is_error=True)
    main.call("t-old", "Bash", "echo old", days_ago=40)
    main.result("t-old", "old")
    # a meta line and a compact summary carry tool_result text that is not the call's result
    main.call("t-meta", "PowerShell", "Get-Date")
    main.result("t-meta", HOOK_TEXT, is_error=True, isMeta=True)
    main.result("t-meta", HOOK_TEXT, is_error=True, isCompactSummary=True)
    main.result("t-meta", "Tuesday")
    # wrong shapes: a broken line, content as a string, a tool_use without a command
    main.raw("{not json")
    main.raw(json.dumps({"type": "user", "uuid": "u-str", "sessionId": "sess-main", "message": {"content": "hello"}}))
    main.raw(json.dumps({"type": "assistant", "uuid": "u-nocmd", "sessionId": "sess-main", "timestamp": iso(1),
                         "message": {"content": [{"type": "tool_use", "id": "t-nocmd", "name": "Bash",
                                                  "input": ["not", "a", "dict"]}]}}))
    main.write(os.path.join(root, "proj-a", "sess-main.jsonl"))

    # a resumed session copies the earlier lines (uuids and sessionId kept), then adds its own call
    resumed = Transcript("sess-resumed")
    resumed.lines = [dict(line) for line in main.lines if isinstance(line, dict)][:2]
    resumed.call("t-new", "PowerShell", "git status")
    resumed.result("t-new", "On branch develop")
    resumed.write(os.path.join(root, "proj-a", "sess-resumed.jsonl"))

    sub = Transcript("sess-main")
    sub.call("t-sub", "PowerShell", "git reset --hard")
    sub.result("t-sub", "HEAD is now at abc1234 msg")
    sub.write(os.path.join(root, "proj-a", "sess-main", "subagents", "agent-1.jsonl"))


class ExtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.projects = os.path.join(cls.tmp.name, "projects")
        build_projects(cls.projects)
        cls.out = os.path.join(cls.tmp.name, "corpus.jsonl")
        cls.code, cls.stdout, cls.stderr = run(EXTRACT, "--projects", cls.projects, "--days", "30", "--out", cls.out)
        cls.rows = {}
        if cls.code == 0:
            with open(cls.out, encoding="utf-8") as f:
                for line in f:
                    row = json.loads(line)
                    cls.rows.setdefault(row["command"], []).append(row)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def row(self, command):
        self.assertEqual(self.code, 0, self.stderr)
        rows = self.rows.get(command, [])
        self.assertEqual(len(rows), 1, "rows for %r: %r" % (command, rows))
        return rows[0]

    def test_labels_one_known_answer_each(self):
        cases = [
            ("echo hi", "ok", None),
            ("Remove-Item -Recurse x", "denied-hook", "fixture-guard"),
            ("rm -rf x", "denied-permission", "user-rejected"),
            ("rmdir y", "denied-permission", "cancelled"),
            ("ls", "denied-permission", "permission-rule"),
            ("ls -la", "denied-hook", "alpha-guard"),
            ("pwd", "denied-hook", "example-hook"),
            ("echo quoted", "ok", None),
            ("echo quoted-plugin", "ok", None),
            ("false", "failed", None),
            ("git reset --hard", "ok", None),
        ]
        for command, label, denied_by in cases:
            with self.subTest(command=command):
                row = self.row(command)
                self.assertEqual(row["label"], label)
                self.assertEqual(row["denied_by"], denied_by)

    def test_row_fields(self):
        row = self.row("false")
        self.assertEqual(set(row), {"id", "session", "ts", "tool", "command", "cwd", "cli_version", "label",
                                    "denied_by", "destructive", "error_excerpt"})
        self.assertEqual((row["session"], row["tool"], row["cwd"], row["cli_version"]),
                         ("sess-main", "Bash", "/work/repo", "2.1.300"))
        self.assertTrue(row["error_excerpt"].startswith("Exit code 1\nboom "), row["error_excerpt"][:30])
        self.assertLessEqual(len(row["error_excerpt"]), 300)
        self.assertEqual(self.row("echo hi")["error_excerpt"], "")

    def test_subagent_transcripts_are_read(self):
        self.assertEqual(self.row("git reset --hard")["tool"], "PowerShell")

    def test_resumed_copy_counted_once(self):
        self.assertEqual(self.row("echo hi")["session"], "sess-main")
        self.assertEqual(self.row("git status")["session"], "sess-resumed")

    def test_meta_and_compact_lines_are_not_results(self):
        self.assertEqual(self.row("Get-Date")["label"], "ok")

    def test_days_cutoff(self):
        self.assertEqual(self.code, 0, self.stderr)
        self.assertNotIn("echo old", self.rows)

    def test_bad_lines_skipped(self):
        self.assertEqual(self.code, 0, self.stderr)
        self.assertEqual(sum(len(v) for v in self.rows.values()), 13, sorted(self.rows))

    def test_destructive_flag_in_rows(self):
        self.assertTrue(self.row("rm -rf x")["destructive"])
        self.assertFalse(self.row("echo hi")["destructive"])

    def test_zero_transcripts_fails(self):
        with tempfile.TemporaryDirectory() as empty:
            code, out, err = run(EXTRACT, "--projects", empty, "--days", "30", "--out", os.path.join(empty, "c.jsonl"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL: read 0 transcripts", out + err)

    def test_zero_rows_fails(self):
        with tempfile.TemporaryDirectory() as root:
            t = Transcript("sess-empty")
            t.call("t-orphan", "Bash", "echo no result")   # a call whose result never arrived
            t.write(os.path.join(root, "proj", "sess-empty.jsonl"))
            code, out, err = run(EXTRACT, "--projects", root, "--days", "30", "--out", os.path.join(root, "c.jsonl"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 0 rows from 1 transcripts", out + err)


class DestructiveTests(unittest.TestCase):
    def test_table(self):
        ex = load_extract()
        table = ex.load_table()
        cases = [
            ("PowerShell", "Remove-Item -Recurse x", True),
            ("Bash", "rm -rf x", True),
            ("Bash", "git reset --hard", True),
            ("PowerShell", "git clean -fd", True),
            ("Bash", "git checkout -- f", True),
            ("PowerShell", "Get-ChildItem x | Remove-Item -Force", True),
            ("PowerShell", "REMOVE-ITEM x", True),
            ("Bash", "cd /x && rm a.txt", True),
            ("Bash", "git -C /x reset --hard HEAD~1", True),
            ("PowerShell", "[IO.Directory]::Delete($p, $true)", True),
            ("PowerShell", "cmd /c rd /s /q x", True),
            ("PowerShell", "robocopy src dst /MIR", True),
            ("Bash", "git restore f", True),
            ("PowerShell", "git worktree remove x", True),
            ("Bash", "git stash drop", True),
            ("Bash", "sudo rm -rf x", True),
            ("PowerShell", "$null = [IO.File]::Delete($f)", True),
            ("Bash", "bash -c 'rm -rf x'", True),
            ("PowerShell", "robocopy src dst /E", False),
            ("Bash", "del x", False),
            ("Bash", "rg rm", False),
            ("Bash", "git reset --soft HEAD~1", False),
            ("Bash", "git clean -n", False),
            ("Bash", "git checkout develop", False),
            ("Bash", 'git commit -m "rm old file"', False),
            ("PowerShell", "Get-Item x", False),
            # find: -delete, and the command an -exec/-execdir/-ok/-okdir clause runs
            ("Bash", "find . -name x -delete", True),
            ("Bash", "find . -name x -print", False),
            ("Bash", "find . -exec rm -rf {} +", True),
            ("Bash", "find . -execdir rm {} \\;", True),
            ("Bash", "find . -ok rm {} \\;", True),
            ("Bash", "find . -okdir rm {} \\;", True),
            ("Bash", "find . -exec grep x {} +", False),
            ("Bash", "find . -exec git clean -f '{}' \\; -n", True),   # the clause ends at \; so -n is find's
            ("Bash", "find . -exec sh -c 'rm -rf x' \\;", True),
            # Git Bash spells cmd's switches with a doubled slash
            ("Bash", "cmd //c rd x", True),
            ("Bash", "cmd //k del x", True),
            ("Bash", "robocopy a b //MIR", True),
            ("Bash", "robocopy a b //E", False),
            # git switch discards uncommitted work only with a force flag
            ("Bash", "git switch -f x", True),
            ("Bash", "git switch --force x", True),
            ("Bash", "git switch --discard-changes x", True),
            ("Bash", "git switch x", False),
            # unless_any: a dry run or an index-only restore is not destructive
            ("Bash", "git clean -fn", False),
            ("Bash", "git clean -f --dry-run", False),
            ("Bash", "git clean -fd", True),
            ("Bash", "git restore --staged f", False),
            ("Bash", "git restore -S f", False),
            ("Bash", "git restore --staged --worktree f", True),
            ("Bash", "git restore -SW f", True),
            ("Bash", "git restore f", True),
            # heredoc bodies are text; the command line around them is not
            ("Bash", "cat <<EOF\nrm -rf x\nEOF\n", False),
            ("Bash", "cat <<'EOF'\nrm -rf x\nEOF\n", False),
            ("Bash", 'cat <<"EOF"\nrm -rf x\nEOF\n', False),
            ("Bash", "cat <<-EOF\n\trm -rf x\n\tEOF\n", False),
            ("Bash", "cat <<-EOF\n\tbody\n\tEOF\nrm x\n", True),
            # a body a shell (or ssh) runs is scanned as that shell's script; a file's content is not
            ("Bash", "bash <<'EOF'\nrm -rf x\nEOF\n", True),
            ("Bash", "sudo sh <<EOF\nrm -rf x\nEOF\n", True),
            ("Bash", "zsh <<EOF\nrm x\nEOF\n", True),
            ("Bash", "ssh host <<EOF\nrm -rf x\nEOF\n", True),
            ("Bash", "cmd <<EOF\ndel x\nEOF\n", True),
            ("Bash", "bash <<'EOF'\necho hi\nEOF\n", False),
            ("Bash", "cat > x.sh <<'EOF'\nrm -rf x\nEOF\n", False),
            ("PowerShell", "@'\nRemove-Item x\n'@ | pwsh -Command -", True),
            ("PowerShell", "@\"\nRemove-Item x\n\"@ | powershell -Command -", True),
            ("PowerShell", "@'\nrm -rf x\n'@ | bash", True),
            ("PowerShell", "@'\nrm -rf x\n'@ | sh", True),
            ("PowerShell", "@'\nRemove-Item x\n'@ | Set-Content f", False),
            ("Bash", "cat <<EOF | rm x\nbody\nEOF\n", True),
            ("Bash", "cat <<EOF\nbody\nEOF\nrm x\n", True),
            # PowerShell here-strings: an apostrophe inside @'...'@ does not close it; only a marker at column 0 does
            ("PowerShell", "$x = @'\nit's a note\nrm -rf x\n'@", False),
            ("PowerShell", "$x = @\"\nrm -rf x\n\"@", False),
            ("PowerShell", "$x = @'\nsay '@ now\nrm -rf x\n'@", False),
            ("PowerShell", "$x = @'\nrm -rf x\n'@\nRemove-Item y", True),
        ]
        for tool, command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(ex.is_destructive(table, tool, command), expected)

    def test_table_schema_is_checked(self):
        ex = load_extract()
        for bad in ('[[command]]\nnames = "rm"\nshells = ["bash"]\nrequires_any = []\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["zsh"]\nrequires_any = []\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["bash"]\nrequires_any = 3\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["bash"]\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["bash"]\nrequires_any = []\nunless_any = "-n"\n'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "t.toml")
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(bad)
                with self.assertRaises(ValueError):
                    ex.load_table(path)

    def test_unless_any_is_optional(self):
        ex = load_extract()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.toml")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write('[[command]]\nnames = ["rm"]\nshells = ["bash"]\nrequires_any = []\nunless_any = ["-n"]\n\n'
                        '[[command]]\nnames = ["rmdir"]\nshells = ["bash"]\nrequires_any = []\n')
            table = ex.load_table(path)
        self.assertEqual([r["unless_any"] for r in table], [["-n"], []])


def load_baseline():
    """baseline.py as a module, no bytecode written next to it."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("corpus_baseline", BASELINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The fake guard's hook name in its deny messages and its off switch (--hook-name, --off-env).
GUARD_HOOK, GUARD_OFF_ENV = "fixture-guard", "FIXTURE_GUARD_OFF"
HOOK = "PreToolUse:Bash hook error: %s: " % GUARD_HOOK

FAKE_GUARD = "OFF_ENV = %r\n" % GUARD_OFF_ENV + r'''
import os

class Finding:
    def __init__(self, rule, deny, message):
        self.rule, self.deny, self.message = rule, deny, message

def _rules(cmd, cwd=None):
    if os.environ.get(OFF_ENV):
        return []
    if cmd.startswith(("git disk", "other disk")) and cwd and os.path.isdir(cwd):   # a rule that reads the disk
        return [Finding("git-disk", True, "m")]
    if cmd.startswith("deny-"):
        return [Finding(cmd.split()[0], True, "m"), Finding("note", False, "m")]
    if cmd.startswith("warn"):
        return [Finding("soft", False, "m")]
    return []

def check(tool, cmd, cwd=None):
    return _rules(cmd, cwd)

def check_installed(tool, cmd, cwd=None):
    return [f for f in _rules(cmd, cwd) if f.rule != "deny-full-only"]
'''


# the baseline guard at its first commit: it also denied what is now `old-deny ...`
FAKE_FIRST = FAKE_GUARD.replace('if cmd.startswith("deny-"):', 'if cmd.startswith(("deny-", "old-deny")):')


def corpus_row(i, tool, command, label="ok", denied_by=None, destructive=False, excerpt=""):
    return {"id": "r%03d" % i, "session": "s", "ts": iso(1), "tool": tool, "command": command, "cwd": None,
            "cli_version": "2.1.300", "label": label, "denied_by": denied_by, "destructive": destructive,
            "error_excerpt": excerpt}


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.guard = os.path.join(self.tmp.name, "fake_guard.py")
        with open(self.guard, "w", encoding="utf-8", newline="") as f:
            f.write(FAKE_GUARD)
        self.first = os.path.join(self.tmp.name, "fake_first.py")
        with open(self.first, "w", encoding="utf-8", newline="") as f:
            f.write(FAKE_FIRST)
        self.assertNotEqual(FAKE_FIRST, FAKE_GUARD)
        self.marker = os.path.join(self.tmp.name, "ran.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def corpus(self, rows):
        path = os.path.join(self.tmp.name, "corpus.jsonl")
        with open(path, "w", encoding="utf-8", newline="") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        return path

    def good_rows(self):
        rows = []
        for k in range(10):
            rows.append(corpus_row(len(rows), "Bash", "deny-rule%d x" % k, "denied-hook", GUARD_HOOK))
        rows.append(corpus_row(len(rows), "PowerShell", "deny-full-only y", "failed"))
        for k in range(10):
            rows.append(corpus_row(len(rows), "PowerShell" if k % 2 else "Bash", "echo ok%d" % k))
        rows.append(corpus_row(len(rows), "Bash", "rm -rf $dir", "ok", destructive=True))
        rows.append(corpus_row(len(rows), "PowerShell", "python -c \"open(r'%s','w')\"" % self.marker))
        rows.append(corpus_row(len(rows), "Bash", "warn me"))
        # more rows of one rule, sorted first: the slice must still spread over rules
        rows += [dict(corpus_row(0, "Bash", "deny-rule0 again%d" % k, "failed"), id="a%02d" % k) for k in range(5)]
        return rows

    def baseline(self, rows, extra_env=None, hook_name=GUARD_HOOK):
        env = dict(os.environ, **{GUARD_OFF_ENV: "off"}, **(extra_env or {}))
        out = os.path.join(self.tmp.name, "baseline.jsonl")
        report = os.path.join(self.tmp.name, "baseline.md")
        known = os.path.join(self.tmp.name, "known.jsonl")
        code, stdout, stderr = run(BASELINE, "--baseline-guard", self.guard, "--first-guard", self.first,
                                   "--first-guard-date", iso(10), "--hook-name", hook_name,
                                   "--off-env", GUARD_OFF_ENV, "--corpus", self.corpus(rows),
                                   "--out", out, "--report", report, "--known", known, env=env)
        return code, stdout + stderr, out, report, known

    def read_jsonl(self, path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_replay_rows_and_report(self):
        code, output, out, report, known = self.baseline(self.good_rows())
        self.assertEqual(code, 0, output)
        rows = {r["id"]: r for r in self.read_jsonl(out)}
        self.assertEqual(rows["r000"], {"id": "r000", "full": ["deny-rule0"], "installed": ["deny-rule0"]})
        self.assertEqual(rows["r010"], {"id": "r010", "full": ["deny-full-only"], "installed": []})
        self.assertEqual(rows["r023"], {"id": "r023", "full": [], "installed": []})
        self.assertFalse(os.path.exists(self.marker), "a corpus command ran")
        with open(report, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("| deny-full-only | 1 | 0 |", text)
        self.assertIn("| baseline guard | 10 |", text)
        self.assertIn("10 of 10", text)
        self.assertNotIn("echo ok", text)
        self.assertNotIn("r000", text)

    def test_other_hooks_are_one_count_without_names(self):
        rows = self.good_rows()
        for name in ("plugin-alpha", "plugin-beta"):
            rows.append(corpus_row(len(rows), "Bash", "echo " + name, "denied-hook", name))
        code, output, out, report, known = self.baseline(rows)
        self.assertEqual(code, 0, output)
        with open(report, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("| other hook | 2 |", text)
        self.assertIn("| baseline guard | 10 |", text)
        self.assertNotIn("plugin-alpha", text)

    def test_dynamic_target_count(self):
        code, output, out, report, known = self.baseline(self.good_rows())
        self.assertEqual(code, 0, output)
        with open(report, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("| Bash | 1 | 1 |", text)

    def test_known_slice(self):
        code, output, out, report, known = self.baseline(self.good_rows())
        self.assertEqual(code, 0, output)
        rows = self.read_jsonl(known)
        denies = [r for r in rows if r["expected_rules"]]
        oks = [r for r in rows if not r["expected_rules"]]
        self.assertEqual((len(denies), len(oks)), (10, 10))
        self.assertEqual(len({r["expected_rules"][0] for r in denies}), 10)
        ok_ids = {r["id"] for r in oks}
        self.assertNotIn("r021", ok_ids)  # destructive
        deny_ids = {"r%03d" % k for k in range(11)} | {"a%02d" % k for k in range(5)}
        self.assertTrue(all(r["id"] in deny_ids for r in denies), denies)

    def test_row_os_reads_the_cwd_as_the_bench_does(self):
        mod = load_baseline()
        path = os.path.join(HERE, "..", "..", "tests", "bench_fixture", "cwd_shapes.tsv")
        with open(path, encoding="utf-8") as f:
            cases = [line.rstrip("\n").split("\t") for line in f.readlines()[1:] if line.strip()]
        self.assertEqual(len(cases), 12)
        for cwd, _shape, want in cases:
            self.assertEqual(mod.row_os(None if cwd == "-" else cwd), want, cwd)

    def test_runs_on_is_the_rule_maps_table(self):
        mod = load_baseline()
        with open(os.path.join(HERE, "rule_map.toml"), "rb") as f:
            table = tomllib.load(f)
        self.assertEqual(sorted(mod.RUNS_ON), sorted(table["map"]))
        self.assertEqual(mod.RUNS_ON["bash-backslash-collapse"], (("Bash",), ("Windows",)))
        self.assertEqual(mod.RUNS_ON["git-no-verify"], (("Bash", "PowerShell"), ("Windows", "Linux")))

    def test_known_slice_expects_only_rules_that_fire_on_the_rows_os_and_tool(self):
        mod = load_baseline()
        linux, win, rows, base = "/w/proj", "C:" + chr(92) + "w", [], []

        def add(i, tool, cwd, full):
            rows.append(dict(corpus_row(0, tool, "x"), id=i, cwd=cwd))
            base.append({"id": i, "full": full, "installed": full})
        add("a00", "PowerShell", win, ["bash-msys-path-mangle"])    # a Bash rule on a pwsh row
        add("a01", "Bash", linux, ["bash-msys-path-mangle"])        # a Git Bash rule on Linux
        add("a02", "Bash", win, ["bash-msys-path-mangle"])
        add("a03", "Bash", linux, ["git-restore-discards"])
        add("a04", "Bash", "/mnt/c/w", ["git-restore-discards"])
        add("a05", "Bash", linux, ["deny-r0"])                      # not in RUNS_ON: Windows only
        for k in range(10):
            add("w%02d" % k, "Bash", win, ["deny-r%d" % k])
        for k in range(6):
            add("o%02d" % k, "Bash", win, [])
            add("p%02d" % k, "PowerShell", win, [])
        for k in range(3):
            add("z%02d" % k, "Bash", linux, [])
        known = mod.known_slice(rows, base)
        by_id = {k["id"]: k for k in known}
        denies = [k for k in known if k["expected_rules"]]
        oks = [k for k in known if not k["expected_rules"]]
        self.assertNotIn("a00", by_id)
        self.assertNotIn("a01", by_id)
        self.assertNotIn("a05", by_id)
        self.assertEqual(by_id["a02"], {"id": "a02", "os": "Windows", "expected_rules": ["bash-msys-path-mangle"]})
        self.assertEqual([by_id.get(i, {}).get("os") for i in ("a03", "a04")], ["Linux", "Linux"], by_id)
        self.assertEqual(len(denies), 12)
        self.assertGreaterEqual(sum(k["os"] == "Linux" for k in oks), 2)
        self.assertGreaterEqual(len(oks) - sum(k["os"] == "Linux" for k in oks), 8)
        for k in known:
            row = next(r for r in rows if r["id"] == k["id"])
            self.assertEqual(k["os"], mod.row_os(row["cwd"]), k)

    def test_fails_on_zero_rows_for_a_shell(self):
        rows = [r for r in self.good_rows() if r["tool"] == "Bash"]
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 0 rows for PowerShell", output)

    def test_fails_on_zero_destructive_rows(self):
        rows = [dict(r, destructive=False) for r in self.good_rows()]
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 0 destructive rows", output)

    def test_fails_on_zero_denies(self):
        rows = [r for r in self.good_rows() if not r["command"].startswith("deny-")]
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 0 baseline denies", output)

    def test_fails_on_a_hook_name_no_row_carries(self):
        code, output, *_ = self.baseline(self.good_rows(), hook_name="fixture-other-hook")
        self.assertEqual(code, 1, output)
        self.assertIn("FAIL: 0 baseline guard hook denies to replay", output)

    def unreplayed_rows(self):
        """One baseline guard hook deny per computed cause, none of which today's guard denies. The rows are older
        than the first baseline guard commit (--first-guard-date is 10 days ago)."""
        rows = self.good_rows()
        hook = HOOK
        gone = os.path.join(self.tmp.name, "removed-worktree")
        rows.append(dict(corpus_row(len(rows), "Bash", "git checkout f", "denied-hook", GUARD_HOOK,
                                    excerpt=hook + "`git checkout` on f throws away edits."), cwd=gone, ts=iso(30)))
        rows.append(dict(corpus_row(len(rows), "PowerShell", "git worktree remove x", "denied-hook", GUARD_HOOK,
                                    excerpt=hook + "`git worktree remove` deletes through junctions: %s holds a "
                                    "junction." % gone), cwd=self.tmp.name, ts=iso(30)))
        rows.append(dict(corpus_row(len(rows), "Bash", "narrowed x", "denied-hook", GUARD_HOOK,
                                    excerpt=hook + "something the first version did not deny"), cwd=self.tmp.name,
                         ts=iso(30)))
        return rows

    def test_unreplayed_rows_get_computed_causes(self):
        code, output, out, report, known = self.baseline(self.unreplayed_rows())
        self.assertEqual(code, 0, output)
        with open(report, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("10 of 13", text)
        self.assertIn("| target gone | 2 |", text)
        self.assertIn("| rule narrowed | 1 |", text)
        self.assertIn("| unexplained | 0 |", text)

    def test_fails_when_unexplained_share_is_over_five_percent(self):
        rows = self.unreplayed_rows()
        rows.append(dict(corpus_row(len(rows), "Bash", "old-deny x", "denied-hook", GUARD_HOOK,
                                    excerpt=HOOK + "still denied at first commit"),
                         cwd=self.tmp.name, ts=iso(30)))
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1, output)
        self.assertIn("FAIL: 1 of 4 baseline guard hook denies that do not replay are unexplained", output)
        self.assertIn("target gone: 2", output)
        self.assertIn("rule narrowed: 1", output)

    def test_target_gone_only_for_rules_that_read_the_disk(self):
        # a gone cwd explains a git row, not a row of a rule that never reads the disk
        rows = self.good_rows()
        rows.append(dict(corpus_row(len(rows), "Bash", "echo cwd-gone", "denied-hook", GUARD_HOOK,
                                    excerpt=HOOK + "x"),
                         cwd=os.path.join(self.tmp.name, "removed"), ts=iso(1)))
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1, output)
        self.assertIn("FAIL: 1 of 1 baseline guard hook denies that do not replay are unexplained", output)
        self.assertIn("unexplained: 1", output)

    def test_rule_narrowed_only_before_the_first_commit(self):
        # the same row, dated after the first baseline guard commit: narrowing cannot explain it
        rows = self.good_rows()
        rows.append(dict(corpus_row(len(rows), "Bash", "narrowed x", "denied-hook", GUARD_HOOK,
                                    excerpt=HOOK + "x"), cwd=self.tmp.name,
                         ts=iso(1)))
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1, output)
        self.assertIn("FAIL: 1 of 1 baseline guard hook denies that do not replay are unexplained", output)

    def test_disk_rule_replays_on_the_real_disk_and_with_the_disk_neutralised(self):
        rows = self.good_rows()
        rows.append(dict(corpus_row(len(rows), "Bash", "git disk a", "denied-hook", GUARD_HOOK,
                                    excerpt=HOOK + "x"),
                         cwd=os.path.join(self.tmp.name, "removed"), ts=iso(30)))
        # a row that is not a git command is not replayed a second time, whatever the guard does with the disk
        rows.append(dict(corpus_row(len(rows), "Bash", "other disk b", "denied-hook", GUARD_HOOK,
                                    excerpt=HOOK + "x"),
                         cwd=os.path.join(self.tmp.name, "removed"), ts=iso(30)))
        code, output, out, report, known = self.baseline(rows)
        self.assertEqual(code, 0, output)
        with open(report, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("real disk: 10 of 12", text)
        self.assertIn("disk check neutralised: 11 of 12", text)

    def test_fails_when_the_known_slice_is_short(self):
        rows = [r for r in self.good_rows() if not r["id"].startswith("a") and r["command"] not in
                ["deny-rule%d x" % k for k in range(3, 10)]]
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1, output)
        self.assertIn("FAIL: known slice has 4 deny and 10 ok rows, needs 10 each", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
