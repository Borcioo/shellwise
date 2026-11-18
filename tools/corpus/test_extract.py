"""Tests for the corpus extractor and the baseline-guard baseline replay.

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


HOOK_TEXT = "PreToolUse:PowerShell hook error: baseline-guard: `Remove-Item` here deletes a tree."


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
    main.result("t-perm2", "Permission to use Bash denied by plugin example: no.", is_error=True)
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
            ("Remove-Item -Recurse x", "denied-hook", "baseline-guard"),
            ("rm -rf x", "denied-permission", "user-rejected"),
            ("rmdir y", "denied-permission", "cancelled"),
            ("ls", "denied-permission", "permission-rule"),
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
        self.assertEqual(sum(len(v) for v in self.rows.values()), 9, sorted(self.rows))

    def test_destructive_flag_in_rows(self):
        self.assertTrue(self.row("rm -rf x")["destructive"])
        self.assertFalse(self.row("echo hi")["destructive"])

    def test_zero_transcripts_fails(self):
        with tempfile.TemporaryDirectory() as empty:
            code, out, err = run(EXTRACT, "--projects", empty, "--days", "30", "--out", os.path.join(empty, "c.jsonl"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL: read 0 transcripts", out + err)


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
        ]
        for tool, command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(ex.is_destructive(table, tool, command), expected)

    def test_table_schema_is_checked(self):
        ex = load_extract()
        for bad in ('[[command]]\nnames = "rm"\nshells = ["bash"]\nrequires_any = []\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["zsh"]\nrequires_any = []\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["bash"]\nrequires_any = 3\n',
                    '[[command]]\nnames = ["rm"]\nshells = ["bash"]\n'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "t.toml")
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(bad)
                with self.assertRaises(ValueError):
                    ex.load_table(path)


FAKE_GUARD = r'''
import os

class Finding:
    def __init__(self, rule, deny, message):
        self.rule, self.deny, self.message = rule, deny, message

def _rules(cmd):
    if os.environ.get("BASELINE_GUARD"):
        return []
    if cmd.startswith("deny-"):
        return [Finding(cmd.split()[0], True, "m"), Finding("note", False, "m")]
    if cmd.startswith("warn"):
        return [Finding("soft", False, "m")]
    return []

def check(tool, cmd, cwd=None):
    return _rules(cmd)

def check_installed(tool, cmd, cwd=None):
    return [f for f in _rules(cmd) if f.rule != "deny-full-only"]
'''


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
            rows.append(corpus_row(len(rows), "Bash", "deny-rule%d x" % k, "denied-hook", "baseline-guard"))
        rows.append(corpus_row(len(rows), "PowerShell", "deny-full-only y", "failed"))
        for k in range(10):
            rows.append(corpus_row(len(rows), "PowerShell" if k % 2 else "Bash", "echo ok%d" % k))
        rows.append(corpus_row(len(rows), "Bash", "rm -rf $dir", "ok", destructive=True))
        rows.append(corpus_row(len(rows), "PowerShell", "python -c \"open(r'%s','w')\"" % self.marker))
        rows.append(corpus_row(len(rows), "Bash", "warn me"))
        # more rows of one rule, sorted first: the slice must still spread over rules
        rows += [dict(corpus_row(0, "Bash", "deny-rule0 again%d" % k, "failed"), id="a%02d" % k) for k in range(5)]
        return rows

    def baseline(self, rows, extra_env=None):
        env = dict(os.environ, BASELINE_GUARD="off", **(extra_env or {}))
        out = os.path.join(self.tmp.name, "baseline.jsonl")
        report = os.path.join(self.tmp.name, "baseline.md")
        known = os.path.join(self.tmp.name, "known.jsonl")
        code, stdout, stderr = run(BASELINE, "--baseline-guard", self.guard, "--corpus", self.corpus(rows),
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
        self.assertIn("| baseline-guard | 10 |", text)
        self.assertIn("10 of 10", text)
        self.assertNotIn("echo ok", text)
        self.assertNotIn("r000", text)

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

    def test_fails_when_hook_denies_do_not_replay(self):
        rows = self.good_rows()
        for k in range(2):
            rows.append(corpus_row(len(rows), "Bash", "echo was-denied%d" % k, "denied-hook", "baseline-guard",
                                   excerpt="PreToolUse:Bash hook error: baseline-guard: `git checkout` on f throws away"))
        rows.append(dict(corpus_row(len(rows), "Bash", "echo was-denied-x", "denied-hook", "baseline-guard",
                                    excerpt="PreToolUse:Bash hook error: baseline-guard: something else"),
                         cwd=self.tmp.name))
        code, output, *_ = self.baseline(rows)
        self.assertEqual(code, 1)
        self.assertIn("FAIL: 10 of 13 baseline-guard hook denies replay", output)
        self.assertIn("git rule (repository state): 2", output)
        self.assertIn("rule changed since: 1", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
