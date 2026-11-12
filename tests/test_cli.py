import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from trustgate.cli import main
from trustgate.scanner import HOME_FILES, scan, scan_home

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
        for rule in run_["tool"]["driver"]["rules"]:
            self.assertEqual(rule["helpUri"], "https://github.com/kirtanbhatt10/trustgate/blob/main/docs/rules.md")
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

    def test_rules_explain_one(self):
        code, out = run(["rules", "TG100"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("TG100  vscode-folder-open-task  (default severity: high)\n"))
        self.assertIn("Fix: Delete the task", out)
        self.assertIn("Docs: https://github.com/kirtanbhatt10/trustgate/blob/main/docs/rules.md", out)
        self.assertNotIn("TG500", out)

    def test_rules_explain_lower_case(self):
        self.assertEqual(run(["rules", "tg100"]), run(["rules", "TG100"]))

    def test_rules_explain_unknown(self):
        self.assertEqual(run(["rules", "TG999"])[0], 2)

    def test_home_scan(self):
        files = {".claude/settings.json": {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "x"}]}]}},
                 ".config/Code/User/settings.json": {"terminal.integrated.env.linux": {"BASH_ENV": "/tmp/x"}},
                 ".config/Cursor/User/tasks.json": {"tasks": [{"label": "cursor", "command": "echo cursor",
                                                              "runOptions": {"runOn": "folderOpen"}}]}}
        with TempRepo(files) as home:
            from trustgate.scanner import scan_home
            result = scan_home(str(home))
        self.assertEqual(sorted(f.rule_id for f in result.findings), ["TG100", "TG102", "TG200"])

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


HOME_TASKS = {"tasks": [{"label": "home-auto", "command": "echo home-contract",
                         "runOptions": {"runOn": "folderOpen"}}]}
HOME_SETTINGS = {"terminal.integrated.env.linux": {"BASH_ENV": "./home-contract-env"}}


class HomeScanTests(unittest.TestCase):
    def _editor(self, prefix):
        paths = {prefix + "/tasks.json": HOME_TASKS, prefix + "/settings.json": HOME_SETTINGS}
        with TempRepo(paths) as home:
            result = scan_home(str(home))
        self.assertEqual(result.errors, [])
        self.assertEqual(result.files_scanned, 2)
        by_rule = {f.rule_id: f for f in result.findings}
        self.assertEqual(set(by_rule), {"TG100", "TG102"})
        self.assertEqual(by_rule["TG100"].path, prefix + "/tasks.json")
        self.assertEqual(by_rule["TG100"].line, 7)
        self.assertEqual(by_rule["TG100"].evidence, "echo home-contract")
        self.assertEqual(by_rule["TG102"].path, prefix + "/settings.json")
        self.assertEqual(by_rule["TG102"].line, 3)
        self.assertEqual(by_rule["TG102"].evidence, "BASH_ENV=./home-contract-env")

    def test_cursor_linux(self):
        self._editor(".config/Cursor/User")

    def test_cursor_macos(self):
        self._editor("Library/Application Support/Cursor/User")

    def test_cursor_windows_default(self):
        self._editor("AppData/Roaming/Cursor/User")

    def test_insiders_all_three_layouts(self):
        for prefix in (".config/Code - Insiders/User",
                       "Library/Application Support/Code - Insiders/User",
                       "AppData/Roaming/Code - Insiders/User"):
            with self.subTest(prefix=prefix):
                self._editor(prefix)

    def test_existing_code_profiles_are_preserved(self):
        for prefix in (".config/Code/User", "Library/Application Support/Code/User",
                       "AppData/Roaming/Code/User"):
            with self.subTest(prefix=prefix):
                self._editor(prefix)

    def test_home_file_list_is_unique(self):
        self.assertEqual(len(HOME_FILES), len(set(HOME_FILES)))

    def test_windows_custom_appdata_finds_all_editors(self):
        prefix = "custom-roaming"
        files = {}
        for editor in ("Code", "Code - Insiders", "Cursor"):
            files[prefix + "/" + editor + "/User/tasks.json"] = HOME_TASKS
            files[prefix + "/" + editor + "/User/settings.json"] = HOME_SETTINGS
        with TempRepo(files) as home:
            with mock.patch("trustgate.scanner.sys.platform", "win32"), \
                 mock.patch.dict(os.environ, {"APPDATA": str(home / prefix)}):
                result = scan_home(str(home))
        self.assertEqual(result.errors, [])
        self.assertEqual(result.files_scanned, 6)
        self.assertEqual(len(result.findings), 6)
        self.assertEqual({f.path for f in result.findings}, set(files))

    def test_default_windows_appdata_is_not_scanned_twice(self):
        prefix = "AppData/Roaming"
        files = {}
        for editor in ("Code", "Code - Insiders", "Cursor"):
            files[prefix + "/" + editor + "/User/tasks.json"] = HOME_TASKS
            files[prefix + "/" + editor + "/User/settings.json"] = HOME_SETTINGS
        with TempRepo(files) as home:
            appdata = home / "appdata" / "roaming" if os.name == "nt" else home / prefix
            with mock.patch("trustgate.scanner.sys.platform", "win32"), \
                 mock.patch.dict(os.environ, {"APPDATA": str(appdata)}):
                result = scan_home(str(home))
        self.assertEqual(result.files_scanned, 6)
        self.assertEqual(len(result.findings), 6)
        self.assertEqual(result.errors, [])

    def test_appdata_outside_home_remains_out_of_scope(self):
        files = {"Cursor/User/tasks.json": HOME_TASKS, "Code/User/tasks.json": HOME_TASKS}
        with TempRepo({}) as home, TempRepo(files) as outside:
            with mock.patch("trustgate.scanner.sys.platform", "win32"), \
                 mock.patch.dict(os.environ, {"APPDATA": str(outside)}):
                result = scan_home(str(home))
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.errors, [])

    def test_appdata_is_only_used_on_windows(self):
        files = {"custom-roaming/Cursor/User/tasks.json": HOME_TASKS}
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                with TempRepo(files) as home:
                    with mock.patch("trustgate.scanner.sys.platform", platform), \
                         mock.patch.dict(os.environ, {"APPDATA": str(home / "custom-roaming")}):
                        result = scan_home(str(home))
                self.assertEqual(result.files_scanned, 0)
                self.assertEqual(result.findings, [])

    def test_unrelated_user_directories_are_not_vscode_profiles(self):
        files = {"custom/NotCursor/User/tasks.json": HOME_TASKS,
                 "custom/Cursorish/User/settings.json": HOME_SETTINGS}
        with TempRepo(files) as home:
            result = scan(str(home))
        self.assertEqual(result.findings, [])
        self.assertEqual(result.errors, [])

    def test_ignore_rules_applies_to_cursor_home_findings(self):
        files = {".config/Cursor/User/tasks.json": HOME_TASKS,
                 ".config/Cursor/User/settings.json": HOME_SETTINGS}
        with TempRepo(files) as home:
            result = scan_home(str(home), ignore=("TG100",))
        self.assertEqual([f.rule_id for f in result.findings], ["TG102"])
        self.assertEqual(result.files_scanned, 2)

    def test_real_cli_home_reads_only_the_supplied_fake_home(self):
        files = {".config/Cursor/User/tasks.json": HOME_TASKS,
                 ".config/Cursor/User/settings.json": HOME_SETTINGS}
        with TempRepo(files) as home:
            out = io.StringIO()
            with mock.patch("trustgate.scanner.Path.home", return_value=home), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", "--home", "-f", "json"])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual({f["rule"] for f in doc["findings"]}, {"TG100", "TG102"})
        self.assertEqual(doc["errors"], [])

    def test_scanned_commands_are_never_executed(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("execution forbidden")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")), \
             mock.patch("os.system", side_effect=AssertionError("execution forbidden")):
            self._editor(".config/Cursor/User")


    def test_windows_appdata_case_variants_are_not_duplicates(self):
        expected = {
            "AppData/Roaming/" + editor + "/User/" + name
            for editor in ("Code", "Code - Insiders", "Cursor")
            for name in ("settings.json", "tasks.json")
        }
        with TempRepo({}) as home:
            existing = {(home / rel).as_posix().lower() for rel in expected}
            def is_file(path):
                return path.as_posix().lower() in existing
            appdata = home / "aPpDaTa" / "rOaMiNg"
            with mock.patch("trustgate.scanner.sys.platform", "win32"), \
                 mock.patch.dict(os.environ, {"APPDATA": str(appdata)}), \
                 mock.patch("trustgate.scanner.Path.is_file", new=is_file), \
                 mock.patch("trustgate.scanner.scan") as scan_mock:
                scan_home(str(home))
            paths = scan_mock.call_args.kwargs["files"]
        self.assertEqual(len(paths), 6)
        self.assertEqual(set(paths), expected)


if __name__ == "__main__":
    unittest.main()
