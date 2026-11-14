import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from trustgate import ioc
from trustgate.cli import main
from trustgate.iocdata import CAMPAIGNS

from helpers import TempRepo


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


def hits(result):
    return sorted((f.campaign, f.name, f.version) for f in result.findings if f.kind == "package")


def parsed(parser, text):
    return sorted(parser(text))


class DataTests(unittest.TestCase):
    def test_campaign_data_is_well_formed(self):
        self.assertEqual(ioc.validate(CAMPAIGNS), [])

    def test_validate_reports_problems(self):
        bad = [{"id": "x", "name": "n", "date": "last week", "summary": "s", "advice": "a",
                "references": ["http://insecure.example"], "packages": {"gems": {"Foo": ["= 1"]}}}]
        problems = "\n".join(ioc.validate(bad + bad))
        for expected in ("duplicate id", "date must be", "https reference", "unknown ecosystem",
                         "not in normalised form", "bad version list"):
            self.assertIn(expected, problems)
        self.assertIn("no indicators", "\n".join(ioc.validate([dict(bad[0], packages={})])))

    def test_newest_campaign_first(self):
        dates = [c["date"] for c in CAMPAIGNS]
        self.assertEqual(dates, sorted(dates, reverse=True))


class ParserTests(unittest.TestCase):
    def test_package_lock_v3(self):
        text = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/axios": {"version": "1.14.1"},
            "node_modules/a/node_modules/@nx/js": {"version": "21.5.0"},
            "node_modules/alias": {"name": "debug", "version": "4.4.2"},
            "packages/local": {"version": "9.9.9"},
            "node_modules/linked": {"link": True},
        }})
        self.assertEqual(parsed(ioc.parse_package_lock, text),
                         [("npm", "@nx/js", "21.5.0"), ("npm", "axios", "1.14.1"), ("npm", "debug", "4.4.2")])

    def test_package_lock_v1_nested_and_alias(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {
            "chalk": {"version": "5.6.1", "dependencies": {"ansi-styles": {"version": "6.2.2"}}},
            "my-http": {"version": "npm:axios@0.30.4"},
            "scoped-alias": {"version": "npm:@nx/key@3.2.0"},
            "from-git": {"version": "github:user/repo#abc"},
        }})
        self.assertEqual(parsed(ioc.parse_package_lock, text), [
            ("npm", "@nx/key", "3.2.0"), ("npm", "ansi-styles", "6.2.2"), ("npm", "axios", "0.30.4"),
            ("npm", "chalk", "5.6.1"), ("npm", "from-git", "github:user/repo#abc")])

    def test_package_lock_tolerates_odd_shapes(self):
        self.assertEqual(parsed(ioc.parse_package_lock, "[]"), [])
        self.assertEqual(parsed(ioc.parse_package_lock, '{"packages": {"node_modules/x": 5}}'), [])
        self.assertEqual(parsed(ioc.parse_package_lock, '{"dependencies": {"x": "1.0.0"}}'), [])

    def test_yarn_classic(self):
        text = ('# yarn lockfile v1\n\n\n'
                '"@nx/devkit@^20.0.0":\n  version "20.9.0"\n  resolved "https://registry.example/x.tgz"\n\n'
                'debug@^4.0.0, debug@^4.3.1:\n  version "4.4.2"\n  dependencies:\n    version "1.0.0"\n    ms "2.1.3"\n')
        self.assertEqual(parsed(ioc.parse_yarn_lock, text),
                         [("npm", "@nx/devkit", "20.9.0"), ("npm", "debug", "4.4.2")])

    def test_yarn_berry_and_alias_resolution(self):
        text = ('__metadata:\n  version: 8\n\n'
                '"chalk@npm:^5.0.0":\n  version: 5.6.1\n  resolution: "chalk@npm:5.6.1"\n\n'
                '"http@npm:axios@1.14.1":\n  version: 1.14.1\n  resolution: "axios@npm:1.14.1"\n')
        self.assertEqual(parsed(ioc.parse_yarn_lock, text),
                         [("npm", "axios", "1.14.1"), ("npm", "chalk", "5.6.1"), ("npm", "http", "1.14.1")])

    def test_pnpm_all_lockfile_generations(self):
        text = ("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      axios:\n"
                "        specifier: ^1.0.0\n        version: 1.14.1\n\n"
                "packages:\n\n"
                "  /debug/4.4.2:\n    resolution: {integrity: x}\n"
                "  /@nx/js/21.5.0_react@18.0.0:\n    dev: true\n"
                "  /chalk@5.6.1:\n    dev: false\n"
                "  /@nx/node@20.9.0(typescript@5.0.0):\n    dev: false\n"
                "  axios@1.14.1:\n    resolution: {integrity: x}\n"
                "  '@duckdb/node-api@1.3.3':\n    resolution: {integrity: x}\n\n"
                "snapshots:\n\n  color@5.0.1(supports-color@10.2.1):\n    dependencies:\n      a: 1.0.0\n")
        self.assertEqual(parsed(ioc.parse_pnpm_lock, text), [
            ("npm", "@duckdb/node-api", "1.3.3"), ("npm", "@nx/js", "21.5.0"), ("npm", "@nx/node", "20.9.0"),
            ("npm", "axios", "1.14.1"), ("npm", "chalk", "5.6.1"), ("npm", "color", "5.0.1"),
            ("npm", "debug", "4.4.2")])

    def test_bun_lock(self):
        text = ('{\n  "lockfileVersion": 1,\n  "workspaces": {"": {"dependencies": {"axios": "^1.0.0"}}},\n'
                '  "packages": {\n    "axios": ["axios@1.14.1", "", {}, "sha512-x"],\n'
                '    "@nx/js": ["@nx/js@21.5.0", "", {}, "sha512-y"],\n  }\n}\n')
        self.assertEqual(parsed(ioc.parse_bun_lock, text),
                         [("npm", "@nx/js", "21.5.0"), ("npm", "axios", "1.14.1")])

    def test_requirements(self):
        text = ("# pinned\n-r base.txt\n--hash=sha256:abc\nlitellm==1.82.8 \\\n    --hash=sha256:abc\n"
                "Guardrails_AI[extra] == 0.10.1 ; python_version > '3.9'\nrequests>=2\nmistralai===2.4.6\n")
        self.assertEqual(parsed(ioc.parse_requirements, text),
                         [("pypi", "Guardrails_AI", "0.10.1"), ("pypi", "litellm", "1.82.8"),
                          ("pypi", "mistralai", "2.4.6")])

    def test_toml_locks(self):
        text = ('version = 1\n\n[[package]]\nname = "litellm"\nversion = "1.82.7"\n'
                'dependencies = [\n    { name = "httpx" },\n]\n\n[package.metadata]\nname = "ignored"\n'
                'version = "0.0.1"\n\n[[package]]\nversion = "2.4.6"\nname = "mistralai"\n')
        self.assertEqual(parsed(ioc.parse_toml_lock, text),
                         [("pypi", "litellm", "1.82.7"), ("pypi", "mistralai", "2.4.6")])

    def test_pipfile_lock(self):
        text = json.dumps({"default": {"litellm": {"version": "==1.82.7"}, "x": "odd"},
                           "develop": {"mistralai": {"version": "==2.4.6"}}})
        self.assertEqual(parsed(ioc.parse_pipfile_lock, text),
                         [("pypi", "litellm", "==1.82.7"), ("pypi", "mistralai", "==2.4.6")])


class ScanTests(unittest.TestCase):
    def test_clean_project(self):
        with TempRepo({"package-lock.json": {"packages": {"node_modules/axios": {"version": "1.14.0"},
                                                         "node_modules/chalk": {"version": "5.6.2"}}},
                       "requirements.txt": "litellm==1.82.6\n"}) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual(result.findings, [])
            self.assertEqual(result.sources, ["package-lock.json", "requirements.txt"])
            self.assertEqual(result.packages_checked, 3)

    def test_lockfile_hits_across_ecosystems(self):
        with TempRepo({
            "package-lock.json": {"packages": {"node_modules/axios": {"version": "1.14.1"},
                                               "node_modules/plain-crypto-js": {"version": "4.2.0"}}},
            "web/yarn.lock": 'chalk@^5.0.0:\n  version "5.6.1"\n',
            "api/requirements-dev.txt": "Guardrails.AI==0.10.1\n",
            "api/Pipfile.lock": {"default": {"litellm": {"version": "==1.82.8"}}},
        }) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual(hits(result), [
                ("axios-2026-03", "axios", "1.14.1"),
                ("axios-2026-03", "plain-crypto-js", "4.2.0"),
                ("litellm-2026-03", "litellm", "1.82.8"),
                ("qix-2025-09", "chalk", "5.6.1"),
                ("tanstack-mistral-2026-05", "guardrails-ai", "0.10.1"),
            ])
            paths = {f.name: f.path for f in result.findings}
            self.assertEqual(paths["chalk"], "web/yarn.lock")
            self.assertEqual(paths["litellm"], "api/Pipfile.lock")

    def test_findings_follow_campaign_order(self):
        with TempRepo({"package-lock.json": {"packages": {"node_modules/nx": {"version": "21.5.0"},
                                                         "node_modules/axios": {"version": "0.30.4"}}}}) as root:
            self.assertEqual([f.campaign for f in ioc.scan_path(str(root)).findings],
                             ["axios-2026-03", "nx-s1ngularity-2025-08"])

    def test_installed_node_modules(self):
        files = {
            "node_modules/debug/package.json": {"name": "debug", "version": "4.4.2"},
            "node_modules/@nx/js/package.json": {"name": "@nx/js", "version": "20.9.0"},
            "node_modules/a/node_modules/plain-crypto-js/package.json": {"name": "plain-crypto-js", "version": "4.2.1"},
            "node_modules/debug/test/fixture/package.json": {"name": "chalk", "version": "5.6.1"},
            "node_modules/debug/yarn.lock": 'chalk@^5.0.0:\n  version "5.6.1"\n',
            "node_modules/.package-lock.json": {"packages": {"node_modules/color": {"version": "5.0.1"}}},
            "package.json": {"name": "axios", "version": "1.14.1"},
        }
        with TempRepo(files) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual(hits(result), [
                ("axios-2026-03", "plain-crypto-js", "4.2.1"),
                ("nx-s1ngularity-2025-08", "@nx/js", "20.9.0"),
                ("qix-2025-09", "color", "5.0.1"),
                ("qix-2025-09", "debug", "4.4.2"),
            ])
            self.assertEqual(ioc.scan_path(str(root), installed=False).findings, [])

    def test_installed_python_distribution_and_pth(self):
        files = {
            ".venv/lib/python3.12/site-packages/litellm-1.82.8.dist-info/METADATA": "Name: litellm\n",
            ".venv/lib/python3.12/site-packages/Guardrails_AI-0.10.1.dist-info/METADATA": "x",
            ".venv/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA": "x",
            ".venv/lib/python3.12/site-packages/litellm_init.pth": "import os\n",
        }
        with TempRepo(files) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual(hits(result), [("litellm-2026-03", "litellm", "1.82.8"),
                                            ("tanstack-mistral-2026-05", "guardrails-ai", "0.10.1")])
            self.assertEqual([(f.campaign, f.path) for f in result.findings if f.kind == "file"],
                             [("litellm-2026-03", ".venv/lib/python3.12/site-packages/litellm_init.pth")])
            lock_only = ioc.scan_path(str(root), installed=False)
            self.assertEqual([f.kind for f in lock_only.findings], ["file"])

    def test_file_indicators_respect_their_location(self):
        files = {
            "setup_bun.js": "// a project may legitimately own a file with this name\n",
            "node_modules/pkg/setup_bun.js": "x",
            "node_modules/pkg/Bun_Environment.js": "x",
            "node_modules/@scope/pkg/dist/tanstack_runner.js": "x",
            ".github/workflows/shai-hulud-workflow.yml": "on: push\n",
        }
        with TempRepo(files) as root:
            found = sorted((f.campaign, f.path) for f in ioc.scan_path(str(root)).findings)
            self.assertEqual(found, [
                ("shai-hulud-2-2025-11", "node_modules/pkg/Bun_Environment.js"),
                ("shai-hulud-2-2025-11", "node_modules/pkg/setup_bun.js"),
                ("shai-hulud-2025-09", ".github/workflows/shai-hulud-workflow.yml"),
                ("tanstack-mistral-2026-05", "node_modules/@scope/pkg/dist/tanstack_runner.js"),
            ])

    def test_infected_lifecycle_script(self):
        with TempRepo({"package.json": {"name": "mine", "version": "1.0.0",
                                        "scripts": {"preinstall": "node setup_bun.js", "test": "vitest", "odd": 5}},
                       "docs/package.json": "[1, 2]", "broken/package.json": "{not json"}) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual([(f.campaign, f.kind, f.path, f.detail) for f in result.findings],
                             [("shai-hulud-2-2025-11", "script", "package.json", "preinstall: node setup_bun.js")])

    def test_exclude_and_vcs_directories(self):
        files = {"tests/fixtures/package-lock.json": {"packages": {"node_modules/axios": {"version": "1.14.1"}}},
                 ".git/yarn.lock": 'chalk@^5.0.0:\n  version "5.6.1"\n',
                 "requirements.txt": "litellm==1.82.7\n"}
        with TempRepo(files) as root:
            self.assertEqual(len(ioc.scan_path(str(root)).findings), 2)
            for glob in ("tests/fixtures", "tests/fixtures/", "tests/*", "*/package-lock.json"):
                self.assertEqual(hits(ioc.scan_path(str(root), exclude=[glob])),
                                 [("litellm-2026-03", "litellm", "1.82.7")], glob)

    def test_unparseable_lockfile_is_reported_not_fatal(self):
        with TempRepo({"package-lock.json": "{ this is not json", "requirements.txt": "litellm==1.82.7\n"}) as root:
            result = ioc.scan_path(str(root))
            self.assertEqual(result.skipped, ["package-lock.json: could not be parsed"])
            self.assertEqual(hits(result), [("litellm-2026-03", "litellm", "1.82.7")])
            self.assertIn("Skipped package-lock.json", ioc.to_text(result))

    def test_utf8_bom_lockfile(self):
        with TempRepo({"package-lock.json": chr(0xFEFF) + json.dumps(
                {"packages": {"node_modules/axios": {"version": "1.14.1"}}})}) as root:
            self.assertEqual(hits(ioc.scan_path(str(root))), [("axios-2026-03", "axios", "1.14.1")])

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_symlinks_are_not_followed(self):
        with TempRepo({"real/requirements.txt": "litellm==1.82.7\n"}) as root, \
                tempfile.TemporaryDirectory() as outside:
            with open(os.path.join(outside, "requirements.txt"), "w", encoding="utf-8") as fh:
                fh.write("mistralai==2.4.6\n")
            try:
                os.symlink(outside, os.path.join(str(root), "linked"), target_is_directory=True)
                os.symlink(os.path.join(outside, "requirements.txt"), os.path.join(str(root), "requirements.txt"))
            except OSError:
                self.skipTest("symlinks not permitted")
            self.assertEqual(hits(ioc.scan_path(str(root))), [("litellm-2026-03", "litellm", "1.82.7")])

    def test_not_a_directory(self):
        with TempRepo({"file.txt": "x"}) as root:
            with self.assertRaises(NotADirectoryError):
                ioc.scan_path(str(root / "file.txt"))

    def test_host_scan(self):
        with TempRepo({".zshrc": "export A=1\nsudo shutdown -h 0\n", ".bashrc": "export A=1\n",
                       "drop/inventory.txt": "x"}) as home:
            campaigns = [{"id": "demo", "name": "Demo", "date": "2025-01", "summary": "s", "advice": "a",
                          "references": ["https://example.com"],
                          "host_files": [str(home / "drop" / "inventory.txt"), str(home / "drop" / "missing")],
                          "host_markers": [{"files": ["~/.bashrc", "~/.zshrc", "~/.profile"],
                                            "text": "sudo shutdown -h 0"}]}]
            result = ioc.scan_host(home=str(home), campaigns=campaigns)
            self.assertTrue(result.host)
            self.assertEqual([(f.kind, f.path) for f in result.findings],
                             [("host", str(home / "drop" / "inventory.txt")), ("host", "~/.zshrc")])
            self.assertIn("contains 'sudo shutdown -h 0'", ioc.to_text(result))
            self.assertNotIn("Lockfiles read", ioc.to_text(result))
            self.assertEqual(ioc.scan_host(home=str(home / "drop"), campaigns=campaigns[:1]).findings[1:], [])


class ReportTests(unittest.TestCase):
    def test_text_report(self):
        with TempRepo({"package-lock.json": {"packages": {"node_modules/axios": {"version": "1.14.1"}}}}) as root:
            text = ioc.to_text(ioc.scan_path(str(root)))
        self.assertIn("[HIT] axios-2026-03: axios maintainer account takeover (2026-03-31)", text)
        self.assertIn("package  axios@1.14.1 (npm) in package-lock.json", text)
        self.assertIn("What to do: Downgrade to axios 1.14.0 or 0.30.3", text)
        self.assertIn("Read more: https://endorlabs.com/learn/npm-axios-compromise", text)
        self.assertIn("1 indicator(s) from 1 campaign(s) found.", text)
        self.assertNotIn("qix-2025-09", text)

    def test_untrusted_text_is_escaped(self):
        escape, override = chr(0x1B), chr(0x202E)  # terminal escape, right-to-left override
        name = "node_modules/ev" + escape + "[2Jil/package.json"
        repo = TempRepo({name: {"name": "plain-crypto-js", "version": "1.0.0" + override}})
        try:
            root = repo.__enter__()
        except (OSError, ValueError):
            repo.__exit__(None, None, None)
            self.skipTest("file system rejects control characters in names")
        try:
            text = ioc.to_text(ioc.scan_path(str(root)))
        finally:
            repo.__exit__(None, None, None)
        self.assertNotIn(escape, text)
        self.assertNotIn(override, text)
        expected = "plain-crypto-js@1.0.0{0}u202e (npm) in node_modules/ev{0}u001b[2Jil/package.json"
        self.assertIn(expected.format(chr(0x5C)), text)

    def test_json_report(self):
        with TempRepo({"uv.lock": '[[package]]\nname = "litellm"\nversion = "1.82.7"\n'}) as root:
            data = json.loads(ioc.to_json(ioc.scan_path(str(root))))
        self.assertEqual(data["mode"], "path")
        self.assertEqual(data["lockfiles"], ["uv.lock"])
        self.assertEqual(data["campaigns_checked"], [c["id"] for c in CAMPAIGNS])
        self.assertEqual(data["findings"], [{"campaign": "litellm-2026-03", "kind": "package", "path": "uv.lock",
                                             "ecosystem": "pypi", "name": "litellm", "version": "1.82.7",
                                             "detail": ""}])

    def test_list_campaigns(self):
        text = ioc.list_campaigns()
        for campaign in CAMPAIGNS:
            self.assertIn(campaign["id"], text)
        self.assertIn("28 package indicator(s), 0 file or host indicator(s)", text)


class CliTests(unittest.TestCase):
    def test_exit_codes_and_output(self):
        with TempRepo({"package-lock.json": {"packages": {"node_modules/debug": {"version": "4.4.2"}}}}) as root:
            code, out = run(["ioc", str(root)])
            self.assertEqual(code, 1)
            self.assertIn("[HIT] qix-2025-09", out)
            code, out = run(["ioc", str(root), "-f", "json"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)["findings"][0]["name"], "debug")
            code, out = run(["ioc", str(root), "--exclude", "package-lock.json"])
            self.assertEqual(code, 0)
            self.assertIn("No indicators from the known campaigns were found.", out)

    def test_no_installed_flag(self):
        with TempRepo({"node_modules/debug/package.json": {"name": "debug", "version": "4.4.2"}}) as root:
            self.assertEqual(run(["ioc", str(root)])[0], 1)
            self.assertEqual(run(["ioc", str(root), "--no-installed"])[0], 0)

    def test_output_file(self):
        with TempRepo({"requirements.txt": "litellm==1.82.7\n"}) as root:
            target = str(root / "report.json")
            code, out = run(["ioc", str(root), "-f", "json", "-o", target])
            self.assertEqual((code, out), (1, ""))
            with open(target, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["findings"][0]["campaign"], "litellm-2026-03")
            self.assertEqual(run(["ioc", str(root), "-o", str(root / "missing" / "report.txt")])[0], 2)

    def test_list_and_usage_errors(self):
        code, out = run(["ioc", "--list"])
        self.assertEqual(code, 0)
        self.assertIn("campaign(s)", out)
        with TempRepo({"file.txt": "x"}) as root:
            self.assertEqual(run(["ioc", str(root / "file.txt")])[0], 2)
        self.assertEqual(run(["ioc", "--format", "sarif"])[0], 2)

    def test_host_flag_uses_the_home_directory(self):
        with TempRepo({".zshrc": "sudo shutdown -h 0\n"}) as home:
            env = {"HOME": str(home), "USERPROFILE": str(home)}
            with mock.patch.dict(os.environ, env), \
                    mock.patch("os.path.lexists", return_value=False):
                code, out = run(["ioc", "--host"])
        self.assertEqual(code, 1)
        self.assertIn("[HIT] nx-s1ngularity-2025-08", out)
        self.assertIn("host     ~/.zshrc: contains 'sudo shutdown -h 0'", out)

    def test_module_entry_point(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ioc.main(["--list"]), 0)
        self.assertIn("trustgate ioc data", out.getvalue())

    def test_existing_commands_still_work(self):
        self.assertEqual(run(["rules"])[0], 0)
        self.assertEqual(run([])[0], 2)


if __name__ == "__main__":
    unittest.main()
