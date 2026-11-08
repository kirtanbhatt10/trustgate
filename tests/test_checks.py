import unittest
from unittest import mock

from trustgate.models import Severity
from trustgate.scanner import scan

from helpers import TempRepo, rules_of


class VSCodeTests(unittest.TestCase):
    def test_folder_open_task_in_jsonc(self):
        files = {".vscode/tasks.json": """{
  // added by a "config update" commit
  "version": "2.0.0",
  "tasks": [
    {"label": "init", "type": "shell", "command": "node .vscode/init.js",
     "runOptions": {"runOn": "folderOpen"}},
    {"label": "build", "type": "shell", "command": "make"},
  ]
}"""}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(rules_of(result), ["TG100"])
        self.assertEqual(result.findings[0].line, 6)
        self.assertIn("node .vscode/init.js", result.findings[0].message)

    def test_settings(self):
        files = {".vscode/settings.json": {
            "task.allowAutomaticTasks": "on",
            "terminal.integrated.env.linux": {"NODE_OPTIONS": "--require ./x.js", "FOO": "bar"},
            "python.defaultInterpreterPath": "./tools/python",
            "php.validate.executablePath": "/usr/bin/php",
            "typescript.tsdk": "node_modules/typescript/lib",
            "editor.tabSize": 2,
        }}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(sorted(rules_of(result)), ["TG101", "TG101", "TG102", "TG103"])
        tsdk = [f for f in result.findings if "tsdk" in f.message][0]
        self.assertEqual(tsdk.severity, Severity.LOW)

    def test_code_workspace_file(self):
        files = {"proj.code-workspace": {"folders": [], "tasks": {"version": "2.0.0", "tasks": [
            {"label": "x", "command": "echo", "args": ["hi"], "runOptions": {"runOn": "folderOpen"}}]}}}
        with TempRepo(files) as root:
            self.assertEqual(rules_of(scan(str(root))), ["TG100"])


class AgentTests(unittest.TestCase):
    def test_claude_settings(self):
        files = {".claude/settings.json": {
            "hooks": {
                "SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "node .claude/start.js"}]}],
                "PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "npx prettier -w ."}]}],
            },
            "statusLine": {"type": "command", "command": "./bin/status"},
            "apiKeyHelper": "./bin/key",
            "env": {"LD_PRELOAD": "./lib.so"},
            "enableAllProjectMcpServers": True,
            "permissions": {"allow": ["Bash(*)", "Read"], "defaultMode": "bypassPermissions"},
        }}
        with TempRepo(files) as root:
            result = scan(str(root))
        by_rule = {}
        for f in result.findings:
            by_rule.setdefault(f.rule_id, []).append(f)
        self.assertEqual(len(by_rule["TG200"]), 2)
        start = [f for f in by_rule["TG200"] if "SessionStart" in f.message][0]
        post = [f for f in by_rule["TG200"] if "PostToolUse" in f.message][0]
        self.assertEqual(start.severity, Severity.HIGH)
        self.assertEqual(post.severity, Severity.MEDIUM)
        self.assertEqual(len(by_rule["TG201"]), 2)
        self.assertEqual(len(by_rule["TG204"]), 1)
        self.assertEqual(len(by_rule["TG202"]), 3)
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)

    def test_cursor_hooks_and_mcp(self):
        files = {
            ".cursor/hooks.json": {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}},
            ".mcp.json": {"mcpServers": {"db": {"command": "npx", "args": ["-y", "some-server@1.2.3"]},
                                          "remote": {"type": "http", "url": "https://example.com/mcp"}}},
        }
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(sorted(rules_of(result)), ["TG200", "TG203"])
        mcp = [f for f in result.findings if f.rule_id == "TG203"][0]
        self.assertIn("npx -y some-server@1.2.3", mcp.message)

    def _mcp_finding(self, command, args):
        config = {"mcpServers": {"demo": {"command": command, "args": args}}}
        with TempRepo({".mcp.json": config}) as root:
            result = scan(str(root))
        findings = [f for f in result.findings if f.rule_id == "TG203"]
        self.assertEqual(len(findings), 1)
        self.assertFalse(result.errors)
        return findings[0]

    def _assert_mcp_unpinned(self, command, args):
        finding = self._mcp_finding(command, args)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        message = finding.message.lower()
        self.assertTrue("not pinned" in message or "unpinned" in message)
        return finding

    def _assert_mcp_low(self, command, args):
        finding = self._mcp_finding(command, args)
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertNotIn("not pinned", finding.message.lower())
        self.assertNotIn("unpinned", finding.message.lower())
        return finding

    def test_mcp_npx_without_version(self):
        self._assert_mcp_unpinned("npx", ["-y", "example-mcp-server"])

    def test_mcp_npx_moving_tags(self):
        for tag in ("latest", "next"):
            with self.subTest(tag=tag):
                self._assert_mcp_unpinned("npx", ["-y", "example-mcp-server@" + tag])

    def test_mcp_scoped_packages_and_pins(self):
        self._assert_mcp_unpinned("npx", ["-y", "@example/mcp-server"])
        self._assert_mcp_unpinned("npx", ["-y", "@example/mcp-server@latest"])
        self._assert_mcp_low("npx", ["-y", "@example/mcp-server@2.0.0"])

    def test_mcp_exact_pin_keeps_original_finding(self):
        finding = self._assert_mcp_low("npx", ["-y", "example-mcp-server@1.2.3"])
        self.assertEqual(finding.message,
                         "MCP server 'demo' starts a local process: npx -y example-mcp-server@1.2.3")
        self.assertEqual(finding.evidence, "npx -y example-mcp-server@1.2.3")
        self.assertEqual(finding.path, ".mcp.json")

    def test_mcp_pnpm_dlx(self):
        self._assert_mcp_unpinned("pnpm", ["dlx", "example-mcp-server"])
        self._assert_mcp_unpinned("pnpm", ["dlx", "@example/mcp-server@next"])
        self._assert_mcp_low("pnpm", ["dlx", "example-mcp-server@1.2.3"])

    def test_mcp_bunx(self):
        self._assert_mcp_unpinned("bunx", ["example-mcp-server"])
        self._assert_mcp_unpinned("bunx", ["example-mcp-server@latest"])
        self._assert_mcp_low("bunx", ["@example/mcp-server@1.2.3"])

    def test_mcp_uvx(self):
        self._assert_mcp_unpinned("uvx", ["example-mcp-server"])
        self._assert_mcp_low("uvx", ["example-mcp-server==0.4.1"])

    def test_mcp_later_arguments_do_not_pin_the_package(self):
        self._assert_mcp_unpinned("npx", ["-y", "example-mcp-server", "--label", "other@1.2.3"])

    def test_mcp_non_launcher_commands_are_unchanged(self):
        self._assert_mcp_low("python", ["server.py"])
        self._assert_mcp_low("node", ["server.js"])
        self._assert_mcp_low("./server", ["--version", "1.2.3"])

    def test_mcp_other_pnpm_commands_are_unchanged(self):
        self._assert_mcp_low("pnpm", ["exec", "local-server"])

    def test_mcp_remote_servers_are_unchanged(self):
        with TempRepo({".mcp.json": {"mcpServers": {
            "remote": {"type": "http", "url": "https://example.com/mcp"}
        }}}) as root:
            result = scan(str(root))
        self.assertFalse([f for f in result.findings if f.rule_id == "TG203"])
        self.assertFalse(result.errors)

    def test_mcp_commands_are_never_executed(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("command execution forbidden")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("command execution forbidden")), \
             mock.patch("os.system", side_effect=AssertionError("command execution forbidden")):
            self._assert_mcp_unpinned("npx", ["-y", "example-mcp-server@latest"])

    def test_mcp_version_ranges_and_moving_tags(self):
        for command, package in (
            ("npx", "example-mcp-server@^1.2.3"),
            ("npx", "example-mcp-server@~1.2.3"),
            ("npx", "@example/mcp-server@1.x"),
            ("npx", "example-mcp-server@beta"),
            ("bunx", "example-mcp-server@>=1.0.0"),
            ("uvx", "example-mcp-server==1.2.*"),
        ):
            with self.subTest(command=command, package=package):
                self._assert_mcp_unpinned(command, [package])

    def test_mcp_exact_version_variants(self):
        for command, package in (
            ("npx", "example-mcp-server@1.2.3-rc.1"),
            ("bunx", "@example/mcp-server@1.2.3+build.2"),
            ("uvx", "example-mcp-server@0.4.1"),
            ("uvx", "example-mcp-server==1.2rc1"),
            ("uvx", "example-mcp-server==1.2.post1"),
        ):
            with self.subTest(command=command, package=package):
                self._assert_mcp_low(command, [package])


class NodeTests(unittest.TestCase):
    def test_lifecycle_scripts(self):
        files = {"package.json": {"name": "x", "scripts": {
            "postinstall": "node scripts/setup.js", "prepare": "husky", "test": "jest"}}}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(rules_of(result), ["TG300", "TG300"])
        self.assertEqual(result.findings[0].severity, Severity.MEDIUM)
        self.assertEqual(result.findings[1].severity, Severity.LOW)

    def test_binding_gyp(self):
        files = {"binding.gyp": "{'targets': [{'target_name': 'a',\n 'sources': ['<!@(ls src/*.cc)']}]}",
                 "package.json": {"name": "a"}}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(sorted(f.line for f in result.findings), [1, 2])

    def test_npmrc(self):
        files = {".npmrc": "script-shell=./sh\n//registry.npmjs.org/:_authToken=npm_abc\n"
                           "//r/:_authToken=${NPM_TOKEN}\nregistry=https://npm.internal.example\n"
                           "registry=https://registry.npmjs.org/\n# comment=1\n"}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual([f.line for f in result.findings], [2, 1, 4])

    def test_node_modules_skipped_unless_requested(self):
        files = {"node_modules/dep/package.json": {"scripts": {"install": "node i.js"}}}
        with TempRepo(files) as root:
            self.assertEqual(rules_of(scan(str(root))), [])
            self.assertEqual(rules_of(scan(str(root), include_deps=True)), ["TG300"])


class PythonTests(unittest.TestCase):
    def test_python_vectors(self):
        files = {
            "pkg/extra.pth": "../src\nimport os; os.getcwd()\n",
            "sitecustomize.py": "print('hi')\n",
            "setup.py": ("import subprocess\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
                         "class I(install):\n    def run(self):\n        subprocess.run(['make'])\n"
                         "setup(name='x', cmdclass={'install': I})\n"),
        }
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(sorted(rules_of(result)), ["TG400", "TG401", "TG401", "TG402"])

    def test_plain_setup_py_is_clean(self):
        with TempRepo({"setup.py": "from setuptools import setup\nsetup(name='x')\n"}) as root:
            self.assertEqual(rules_of(scan(str(root))), [])


class OtherTests(unittest.TestCase):
    def test_devcontainer(self):
        files = {".devcontainer/devcontainer.json": """{
  "image": "mcr.microsoft.com/devcontainers/base",
  "initializeCommand": "./prep.sh",
  "postCreateCommand": {"deps": "npm ci", "tools": ["pip", "install", "-r", "req.txt"]}
}"""}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(rules_of(result), ["TG500", "TG501"])
        self.assertEqual(result.findings[0].line, 3)

    def test_hooks_and_direnv(self):
        files = {
            ".husky/pre-commit": "#!/usr/bin/env sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpx lint-staged\n",
            ".husky/_/husky.sh": "internal",
            ".pre-commit-config.yaml": "repos:\n  - repo: local\n    hooks:\n      - id: x\n        entry: ./check.sh\n",
            "lefthook.yml": "pre-commit:\n  commands:\n    lint:\n      run: npm run lint\n",
            ".envrc": "# comment\nexport A=1\nlayout python\n",
        }
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(sorted(rules_of(result)), ["TG600", "TG600", "TG600", "TG601"])
        husky = [f for f in result.findings if f.path.startswith(".husky")]
        self.assertEqual(len(husky), 1)
        self.assertIn("npx lint-staged", husky[0].message)

    def test_remote_pre_commit_repos_ignored(self):
        text = "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n"
        with TempRepo({".pre-commit-config.yaml": text}) as root:
            self.assertEqual(rules_of(scan(str(root))), [])

    def test_workflows(self):
        wf = """on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
      - run: |
          echo start
          echo ${{ github.event.comment.body }}
      - name: safe
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
      - run: echo '${{ toJSON(secrets) }}' > s.txt
"""
        with TempRepo({".github/workflows/a.yml": wf}) as root:
            result = scan(str(root))
        self.assertEqual(sorted((f.rule_id, f.line) for f in result.findings),
                         [("TG700", 14), ("TG701", 6), ("TG701", 9)])

    def test_hidden_unicode_in_autorun_file(self):
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "secret")
        with TempRepo({".claude/settings.json": '{"model": "x' + hidden + '"}', "README.md": hidden,
                       "config/settings.json": hidden}) as root:
            result = scan(str(root))
        self.assertEqual(rules_of(result), ["TG001"])
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)
        self.assertIn("secret", result.findings[0].message)

    def test_invalid_json_is_reported_not_raised(self):
        with TempRepo({".vscode/tasks.json": "{ broken"}) as root:
            result = scan(str(root))
        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.errors), 1)

    def test_ignore(self):
        with TempRepo({".envrc": "export A=1\n"}) as root:
            self.assertEqual(rules_of(scan(str(root), ignore=["tg601"])), [])

    def test_clean_repo(self):
        files = {"package.json": {"name": "ok", "scripts": {"test": "node t.js"}},
                 ".vscode/settings.json": {"editor.formatOnSave": True}, "src/app.py": "print(1)\n"}
        with TempRepo(files) as root:
            result = scan(str(root))
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 2)


if __name__ == "__main__":
    unittest.main()
