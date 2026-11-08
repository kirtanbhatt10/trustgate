"""Core data types: severities, rules and findings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (expected one of: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    def bump(self, steps: int = 1) -> "Severity":
        return Severity(min(int(self) + steps, int(Severity.CRITICAL)))


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    summary: str
    remediation: str


RULES: Dict[str, Rule] = {}


def _rule(rule_id: str, name: str, severity: Severity, summary: str, remediation: str) -> None:
    RULES[rule_id] = Rule(rule_id, name, severity, summary, remediation)


_rule("TG001", "hidden-unicode", Severity.HIGH,
      "Invisible or bidirectional Unicode characters in a file that tools or agents execute or obey.",
      "Remove the characters. Legitimate config files almost never need them.")
_rule("TG100", "vscode-folder-open-task", Severity.HIGH,
      "A VS Code task is configured to run automatically when the folder is opened.",
      "Delete the task or remove runOptions.runOn unless you wrote it yourself.")
_rule("TG101", "vscode-workspace-executable", Severity.MEDIUM,
      "A workspace setting points an extension at an executable inside the repository.",
      "Point the setting at a trusted, system-installed binary or remove it from the workspace settings.")
_rule("TG102", "vscode-terminal-env", Severity.HIGH,
      "Workspace settings inject environment variables that load code into every terminal process.",
      "Remove the variable from terminal.integrated.env.* in the workspace settings.")
_rule("TG103", "vscode-auto-tasks-setting", Severity.MEDIUM,
      "Workspace settings try to allow automatic tasks without asking.",
      "Remove task.allowAutomaticTasks from the workspace settings.")
_rule("TG200", "agent-hook", Severity.MEDIUM,
      "An AI coding agent hook runs a shell command on agent events.",
      "Review the command. Only keep hooks you added yourself.")
_rule("TG201", "agent-command-setting", Severity.MEDIUM,
      "An AI agent setting executes a shell command (status line, API key helper).",
      "Review the command or move the setting to your user-level config.")
_rule("TG202", "agent-auto-approve", Severity.HIGH,
      "Project settings weaken the agent's approval prompts.",
      "Remove the setting from the project; grant broad permissions only in your own user config.")
_rule("TG203", "mcp-server-autostart", Severity.LOW,
      "A project-level MCP server will be launched as a local process by the agent.",
      "Confirm the server package and arguments are expected and pinned.")
_rule("TG204", "agent-env-injection", Severity.HIGH,
      "Agent settings inject environment variables that load code into child processes.",
      "Remove the variable from the agent's env settings.")
_rule("TG205", "agent-plugin-enable", Severity.MEDIUM,
      "Project settings enable agent plugins or add plugin marketplaces; plugins can bring their own hooks and MCP servers.",
      "Remove enabledPlugins / extraKnownMarketplaces from the project settings and install plugins yourself.")
_rule("TG300", "npm-lifecycle-script", Severity.MEDIUM,
      "package.json defines a script that npm runs automatically on install.",
      "Install with --ignore-scripts and review the script before running it.")
_rule("TG301", "node-gyp-exec", Severity.MEDIUM,
      "binding.gyp triggers an implicit install build or runs shell command expansions.",
      "Review every <!( ) expansion; install with --ignore-scripts until reviewed.")
_rule("TG302", "npmrc-risk", Severity.MEDIUM,
      "A project .npmrc changes how npm executes scripts, where it downloads from, or contains a token.",
      "Remove the setting from the committed .npmrc; keep tokens in your user config or CI secrets.")
_rule("TG303", "package-manager-exec", Severity.MEDIUM,
      "Package manager config makes yarn, pnpm or bun run JavaScript from the repository on every command or install.",
      "Read the referenced file before running the package manager; remove the setting if you did not expect it.")
_rule("TG400", "python-pth-exec", Severity.HIGH,
      "A .pth file contains import lines, which Python executes at interpreter start-up.",
      "Delete the .pth file or reduce it to plain path entries.")
_rule("TG401", "setup-py-exec", Severity.MEDIUM,
      "setup.py runs commands or fetches code at build/install time.",
      "Build in an isolated environment and review the setup.py code paths.")
_rule("TG402", "python-startup-hook", Severity.MEDIUM,
      "sitecustomize.py or usercustomize.py is shipped and runs whenever it lands on sys.path.",
      "Remove the file unless the project explicitly documents why it needs it.")
_rule("TG403", "python-local-build-backend", Severity.MEDIUM,
      "pyproject.toml uses an in-tree build backend (backend-path), so pip runs repository code to build or install.",
      "Read the backend module before running pip install; prefer a published build backend.")
_rule("TG500", "devcontainer-host-command", Severity.HIGH,
      "devcontainer initializeCommand runs on your host machine, outside the container.",
      "Review the command; it has full access to your machine.")
_rule("TG501", "devcontainer-lifecycle-command", Severity.LOW,
      "A dev container lifecycle command runs automatically inside the container.",
      "Review the command, especially if secrets or your SSH agent are forwarded.")
_rule("TG600", "git-hook-script", Severity.LOW,
      "A git hook manager will run repository scripts on git operations.",
      "Read the hook scripts before running the project's install or setup step.")
_rule("TG601", "direnv-envrc", Severity.MEDIUM,
      "An .envrc file runs shell code when you cd into the directory (once allowed).",
      "Read the file before running 'direnv allow'.")
_rule("TG700", "workflow-secret-dump", Severity.CRITICAL,
      "A GitHub Actions workflow serialises the entire secrets context.",
      "Delete the workflow and rotate every repository and organisation secret.")
_rule("TG701", "workflow-untrusted-exec", Severity.HIGH,
      "A workflow interpolates attacker-controlled event text directly into a shell step.",
      "Pass the value through an environment variable and never execute it.")
_rule("TG800", "gradle-wrapper-distribution", Severity.MEDIUM,
      "The Gradle wrapper downloads Gradle from a non-official location; IDEs run it when the project is imported.",
      "Point distributionUrl at https://services.gradle.org/distributions/ and add distributionSha256Sum.")


@dataclass
class Finding:
    rule_id: str
    path: str
    message: str
    line: int = 1
    severity: Optional[Severity] = None
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.rule_id not in RULES:
            raise KeyError(f"unknown rule id {self.rule_id}")
        if self.severity is None:
            self.severity = RULES[self.rule_id].severity
        if self.line < 1:
            self.line = 1

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def fingerprint(self) -> str:
        raw = "\x1f".join((self.rule_id, self.path, self.evidence or self.message))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "name": self.rule.name,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.rule.remediation,
            "fingerprint": self.fingerprint,
        }
