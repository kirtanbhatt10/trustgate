"""Walks a directory, runs every check and returns sorted findings."""

from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable, List, Optional, Sequence

from .checks import Context, agents, build, devcontainer, hooks, node, php, python, vscode, workflows
from .models import Finding, Severity
from .unicode import find_hidden

CHECKS = (vscode, agents, node, php, python, devcontainer, hooks, workflows, build)

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".terraform", ".next", ".cache"}

AUTORUN_NAMES = {
    "tasks.json", "settings.json", "settings.local.json", "hooks.json", "mcp.json", ".mcp.json",
    ".claude.json", "package.json", "binding.gyp", ".npmrc", "setup.py", "sitecustomize.py",
    "usercustomize.py", "devcontainer.json", ".devcontainer.json", ".pre-commit-config.yaml",
    ".pre-commit-config.yml", ".envrc", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml",
    "lefthook-local.yml", "lefthook-local.yaml", ".yarnrc.yml", ".yarnrc", ".pnpmfile.cjs", "bunfig.toml",
    "pyproject.toml", "gradle-wrapper.properties",
    "composer.json",
    ".nvim.lua", ".nvimrc", ".exrc", ".vimrc",
    "build.rs", "Cargo.toml",
}

# Instruction files that AI coding agents read and follow. They do not run code, so they are
# only checked for hidden Unicode (TG001), the usual way to smuggle instructions past review.
INSTRUCTION_NAMES = {
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "GEMINI.md", ".cursorrules",
    ".windsurfrules", ".clinerules", "copilot-instructions.md",
}
INSTRUCTION_DIRS = {
    (".cursor", "rules"), (".claude", "commands"), (".claude", "agents"), (".claude", "skills"),
    (".github", "instructions"), (".github", "prompts"), (".windsurf", "rules"), (".clinerules",),
}

# User-level files worth checking after a suspected compromise (relative to $HOME).
HOME_FILES = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude.json",
    ".cursor/hooks.json", ".cursor/mcp.json", ".gemini/settings.json", ".npmrc",
    ".config/Code/User/settings.json", ".config/Code/User/tasks.json",
    ".config/Code - Insiders/User/settings.json", ".config/Code - Insiders/User/tasks.json",
    ".config/VSCodium/User/settings.json",
    ".config/Cursor/User/settings.json", ".config/Cursor/User/tasks.json",
    "Library/Application Support/Code/User/settings.json",
    "Library/Application Support/Code/User/tasks.json",
    "Library/Application Support/Code - Insiders/User/settings.json",
    "Library/Application Support/Code - Insiders/User/tasks.json",
    "Library/Application Support/Cursor/User/settings.json",
    "Library/Application Support/Cursor/User/tasks.json",
    "AppData/Roaming/Code/User/settings.json", "AppData/Roaming/Code/User/tasks.json",
    "AppData/Roaming/Code - Insiders/User/settings.json",
    "AppData/Roaming/Code - Insiders/User/tasks.json",
    "AppData/Roaming/Cursor/User/settings.json", "AppData/Roaming/Cursor/User/tasks.json",
)


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    files_scanned: int = 0
    baselined: int = 0

    def at_least(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity >= severity]


# Generic names only count inside the directories whose tools actually load them.
GENERIC_NAMES = {"tasks.json", "settings.json", "settings.local.json", "hooks.json", "mcp.json"}
GENERIC_PARENTS = {".vscode", "User", *agents.AGENT_DIRS}


def is_instruction_file(p: PurePosixPath) -> bool:
    if p.name in INSTRUCTION_NAMES:
        return True
    if p.suffix not in (".md", ".mdc", ".txt"):
        return False
    dirs = p.parts[:-1]
    return any(tuple(dirs[i:i + len(d)]) == d for d in INSTRUCTION_DIRS for i in range(len(dirs)))


def _autorun_file(p: PurePosixPath) -> bool:
    if is_instruction_file(p):
        return True
    if p.name in GENERIC_NAMES:
        return len(p.parts) >= 2 and p.parts[-2] in GENERIC_PARENTS
    if p.name in AUTORUN_NAMES or p.suffix in (".pth", ".code-workspace"):
        return True
    if ".husky" in p.parts or (len(p.parts) >= 3 and p.parts[-3:-1] == (".github", "workflows")):
        return True
    return False


def excluded(rel: str, patterns: Sequence[str]) -> bool:
    """True if rel (a POSIX path) or one of its parent directories matches a glob pattern."""
    if not patterns:
        return False
    parts = rel.split("/")
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for pattern in patterns:
        pat = pattern.replace("\\", "/").strip("/")
        if pat.startswith("./"):
            pat = pat[2:]
        if any(fnmatch.fnmatchcase(prefix, pat) for prefix in prefixes):
            return True
    return False


def walk(root: Path, include_deps: bool = False, exclude: Sequence[str] = ()) -> List[str]:
    skip = SKIP_DIRS - ({"node_modules"} if include_deps else set())
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if d not in skip
                             and not excluded(PurePosixPath(*rel_dir.parts, d).as_posix(), exclude))
        for name in sorted(filenames):
            rel = PurePosixPath(*(rel_dir.parts + (name,)))
            if (_autorun_file(rel) and not excluded(rel.as_posix(), exclude)
                    and not (root / rel_dir / name).is_symlink()):
                found.append(rel.as_posix())
    return found


def _unicode(ctx: Context) -> None:
    for rel in ctx.files:
        text = ctx.text(rel)
        if not text:
            continue
        for run in find_hidden(text):
            sev = {"tags": Severity.CRITICAL, "bidi": Severity.HIGH, "zero-width": Severity.MEDIUM}[run.kind]
            label = {"tags": "tag"}.get(run.kind, run.kind)
            ctx.add("TG001", rel, f"{run.count} hidden {label} character(s) at column {run.column}: {run.detail}",
                    line=run.line, severity=sev, evidence=run.detail)


def scan(path: str, *, include_deps: bool = False, files: Optional[Sequence[str]] = None,
         ignore: Iterable[str] = (), exclude: Sequence[str] = ()) -> ScanResult:
    root = Path(path).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {path}")
    rels = list(files) if files is not None else walk(root, include_deps, exclude)
    ctx = Context(root=root, files=rels)
    for module in CHECKS:
        module.check(ctx)
    _unicode(ctx)
    ignored = {i.upper() for i in ignore}
    findings = [f for f in ctx.findings if f.rule_id not in ignored]
    unique = {}
    for f in findings:
        unique.setdefault((f.rule_id, f.path, f.line, f.message), f)
    ordered = sorted(unique.values(), key=lambda f: (-int(f.severity), f.path, f.line, f.rule_id))
    return ScanResult(root=str(root), findings=ordered, errors=ctx.errors, files_scanned=len(rels))


def scan_home(home: Optional[str] = None, ignore: Iterable[str] = ()) -> ScanResult:
    base = Path(home or Path.home())
    present = [rel for rel in HOME_FILES if (base / rel).is_file()]
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        appdata = Path(os.environ["APPDATA"])
        if appdata.is_relative_to(base):
            seen = {PureWindowsPath(rel) for rel in present}
            for editor in ("Code", "Code - Insiders", "Cursor"):
                for name in ("settings.json", "tasks.json"):
                    rel = (appdata.relative_to(base) / editor / "User" / name).as_posix()
                    key = PureWindowsPath(rel)
                    if (base / rel).is_file() and key not in seen:
                        present.append(rel)
                        seen.add(key)
    return scan(str(base), files=present, ignore=ignore)
