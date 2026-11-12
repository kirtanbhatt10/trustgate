"""VS Code workspace files: auto-run tasks, executable settings and terminal env."""

from __future__ import annotations

import re
from typing import Any

from ..models import Severity
from . import Context, command_text, in_dir

# Variables that make an interpreter or the dynamic loader pull in extra code.
LOADER_ENV = {
    "NODE_OPTIONS", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV",
    "PROMPT_COMMAND", "ZDOTDIR", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL",
}

EXEC_KEY = re.compile(r"(executablePath|interpreterPath|serverPath|binPath|\.tsdk|\.path|[a-z]Path)$")


def _is_workspace_path(value: str) -> bool:
    v = value.strip()
    if not v or v.startswith(("~", "/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", v):
        return False
    if v.startswith("${workspaceFolder") or v.startswith(("./", "../", ".\\", "..\\")):
        return True
    return "/" in v or "\\" in v


def _tasks(ctx: Context, rel: str, tasks: Any) -> None:
    if not isinstance(tasks, list):
        return
    for task in tasks:
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn") if isinstance(task.get("runOptions"), dict) else None
        if run_on != "folderOpen":
            continue
        label = str(task.get("label") or task.get("taskName") or "unnamed")
        cmd = command_text(task.get("command", ""))
        args = task.get("args")
        if args:
            cmd = f"{cmd} {command_text(args)}"
        ctx.add("TG100", rel, f"Task '{label}' runs automatically when the folder is opened: {cmd or '(no command)'}",
                needle='"folderOpen"', evidence=cmd)


def _settings(ctx: Context, rel: str, settings: Any) -> None:
    if not isinstance(settings, dict):
        return
    for key, value in settings.items():
        if key == "task.allowAutomaticTasks" and str(value).lower() == "on":
            ctx.add("TG103", rel, "Workspace sets task.allowAutomaticTasks to 'on'.", needle=key)
        elif key.startswith("terminal.integrated.env.") and isinstance(value, dict):
            for var, val in value.items():
                if str(var).upper() in LOADER_ENV:
                    ctx.add("TG102", rel, f"{key} sets {var}={val!s} for every integrated terminal.",
                            needle=str(var), evidence=f"{var}={val}")
        elif isinstance(value, str) and EXEC_KEY.search(key) and _is_workspace_path(value):
            sev = Severity.LOW if key == "typescript.tsdk" and "node_modules" in value else None
            ctx.add("TG101", rel, f"{key} points at a repository-controlled executable: {value}",
                    needle=key, evidence=value, severity=sev)


def _user_dir(p) -> bool:
    """VS Code user profile folder (Code/User, Code - Insiders/User, VSCodium/User, Cursor/User)."""
    return len(p.parts) >= 3 and p.parts[-2] == "User" and p.parts[-3] in ("Code", "Code - Insiders", "VSCodium", "Cursor")


def check(ctx: Context) -> None:
    for rel in ctx.matching(lambda p: (in_dir(p, ".vscode") or _user_dir(p)) and p.name == "tasks.json"):
        data = ctx.json(rel)
        if isinstance(data, dict):
            _tasks(ctx, rel, data.get("tasks"))
    for rel in ctx.matching(lambda p: (in_dir(p, ".vscode") or _user_dir(p)) and p.name == "settings.json"):
        _settings(ctx, rel, ctx.json(rel))
    for rel in ctx.matching(lambda p: p.suffix == ".code-workspace"):
        data = ctx.json(rel)
        if isinstance(data, dict):
            _settings(ctx, rel, data.get("settings"))
            tasks = data.get("tasks")
            if isinstance(tasks, dict):
                _tasks(ctx, rel, tasks.get("tasks"))
