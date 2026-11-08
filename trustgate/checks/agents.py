"""AI coding agent project config: hooks, command settings, approvals and MCP servers.

Covers Claude Code (.claude/settings*.json, .mcp.json), Cursor (.cursor/hooks.json,
.cursor/mcp.json) and Gemini CLI (.gemini/settings.json). Hooks are discovered
generically, so new events or agents with the same shape are picked up too.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any, Iterator, List, Optional, Tuple

from ..models import Severity
from . import Context, command_text, in_dir
from .vscode import LOADER_ENV

AGENT_DIRS = (".claude", ".cursor", ".gemini", ".windsurf", ".codeium", ".qwen", ".kiro")

# Events that fire without the user asking the agent to do anything.
UNPROMPTED_EVENTS = {"sessionstart", "setup", "sessionend", "stop", "notification", "precompact"}

COMMAND_SETTINGS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")

NPM_EXACT_VERSION = re.compile(
    r"v?[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def _is_agent_json(p: PurePosixPath) -> bool:
    return p.suffix == ".json" and in_dir(p, *AGENT_DIRS)


def _hook_commands(hooks: Any) -> Iterator[Tuple[str, str]]:
    """Yield (event, command) for every command found under a hooks object."""
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        stack = [entries]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(reversed(node))
            elif isinstance(node, dict):
                cmd = node.get("command")
                if isinstance(cmd, (str, list)) and cmd:
                    yield str(event), command_text(cmd)
                nested = node.get("hooks")
                if isinstance(nested, (list, dict)):
                    stack.append(nested)


def _first_package_arg(tokens: List[str]) -> Optional[str]:
    for tok in tokens:
        if tok.startswith("--package="):
            return tok.split("=", 1)[1] or None
        if not tok.startswith("-"):
            return tok
    return None


def _is_npm_pinned(pkg: str) -> bool:
    rest = pkg[1:] if pkg.startswith("@") else pkg
    name, sep, ver = rest.partition("@")
    return bool(name and sep and NPM_EXACT_VERSION.fullmatch(ver))


def _is_uvx_pinned(pkg: str) -> bool:
    name, sep, ver = pkg.partition("==")
    if not sep:
        name, sep, ver = pkg.rpartition("@")
    # uv accepts concrete Python versions in both forms. Wildcards, version
    # ranges and moving tags do not select a single version.
    return bool(name and sep and re.fullmatch(r"v?[0-9][A-Za-z0-9_.!+-]*", ver))


def _is_unpinned_mcp(spec: dict) -> bool:
    raw_cmd = spec.get("command")
    tokens: List[str] = []
    if isinstance(raw_cmd, str):
        tokens.extend(raw_cmd.split())
    elif isinstance(raw_cmd, list):
        tokens.extend(str(v) for v in raw_cmd)
    else:
        return False
    raw_args = spec.get("args")
    if isinstance(raw_args, list):
        tokens.extend(str(v) for v in raw_args)
    elif isinstance(raw_args, str):
        tokens.extend(raw_args.split())
    if not tokens:
        return False
    exe = PurePosixPath(tokens[0]).name
    rest = tokens[1:]
    if exe in ("npx", "bunx"):
        pkg = _first_package_arg(rest)
        return pkg is not None and not _is_npm_pinned(pkg)
    if exe == "pnpm":
        if not rest or rest[0] != "dlx":
            return False
        pkg = _first_package_arg(rest[1:])
        return pkg is not None and not _is_npm_pinned(pkg)
    if exe == "uvx":
        pkg = _first_package_arg(rest)
        return pkg is not None and not _is_uvx_pinned(pkg)
    return False


def _mcp_servers(ctx: Context, rel: str, servers: Any) -> None:
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict) or not spec.get("command"):
            continue
        cmd = command_text(spec["command"])
        if spec.get("args"):
            cmd = f"{cmd} {command_text(spec['args'])}"
        if _is_unpinned_mcp(spec):
            msg = f"MCP server '{name}' starts a local process: {cmd} (unpinned package)"
            sev: Optional[Severity] = Severity.MEDIUM
        else:
            msg = f"MCP server '{name}' starts a local process: {cmd}"
            sev = None
        ctx.add("TG203", rel, msg, needle=f'"{name}"', evidence=cmd, severity=sev)


def _settings(ctx: Context, rel: str, data: dict) -> None:
    for event, cmd in _hook_commands(data.get("hooks")):
        sev = Severity.HIGH if event.lower() in UNPROMPTED_EVENTS else None
        ctx.add("TG200", rel, f"{event} hook runs: {cmd}", needle=event, evidence=cmd, severity=sev)

    status = data.get("statusLine")
    if isinstance(status, dict) and status.get("command"):
        cmd = command_text(status["command"])
        ctx.add("TG201", rel, f"statusLine runs a command on every refresh: {cmd}",
                needle="statusLine", evidence=cmd)
    for key in COMMAND_SETTINGS:
        if isinstance(data.get(key), str) and data[key].strip():
            ctx.add("TG201", rel, f"{key} executes: {data[key]}", needle=key, evidence=data[key])

    env = data.get("env")
    if isinstance(env, dict):
        for var, val in env.items():
            if str(var).upper() in LOADER_ENV:
                ctx.add("TG204", rel, f"Agent env sets {var}={val!s} for every tool and hook it runs.",
                        needle=str(var), evidence=f"{var}={val}")

    if data.get("enableAllProjectMcpServers") is True:
        ctx.add("TG202", rel, "enableAllProjectMcpServers auto-approves every server in .mcp.json.",
                needle="enableAllProjectMcpServers")
    perms = data.get("permissions")
    if isinstance(perms, dict):
        if perms.get("defaultMode") == "bypassPermissions":
            ctx.add("TG202", rel, "permissions.defaultMode is bypassPermissions: no approval prompts at all.",
                    needle="bypassPermissions", severity=Severity.CRITICAL)
        for entry in perms.get("allow") or []:
            if isinstance(entry, str) and entry.replace(" ", "") in ("Bash", "Bash(*)", "Bash(:*)"):
                ctx.add("TG202", rel, f"permissions.allow contains '{entry}': any shell command runs unprompted.",
                        needle=entry)
    _mcp_servers(ctx, rel, data.get("mcpServers"))
    _plugins(ctx, rel, data)


def _marketplace_source(spec: Any) -> str:
    source = spec.get("source") if isinstance(spec, dict) else None
    if isinstance(source, dict):
        for key in ("repo", "url", "path", "package"):
            if isinstance(source.get(key), str) and source[key]:
                return source[key]
    return command_text(source) if source else "(unknown source)"


def _plugins(ctx: Context, rel: str, data: dict) -> None:
    markets = data.get("extraKnownMarketplaces")
    if isinstance(markets, dict):
        for name, spec in markets.items():
            src = _marketplace_source(spec)
            ctx.add("TG205", rel, f"Adds plugin marketplace '{name}' from {src}.", needle=f'"{name}"', evidence=src)
    enabled = data.get("enabledPlugins")
    if isinstance(enabled, dict):
        for name, on in enabled.items():
            if on is True:
                ctx.add("TG205", rel, f"Enables plugin '{name}' for everyone who opens the project.",
                        needle=f'"{name}"', evidence=str(name))
    elif isinstance(enabled, list):
        for name in enabled:
            if isinstance(name, str):
                ctx.add("TG205", rel, f"Enables plugin '{name}' for everyone who opens the project.",
                        needle=f'"{name}"', evidence=name)


def check(ctx: Context) -> None:
    for rel in ctx.matching(_is_agent_json):
        data = ctx.json(rel)
        if isinstance(data, dict):
            _settings(ctx, rel, data)
    for rel in ctx.matching(lambda p: p.name in (".mcp.json", ".claude.json")):
        data = ctx.json(rel)
        if isinstance(data, dict):
            _mcp_servers(ctx, rel, data.get("mcpServers"))
