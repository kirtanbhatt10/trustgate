"""Python: .pth start-up code, sitecustomize hooks and setup.py side effects."""

from __future__ import annotations

import ast
import re
from typing import Optional

from . import Context

# Calls in setup.py that run programs, evaluate code or open network connections.
RISKY_CALLS = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execvp", "os.execl", "os.spawnv",
    "os.startfile", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "exec", "eval", "compile",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urlopen", "urlretrieve",
    "requests.get", "requests.post", "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
}
TOML_TABLE = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*(?:#.*)?$")
TOML_KEY = re.compile(r"^\s*(backend-path|build-backend)\s*=\s*(.+?)\s*$")
INSTALL_COMMANDS = {"install", "develop", "egg_info", "build_py", "build_ext", "bdist_wheel", "sdist"}


def _dotted(node: ast.AST) -> Optional[str]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _setup_py(ctx: Context, rel: str) -> None:
    text = ctx.text(rel)
    if text is None:
        return
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        ctx.errors.append(f"{rel}: could not parse ({exc.msg})")
        return
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in RISKY_CALLS and (name, node.lineno) not in seen:
                seen.add((name, node.lineno))
                ctx.add("TG401", rel, f"setup.py calls {name}() at build/install time.",
                        line=node.lineno, evidence=ast.get_source_segment(text, node) or name)
            if name in ("setup", "setuptools.setup"):
                for kw in node.keywords:
                    if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                        for key in kw.value.keys:
                            if isinstance(key, ast.Constant) and key.value in INSTALL_COMMANDS:
                                ctx.add("TG401", rel, f"setup.py overrides the '{key.value}' command with custom code.",
                                        line=key.lineno, evidence=f"cmdclass[{key.value!r}]")


def _pth(ctx: Context, rel: str) -> None:
    text = ctx.text(rel)
    if text is None:
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith(("import ", "import\t")):
            ctx.add("TG400", rel, "Line is executed by Python at every interpreter start-up once installed.",
                    line=lineno, evidence=line.strip())


def _pyproject(ctx: Context, rel: str) -> None:
    """Find [build-system] backend-path without a TOML parser (tomllib needs Python 3.11)."""
    text = ctx.text(rel)
    if text is None:
        return
    table, backend, path_line, path_value = "", "", 0, ""
    for lineno, line in enumerate(text.splitlines(), 1):
        m = TOML_TABLE.match(line)
        if m:
            table = m.group(1)
            continue
        if table != "build-system":
            continue
        m = TOML_KEY.match(line)
        if m and m.group(1) == "build-backend":
            backend = m.group(2).strip("'\"")
        elif m:
            path_line, path_value = lineno, m.group(2)
    if path_line:
        name = f"'{backend}' " if backend else ""
        ctx.add("TG403", rel, f"build backend {name}is loaded from the repository (backend-path = {path_value}).",
                line=path_line, evidence=f"{backend} {path_value}".strip())


def check(ctx: Context) -> None:
    for rel in ctx.matching(lambda p: p.suffix == ".pth"):
        _pth(ctx, rel)
    for rel in ctx.matching(lambda p: p.name in ("sitecustomize.py", "usercustomize.py")):
        ctx.add("TG402", rel, f"{rel.rsplit('/', 1)[-1]} is imported automatically by Python when it is on sys.path.")
    for rel in ctx.matching(lambda p: p.name == "setup.py"):
        _setup_py(ctx, rel)
    for rel in ctx.matching(lambda p: p.name == "pyproject.toml"):
        _pyproject(ctx, rel)
