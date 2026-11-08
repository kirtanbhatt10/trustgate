"""Checks. Each module exposes check(ctx) and inspects the files it cares about."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, List, Optional

from ..models import Finding, Severity
from ..textutil import line_of, load_jsonc, printable, read_text, shorten


@dataclass
class Context:
    root: Path
    files: List[str]
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    _cache: dict = field(default_factory=dict)

    def matching(self, predicate: Callable[[PurePosixPath], bool]) -> Iterable[str]:
        for rel in self.files:
            if predicate(PurePosixPath(rel)):
                yield rel

    def text(self, rel: str) -> Optional[str]:
        if rel not in self._cache:
            self._cache[rel] = read_text(self.root / rel)
        return self._cache[rel]

    def json(self, rel: str) -> Any:
        """Parsed JSON/JSONC content, or None (parse errors are recorded, not raised)."""
        text = self.text(rel)
        if text is None:
            return None
        try:
            return load_jsonc(text)
        except ValueError as exc:
            self.errors.append(f"{rel}: could not parse as JSON ({exc})")
            return None

    def add(self, rule_id: str, rel: str, message: str, *, needle: str = "",
            evidence: str = "", severity: Optional[Severity] = None, line: int = 0) -> None:
        if not line:
            line = locate(self.text(rel) or "", needle)
        self.findings.append(Finding(rule_id, printable(rel), printable(" ".join(message.split())), line=line,
                                     severity=severity, evidence=shorten(evidence)))


def locate(text: str, needle: str) -> int:
    """Find a value in raw file text, trying its JSON-escaped form too."""
    if not needle:
        return 1
    probe = needle[:60]
    line = line_of(text, probe, 0)
    if line:
        return line
    escaped = json.dumps(probe)[1:-1]
    return line_of(text, escaped, 1)


def command_text(value: Any) -> str:
    """Render a command given as a string, an argv list or a dict of named commands."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}: {command_text(v)}" for k, v in value.items())
    return str(value)


def in_dir(path: PurePosixPath, *names: str) -> bool:
    return len(path.parts) >= 2 and path.parts[-2] in names
