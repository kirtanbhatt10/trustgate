"""Lockfile readers: the exact package versions a project resolves to.

Each reader takes the file text and yields Pin(ecosystem, name, version, line). Readers never
execute anything and need no third-party parser: JSON files go through json, the YAML and TOML
lockfiles have a fixed machine-written layout and are read line by line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Iterator, Optional

from .textutil import line_of, load_jsonc


@dataclass(frozen=True)
class Pin:
    ecosystem: str
    name: str
    version: str
    line: int = 1


Reader = Callable[[str], Iterator[Pin]]


def _object(text: str) -> dict:
    doc = load_jsonc(text)
    if not isinstance(doc, dict):
        raise ValueError("expected a JSON object")
    return doc


def _alias(name: str, version: str) -> tuple:
    """npm aliases install one package under another name: "npm:real-name@1.2.3"."""
    if version.startswith("npm:"):
        real, at, pinned = version[4:].rpartition("@")
        if at and real:
            return real, pinned
    return name, version


def npm_lock(text: str) -> Iterator[Pin]:
    """package-lock.json, npm-shrinkwrap.json and node_modules/.package-lock.json (v1, v2, v3)."""
    doc = _object(text)
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.rpartition("node_modules/")[2]
            version = meta.get("version")
            if isinstance(name, str) and isinstance(version, str):
                yield Pin("npm", name, version, line_of(text, f'"{key}"'))
        return
    yield from _npm_v1(doc.get("dependencies"), text)


def _npm_v1(dependencies: Any, text: str) -> Iterator[Pin]:
    if not isinstance(dependencies, dict):
        return
    for name, meta in dependencies.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str):
            real, pinned = _alias(name, version)
            yield Pin("npm", real, pinned, line_of(text, f'"{name}"'))
        yield from _npm_v1(meta.get("dependencies"), text)


_YARN_VERSION = re.compile(r'^version:?\s+"?([^"\s]+)"?$')


def yarn_lock(text: str) -> Iterator[Pin]:
    """yarn.lock, both the classic format and Yarn Berry's YAML."""
    name: Optional[str] = None
    start = 1
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            name = None
            header = raw.rstrip()
            if header.endswith(":"):
                spec = header[:-1].split(",")[0].strip().strip("\"'")
                at = spec.find("@", 1)
                if at > 0:
                    name, wanted = spec[:at], spec[at + 1:]
                    if wanted.startswith("npm:") and wanted.find("@", 5) > 0:
                        name = wanted[4:wanted.find("@", 5)]
                    start = number
            continue
        match = _YARN_VERSION.match(raw.strip())
        if name and match:
            yield Pin("npm", name, match.group(1), start)


_PNPM_SLASH = re.compile(r"^/((?:@[^/]+/)?[^/@]+)/(\d[^_(/]*)")
_PNPM_AT = re.compile(r"^/?((?:@[^/]+/)?[^/@]+)@(\d[^_(]*)")


def pnpm_lock(text: str) -> Iterator[Pin]:
    """pnpm-lock.yaml: /name/1.2.3 (v5), /name@1.2.3 (v6) and name@1.2.3 (v9) keys."""
    section = ""
    for number, raw in enumerate(text.splitlines(), 1):
        if raw and not raw[0].isspace():
            section = raw.split(":")[0].strip()
            continue
        if section not in ("packages", "snapshots") or not raw.startswith("  ") or raw[2:3].isspace():
            continue
        key = raw.strip()
        if not key.endswith(":"):
            continue
        key = key[:-1].strip().strip("\"'")
        match = _PNPM_SLASH.match(key) or _PNPM_AT.match(key)
        if match:
            yield Pin("npm", match.group(1), match.group(2), number)


def bun_lock(text: str) -> Iterator[Pin]:
    """bun.lock (the text lockfile; the older binary bun.lockb cannot be read)."""
    packages = _object(text).get("packages")
    if not isinstance(packages, dict):
        return
    for entry in packages.values():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            name, at, version = entry[0].rpartition("@")
            if at and name:
                yield Pin("npm", name, version.removeprefix("npm:"), line_of(text, f'"{entry[0]}"'))


_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)


def requirements(text: str) -> Iterator[Pin]:
    """requirements.txt style files; only exact pins (name==1.2.3) say what gets installed."""
    for number, raw in enumerate(text.splitlines(), 1):
        match = _REQUIREMENT.match(raw)
        if match:
            yield Pin("pypi", match.group(1), match.group(2), number)


_TOML_FIELD = re.compile(r'^(name|version)\s*=\s*"([^"]*)"')


def toml_lock(text: str) -> Iterator[Pin]:
    """poetry.lock, uv.lock and pdm.lock: a list of [[package]] tables with name and version."""
    fields: dict = {}
    start = 1
    inside = False
    for number, raw in enumerate(text.splitlines() + ["["], 1):
        line = raw.strip()
        if line.startswith("["):
            if inside and "name" in fields and "version" in fields:
                yield Pin("pypi", fields["name"], fields["version"], start)
            inside, fields, start = line == "[[package]]", {}, number
        elif inside:
            match = _TOML_FIELD.match(line)
            if match:
                fields.setdefault(match.group(1), match.group(2))


def pipfile_lock(text: str) -> Iterator[Pin]:
    doc = _object(text)
    for section in ("default", "develop"):
        names = doc.get(section)
        if not isinstance(names, dict):
            continue
        for name, meta in names.items():
            version = meta.get("version") if isinstance(meta, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                yield Pin("pypi", name, version[2:], line_of(text, f'"{name}"'))


_BY_NAME = {
    "package-lock.json": npm_lock,
    "npm-shrinkwrap.json": npm_lock,
    ".package-lock.json": npm_lock,
    "yarn.lock": yarn_lock,
    "pnpm-lock.yaml": pnpm_lock,
    "bun.lock": bun_lock,
    "poetry.lock": toml_lock,
    "uv.lock": toml_lock,
    "pdm.lock": toml_lock,
    "Pipfile.lock": pipfile_lock,
}


def reader_for(path: PurePosixPath) -> Optional[Reader]:
    """The reader for a lockfile path, or None if the file is not a lockfile trustgate knows."""
    reader = _BY_NAME.get(path.name)
    if reader:
        return reader
    if path.suffix == ".txt" and (path.name.startswith(("requirements", "constraints"))
                                  or path.parent.name == "requirements"):
        return requirements
    return None
