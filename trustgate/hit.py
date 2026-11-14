"""Am I hit? Match lockfiles, installed packages and dropped files against known attacks.

`trustgate scan` shows what a repository would run. `trustgate hit` answers the question that
follows an incident report: does this project resolve to one of the releases that were
published by the attacker, and is one of the files the malware drops sitting on this machine?

Like the rest of trustgate it only reads files: no network, no package manager, no execution.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .campaigns import Campaign, Index
from .lockfiles import Pin, reader_for
from .models import Finding
from .report import BOLD, COLORS, DIM, RESET, _display_root
from .scanner import SKIP_DIRS, ScanResult, excluded
from .textutil import load_jsonc, printable, read_text, shorten

# Skipped by default like everywhere else in trustgate; --deps reads them.
DEP_DIRS = {"node_modules", ".venv", "venv"}

_DIST_INFO = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")


def _source(campaign: Campaign) -> str:
    return f" Details: {campaign.sources[0]}" if campaign.sources else ""


def _label(campaign: Campaign) -> str:
    return f"{campaign.name}, {campaign.date}" if campaign.date else campaign.name


def _release(rel: str, pin: Pin, campaign: Campaign) -> Finding:
    message = (f"{pin.name} {pin.version} ({pin.ecosystem}) is a known-malicious release "
               f"({_label(campaign)}).{_source(campaign)}")
    return Finding("TG900", printable(rel), printable(" ".join(message.split())), line=pin.line,
                   evidence=shorten(f"{pin.ecosystem}:{pin.name}@{pin.version}"))


def _artifact(rel: str, entry: str, campaign: Campaign, kind: str = "file") -> Finding:
    message = (f"This {kind} has the name of a known payload or persistence file, '{entry}' "
               f"({_label(campaign)}).{_source(campaign)}")
    return Finding("TG901", printable(rel), printable(" ".join(message.split())),
                   evidence=shorten(f"{campaign.id}:{entry}"))


def _finish(root: Path, findings: List[Finding], errors: List[str], checked: int,
            ignore: Iterable[str]) -> ScanResult:
    ignored = {i.upper() for i in ignore}
    unique: Dict[Tuple[str, str, str], Finding] = {}
    for f in findings:
        if f.rule_id not in ignored:
            unique.setdefault((f.rule_id, f.path, f.evidence), f)
    ordered = sorted(unique.values(), key=lambda f: (-int(f.severity), f.path, f.line, f.rule_id))
    return ScanResult(root=str(root), findings=ordered, errors=errors, files_scanned=checked)


def _manifest(text: str) -> Optional[Pin]:
    """Name and version of an installed npm package from its package.json."""
    try:
        doc = load_jsonc(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    name, version = doc.get("name"), doc.get("version")
    if isinstance(name, str) and isinstance(version, str):
        return Pin("npm", name, version, 1)
    return None


def check(path: str, *, include_deps: bool = False, exclude: Sequence[str] = (),
          ignore: Iterable[str] = (), index: Optional[Index] = None) -> ScanResult:
    """Check every lockfile under path, and with include_deps what is actually installed."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {path}")
    index = index or Index()
    skip = SKIP_DIRS - (DEP_DIRS if include_deps else set())
    findings: List[Finding] = []
    errors: List[str] = []
    checked = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        kept = []
        for name in sorted(dirnames):
            rel = PurePosixPath(*rel_dir.parts, name).as_posix()
            if name in skip or excluded(rel, exclude):
                continue
            kept.append(name)
            dist = _DIST_INFO.match(name)
            if dist:  # an installed Python distribution, e.g. litellm-1.82.8.dist-info
                checked += 1
                pin = Pin("pypi", dist.group(1), dist.group(2))
                campaign = index.release(pin.ecosystem, pin.name, pin.version)
                if campaign:
                    findings.append(_release(rel, pin, campaign))
        dirnames[:] = kept
        installed = "node_modules" in rel_dir.parts
        for name in sorted(filenames):
            rel_path = PurePosixPath(*rel_dir.parts, name)
            rel = rel_path.as_posix()
            if excluded(rel, exclude) or (root / rel_dir / name).is_symlink():
                continue
            dropped = index.file(rel)
            if dropped:
                findings.append(_artifact(rel, *dropped))
            reader = reader_for(rel_path)
            if reader is None and not (installed and name == "package.json"):
                continue
            text = read_text(root / rel_dir / name)
            if text is None:
                continue
            checked += 1
            if reader is None:
                manifest = _manifest(text)
                pins = [manifest] if manifest else []
            else:
                try:
                    pins = list(reader(text))
                except ValueError as exc:
                    errors.append(f"{printable(rel)}: could not parse ({exc})")
                    continue
            for pin in pins:
                campaign = index.release(pin.ecosystem, pin.name, pin.version)
                if campaign:
                    findings.append(_release(rel, pin, campaign))
    return _finish(root, findings, errors, checked, ignore)


def check_home(home: Optional[str] = None, *, ignore: Iterable[str] = (),
               index: Optional[Index] = None) -> ScanResult:
    """Look in the home directory for files and folders that known campaigns leave behind."""
    base = Path(home or Path.home())
    index = index or Index()
    findings: List[Finding] = []
    checked = 0
    for campaign in index.campaigns:
        for entry in campaign.home:
            checked += 1
            target = base / entry
            if os.path.lexists(target):
                kind = "folder" if target.is_dir() and not target.is_symlink() else "file"
                findings.append(_artifact(PurePosixPath(entry).as_posix(), entry, campaign, kind))
    return _finish(base, findings, [], checked, ignore)


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def coverage(index: Index) -> str:
    return f"{_plural(index.releases, 'known-bad release')} from {_plural(len(index.campaigns), 'campaign')}"


def to_text(result: ScanResult, index: Index, color: bool = False, home: bool = False) -> str:
    def paint(code: str, s: str) -> str:
        return f"{code}{s}{RESET}" if color else s

    if home:
        looked = _plural(result.files_scanned, "known location")
    elif result.files_scanned == 1:
        looked = "1 lockfile or manifest"
    else:
        looked = f"{result.files_scanned} lockfiles and manifests"
    lines = [paint(BOLD, f"trustgate {__version__}") + f"  hit  {_display_root(result.root)}  "
             f"({looked} checked against {coverage(index)})", ""]
    if not result.findings:
        lines.append("No known-malicious release and no known campaign file found.")
        lines.append("")
    for f in result.findings:
        tag = paint(COLORS[f.severity], f"{f.severity.label.upper():8}")
        lines.append(f"{tag} {f.rule_id} {f.rule.name}  {f.path}:{f.line}")
        lines.append(f"         {f.message}")
        lines.append(paint(DIM, f"         fix: {f.rule.remediation}"))
        lines.append("")
    for err in result.errors:
        lines.append(paint(DIM, f"warning: {err}"))
    if not home and result.files_scanned == 0:
        lines.append(paint(DIM, "warning: no lockfile found here, so there was nothing to compare"))
    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True)) or "0 findings"
    lines.append(f"Summary: {summary}")
    if not result.findings:
        lines.append(paint(DIM, "A clean result is not proof of safety: only the campaigns in "
                                "'trustgate hit --list' are covered."))
    return "\n".join(lines) + "\n"


def listing(index: Index) -> str:
    """The campaigns in the index, newest first, for `trustgate hit --list`."""
    out = []
    for campaign in sorted(index.campaigns, key=lambda c: c.date, reverse=True):
        parts = []
        if campaign.releases:
            parts.append(_plural(campaign.releases, "release"))
        if campaign.files or campaign.home:
            parts.append(_plural(len(campaign.files) + len(campaign.home), "file"))
        out.append(f"{printable(campaign.id)}  {printable(campaign.date) or '-':10}  {printable(campaign.name)}")
        out.append(f"      {', '.join(parts) or 'no indicators'}")
        if campaign.note:
            out.append(f"      {printable(campaign.note)}")
        for source in campaign.sources:
            out.append(f"      {printable(source)}")
    out.append(f"{coverage(index)}.")
    return "\n".join(out) + "\n"
