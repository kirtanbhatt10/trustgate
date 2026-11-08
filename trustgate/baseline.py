"""Baselines: accept the findings you have reviewed, fail only on new ones.

A baseline is a JSON file of finding fingerprints. A fingerprint covers the rule, the file
and what is configured to run, but not the line number, so unrelated edits to a file do not
reopen a reviewed finding while a changed command does.

Any trustgate JSON report also works as a baseline.
"""

from __future__ import annotations

import json
from typing import Iterable, Set, Tuple

from . import __version__
from .models import Finding

FORMAT = "trustgate-baseline/v1"


def dump(findings: Iterable[Finding]) -> str:
    entries = sorted(({"fingerprint": f.fingerprint, "rule": f.rule_id, "path": f.path, "message": f.message}
                      for f in findings), key=lambda e: (e["path"], e["rule"], e["fingerprint"]))
    unique = list({e["fingerprint"]: e for e in entries}.values())
    doc = {"format": FORMAT, "tool": "trustgate", "version": __version__, "findings": unique}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def load(path: str) -> Set[str]:
    """Fingerprints from a baseline or a JSON report. Raises ValueError if the file is not one."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read baseline {path}: {exc.strerror or exc}") from None
    except ValueError as exc:
        raise ValueError(f"baseline {path} is not valid JSON: {exc}") from None
    findings = doc.get("findings") if isinstance(doc, dict) else None
    if not isinstance(findings, list):
        raise ValueError(f"baseline {path} has no 'findings' list; create one with 'trustgate baseline'")
    prints = {f.get("fingerprint") for f in findings if isinstance(f, dict)}
    prints.discard(None)
    return {p for p in prints if isinstance(p, str)}


def split(findings: Iterable[Finding], known: Set[str]) -> Tuple[list, int]:
    """Return (new findings, number suppressed by the baseline)."""
    new, suppressed = [], 0
    for f in findings:
        if f.fingerprint in known:
            suppressed += 1
        else:
            new.append(f)
    return new, suppressed
