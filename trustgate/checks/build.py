"""JVM build tools: the Gradle wrapper, which IDEs run when a project is imported."""

from __future__ import annotations

import re

from ..models import Severity
from . import Context

DISTRIBUTION_URL = re.compile(r"^\s*distributionUrl\s*[=:]\s*(.+?)\s*$")
OFFICIAL = re.compile(r"^https\\?://services\.gradle\.org/distributions(?:-snapshots)?/")


def _wrapper(ctx: Context, rel: str) -> None:
    text = ctx.text(rel)
    if text is None:
        return
    has_checksum = "distributionSha256Sum" in text
    for lineno, line in enumerate(text.splitlines(), 1):
        m = DISTRIBUTION_URL.match(line)
        if not m:
            continue
        raw = m.group(1)
        if OFFICIAL.match(raw):
            continue
        url = raw.replace("\\:", ":")
        plain_http = url.lower().startswith("http:")
        sev = Severity.HIGH if plain_http and not has_checksum else None
        note = "" if has_checksum else " with no distributionSha256Sum"
        ctx.add("TG800", rel, f"Gradle wrapper downloads Gradle from {url}{note}.", line=lineno,
                severity=sev, evidence=url)


def check(ctx: Context) -> None:
    for rel in ctx.matching(lambda p: p.name == "gradle-wrapper.properties"):
        _wrapper(ctx, rel)
