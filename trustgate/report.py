"""Output formats: human-readable text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
import os
import re
from collections import Counter

from . import __version__
from .models import RULES, Severity
from .scanner import ScanResult

COLORS = {
    Severity.CRITICAL: "\033[1;35m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[37m",
}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"

SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_text(result: ScanResult, color: bool = False) -> str:
    def paint(code: str, s: str) -> str:
        return f"{code}{s}{RESET}" if color else s

    lines = [paint(BOLD, f"trustgate {__version__}") + f"  {_display_root(result.root)}  ({_files(result)})", ""]
    if not result.findings:
        lines.append("No new auto-run entry points found." if result.baselined else "No auto-run entry points found.")
        lines.append("")
    for f in result.findings:
        tag = paint(COLORS[f.severity], f"{f.severity.label.upper():8}")
        lines.append(f"{tag} {f.rule_id} {f.rule.name}  {f.path}:{f.line}")
        lines.append(f"         {f.message}")
        lines.append(paint(DIM, f"         fix: {f.rule.remediation}"))
        lines.append("")
    for err in result.errors:
        lines.append(paint(DIM, f"warning: {err}"))
    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True)) or "0 findings"
    if result.baselined:
        summary += f" ({result.baselined} accepted by baseline)"
    lines.append(f"Summary: {summary}")
    return "\n".join(lines) + "\n"


def _display_root(root: str) -> str:
    """Show the scanned directory with the home directory abbreviated to ~."""
    home = os.path.expanduser("~")
    if home and home not in ("~", os.sep) and (root == home or root.startswith(home.rstrip(os.sep) + os.sep)):
        return "~" + root[len(home.rstrip(os.sep)):]
    return root


def _files(result: ScanResult) -> str:
    return f"{result.files_scanned} file{'' if result.files_scanned == 1 else 's'} checked"


def to_json(result: ScanResult) -> str:
    counts = Counter(f.severity.label for f in result.findings)
    doc = {
        "tool": "trustgate",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "baselined": result.baselined,
        "summary": {s.label: counts.get(s.label, 0) for s in sorted(Severity, reverse=True)},
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def to_sarif(result: ScanResult) -> str:
    rule_ids = sorted({f.rule_id for f in result.findings})
    rules = [{
        "id": rid,
        "name": RULES[rid].name,
        "shortDescription": {"text": RULES[rid].summary},
        "help": {"text": RULES[rid].remediation},
        "defaultConfiguration": {"level": SARIF_LEVEL[RULES[rid].severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[RULES[rid].severity],
                       "tags": ["security", "supply-chain"]},
    } for rid in rule_ids]
    results = [{
        "ruleId": f.rule_id,
        "ruleIndex": rule_ids.index(f.rule_id),
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": f.line},
        }}],
        "partialFingerprints": {"trustgate/v1": f.fingerprint},
        "properties": {"severity": f.severity.label, "security-severity": SECURITY_SEVERITY[f.severity]},
    } for f in result.findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trustgate", "version": __version__,
                                "informationUri": "https://github.com/kirtanbhatt10/trustgate",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


GITHUB_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "notice", Severity.INFO: "notice"}


def _gh_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_prop(value: str) -> str:
    return _gh_data(value).replace(":", "%3A").replace(",", "%2C")


def to_github(result: ScanResult, prefix: str = "") -> str:
    """GitHub Actions workflow commands: one annotation per finding on the file and line."""
    lines = []
    for f in result.findings:
        path = f"{prefix.rstrip('/')}/{f.path}" if prefix and prefix != "." else f.path
        title = f"{f.rule_id} {f.rule.name} ({f.severity.label})"
        body = f"{f.message} Fix: {f.rule.remediation}"
        lines.append(f"::{GITHUB_LEVEL[f.severity]} file={_gh_prop(path)},line={f.line},"
                     f"title={_gh_prop(title)}::{_gh_data(body)}")
    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True)) or "0 findings"
    lines.append(f"trustgate {__version__}: {summary}"
                 + (f" ({result.baselined} accepted by baseline)" if result.baselined else ""))
    return "\n".join(lines) + "\n"


MD_SPECIAL = re.compile(r"([\\`*_\[\]()!#~>|])")


def _md(value: str) -> str:
    """Escape text so repository content cannot add links, images or HTML to the summary."""
    value = value.replace("\n", " ").replace("&", "&amp;").replace("<", "&lt;")
    return MD_SPECIAL.sub(r"\\\1", value)


def _md_code(value: str) -> str:
    return value.replace("`", "'").replace("|", "\\|").replace("\n", " ")


def to_markdown(result: ScanResult) -> str:
    """A Markdown summary for GitHub job summaries and pull request comments."""
    counts = Counter(f.severity for f in result.findings)
    out = ["### trustgate", ""]
    if not result.findings:
        out.append("No new auto-run entry points found." if result.baselined else "No auto-run entry points found.")
    else:
        badges = " · ".join(f"**{counts[s]}** {s.label}" for s in sorted(counts, reverse=True))
        out += [badges, "", "| Severity | Rule | Location | What runs |", "|---|---|---|---|"]
        for f in result.findings:
            out.append(f"| {f.severity.label} | `{f.rule_id}` {f.rule.name} | `{_md_code(f.path)}:{f.line}` | {_md(f.message)} |")
    extra = f" · {result.baselined} accepted by baseline" if result.baselined else ""
    out += ["", f"<sub>trustgate {__version__} · {_files(result)}{extra}</sub>", ""]
    return "\n".join(out)
