"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__, baseline
from .models import RULES, Severity
from .report import to_github, to_json, to_markdown, to_sarif, to_text
from .scanner import ScanResult, scan, scan_home

FORMATS = ("text", "json", "sarif", "github", "markdown")

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustgate",
        description="Find everything a repository will execute when you open, install or build it.",
    )
    parser.add_argument("--version", action="version", version=f"trustgate {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    s = sub.add_parser("scan", help="scan a directory (default: current directory)")
    s.add_argument("path", nargs="?", default=".", help="directory to scan")
    s.add_argument("--home", action="store_true",
                   help="scan your user-level editor, agent and npm config instead of a repository")
    _common(s)
    s.add_argument("-f", "--format", choices=FORMATS, default="text",
                   help="text (default), json, sarif, github (Actions annotations) or markdown")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("--baseline", metavar="FILE",
                   help="hide findings already recorded in FILE (from 'trustgate baseline' or a JSON report)")
    s.add_argument("--min-severity", type=_severity, default=Severity.INFO, metavar="LEVEL",
                   help="hide findings below LEVEL (default: info)")
    s.add_argument("--fail-on", type=_severity, default=Severity.HIGH, metavar="LEVEL",
                   help="exit 1 if any finding is at or above LEVEL (default: high)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")

    b = sub.add_parser("baseline", help="record current findings so later scans only report new ones")
    b.add_argument("path", nargs="?", default=".", help="directory to scan")
    _common(b)
    b.add_argument("-o", "--output", default=".trustgate-baseline.json",
                   help="baseline file to write (default: .trustgate-baseline.json)")

    sub.add_parser("rules", help="list every rule")
    return parser


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--deps", action="store_true", help="also descend into node_modules")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="skip a rule id, e.g. --ignore TG600 (repeatable)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching GLOB, e.g. --exclude 'tests/fixtures/*' (repeatable)")


def _rules() -> str:
    out = []
    for rule in RULES.values():
        out.append(f"{rule.id}  {rule.severity.label:8}  {rule.name}\n      {rule.summary}")
    return "\n".join(out) + "\n"


def _write(path: Optional[str], report: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)


def _annotation_prefix(result: ScanResult) -> str:
    """Path of the scanned root relative to the working directory, for GitHub annotations."""
    try:
        rel = os.path.relpath(result.root)
    except ValueError:  # different drive on Windows
        return ""
    return "" if rel == "." or rel.startswith("..") else rel.replace(os.sep, "/")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        sys.stdout.write(_rules())
        return EXIT_OK
    if args.command not in ("scan", "baseline"):
        parser.print_help()
        return EXIT_USAGE

    unknown = [r for r in args.ignore if r.upper() not in RULES]
    if unknown:
        parser.error(f"unknown rule id(s): {', '.join(unknown)}")
    known = set()
    if getattr(args, "baseline", None):
        try:
            known = baseline.load(args.baseline)
        except ValueError as exc:
            print(f"trustgate: {exc}", file=sys.stderr)
            return EXIT_USAGE
    try:
        if getattr(args, "home", False):
            result = scan_home(ignore=args.ignore)
        else:
            result = scan(args.path, include_deps=args.deps, ignore=args.ignore, exclude=args.exclude)
    except NotADirectoryError as exc:
        print(f"trustgate: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.command == "baseline":
            _write(args.output, baseline.dump(result.findings))
            print(f"trustgate: recorded {len(result.findings)} finding(s) in {args.output}", file=sys.stderr)
            return EXIT_OK

        result.findings, result.baselined = baseline.split(result.findings, known)
        result.findings = result.at_least(args.min_severity)
        if args.format == "json":
            report = to_json(result)
        elif args.format == "sarif":
            report = to_sarif(result)
        elif args.format == "github":
            report = to_github(result, prefix=_annotation_prefix(result))
        elif args.format == "markdown":
            report = to_markdown(result)
        else:
            color = (not args.no_color and not args.output and sys.stdout.isatty()
                     and "NO_COLOR" not in os.environ)
            report = to_text(result, color=color)
        _write(args.output, report)
    except OSError as exc:
        print(f"trustgate: cannot write {args.output}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_FINDINGS if result.at_least(args.fail_on) else EXIT_OK
