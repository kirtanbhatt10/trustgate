"""Check a project, or this machine, against known supply-chain compromises.

"trustgate scan" answers "what will run?". "trustgate ioc" answers the question people ask
after an incident: "did I install one of the package versions, or do I have one of the files,
that public write-ups tie to a known campaign?"

Like the rest of trustgate it is offline and read-only. Lockfiles and manifests are parsed,
nothing is executed and nothing is fetched. The indicator list lives in iocdata.py.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .iocdata import CAMPAIGNS, DATA_VERSION

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

MAX_BYTES = 64 * 1024 * 1024
MAX_HOST_BYTES = 1024 * 1024
SKIP_DIRS = frozenset({".git", ".hg", ".svn"})

DESCRIPTION = ("Check lockfiles, installed packages and files against known supply-chain "
               "compromises. Offline and read-only.")

Package = Tuple[str, str, str]  # ecosystem, name, version


@dataclass(frozen=True)
class Finding:
    campaign: str
    kind: str  # package, file, script or host
    path: str
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    detail: str = ""


@dataclass
class IocResult:
    root: str
    campaigns: List[dict]
    host: bool = False
    findings: List[Finding] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    packages_checked: int = 0
    skipped: List[str] = field(default_factory=list)


class _Unreadable(Exception):
    pass


def normalize_name(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    return name


def _clean_version(version: str) -> str:
    return version.strip().lstrip("=").strip()


class Index:
    """Lookup tables built once from the campaign list."""

    def __init__(self, campaigns: Sequence[dict]) -> None:
        self.exact: Dict[Tuple[str, str, str], List[str]] = {}
        self.any: Dict[Tuple[str, str], List[str]] = {}
        self.files: Dict[str, List[Tuple[str, dict]]] = {}
        self.markers: List[Tuple[str, str]] = []
        for campaign in campaigns:
            cid = campaign["id"]
            for eco, names in campaign.get("packages", {}).items():
                for name, versions in names.items():
                    for version in versions:
                        self.exact.setdefault((eco, normalize_name(eco, name), version), []).append(cid)
            for eco, names in campaign.get("any_version", {}).items():
                for name in names:
                    self.any.setdefault((eco, normalize_name(eco, name)), []).append(cid)
            for spec in campaign.get("files", []):
                self.files.setdefault(spec["name"].lower(), []).append((cid, spec))
            for marker in campaign.get("script_markers", []):
                self.markers.append((cid, marker))

    def match_package(self, ecosystem: str, name: str, version: str) -> List[str]:
        key = normalize_name(ecosystem, name)
        return (self.exact.get((ecosystem, key, _clean_version(version)), [])
                + self.any.get((ecosystem, key), []))


# --------------------------------------------------------------------------- parsers
# Each parser takes the text of one file and yields (ecosystem, name, version).


def _npm_alias(name: str, version: str) -> Tuple[str, str]:
    """package-lock v1 stores an alias as version "npm:real-name@1.2.3"."""
    if version.startswith("npm:"):
        at = version.rfind("@")
        if at > len("npm:"):
            return version[len("npm:"):at], version[at + 1:]
    return name, version


def parse_package_lock(text: str) -> Iterator[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not isinstance(entry, dict) or "node_modules/" not in key:
                continue
            name = entry.get("name")
            if not isinstance(name, str):
                name = key.rsplit("node_modules/", 1)[1]
            version = entry.get("version")
            if isinstance(version, str):
                yield "npm", name, version
        return
    stack = [data.get("dependencies")]
    while stack:
        deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                real, real_version = _npm_alias(name, version)
                yield "npm", real, real_version
            stack.append(entry.get("dependencies"))


_YARN_VERSION = re.compile(r'^ {2}version:?\s+"?([^"\s]+)"?\s*$')
_YARN_RESOLUTION = re.compile(r'^ {2}resolution:\s+"?((?:@[^/@"\s]+/)?[^/@"\s]+)@npm:([^"\s]+)"?\s*$')


def parse_yarn_lock(text: str) -> Iterator[Package]:
    names: List[str] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace():
            names = []
            header = line.rstrip()
            if header.endswith(":"):
                for spec in header[:-1].split(","):
                    spec = spec.strip().strip("\"'")
                    at = spec.find("@", 1)
                    if at > 0 and spec[:at] not in names:
                        names.append(spec[:at])
            continue
        match = _YARN_VERSION.match(line)
        if match:
            for name in names:
                yield "npm", name, match.group(1)
            continue
        match = _YARN_RESOLUTION.match(line)
        if match and match.group(1) not in names:
            yield "npm", match.group(1), match.group(2)


_PNPM_KEY = re.compile(r"^ {2}(\S.*?):\s*$")
_PNPM_AT = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)@(\d[0-9A-Za-z.+-]*)")
_PNPM_SLASH = re.compile(r"^/((?:@[^/@]+/)?[^/@]+)/(\d[0-9A-Za-z.+-]*)")


def parse_pnpm_lock(text: str) -> Iterator[Package]:
    section = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        match = _PNPM_KEY.match(line)
        if not match:
            continue
        key = match.group(1).strip("\"'")
        hit = _PNPM_AT.match(key) or _PNPM_SLASH.match(key)
        if hit:
            yield "npm", hit.group(1), hit.group(2)


_BUN_ENTRY = re.compile(r'"((?:@[^/@"\s]+/)?[^/@"\s]+)@(\d[0-9A-Za-z.+-]*)"')


def parse_bun_lock(text: str) -> Iterator[Package]:
    for match in _BUN_ENTRY.finditer(text):
        yield "npm", match.group(1), match.group(2)


_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9A-Za-z.!+_-]+)")


def parse_requirements(text: str) -> Iterator[Package]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = _REQUIREMENT.match(line)
        if match:
            yield "pypi", match.group(1), match.group(2)


_TOML_FIELD = re.compile(r'^(name|version)\s*=\s*"([^"]*)"')


def parse_toml_lock(text: str) -> Iterator[Package]:
    """poetry.lock, uv.lock and pdm.lock: [[package]] tables with name and version."""
    in_package = False
    found: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_package = line == "[[package]]"
            found = {}
            continue
        if not in_package:
            continue
        match = _TOML_FIELD.match(line)
        if match:
            found[match.group(1)] = match.group(2)
            if len(found) == 2:
                yield "pypi", found["name"], found["version"]
                in_package = False


def parse_pipfile_lock(text: str) -> Iterator[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    for section in ("default", "develop"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            version = entry.get("version") if isinstance(entry, dict) else None
            if isinstance(version, str):
                yield "pypi", name, version


LOCKFILES: Dict[str, Callable[[str], Iterator[Package]]] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    ".package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_bun_lock,
    "poetry.lock": parse_toml_lock,
    "uv.lock": parse_toml_lock,
    "pdm.lock": parse_toml_lock,
    "Pipfile.lock": parse_pipfile_lock,
}


def _lock_parser(filename: str) -> Optional[Callable[[str], Iterator[Package]]]:
    parser = LOCKFILES.get(filename)
    if parser:
        return parser
    low = filename.lower()
    if low.endswith(".txt") and ("requirements" in low or low.startswith("constraints")):
        return parse_requirements
    return None


# --------------------------------------------------------------------------- scanning


def _read(path: str, limit: int = MAX_BYTES) -> str:
    try:
        if os.path.getsize(path) > limit:
            raise _Unreadable("larger than the size limit")
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().lstrip(chr(0xFEFF))  # UTF-8 byte order mark
    except OSError as exc:
        raise _Unreadable(exc.strerror or "unreadable") from None


def _is_package_dir(parts: Sequence[str]) -> bool:
    """True for node_modules/<name> and node_modules/@scope/<name>."""
    if len(parts) >= 2 and parts[-2] == "node_modules" and not parts[-1].startswith("@"):
        return True
    return len(parts) >= 3 and parts[-3] == "node_modules" and parts[-2].startswith("@")


def scan_path(path: str, installed: bool = True, exclude: Sequence[str] = (),
              campaigns: Optional[Sequence[dict]] = None) -> IocResult:
    """Walk path and compare what is locked, installed and on disk with the campaign list."""
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"not a directory: {path}")
    campaigns = CAMPAIGNS if campaigns is None else campaigns
    index = Index(campaigns)
    result = IocResult(root=root, campaigns=list(campaigns))
    seen: Dict[Finding, None] = {}

    def rel(full: str) -> str:
        return os.path.relpath(full, root).replace(os.sep, "/")

    def excluded(relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, glob) or fnmatch.fnmatch(relative, glob.rstrip("/") + "/*")
                   for glob in exclude)

    def check(ecosystem: str, name: str, version: str, where: str, detail: str = "") -> None:
        result.packages_checked += 1
        for cid in index.match_package(ecosystem, name, version):
            seen.setdefault(Finding(cid, "package", where, ecosystem,
                                    normalize_name(ecosystem, name), _clean_version(version), detail))

    def check_manifest(full: str, relative: str, parts: Sequence[str]) -> None:
        try:
            data = json.loads(_read(full))
        except _Unreadable as exc:
            result.skipped.append(f"{relative}: {exc}")
            return
        except (ValueError, RecursionError):
            return
        if not isinstance(data, dict):
            return
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for key, command in scripts.items():
                if not isinstance(command, str):
                    continue
                for cid, marker in index.markers:
                    if marker in command:
                        seen.setdefault(Finding(cid, "script", relative, detail=f"{key}: {command[:200]}"))
        name, version = data.get("name"), data.get("version")
        if installed and _is_package_dir(parts) and isinstance(name, str) and isinstance(version, str):
            check("npm", name, version, relative, "installed package")

    for dirpath, dirnames, filenames in os.walk(root):
        parts = [] if dirpath == root else rel(dirpath).split("/")
        in_modules = "node_modules" in parts
        keep = []
        for dirname in sorted(dirnames):
            full = os.path.join(dirpath, dirname)
            relative = rel(full)
            if dirname in SKIP_DIRS or os.path.islink(full) or excluded(relative):
                continue
            if dirname == "node_modules" and not installed:
                continue
            if installed and dirname.endswith(".dist-info"):
                name, _, version = dirname[:-len(".dist-info")].rpartition("-")
                if name:
                    check("pypi", name, version, relative, "installed distribution")
            keep.append(dirname)
        dirnames[:] = keep

        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            relative = rel(full)
            if os.path.islink(full) or excluded(relative):
                continue
            for cid, spec in index.files.get(filename.lower(), ()):
                within = spec.get("within", "")
                if not within or within in parts:
                    seen.setdefault(Finding(cid, "file", relative, detail=spec.get("note", "")))
            if filename == "package.json":
                check_manifest(full, relative, parts)
                continue
            parser = _lock_parser(filename)
            if parser is None:
                continue
            # A lockfile shipped inside a dependency describes that dependency's own
            # development setup, not what is installed here.
            if in_modules and not (filename == ".package-lock.json" and parts[-1] == "node_modules"):
                continue
            try:
                for ecosystem, name, version in parser(_read(full)):
                    check(ecosystem, name, version, relative)
                result.sources.append(relative)
            except _Unreadable as exc:
                result.skipped.append(f"{relative}: {exc}")
            except (ValueError, RecursionError):
                result.skipped.append(f"{relative}: could not be parsed")

    order = {campaign["id"]: position for position, campaign in enumerate(campaigns)}
    result.findings = sorted(seen, key=lambda f: (order[f.campaign], f.path, f.name, f.version, f.detail))
    return result


def scan_host(home: Optional[str] = None, campaigns: Optional[Sequence[dict]] = None) -> IocResult:
    """Look for artefacts that known campaigns leave on a machine, outside any project."""
    home = os.path.expanduser("~") if home is None else home
    campaigns = CAMPAIGNS if campaigns is None else campaigns
    result = IocResult(root=home, campaigns=list(campaigns), host=True)

    def expand(path: str) -> str:
        return os.path.join(home, path[2:]) if path.startswith("~/") else path

    for campaign in campaigns:
        for path in campaign.get("host_files", []):
            if os.path.lexists(expand(path)):
                result.findings.append(Finding(campaign["id"], "host", path, detail="file exists"))
        for marker in campaign.get("host_markers", []):
            for path in marker["files"]:
                try:
                    text = _read(expand(path), MAX_HOST_BYTES)
                except _Unreadable:
                    continue
                if marker["text"] in text:
                    result.findings.append(
                        Finding(campaign["id"], "host", path, detail=f"contains '{marker['text']}'"))
    return result


# --------------------------------------------------------------------------- reports


def _safe(text: str) -> str:
    """Scanned names and paths are untrusted: never let them move the cursor or hide text."""
    return "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in text)


def _describe(finding: Finding) -> str:
    if finding.kind == "package":
        line = f"package  {finding.name}@{finding.version} ({finding.ecosystem}) in {finding.path}"
        return line + (f" [{finding.detail}]" if finding.detail else "")
    if finding.kind == "script":
        return f"script   {finding.path}: {finding.detail}"
    line = f"{finding.kind:8} {finding.path}"
    return line + (f": {finding.detail}" if finding.detail else "")


def to_text(result: IocResult) -> str:
    lines = [f"trustgate ioc: checked {_safe(result.root)} against {len(result.campaigns)} "
             f"known campaign(s), data {DATA_VERSION}"]
    if not result.host:
        lines.append(f"Lockfiles read: {len(result.sources)}   "
                     f"Package records compared: {result.packages_checked}")
    grouped: Dict[str, List[Finding]] = {}
    for finding in result.findings:
        grouped.setdefault(finding.campaign, []).append(finding)
    for campaign in result.campaigns:
        hits = grouped.get(campaign["id"])
        if not hits:
            continue
        lines += ["", f"[HIT] {campaign['id']}: {campaign['name']} ({campaign['date']})"]
        lines += ["  " + _safe(_describe(finding)) for finding in hits]
        lines.append(f"  What happened: {campaign['summary']}")
        lines.append(f"  What to do: {campaign['advice']}")
        lines += [f"  Read more: {url}" for url in campaign["references"]]
    lines.append("")
    if result.findings:
        lines.append(f"{len(result.findings)} indicator(s) from {len(grouped)} campaign(s) found. "
                     "Treat each one as a lead to investigate.")
    else:
        lines.append("No indicators from the known campaigns were found.")
        lines.append("This compares against a published list; it cannot prove that a machine is clean.")
    lines += [f"Skipped {_safe(item)}" for item in result.skipped]
    return "\n".join(lines) + "\n"


def to_json(result: IocResult) -> str:
    return json.dumps({
        "tool": "trustgate ioc",
        "data_version": DATA_VERSION,
        "root": result.root,
        "mode": "host" if result.host else "path",
        "campaigns_checked": [campaign["id"] for campaign in result.campaigns],
        "lockfiles": result.sources,
        "packages_checked": result.packages_checked,
        "findings": [asdict(finding) for finding in result.findings],
        "skipped": result.skipped,
    }, indent=2) + "\n"


def list_campaigns(campaigns: Optional[Sequence[dict]] = None) -> str:
    campaigns = CAMPAIGNS if campaigns is None else campaigns
    lines = [f"trustgate ioc data {DATA_VERSION}: {len(campaigns)} campaign(s)", ""]
    for campaign in campaigns:
        versions = sum(len(v) for names in campaign.get("packages", {}).values() for v in names.values())
        versions += sum(len(names) for names in campaign.get("any_version", {}).values())
        other = (len(campaign.get("files", [])) + len(campaign.get("script_markers", []))
                 + len(campaign.get("host_files", [])) + len(campaign.get("host_markers", [])))
        lines.append(f"{campaign['id']:26} {campaign['date']:10}  {campaign['name']}")
        lines.append(f"{'':26} {versions} package indicator(s), {other} file or host indicator(s)")
    return "\n".join(lines) + "\n"


_DATE = re.compile(r"^\d{4}-\d{2}(-\d{2})?$")
_ECOSYSTEMS = ("npm", "pypi")


def validate(campaigns: Sequence[dict]) -> List[str]:
    """Return a list of problems with the campaign data (empty when it is well formed)."""
    problems: List[str] = []
    ids = set()
    for campaign in campaigns:
        cid = campaign.get("id", "?")
        if cid in ids:
            problems.append(f"{cid}: duplicate id")
        ids.add(cid)
        for key in ("id", "name", "date", "summary", "advice"):
            if not isinstance(campaign.get(key), str) or not campaign[key].strip():
                problems.append(f"{cid}: missing {key}")
        if not _DATE.match(str(campaign.get("date", ""))):
            problems.append(f"{cid}: date must be YYYY-MM or YYYY-MM-DD")
        references = campaign.get("references") or []
        if not references or not all(isinstance(u, str) and u.startswith("https://") for u in references):
            problems.append(f"{cid}: needs at least one https reference")
        indicators = 0
        for eco, names in campaign.get("packages", {}).items():
            if eco not in _ECOSYSTEMS:
                problems.append(f"{cid}: unknown ecosystem {eco}")
            for name, versions in names.items():
                indicators += len(versions)
                if name != normalize_name(eco, name):
                    problems.append(f"{cid}: {name} is not in normalised form")
                if not versions or not all(isinstance(v, str) and v == _clean_version(v) and " " not in v
                                           for v in versions):
                    problems.append(f"{cid}: bad version list for {name}")
        for eco, names in campaign.get("any_version", {}).items():
            if eco not in _ECOSYSTEMS:
                problems.append(f"{cid}: unknown ecosystem {eco}")
            indicators += len(names)
        for spec in campaign.get("files", []):
            indicators += 1
            if not spec.get("name") or "/" in spec["name"]:
                problems.append(f"{cid}: file indicators need a bare file name")
        indicators += len(campaign.get("script_markers", [])) + len(campaign.get("host_files", []))
        indicators += len(campaign.get("host_markers", []))
        if not indicators:
            problems.append(f"{cid}: no indicators")
    return problems


# --------------------------------------------------------------------------- command line


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="directory to check (default: current directory)")
    parser.add_argument("--host", action="store_true",
                        help="check this machine for artefacts known campaigns leave behind, instead of a directory")
    parser.add_argument("--no-installed", action="store_true",
                        help="read lockfiles only; do not look inside node_modules or at installed Python packages")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip paths matching GLOB (repeatable)")
    parser.add_argument("-f", "--format", choices=("text", "json"), default="text",
                        help="text (default) or json")
    parser.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    parser.add_argument("--list", action="store_true", dest="list_campaigns",
                        help="list the campaigns this version knows about and exit")


def add_parser(subparsers) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "ioc", help="check lockfiles and installed packages against known supply-chain compromises",
        description=DESCRIPTION)
    add_arguments(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    """Exit codes match "trustgate scan": 0 nothing found, 1 indicators found, 2 usage error."""
    if args.list_campaigns:
        sys.stdout.write(list_campaigns())
        return EXIT_OK
    try:
        if args.host:
            result = scan_host()
        else:
            result = scan_path(args.path, installed=not args.no_installed, exclude=args.exclude)
    except NotADirectoryError as exc:
        print(f"trustgate: {exc}", file=sys.stderr)
        return EXIT_USAGE
    report = to_json(result) if args.format == "json" else to_text(result)
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(report)
        else:
            sys.stdout.write(report)
    except OSError as exc:
        print(f"trustgate: cannot write {args.output}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_FINDINGS if result.findings else EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="trustgate ioc", description=DESCRIPTION)
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
