"""Known supply-chain attacks: the releases they published and the files they leave behind.

Every entry is copied from a public incident write-up, linked in ``sources``. Nothing here is
guessed: when a write-up names a package without a version, the package is left out.

The list is a starting point, not a complete record. Several of these attacks touched hundreds
of packages and the write-ups only print part of the list (see ``note``). Add campaigns with
``trustgate hit --ioc FILE`` or send a pull request; docs/campaigns.md explains both.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

ECOSYSTEMS = ("npm", "pypi")

Packages = Dict[str, Dict[str, Tuple[str, ...]]]


@dataclass(frozen=True)
class Campaign:
    id: str
    name: str
    date: str  # first public report, YYYY-MM-DD or YYYY-MM
    sources: Tuple[str, ...]
    packages: Packages  # ecosystem -> package name -> malicious versions
    files: Tuple[str, ...] = ()  # file names, or path endings when they contain a slash
    home: Tuple[str, ...] = ()  # paths relative to the home directory
    note: str = ""

    @property
    def releases(self) -> int:
        return sum(len(versions) for names in self.packages.values() for versions in names.values())


def _span(prefix: str, first: int, last: int) -> Tuple[str, ...]:
    """Consecutive releases: _span("0.7.", 4, 8) is 0.7.4, 0.7.5, 0.7.6, 0.7.7, 0.7.8."""
    return tuple(f"{prefix}{n}" for n in range(first, last + 1))


def _scoped(scope: str, names: Dict[str, Tuple[str, ...]]) -> Dict[str, Tuple[str, ...]]:
    return {f"{scope}/{name}": versions for name, versions in names.items()}


UNIT42_2026 = "https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/"

CAMPAIGNS: Tuple[Campaign, ...] = (
    Campaign(
        id="chalk-debug-2025-09",
        name="chalk / debug maintainer phishing",
        date="2025-09-08",
        sources=(
            "https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack",
            "https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack",
        ),
        packages={"npm": {
            "ansi-regex": ("6.2.1",),
            "ansi-styles": ("6.2.2",),
            "backslash": ("0.2.1",),
            "chalk": ("5.6.1",),
            "chalk-template": ("1.1.1",),
            "color": ("5.0.1",),
            "color-convert": ("3.1.1",),
            "color-name": ("2.0.1",),
            "color-string": ("2.1.1",),
            "debug": ("4.4.2",),
            "error-ex": ("1.3.3",),
            "has-ansi": ("6.0.1",),
            "is-arrayish": ("0.3.3",),
            "proto-tinker-wc": ("0.1.87",),
            "simple-swizzle": ("0.2.3",),
            "slice-ansi": ("7.1.1",),
            "strip-ansi": ("7.1.1",),
            "supports-color": ("10.2.1",),
            "supports-hyperlinks": ("4.1.1",),
            "wrap-ansi": ("9.0.1",),
            "duckdb": ("1.3.3",),
            "@duckdb/node-api": ("1.3.3",),
            "@duckdb/node-bindings": ("1.3.3",),
            "@duckdb/duckdb-wasm": ("1.29.2",),
            "@coveops/abi": ("2.0.1",),
            "prebid": ("10.9.2",),
            "prebid.js": ("10.9.2",),
            "prebid-universal-creative": ("1.17.3",),
        }},
    ),
    Campaign(
        id="shai-hulud-2025-09",
        name="Shai-Hulud npm worm",
        date="2025-09",
        sources=(
            "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/",
            "https://apiiro.com/?p=12169",
        ),
        packages={"npm": _scoped("@ctrl", {
            "deluge": ("7.2.2",),
            "golang-template": ("1.4.3",),
            "magnet-link": ("4.0.4",),
            "ngx-codemirror": ("7.0.2",),
            "ngx-csv": ("6.0.2",),
            "ngx-emoji-mart": ("9.2.2",),
            "ngx-rightclick": ("4.0.2",),
            "qbittorrent": ("9.7.2",),
            "react-adsense": ("2.0.2",),
            "shared-torrent": ("6.3.2",),
            "tinycolor": ("4.1.1", "4.1.2"),
            "torrent-file": ("4.1.2",),
            "transmission": ("7.3.1",),
            "ts-base32": ("4.0.2",),
        })},
        files=(".github/workflows/shai-hulud-workflow.yml",),
        note="Partial: only the @ctrl packages are listed; the worm republished many more.",
    ),
    Campaign(
        id="shai-hulud-2-2025-11",
        name="Shai-Hulud 2.0 npm worm",
        date="2025-11-24",
        sources=(
            "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",
            "https://safedep.io/shai-hulud-second-coming-supply-chain-attack",
        ),
        packages={},
        files=("setup_bun.js", "bun_environment.js"),
        home=(".dev-env",),
        note="Files only: the worm backdoored several hundred packages and no version list is bundled.",
    ),
    Campaign(
        id="litellm-2026-03",
        name="LiteLLM PyPI compromise",
        date="2026-03-24",
        sources=(
            "https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm",
            "https://getsafety.com/blog-posts/litellm-pypi-compromised",
        ),
        packages={"pypi": {"litellm": ("1.82.7", "1.82.8")}},
        files=("litellm_init.pth",),
        home=(".config/sysmon/sysmon.py", ".config/systemd/user/sysmon.service"),
    ),
    Campaign(
        id="axios-2026-03",
        name="axios maintainer account takeover",
        date="2026-03-31",
        sources=(
            "https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/",
            "https://safedep.io/axios-npm-supply-chain-compromise",
            "https://www.veracode.com/?p=28741",
        ),
        packages={"npm": {
            "axios": ("1.14.1", "0.30.4"),
            "plain-crypto-js": ("4.2.1",),
            "@shadanai/openclaw": ("2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"),
            "@qqbrowser/openclaw-qbot": ("0.0.130",),
            "@depup/axios": ("1.14.1-depup.0",),
        }},
    ),
    Campaign(
        id="bitwarden-cli-2026-04",
        name="Bitwarden CLI impersonation",
        date="2026-04-22",
        sources=(UNIT42_2026,),
        packages={"npm": {"@bitwarden/cli": ("2026.4.0",)}},
        files=("bw_setup.js",),
    ),
    Campaign(
        id="mini-shai-hulud-sap-2026-04",
        name="Mini Shai-Hulud SAP wave",
        date="2026-04-29",
        sources=(UNIT42_2026,),
        packages={"npm": {
            "@cap-js/sqlite": ("2.2.2",),
            "@cap-js/postgres": ("2.2.2",),
            "@cap-js/db-service": ("2.10.1",),
            "mbt": ("1.2.48",),
        }},
        files=(".vscode/setup.mjs", ".claude/execution.js"),
    ),
    Campaign(
        id="mini-shai-hulud-tanstack-2026-05",
        name="Mini Shai-Hulud TanStack wave",
        date="2026-05-11",
        sources=(
            "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral",
            UNIT42_2026,
        ),
        packages={
            "npm": {
                **_scoped("@tanstack", {
                    "arktype-adapter": ("1.166.12", "1.166.15"),
                    "eslint-plugin-router": ("1.161.9", "1.161.12"),
                    "eslint-plugin-start": ("0.0.4", "0.0.7"),
                    "history": ("1.161.9", "1.161.12"),
                    "nitro-v2-vite-plugin": ("1.154.12", "1.154.15"),
                    "react-router": ("1.169.5", "1.169.8"),
                    "react-router-devtools": ("1.166.16", "1.166.19"),
                    "react-router-ssr-query": ("1.166.15", "1.166.18"),
                    "react-start": ("1.167.68", "1.167.71"),
                    "react-start-client": ("1.166.51", "1.166.54"),
                    "react-start-rsc": ("0.0.47", "0.0.50"),
                    "react-start-server": ("1.166.55", "1.166.58"),
                    "router-cli": ("1.166.46", "1.166.49"),
                    "router-core": ("1.169.5", "1.169.8"),
                    "router-devtools": ("1.166.16", "1.166.19"),
                    "router-devtools-core": ("1.167.6", "1.167.9"),
                    "router-generator": ("1.166.45", "1.166.48"),
                    "router-plugin": ("1.167.38", "1.167.41"),
                    "router-ssr-query-core": ("1.168.3", "1.168.6"),
                    "router-utils": ("1.161.11", "1.161.14"),
                }),
                **_scoped("@mistralai", {
                    "mistralai": ("2.2.2", "2.2.3", "2.2.4"),
                    "mistralai-azure": ("1.7.1", "1.7.2", "1.7.3"),
                    "mistralai-gcp": ("1.7.1", "1.7.2", "1.7.3"),
                }),
                **_scoped("@uipath", {
                    "access-policy-sdk": ("0.3.1",),
                    "access-policy-tool": ("0.3.1",),
                    "admin-tool": ("0.1.1",),
                    "agent-sdk": ("1.0.2",),
                    "agent-tool": ("1.0.1",),
                    "agent.sdk": ("0.0.18",),
                    "aops-policy-tool": ("0.3.1",),
                    "ap-chat": ("1.5.7",),
                    "api-workflow-tool": ("1.0.1",),
                    "apollo-core": ("5.9.2",),
                    "apollo-react": ("4.24.5",),
                    "apollo-wind": ("2.16.2",),
                    "auth": ("1.0.1",),
                    "case-tool": ("1.0.1",),
                    "cli": ("1.0.1",),
                    "codedagent-tool": ("1.0.1",),
                    "codedagents-tool": ("0.1.12",),
                    "codedapp-tool": ("1.0.1",),
                    "common": ("1.0.1",),
                    "context-grounding-tool": ("0.1.1",),
                }),
                **_scoped("@squawk", {
                    "airport-data": _span("0.7.", 4, 8),
                    "airports": _span("0.6.", 2, 6),
                    "airspace": _span("0.8.", 1, 5),
                    "airspace-data": _span("0.5.", 3, 7),
                    "airway-data": _span("0.5.", 4, 8),
                    "airways": _span("0.4.", 2, 6),
                    "fix-data": _span("0.6.", 4, 8),
                    "fixes": _span("0.3.", 2, 6),
                    "flight-math": _span("0.5.", 4, 8),
                    "flightplan": _span("0.5.", 2, 6),
                    "geo": _span("0.4.", 4, 8),
                    "icao-registry": _span("0.5.", 2, 6),
                    "icao-registry-data": _span("0.8.", 4, 8),
                    "mcp": _span("0.9.", 1, 5),
                    "navaid-data": _span("0.6.", 4, 8),
                    "navaids": _span("0.4.", 2, 6),
                    "notams": _span("0.3.", 6, 10),
                    "procedure-data": _span("0.7.", 3, 7),
                    "procedures": _span("0.5.", 2, 6),
                    "types": _span("0.8.", 1, 5),
                }),
                **_scoped("@tallyui", {
                    "components": _span("1.0.", 1, 3),
                    "connector-medusa": _span("1.0.", 1, 3),
                    "connector-shopify": _span("1.0.", 1, 3),
                    "connector-vendure": _span("1.0.", 1, 3),
                    "connector-woocommerce": _span("1.0.", 1, 3),
                    "core": _span("0.2.", 1, 3),
                    "database": _span("1.0.", 1, 3),
                    "pos": _span("0.1.", 1, 3),
                    "storage-sqlite": _span("0.2.", 1, 3),
                    "theme": _span("0.2.", 1, 3),
                }),
                "@beproduct/nestjs-auth": _span("0.1.", 2, 19),
                "@draftauth/client": ("0.2.1", "0.2.2"),
                "@draftauth/core": ("0.13.1", "0.13.2"),
                "@draftlab/auth": ("0.24.1", "0.24.2"),
                "@draftlab/auth-router": ("0.5.1", "0.5.2"),
                "@draftlab/db": ("0.16.1", "0.16.2"),
                "@supersurkhet/cli": _span("0.0.", 2, 7),
                "@supersurkhet/sdk": _span("0.0.", 2, 7),
                "@taskflow-corp/cli": _span("0.1.", 24, 29),
                "@tolka/cli": _span("1.0.", 2, 6),
                "@mesadev/rest": ("0.28.3",),
                "@mesadev/saguaro": ("0.4.22",),
                "@mesadev/sdk": ("0.28.3",),
                "@ml-toolkit-ts/preprocessing": ("1.0.2", "1.0.3"),
                "@ml-toolkit-ts/xgboost": ("1.0.3", "1.0.4"),
                "@dirigible-ai/sdk": ("0.6.2", "0.6.3"),
                "@opensearch-project/opensearch": ("3.5.3", "3.6.2", "3.7.0", "3.8.0"),
                "agentwork-cli": ("0.1.4", "0.1.5"),
                "cmux-agent-mcp": _span("0.1.", 3, 8),
                "cross-stitch": _span("1.1.", 3, 7),
                "git-branch-selector": _span("1.3.", 3, 7),
                "git-git-git": _span("1.0.", 8, 12),
                "intercom-client": ("7.0.4",),
                "ml-toolkit-ts": ("1.0.4", "1.0.5"),
                "nextmove-mcp": _span("0.1.", 3, 7),
                "safe-action": ("0.8.3", "0.8.4"),
                "ts-dna": _span("3.0.", 1, 5),
                "wot-api": _span("0.8.", 1, 4),
            },
            "pypi": {
                "mistralai": ("2.4.6",),
                "guardrails-ai": ("0.10.1",),
            },
        },
        files=("tanstack_runner.js", ".claude/setup.mjs", ".claude/router_runtime.js", ".vscode/setup.mjs"),
        note="Partial: the write-up prints 20 of 42 @tanstack, 20 of 66 @uipath and 20 of 22 @squawk packages.",
    ),
    Campaign(
        id="miasma-redhat-2026-06",
        name="Miasma Red Hat Cloud Services compromise",
        date="2026-06-01",
        sources=(UNIT42_2026,),
        packages={"npm": _scoped("@redhat-cloud-services", {
            "chrome": ("2.3.1", "2.3.2"),
            "compliance-client": ("4.0.3", "4.0.4", "4.0.6"),
            "config-manager-client": ("5.0.4", "5.0.5", "5.0.7"),
            "entitlements-client": ("4.0.11", "4.0.12", "4.0.14"),
            "eslint-config-redhat-cloud-services": ("3.2.1", "3.2.2", "3.2.4"),
            "frontend-components": ("7.7.2", "7.7.3", "7.7.5"),
            "frontend-components-advisor-components": ("3.8.2", "3.8.4", "3.8.6"),
            "frontend-components-config": ("6.11.3", "6.11.4", "6.11.6"),
            "frontend-components-config-utilities": ("4.11.2", "4.11.3", "4.11.5"),
            "frontend-components-notifications": ("6.9.2", "6.9.3"),
            "frontend-components-remediations": ("4.9.2", "4.9.3", "4.9.5"),
            "frontend-components-testing": ("1.2.1", "1.2.2", "1.2.4"),
            "frontend-components-translations": ("4.4.1", "4.4.2"),
            "frontend-components-utilities": ("7.4.1", "7.4.2", "7.4.4"),
            "hcc-feo-mcp": ("0.3.1", "0.3.2", "0.3.4"),
            "hcc-kessel-mcp": ("0.3.1", "0.3.2", "0.3.4"),
            "hcc-pf-mcp": ("0.6.1", "0.6.2", "0.6.4"),
            "host-inventory-client": ("5.0.3", "5.0.4", "5.0.6"),
            "insights-client": ("4.0.4", "4.0.5", "4.0.7"),
            "integrations-client": ("6.0.4", "6.0.5", "6.0.7"),
            "javascript-clients-shared": ("2.0.8", "2.0.9", "2.0.11"),
            "notifications-client": ("6.1.4", "6.1.5", "6.1.7"),
            "patch-client": ("4.0.4", "4.0.5", "4.0.7"),
            "quickstarts-client": ("4.0.11", "4.0.12", "4.0.14"),
            "rbac-client": ("9.0.3", "9.0.4", "9.0.6"),
            "remediations-client": ("4.0.4", "4.0.5", "4.0.7"),
            "rule-components": ("4.7.2", "4.7.3"),
            "sources-client": ("3.0.10", "3.0.11", "3.0.13"),
            "topological-inventory-client": ("3.0.10", "3.0.11", "3.0.13"),
            "tsc-transform-imports": ("1.2.2", "1.2.4", "1.2.6"),
            "types": ("3.6.1", "3.6.2", "3.6.4"),
            "vulnerabilities-client": ("2.1.8", "2.1.9", "2.1.11"),
        })},
    ),
    Campaign(
        id="miasma-asyncapi-2026-07",
        name="Miasma AsyncAPI compromise",
        date="2026-07-14",
        sources=(UNIT42_2026,),
        packages={"npm": {
            "@asyncapi/generator": ("3.3.1",),
            "@asyncapi/specs": ("6.11.2", "6.11.2-alpha.1"),
            "@asyncapi/generator-helpers": ("1.1.1",),
            "@asyncapi/generator-components": ("0.7.1",),
        }},
        home=(".config/.miasma",),
    ),
)


def normalize(ecosystem: str, name: str) -> str:
    """Package names as the registry compares them (PyPI treats -, _ and . as the same)."""
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def clean_version(version: str) -> str:
    return version.strip().lstrip("=").removeprefix("v")


class Index:
    """Look-up tables over a set of campaigns."""

    def __init__(self, campaigns: Iterable[Campaign] = CAMPAIGNS) -> None:
        self.campaigns: Tuple[Campaign, ...] = tuple(campaigns)
        self._releases: Dict[Tuple[str, str, str], Campaign] = {}
        self._names: Dict[str, Campaign] = {}
        self._endings: List[Tuple[str, Campaign]] = []
        for campaign in self.campaigns:
            for ecosystem, names in campaign.packages.items():
                for name, versions in names.items():
                    for version in versions:
                        key = (ecosystem, normalize(ecosystem, name), clean_version(version))
                        self._releases.setdefault(key, campaign)
            for entry in campaign.files:
                if "/" in entry:
                    self._endings.append((entry.strip("/"), campaign))
                else:
                    self._names.setdefault(entry, campaign)

    @property
    def releases(self) -> int:
        return len(self._releases)

    def release(self, ecosystem: str, name: str, version: str) -> Optional[Campaign]:
        return self._releases.get((ecosystem, normalize(ecosystem, name), clean_version(version)))

    def file(self, rel: str) -> Optional[Tuple[str, Campaign]]:
        """The matching entry and campaign for a POSIX path relative to the scanned directory."""
        name = rel.rsplit("/", 1)[-1]
        if name in self._names:
            return name, self._names[name]
        for ending, campaign in self._endings:
            if rel == ending or rel.endswith("/" + ending):
                return ending, campaign
        return None


def _strings(value: Any, where: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError(f"{where} must be a list of non-empty strings")
    return tuple(v.strip() for v in value)


def parse(doc: Any, origin: str = "campaign file") -> List[Campaign]:
    """Campaigns from the JSON structure documented in docs/campaigns.md. Raises ValueError."""
    entries = doc.get("campaigns") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{origin} has no 'campaigns' list")
    out: List[Campaign] = []
    for n, entry in enumerate(entries, 1):
        where = f"{origin}: campaign {n}"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} is not an object")
        for key in ("id", "name"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError(f"{where} needs a non-empty '{key}'")
        where = f"{origin}: campaign '{entry['id']}'"
        packages: Packages = {}
        raw = entry.get("packages", {})
        if not isinstance(raw, dict):
            raise ValueError(f"{where}: 'packages' must be an object")
        for ecosystem, names in raw.items():
            if ecosystem not in ECOSYSTEMS:
                raise ValueError(f"{where}: unknown ecosystem '{ecosystem}' (expected npm or pypi)")
            if not isinstance(names, dict):
                raise ValueError(f"{where}: packages.{ecosystem} must be an object")
            packages[ecosystem] = {
                name: _strings(versions, f"{where}: versions of {name}") for name, versions in names.items()
            }
        date = entry.get("date", "")
        if not isinstance(date, str):
            raise ValueError(f"{where}: 'date' must be a string")
        out.append(Campaign(
            id=entry["id"].strip(),
            name=entry["name"].strip(),
            date=date.strip(),
            sources=_strings(entry.get("sources"), f"{where}: 'sources'"),
            packages=packages,
            files=_strings(entry.get("files"), f"{where}: 'files'"),
            home=_strings(entry.get("home"), f"{where}: 'home'"),
            note=str(entry.get("note", "")),
        ))
    return out


def load_file(path: str) -> List[Campaign]:
    """Campaigns from a JSON file given with --ioc. Raises ValueError with a readable message."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read campaign file {path}: {exc.strerror or exc}") from None
    except ValueError as exc:
        raise ValueError(f"campaign file {path} is not valid JSON: {exc}") from None
    return parse(doc, origin=f"campaign file {path}")
