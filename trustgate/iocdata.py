"""Known supply-chain compromises checked by "trustgate ioc".

Each campaign is a plain dict so that adding one is a data-only change:

    id              stable identifier, shown in reports
    name, date      human title and the day (or month) the compromise was published
    summary         one or two sentences on what happened
    advice          what to do if an indicator is found
    references      public write-ups the indicators were taken from (required)
    packages        {ecosystem: {package name: [exact malicious versions]}}
    any_version     {ecosystem: [package names that are malicious at every version]}
    files           [{"name": file name, "within": path component it must sit under, "note": why}]
    script_markers  text that only appears in infected package.json scripts
    host_files      artefacts the malware leaves on a machine ("~/" means the home directory)
    host_markers    [{"files": [...], "text": "..."}] text the malware adds to existing files

Only indicators confirmed by the linked write-ups belong here. Newest campaign first.
"""

from __future__ import annotations

DATA_VERSION = "2026.11.15"

ROTATE = ("Assume every secret reachable from that machine or CI job was read: rotate npm, PyPI, "
          "GitHub and cloud credentials and SSH keys, then reinstall from a clean lockfile.")

CAMPAIGNS = [
    {
        "id": "asyncapi-2026-07",
        "name": "AsyncAPI release pipeline compromise",
        "date": "2026-07-14",
        "summary": "Attackers took over the release pipelines of AsyncAPI repositories and published "
                   "trojanised packages to npm. This list is partial: one of the five packages is covered.",
        "advice": ROTATE,
        "references": ["https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/"],
        "packages": {"npm": {"@asyncapi/generator": ["3.3.1"]}},
    },
    {
        "id": "tanstack-mistral-2026-05",
        "name": "TanStack / Mistral AI worm (npm and PyPI)",
        "date": "2026-05-11",
        "summary": "A self-spreading worm entered through a CI pipeline and republished itself across npm "
                   "scopes and two PyPI projects. The npm side is detected by its payload file name.",
        "advice": ROTATE,
        "references": [
            "https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral",
            "https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/",
        ],
        "packages": {"pypi": {"mistralai": ["2.4.6"], "guardrails-ai": ["0.10.1"]}},
        "files": [
            {"name": "tanstack_runner.js", "within": "node_modules",
             "note": "payload file name used by this worm"},
        ],
    },
    {
        "id": "bitwarden-cli-2026-04",
        "name": "Malicious @bitwarden/cli release",
        "date": "2026-04",
        "summary": "A malicious package was published to npm as @bitwarden/cli 2026.4.0 as part of a wider "
                   "campaign against developer tooling.",
        "advice": ROTATE,
        "references": ["https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/"],
        "packages": {"npm": {"@bitwarden/cli": ["2026.4.0"]}},
    },
    {
        "id": "axios-2026-03",
        "name": "axios maintainer account takeover",
        "date": "2026-03-31",
        "summary": "Two axios releases added a dependency, plain-crypto-js, whose install script drops a "
                   "remote access trojan. The plain-crypto-js package exists only for this attack.",
        "advice": "Downgrade to axios 1.14.0 or 0.30.3 and delete node_modules. " + ROTATE,
        "references": [
            "https://endorlabs.com/learn/npm-axios-compromise",
            "https://www.chainguard.dev/unchained/malicious-axios-versions-published-to-npm-chainguard-customers-protected",
        ],
        "packages": {"npm": {"axios": ["1.14.1", "0.30.4"]}},
        "any_version": {"npm": ["plain-crypto-js"]},
    },
    {
        "id": "litellm-2026-03",
        "name": "LiteLLM PyPI backdoor",
        "date": "2026-03-24",
        "summary": "Two litellm releases on PyPI carried a credential stealer. Version 1.82.8 also installs "
                   "litellm_init.pth, which runs on every Python start-up without any import.",
        "advice": "Install litellm 1.82.6 or a later fixed release and remove litellm_init.pth from "
                  "site-packages and package caches. " + ROTATE,
        "references": [
            "https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm",
            "https://labs.boostsecurity.io/articles/teampcp-litellm-supply-chain-compromise/",
        ],
        "packages": {"pypi": {"litellm": ["1.82.7", "1.82.8"]}},
        "files": [{"name": "litellm_init.pth", "note": "start-up hook shipped in litellm 1.82.8"}],
    },
    {
        "id": "shai-hulud-2-2025-11",
        "name": "Shai-Hulud 2.0 npm worm",
        "date": "2025-11",
        "summary": "Infected packages gained a preinstall script that runs setup_bun.js, which installs the "
                   "Bun runtime and starts the bun_environment.js payload. Hundreds of packages were hit, "
                   "so this is detected by those files, not by a version list.",
        "advice": "Check your GitHub account for repositories you did not create. " + ROTATE,
        "references": [
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/",
            "https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised",
        ],
        "files": [
            {"name": "setup_bun.js", "within": "node_modules", "note": "dropper added to infected packages"},
            {"name": "bun_environment.js", "within": "node_modules", "note": "worm payload"},
        ],
        "script_markers": ["setup_bun.js", "bun_environment.js"],
    },
    {
        "id": "qix-2025-09",
        "name": "chalk / debug maintainer phishing",
        "date": "2025-09-08",
        "summary": "A phished maintainer account published versions of chalk, debug and related packages "
                   "containing a browser-side cryptocurrency stealer.",
        "advice": "Move to the next clean release of each package and rebuild any front-end bundle that was "
                  "built while these versions were installed.",
        "references": [
            "https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack",
            "https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack",
        ],
        "packages": {"npm": {
            "ansi-regex": ["6.2.1"],
            "ansi-styles": ["6.2.2"],
            "backslash": ["0.2.1"],
            "chalk": ["5.6.1"],
            "chalk-template": ["1.1.1"],
            "color": ["5.0.1"],
            "color-convert": ["3.1.1"],
            "color-name": ["2.0.1"],
            "color-string": ["2.1.1"],
            "debug": ["4.4.2"],
            "error-ex": ["1.3.3"],
            "has-ansi": ["6.0.1"],
            "is-arrayish": ["0.3.3"],
            "simple-swizzle": ["0.2.3"],
            "slice-ansi": ["7.1.1"],
            "strip-ansi": ["7.1.1"],
            "supports-color": ["10.2.1"],
            "supports-hyperlinks": ["4.1.1"],
            "wrap-ansi": ["9.0.1"],
            "duckdb": ["1.3.3"],
            "@duckdb/node-api": ["1.3.3"],
            "@duckdb/node-bindings": ["1.3.3"],
            "@duckdb/duckdb-wasm": ["1.29.2"],
            "@coveops/abi": ["2.0.1"],
            "prebid": ["10.9.2"],
            "prebid.js": ["10.9.2"],
            "prebid-universal-creative": ["1.17.3"],
            "proto-tinker-wc": ["0.1.87"],
        }},
    },
    {
        "id": "shai-hulud-2025-09",
        "name": "Shai-Hulud npm worm (first wave)",
        "date": "2025-09",
        "summary": "The first Shai-Hulud worm stole tokens and added a GitHub Actions workflow named "
                   "shai-hulud-workflow.yml to repositories it could write to.",
        "advice": "Delete the workflow, review recent commits and workflow runs. " + ROTATE,
        "references": ["https://www.zscaler.com/blogs/security-research/shai-hulud-v2-poses-risk-npm-supply-chain"],
        "files": [{"name": "shai-hulud-workflow.yml", "note": "workflow planted by the worm"}],
    },
    {
        "id": "nx-s1ngularity-2025-08",
        "name": "Nx build system compromise (s1ngularity)",
        "date": "2025-08-26",
        "summary": "Malicious Nx releases ran a postinstall script that collected credentials and wallet "
                   "files and uploaded them to a public s1ngularity-repository on the victim's GitHub account.",
        "advice": "Look for repositories named s1ngularity-repository in your GitHub account, and remove "
                  "any 'sudo shutdown -h 0' line from your shell start-up files. " + ROTATE,
        "references": [
            "https://www.wiz.io/blog/s1ngularity-supply-chain-attack",
            "https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware",
        ],
        "packages": {"npm": {
            "nx": ["20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"],
            "@nx/devkit": ["20.9.0", "21.5.0"],
            "@nx/enterprise-cloud": ["3.2.0"],
            "@nx/eslint": ["21.5.0"],
            "@nx/js": ["20.9.0", "21.5.0"],
            "@nx/key": ["3.2.0"],
            "@nx/node": ["20.9.0", "21.5.0"],
            "@nx/workspace": ["20.9.0", "21.5.0"],
        }},
        "host_files": ["/tmp/inventory.txt", "/tmp/inventory.txt.bak"],
        "host_markers": [{"files": ["~/.bashrc", "~/.zshrc"], "text": "sudo shutdown -h 0"}],
    },
]
