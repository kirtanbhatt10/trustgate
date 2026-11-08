# trustgate

**See everything a repository will run before you open, install or build it.**

[![ci](https://github.com/kirtanbhatt10/trustgate/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/trustgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)
[![good first issues](https://img.shields.io/github/issues/kirtanbhatt10/trustgate/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/kirtanbhatt10/trustgate/labels/good%20first%20issue)

![trustgate scanning a freshly cloned repository and listing seven auto-run entry points](docs/demo-scan.gif)

You clone a repo, open it in your editor, start your AI coding agent and run `npm install`.
Each of those steps can run code that came with the repo: a VS Code task set to run on
folder open, a Claude Code `SessionStart` hook, a `postinstall` script, a dev container
`initializeCommand` that runs on your host, a `.pth` file that Python runs at start-up.

In 2026 self-spreading npm worms began writing exactly these files into the repositories
they infected. The Keyv-linked worm of August 2026 left `.claude/settings.json` and
`.vscode/tasks.json` hooks that start the payload as soon as the project is opened, so the
infection outlives a clean `npm install`. These files have valid syntax and look like
routine configuration, which makes them easy to miss in review.

trustgate finds every one of those auto-run entry points, tells you what each one will run
and when, and fails CI when something new shows up.

- **Zero dependencies.** Python 3.10+ standard library only. Nothing to trust but this code.
- **Offline.** Reads files and nothing else: no network, no execution, no telemetry.
- **Built for review and CI.** Text, JSON, SARIF, GitHub annotations and Markdown output;
  a GitHub Action; a pre-commit hook; baselines so only *new* entry points fail the build.

## Install

```sh
pipx install git+https://github.com/kirtanbhatt10/trustgate@v0.2.0
# or run it once without installing anything:
uvx --from git+https://github.com/kirtanbhatt10/trustgate@v0.2.0 trustgate scan .
# or straight from a checkout:
git clone https://github.com/kirtanbhatt10/trustgate && python -m trustgate scan /path/to/repo
```

> Do not `pip install trustgate`: that name on PyPI belongs to an unrelated project.

## Usage

```sh
trustgate scan                       # scan the current directory
trustgate scan ~/src/some-repo       # scan a fresh clone *before* opening it
trustgate scan . --deps              # also look inside node_modules
trustgate scan --home                # audit your own editor / agent / npm config
trustgate scan . -f sarif -o trustgate.sarif
trustgate scan . -f json --min-severity medium
trustgate baseline                   # accept today's findings ...
trustgate scan --baseline .trustgate-baseline.json   # ... and report only new ones
trustgate rules                      # list every rule
trustgate rules TG100                # explain one rule and how to fix it
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-f, --format` | `text` | `text`, `json`, `sarif`, `github` (Actions annotations) or `markdown` |
| `-o, --output` | stdout | write the report to a file |
| `--fail-on LEVEL` | `high` | exit 1 if any finding is at or above `LEVEL` |
| `--min-severity LEVEL` | `info` | hide findings below `LEVEL` |
| `--baseline FILE` | | hide findings recorded by `trustgate baseline` (or in any JSON report) |
| `--ignore RULE` | | skip a rule id (repeatable) |
| `--exclude GLOB` | | skip matching paths, e.g. `tests/fixtures` (repeatable) |
| `--deps` | off | descend into `node_modules` |
| `--home` | off | scan user-level config in your home directory instead of a repo |
| `--no-color` | | plain output (also respects `NO_COLOR`) |

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error.

### A safer clone habit

```sh
git clone https://github.com/someone/project && trustgate scan project && code project
```

Only open the folder (and only grant VS Code *Workspace Trust*) once you have read what
trustgate reported.

### Hidden instructions for AI agents

`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md` and similar files
do not run code, but your agent reads and follows them. Unicode tag characters are invisible
in editors and diffs while models still read them, so trustgate decodes them for you:

![trustgate decoding hidden Unicode tag characters in CLAUDE.md](docs/demo-hidden.gif)

### Fail only on what is new

Healthy projects have expected entry points (`prepare: husky`, a lint hook). Record them once
and trustgate stays quiet until something changes:

![trustgate baseline accepting two reviewed findings and then failing on a newly merged folder-open task](docs/demo-baseline.gif)

A fingerprint covers the rule, the file and the configured command, not the line, so
moving a script keeps it accepted while changing what it runs reopens it.

### After a suspected compromise

`trustgate scan --home` checks the user-level files a worm would use to survive a repo
cleanup: `~/.claude/settings.json`, `~/.claude.json`, `~/.cursor/hooks.json`,
`~/.gemini/settings.json`, `~/.npmrc` and VS Code user `settings.json` / `tasks.json` on
Linux, macOS and Windows. Anything listed there runs for *every* project you open.

## What it checks

| Area | Files | What is flagged |
|------|-------|-----------------|
| VS Code | `.vscode/tasks.json`, `.vscode/settings.json`, `*.code-workspace` | tasks with `runOn: folderOpen`; settings pointing at executables inside the repo; `terminal.integrated.env.*` setting `NODE_OPTIONS`, `LD_PRELOAD`, `BASH_ENV` and similar; `task.allowAutomaticTasks` |
| AI agents | `.claude/settings*.json`, `.mcp.json`, `.cursor/hooks.json`, `.cursor/mcp.json`, `.gemini/settings.json` | every hook command (unprompted events like `SessionStart` rated high); `statusLine` and `apiKeyHelper`-style commands; loader env vars; `enableAllProjectMcpServers`, `bypassPermissions`, `Bash(*)`; locally launched MCP servers; project-enabled plugins and plugin marketplaces |
| Agent instructions | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.claude/commands/`, ... | hidden Unicode used to smuggle instructions past review |
| npm, yarn, pnpm, bun | `package.json`, `binding.gyp`, `.npmrc`, `.yarnrc.yml`, `.yarnrc`, `.pnpmfile.cjs`, `bunfig.toml` | install-time lifecycle scripts; gyp `<!( )` command expansions and implicit `node-gyp rebuild`; `script-shell` / `node-options`; committed auth tokens; non-default registries; `yarnPath` and yarn plugins; pnpm hooks; bun `preload` |
| Python | `*.pth`, `sitecustomize.py`, `usercustomize.py`, `setup.py`, `pyproject.toml` | `.pth` import lines; start-up hooks; `setup.py` process, eval or network calls and overridden install commands (parsed with `ast`, never executed); in-tree build backends (`backend-path`) |
| Dev Containers | `.devcontainer/**/devcontainer.json`, `.devcontainer.json` | `initializeCommand` (runs on the host) and in-container lifecycle commands |
| Git hooks & shell | `.husky/*`, `lefthook.yml`, `.pre-commit-config.yaml`, `.envrc` | hook scripts, local pre-commit entries, direnv files |
| GitHub Actions | `.github/workflows/*.yml` | `toJSON(secrets)` dumps; issue / PR / comment / discussion text interpolated into `run:` |
| Gradle | `gradle/wrapper/gradle-wrapper.properties` | wrapper downloading Gradle from outside `services.gradle.org` |
| Everything above | | invisible Unicode: tag characters (decoded for you), bidi controls, zero-width characters |

Full rule list with severities: [docs/rules.md](docs/rules.md).

trustgate reports *where* code will run and *what* is configured to run. It does not try
to decide whether a script is malicious; a reviewer makes that call with the evidence in
front of them. Expect findings in healthy projects too (a `prepare: husky` script is
normal). The value is that nothing runs without you knowing.

## CI

### GitHub Action

```yaml
name: trustgate
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: kirtanbhatt10/trustgate@v0.2.0
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: trustgate.sarif
```

A pull request that adds a folder-open task, an agent hook or an install script now fails
the check, gets an annotation on the exact file and line, a table in the job summary, and
shows up in code scanning.

| Input | Default | Meaning |
|-------|---------|---------|
| `path` | `.` | directory to scan |
| `fail-on` | `high` | fail at or above this severity |
| `min-severity` | `info` | hide findings below this severity |
| `sarif-file` | `trustgate.sarif` | SARIF output path (empty to skip) |
| `baseline` | | baseline file (see below) |
| `ignore` | | rule ids to skip, space or comma separated |
| `exclude` | | path globs to skip, space or comma separated |
| `annotations` | `true` | annotate each finding's file and line |
| `job-summary` | `true` | write a Markdown table to the job summary |

Outputs: `sarif-file` and `findings` (the number of findings reported).

#### With a baseline

Commit `.trustgate-baseline.json` (created with `trustgate baseline`), then read it from the
**base branch** so a pull request cannot accept its own findings by editing the file:

```yaml
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Baseline from the base branch
        run: git show "origin/${GITHUB_BASE_REF}:.trustgate-baseline.json" > "$RUNNER_TEMP/baseline.json" || echo '{"findings": []}' > "$RUNNER_TEMP/baseline.json"
      - uses: kirtanbhatt10/trustgate@v0.2.0
        with:
          baseline: ${{ runner.temp }}/baseline.json
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/kirtanbhatt10/trustgate
    rev: v0.2.0
    hooks:
      - id: trustgate
```

## Design notes

- **No repository-controlled config.** trustgate never reads an ignore file from the
  repo it scans; otherwise the attacker's commit could switch the scanner off. Use
  `--ignore`, `--exclude` and `--baseline` in your CI workflow instead.
- **Never executes anything.** JSON and JSONC are parsed by a small built-in reader,
  `setup.py` by Python's `ast`, YAML and TOML by line matching. Symlinks are not followed.
- **Safe to print.** Terminal escape sequences and invisible or bidirectional characters in
  repository text are shown as `\uXXXX`, so a crafted command cannot rewrite the report.
- **Bounded.** Files over 2 MB and binary files are skipped; `.git`, virtualenvs and
  `node_modules` are skipped unless you pass `--deps`.
- **Stable fingerprints.** SARIF results carry `partialFingerprints` so code scanning can
  track a finding across commits; baselines use the same fingerprints.

## Related tools

trustgate covers one question: *what runs automatically?* For neighbouring problems:

- [mcp-warden](https://github.com/kirtanbhatt10/mcp-warden): deep audit of MCP server configs
- [runnerguard](https://github.com/kirtanbhatt10/runnerguard): full GitHub Actions workflow linting
- [promptshield](https://github.com/kirtanbhatt10/promptshield): runtime prompt-injection guardrails for LLM apps

## Contributing

trustgate is small, has no dependencies and every check lives in one short file, which makes
it a good first open-source contribution. Start with an issue labelled
[good first issue](https://github.com/kirtanbhatt10/trustgate/labels/good%20first%20issue),
read [CONTRIBUTING.md](CONTRIBUTING.md), or look at the [roadmap](ROADMAP.md). Bug
reports, false positives and new auto-run locations are all welcome. Security issues:
[SECURITY.md](SECURITY.md).

The demo GIFs are generated from real runs by [`scripts/make_demos.py`](scripts/make_demos.py).

## License

[MIT](LICENSE) © 2026 Kirtan Bhatt
