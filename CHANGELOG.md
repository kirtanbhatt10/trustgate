# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `trustgate ioc`: checks lockfiles, installed packages and files against indicators from known
  supply-chain compromises (axios, LiteLLM, Shai-Hulud, Nx, chalk / debug and more). Offline,
  text or JSON output, `--host` for artefacts left on the machine. See [docs/ioc.md](docs/ioc.md).
- `trustgate rules TG100` explains a single rule: name, default severity, fix and a link to the docs.
  Lower-case ids work too; an unknown id exits with code 2.
- `test_every_rule_has_a_test` in `tests/test_meta.py`: verifies that every registered rule in `RULES` is covered by at least one test. (#11)
- `TG304 composer-script`: flags Composer event scripts in `composer.json` that run automatically on install, update, or autoload dump (#7).
- `TG602 vim-exrc`: flags root-level Neovim / Vim configuration files (`.nvim.lua`, `.nvimrc`, `.exrc`, `.vimrc`) that run automatically when the editor opens the directory if `exrc` is enabled (#9).
- `TG801 rust-build-script`: flags Cargo build scripts (`build.rs`) and custom `build = "..."` definitions in `Cargo.toml` that run when the project is compiled or opened in rust-analyzer (#8).
- SARIF rules link to `docs/rules.md` through `helpUri`, so code scanning shows a "Learn more" link (#4).

### Changed

- TG203 is `medium` when an MCP server is launched with `npx`, `pnpm dlx`, `bunx` or `uvx` without an
  exact version pin (no version, a moving tag such as `@latest`, or a range); exact pins stay `low` (#5).
- CI and release workflows use `actions/checkout@v7`, `actions/setup-python@v7`,
  `actions/upload-artifact@v7` and `actions/download-artifact@v8`.

### Documentation

- The README states that contributions are accepted under the project's MIT License.

## [0.2.0] - 2026-11-09

### Added

- `trustgate baseline` and `scan --baseline FILE`: accept the findings you have reviewed and
  fail only on new ones. Any JSON report also works as a baseline.
- `--format github` (inline annotations on the file and line in a workflow run) and
  `--format markdown` (job summaries and PR comments).
- `--exclude GLOB` to skip paths such as test fixtures (command line only, never read from
  the scanned repository).
- TG205: project settings that enable Claude Code plugins or add plugin marketplaces.
- TG303: yarn `yarnPath` / `plugins` (`.yarnrc.yml`), yarn 1 `yarn-path`, `.pnpmfile.cjs`
  and bun `preload` (`bunfig.toml`).
- TG403: in-tree Python build backends (`[build-system] backend-path` in `pyproject.toml`).
- TG800: Gradle wrapper downloading Gradle from an unofficial URL.
- Hidden-Unicode checks (TG001) on agent instruction files: `CLAUDE.md`, `AGENTS.md`,
  `GEMINI.md`, `.cursorrules`, `.github/copilot-instructions.md`, `.cursor/rules/` and more.
- GitHub Action: `baseline`, `ignore`, `exclude` and `min-severity` inputs, annotations,
  a job summary and a `findings` output.
- Release workflow: GitHub release with built wheel and sdist; optional PyPI upload as
  `trustgate-scan` with trusted publishing.

### Changed

- The text report header now says "N files checked".

### Security

- Terminal escape sequences, control characters and invisible or bidirectional Unicode in
  repository-controlled text are printed as `\uXXXX`, so a crafted command can no longer
  rewrite or hide other lines of the report.
- Markdown output escapes repository text, so it cannot add links, images or HTML.

## [0.1.0] - 2026-11-08

### Added

- `trustgate scan` for repositories and `trustgate scan --home` for user-level config.
- VS Code: folder-open tasks, repository-controlled executables, loader environment
  variables in terminal settings, `task.allowAutomaticTasks`.
- AI agents (Claude Code, Cursor, Gemini CLI): hooks, command settings, environment
  injection, auto-approval settings and local MCP servers.
- npm: install lifecycle scripts, `binding.gyp` command expansions, risky `.npmrc` keys.
- Python: `.pth` import lines, `sitecustomize.py` / `usercustomize.py`, `setup.py`
  side effects via `ast`.
- Dev Containers: `initializeCommand` on the host and in-container lifecycle commands.
- husky, lefthook, local pre-commit hooks and direnv `.envrc`.
- GitHub Actions: `toJSON(secrets)` and untrusted event text in `run:` steps.
- Hidden Unicode detection with decoding of tag-character text.
- Text, JSON and SARIF 2.1.0 output; GitHub Action; pre-commit hook.

[0.2.0]: https://github.com/kirtanbhatt10/trustgate/releases/tag/v0.2.0
