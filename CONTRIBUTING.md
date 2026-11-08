# Contributing

Thanks for helping. trustgate stays small on purpose: standard library only, no network,
and it never executes anything it scans.

## Setup

```sh
git clone https://github.com/kirtanbhatt10/trustgate
cd trustgate
python -m unittest discover -s tests -t tests -v
python -m trustgate scan . --exclude tests/fixtures
```

`tests/fixtures/trapped/` is a deliberately booby-trapped folder used by the Action
self-test and the README demo. Its commands point at files that do not exist.

No virtualenv or dependencies are needed. Python 3.10 is the oldest supported version, so
avoid syntax newer than that.

## Adding a rule

1. Register it in `trustgate/models.py` with an id, name, default severity, summary and fix.
   Ids are grouped by area: `TG0xx` generic, `TG1xx` VS Code, `TG2xx` AI agents,
   `TG3xx` npm, `TG4xx` Python, `TG5xx` dev containers, `TG6xx` git hooks and shell,
   `TG7xx` CI workflows, `TG8xx` build tools (Gradle, Maven, ...).
2. Implement the detection in the matching module under `trustgate/checks/`.
   If the rule needs a new file name, add it to `AUTORUN_NAMES` in `trustgate/scanner.py`.
3. Add tests in `tests/test_checks.py` for one positive case and one look-alike that must
   not be flagged.
4. Update `docs/rules.md` and the coverage table in `README.md`
   (`tests/test_meta.py` fails if a rule is missing from `docs/rules.md`).
5. Add a line under "Unreleased" in `CHANGELOG.md`.

## First contribution?

Issues labelled
[good first issue](https://github.com/kirtanbhatt10/trustgate/labels/good%20first%20issue)
are scoped to a single file or rule and list the exact files to touch. Comment on the issue
to claim it, and ask there if anything is unclear. [ROADMAP.md](ROADMAP.md) lists bigger
ideas.

## Releasing (maintainers)

1. Move the "Unreleased" entries in `CHANGELOG.md` under a new version heading.
2. Bump `version` in `pyproject.toml` and `__version__` in `trustgate/__init__.py`.
3. Tag and push: `git tag v0.3.0 && git push origin v0.3.0`. The release workflow tests,
   builds and creates the GitHub release. It also publishes to PyPI with trusted publishing
   when the repository variable `PYPI_PUBLISH` is `true`.

## Guidelines

- Report what is configured to run, with the exact command, file and line.
- Prefer precise matching on documented config keys over broad text searches.
- Every new finding should come with a concrete fix in its rule's remediation text.
- Keep messages short and specific; they are read in terminals and code-scanning UIs.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).
