## What this changes

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Checklist

- [ ] `python -m unittest discover -s tests -t tests` passes
- [ ] `python -m trustgate scan . --fail-on medium --exclude tests/fixtures` is clean
- [ ] New or changed rules have a positive test and a look-alike that must not be flagged
- [ ] `docs/rules.md`, the README coverage table and `CHANGELOG.md` (under "Unreleased") are updated
- [ ] No new dependencies, no network access, nothing from the scanned repo is executed
