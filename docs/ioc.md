# trustgate ioc

`trustgate scan` shows what a repository will run. `trustgate ioc` answers the question people
ask on the day a supply-chain attack is announced: **did I install it?**

It compares your lockfiles, installed packages and files with the indicators that public
write-ups list for known compromises. It is offline and read-only: files are parsed, nothing
is executed and nothing is fetched.

## Usage

```
trustgate ioc                      # check the current project
trustgate ioc ~/src                # check every project under a folder
trustgate ioc . --no-installed     # lockfiles only, skip node_modules and installed Python packages
trustgate ioc . --exclude tests/fixtures
trustgate ioc . -f json -o ioc.json
trustgate ioc --host               # look for artefacts known malware leaves on this machine
trustgate ioc --list               # campaigns this version knows about
```

Exit codes: `0` nothing found, `1` at least one indicator found, `2` usage error.

## What it reads

| Source | Files |
|--------|-------|
| npm, yarn, pnpm, bun lockfiles | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml` (v5 to v9), `bun.lock` |
| Python lockfiles | `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock` |
| Installed npm packages | every `node_modules/<name>/package.json`, plus `node_modules/.package-lock.json` |
| Installed Python packages | `*.dist-info` folders in any virtualenv or `site-packages` under the path |
| Files | payload and persistence files named in the write-ups, for example `litellm_init.pth` |
| Scripts | `package.json` scripts that call a known dropper |
| Machine (`--host`) | artefacts outside any project, for example lines added to `~/.bashrc` |

`.git` folders, symlinks and paths matching `--exclude` are skipped. Lockfiles that ship inside
a dependency are ignored, because they describe that dependency's own development setup.

## Campaigns

Run `trustgate ioc --list` for the list in your version. The data lives in
[`trustgate/iocdata.py`](../trustgate/iocdata.py) and every entry links the write-ups it was
taken from.

| Id | Date | What is matched |
|----|------|-----------------|
| `asyncapi-2026-07` | 2026-07-14 | `@asyncapi/generator` 3.3.1 (partial list) |
| `tanstack-mistral-2026-05` | 2026-05-11 | `mistralai` 2.4.6 and `guardrails-ai` 0.10.1 on PyPI, `tanstack_runner.js` payload |
| `bitwarden-cli-2026-04` | 2026-04 | `@bitwarden/cli` 2026.4.0 |
| `axios-2026-03` | 2026-03-31 | `axios` 1.14.1 and 0.30.4, any `plain-crypto-js` |
| `litellm-2026-03` | 2026-03-24 | `litellm` 1.82.7 and 1.82.8, `litellm_init.pth` |
| `shai-hulud-2-2025-11` | 2025-11 | `setup_bun.js` and `bun_environment.js` in `node_modules`, scripts that call them |
| `qix-2025-09` | 2025-09-08 | 28 package versions including `chalk` 5.6.1 and `debug` 4.4.2 |
| `shai-hulud-2025-09` | 2025-09 | `shai-hulud-workflow.yml` |
| `nx-s1ngularity-2025-08` | 2025-08-26 | 19 `nx` and `@nx/*` versions, host artefacts |

## Reading the result

A hit means a name and version, or a file, matches a published indicator. Treat it as a lead:
check when the package was installed, then follow the "What to do" line in the report.

No hits means nothing on this list matched. It does not prove a machine is clean. Worms such
as Shai-Hulud hit hundreds of packages and the public lists are incomplete, so those campaigns
are matched by the files they leave, not by version.

## Adding a campaign

1. Find a public write-up that names exact package versions, file names or other artefacts.
2. Add a dict to `CAMPAIGNS` in `trustgate/iocdata.py`, newest first. The module docstring
   explains each field. Package names are lower case; PyPI names use `-` as the separator.
3. Run `python -m unittest discover -s tests -t tests`. `test_campaign_data_is_well_formed`
   rejects entries with no reference, a bad date or a malformed version list.
4. Add a row to the table above and open a pull request.

Only indicators confirmed by a linked source are accepted. No guesses, no "probably affected".
