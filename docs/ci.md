# GitLab CI and CircleCI

trustgate runs anywhere with Python 3.10+ and Git for the pinned installation.
These examples scan the checked-out repository without installing or executing
its code. Installation needs network access; the scan itself is offline.

The scan exits with `0` when nothing reaches the threshold, `1` when findings
reach it, and `2` for a usage error. Keep the nonzero exit status so findings fail
the job, and upload the JSON report even when the scan fails.

## GitLab CI

Add this job to `.gitlab-ci.yml`. The full Python image includes Git; the slim
image needs Git installed separately.

```yaml
trustgate:
  image: python:3.12-bookworm
  script:
    - python -m pip install pipx
    - pipx install git+https://github.com/kirtanbhatt10/trustgate@v0.2.0
    - export PATH="$HOME/.local/bin:$PATH"
    - trustgate scan . --fail-on high -f json -o trustgate.json
  artifacts:
    when: always
    paths:
      - trustgate.json
    expire_in: 1 week
```

GitLab checks out the repository before `script` runs.
[`artifacts:when: always`](https://docs.gitlab.com/ci/yaml/#artifactswhen)
retains the report when findings make the job fail. If your pipeline defines
custom stages, add `stage:` with an existing stage name.

## CircleCI

Add this configuration to `.circleci/config.yml`, or add the job to an existing
workflow. Keeping installation and scanning in separate steps makes installation
failures easy to distinguish from findings.

```yaml
version: 2.1
jobs:
  trustgate:
    docker:
      - image: python:3.12-bookworm
    steps:
      - checkout
      - run:
          name: Install trustgate
          command: |
            python -m pip install pipx
            pipx install git+https://github.com/kirtanbhatt10/trustgate@v0.2.0
      - run:
          name: Scan repository
          command: |
            export PATH="$HOME/.local/bin:$PATH"
            trustgate scan . --fail-on high -f json -o trustgate.json
      - store_artifacts:
          path: trustgate.json
workflows:
  security:
    jobs:
      - trustgate
```

CircleCI runs
[`store_artifacts`](https://circleci.com/docs/reference/configuration-reference/#store_artifacts)
after a failed step too, so the report remains available when the scanner exits
with findings. A canceled or timed-out job may not upload artifacts.

## Reviewing expected findings

An install hook or build entry point can be legitimate. Review the command and
its source before accepting it. To report only new findings, pass
`--baseline /path/to/reviewed-baseline.json` to the scan. Obtain that baseline
from the trusted base branch or protected CI configuration, rather than letting
a pull request change the baseline that judges its own findings.

See the [README](../README.md#fail-only-on-what-is-new) for baseline usage.
