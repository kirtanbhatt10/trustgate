# Roadmap

trustgate answers one question: *what in this repository runs automatically?* The plan is
to keep answering it for more tools without adding dependencies or ever running anything.

## Next

- More editors: JetBrains run configurations and startup tasks, Zed, Neovim `.nvim.lua` / `.exrc`.
- More agents as they ship project-level hooks or settings.
- More package managers and build tools: pnpm `pnpmfile` settings, Maven extensions,
  `cargo` build scripts and `.cargo/config.toml` runners, Composer scripts, Bundler.
- `trustgate rules TG100` to explain a single rule with examples.

## Later

- `trustgate diff A B` to compare two checkouts and show only what changed.
- An optional, signed list of known-good Gradle wrapper checksums.

Want to work on one of these? Look for issues labelled
[good first issue](https://github.com/kirtanbhatt10/trustgate/labels/good%20first%20issue) or
open a "New auto-run location" issue.
