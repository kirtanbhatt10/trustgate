# trapped: a deliberately booby-trapped fixture

This folder imitates a repository that a self-spreading npm worm has written into. Every
command points at a file that does not exist, so nothing here does anything if run; it
exists so the tests, the GitHub Action self-test and the README demo have a realistic
target. Editors and agents only load these files from a project root, never from a nested
folder like this one.

trustgate's own CI scans the repository with `--exclude tests/fixtures`.
