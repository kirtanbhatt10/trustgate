import unittest
from pathlib import PurePosixPath

from trustgate import lockfiles
from trustgate.lockfiles import Pin, reader_for


def pins(reader, text):
    return {(p.ecosystem, p.name, p.version) for p in reader(text)}


class NpmLockTests(unittest.TestCase):
    def test_v3_packages_map(self):
        text = """{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/chalk": {"version": "5.6.1"},
    "node_modules/@ctrl/tinycolor": {"version": "4.1.2"},
    "node_modules/a/node_modules/debug": {"version": "4.4.2"},
    "node_modules/linked": {"resolved": "packages/linked", "link": true},
    "packages/linked": {"name": "linked", "version": "9.9.9"}
  }
}"""
        found = list(lockfiles.npm_lock(text))
        self.assertEqual({(p.name, p.version) for p in found},
                         {("chalk", "5.6.1"), ("@ctrl/tinycolor", "4.1.2"), ("debug", "4.4.2")})
        self.assertEqual({p.name: p.line for p in found}["chalk"], 6)

    def test_v3_alias_uses_the_real_package_name(self):
        text = '{"packages": {"node_modules/my-http": {"name": "axios", "version": "1.14.1"}}}'
        self.assertEqual(pins(lockfiles.npm_lock, text), {("npm", "axios", "1.14.1")})

    def test_v1_nested_dependencies_and_aliases(self):
        text = """{
  "lockfileVersion": 1,
  "dependencies": {
    "axios": {
      "version": "0.30.4",
      "dependencies": {"plain-crypto-js": {"version": "4.2.1"}}
    },
    "colors": {"version": "npm:chalk@5.6.1"},
    "local": {"version": "file:../local"}
  }
}"""
        self.assertEqual(pins(lockfiles.npm_lock, text), {
            ("npm", "axios", "0.30.4"), ("npm", "plain-crypto-js", "4.2.1"), ("npm", "chalk", "5.6.1"),
            ("npm", "local", "file:../local"),
        })

    def test_not_an_object_is_a_parse_error(self):
        with self.assertRaises(ValueError):
            list(lockfiles.npm_lock("[]"))
        with self.assertRaises(ValueError):
            list(lockfiles.npm_lock("{ not json"))


class YarnLockTests(unittest.TestCase):
    def test_classic(self):
        text = """# yarn lockfile v1


"@ctrl/tinycolor@^4.1.0":
  version "4.1.1"
  resolved "https://registry.yarnpkg.com/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz"

chalk@^5.0.0, chalk@^5.6.0:
  version "5.6.1"
  dependencies:
    version-thing "^1.0.0"

http@npm:axios@1.14.1:
  version "1.14.1"
"""
        found = list(lockfiles.yarn_lock(text))
        self.assertEqual({(p.name, p.version) for p in found},
                         {("@ctrl/tinycolor", "4.1.1"), ("chalk", "5.6.1"), ("axios", "1.14.1")})
        self.assertEqual({p.name: p.line for p in found}["chalk"], 8)

    def test_berry(self):
        text = """__metadata:
  version: 8
  cacheKey: 10

"debug@npm:^4.4.0":
  version: 4.4.2
  resolution: "debug@npm:4.4.2"
  languageName: node

"@asyncapi/specs@npm:6.11.2":
  version: 6.11.2
"""
        self.assertEqual(pins(lockfiles.yarn_lock, text),
                         {("npm", "debug", "4.4.2"), ("npm", "@asyncapi/specs", "6.11.2")})


class PnpmLockTests(unittest.TestCase):
    def test_v9_keys_and_snapshots(self):
        text = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      chalk:
        specifier: ^5.6.0
        version: 5.6.1

packages:

  '@tanstack/react-router@1.169.5':
    resolution: {integrity: sha512-x}

  chalk@5.6.1:
    resolution: {integrity: sha512-y}

snapshots:

  '@tanstack/react-router@1.169.5(react@19.0.0)':
    dependencies:
      react: 19.0.0

  chalk@5.6.1: {}
"""
        found = list(lockfiles.pnpm_lock(text))
        self.assertEqual({(p.name, p.version) for p in found},
                         {("@tanstack/react-router", "1.169.5"), ("chalk", "5.6.1")})
        self.assertEqual(min(p.line for p in found if p.name == "chalk"), 16)

    def test_v6_and_v5_keys(self):
        text = """lockfileVersion: '6.0'

packages:

  /@babel/core@7.23.0(supports-color@10.2.1):
    resolution: {integrity: sha512-x}

  /debug@4.4.2:
    resolution: {integrity: sha512-y}

  /@ctrl/tinycolor/4.1.1:
    resolution: {integrity: sha512-z}

  /strip-ansi/7.1.1_react@17.0.2:
    resolution: {integrity: sha512-w}
"""
        self.assertEqual(pins(lockfiles.pnpm_lock, text), {
            ("npm", "@babel/core", "7.23.0"), ("npm", "debug", "4.4.2"),
            ("npm", "@ctrl/tinycolor", "4.1.1"), ("npm", "strip-ansi", "7.1.1"),
        })


class BunLockTests(unittest.TestCase):
    def test_text_lockfile_with_trailing_commas(self):
        text = """{
  "lockfileVersion": 1,
  "workspaces": {"": {"name": "app", "dependencies": {"chalk": "^5.6.0"}}},
  "packages": {
    "chalk": ["chalk@5.6.1", "", {}, "sha512-x"],
    "@bitwarden/cli": ["@bitwarden/cli@2026.4.0", "", {}, "sha512-y"],
  }
}"""
        found = list(lockfiles.bun_lock(text))
        self.assertEqual({(p.name, p.version) for p in found},
                         {("chalk", "5.6.1"), ("@bitwarden/cli", "2026.4.0")})
        self.assertEqual({p.name: p.line for p in found}["@bitwarden/cli"], 6)


class PythonLockTests(unittest.TestCase):
    def test_requirements_exact_pins_only(self):
        text = """# comment
litellm==1.82.8 \\
    --hash=sha256:abc
mistralai[gcp] == 2.4.6 ; python_version >= "3.10"
requests>=2.0
guardrails_ai===0.10.1
-r other.txt
https://example.com/pkg.whl
"""
        found = list(lockfiles.requirements(text))
        self.assertEqual([(p.name, p.version, p.line) for p in found],
                         [("litellm", "1.82.8", 2), ("mistralai", "2.4.6", 4), ("guardrails_ai", "0.10.1", 6)])

    def test_poetry_and_uv_lock(self):
        text = """version = 1

[[package]]
name = "litellm"
version = "1.82.7"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "openai" },
]

[package.dependencies]
name = "ignored"

[[package]]
name = "openai"
version = "2.0.0"
"""
        found = list(lockfiles.toml_lock(text))
        self.assertEqual([(p.ecosystem, p.name, p.version, p.line) for p in found],
                         [("pypi", "litellm", "1.82.7", 3), ("pypi", "openai", "2.0.0", 14)])

    def test_pipfile_lock(self):
        text = """{
  "_meta": {"hash": {"sha256": "x"}},
  "default": {"litellm": {"version": "==1.82.8"}, "editable": {"path": "."}},
  "develop": {"mistralai": {"version": "==2.4.6"}}
}"""
        self.assertEqual(pins(lockfiles.pipfile_lock, text),
                         {("pypi", "litellm", "1.82.8"), ("pypi", "mistralai", "2.4.6")})


class ReaderForTests(unittest.TestCase):
    def test_known_lockfiles(self):
        for name in ("package-lock.json", "npm-shrinkwrap.json", "node_modules/.package-lock.json", "yarn.lock",
                     "apps/web/pnpm-lock.yaml", "bun.lock", "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock",
                     "requirements.txt", "requirements-dev.txt", "constraints.txt", "requirements/prod.txt"):
            self.assertIsNotNone(reader_for(PurePosixPath(name)), name)

    def test_other_files_are_not_lockfiles(self):
        for name in ("package.json", "notes.txt", "docs/requirements.md", "Cargo.lock", "bun.lockb"):
            self.assertIsNone(reader_for(PurePosixPath(name)), name)

    def test_pin_defaults_to_line_one(self):
        self.assertEqual(Pin("npm", "a", "1.0.0").line, 1)


if __name__ == "__main__":
    unittest.main()
