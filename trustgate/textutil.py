"""Small text helpers: JSON-with-comments parsing, safe file reads and line lookup."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

MAX_FILE_BYTES = 2 * 1024 * 1024


def read_text(path: Path) -> Optional[str]:
    """Read a file as UTF-8 (lossy). Returns None for unreadable, huge or binary files."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings untouched.

    VS Code, devcontainer and several agent config files are JSONC, which the
    standard json module rejects. Removed characters are replaced by spaces
    (newlines are kept) so error positions still map to the original text.
    """
    out = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.extend("\n" if c == "\n" else " " for c in text[i:end])
            i = end
            continue
        out.append(ch)
        i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    chars = list(text)
    in_string = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ",":
            j = i + 1
            while j < len(chars) and chars[j] in " \t\r\n":
                j += 1
            if j < len(chars) and chars[j] in "]}":
                chars[i] = " "
        i += 1
    return "".join(chars)


def load_jsonc(text: str) -> Any:
    """Parse JSON or JSONC. Raises ValueError on invalid input."""
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(strip_jsonc(text))


def line_of(text: str, needle: str, default: int = 1) -> int:
    """1-based line number of the first occurrence of needle, or default."""
    if not needle:
        return default
    idx = text.find(needle)
    if idx == -1:
        return default
    return text.count("\n", 0, idx) + 1


def _unsafe(cp: int) -> bool:
    return (cp < 0x20 or 0x7F <= cp <= 0x9F or 0x200B <= cp <= 0x200F or 0x202A <= cp <= 0x202E
            or 0x2060 <= cp <= 0x2069 or cp == 0xFEFF or 0xE0000 <= cp <= 0xE007F)


def printable(value: str) -> str:
    """Make repository-controlled text safe to print.

    Terminal escape sequences, control characters and invisible or direction-changing
    Unicode are shown as \\uXXXX so a crafted command cannot rewrite or hide other
    output lines (for example with ESC[2K or a right-to-left override).
    """
    if not any(_unsafe(ord(c)) for c in value):
        return value
    return "".join(f"\\u{ord(c):04x}" if _unsafe(ord(c)) else c for c in value)


def shorten(value: str, limit: int = 160) -> str:
    value = printable(" ".join(value.split()))
    return value if len(value) <= limit else value[: limit - 3] + "..."
