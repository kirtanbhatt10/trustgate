"""Render the README demo GIFs from real trustgate runs.

    python scripts/make_demos.py            # writes docs/demo-*.gif
    python scripts/make_demos.py --mp4      # also writes .mp4 copies for social posts

Every command shown is really executed in a temporary directory (through a pseudo-terminal,
so trustgate prints its normal colours) and the captured output is drawn frame by frame.
Needs Pillow (and ffmpeg for --mp4); trustgate itself still has no dependencies.
"""

from __future__ import annotations

import argparse
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "trapped"
OUT = ROOT / "docs"

COLS, ROWS = 104, 40
FONT_SIZE = 15
PAD = 18
BAR = 30
BG, FG, DIM_FG = (24, 24, 32), (220, 221, 228), (128, 130, 145)
PROMPT_FG = (125, 211, 160)
ANSI = {"30": (90, 90, 100), "31": (255, 107, 107), "32": (125, 211, 160), "33": (241, 196, 90),
        "34": (110, 160, 255), "35": (214, 130, 255), "36": (100, 210, 230), "37": (200, 200, 210)}
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def font(bold: bool = False) -> ImageFont.FreeTypeFont:
    names = ["DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"]
    for base in ("/usr/share/fonts/truetype/dejavu", "/Library/Fonts", "C:/Windows/Fonts"):
        for name in names:
            path = Path(base) / name
            if path.exists():
                return ImageFont.truetype(str(path), FONT_SIZE)
    return ImageFont.load_default()


REGULAR, BOLD = font(), font(True)
CW = int(REGULAR.getlength("M"))
LH = FONT_SIZE + 6
WIDTH = PAD * 2 + CW * COLS
HEIGHT = BAR + PAD * 2 + LH * ROWS


def run_in_pty(command: str, cwd: str, env: dict) -> str:
    """Run a shell command attached to a pseudo-terminal and return what it printed."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(["bash", "-c", command], cwd=cwd, env=env, stdin=slave, stdout=slave,
                            stderr=slave, close_fds=True)
    os.close(slave)
    chunks = []
    while True:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        elif proc.poll() is not None:
            break
    proc.wait()
    os.close(master)
    return b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")


def spans(line: str):
    """Split a line with SGR codes into (text, colour, bold) spans."""
    color, bold, out, pos = FG, False, [], 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], color, bold))
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                color, bold = FG, False
            elif code == "1":
                bold = True
            elif code == "2":
                color = DIM_FG
            elif code in ANSI:
                color = ANSI[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], color, bold))
    return out


def wrap(line: str):
    """Wrap a coloured line at COLS visible characters, carrying the colour over."""
    plain_len = len(SGR.sub("", line))
    if plain_len <= COLS:
        return [line]
    plain = SGR.sub("", line)
    indent = " " * min(len(plain) - len(plain.lstrip(" ")), 12)
    rows, current, count, active = [], "", 0, ""
    i = 0
    while i < len(line):
        m = SGR.match(line, i)
        if m:
            current += m.group(0)
            active = "" if m.group(1) in ("0", "") else active + m.group(0)
            i = m.end()
            continue
        if count == COLS:
            rows.append(current + "\x1b[0m")
            current, count = indent + active, len(indent)
        current += line[i]
        count += 1
        i += 1
    rows.append(current)
    return rows


class Terminal:
    def __init__(self, title: str, where: str = "~/src"):
        self.title = title
        self.where = where
        self.lines = [""]
        self.frames = []  # (image, duration ms)

    def _render(self, cursor: bool) -> Image.Image:
        img = Image.new("RGB", (WIDTH, HEIGHT), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, WIDTH, BAR], fill=(38, 38, 50))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([14 + i * 20, 10, 26 + i * 20, 22], fill=c)
        tw = REGULAR.getlength(self.title)
        d.text(((WIDTH - tw) / 2, 7), self.title, font=REGULAR, fill=DIM_FG)
        visible = self.lines[-ROWS:]
        y = BAR + PAD
        for row, line in enumerate(visible):
            x = PAD
            for text, color, bold in spans(line):
                d.text((x, y), text, font=BOLD if bold else REGULAR, fill=color)
                x += CW * len(text)
            if cursor and row == len(visible) - 1:
                d.rectangle([x + 1, y + 1, x + CW - 1, y + LH - 3], fill=FG)
            y += LH
        return img

    def snap(self, ms: int, cursor: bool = True) -> None:
        self.max_rows = max(getattr(self, "max_rows", 0), len(self.lines))
        self.frames.append((self._render(cursor), ms))

    def prompt(self) -> None:
        self.lines[-1] = f"\x1b[32m{self.where}\x1b[0m $ "

    def type(self, text: str) -> None:
        for ch in text:
            self.lines[-1] += ch
            self.snap(45 if ch != " " else 70)
        self.snap(450)

    def output(self, text: str, per_line: int = 55) -> None:
        self.lines.append("")
        body = text.rstrip("\n").split("\n") if text.strip() else []
        self.lines.pop()
        for raw in body:
            for row in wrap(raw):
                self.lines.append(row)
                self.snap(per_line, cursor=False)
        self.lines.append("")

    def comment(self, text: str) -> None:
        self.lines[-1] = f"\x1b[2m# {text}\x1b[0m"
        self.snap(1500, cursor=False)
        self.lines.append("")

    def save(self, path: Path) -> None:
        used = BAR + PAD * 2 + LH * min(self.max_rows, ROWS)
        images = [f[0].crop((0, 0, WIDTH, used)) for f in self.frames]
        durations = [f[1] for f in self.frames]
        durations[-1] = 4000
        swatch = Image.new("RGB", (WIDTH, used + 40), BG)
        swatch.paste(images[-1], (0, 0))
        sd = ImageDraw.Draw(swatch)
        theme = [FG, DIM_FG, PROMPT_FG, (38, 38, 50), (255, 95, 86), (255, 189, 46), (39, 201, 63), *ANSI.values()]
        for i, c in enumerate(theme):
            sd.rectangle([i * 40, used, i * 40 + 39, used + 39], fill=c)
        pal = swatch.quantize(colors=96, method=Image.Quantize.MEDIANCUT)
        frames = [im.quantize(palette=pal, dither=Image.Dither.NONE) for im in images]
        frames[0].save(path, save_all=True, append_images=frames[1:], duration=durations, loop=0,
                       optimize=True, disposal=1)
        self.path = path


def session(title: str, steps, cwd: str, env: dict, where: str = "~/src") -> Terminal:
    term = Terminal(title, where)
    term.prompt()
    term.snap(600)
    for kind, value in steps:
        if kind == "comment":
            term.comment(value)
            term.prompt()
        elif kind == "run":
            term.type(value)
            out = run_in_pty(value, cwd, env)
            term.output(out)
            term.prompt()
            term.snap(1200)
    return term


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mp4", action="store_true", help="also write .mp4 files (needs ffmpeg)")
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="trustgate-demo-"))
    bindir = tmp / "bin"
    bindir.mkdir()
    shim = bindir / "trustgate"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m trustgate "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "PYTHONPATH": str(ROOT), "TERM": "xterm-256color",
           "COLUMNS": str(COLS), "LANG": "C.UTF-8", "HOME": str(tmp), "PYTHONDONTWRITEBYTECODE": "1",
           "GIT_AUTHOR_NAME": "demo", "GIT_AUTHOR_EMAIL": "demo@example.com",
           "GIT_COMMITTER_NAME": "demo", "GIT_COMMITTER_EMAIL": "demo@example.com", "GIT_CONFIG_NOSYSTEM": "1"}
    src = tmp / "src"
    src.mkdir()

    project = src / "cool-project"
    shutil.copytree(FIXTURE, project)
    (project / "README.md").write_text("# cool-project\n\nA small, popular utility library.\n", encoding="utf-8")
    OUT.mkdir(exist_ok=True)
    made = []

    made.append(session("trustgate: scan a fresh clone before you open it", [
        ("comment", "you just cloned cool-project. before opening it in your editor or agent:"),
        ("run", "trustgate scan cool-project"),
        ("comment", "7 findings before you opened a single file. now you know what to read first."),
    ], str(src), env))
    made[-1].save(OUT / "demo-scan.gif")

    made.append(session("trustgate: hidden instructions for your AI agent", [
        ("comment", "CLAUDE.md looks harmless in your editor and in the diff:"),
        ("run", "cat cool-project/CLAUDE.md"),
        ("run", "trustgate scan cool-project --min-severity critical"),
        ("comment", "invisible Unicode tag characters, decoded so you can read them"),
    ], str(src), env))
    made[-1].save(OUT / "demo-hidden.gif")

    app = src / "my-app"
    app.mkdir()
    (app / "package.json").write_text('{\n  "name": "my-app",\n  "scripts": {\n    "prepare": "husky",\n'
                                      '    "test": "node --test"\n  }\n}\n', encoding="utf-8")
    (app / ".husky").mkdir()
    (app / ".husky" / "pre-commit").write_text("npx lint-staged\n", encoding="utf-8")
    git = ["bash", "-c", ("git init -q -b main && git add -A && git commit -qm init && git checkout -qb pr-42 && "
                          "mkdir -p .vscode && cp ../cool-project/.vscode/tasks.json .vscode/ && git add -A && "
                          "git commit -qm 'chore: workspace setup' && git checkout -q main")]
    subprocess.run(git, cwd=app, env=env, check=True)
    made.append(session("trustgate: accept what you reviewed, fail on anything new", [
        ("run", "trustgate scan --fail-on low; echo exit=$?"),
        ("comment", "you've read both and they're fine. record them:"),
        ("run", "trustgate baseline"),
        ("run", "trustgate scan --fail-on low --baseline .trustgate-baseline.json; echo exit=$?"),
        ("comment", "later, a pull request quietly adds a folder-open task..."),
        ("run", "git merge -q pr-42"),
        ("run", "trustgate scan --fail-on low --baseline .trustgate-baseline.json; echo exit=$?"),
    ], str(app), env, where="~/src/my-app"))
    made[-1].save(OUT / "demo-baseline.gif")

    for term in made:
        size = term.path.stat().st_size // 1024
        print(f"wrote {term.path.relative_to(ROOT)} ({len(term.frames)} frames, {size} KiB)")
        if args.mp4:
            mp4 = term.path.with_suffix(".mp4")
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(term.path), "-movflags", "faststart",
                            "-pix_fmt", "yuv420p", "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                            "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", str(mp4)], check=True)
            print(f"wrote {mp4.relative_to(ROOT)}")
    shutil.rmtree(tmp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
