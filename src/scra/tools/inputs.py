"""parse_input tool: classify and normalise what the user uploaded.

Never executes or imports the content. For diffs, it rebuilds the post-change view of each
hunk so line numbers match the new file, and records which lines were added — findings on
unchanged context lines are filtered out later.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

MAX_BYTES = 200_000
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class InputError(ValueError):
    """Raised for input the agent refuses to process. Message is safe to show the user."""


@dataclass
class SourceFile:
    path: str
    text: str
    added_lines: set[int] | None = None  # None = whole file is in scope


@dataclass
class ParsedInput:
    name: str
    kind: str  # "file" | "diff" | "manifest"
    files: list[SourceFile] = field(default_factory=list)
    manifest: dict | None = None

    def summary(self) -> str:
        if self.kind == "manifest":
            deps = (self.manifest or {}).get("dependencies", {})
            return f"package.json with {len(deps)} dependencies"
        if self.kind == "diff":
            added = sum(len(f.added_lines or ()) for f in self.files)
            return f"diff touching {len(self.files)} JS file(s), {added} added line(s)"
        return f"JS file, {self.files[0].text.count(chr(10)) + 1} lines"


def _decode(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="strict")
    if len(raw) > MAX_BYTES:
        raise InputError(f"Input is {len(raw):,} bytes; the limit is {MAX_BYTES:,}.")
    if not raw.strip():
        raise InputError("Input is empty.")
    if b"\x00" in raw:
        raise InputError("Input looks binary; upload a JavaScript file, diff, or package.json.")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("Input is not valid UTF-8 text.") from exc


def _looks_like_diff(text: str) -> bool:
    return bool(re.search(r"^(diff --git |--- \S+\n\+\+\+ \S+)", text, re.M)) and "@@" in text


def parse_diff(text: str) -> list[SourceFile]:
    files: list[SourceFile] = []
    current: dict | None = None
    new_line = 0

    def flush():
        if current and current["path"].endswith(JS_EXTENSIONS) and current["lines"]:
            max_line = max(current["lines"])
            body = [current["lines"].get(i, "") for i in range(1, max_line + 1)]
            files.append(SourceFile(current["path"], "\n".join(body) + "\n", current["added"]))

    for line in text.splitlines():
        if line.startswith("+++ "):
            flush()
            path = line[4:].strip()
            path = path[2:] if path.startswith("b/") else path
            current = {"path": path, "lines": {}, "added": set()}
            continue
        if current is None or line.startswith("--- ") or line.startswith("diff --git"):
            continue
        m = _HUNK.match(line)
        if m:
            new_line = int(m.group(1))
            continue
        if line.startswith("+"):
            current["lines"][new_line] = line[1:]
            current["added"].add(new_line)
            new_line += 1
        elif line.startswith(" ") or line == "":
            current["lines"][new_line] = line[1:]
            new_line += 1
        # "-" lines exist only in the old file; "\ No newline" markers are ignored.
    flush()
    return files


def parse_input(name: str, raw: bytes | str) -> ParsedInput:
    text = _decode(raw)
    lower = name.lower()

    if lower.endswith("package.json") or (lower.endswith(".json") and '"dependencies"' in text):
        try:
            manifest = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(f"package.json is not valid JSON (line {exc.lineno}).") from exc
        if not isinstance(manifest, dict):
            raise InputError("package.json must be a JSON object.")
        return ParsedInput(name, "manifest", manifest=manifest)

    if lower.endswith((".diff", ".patch")) or _looks_like_diff(text):
        files = parse_diff(text)
        if not files:
            raise InputError("Diff contains no added lines in JavaScript files.")
        return ParsedInput(name, "diff", files=files)

    if lower.endswith(JS_EXTENSIONS):
        return ParsedInput(name, "file", files=[SourceFile(name, text)])

    raise InputError("Unsupported input. Upload a .js/.mjs/.cjs file, a .diff/.patch, or a package.json.")
