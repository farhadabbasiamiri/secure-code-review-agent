"""run_semgrep tool: run the project's custom rules over the parsed input.

Files are written to a private temp directory (never executed), scanned with the rules in
rules/js-security.yml, and results are normalised into plain dicts. Duplicate hits on the same
(file, line, class) are merged, keeping the highest confidence.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .inputs import SourceFile

RULES = Path(__file__).resolve().parents[3] / "rules" / "js-security.yml"
CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.5}
TIMEOUT_S = 60


class ToolError(RuntimeError):
    pass


def mask_secret(s: str) -> str:
    """Keep the first 4 characters of anything that looks like a secret literal."""

    def _m(m: re.Match) -> str:
        q, val = m.group(1), m.group(2)
        return f"{q}{val[:4]}{'*' * min(len(val) - 4, 12)}{q}" if len(val) > 4 else m.group(0)

    return re.sub(r"([\"'`])([^\"'`\s]{8,})\1", _m, s)


_KNOWN_TOKENS = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[0-9a-zA-Z]{24,}"
)
_NAMED_SECRET = re.compile(
    r"(?i)((?:secret|passw(?:or)?d|pwd|token|api_?key|access_?key|private_?key|credential)\w*[\"']?\s*[:=]\s*)"
    r"([\"'`])([^\"'`\n]{4,})\2"
)
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")


def redact_secrets_in_code(text: str) -> str:
    """Mask secret-looking literals before code is shown to an LLM.

    Keeps the first 4 characters and preserves line structure, so line numbers are unchanged.
    """
    text = _PEM.sub(lambda m: "\n".join("[redacted private key]" if i == 0 else ""
                                        for i, _ in enumerate(m.group(0).split("\n"))), text)
    text = _KNOWN_TOKENS.sub(lambda m: m.group(0)[:4] + "*" * 12, text)

    def _named(m: re.Match) -> str:
        if _VERSION.match(m.group(3)):  # e.g. "jsonwebtoken": "8.5.1" is a package, not a secret
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{m.group(3)[:4]}{'*' * 12}{m.group(2)}"

    return _NAMED_SECRET.sub(_named, text)


_VERSION = re.compile(r"^[\^~=<>v ]*\d+(\.[\dx*]+){0,3}([-+][\w.]+)?$")


def semgrep_binary() -> str | None:
    """SCRA_SEMGREP, then PATH, then next to the running Python (an un-activated virtualenv)."""
    if os.getenv("SCRA_SEMGREP"):
        return os.environ["SCRA_SEMGREP"]
    found = shutil.which("semgrep")
    if found:
        return found
    for name in ("semgrep.exe", "semgrep"):
        candidate = Path(sys.executable).parent / name
        if candidate.is_file():
            return str(candidate)
    return None


def run_semgrep(files: list[SourceFile], rules: Path = RULES) -> list[dict]:
    binary = semgrep_binary()
    if not binary:
        raise ToolError("Semgrep is not installed (pip install semgrep).")
    if not files:
        return []

    with tempfile.TemporaryDirectory(prefix="scra-") as tmp:
        tmp_path = Path(tmp)
        index: dict[str, SourceFile] = {}
        for i, f in enumerate(files):
            suffix = Path(f.path).suffix if Path(f.path).suffix in (".js", ".mjs", ".cjs", ".jsx") else ".js"
            local = tmp_path / f"f{i}{suffix}"
            local.write_text(f.text, encoding="utf-8")
            index[str(local)] = f

        cmd = [
            binary, "scan", "--config", str(rules), "--json", "--quiet",
            "--metrics", "off", "--disable-version-check", "--timeout", "20", *index.keys(),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Semgrep timed out after {TIMEOUT_S}s.") from exc
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ToolError(f"Semgrep returned invalid JSON: {proc.stderr[:300]}") from exc
        if proc.returncode not in (0, 1) and not data.get("results"):
            msg = "; ".join(e.get("message", "")[:200] for e in data.get("errors", [])) or proc.stderr[:300]
            raise ToolError(f"Semgrep failed: {msg}")

    merged: dict[tuple, dict] = {}
    for r in data.get("results", []):
        src = index.get(r["path"])
        if src is None:
            continue
        line = r["start"]["line"]
        if src.added_lines is not None and line not in src.added_lines:
            continue  # unchanged context in a diff — not this PR's responsibility
        meta = r.get("extra", {}).get("metadata", {})
        snippet = src.text.splitlines()[line - 1].strip() if line <= src.text.count("\n") + 1 else ""
        hit = {
            "rule_id": r["check_id"].split(".", 1)[-1] if r["check_id"].startswith("rules.") else r["check_id"],
            "vuln_class": meta.get("vuln_class"),
            "cwe": meta.get("cwe"),
            "file": src.path,
            "line": line,
            "snippet": (mask_secret(snippet) if meta.get("vuln_class") == "hardcoded_secret" else snippet)[:300],
            "message": r.get("extra", {}).get("message", ""),
            "confidence": CONFIDENCE.get(str(meta.get("confidence", "MEDIUM")).upper(), 0.75),
        }
        key = (hit["file"], line, hit["vuln_class"])
        if key not in merged or hit["confidence"] > merged[key]["confidence"]:
            merged[key] = hit
    return sorted(merged.values(), key=lambda h: (h["file"], h["line"]))
