"""Runtime configuration from environment variables, optionally loaded from a `.env` file.

The `.env` loader is deliberately tiny (KEY=value lines, # comments, optional quotes) so the
project needs no extra dependency. Variables already set in the environment win over `.env`.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_dotenv(path: Path = ROOT / ".env") -> list[str]:
    """Load KEY=value pairs that are not already set. Returns the names that were loaded."""
    if not path.is_file():
        return []
    loaded = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.startswith("export "):
            key = key[7:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def hosted() -> bool:
    """Public deployment mode: only fixed hosted LLM endpoints, no user-supplied URLs.

    Letting visitors of a public app point the server at any URL would let them make the server
    send requests into its own network (SSRF). Locally this restriction is unnecessary.
    """
    return os.getenv("SCRA_HOSTED", "0") == "1"


def server_address() -> tuple[str, int]:
    return os.getenv("SCRA_HOST", "127.0.0.1"), int(os.getenv("SCRA_PORT", "7860"))
