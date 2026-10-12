"""Run logging and monitoring.

    logs/runs.jsonl    one line per review: kind, size, provider, timings, counts, errors
    logs/events.jsonl  approval decisions, drafted comments/patches, connection tests

Records metadata only — tool names, timings, counts, classes, errors. Never the uploaded
source, snippets, API keys, or secret values (see docs/03-safety-boundaries.md).
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(os.getenv("SCRA_LOG_DIR", Path(__file__).resolve().parents[2] / "logs"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append(filename: str, entry: dict) -> None:
    if os.getenv("SCRA_DISABLE_LOGS") == "1":
        return
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / filename).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # logging must never break a review


def log_run(result, seconds: float, input_bytes: int) -> None:
    entry = {
        "ts": _now(),
        "review_id": result.review_id,
        "input_kind": result.input_kind,
        "input_bytes": input_bytes,
        "provider": result.llm_provider,
        "seconds": round(seconds, 3),
        "findings": len(result.findings),
        "by_class": {},
        "dropped": result.dropped,
        "tools": [{"tool": t.tool, "ok": t.ok, "ms": t.duration_ms} for t in result.trace],
        "errors": result.errors,
    }
    for f in result.findings:
        entry["by_class"][f.vuln_class.value] = entry["by_class"].get(f.vuln_class.value, 0) + 1
    _append("runs.jsonl", entry)


def log_event(event: str, **fields) -> None:
    """Non-review events. Callers pass metadata only (ids, classes, decisions, ok flags)."""
    _append("events.jsonl", {"ts": _now(), "event": event, **fields})


def _read(filename: str, limit: int) -> list[dict]:
    path = LOG_DIR / filename
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def summarize_logs(limit: int = 2000) -> dict:
    """Aggregate the most recent runs and events for the monitoring tab and `scra stats`."""
    runs, events = _read("runs.jsonl", limit), _read("events.jsonl", limit)
    secs = sorted(r.get("seconds", 0) for r in runs)
    tool_calls: Counter = Counter()
    tool_fail: Counter = Counter()
    tool_ms: dict[str, list[int]] = {}
    for r in runs:
        for t in r.get("tools", []):
            tool_calls[t["tool"]] += 1
            tool_ms.setdefault(t["tool"], []).append(t.get("ms", 0))
            if not t.get("ok", True):
                tool_fail[t["tool"]] += 1
    by_class: Counter = Counter()
    for r in runs:
        by_class.update(r.get("by_class", {}))
    error_kinds: Counter = Counter()
    for r in runs:
        for e in r.get("errors", []):
            error_kinds[e.split(":")[0].split(";")[0][:60]] += 1
    decisions = Counter(e.get("decision") for e in events if e.get("event") == "decision")

    def pct(p: float) -> float:
        return secs[min(len(secs) - 1, int(p * len(secs)))] if secs else 0.0

    return {
        "runs": len(runs),
        "invalid_inputs": sum(r.get("input_kind") == "invalid" for r in runs),
        "runs_with_errors": sum(bool(r.get("errors")) for r in runs),
        "latency_s": {"mean": round(sum(secs) / len(secs), 2) if secs else 0.0,
                      "p50": pct(0.5), "p95": pct(0.95), "max": secs[-1] if secs else 0.0},
        "providers": dict(Counter(r.get("provider") for r in runs)),
        "input_kinds": dict(Counter(r.get("input_kind") for r in runs)),
        "findings_by_class": dict(by_class),
        "dropped_model_findings": sum(r.get("dropped", 0) for r in runs),
        "tools": {t: {"calls": n, "failures": tool_fail[t],
                      "avg_ms": round(sum(tool_ms[t]) / len(tool_ms[t]))} for t, n in tool_calls.most_common()},
        "error_kinds": dict(error_kinds.most_common(8)),
        "decisions": {k: v for k, v in decisions.items() if k},
        "recent": runs[-15:][::-1],
    }
