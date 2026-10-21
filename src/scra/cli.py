"""Command-line entry point.

    python -m scra.cli review data/samples/mixed_vuln.js
    python -m scra.cli review data/samples/package_vuln.json --json
    python -m scra.cli ui        # start the Gradio app (same as python -m scra.app)
    python -m scra.cli stats     # summary of logs/runs.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import review
from .config import load_dotenv

SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". ", "info": "  "}


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    ap = argparse.ArgumentParser(prog="scra", description="Secure Code Review Agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review", help="Review a JS file, diff, or package.json")
    r.add_argument("path", type=Path)
    r.add_argument("--json", action="store_true", help="Print the full ReviewResult as JSON")
    r.add_argument("--offline", action="store_true", help="Use the bundled OSV snapshot")
    sub.add_parser("ui", help="Start the web app")
    sub.add_parser("stats", help="Summarize the run logs")
    args = ap.parse_args(argv)

    if args.cmd == "ui":
        from .app import main as run_app

        run_app()
        return 0
    if args.cmd == "stats":
        from .logging_utils import summarize_logs

        s = summarize_logs()
        s.pop("recent")
        print(json.dumps(s, indent=2))
        return 0

    if not args.path.is_file():
        print(f"error: {args.path} is not a file", file=sys.stderr)
        return 2
    result = review(args.path.name, args.path.read_bytes(), offline=args.offline or None)

    if args.json:
        print(result.model_dump_json(indent=2))
        return 0 if not result.errors or result.findings else 1

    print(f"Reviewed {result.input_name} ({result.input_kind}) with {result.llm_provider}")
    print("Agent steps:")
    for t in result.trace:
        args_s = f"({', '.join(f'{k}={v}' for k, v in t.arguments.items() if k != 'name')})" if t.tool == "retrieve_guidance" else ""
        print(f"  {'ok ' if t.ok else 'ERR'} {t.tool}{args_s} [{t.duration_ms} ms] {t.error or t.summary}")
    for e in result.errors:
        print(f"Note: {e}")
    if not result.findings:
        print("\nNo security issues found by the configured rules.")
    for i, f in enumerate(result.findings, 1):
        loc = f"{f.evidence.file}:{f.evidence.line}" if f.evidence.line else f.evidence.file
        print(f"\n{SEV_MARK[f.severity.value]} [{i}] {f.severity.value.upper()} {f.finding}")
        print(f"     {f.cwe} | {loc} | confidence {f.confidence:.2f} | via {f.tool}")
        print(f"     > {f.evidence.snippet}")
        print(f"     Why: {f.explanation}")
        print(f"     Fix: {f.fix}")
        if f.sources:
            print(f"     Sources: {', '.join(f.sources)}")
    if result.dropped:
        print(f"\n({result.dropped} model finding(s) dropped: not backed by tool evidence or invalid)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
