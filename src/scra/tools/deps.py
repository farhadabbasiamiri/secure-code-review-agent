"""check_dependencies tool: look up package.json dependencies in OSV.

Tries the live OSV API first; on any network failure falls back to the bundled snapshot and
says so in the result. Only exact or caret/tilde-pinned versions are checked — the base version
of a range is treated as the installed version, which is noted as a limitation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import requests

SNAPSHOT = Path(__file__).resolve().parents[3] / "data" / "osv_snapshot.json"
OSV_URL = "https://api.osv.dev/v1/querybatch"
TIMEOUT_S = 5


def parse_version(v: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def _in_range(ver: tuple, rng: dict) -> bool:
    lo = parse_version(rng.get("introduced", "0")) or (0, 0, 0)
    if ver < lo:
        return False
    if "fixed" in rng:
        return ver < parse_version(rng["fixed"])
    if "last_affected" in rng:
        return ver <= parse_version(rng["last_affected"])
    return True


def _collect(manifest: dict) -> list[tuple[str, str]]:
    deps: dict = {}
    for key in ("dependencies", "devDependencies"):
        if isinstance(manifest.get(key), dict):
            deps.update(manifest[key])
    out = []
    for name, spec in deps.items():
        if (isinstance(spec, str) and parse_version(spec)
                and not spec.startswith(("http", "git", "file:", "npm:", "link:", "workspace:"))):
            out.append((name, re.sub(r"^[\^~=v>< ]+", "", spec)))
    return out


def _enrich(vuln_id: str, package: str, version: str) -> dict:
    """Fetch summary / severity / fixed version for one advisory. Best effort."""
    try:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=TIMEOUT_S)
        r.raise_for_status()
        d = r.json()
    except (requests.RequestException, ValueError):
        return {}
    # Pick the lowest fixed version above the installed one (advisories can list several branches).
    current = parse_version(version) or (0, 0, 0)
    candidates = []
    for aff in d.get("affected", []):
        if aff.get("package", {}).get("name") == package:
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    fv = parse_version(ev.get("fixed", ""))
                    if fv and fv > current:
                        candidates.append((fv, ev["fixed"]))
    fixed = min(candidates)[1] if candidates else None
    sev = (d.get("database_specific") or {}).get("severity", "unknown")
    return {"aliases": d.get("aliases", []), "summary": d.get("summary", ""),
            "severity": str(sev).lower().replace("moderate", "medium"), "fixed": fixed}


def _query_osv(pkgs: list[tuple[str, str]], max_enrich: int = 15) -> list[dict]:
    body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in pkgs]}
    resp = requests.post(OSV_URL, json=body, timeout=TIMEOUT_S)
    resp.raise_for_status()
    hits = []
    for (name, ver), res in zip(pkgs, resp.json().get("results", [])):
        for v in res.get("vulns", []) or []:
            hit = {"package": name, "version": ver, "id": v["id"], "aliases": [],
                   "summary": "", "severity": "unknown", "fixed": None}
            if len(hits) < max_enrich:
                hit.update(_enrich(v["id"], name, ver))
            hits.append(hit)
    return hits


def _query_snapshot(pkgs: list[tuple[str, str]], snapshot: Path) -> list[dict]:
    advisories = json.loads(snapshot.read_text())["advisories"]
    hits = []
    for name, ver in pkgs:
        pv = parse_version(ver)
        for adv in advisories:
            if adv["package"] != name:
                continue
            for rng in adv["ranges"]:
                if _in_range(pv, rng):
                    hits.append({"package": name, "version": ver, "id": adv["id"],
                                 "aliases": adv["aliases"], "summary": adv["summary"],
                                 "severity": adv["severity"], "fixed": rng.get("fixed")})
                    break
    return hits


def check_dependencies(manifest: dict, offline: bool = False, snapshot: Path = SNAPSHOT) -> dict:
    pkgs = _collect(manifest)
    if not pkgs:
        return {"source": "none", "checked": 0, "vulnerabilities": [], "note": "No pinned dependencies found."}
    if not offline:
        try:
            return {"source": "osv-live", "checked": len(pkgs), "vulnerabilities": _query_osv(pkgs), "note": ""}
        except (requests.RequestException, ValueError) as exc:
            note = f"OSV unreachable ({type(exc).__name__}); used offline snapshot."
    else:
        note = "Offline mode; used bundled snapshot."
    return {"source": "snapshot", "checked": len(pkgs),
            "vulnerabilities": _query_snapshot(pkgs, snapshot), "note": note}
