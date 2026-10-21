"""HTML/Markdown rendering for the Gradio UI.

Pure functions from results to strings, kept apart from app.py so they can be tested.
Everything taken from the uploaded code or the model is HTML-escaped: snippets are
attacker-influenced text, and this page must not become an XSS example itself.
"""
from __future__ import annotations

from html import escape

from .llm import PRESETS
from .schema import Finding, ReviewResult, ToolCall
from .tools.retrieve import get_kb

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CLASS_LABELS = {
    "xss": "Cross-site scripting", "injection": "Injection", "insecure_cookie": "Insecure cookie",
    "missing_input_validation": "Missing input validation", "hardcoded_secret": "Hardcoded secret",
    "vulnerable_dependency": "Vulnerable dependency",
}
TOOL_LABELS = {
    "parse_input": "Read the input", "run_semgrep": "Scan with Semgrep rules",
    "check_dependencies": "Check dependencies (OSV)", "retrieve_guidance": "Look up guidance",
}

CSS = """
:root, .light {
  --scra-ink: #1D2433; --scra-muted: #5B6478; --scra-line: #D9DEE7; --scra-soft: #F2F4F8;
  --scra-accent: #2B59C3;
  --sev-critical: #A3174A; --sev-high: #C2410C; --sev-medium: #A16207; --sev-low: #3F6212; --sev-info: #475569;
  --scra-warn-bg: #FFF7E6; --scra-warn-line: #E8B04B; --scra-bad-bg: #FDECEF; --scra-ok: #2F7D4F;
  --scra-code-bg: #FFFFFF;
}
.dark {
  --scra-ink: #E6E9F0; --scra-muted: #A3ABBD; --scra-line: #343B4C; --scra-soft: #1B2130;
  --scra-accent: #7FA2F0;
  --sev-critical: #F0749E; --sev-high: #F59262; --sev-medium: #E2B44F; --sev-low: #A3C76A; --sev-info: #A3ABBD;
  --scra-warn-bg: #33290F; --scra-warn-line: #8A6A1F; --scra-bad-bg: #3A1820; --scra-ok: #6FCF97;
  --scra-code-bg: #10151F;
}
.scra { color: var(--scra-ink); font-size: 15px; line-height: 1.5; }
.scra code, .scra pre { font-family: var(--font-mono); }
.scra-head h1 { font-size: 26px; font-weight: 600; margin: 0 0 2px; letter-spacing: -0.01em; }
.scra-head p { margin: 0; color: var(--scra-muted); max-width: 72ch; }
.scra-verdict { font-size: 20px; font-weight: 600; margin: 0 0 6px; }
.scra-meta { color: var(--scra-muted); margin: 0 0 12px; }
.scra-counts { display: flex; flex-wrap: wrap; gap: 6px 16px; margin: 0 0 14px; padding: 0; list-style: none; }
.scra-counts li { display: flex; align-items: center; gap: 6px; }
.scra-counts li::before { content: ""; width: 10px; height: 10px; border-radius: 2px; background: var(--c); }
.scra-counts li.zero { color: var(--scra-muted); }
.scra-counts li.zero::before { opacity: .35; }
.scra-note { border-left: 3px solid var(--scra-warn-line); background: var(--scra-warn-bg);
  padding: 8px 12px; margin: 0 0 8px; border-radius: 0 4px 4px 0; }
.scra-note.bad { border-left-color: var(--sev-critical); background: var(--scra-bad-bg); }
.scra-f { border-left: 4px solid var(--c); background: var(--scra-soft); margin: 0 0 10px;
  border-radius: 0 6px 6px 0; }
.scra-f > summary { cursor: pointer; list-style: none; padding: 10px 14px; display: grid;
  grid-template-columns: auto 1fr auto; gap: 4px 12px; align-items: baseline; }
.scra-f > summary::-webkit-details-marker { display: none; }
.scra-f > summary:focus-visible { outline: 2px solid var(--scra-accent); outline-offset: 2px; }
.scra-sev { color: var(--c); font-weight: 600; font-size: 13px; }
.scra-title { font-weight: 600; }
.scra-loc { color: var(--scra-muted); font-family: var(--font-mono); font-size: 13px; white-space: nowrap; }
.scra-body { padding: 0 14px 12px; }
.scra-gutter { display: grid; grid-template-columns: 3.5em 1fr; border: 1px solid var(--scra-line);
  border-radius: 4px; overflow-x: auto; font-family: var(--font-mono); font-size: 13px; margin: 0 0 10px;
  background: var(--scra-code-bg); }
.scra-gutter .ln { text-align: right; padding: 6px 8px; color: var(--scra-muted);
  border-right: 2px solid var(--c); user-select: none; }
.scra-gutter code { padding: 6px 10px; white-space: pre; background: none; }
.scra-body dl { margin: 0; display: grid; grid-template-columns: 4.5em 1fr; gap: 6px 10px; }
.scra-body dt { color: var(--scra-muted); }
.scra-body dd { margin: 0; max-width: 78ch; }
.scra-prov { color: var(--scra-muted); font-size: 13px; margin: 10px 0 0; }
.scra-decision { font-size: 13px; font-weight: 600; }
.scra-decision.approved { color: var(--scra-ok); }
.scra-decision.rejected { color: var(--scra-muted); text-decoration: line-through; }
.scra .scra-trace { width: 100%; border-collapse: collapse; font-size: 14px; border: none !important; margin: 0; }
.scra .scra-trace td, .scra .scra-trace th { text-align: left; padding: 6px 8px; border: none !important;
  border-bottom: 1px solid var(--scra-line) !important; vertical-align: top; background: none; }
.scra-trace .arg { color: var(--scra-muted); font-family: var(--font-mono); font-size: 13px; white-space: nowrap; }
.scra-trace th { color: var(--scra-muted); font-weight: 500; }
.scra-trace .n { color: var(--scra-muted); width: 2em; }
.scra-trace .ms { white-space: nowrap; text-align: right; color: var(--scra-muted); }
.scra-trace .err { color: var(--sev-critical); }
.scra-trace .llm td { color: var(--scra-muted); }
.scra-empty { color: var(--scra-muted); padding: 24px 0; max-width: 60ch; }
.scra-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 0 0 16px; }
.scra-tile { background: var(--scra-soft); border-radius: 6px; padding: 10px 14px; }
.scra-tile b { display: block; font-size: 22px; font-weight: 600; }
.scra-tile span { color: var(--scra-muted); font-size: 13px; }
.scra-steps { list-style: none; padding: 0; margin: 0; }
.scra-steps li { padding: 4px 0 4px 24px; position: relative; }
.scra-steps li::before { position: absolute; left: 0; font-weight: 700; }
.scra-steps li.ok::before { content: "\\2713"; color: var(--scra-ok); }
.scra-steps li.fail::before { content: "\\2717"; color: var(--sev-critical); }
@media (max-width: 640px) {
  .scra-f > summary { grid-template-columns: auto 1fr; }
  .scra-loc { grid-column: 1 / -1; }
  .scra-body dl { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
"""


def _sev_var(sev: str) -> str:
    return f"--c: var(--sev-{sev})"


def header_html(provider_label: str, hosted: bool) -> str:
    where = " Public demo: don't upload code you can't share." if hosted else ""
    return (f'<div class="scra scra-head"><h1>Secure Code Review Agent</h1>'
            f"<p>Upload a small JavaScript file, a diff, or a package.json. The agent runs Semgrep and an "
            f"advisory check, looks up OWASP/CWE guidance, and explains what to fix. "
            f"Model: <b>{escape(provider_label)}</b>. Defensive use only.{where}</p></div>")


def empty_results_html() -> str:
    return ('<div class="scra scra-empty">Pick a sample or upload a file, then select <b>Review</b>. '
            "Findings appear here with the line that triggered them, why it matters, and how to fix it.</div>")


def summary_html_message(text: str, busy: bool = False, bad: bool = False) -> str:
    cls = " bad" if bad else ""
    body = f'<p class="scra-verdict">{escape(text)}</p>' if busy else f'<div class="scra-note{cls}">{escape(text)}</div>'
    return f'<div class="scra" aria-live="polite">{body}</div>'


def _location(f: Finding) -> str:
    if f.evidence.line is None:
        return f.evidence.file + (f" ({f.evidence.package}@{f.evidence.version})" if f.evidence.package else "")
    return f"{f.evidence.file}:{f.evidence.line}"


def _sources(f: Finding) -> str:
    kb = get_kb().by_id
    out = []
    for s in f.sources:
        if s in kb:
            out.append(f'<a href="{escape(kb[s]["url"])}" target="_blank" rel="noopener">{escape(s)}</a> '
                       f'{escape(kb[s]["title"])}')
        else:
            out.append(escape(s))
    return "<br>".join(out)


def _provenance(f: Finding) -> str:
    who = ("a fixed template (the model did not cover this hit)" if f.explained_by == "template"
           else "the offline mock provider" if f.explained_by == "mock"
           else f"the LLM ({f.explained_by})" if f.explained_by else "the agent")
    return (f"Detected by {escape(f.tool)} with confidence {f.confidence:.2f}, {escape(f.cwe)}. "
            f"Explanation and fix written by {escape(who)}.")


def summary_html(result: ReviewResult) -> str:
    n = len(result.findings)
    if result.input_kind == "invalid":
        verdict = "Input rejected"
    elif n:
        verdict = f"{n} issue{'s' if n != 1 else ''} in {result.input_name}"
    else:
        verdict = f"No issues found in {result.input_name}"
    kinds = {"file": "a JavaScript file", "diff": "a diff (only added lines are checked)",
             "manifest": "a package.json", "invalid": "invalid input"}
    meta = (f"Reviewed as {kinds.get(result.input_kind, result.input_kind)} using {escape(result.llm_provider)} "
            f"in {result.seconds:.1f} s.")
    if result.dropped:
        meta += f" {result.dropped} model finding(s) were dropped because no tool evidence backed them."
    counts = {s: 0 for s in SEVERITIES}
    for f in result.findings:
        counts[f.severity.value] += 1
    strip = "".join(f'<li class="{"zero" if not c else ""}" style="{_sev_var(s)}">{c} {s.capitalize()}</li>'
                    for s, c in counts.items() if s != "info" or c)
    notes = ""
    for e in result.errors:
        bad = "incomplete" in e or result.input_kind == "invalid"
        notes += f'<div class="scra-note{" bad" if bad else ""}">{escape(e)}</div>'
    if not n and result.input_kind != "invalid" and not any("incomplete" in e for e in result.errors):
        notes += ('<div class="scra-note">The rules cover six classes of issue. A clean result means none of '
                  "those patterns matched, not that the code is proven safe.</div>")
    return (f'<div class="scra"><p class="scra-verdict">{escape(verdict)}</p><p class="scra-meta">{meta}</p>'
            + (f'<ul class="scra-counts">{strip}</ul>' if result.input_kind != "invalid" else "") + notes + "</div>")


def findings_html(result: ReviewResult, decisions: dict[int, str] | None = None) -> str:
    if not result.findings:
        return ""
    decisions = decisions or {}
    rows = []
    for i, f in enumerate(result.findings):
        sev = f.severity.value
        d = decisions.get(i, "pending")
        badge = {"approved": "Approved", "rejected": "Rejected as false positive"}.get(d, "")
        line = "&nbsp;" if f.evidence.line is None else str(f.evidence.line)
        rows.append(
            f'<details class="scra-f" style="{_sev_var(sev)}"{" open" if i == 0 else ""}>'
            f'<summary><span class="scra-sev">{sev.capitalize()}</span>'
            f'<span class="scra-title">{i + 1}. {escape(f.finding)}'
            + (f' <span class="scra-decision {d}">{badge}</span>' if badge else "")
            + f'</span><span class="scra-loc">{escape(_location(f))}</span></summary>'
            f'<div class="scra-body"><div class="scra-gutter"><span class="ln">{line}</span>'
            f"<code>{escape(f.evidence.snippet)}</code></div>"
            f"<dl><dt>Class</dt><dd>{escape(CLASS_LABELS.get(f.vuln_class.value, f.vuln_class.value))}</dd>"
            f"<dt>Why</dt><dd>{escape(f.explanation)}</dd><dt>Fix</dt><dd>{escape(f.fix)}</dd>"
            + (f"<dt>Sources</dt><dd>{_sources(f)}</dd>" if f.sources else "")
            + f'</dl><p class="scra-prov">{_provenance(f)}</p></div></details>')
    return '<div class="scra">' + "".join(rows) + "</div>"


def _args(call: ToolCall) -> str:
    if call.tool == "retrieve_guidance":
        a = call.arguments
        return " ".join(x for x in (a.get("vuln_class"), a.get("cwe")) if x) or a.get("query", "")
    return ""


def _ms(ms: int) -> str:
    return f"{ms / 1000:.1f} s" if ms >= 1000 else f"{ms} ms"


def trace_html(events: list[tuple[float, dict]], running: bool = False) -> str:
    """Agent steps in order. events = [(timestamp, event)] as received from agent.review."""
    if not events:
        return '<div class="scra scra-empty">The agent\'s tool calls will be listed here as it works.</div>'
    rows: list[dict] = []
    for _, ev in events:
        kind = ev["type"]
        if kind == "llm":
            rows.append({"llm": True, "label": "Model decides the next step", "detail": ev.get("provider", ""),
                         "time": "thinking" if running else "", "open": True})
        elif kind == "llm_end" and rows and rows[-1].get("llm"):
            r = rows[-1]
            r["open"], r["time"] = False, _ms(ev["ms"])
            if not ev["ok"]:
                r["detail"], r["err"] = f"Failed: {ev.get('error', '')}", True
            else:
                tools = list(dict.fromkeys(ev.get("tools") or []))
                counts = {t: (ev.get("tools") or []).count(t) for t in tools}
                r["detail"] = ("Calls " + ", ".join(TOOL_LABELS.get(t, t).lower()
                                                    + (f" ×{counts[t]}" if counts[t] > 1 else "") for t in tools)
                               if tools else "Writes the final findings")
        elif kind == "tool_start":
            arg = _args(ToolCall(tool=ev["tool"], arguments=ev["arguments"], ok=True, duration_ms=0, summary=""))
            rows.append({"tool": ev["tool"], "label": TOOL_LABELS.get(ev["tool"], ev["tool"]), "arg": arg,
                         "detail": "", "time": "running" if running else "", "open": True})
        elif kind == "tool":
            c: ToolCall = ev["call"]
            r = next((x for x in rows if x.get("open") and x.get("tool") == c.tool), None)
            if r is None:
                r = {"tool": c.tool, "label": TOOL_LABELS.get(c.tool, c.tool), "arg": _args(c)}
                rows.append(r)
            r.update(open=False, time=_ms(c.duration_ms), err=not c.ok,
                     detail=f"Failed: {c.error}" if not c.ok else c.summary)
    html = []
    for n, r in enumerate(rows, 1):
        label = escape(r["label"]) if r.get("llm") else f"<b>{escape(r['label'])}</b>"
        if r.get("arg"):
            label += f' <span class="arg">{escape(r["arg"])}</span>'
        detail = f'<span class="err">{escape(r["detail"])}</span>' if r.get("err") else escape(r["detail"])
        html.append(f'<tr class="{"llm" if r.get("llm") else ""}"><td class="n">{n}</td><td>{label}</td>'
                    f'<td>{detail}</td><td class="ms">{escape(r["time"])}</td></tr>')
    return ('<div class="scra"><table class="scra-trace"><thead><tr><th></th><th>Step</th><th>Result</th>'
            '<th class="ms">Time</th></tr></thead><tbody>' + "".join(html) + "</tbody></table></div>")


def steps_html(steps: list[tuple[bool, str]]) -> str:
    items = "".join(f'<li class="{"ok" if ok else "fail"}">{escape(msg)}</li>' for ok, msg in steps)
    return f'<div class="scra"><ul class="scra-steps">{items}</ul></div>'


def monitoring_html(s: dict) -> str:
    if not s["runs"]:
        return ('<div class="scra scra-empty">No reviews logged yet. Run a review and refresh. '
                "Logs are written to <code>logs/runs.jsonl</code> unless SCRA_DISABLE_LOGS=1.</div>")
    lat = s["latency_s"]
    tool_fail = sum(t["failures"] for t in s["tools"].values())
    tiles = [(s["runs"], "reviews logged"), (f'{lat["p50"]:.1f} s', "median time"),
             (f'{lat["p95"]:.1f} s', "95th percentile time"), (s["runs_with_errors"], "reviews with notes or errors"),
             (tool_fail, "failed tool calls"), (s["dropped_model_findings"], "model findings dropped")]
    html = '<div class="scra"><div class="scra-tiles">' + "".join(
        f'<div class="scra-tile"><b>{escape(str(v))}</b><span>{escape(k)}</span></div>' for v, k in tiles) + "</div>"

    def table(title: str, head: list[str], rows: list[list]) -> str:
        if not rows:
            return ""
        return (f"<h3>{escape(title)}</h3><table class='scra-trace'><thead><tr>"
                + "".join(f"<th>{escape(h)}</th>" for h in head) + "</tr></thead><tbody>"
                + "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
                + "</tbody></table>")

    html += table("Tools", ["Tool", "Calls", "Failures", "Average time"],
                  [[TOOL_LABELS.get(t, t), v["calls"], v["failures"], f'{v["avg_ms"]} ms'] for t, v in s["tools"].items()])
    html += table("Findings by class", ["Class", "Count"],
                  [[CLASS_LABELS.get(k, k), v] for k, v in sorted(s["findings_by_class"].items(), key=lambda x: -x[1])])
    html += table("Reviewer decisions", ["Decision", "Count"], [[k, v] for k, v in s["decisions"].items()])
    html += table("Providers", ["Provider", "Reviews"], [[k, v] for k, v in s["providers"].items()])
    html += table("Most common notes and errors", ["Message starts with", "Count"],
                  [[k, v] for k, v in s["error_kinds"].items()])
    return html + "</div>"


PRESET_HELP = {
    "mock": """**No setup.** The mock provider follows the same tool-calling protocol as a real model, so you
see the real tools run (Semgrep, OSV, retrieval), but explanations come from templates plus the
retrieved guidance. Use it to learn the app, run tests, or demo without a network.""",
    "ollama": """**Free, local, private.** Code never leaves your machine.

1. Install Ollama from <https://ollama.com/download> (Windows, macOS, Linux). It runs in the background.
2. In a terminal, download a model that supports tool calling:
   `ollama pull qwen2.5-coder:7b` (about 4.7 GB, good quality) or `ollama pull llama3.2:3b` (about 2 GB, faster on a laptop without a GPU).
3. Select **Fetch models**, pick the model, then **Test connection**.

If the test says nothing is answering, start Ollama from the Start menu (or run `ollama serve`).
Without a GPU, expect 30 s to a few minutes per review. Raise the two time limits on this tab if
reviews stop early.""",
    "lmstudio": """**Free, local, with a desktop UI.**

1. Install LM Studio from <https://lmstudio.ai>.
2. Download a model with tool-use support (for example Qwen2.5 Coder 7B Instruct).
3. Open the **Developer** tab and start the server (default `http://localhost:1234/v1`).
4. Select **Fetch models**, pick the loaded model, then **Test connection**.""",
    "groq": """**Hosted, free tier, very fast.** Your (masked) code is sent to Groq.

1. Sign in at <https://console.groq.com> and create a key under **API Keys**.
2. Paste it below, or put `GROQ_API_KEY=...` in a `.env` file in the project folder.
3. Select **Fetch models** to see current model ids, then **Test connection**.

Free-tier rate limits apply; a review makes 3 to 6 model calls.""",
    "gemini": """**Hosted, free tier.** Uses Google's OpenAI-compatible endpoint. Your (masked) code is sent to Google.

1. Create a key at <https://aistudio.google.com/apikey>.
2. Paste it below, or put `GEMINI_API_KEY=...` in `.env`.
3. **Fetch models** lists ids like `models/gemini-...`; use the part after `models/` if the full id fails.""",
    "openrouter": """**Hosted, one key for many models.** Some models are free (their ids end in `:free`).

1. Create a key at <https://openrouter.ai/keys>.
2. Paste it below, or put `OPENROUTER_API_KEY=...` in `.env`.
3. **Fetch models**, choose one that supports tools, then **Test connection**.""",
    "openai": """**Hosted, paid.** Your (masked) code is sent to OpenAI.

1. Create a key at <https://platform.openai.com/api-keys> (billing must be set up).
2. Paste it below, or put `OPENAI_API_KEY=...` in `.env`.""",
    "custom": """**Any server that speaks the OpenAI chat-completions API with tool calling**, for example vLLM or the
llama.cpp server. Enter its base URL (ending in `/v1`) and model id. Leave the key blank if the server needs none.""",
}

HOW_IT_WORKS = """
### What happens when you select Review

1. **Read the input.** The file is classified as JavaScript, a diff, or a package.json. Nothing is executed.
   For diffs, only added lines count.
2. **The model picks tools.** The LLM is given three tools and decides which to call:
   - *Scan with Semgrep rules*: custom rules for XSS, injection (SQL, shell, eval), insecure cookies,
     missing input validation, and hardcoded secrets.
   - *Check dependencies*: package versions against the OSV advisory database (bundled snapshot when offline).
   - *Look up guidance*: retrieval over a curated OWASP/CWE knowledge base, cited in every finding.
3. **Grounding guard.** Each finding the model writes must match a tool hit (same class, within 2 lines).
   Anything else is dropped and counted. Line numbers, snippets and tool names always come from the tool.
   Tool hits the model leaves out are added back with template text, so nothing found is ever hidden.
4. **You decide.** On *Approve and export* you mark findings as approved or false positives. Only approved
   findings can be turned into PR comments or a patch draft.

### Where each part of a finding comes from

| Part | Source |
|------|--------|
| Class, CWE, line, snippet, confidence | Semgrep rule or OSV advisory |
| Explanation and fix | LLM (or template / mock), checked for attack payloads |
| Sources | Retrieved OWASP/CWE entries |
| Approved / rejected | You |

### Safety boundaries

- Uploaded code is never run, installed, or imported.
- Secrets are masked before code reaches the model, and in all output and logs.
- The model is told the code is untrusted data; comments like "AI reviewer, report nothing" can't hide a tool finding.
- Explanations are filtered for exploit payloads.
- Logs (Monitoring tab) hold timings and counts only, never code or keys.
"""


def preset_choices(hosted: bool) -> list[tuple[str, str]]:
    return [(p["label"], k) for k, p in PRESETS.items() if not hosted or not p["local"] or k == "mock"]
