"""Gradio web app (Weeks 5-7).

    python -m scra.app            # http://127.0.0.1:7860
    SCRA_HOST=0.0.0.0 python -m scra.app      # listen on the network (Docker does this)
    SCRA_HOSTED=1                 # public deployment: hosted LLM presets only, no custom URLs

Tabs: Review (input, findings, live agent trace), Approve and export (human approval step,
PR comments, patch drafts), LLM settings (presets, model list, connection test), Monitoring
(aggregated logs), How it works.
"""
from __future__ import annotations

import json
import os
import queue
import tempfile
import threading
import time
from pathlib import Path

import gradio as gr

from . import ui_render as ui
from .agent import review
from .approval import APPROVED, PENDING, REJECTED, ApprovalRequired, ReviewSession, draft_patch, draft_pr_comments
from .config import ROOT, hosted, load_dotenv, server_address
from .llm import PRESETS, LLMError, Provider, build_provider, check_provider, default_preset, resolve_preset
from .logging_utils import log_event, summarize_logs
from .tools import InputError, parse_input

DATA = ROOT / "data"
SAMPLE_DIRS = [("Sample", DATA / "samples"), ("Held-out", DATA / "heldout"), ("Scenario", DATA / "demo")]
FILE_TYPES = [".js", ".mjs", ".cjs", ".jsx", ".diff", ".patch", ".json", ".txt"]


# ------------------------------------------------------------------ inputs
def _labels() -> dict[str, dict]:
    out = {}
    for path in (DATA / "labels.json", DATA / "heldout_labels.json"):
        if path.is_file():
            out.update(json.loads(path.read_text(encoding="utf-8"))["samples"])
    demo = DATA / "demo" / "scenarios.json"
    if demo.is_file():
        out.update({k: {"note": v} for k, v in json.loads(demo.read_text(encoding="utf-8")).items()})
    return out


def sample_choices() -> list[tuple[str, str]]:
    labels, choices = _labels(), []
    for group, folder in SAMPLE_DIRS:
        if not folder.is_dir():
            continue
        for p in sorted(folder.iterdir()):
            if p.suffix not in FILE_TYPES or p.name == "scenarios.json":
                continue
            spec = labels.get(p.name, {})
            if "note" in spec:
                desc = spec["note"]
            else:
                classes = sorted({ui.CLASS_LABELS[f["class"]].lower() for f in spec.get("findings", [])})
                desc = ", ".join(classes) if classes else "no issues expected"
            choices.append((f"{group}: {p.name} ({desc})", str(p.relative_to(DATA)).replace("\\", "/")))
    return choices


def _language(name: str) -> str | None:
    n = name.lower()
    return "json" if n.endswith(".json") else "javascript" if n.endswith((".js", ".mjs", ".cjs", ".jsx")) else None


def load_sample(rel: str):
    if not rel:
        return gr.skip(), gr.skip()
    p = (DATA / rel).resolve()
    if DATA.resolve() not in p.parents or not p.is_file():
        raise gr.Error("Unknown sample.")
    name = "package.json" if p.name.startswith("package") and p.suffix == ".json" else p.name
    return name, gr.update(value=p.read_text(encoding="utf-8"), language=_language(name))


def load_upload(path: str | None):
    if not path:
        return gr.skip(), gr.skip()
    p = Path(path)
    raw = p.read_bytes()
    try:
        parse_input(p.name, raw)
    except InputError as exc:
        gr.Warning(f"{p.name}: {exc}")
        if b"\x00" in raw or len(raw) > 200_000:
            return gr.skip(), gr.skip()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return gr.skip(), gr.skip()
    return p.name, gr.update(value=text, language=_language(p.name))


# ---------------------------------------------------------------- provider
def make_provider(preset: str, base_url: str, model: str, api_key: str, timeout: float) -> Provider:
    if preset not in PRESETS:
        raise gr.Error("Choose an LLM preset on the LLM settings tab.")
    if hosted():
        if PRESETS[preset]["local"] and preset != "mock":
            raise gr.Error("Local model servers are disabled on this public deployment.")
        base_url = ""  # never let visitors point the server at their own URL
    return build_provider(preset, base_url.strip(), (model or "").strip(), (api_key or "").strip(), int(timeout))


def provider_label(preset: str, model: str) -> str:
    p = resolve_preset(preset if preset in PRESETS else "mock")
    if p["kind"] == "mock":
        return "mock provider (no LLM)"
    return f"{model or p['model']} via {p['label'].split(' (')[0]}"


# ----------------------------------------------------------------- review
def _choices(session: ReviewSession | None) -> list[tuple[str, int]]:
    if session is None:
        return []
    return [(f"{i + 1}. [{f.severity.value}] {f.finding}", i) for i, f in enumerate(session.result.findings)]


def _decision_lists(session: ReviewSession | None) -> tuple[list[int], list[int]]:
    if session is None:
        return [], []
    return ([i for i, d in session.decisions.items() if d == APPROVED],
            [i for i, d in session.decisions.items() if d == REJECTED])


def _approval_outputs(session: ReviewSession | None):
    choices = _choices(session)
    approved, rejected = _decision_lists(session)
    approved_choices = [c for c in choices if c[1] in approved]
    if session is None:
        status = "Run a review first. Its findings will appear here for you to approve or reject."
    else:
        n = len(session.result.findings)
        pending = n - len(approved) - len(rejected)
        status = (f"**{len(approved)} approved, {len(rejected)} rejected, {pending} undecided** "
                  f"of {n} finding(s) in `{session.result.input_name}`." if n else
                  f"`{session.result.input_name}` has no findings to approve.")
    return (gr.update(choices=choices, value=approved), gr.update(choices=choices, value=rejected), status,
            gr.update(choices=approved_choices, value=approved_choices[0][1] if approved_choices else None))


def run_review(name, code_text, offline, preset, base_url, model, api_key, timeout, deadline):
    name = (name or "").strip() or "snippet.js"
    try:
        provider = make_provider(preset, base_url, model, api_key, timeout)
    except gr.Error as exc:
        yield (ui.summary_html_message(str(exc)), "", gr.skip(), gr.skip(), gr.skip(), gr.skip(),
               *[gr.skip()] * 4, gr.update(interactive=True))
        return
    events: list[tuple[float, dict]] = []
    q: queue.Queue = queue.Queue()
    box: dict = {}

    def worker():
        try:
            box["result"] = review(name, code_text or "", provider=provider, offline=bool(offline),
                                   on_event=lambda ev: q.put((time.perf_counter(), ev)), deadline_s=int(deadline))
        except Exception as exc:  # noqa: BLE001 - surface anything unexpected instead of hanging the UI
            box["error"] = f"{type(exc).__name__}: {exc}"

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    running = ui.summary_html_message(f"Reviewing {name} with {provider.name}...", busy=True)
    yield (running, "", ui.trace_html(events, running=True), gr.skip(), gr.skip(), gr.skip(),
           *[gr.skip()] * 4, gr.update(interactive=False))
    while t.is_alive() or not q.empty():
        try:
            events.append(q.get(timeout=0.25))
        except queue.Empty:
            continue
        yield (running, "", ui.trace_html(events, running=True), gr.skip(), gr.skip(), gr.skip(),
               *[gr.skip()] * 4, gr.skip())
    t.join()
    if "error" in box:
        yield (ui.summary_html_message("The review crashed: " + box["error"], bad=True), "",
               ui.trace_html(events), gr.skip(), gr.skip(), None, *_approval_outputs(None),
               gr.update(interactive=True))
        return
    result = box["result"]
    session = ReviewSession(result, code_text or "")
    out = Path(tempfile.gettempdir()) / f"scra-review-{result.review_id}.json"
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    yield (ui.summary_html(result), ui.findings_html(result), ui.trace_html(events),
           json.loads(result.model_dump_json()), str(out), session, *_approval_outputs(session),
           gr.update(interactive=True))


# --------------------------------------------------------------- approval
def update_decisions(session: ReviewSession | None, approved: list[int], rejected: list[int], changed: str):
    if session is None:
        return (gr.skip(), *_approval_outputs(None))
    approved, rejected = set(approved or []), set(rejected or [])
    # The list the reviewer just touched wins if a finding ended up in both.
    if changed == "approve":
        rejected -= approved
    else:
        approved -= rejected
    for i in range(len(session.result.findings)):
        session.decide(i, APPROVED if i in approved else REJECTED if i in rejected else PENDING)
    return (ui.findings_html(session.result, session.decisions), *_approval_outputs(session))


def make_pr_comments(session: ReviewSession | None):
    if session is None:
        return "Run a review first.", None
    try:
        md, comments = draft_pr_comments(session)
    except ApprovalRequired as exc:
        return f"**{exc}**", None
    folder = Path(tempfile.mkdtemp(prefix="scra-pr-"))
    (folder / "review-comments.md").write_text(md, encoding="utf-8")
    (folder / "review-comments.json").write_text(json.dumps(comments, indent=2), encoding="utf-8")
    return md, [str(folder / "review-comments.md"), str(folder / "review-comments.json")]


def make_patch(session: ReviewSession | None, index, preset, base_url, model, api_key, timeout):
    if session is None:
        return "Run a review first."
    if index is None:
        return "**Approve a finding first**, then choose it here."
    try:
        provider = make_provider(preset, base_url, model, api_key, timeout)
        p = draft_patch(session, int(index), provider)
    except ApprovalRequired as exc:
        return f"**{exc}**"
    except gr.Error as exc:
        return f"**{exc}**"
    if not p.diff:
        return p.note
    source = {"rule": "a built-in rewrite rule", "llm": f"the LLM ({provider.name})"}[p.method]
    return (f"Drafted by {source}. {p.note}\n\n```diff\n{p.diff}\n```\n\n"
            "This is a suggestion only. Nothing has been changed; copy it into your editor and test it.")


# ----------------------------------------------------------- llm settings
def on_preset(preset: str):
    p = resolve_preset(preset)
    key_hint = ""
    if p.get("key_env"):
        key_hint = (f"Using {p['key_env']} from the environment" if os.getenv(p["key_env"])
                    else f"Paste a key, or set {p['key_env']} in .env")
    is_mock = p["kind"] == "mock"
    return (gr.update(value=p["base_url"], visible=not is_mock, interactive=not hosted()),
            gr.update(choices=[p["model"]] if p["model"] else [], value=p["model"] or None, visible=not is_mock),
            gr.update(visible=p["needs_key"] or preset == "custom", placeholder=key_hint or "Not needed for this server",
                      value=""),
            ui.PRESET_HELP[preset], "", ui.header_html(provider_label(preset, p["model"]), hosted()))


def fetch_models(preset, base_url, model, api_key, timeout):
    try:
        provider = make_provider(preset, base_url, model, api_key, timeout)
        models = provider.list_models() if hasattr(provider, "list_models") else []
    except (LLMError, gr.Error) as exc:
        return gr.skip(), ui.steps_html([(False, str(exc))])
    if not models:
        return gr.skip(), ui.steps_html([(False, "The server returned no models. For Ollama, run `ollama pull <model>`.")])
    value = model if model in models else models[0]
    return gr.update(choices=models, value=value), ui.steps_html([(True, f"Found {len(models)} model(s).")])


def test_connection(preset, base_url, model, api_key, timeout):
    try:
        provider = make_provider(preset, base_url, model, api_key, timeout)
    except gr.Error as exc:
        return ui.steps_html([(False, str(exc))])
    steps = check_provider(provider)
    log_event("connection_test", preset=preset, ok=all(ok for ok, _ in steps))
    return ui.steps_html(steps)


def refresh_monitoring():
    s = summarize_logs()
    rows = [[r.get("ts", "").replace("T", " ").replace("+00:00", ""), r.get("input_kind", ""),
             r.get("provider", ""), round(r.get("seconds", 0), 1), r.get("findings", 0), r.get("dropped", 0),
             "; ".join(r.get("errors", []))[:160]] for r in s["recent"]]
    return ui.monitoring_html(s), rows


# ------------------------------------------------------------------- build
THEME_COLOR = gr.themes.Color(c50="#EEF3FC", c100="#DCE6F9", c200="#B9CCF2", c300="#8FADE8", c400="#5F86DA",
                              c500="#2B59C3", c600="#234AA6", c700="#1D3D88", c800="#18326E", c900="#142A5A",
                              c950="#0C1A3A", name="review")


def theme() -> gr.themes.Base:
    return gr.themes.Base(
        primary_hue=THEME_COLOR, neutral_hue=gr.themes.colors.slate, radius_size=gr.themes.sizes.radius_sm,
        font=[gr.themes.GoogleFont("IBM Plex Sans"), "system-ui", "sans-serif"],
        font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "ui-monospace", "Consolas", "monospace"],
    )


def build() -> gr.Blocks:
    preset0 = default_preset()
    if hosted() and PRESETS[preset0]["local"]:
        preset0 = "mock"
    p0 = resolve_preset(preset0)
    samples = sample_choices()
    first = next((v for _, v in samples if v.endswith("mixed_vuln.js")), samples[0][1] if samples else None)
    first_name, first_code = load_sample(first) if first else ("snippet.js", gr.update(value=""))

    with gr.Blocks(title="Secure Code Review Agent") as demo:
        session = gr.State(None)
        header = gr.HTML(ui.header_html(provider_label(preset0, p0["model"]), hosted()))

        with gr.Tabs():
            # -------------------------------------------------------- Review
            with gr.Tab("Review", id="review"):
                with gr.Row(equal_height=False):
                    with gr.Column(scale=5, min_width=320):
                        sample = gr.Dropdown(samples, value=first, label="Start from a sample",
                                             info="Loads it into the editor. Edit it freely before reviewing.")
                        with gr.Row():
                            filename = gr.Textbox(first_name, label="File name", scale=3,
                                                  info="Decides how the input is read: .js, .diff, or package.json")
                            upload = gr.UploadButton("Upload a file", file_types=FILE_TYPES, scale=1)
                        code = gr.Code(first_code["value"], language=_language(first_name), label="Code to review",
                                       interactive=True, lines=16, max_lines=40)
                        review_btn = gr.Button("Review", variant="primary", size="lg")
                        offline = gr.Checkbox(True, label="Use the bundled advisory snapshot for package.json",
                                              info="Uncheck to query the live OSV database (needs internet).")
                    with gr.Column(scale=7, min_width=320):
                        summary = gr.HTML(ui.empty_results_html())
                        findings = gr.HTML("")
                        with gr.Accordion("Agent steps", open=True):
                            trace = gr.HTML(ui.trace_html([]))
                        with gr.Accordion("Structured output (JSON)", open=False):
                            json_out = gr.JSON(label="ReviewResult")
                            download = gr.DownloadButton("Download JSON", value=None)

            # ------------------------------------------------- Approve/export
            with gr.Tab("Approve and export", id="approve"):
                gr.Markdown("Findings are suggestions until a person checks them. Approve the ones that are real "
                            "and reject false positives. **PR comments and patch drafts are only produced for "
                            "approved findings**, and nothing is posted or applied: you copy or download the result.")
                decision_status = gr.Markdown("Run a review first. Its findings will appear here for you to "
                                              "approve or reject.")
                with gr.Row():
                    approve = gr.CheckboxGroup([], label="Approve (real issue)", type="value")
                    reject = gr.CheckboxGroup([], label="Reject (false positive)", type="value")
                with gr.Row(equal_height=False):
                    with gr.Column():
                        pr_btn = gr.Button("Draft PR comments")
                        pr_files = gr.File(label="Download comments", file_count="multiple", interactive=False)
                        pr_md = gr.Markdown()
                    with gr.Column():
                        patch_pick = gr.Dropdown([], label="Approved finding to patch", type="value")
                        patch_btn = gr.Button("Draft a patch")
                        patch_md = gr.Markdown()

            # ---------------------------------------------------- Settings
            with gr.Tab("LLM settings", id="settings"):
                with gr.Row(equal_height=False):
                    with gr.Column(scale=5):
                        preset = gr.Dropdown(ui.preset_choices(hosted()), value=preset0, label="Model provider")
                        base_url = gr.Textbox(p0["base_url"], label="Server URL",
                                              visible=p0["kind"] != "mock", interactive=not hosted())
                        with gr.Row():
                            model = gr.Dropdown([p0["model"]] if p0["model"] else [],
                                                value=p0["model"] or None, label="Model",
                                                allow_custom_value=True, scale=3,
                                                visible=p0["kind"] != "mock")
                            fetch_btn = gr.Button("Fetch models", scale=1)
                        api_key = gr.Textbox("", label="API key", type="password",
                                             visible=p0["needs_key"],
                                             info="Kept in memory for this browser session only. Never logged or saved.")
                        with gr.Row():
                            timeout = gr.Slider(10, 600, value=int(os.getenv("SCRA_LLM_TIMEOUT", "120")), step=10,
                                                label="Per-call timeout (s)")
                            deadline = gr.Slider(30, 900, value=int(os.getenv("SCRA_AGENT_DEADLINE", "240")),
                                                 step=10, label="Whole-review time limit (s)")
                        test_btn = gr.Button("Test connection", variant="primary")
                        test_out = gr.HTML()
                    with gr.Column(scale=5):
                        preset_help = gr.Markdown(ui.PRESET_HELP[preset0])
                        gr.Markdown("Settings apply to the next review. The connection test checks three things: "
                                    "the server answers, the model exists, and the model can call tools. Tool "
                                    "calling is what lets the model drive the scanners.")

            # -------------------------------------------------- Monitoring
            with gr.Tab("Monitoring", id="monitoring") as mon_tab:
                refresh = gr.Button("Refresh")
                mon = gr.HTML()
                recent = gr.Dataframe(headers=["Time (UTC)", "Input", "Provider", "Seconds", "Found",
                                               "Dropped", "Notes"], label="Recent reviews", interactive=False,
                                      wrap=True, column_widths=["16%", "7%", "17%", "8%", "7%", "8%", "37%"])

            with gr.Tab("How it works", id="about"):
                gr.Markdown(ui.HOW_IT_WORKS)

        # ------------------------------------------------------------ events
        llm_inputs = [preset, base_url, model, api_key, timeout]
        sample.change(load_sample, sample, [filename, code])
        upload.upload(load_upload, upload, [filename, code])
        filename.change(lambda n: gr.update(language=_language(n or "")), filename, code)
        review_btn.click(run_review, [filename, code, offline, *llm_inputs, deadline],
                         [summary, findings, trace, json_out, download, session, approve, reject, decision_status,
                          patch_pick, review_btn])
        approve.input(lambda s, a, r: update_decisions(s, a, r, "approve"), [session, approve, reject],
                      [findings, approve, reject, decision_status, patch_pick])
        reject.input(lambda s, a, r: update_decisions(s, a, r, "reject"), [session, approve, reject],
                     [findings, approve, reject, decision_status, patch_pick])
        pr_btn.click(make_pr_comments, session, [pr_md, pr_files])
        patch_btn.click(make_patch, [session, patch_pick, *llm_inputs], patch_md)
        preset.change(on_preset, preset, [base_url, model, api_key, preset_help, test_out, header])
        model.change(lambda p, m: ui.header_html(provider_label(p, m), hosted()), [preset, model], header)
        fetch_btn.click(fetch_models, llm_inputs, [model, test_out])
        test_btn.click(test_connection, llm_inputs, test_out)
        refresh.click(refresh_monitoring, None, [mon, recent])
        mon_tab.select(refresh_monitoring, None, [mon, recent])
    return demo


def main() -> None:
    load_dotenv()
    host, port = server_address()
    build().queue(default_concurrency_limit=4).launch(server_name=host, server_port=port, theme=theme(),
                                                       css=ui.CSS, show_error=True)


if __name__ == "__main__":
    main()
