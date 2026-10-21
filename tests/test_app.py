"""UI handlers and rendering, tested without starting a server."""
import gradio as gr
import pytest

from scra import app, ui_render
from scra.agent import review
from scra.approval import APPROVED, ReviewSession


def _last(gen):
    out = None
    for out in gen:
        pass
    return out


def test_run_review_streams_steps_then_results(sample):
    outputs = list(app.run_review("xss_dom_vuln.js", sample("xss_dom_vuln.js").decode(), True,
                                  "mock", "", "", "", 60, 120))
    assert len(outputs) >= 3  # a "reviewing" state, live trace updates, final results
    assert "Reviewing" in outputs[0][0]
    summary, findings, trace, data, path, session = outputs[-1][:6]
    assert "1 issue in xss_dom_vuln.js" in summary
    assert "textContent" in findings or "innerHTML" in findings
    assert "Scan with Semgrep rules" in trace and "thinking" not in trace
    assert data["findings"][0]["vuln_class"] == "xss" and path.endswith(".json")
    assert isinstance(session, ReviewSession)


def test_decisions_are_mutually_exclusive(sample):
    raw = sample("cookie_vuln.js").decode()
    s = ReviewSession(review("cookie_vuln.js", raw), raw)
    app.update_decisions(s, [0, 1], [], "approve")
    app.update_decisions(s, [0, 1], [1], "reject")  # rejecting #2 removes it from approved
    assert s.decisions == {0: "approved", 1: "rejected"}
    html = app.update_decisions(s, [0], [1], "approve")[0]
    assert "Approved" in html and "Rejected as false positive" in html


def test_patch_handler_refuses_unapproved(sample):
    raw = sample("xss_dom_vuln.js").decode()
    s = ReviewSession(review("xss_dom_vuln.js", raw), raw)
    assert "not been approved" in app.make_patch(s, 0, "mock", "", "", "", 60)
    s.decide(0, APPROVED)
    assert "```diff" in app.make_patch(s, 0, "mock", "", "", "", 60)


def test_hosted_mode_blocks_local_servers(monkeypatch):
    monkeypatch.setenv("SCRA_HOSTED", "1")
    with pytest.raises(gr.Error):
        app.make_provider("ollama", "http://localhost:11434", "", "", 60)
    p = app.make_provider("groq", "http://169.254.169.254/latest", "", "k", 60)
    assert p.base == "https://api.groq.com/openai/v1"  # visitor URL ignored
    assert all(k in ("mock", "groq", "gemini", "openrouter", "openai")
               for _, k in ui_render.preset_choices(hosted=True))


def test_sample_loader_stays_inside_data_folder():
    with pytest.raises(gr.Error):
        app.load_sample("../pyproject.toml")
    name, update = app.load_sample("samples/package_vuln.json")
    assert name == "package.json" and update["language"] == "json"


def test_rendered_html_escapes_uploaded_code(sample):
    code = 'document.body.innerHTML = "<img src=x onerror=alert(1)>" + location.hash;\n'
    r = review("evil.js", code)
    html = ui_render.findings_html(r)
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_invalid_input_renders_rejection():
    r = review("notes.txt", "hello")
    assert "Input rejected" in ui_render.summary_html(r)
