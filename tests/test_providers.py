"""Provider plumbing tests with faked HTTP. These check request/response handling only —
they do not prove a given model follows the protocol well. That is evaluated in Week 6."""
import json

import pytest
import requests

from scra import llm
from scra.agent import review


class FakeResp:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def _scripted(replies, seen):
    it = iter(replies)

    def post(url, json=None, **kw):
        seen.append((url, json))
        return FakeResp(next(it))

    return post


def test_ollama_tool_loop(monkeypatch, sample):
    final = {"findings": [{
        "finding": "DOM XSS via innerHTML", "vuln_class": "xss", "cwe": "CWE-79",
        "evidence": {"file": "xss_dom_vuln.js", "line": 4, "snippet": "el.innerHTML = ..."},
        "severity": "high", "explanation": "Hash value is parsed as HTML.",
        "fix": "Use textContent.", "confidence": 0.8, "sources": ["CWE-79"], "tool": "semgrep"}]}
    seen = []
    monkeypatch.setattr(llm.requests, "post", _scripted([
        {"message": {"content": "", "tool_calls": [{"function": {"name": "run_semgrep", "arguments": {}}}]}},
        {"message": {"content": "", "tool_calls": [{"function": {"name": "retrieve_guidance",
                                                                 "arguments": '{"query": "dom xss", "cwe": "CWE-79"}'}}]}},
        {"message": {"content": json.dumps(final)}},
    ], seen))
    r = review("xss_dom_vuln.js", sample("xss_dom_vuln.js"), provider=llm.OllamaProvider())
    assert r.llm_provider.startswith("ollama:")
    assert [t.tool for t in r.trace] == ["parse_input", "run_semgrep", "retrieve_guidance"]
    assert r.findings[0].finding == "DOM XSS via innerHTML" and r.dropped == 0
    assert seen[0][0].endswith("/api/chat") and seen[0][1]["tools"]
    assert any(m["role"] == "tool" for m in seen[1][1]["messages"])


def test_openai_compat_message_format(monkeypatch, sample):
    seen = []
    monkeypatch.setattr(llm.requests, "post", _scripted([
        {"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "run_semgrep", "arguments": "{}"}}]}}]},
        {"choices": [{"message": {"content": '{"findings": []}'}}]},
    ], seen))
    r = review("xss_dom_vuln.js", sample("xss_dom_vuln.js"), provider=llm.OpenAICompatProvider())
    second = seen[1][1]["messages"]
    assistant = next(m for m in second if m.get("tool_calls"))
    assert isinstance(assistant["tool_calls"][0]["function"]["arguments"], str)  # OpenAI wants a JSON string
    tool_msg = next(m for m in second if m["role"] == "tool")
    assert tool_msg["tool_call_id"] == "c1" and "tool_name" not in tool_msg
    assert [(f.vuln_class.value, f.evidence.line) for f in r.findings] == [("xss", 4)]  # restored by guard


def test_provider_network_error_becomes_llm_error(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(llm.requests, "post", boom)
    with pytest.raises(llm.LLMError):
        llm.OllamaProvider().chat([], [])


def test_get_provider_default_is_mock(monkeypatch):
    monkeypatch.delenv("SCRA_LLM", raising=False)
    assert llm.get_provider().name == "mock"
