"""Presets, UI-supplied settings, and the connection check (faked HTTP)."""
import pytest
import requests

from scra import llm


class FakeResp:
    def __init__(self, payload, status=200):
        self.payload, self.status_code, self.text = payload, status, str(payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error", response=self)

    def json(self):
        return self.payload


def test_build_provider_uses_preset_then_overrides():
    p = llm.build_provider("groq", api_key="gsk_test")
    assert isinstance(p, llm.OpenAICompatProvider)
    assert p.base == "https://api.groq.com/openai/v1" and p.key == "gsk_test"
    p = llm.build_provider("ollama", base_url="http://10.0.0.5:11434/", model="llama3.2:3b", timeout=30)
    assert p.url == "http://10.0.0.5:11434" and p.model == "llama3.2:3b" and p.timeout == 30
    assert isinstance(llm.build_provider("mock"), llm.MockProvider)


def test_key_falls_back_to_preset_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "from-env-key")
    assert llm.build_provider("gemini").key == "from-env-key"


def test_check_provider_happy_path(monkeypatch):
    monkeypatch.setattr(llm.requests, "get", lambda *a, **k: FakeResp({"models": [{"name": "qwen2.5-coder:7b"}]}))
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: FakeResp(
        {"message": {"content": "", "tool_calls": [{"function": {"name": "ping", "arguments": {}}}]}}))
    steps = llm.check_provider(llm.OllamaProvider())
    assert [ok for ok, _ in steps] == [True, True] and "tool calling" in steps[-1][1]


def test_check_provider_missing_model_suggests_pull(monkeypatch):
    monkeypatch.setattr(llm.requests, "get", lambda *a, **k: FakeResp({"models": [{"name": "llama3.2:3b"}]}))
    steps = llm.check_provider(llm.OllamaProvider(model="qwen2.5-coder:7b"))
    assert steps[-1][0] is False and "ollama pull qwen2.5-coder:7b" in steps[-1][1]


def test_check_provider_model_without_tools(monkeypatch):
    monkeypatch.setattr(llm.requests, "get", lambda *a, **k: FakeResp({"data": [{"id": "m"}]}))
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: FakeResp({"choices": [{"message": {"content": "pong"}}]}))
    steps = llm.check_provider(llm.OpenAICompatProvider(model="m"))
    assert steps[-1][0] is False and "did not call the tool" in steps[-1][1]


def test_connection_refused_is_explained(monkeypatch):
    def refuse(*a, **k):
        raise requests.ConnectionError("Max retries exceeded ... [WinError 10061]")

    monkeypatch.setattr(llm.requests, "get", refuse)
    steps = llm.check_provider(llm.OllamaProvider())
    assert steps == [(False, "Cannot reach Ollama at http://localhost:11434: nothing is answering at that "
                             "address. Is the server running, and is the URL right?")]


def test_server_error_text_is_shown_and_key_is_masked(monkeypatch):
    key = "sk-supersecretkey123"
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: FakeResp(
        {"error": {"message": f"Invalid API key {key}"}}, status=401))
    with pytest.raises(llm.LLMError) as e:
        llm.OpenAICompatProvider(api_key=key).chat([], [])
    assert "HTTP 401: Invalid API key sk-s****" in str(e.value) and key not in str(e.value)


def test_malformed_tool_call_is_an_llm_error(monkeypatch):
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: FakeResp(
        {"message": {"tool_calls": [{"function": {"name": "run_semgrep", "arguments": "{not json"}}]}}))
    with pytest.raises(llm.LLMError):
        llm.OllamaProvider().chat([], [])
