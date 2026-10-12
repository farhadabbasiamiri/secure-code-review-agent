"""LLM providers behind one interface.

    SCRA_LLM=mock      deterministic, offline (default) — tests, CI, hosted demo without a model
    SCRA_LLM=ollama    local Ollama  (SCRA_OLLAMA_URL, SCRA_OLLAMA_MODEL)
    SCRA_LLM=openai    any OpenAI-compatible server: LM Studio, Groq, OpenRouter, Gemini, OpenAI
                       (SCRA_OPENAI_BASE_URL, SCRA_OPENAI_MODEL, SCRA_OPENAI_API_KEY)

Every provider returns an LLMReply: either tool calls to run, or final text content.
Constructor arguments (set from the UI) override the environment variables. API keys are
held in memory only and are never logged or included in error messages.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field

import requests

from .templates import SEVERITY_DEFAULT, TITLE_TEMPLATES, fix_for

LLM_TIMEOUT_S = int(os.getenv("SCRA_LLM_TIMEOUT", "120"))


@dataclass
class ToolRequest:
    id: str
    name: str
    arguments: dict


@dataclass
class LLMReply:
    content: str = ""
    tool_calls: list[ToolRequest] = field(default_factory=list)


class LLMError(RuntimeError):
    pass


def _http_error(prefix: str, exc: Exception, secret: str = "") -> LLMError:
    """Turn a requests failure into a message that says *why* (the server's own error text)."""
    detail = str(exc)
    resp = getattr(exc, "response", None)
    if isinstance(exc, requests.ConnectionError) and resp is None:
        detail = "nothing is answering at that address. Is the server running, and is the URL right?"
    elif isinstance(exc, requests.Timeout):
        detail = "no answer before the timeout. The model may still be loading; try again or raise the timeout."
    elif resp is not None:
        try:
            body = resp.json()
            err = body.get("error", body) if isinstance(body, dict) else body
            detail = f"HTTP {resp.status_code}: {err.get('message', err) if isinstance(err, dict) else err}"
        except ValueError:
            detail = f"HTTP {resp.status_code}: {resp.text[:300]}"
    if secret and len(secret) > 4:
        detail = detail.replace(secret, secret[:4] + "****")
    return LLMError(f"{prefix}: {detail}")


class Provider:
    name = "base"

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------- Ollama
class OllamaProvider(Provider):
    def __init__(self, url: str | None = None, model: str | None = None, timeout: int | None = None):
        self.url = (url or os.getenv("SCRA_OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("SCRA_OLLAMA_MODEL", "qwen2.5-coder:7b")
        self.timeout = timeout or LLM_TIMEOUT_S
        self.name = f"ollama:{self.model}"

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=5)
            r.raise_for_status()
            return sorted(m["name"] for m in r.json().get("models", []))
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise _http_error(f"Cannot reach Ollama at {self.url}", exc) from exc

    def chat(self, messages, tools):
        body = {"model": self.model, "messages": messages, "tools": tools, "stream": False,
                "options": {"temperature": 0.1}}
        try:
            r = requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            msg = r.json()["message"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise _http_error("Ollama request failed", exc) from exc
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args or "{}")
                except ValueError as exc:
                    raise LLMError(f"Model returned a malformed tool call: {exc}") from exc
            calls.append(ToolRequest(c.get("id") or uuid.uuid4().hex[:8], fn.get("name", ""), args))
        return LLMReply(msg.get("content") or "", calls)


# ----------------------------------------------------------- OpenAI-compatible
class OpenAICompatProvider(Provider):
    def __init__(self, base_url: str | None = None, model: str | None = None, api_key: str | None = None,
                 timeout: int | None = None):
        self.base = (base_url or os.getenv("SCRA_OPENAI_BASE_URL", "http://localhost:1234/v1")).rstrip("/")
        self.model = model or os.getenv("SCRA_OPENAI_MODEL", "qwen2.5-coder-7b-instruct")
        self.key = api_key or os.getenv("SCRA_OPENAI_API_KEY") or "not-needed"
        self.timeout = timeout or LLM_TIMEOUT_S
        self.name = f"openai-compat:{self.model}"

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base}/models", timeout=10, headers={"Authorization": f"Bearer {self.key}"})
            r.raise_for_status()
            return sorted(m["id"] for m in r.json().get("data", []))
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise _http_error(f"Cannot list models at {self.base}", exc, self.key) from exc

    def chat(self, messages, tools):
        oa_tools = [{"type": "function", "function": t["function"]} for t in tools]
        oa_msgs = []
        for m in messages:
            m = {k: v for k, v in m.items() if k != "tool_name"}  # not part of the OpenAI schema
            if m.get("tool_calls"):
                m["tool_calls"] = [{"id": c["id"], "type": "function",
                                    "function": {"name": c["function"]["name"],
                                                 "arguments": json.dumps(c["function"]["arguments"])}}
                                   for c in m["tool_calls"]]
            oa_msgs.append(m)
        body = {"model": self.model, "messages": oa_msgs, "tools": oa_tools, "temperature": 0.1}
        try:
            r = requests.post(f"{self.base}/chat/completions", json=body, timeout=self.timeout,
                              headers={"Authorization": f"Bearer {self.key}"})
            r.raise_for_status()
            msg = r.json()["choices"][0]["message"]
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            raise _http_error("OpenAI-compatible request failed", exc, self.key) from exc
        try:
            calls = [ToolRequest(c.get("id") or uuid.uuid4().hex[:8], c["function"]["name"],
                                 json.loads(c["function"].get("arguments") or "{}"))
                     for c in msg.get("tool_calls") or []]
        except (KeyError, TypeError, ValueError) as exc:
            raise LLMError(f"Model returned a malformed tool call: {exc}") from exc
        return LLMReply(msg.get("content") or "", calls)


# ----------------------------------------------------------------------- Mock
class MockProvider(Provider):
    """Deterministic stand-in that follows the same protocol as a real model.

    It reads the conversation, decides which tool to call next, and finally writes findings
    from templates plus retrieved guidance. Used for tests and offline demos; the UI and logs
    always show provider="mock" so nobody mistakes it for model output.
    """

    name = "mock"

    def chat(self, messages, tools):
        results = {}
        for m in messages:
            if m["role"] == "tool":
                results.setdefault(m.get("tool_name", ""), []).append(json.loads(m["content"]))
        kind = json.loads(messages[1]["content"].split("INPUT_META:", 1)[1].split("\n", 1)[0])["kind"]

        # Step 1: detection tool for this input kind
        if kind == "manifest" and "check_dependencies" not in results:
            return self._call("check_dependencies", {})
        if kind != "manifest" and "run_semgrep" not in results:
            return self._call("run_semgrep", {})

        hits = self._hits(results)
        # Step 2: one retrieval per distinct (class, cwe)
        needed = {}
        for h in hits:
            needed.setdefault((h["vuln_class"], h["cwe"]), h["message"])
        done = {(r["vuln_class"], r["cwe"]) for r in results.get("retrieve_guidance", [])}
        todo = [(k, msg) for k, msg in needed.items() if k not in done]
        if todo:
            # Query with the tool's own description of the problem, as a real model would.
            return LLMReply(tool_calls=[ToolRequest(uuid.uuid4().hex[:8], "retrieve_guidance",
                                                    {"query": f"{msg} how to fix", "vuln_class": c, "cwe": w})
                                        for (c, w), msg in todo])

        # Step 3: final structured answer
        guidance = {(r["vuln_class"], r["cwe"]): r for r in results.get("retrieve_guidance", [])}
        findings = []
        for h in hits:
            g = guidance.get((h["vuln_class"], h["cwe"]), {"results": []})
            ids = [x["id"] for x in g["results"]]
            lead = g["results"][0]["text"].split(". ")[0].rstrip(".") + "." if g["results"] else ""
            findings.append({
                "finding": TITLE_TEMPLATES[h["vuln_class"]].format(**h),
                "vuln_class": h["vuln_class"], "cwe": h["cwe"],
                "evidence": h["evidence"],
                "severity": h.get("severity") or SEVERITY_DEFAULT[h["vuln_class"]],
                "explanation": f"{h['message']} {lead}".strip(),
                "fix": fix_for(h["vuln_class"], h["cwe"], h),
                "confidence": h["confidence"], "sources": ids, "tool": h["tool"],
            })
        return LLMReply(content=json.dumps({"findings": findings}))

    @staticmethod
    def _call(name, args):
        return LLMReply(tool_calls=[ToolRequest(uuid.uuid4().hex[:8], name, args)])

    @staticmethod
    def _hits(results: dict) -> list[dict]:
        hits = []
        for r in results.get("run_semgrep", []):
            for h in r.get("hits", []):
                hits.append({**h, "tool": "semgrep", "fixed": None, "package": None, "version": None,
                             "evidence": {"file": h["file"], "line": h["line"], "snippet": h["snippet"]}})
        for r in results.get("check_dependencies", []):
            for v in r.get("vulnerabilities", []):
                hits.append({"vuln_class": "vulnerable_dependency", "cwe": "CWE-1395", "tool": f"osv:{r['source']}",
                             "confidence": 0.9 if r["source"] != "none" else 0.5,
                             "severity": v["severity"] if v["severity"] in ("critical", "high", "medium", "low") else None,
                             "message": f"{v['package']}@{v['version']} is affected by {v['id']}"
                                        f"{' (' + ', '.join(v['aliases']) + ')' if v['aliases'] else ''}"
                                        f"{': ' + v['summary'].rstrip('.') if v['summary'] else ''}.",
                             "package": v["package"], "version": v["version"], "fixed": v.get("fixed") or "a patched release",
                             "advisory": v["id"], "line": None, "file": "package.json",
                             "evidence": {"file": "package.json", "line": None,
                                          "snippet": f'"{v["package"]}": "{v["version"]}"',
                                          "package": v["package"], "version": v["version"]}})
        return hits


def get_provider(name: str | None = None) -> Provider:
    name = (name or os.getenv("SCRA_LLM", "mock")).lower()
    return {"mock": MockProvider, "ollama": OllamaProvider, "openai": OpenAICompatProvider}[name]()


# -------------------------------------------------------------------- Presets
# Model names change often, so these are starting points. "Fetch models" in the UI lists what
# the server actually offers. kind = which Provider class talks to it.
PRESETS: dict[str, dict] = {
    "mock": {"label": "Mock (offline, no model)", "kind": "mock", "base_url": "", "model": "",
             "needs_key": False, "local": True},
    "ollama": {"label": "Ollama (local, free)", "kind": "ollama", "base_url": "http://localhost:11434",
               "model": "qwen2.5-coder:7b", "needs_key": False, "local": True},
    "lmstudio": {"label": "LM Studio (local, free)", "kind": "openai", "base_url": "http://localhost:1234/v1",
                 "model": "qwen2.5-coder-7b-instruct", "needs_key": False, "local": True},
    "groq": {"label": "Groq (free tier, API key)", "kind": "openai", "base_url": "https://api.groq.com/openai/v1",
             "model": "llama-3.3-70b-versatile", "needs_key": True, "local": False, "key_env": "GROQ_API_KEY"},
    "gemini": {"label": "Google Gemini (free tier, API key)", "kind": "openai",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "model": "gemini-2.5-flash",
               "needs_key": True, "local": False, "key_env": "GEMINI_API_KEY"},
    "openrouter": {"label": "OpenRouter (API key)", "kind": "openai", "base_url": "https://openrouter.ai/api/v1",
                   "model": "meta-llama/llama-3.3-70b-instruct", "needs_key": True, "local": False,
                   "key_env": "OPENROUTER_API_KEY"},
    "openai": {"label": "OpenAI (paid API key)", "kind": "openai", "base_url": "https://api.openai.com/v1",
               "model": "gpt-4o-mini", "needs_key": True, "local": False, "key_env": "OPENAI_API_KEY"},
    "custom": {"label": "Custom OpenAI-compatible server", "kind": "openai", "base_url": "http://localhost:8000/v1",
               "model": "", "needs_key": False, "local": True},
}


def resolve_preset(key: str) -> dict:
    """A preset with environment overrides applied (read at call time, after .env is loaded)."""
    p = dict(PRESETS[key])
    if key == "ollama":
        p["base_url"] = os.getenv("SCRA_OLLAMA_URL", p["base_url"])
        p["model"] = os.getenv("SCRA_OLLAMA_MODEL", p["model"])
    elif key == "custom":
        p["base_url"] = os.getenv("SCRA_OPENAI_BASE_URL", p["base_url"])
        p["model"] = os.getenv("SCRA_OPENAI_MODEL", p["model"])
        p["key_env"] = "SCRA_OPENAI_API_KEY"
    return p


def default_preset() -> str:
    """SCRA_PRESET if set (e.g. "groq"), else the preset matching SCRA_LLM, so the UI starts where the CLI would."""
    if os.getenv("SCRA_PRESET", "").lower() in PRESETS:
        return os.environ["SCRA_PRESET"].lower()
    name = os.getenv("SCRA_LLM", "mock").lower()
    return {"mock": "mock", "ollama": "ollama"}.get(name, "custom" if name == "openai" else "mock")


def build_provider(preset: str, base_url: str = "", model: str = "", api_key: str = "",
                   timeout: int | None = None) -> Provider:
    """Provider from UI settings. Blank fields fall back to the preset, then the environment."""
    p = resolve_preset(preset)
    if p["kind"] == "mock":
        return MockProvider()
    if p["kind"] == "ollama":
        return OllamaProvider(url=base_url or p["base_url"], model=model or p["model"], timeout=timeout)
    key = api_key or (os.getenv(p["key_env"], "") if p.get("key_env") else "")
    return OpenAICompatProvider(base_url=base_url or p["base_url"], model=model or p["model"],
                                api_key=key or None, timeout=timeout)


PING_TOOL = [{"type": "function", "function": {
    "name": "ping", "description": "Connectivity check. Always call this tool once.",
    "parameters": {"type": "object", "properties": {}, "required": []}}}]


def check_provider(provider: Provider) -> list[tuple[bool, str]]:
    """Step-by-step connection check: reach the server, find the model, confirm tool calling.

    Tool calling is what the agent depends on: a model that can only chat can't drive the tools.
    """
    if isinstance(provider, MockProvider):
        return [(True, "Mock provider needs no connection.")]
    steps: list[tuple[bool, str]] = []
    try:
        models = provider.list_models()
        steps.append((True, f"Server reachable ({len(models)} model(s) listed)."))
    except LLMError as exc:
        steps.append((False, str(exc)))
        return steps
    if models and provider.model not in models and f"{provider.model}:latest" not in models:
        hint = f" or run `ollama pull {provider.model}`" if isinstance(provider, OllamaProvider) else ""
        steps.append((False, f"Model '{provider.model}' is not on this server. Pick one with 'Fetch models'{hint}."))
        return steps
    try:
        reply = provider.chat([{"role": "system", "content": "You are testing a tool connection."},
                               {"role": "user", "content": "Call the ping tool now."}], PING_TOOL)
    except LLMError as exc:
        steps.append((False, f"Chat request failed: {exc}"))
        return steps
    if any(c.name == "ping" for c in reply.tool_calls):
        steps.append((True, "Model supports tool calling. Ready to review."))
    else:
        steps.append((False, "Model replied but did not call the tool. Reviews will still show tool findings, "
                             "but explanations fall back to templates. Try a tool-capable model."))
    return steps
