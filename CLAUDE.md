# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A defensive secure-code-review agent (Python package `scra`, in `src/scra/`) for small JavaScript/Node files, unified diffs, and `package.json` manifests. Gradio UI, CLI, and an evaluation harness. Defensive use only. See `docs/03-safety-boundaries.md`.

## Commands (Windows, from repo root)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e . --no-deps    # needed for `-m scra.*`; requirements.txt doesn't install the package itself

.venv\Scripts\python -m scra.app                      # Gradio UI on http://127.0.0.1:7860 (also: python app.py)
.venv\Scripts\python -m scra.cli review data\samples\mixed_vuln.js
.venv\Scripts\python -m scra.cli review data\samples\package_vuln.json --offline --json
.venv\Scripts\python -m scra.cli stats                # summary of logs/*.jsonl

.venv\Scripts\python -m pytest                        # full suite
.venv\Scripts\python -m pytest tests\test_agent.py::test_deadline_stops_slow_models   # single test

.venv\Scripts\python eval\evaluate.py --mode tools                  # detection, dev set (data/samples + data/labels.json)
.venv\Scripts\python eval\evaluate.py --mode tools --set heldout    # detection, held-out set
.venv\Scripts\python eval\evaluate.py --demo                        # 10 end-to-end cases (eval/demo_cases.json)
.venv\Scripts\python eval\evaluate.py --all --out eval\results\week6.json
```

Other evaluate.py flags: `--mode agent`, `--retrieval`, `--rubric`, `--safety`. Docker: `docker compose up --build`.

`tests/conftest.py` forces `SCRA_LLM=mock`, `SCRA_OFFLINE=1` (OSV snapshot instead of network) and `SCRA_DISABLE_LOGS=1`. Tests need the `semgrep` binary. It's found via `SCRA_SEMGREP`, then PATH, then next to `sys.executable`, so an un-activated venv works.

## Architecture

Core principle: **tools detect, the LLM explains.** A finding reaches the user only if a tool produced evidence for it. A model can't add a finding, and it can't hide one either.

`agent.review()` (`src/scra/agent.py`) is the whole pipeline:
1. `parse_input` (`tools/inputs.py`) runs deterministically first. It enforces the 200 KB cap and UTF-8, classifies the input as file, diff, or manifest, and for diffs records `added_lines`. Uploaded code is never executed.
2. A plain tool-calling loop runs for at most `MAX_STEPS=8` steps with an overall deadline (`SCRA_AGENT_DEADLINE`, default 240 s). The model gets secret-masked, line-numbered code (`redact_secrets_in_code`, first 300 lines) plus three tools:
   - `run_semgrep` (`tools/semgrep_tool.py`) runs the custom rules in `rules/js-security.yml`. Each rule's metadata carries `vuln_class`, `cwe`, `confidence` (HIGH/MEDIUM/LOW → 0.9/0.75/0.5). For diffs, only hits on added lines count.
   - `check_dependencies` (`tools/deps.py`) queries OSV.dev and falls back to `data/osv_snapshot.json`.
   - `retrieve_guidance` (`tools/retrieve.py`) does TF-IDF retrieval over `data/kb/owasp_cwe.json`, with the CWE pinned first and a same-class boost.
   `run_semgrep` and `check_dependencies` take **no arguments** and always operate on the parsed upload, which guards against prompt injection. Keep it that way.
3. Guarantees: if the model never calls the detection tool, the agent runs it itself. If detection failed, `errors` says the review is incomplete.
4. Grounding guard: each model finding is validated against the Pydantic `Finding` (`schema.py`) and matched to the closest *unclaimed* tool hit of the same class (±2 lines, or same package). Unmatched findings are dropped and counted in `dropped`. Evidence fields and `tool` are overwritten from the hit, confidence is clamped to ±0.15 of the tool value, and text goes through `_redact_payloads`. Tool hits with no model finding are restored from `templates.py` with `explained_by="template"`.

Other modules:
- `llm.py`: one `Provider` interface (`chat(messages, tools) -> LLMReply`) with `MockProvider`, `OllamaProvider`, and `OpenAICompatProvider`, plus presets (LM Studio, Groq, Gemini, OpenRouter, OpenAI, custom). `MockProvider` follows the real tool-calling protocol, so the whole loop runs offline in tests. Configured by `SCRA_LLM`, `SCRA_PRESET`, `SCRA_OLLAMA_*`, `SCRA_OPENAI_*` (see `.env.example`, loaded by the tiny loader in `config.py`).
- `approval.py`: `ReviewSession` holds per-finding decisions. `draft_pr_comments` and `draft_patch` raise `ApprovalRequired` for unapproved findings. This check is enforced in the backend, not just the UI. Patches come from rule-based rewrites (always used with the mock) or from an LLM drafting over a masked ±6-line window. They are produced as unified diffs only and are never applied or posted.
- `app.py` / `ui_render.py`: Gradio 6 Blocks with five tabs. Reviews run in a worker thread and stream `on_event` callbacks (`llm`, `llm_end`, `tool_start`, `tool`) to show live progress. `SCRA_HOSTED=1` locks LLM endpoints to fixed hosted URLs and ignores user-supplied URLs, which prevents SSRF.
- `logging_utils.py`: writes `logs/runs.jsonl` and `logs/events.jsonl`. These hold **metadata only**, never code, snippets, or secrets, and a logging failure must never break a review.

## Invariants to preserve when changing code

- There are exactly six `VulnClass` values: xss, injection (CWE-89/78/95), insecure_cookie, missing_input_validation, hardcoded_secret, vulnerable_dependency. Every rule, label, KB entry, and template maps to one of them.
- Secret values must never reach the LLM, the logs, or diffs. Masking must preserve line structure so line numbers still match.
- The held-out set (`data/heldout/`, `data/heldout_labels.json`) was written after the rules were frozen. Don't tune rules to fix its known misses (listed in `eval/EVALUATION.md`). That would turn it into training data.
- Labels match on class plus line within ±2, and they can list `acceptable` extra classes that count as neither TP nor FP.
- Dependency pins `opentelemetry-api~=1.37.0` and `fastapi<0.142` keep Gradio 6 and Semgrep working in one environment. Gradio 6 otherwise pulls a newer OpenTelemetry that Semgrep can't start with. Don't drop them.
- Sample secrets are documented placeholders only (e.g. `AKIAIOSFODNN7EXAMPLE`).

Git commit dates (2–30 Oct 2026) are reconstructed, and the README's Status section says so. Keep that note when editing the README.
