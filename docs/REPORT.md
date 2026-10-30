# Secure Code Review Agent: final report

Applied AI Agents for Cybersecurity Operations, Fall 2026, Laurentian University. Brief 9B.
Author: om (solo project).

## 1. Problem

Web applications ship client- and server-side vulnerabilities that could be caught when a pull
request is reviewed. Static analysers find patterns but produce terse output that developers often
ignore. General-purpose LLM chat explains well but is ungrounded: it invents issues, misquotes line
numbers, and can be talked out of reporting a problem by text inside the code it is reading.

**Goal.** An agent that reviews one small JavaScript/Node file, a unified diff, or a `package.json`,
runs real analysis tools, grounds its explanation in OWASP/CWE guidance, and returns structured
findings a developer can act on, with a person approving anything that leaves the review screen.

**User.** A developer or reviewer looking at a pull request for a small Node/Express or browser
JavaScript change.

## 2. Requirements

| Requirement                                                                                             | Source         | How it is met                                                       |
| ------------------------------------------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------- |
| Web app accepting a JS file or diff                                                                     | Brief, SDLC §6 | Gradio app: samples, upload, editable code                          |
| Six classes: XSS, injection, insecure cookie, missing validation, hardcoded secret, outdated dependency | Brief          | Custom Semgrep rules + OSV check                                    |
| Static analysis + dependency checks                                                                     | Brief          | Semgrep (10 custom rules), OSV API with offline snapshot            |
| RAG over OWASP/CWE                                                                                      | Brief          | 21-entry curated KB, TF-IDF retriever, cited in every finding       |
| Output: finding, evidence, severity, fix, confidence                                                    | Brief          | Pydantic `Finding` schema, validated                                |
| Agent selects and executes tools                                                                        | SDLC §1, §6    | LLM tool-calling loop; steps shown live                             |
| Handles invalid input, timeouts, tool/API failures                                                      | SDLC §6        | Input checks, per-call and per-review limits, fallbacks; demo cases |
| Human approval for sensitive recommendations                                                            | Brief metrics  | Approval step gating PR comments and patches                        |
| Evaluated with documented cases                                                                         | SDLC §6        | Dev + held-out detection, rubric, demo cases, safety checks         |
| Reproducible / deployed                                                                                 | SDLC §6        | Python, Docker, Compose, Hugging Face Space instructions            |
| Logging and monitoring                                                                                  | SDLC stage 7   | JSONL logs, Monitoring tab, `scra stats`                            |
| No hard-coded keys                                                                                      | SDLC §8        | Environment / `.env` / session-only key field                       |

## 3. Design

Architecture diagram and component table: [`02-architecture.md`](02-architecture.md). Key decisions:

- **Tools detect, the LLM explains.** The model chooses which tools to run and
  writes explanation and fix. A grounding guard matches each model finding to a tool hit, copies the
  evidence from the tool, bounds the confidence, drops anything unmatched, and restores tool hits the
  model left out. Detection quality therefore does not depend on which model is used.
- **Plain Python tool-calling loop** instead of LangGraph: every step is visible and testable.
- **One provider interface:** a deterministic mock for tests and offline demos, Ollama,
  and any OpenAI-compatible API, with presets and a connection test that checks tool calling.
- **TF-IDF retrieval over a small curated KB** instead of embeddings and a vector database.
- **Human approval enforced in the backend.**

## 4. Implementation

| Part                                   | Files                                                     |
| -------------------------------------- | --------------------------------------------------------- |
| Input parsing (file / diff / manifest) | `src/scra/tools/inputs.py`                                |
| Semgrep tool, secret masking           | `src/scra/tools/semgrep_tool.py`, `rules/js-security.yml` |
| Dependency tool                        | `src/scra/tools/deps.py`, `data/osv_snapshot.json`        |
| Retrieval                              | `src/scra/tools/retrieve.py`, `data/kb/owasp_cwe.json`    |
| Agent loop and grounding guard         | `src/scra/agent.py`                                       |
| LLM providers and presets              | `src/scra/llm.py`                                         |
| Approval, PR comments, patch drafts    | `src/scra/approval.py`                                    |
| Web app                                | `src/scra/app.py`, `src/scra/ui_render.py`                |
| Logging and monitoring                 | `src/scra/logging_utils.py`                               |
| CLI                                    | `src/scra/cli.py`                                         |
| Evaluation                             | `eval/evaluate.py`, `eval/demo_cases.json`                |

Test suite: 72 pytest tests covering tools, providers (faked HTTP), agent behaviour (hallucinated
findings, duplicate findings, payloads, step and time limits, outages, prompt injection, secret
masking), the approval step, UI handlers, and HTML escaping.

## 5. Evaluation

Full numbers and caveats: [`eval/EVALUATION.md`](../eval/EVALUATION.md). Summary:

| Measure                                                                | Result                               |
| ---------------------------------------------------------------------- | ------------------------------------ |
| Detection, development set (21 inputs, 20 labels)                      | P = R = F1 = 1.00                    |
| Detection, held-out set (13 inputs, 13 labels)                         | P = 0.77, R = 0.77, F1 = 0.77        |
| Retrieval, top-1 / precision@3 (query only)                            | 0.85 / 0.74                          |
| Retrieval, top-1 / precision@3 (with class hint, as the agent uses it) | 1.00 / 0.95                          |
| End-to-end demo cases                                                  | 10 / 10                              |
| Safety checks                                                          | 7 / 7                                |
| Automated explanation rubric                                           | every finding passes all five checks |

The development-set score only shows the pipeline is wired correctly: the rules and the samples
were written together. The held-out set, written after the rules were frozen, is the honest
estimate. Its errors are specific and explainable: a session-cookie finding reported on the call
line rather than the `secure: false` line, `findOneAndUpdate(req.body)` not covered, an npm alias of
a vulnerable package skipped, a constant named `TOKEN_HEADER` mistaken for a secret, and a number
written to `innerHTML` flagged as XSS. They were deliberately not fixed against the held-out data.

The agent scores the same as the tools alone, as designed: the model adds explanations, not
detections. Agent numbers above use the mock provider. A run with a real model and the manual
rubric (`eval/RUBRIC.md`) is the remaining evaluation step.

## 6. Safety

Ten boundaries, each with where it is enforced and which test covers it:
[`03-safety-boundaries.md`](03-safety-boundaries.md). Highlights: uploaded code is never executed;
secrets are masked before code reaches a model and in every output; instructions inside the code
can't suppress findings; model text is filtered for attack payloads; logs hold metadata only;
public deployments can't be used to make the server call arbitrary URLs.

## 7. Deployment and monitoring

Runs locally with Python on Windows, macOS and Linux; in Docker; with Compose including an optional
Ollama container; and on a Hugging Face Docker Space with `SCRA_HOSTED=1` ([`DEPLOY.md`](DEPLOY.md)).
Each review and approval decision is logged as metadata; the Monitoring tab shows review count,
latency percentiles, tool failures, findings by class, reviewer decisions and recent runs.

## 8. Limitations

- **Rule coverage.** Pattern rules miss variants they weren't written for, and there are no
  React/JSX, Vue, or TypeScript-aware rules. Taint tracking is per-file only.
- **Dataset.** 34 small, single-author inputs. Results show the approach works on clear cases,
  not real-world recall.
- **Dependency checks** use the base version of a range, skip aliases and git/file specs, and need
  network access for current advisories (the bundled snapshot covers four packages).
- **Speed.** Semgrep takes about 5 s to start on Windows (2 s on Linux); local models without a
  GPU take minutes per review.
- **Real-model evaluation** not yet recorded; the mock provider's explanations are templates.
- **Patch drafts** cover the sample patterns; others fall back to written guidance.

## 9. Future work

React and TypeScript rules; a larger held-out set drawn from real (public, permissively licensed)
pull requests; comparing TF-IDF with embedding retrieval; recording false-positive rejections to
tune rules on a separate split; a GitHub App that posts approved comments to the PR.

## 10. Lessons learned

- The most serious bug was found by using the product, not by tests: with Semgrep missing from
  PATH, every review came back "no issues" with no error. A security tool must never turn its own
  failure into a clean result.
- Writing the held-out set after freezing the rules turned a meaningless 1.00 into a useful 0.77
  with a concrete list of what to fix next.
- Constraining the model to explanation, with evidence copied from tools, made the system robust to
  weak models, prompt injection, and outages at the same time.

## 11. Contributions

Solo project: all planning, data, rules, agent, UI, evaluation, deployment and documentation by om.
The brief's five roles (data, AI/RAG, agent, app, evaluation) map to `data/`, `src/scra/tools/` +
`data/kb/`, `src/scra/agent.py` + `llm.py`, `src/scra/app.py`, and `eval/` respectively.

## References

- Semgrep: <https://semgrep.dev/>
- OWASP Web Security Testing Guide: <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Cheat Sheet Series: <https://cheatsheetseries.owasp.org/>
- MITRE CWE: <https://cwe.mitre.org/>
- OSV: <https://osv.dev/>
- Node.js security best practices: <https://nodejs.org/en/learn/getting-started/security-best-practices>
