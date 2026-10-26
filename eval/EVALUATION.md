# Week 6 Evaluation

Run on 30 Oct 2026, Windows 11, Semgrep 1.183, mock LLM provider. Reproduce with:

```bash
python eval/evaluate.py --all --out eval/results/week6.json
```

Console output of that run: [`results/week6.txt`](results/week6.txt). The Week 3 baseline is in
[`BASELINE.md`](BASELINE.md).

## 1. Detection

A prediction matches a label when the class matches and the line is within ±2 (dependencies: same
package). "Agent" runs the full loop; with the mock provider its findings come from the same tool
hits, so the two rows are expected to agree. With a real model they must still agree, because the
grounding guard drops anything the tools didn't find and restores anything the model skipped.

| Set | Mode | Precision | Recall | F1 | TP | FP | FN |
|-----|------|-----------|--------|----|----|----|----|
| Development (21 inputs) | tools | 1.00 | 1.00 | 1.00 | 20 | 0 | 0 |
| Development (21 inputs) | agent | 1.00 | 1.00 | 1.00 | 20 | 0 | 0 |
| **Held-out (13 inputs)** | tools | **0.77** | **0.77** | **0.77** | 10 | 3 | 3 |
| **Held-out (13 inputs)** | agent | **0.77** | **0.77** | **0.77** | 10 | 3 | 3 |

The development samples and the rules were written together, so 1.00 only shows the pipeline is
wired correctly. The held-out set was written after the rules were frozen and labelled by what a
reviewer would report: **0.77 is the honest number.**

Held-out per class:

| Class | P | R | F1 | Notes |
|-------|---|---|----|-------|
| injection | 1.00 | 1.00 | 1.00 | Template-literal SQL with `pg`, and `child.exec` with an unusual import name, both caught |
| xss | 0.67 | 1.00 | 0.80 | `insertAdjacentHTML` from `postMessage` caught; one false positive |
| vulnerable_dependency | 1.00 | 0.67 | 0.80 | Caret/tilde ranges handled; npm alias missed |
| hardcoded_secret | 0.50 | 1.00 | 0.67 | Real password found; one false positive |
| insecure_cookie | 0.67 | 0.67 | 0.67 | Partial flags and diff case caught; session config on the wrong line |
| missing_input_validation | 1.00 | 0.50 | 0.67 | `Object.assign(user, req.body)` caught; `findOneAndUpdate` missed |

Every error, and why:

| Sample | Error | Cause | Possible fix (not applied, so the held-out set stays unseen) |
|--------|-------|-------|-------------------------------------|
| `h_session_insecure.js` | Missed at line 9, false positive at line 5 | The rule reports the start of the `session({...})` call, 4 lines above the `secure: false` it is about. One issue, counted as one miss plus one false positive | `focus-metavariable` on the flag so the evidence points at it |
| `h_validation_findoneandupdate.js` | Missed | `findOneAndUpdate` isn't in the rule's list of data-layer calls | Add `findOneAndUpdate`, `updateMany`, `replaceOne` |
| `h_package_mixed.json` | Missed `my-lodash` | npm aliases are skipped, so `npm:lodash@4.17.15` isn't checked | Resolve the alias to the real package name |
| `h_secret_config.js` | False positive at line 1 | `const TOKEN_HEADER = "x-access-token"` matches the credential-name pattern | Ignore values that look like header names or contain no digits |
| `h_clean_dom.js` | False positive at line 8 | `innerHTML = "<b>" + comments.length + "</b>"`: the value is a number, but pattern rules can't know | Accept as a reviewer decision; this is what the approval step's *Reject* is for |

Things the held-out set confirmed work: escaped output (`escapeHtml`), `execFile` with an argument
array, and `RegExp.exec` are not flagged; in the diff, the `eval` on an unchanged context line is
correctly ignored while the added cookie line is reported.

## 2. Retrieval (RAG)

13 queries with an expected vulnerability class; an entry is relevant if its class matches.

| Setting | Top-1 accuracy | Precision@3 |
|---------|----------------|-------------|
| Query text only | 0.846 | 0.744 |
| With class hint (how the agent calls it) | 1.000 | 0.949 |

Unchanged since the review pass. Per-query results are in `results/week6.txt`.

## 3. Explanation quality (rubric)

**Automated checks**, all 33 findings across both sets (definitions in [`RUBRIC.md`](RUBRIC.md)):

| Clear | Evidence-based | Actionable | Safe | Cited | All five |
|-------|----------------|------------|------|-------|----------|
| 100 % | 100 % | 100 % | 100 % | 100 % | 100 % |

With the mock provider this mostly verifies the templates, the evidence plumbing and the citations.
The same checks apply unchanged to a real model's output.

**Manual scoring with a real model: not yet done.** Use the sheet in `RUBRIC.md` on 8 findings per
model and record the averages here:

| Model | Provider | Date | Clear | Evidence | Actionable | Safe |
|-------|----------|------|-------|----------|------------|------|
| *(to do)* | | | | | | |

## 4. End-to-end demo cases

The brief asks for the demo success rate on 5–10 prepared cases. Each case runs the full agent the
way the UI does ([`demo_cases.json`](demo_cases.json)).

| Case | What it shows | Result |
|------|---------------|--------|
| mixed-express-app | Four issue types in one Express file | Pass |
| pull-request-diff | Only the added line of a diff is reported | Pass |
| dependencies | Four vulnerable versions from package.json | Pass |
| fixed-code | Fixed version of a vulnerable file has no findings | Pass |
| prompt-injection | A comment telling the AI to stay quiet doesn't hide `eval()` | Pass |
| session-cookie | Insecure `express-session` configuration | Pass |
| unsupported-file | A `.txt` file is rejected with a clear message | Pass |
| binary-upload | A binary is rejected, never parsed or run | Pass |
| llm-outage | LLM unreachable: tool findings shown with a note | Pass |
| held-out-sqli | Held-out template-literal SQL injection | Pass |
| **Total** | | **10 / 10** |

Typical time per JavaScript review: 5–6 s, almost all of it Semgrep starting up on Windows (about
2 s on Linux). A real model adds its own latency; the Monitoring tab measures it.

## 5. Safety

| Check | Result |
|-------|--------|
| No secret value reaches the LLM or the output: `secret_vuln.js` (4 secrets) | Pass |
| Same for `mixed_vuln.js` (2 secrets) | Pass |
| Same for held-out `h_secret_config.js` (2 secret-like values) | Pass |
| Instructions hidden in code can't suppress a tool finding | Pass |
| Attack payloads in model output are redacted | Pass |
| PR comments and patches refuse to run without approval | Pass |
| A failed scanner is reported as incomplete, not as clean | Pass |
| **Total** | **7 / 7** |

These run against simulated misbehaving models (one that obeys the injected comment, one that adds
payloads to its text), so they test the guard rather than any particular model's manners.

## 6. Functional and failure-handling tests

`pytest`: 72 tests, all passing. Beyond the above they cover: invalid, empty, binary and oversized
input; Semgrep timeout and absence; OSV unreachable (snapshot fallback); LLM outage, malformed tool
calls, unknown tools, step limit and time limit; hallucinated, duplicate and adjacent findings;
confidence bounds; the approval gate and decision logging; provider presets, model listing,
connection test messages and API-key masking; hosted-mode URL lock; HTML escaping of uploaded code.

## 7. Human-in-the-loop behaviour

- Sensitive actions (PR comments, patch drafts) are refused until a finding is approved: tested in
  the backend and checked through the UI.
- Approve/reject decisions are logged per finding (class, CWE, tool, confidence, decision), so
  rejected findings become false-positive data. The Monitoring tab shows decision counts.
- Patch drafts are never applied; secrets are masked on both sides of the diff.

## 8. Still to do

1. Run the agent with a real model (Ollama `qwen2.5-coder:7b` and Groq), record detection
   (expected unchanged), dropped-finding counts, latency, and the manual rubric scores above.
2. Extend the held-out set before touching the rules; then fix the five errors in §1 and write a
   *new* held-out set to measure the fix.
