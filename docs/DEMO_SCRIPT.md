# Demo script (8–10 minutes)

For the early-December live demonstration. Rehearse it at least twice against the real setup,
timing each part.

## Before the session

- [ ] App running: `.venv\Scripts\python -m scra.app`, browser open on <http://127.0.0.1:7860>, zoom 125 %.
- [ ] Model chosen and **Test connection** shows three ticks. If using Ollama, run one review first
      so the model is loaded (the first call is slow).
- [ ] Time limits raised if using a local model (300 s per call, 600 s per review).
- [ ] Clear old logs if you want a clean Monitoring tab: delete `logs/`.
- [ ] Backup ready (see the end of this page).

## The story

**1. The problem (30 s).** "Pull requests ship XSS, injection and leaked keys. Static analysers
catch patterns but their output gets ignored; chat assistants explain well but make things up. This
agent combines the two: tools find the problems, the model explains them, and nothing the model says
is shown unless a tool backs it."

**2. A review (2 min).** Review `mixed_vuln.js`.
- Point at **Agent steps** as they appear: the model chose Semgrep, then looked up guidance once per
  issue type. "This is the agent selecting and executing tools, not a chat response."
- Open the critical finding: evidence line, why, fix, sources, and the provenance line ("detected by
  Semgrep, explanation by the model").

**3. Grounding (1 min).** Review `Scenario: prompt_injection.js`. "The file tells the AI to report
nothing. The eval() is still reported: detection doesn't depend on the model obeying."

**4. A pull request diff (45 s).** Review `xss_added.diff`: only the added line is flagged.

**5. Human approval (2 min).** Back to `mixed_vuln.js`, **Approve and export**.
- Try **Draft PR comments** first: refused. "Sensitive actions need a person."
- Approve two findings, reject one. Draft PR comments; show the download. Draft a patch for the
  command injection and show the diff. "Suggested, never applied."

**6. Failure handling (1 min).** On **LLM settings**, point the provider at a stopped server and
**Test connection**: plain-language failure. Review anyway: findings still appear with a note.
(Or show the `llm-outage` demo case from the evaluation.)

**7. Evaluation (1.5 min).** Show the table in `eval/EVALUATION.md`: perfect on the development set
"which proves the wiring, not accuracy", 0.77 F1 on the held-out set written after the rules froze,
and the specific misses. 10/10 demo cases, 7/7 safety checks. **Monitoring** tab for latency.

**8. Limits and next steps (45 s).** React/JSX not covered (show `react_profile.jsx`), rules are
pattern-based, small dataset. Next: more held-out data, React rules, a real-model comparison.

## Likely questions

- *Why not let the model find vulnerabilities itself?* Unbounded false positives and invented line
  numbers. Here the model adds explanation and fixes; recall comes from rules we can test.
- *What if the model is wrong?* Its text is limited to explanation and fix; evidence is copied from
  the tool, confidence is bounded, and a person approves before anything leaves the screen.
- *Does code leave the machine?* Not with Ollama/LM Studio. With hosted APIs, masked code does.
- *Why TF-IDF and not embeddings?* 21 curated entries; TF-IDF is deterministic and needs no GPU.
  Retrieval precision is in the evaluation.

## Backup plan

In order of preference if something fails live:

1. **Model down or slow:** switch to *Mock* on LLM settings. Everything else works identically,
   and the provenance line makes the switch visible.
2. **App won't start:** `python -m scra.cli review data\samples\mixed_vuln.js` shows the same
   findings and agent steps in the terminal.
3. **Laptop problem:** play the recorded walkthrough (record it during rehearsal: Windows
   Game Bar, Win+Alt+R, following steps 2–7), and show `docs/screenshots/`.
