# Slide outline (12 slides, ~12 minutes with the live demo)

Content for the final presentation. One idea per slide; the speaker notes are the sentence to say.

1. **Secure Code Review Agent.** Brief 9B, Fall 2026, om. _Note:_ "An agent that reviews a pull
   request's JavaScript for security issues, and only says what its tools can prove."
2. **The problem.** Vulnerabilities reach production through PRs. Static analysers: precise, terse,
   ignored. LLM chat: fluent, ungrounded, invents line numbers. _Note:_ we want both strengths.
3. **What it does.** Input: one JS file, a diff, or package.json. Output: findings with evidence,
   severity, explanation, fix, confidence, OWASP/CWE sources. Six vulnerability classes.
4. **Architecture.** Diagram from `docs/02-architecture.md`. _Note:_ point at the three tools and
   the grounding guard.
5. **Tools detect, the model explains.** Grounding guard: schema, match to a tool hit, evidence
   copied from the tool, bounded confidence, coverage guarantee. _Note:_ "A weaker model makes worse
   explanations, never a less complete review."
6. **Live demo** (see `docs/DEMO_SCRIPT.md`): review, prompt injection, diff, approval, patch,
   failure handling.
7. **Human in the loop.** Approve/reject per finding; PR comments and patches only for approved
   findings, enforced in the backend; nothing posted or applied. Rejections are logged as
   false-positive data.
8. **Evaluation: detection.** Development set 1.00 (wiring check) vs held-out 0.77 F1 (written after
   rules froze). Table of misses and false positives. _Note:_ the held-out number is the honest one.
9. **Evaluation: everything else.** 10/10 demo cases incl. bad input and LLM outage; 7/7 safety
   checks; rubric checks; retrieval precision@3 0.95 with class hint. Real-model rubric scores (add
   after running `eval/RUBRIC.md`).
10. **Safety boundaries.** No execution, no payloads, secrets masked before the model sees code,
    metadata-only logs, untrusted-input prompt, SSRF lock on public deployments, escaped output.
11. **Limitations.** Pattern rules miss variants (`findOneAndUpdate`, aliases); no React/JSX rules;
    small single-author dataset; Semgrep start-up ~5 s on Windows; local models slow without a GPU.
12. **Lessons and future work.** Biggest bug found was a scanner failure that looked like a clean
    result. Next: React rules, more held-out data from real PRs, embedding retrieval comparison,
    GitHub App that posts approved comments.

Screenshots for slides 3, 6, 7: `docs/screenshots/`.
