# Week 3 Baseline Evaluation

> Superseded for Week 6 by [`EVALUATION.md`](EVALUATION.md) (held-out set, rubric, demo cases, safety). Kept as the Week 3 record.

Run on 30 Oct 2026. Reproduce with:

```bash
python eval/evaluate.py --mode tools
python eval/evaluate.py --retrieval
```

## Detection — tools only (Semgrep custom rules + OSV snapshot, no LLM)

| Class | Precision | Recall | F1 | TP | FP | FN |
|-------|-----------|--------|----|----|----|----|
| xss | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| injection | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| insecure_cookie | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| missing_input_validation | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| hardcoded_secret | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| vulnerable_dependency | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| **Overall** | **1.00** | **1.00** | **1.00** | **20** | **0** | **0** |

Runtime: ~45 s for 21 inputs (≈2 s per Semgrep start-up, the dominant cost).

**How to read this:** the rules and the dataset were written by the same person in the same
week, so a perfect score shows the pipeline is wired correctly — it is **not** an estimate of
real-world accuracy. Week 6 adds held-out samples written *after* the rules are frozen.

## Retrieval — RAG over the OWASP/CWE knowledge base

13 natural-language queries, each with an expected vulnerability class. A retrieved entry is
relevant if its `vuln_class` matches.

| Setting | Top-1 accuracy | Precision@3 |
|---------|----------------|-------------|
| Query text only | 0.846 | 0.744 |
| With class hint (how the agent calls it) | 1.000 | 0.949 |

Query-only precision@3 history: 0.615 (prose only) → 0.692 (added `keywords`) → 0.744 (added
CWE-1395 entry in the review pass).

Notable misses (query only):
- "res.send with req.query parameter" → SQL guidance ranks first because "query" dominates.
- "eval on request body" → mass-assignment entry ranks above CWE-95 ("request body" overlap).
- "req.body passed directly to User.create" → only CWE-915 is on-topic in the top 3.

Since the agent always passes the class and CWE from Semgrep metadata, the class-hinted
number is what users see. The query-only number is the honest measure of the retriever itself.
